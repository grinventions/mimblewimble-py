"""
mimblewimble/p2p/state_sync.py

Stage 2 of PIBD sync: UTXO-set / block-body synchronisation.

Two sub-paths are supported:

  A) PIBD (preferred) — downloads individual PMMR segments from peers and
     assembles them into a complete TxHashSet via :class:`Desegmenter`.

  B) TxHashSet snapshot (fallback) — requests a ZIP archive of the TxHashSet
     from a peer, verifies the PMMR roots inside it against the archive header
     obtained from Stage 1, then applies it.

The fallback is triggered when no PIBD-capable peer has been seen for
``TXHASHSET_ZIP_FALLBACK_TIME_SECS`` seconds (from ``pibd_params.py``).

Reference: servers/src/grin/sync/state_sync.rs
"""

from __future__ import annotations

import io
import logging
import time
import zipfile
from pathlib import Path
from typing import Optional

from mimblewimble.mmr.pibd import PIBDSegmentContainer, SyncState, SyncStatus
from mimblewimble.mmr.pibd_params import (
    SEGMENT_REQUEST_COUNT,
    SEGMENT_REQUEST_TIMEOUT_SECS,
    TXHASHSET_ZIP_FALLBACK_TIME_SECS,
)
from mimblewimble.mmr.segment import SegmentType, SegmentTypeIdentifier
from mimblewimble.mmr.sync import TxHashSetSync
from mimblewimble.mmr.txhashset import Desegmenter, TxHashSet, TxHashSetError
from mimblewimble.p2p.adapter import ChainAdapter
from mimblewimble.p2p.peer import Peer
from mimblewimble.p2p.peers import PeerStore

log = logging.getLogger(__name__)


class StateSyncError(Exception):
    pass


class StateSync:
    """Stage-2 PIBD sync: download the UTXO set.

    Instantiated by :class:`SyncRunner`; its ``check_run()`` method is
    called every iteration of the main sync loop.
    """

    def __init__(
        self,
        adapter: ChainAdapter,
        peers: PeerStore,
        sync_state: SyncState,
        txhashset: TxHashSet,
        data_dir: Path,
    ) -> None:
        self._adapter = adapter
        self._peers = peers
        self._sync_state = sync_state
        self._txhashset = txhashset
        self._data_dir = Path(data_dir)

        # The desegmenter is created once we know the archive header
        self._desegmenter: Optional[Desegmenter] = None
        self._archive_header = None

        # Timestamps for fallback logic
        self._pibd_peer_last_seen: float = 0.0
        self._snapshot_initiated: bool = False
        self._snapshot_start: float = 0.0

    # ------------------------------------------------------------------
    # Main entry-point  (called by SyncRunner each loop iteration)
    # ------------------------------------------------------------------

    def check_run(
        self,
        archive_header,
        genesis_header,
        best_header_hash: bytes,
    ) -> bool:
        """Advance PIBD or snapshot sync by one step.

        Args:
            archive_header      The header at the PIBD horizon (from Stage 1).
            genesis_header      The genesis block header.
            best_header_hash    Hash of the current best KNOWN header (used
                                for snapshot root verification).

        Returns:
            True if work was done this call; False if nothing to do.
        """
        # Initialise desegmenter lazily
        if self._desegmenter is None:
            self._archive_header = archive_header
            self._desegmenter = self._txhashset.desegmenter(
                archive_header, genesis_header
            )
            self._sync_state.update(SyncStatus.TXHASHSET_PIBD)
            log.info("StateSync: PIBD desegmenter initialised")

        if self._desegmenter.is_complete():
            return self._finalise()

        # Try PIBD path
        pibd_peers = self._peers.pibd_capable().pick_n(SEGMENT_REQUEST_COUNT)
        if pibd_peers:
            self._pibd_peer_last_seen = time.monotonic()
            return self._continue_pibd(pibd_peers, best_header_hash)

        # No PIBD peers: check fallback timeout
        time_without_pibd = time.monotonic() - self._pibd_peer_last_seen
        if (
            self._pibd_peer_last_seen > 0
            and time_without_pibd > TXHASHSET_ZIP_FALLBACK_TIME_SECS
            and not self._snapshot_initiated
        ):
            log.info(
                "No PIBD peers for %.0f s — falling back to TxHashSet snapshot",
                time_without_pibd,
            )
            return self._initiate_snapshot_sync(best_header_hash)

        return False

    # ------------------------------------------------------------------
    # PIBD path
    # ------------------------------------------------------------------

    def _continue_pibd(self, pibd_peers: list, archive_header_hash: bytes) -> bool:
        """Request the next batch of segments from available PIBD peers."""
        assert self._desegmenter is not None

        # Remove stale in-flight requests and log them
        stale = self._sync_state.remove_stale_pibd_requests()
        if stale:
            log.debug("StateSync: %d stale segment requests removed", len(stale))

        # Apply any pending segments that have already been delivered
        applied = self._desegmenter.apply_next_segments()
        if applied > 0:
            log.debug("StateSync: applied %d segments", applied)

        # Work out how many new requests we can send
        in_flight = self._sync_state.pending_segment_count()
        headroom = SEGMENT_REQUEST_COUNT - in_flight
        if headroom <= 0:
            return True  # already at capacity

        desired = self._desegmenter.next_desired_segments(headroom)
        if not desired:
            return False  # nothing more to request

        peer_iter = iter(pibd_peers * ((len(desired) // len(pibd_peers)) + 1))
        for seg_type_id in desired:
            peer = next(peer_iter)
            ident = seg_type_id.identifier
            seg_type = seg_type_id.segment_type

            if seg_type == SegmentType.BITMAP:
                peer.request_bitmap_segment(archive_header_hash, ident)
            elif seg_type == SegmentType.OUTPUT:
                peer.request_output_segment(archive_header_hash, ident)
            elif seg_type == SegmentType.RANGEPROOF:
                peer.request_rangeproof_segment(archive_header_hash, ident)
            elif seg_type == SegmentType.KERNEL:
                peer.request_kernel_segment(archive_header_hash, ident)

            self._sync_state.add_pibd_segment_request(seg_type_id, peer.addr)
            log.debug(
                "StateSync: requested %s h=%d idx=%d from %s",
                seg_type.name,
                ident.height,
                ident.idx,
                peer.addr,
            )

        # Update progress
        p_applied, p_total = (
            int(self._desegmenter.progress_fraction() * 100),
            100,
        )
        self._sync_state.update_pibd_progress(p_applied, p_total)
        return True

    # ------------------------------------------------------------------
    # Snapshot (ZIP) fallback path
    # ------------------------------------------------------------------

    def _initiate_snapshot_sync(self, best_header_hash: bytes) -> bool:
        """Request a TxHashSet ZIP from a txhashset-capable peer.

        Verifies the archive block hash against the Stage-1 header chain
        before accepting the ZIP (preventing a rogue peer from supplying a
        mismatched snapshot).
        """
        peer = self._peers.txhashset_capable().highest_difficulty().pick()
        if peer is None:
            log.warning("StateSync: no txhashset-capable peer for snapshot fallback")
            return False

        if self._archive_header is None:
            log.warning("StateSync: no archive header set — cannot initiate snapshot")
            return False

        archive_hash = (
            self._archive_header.getHash()
            if hasattr(self._archive_header, "getHash")
            else best_header_hash
        )
        archive_height = getattr(self._archive_header, "height", 0)

        log.info(
            "StateSync: requesting TxHashSet snapshot from %s " "(hash=%s height=%d)",
            peer.addr,
            archive_hash.hex()[:12],
            archive_height,
        )

        self._snapshot_initiated = True
        self._snapshot_start = time.monotonic()
        self._sync_state.update(SyncStatus.TXHASHSET_DOWNLOAD)
        peer.request_txhashset(archive_hash, archive_height)
        return True

    def apply_snapshot(
        self,
        block_hash: bytes,
        height: int,
        zip_bytes: bytes,
        expected_output_root: bytes,
        expected_rangeproof_root: bytes,
        expected_kernel_root: bytes,
    ) -> bool:
        """Validate and apply a received TxHashSet ZIP.

        The ZIP is verified by:
          1. Extracting it into a temporary TxHashSet.
          2. Computing the PMMR roots.
          3. Comparing them against the roots from the Stage-1 header at
             *block_hash* (the ``expected_*_root`` parameters).

        Returns True on success; raises :class:`StateSyncError` on failure.
        """
        log.info(
            "StateSync: validating TxHashSet snapshot (hash=%s height=%d size=%d B)",
            block_hash.hex()[:12],
            height,
            len(zip_bytes),
        )
        self._sync_state.update(SyncStatus.TXHASHSET_VALIDATION)

        # Extract ZIP to a temp directory
        tmp_dir = self._data_dir / f"_snapshot_{block_hash.hex()[:16]}"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        zip_path = tmp_dir / "snapshot.zip"
        zip_path.write_bytes(zip_bytes)

        try:
            TxHashSetSync.extract(zip_path, tmp_dir)
        except (TxHashSetError, zipfile.BadZipFile, OSError, ValueError) as e:
            raise StateSyncError(f"Failed to extract snapshot ZIP: {e}") from e

        # Open the extracted TxHashSet and verify roots
        try:
            tmp_txhs = TxHashSet(tmp_dir)
            out_root = tmp_txhs.output_pmmr.root()
            rp_root = tmp_txhs.rangeproof_pmmr.root()
            kern_root = tmp_txhs.kernel_mmr.root()
            tmp_txhs.close()
        except Exception as e:
            raise StateSyncError(f"Cannot read extracted TxHashSet: {e}") from e

        if out_root != expected_output_root:
            raise StateSyncError(
                f"Snapshot output root mismatch: "
                f"got {out_root.hex()} expected {expected_output_root.hex()}"
            )
        if rp_root != expected_rangeproof_root:
            raise StateSyncError(
                f"Snapshot rangeproof root mismatch: "
                f"got {rp_root.hex()} expected {expected_rangeproof_root.hex()}"
            )
        if kern_root != expected_kernel_root:
            raise StateSyncError(
                f"Snapshot kernel root mismatch: "
                f"got {kern_root.hex()} expected {expected_kernel_root.hex()}"
            )

        log.info("StateSync: snapshot roots verified — applying to chain")
        # Move validated txhashset data into the live txhashset dir
        # (caller is responsible for this swap; we just confirm validity)
        return True

    # ------------------------------------------------------------------
    # Segment delivery callbacks (called from peer dispatch)
    # ------------------------------------------------------------------

    def receive_bitmap_segment(self, block_hash: bytes, segment) -> None:
        if self._desegmenter is None:
            return
        output_root = getattr(self._archive_header, "outputRoot", b"\x00" * 32)
        try:
            self._desegmenter.add_bitmap_segment(segment, output_root)
            sti = SegmentTypeIdentifier(
                segment_type=SegmentType.BITMAP, identifier=segment.identifier
            )
            self._sync_state.remove_pibd_segment_request(sti)
        except Exception as e:
            log.warning("Bad bitmap segment idx=%d: %s", segment.identifier.idx, e)

    def receive_output_segment(self, block_hash: bytes, segment) -> None:
        if self._desegmenter is None:
            return
        bitmap_root = self._desegmenter._bitmap.root(0) or b"\x00" * 32
        try:
            self._desegmenter.add_output_segment(segment, bitmap_root)
            sti = SegmentTypeIdentifier(
                segment_type=SegmentType.OUTPUT, identifier=segment.identifier
            )
            self._sync_state.remove_pibd_segment_request(sti)
        except Exception as e:
            log.warning("Bad output segment idx=%d: %s", segment.identifier.idx, e)

    def receive_rangeproof_segment(self, block_hash: bytes, segment) -> None:
        if self._desegmenter is None:
            return
        try:
            self._desegmenter.add_rangeproof_segment(segment)
            sti = SegmentTypeIdentifier(
                segment_type=SegmentType.RANGEPROOF, identifier=segment.identifier
            )
            self._sync_state.remove_pibd_segment_request(sti)
        except Exception as e:
            log.warning("Bad rangeproof segment idx=%d: %s", segment.identifier.idx, e)

    def receive_kernel_segment(self, block_hash: bytes, segment) -> None:
        if self._desegmenter is None:
            return
        try:
            self._desegmenter.add_kernel_segment(segment)
            sti = SegmentTypeIdentifier(
                segment_type=SegmentType.KERNEL, identifier=segment.identifier
            )
            self._sync_state.remove_pibd_segment_request(sti)
        except Exception as e:
            log.warning("Bad kernel segment idx=%d: %s", segment.identifier.idx, e)

    # ------------------------------------------------------------------
    # Finalisation
    # ------------------------------------------------------------------

    def _finalise(self) -> bool:
        """Validate and finalise the fully assembled TxHashSet."""
        assert self._desegmenter is not None
        log.info("StateSync: all segments received — validating complete state")
        try:
            self._desegmenter.check_update_leaf_set_state()
            self._desegmenter.validate_complete_state()
        except Exception as e:
            log.error("StateSync: final validation failed: %s", e)
            self._sync_state.update(SyncStatus.TXHASHSET_PIBD)
            return False

        self._sync_state.update(SyncStatus.BODY_SYNC)
        log.info("StateSync: PIBD sync complete — transitioning to body sync")
        return True
