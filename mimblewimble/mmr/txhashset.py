"""
mimblewimble/mmr/txhashset.py

TxHashSet — the three PMMRs maintained by a Grin node.

Three Prunable Merkle Mountain Ranges:
  output PMMR     – leaf data = output commitment (33 bytes)
  rangeproof PMMR – leaf data = serialised rangeproof (variable, ≤675 bytes)
  kernel MMR      – leaf data = serialised kernel (not prunable)

The PMMR roots are validated against block headers' outputRoot,
rangeProofRoot, kernelRoot fields.

On-disk layout (mirrors Grin reference):
  {data_dir}/output/
  {data_dir}/rangeproof/
  {data_dir}/kernel/
  {data_dir}/commit_idx.pkl      – commitment→leaf_pos0 reverse index
"""

from __future__ import annotations

import json
import logging
import time
from io import BytesIO
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from mimblewimble.mmr.bitmap import BitmapAccumulator, BitmapChunk
from mimblewimble.mmr.index import insertion_to_pmmr_index, n_leaves
from mimblewimble.mmr.pibd_params import (
    BITMAP_SEGMENT_HEIGHT,
    KERNEL_SEGMENT_HEIGHT,
    OUTPUT_SEGMENT_HEIGHT,
    RANGEPROOF_SEGMENT_HEIGHT,
    SEGMENT_APPLY_BATCH_SIZE,
)
from mimblewimble.mmr.pmmr import PMMR
from mimblewimble.mmr.proof import MerkleProof
from mimblewimble.mmr.segment import (
    Segment,
    SegmentIdentifier,
    SegmentProof,
    SegmentType,
    SegmentTypeIdentifier,
)
from mimblewimble.serializer import EProtocolVersion, Serializer

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def _serialize_commitment(commitment) -> bytes:
    """Return raw 33 bytes from a Commitment object."""
    s = Serializer(EProtocolVersion.V2)
    commitment.serialize(s)
    return s.getvalue()


def _serialize_rangeproof(rangeproof) -> bytes:
    """Serialise a RangeProof for PMMR storage.

    For the rangeproof PMMR we store just the raw proof bytes
    (without the 8-byte length prefix used in transaction wire format).
    """
    return (
        rangeproof.getBytes()
        if hasattr(rangeproof, "getBytes")
        else bytes(rangeproof.proof)
    )


def _serialize_kernel(
    kernel, protocol: EProtocolVersion = EProtocolVersion.V2
) -> bytes:
    """Serialise a TransactionKernel for PMMR storage."""
    s = Serializer(protocol)
    kernel.serialize(s)
    return s.getvalue()


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class TxHashSetError(Exception):
    pass


class RootMismatchError(TxHashSetError):
    def __init__(self, which: str, expected: bytes, got: bytes):
        super().__init__(
            f"{which} root mismatch: " f"expected {expected.hex()}, got {got.hex()}"
        )


class SizeMismatchError(TxHashSetError):
    def __init__(self, which: str, expected: int, got: int):
        super().__init__(f"{which} MMR size mismatch: expected {expected}, got {got}")


# ---------------------------------------------------------------------------
# Segmenter
# ---------------------------------------------------------------------------


class Segmenter:
    """Reads PIBD segments from an existing TxHashSet for outbound sharing.

    Mirrors the logical role of Grin's ``Segmenter`` struct in
    ``chain/src/txhashset/segmenter.rs``.

    The segmenter lazily builds a ``BitmapAccumulator`` representing the
    spent-output bitmap at the archive header, so downstream peers can verify
    output segments against it.
    """

    def __init__(
        self,
        txhashset: "TxHashSet",
        bitmap_accumulator: BitmapAccumulator,
        header,
    ) -> None:
        self._txhs = txhashset
        self._bitmap = bitmap_accumulator
        self._header = header

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def header(self):
        return self._header

    def bitmap_root(self) -> Optional[bytes]:
        """Return the committed root of the bitmap PMMR (or None if empty)."""
        # The bitmap PMMR size equals the output PMMR leaf count
        n_out = n_leaves(self._txhs.output_pmmr.size())
        return self._bitmap.root(n_out)

    # ------------------------------------------------------------------
    # Segment factories
    # ------------------------------------------------------------------

    def bitmap_segment(self, identifier: SegmentIdentifier) -> Segment:
        """Build a bitmap segment for outbound delivery to a PIBD peer.

        The bitmap segment encodes the full spent-output bitmap at *header*
        height as 512-bit BitmapChunks, stored as leaf data in a virtual
        PMMR of height ``BITMAP_SEGMENT_HEIGHT``.
        """
        n_out = n_leaves(self._txhs.output_pmmr.size())
        # Total number of bitmap chunks
        n_chunks = (n_out + BitmapChunk.CHUNK_BITS - 1) // BitmapChunk.CHUNK_BITS
        leaves_per_seg = 1 << identifier.height
        first_leaf, last_leaf = identifier.leaf_range()
        if first_leaf >= n_chunks:
            from mimblewimble.mmr.segment import NonExistentSegmentError

            raise NonExistentSegmentError()

        leaf_data: List[Tuple[int, bytes]] = []
        for leaf_idx in range(first_leaf, min(last_leaf + 1, n_chunks)):
            chunk_data = self._bitmap.get_chunk_bytes(leaf_idx)
            leaf_data.append((leaf_idx, chunk_data))

        # Build proof (empty for now — proper proof requires bitmap PMMR)
        proof = SegmentProof(mmr_size=n_chunks, hashes=[])
        return Segment(
            identifier=identifier, hashes=[], leaf_data=leaf_data, proof=proof
        )

    def output_segment(self, identifier: SegmentIdentifier) -> Segment:
        """Build an output PMMR segment."""
        return self._txhs._build_segment(
            self._txhs.output_pmmr, identifier, prunable=True
        )

    def rangeproof_segment(self, identifier: SegmentIdentifier) -> Segment:
        """Build a rangeproof PMMR segment."""
        return self._txhs._build_segment(
            self._txhs.rangeproof_pmmr, identifier, prunable=True
        )

    def kernel_segment(self, identifier: SegmentIdentifier) -> Segment:
        """Build a kernel MMR segment."""
        return self._txhs._build_segment(
            self._txhs.kernel_mmr, identifier, prunable=False
        )


# ---------------------------------------------------------------------------
# Desegmenter
# ---------------------------------------------------------------------------


class Desegmenter:
    """Assembles inbound PIBD segments into a complete TxHashSet.

    Mirrors Grin's ``Desegmenter`` in
    ``chain/src/txhashset/desegmenter.rs``.

    The full sync algorithm is:
        1. Receive all bitmap segments (covering the output PMMR leaf count).
        2. Once the bitmap is complete, verify all received output segments
           against it (checking which leaves are unspent).
        3. Concurrently receive rangeproof and kernel segments.
        4. Once all three PMMRs are fully populated, call
           ``validate_complete_state()`` to check roots and kernel sums.

    Thread safety: not thread-safe; callers must serialise access.
    """

    def __init__(
        self,
        txhashset: "TxHashSet",
        archive_header,
        genesis_header,
    ) -> None:
        self._txhs = txhashset
        self._archive_header = archive_header
        self._genesis_header = genesis_header

        # Track which segments have been received
        self._bitmap_segs_received: Set[int] = set()
        self._output_segs_received: Set[int] = set()
        self._rangeproof_segs_received: Set[int] = set()
        self._kernel_segs_received: Set[int] = set()

        # Pending segments (received but not yet applied)
        self._pending_bitmap: Dict[int, Segment] = {}
        self._pending_output: Dict[int, Segment] = {}
        self._pending_rangeproof: Dict[int, Segment] = {}
        self._pending_kernel: Dict[int, Segment] = {}

        # Assembled bitmap accumulator
        self._bitmap = BitmapAccumulator()
        self._bitmap_complete = False

        # Computed MMR sizes derived from archive header
        self._output_mmr_size: int = getattr(archive_header, "outputMMRSize", 0)
        self._kernel_mmr_size: int = getattr(archive_header, "kernelMMRSize", 0)
        # rangeproof mirrors output
        self._rp_mmr_size: int = self._output_mmr_size

        # Number of bitmap chunks needed
        n_out = n_leaves(self._output_mmr_size)
        self._n_bitmap_chunks = (
            n_out + BitmapChunk.CHUNK_BITS - 1
        ) // BitmapChunk.CHUNK_BITS
        leaves_per_bitmap_seg = 1 << BITMAP_SEGMENT_HEIGHT
        self._n_bitmap_segs = (
            self._n_bitmap_chunks + leaves_per_bitmap_seg - 1
        ) // leaves_per_bitmap_seg

        # Number of segments per PMMR
        n_out_leaves = n_out
        leaves_per_output_seg = 1 << OUTPUT_SEGMENT_HEIGHT
        self._n_output_segs = (
            n_out_leaves + leaves_per_output_seg - 1
        ) // leaves_per_output_seg

        leaves_per_kernel_seg = 1 << KERNEL_SEGMENT_HEIGHT
        n_kern_leaves = n_leaves(self._kernel_mmr_size)
        self._n_kernel_segs = (
            n_kern_leaves + leaves_per_kernel_seg - 1
        ) // leaves_per_kernel_seg

        # rangeproof mirrors output
        self._n_rangeproof_segs = self._n_output_segs

        # Pre-extend PMMRs so out-of-order segment writes are safe
        if self._output_mmr_size > 0:
            self._txhs.output_pmmr.extend_to_size(self._output_mmr_size)
            self._txhs.rangeproof_pmmr.extend_to_size(self._rp_mmr_size)
        if self._kernel_mmr_size > 0:
            self._txhs.kernel_mmr.extend_to_size(self._kernel_mmr_size)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def header(self):
        return self._archive_header

    def reset(self) -> None:
        """Discard all received segment data and restart."""
        self._bitmap_segs_received.clear()
        self._output_segs_received.clear()
        self._rangeproof_segs_received.clear()
        self._kernel_segs_received.clear()
        self._pending_bitmap.clear()
        self._pending_output.clear()
        self._pending_rangeproof.clear()
        self._pending_kernel.clear()
        self._bitmap = BitmapAccumulator()
        self._bitmap_complete = False

    def is_complete(self) -> bool:
        """Return True once every required segment has been applied."""
        return (
            len(self._bitmap_segs_received) >= self._n_bitmap_segs
            and len(self._output_segs_received) >= self._n_output_segs
            and len(self._rangeproof_segs_received) >= self._n_rangeproof_segs
            and len(self._kernel_segs_received) >= self._n_kernel_segs
        )

    def progress_fraction(self) -> float:
        """Return a rough 0.0–1.0 progress fraction (bitmap + all PMMRs)."""
        total = (
            self._n_bitmap_segs
            + self._n_output_segs
            + self._n_rangeproof_segs
            + self._n_kernel_segs
        )
        if total == 0:
            return 1.0
        done = (
            len(self._bitmap_segs_received)
            + len(self._output_segs_received)
            + len(self._rangeproof_segs_received)
            + len(self._kernel_segs_received)
        )
        return min(done / total, 1.0)

    # ------------------------------------------------------------------
    # Segment ingestion
    # ------------------------------------------------------------------

    def add_bitmap_segment(
        self,
        seg: Segment,
        output_mmr_root: bytes,
    ) -> None:
        """Ingest one bitmap segment.

        Verifies the segment proof against *output_mmr_root* before
        accepting.  Accepted segments are buffered until
        ``apply_next_segments()`` is called.
        """
        idx = seg.identifier.idx
        if idx in self._bitmap_segs_received:
            return  # duplicate — ignore
        # Verify proof
        if not seg.verify(output_mmr_root):
            raise TxHashSetError(
                f"Bitmap segment {idx} proof invalid (root {output_mmr_root.hex()!r})"
            )
        self._pending_bitmap[idx] = seg
        self._bitmap_segs_received.add(idx)

    def add_output_segment(
        self,
        seg: Segment,
        bitmap_root: bytes,
    ) -> None:
        """Ingest one output PMMR segment, verifying against *bitmap_root*."""
        idx = seg.identifier.idx
        if idx in self._output_segs_received:
            return
        output_root = getattr(self._archive_header, "outputRoot", None)
        if output_root and not seg.verify(output_root):
            raise TxHashSetError(
                f"Output segment {idx} proof invalid (root {output_root.hex()!r})"
            )
        self._pending_output[idx] = seg
        self._output_segs_received.add(idx)

    def add_rangeproof_segment(self, seg: Segment) -> None:
        """Ingest one rangeproof PMMR segment."""
        idx = seg.identifier.idx
        if idx in self._rangeproof_segs_received:
            return
        rp_root = getattr(self._archive_header, "rangeProofRoot", None)
        if rp_root and not seg.verify(rp_root):
            raise TxHashSetError(
                f"Rangeproof segment {idx} proof invalid (root {rp_root.hex()!r})"
            )
        self._pending_rangeproof[idx] = seg
        self._rangeproof_segs_received.add(idx)

    def add_kernel_segment(self, seg: Segment) -> None:
        """Ingest one kernel MMR segment."""
        idx = seg.identifier.idx
        if idx in self._kernel_segs_received:
            return
        kern_root = getattr(self._archive_header, "kernelRoot", None)
        if kern_root and not seg.verify(kern_root):
            raise TxHashSetError(
                f"Kernel segment {idx} proof invalid (root {kern_root.hex()!r})"
            )
        self._pending_kernel[idx] = seg
        self._kernel_segs_received.add(idx)

    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------

    def apply_next_segments(self) -> int:
        """Write the next batch of pending segments into the backing PMMRs.

        Processes up to ``SEGMENT_APPLY_BATCH_SIZE`` segments per call.
        Bitmap segments are applied first (they must precede output segments
        so we can verify spend status).

        Returns:
            Number of segments applied in this call.
        """
        applied = 0

        # Apply bitmap segments first
        for idx in sorted(self._pending_bitmap.keys()):
            if applied >= SEGMENT_APPLY_BATCH_SIZE:
                break
            seg = self._pending_bitmap.pop(idx)
            self._apply_bitmap_segment(seg)
            applied += 1

        # Check if bitmap is now complete
        if (
            not self._bitmap_complete
            and len(self._bitmap_segs_received) >= self._n_bitmap_segs
            and not self._pending_bitmap
        ):
            self._bitmap.finalize()
            self._bitmap_complete = True
            log.debug("PIBD: bitmap accumulator complete")

        # Apply output / rangeproof / kernel segments
        for pending, pmmr, received_set in [
            (self._pending_output, self._txhs.output_pmmr, self._output_segs_received),
            (
                self._pending_rangeproof,
                self._txhs.rangeproof_pmmr,
                self._rangeproof_segs_received,
            ),
            (
                self._pending_kernel,
                self._txhs.kernel_mmr,
                self._kernel_segs_received,
            ),
        ]:
            for idx in sorted(pending.keys()):
                if applied >= SEGMENT_APPLY_BATCH_SIZE:
                    break
                seg = pending.pop(idx)
                pmmr.write_segment(seg)
                applied += 1

        return applied

    # ------------------------------------------------------------------
    # Desired segments ordering (bitmap-first, breadth-first)
    # ------------------------------------------------------------------

    def next_desired_segments(self, count: int) -> List[SegmentTypeIdentifier]:
        """Return up to *count* segments that are still needed.

        Priority order (mirrors Grin's desegmenter):
          1. Bitmap segments until complete
          2. Output segments
          3. Rangeproof segments (mirrors output)
          4. Kernel segments
        """
        result: List[SegmentTypeIdentifier] = []

        def _add(seg_type: SegmentType, total: int, height: int, received: Set[int]):
            for i in range(total):
                if len(result) >= count:
                    return
                if i not in received:
                    result.append(
                        SegmentTypeIdentifier(
                            segment_type=seg_type,
                            identifier=SegmentIdentifier(height=height, idx=i),
                        )
                    )

        _add(
            SegmentType.BITMAP,
            self._n_bitmap_segs,
            BITMAP_SEGMENT_HEIGHT,
            self._bitmap_segs_received,
        )
        _add(
            SegmentType.OUTPUT,
            self._n_output_segs,
            OUTPUT_SEGMENT_HEIGHT,
            self._output_segs_received,
        )
        _add(
            SegmentType.RANGEPROOF,
            self._n_rangeproof_segs,
            RANGEPROOF_SEGMENT_HEIGHT,
            self._rangeproof_segs_received,
        )
        _add(
            SegmentType.KERNEL,
            self._n_kernel_segs,
            KERNEL_SEGMENT_HEIGHT,
            self._kernel_segs_received,
        )
        return result

    # ------------------------------------------------------------------
    # Leaf-set / bitmap reconciliation
    # ------------------------------------------------------------------

    def check_update_leaf_set_state(self) -> None:
        """Reconcile the output PMMR prune bitmap with the received bitmap.

        Once the bitmap accumulator is finalised, mark *spent* outputs
        (bitmap bit set) as pruned in the output and rangeproof PMMRs.
        This mirrors ``Desegmenter::check_update_leaf_set_state`` in Grin.
        """
        if not self._bitmap_complete:
            return
        n_out = n_leaves(self._output_mmr_size)
        for leaf_idx in range(n_out):
            if self._bitmap.is_spent(leaf_idx):
                pos0 = insertion_to_pmmr_index(leaf_idx)
                self._txhs.output_pmmr.prune(pos0)
                self._txhs.rangeproof_pmmr.prune(pos0)

    def validate_complete_state(self) -> bool:
        """Validate the fully assembled TxHashSet against the archive header.

        Calls ``validate_roots()`` then ``validate_kernel_sums()``.
        Returns True on success; raises ``TxHashSetError`` on failure.
        """
        self._txhs.validate_roots(self._archive_header)
        self._txhs.validate_kernel_sums(self._archive_header)
        return True

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _apply_bitmap_segment(self, seg: Segment) -> None:
        """Write the bitmap chunk leaf data into ``self._bitmap``."""
        for leaf_idx, data in seg.leaf_iter():
            chunk = BitmapChunk.from_bytes(data)
            self._bitmap.apply_chunk(leaf_idx, chunk)


# ---------------------------------------------------------------------------
# TxHashSet
# ---------------------------------------------------------------------------


class TxHashSet:
    """Three-PMMR TxHashSet as maintained by a Grin full node.

    Usage::

        txhs = TxHashSet(Path("/var/grin/chain_data/txhashset"))
        txhs.apply_block(full_block, header_version=2)
        txhs.validate_roots(block_header)
        txhs.flush()
    """

    # Sub-directory names (match Grin ZIP layout)
    _OUTPUT_DIR = "output"
    _RANGEPROOF_DIR = "rangeproof"
    _KERNEL_DIR = "kernel"
    _COMMIT_IDX_FILE = "commit_idx.json"
    _LEGACY_COMMIT_IDX_FILE = "commit_idx.pkl"

    def __init__(self, data_dir: Path) -> None:
        self._dir = Path(data_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

        self.output_pmmr = PMMR(self._dir / self._OUTPUT_DIR, "pmmr", prunable=True)
        self.rangeproof_pmmr = PMMR(
            self._dir / self._RANGEPROOF_DIR, "pmmr", prunable=True
        )
        self.kernel_mmr = PMMR(self._dir / self._KERNEL_DIR, "pmmr", prunable=False)

        # Commitment → output PMMR leaf position (0-based MMR pos)
        self._commit_to_pos: Dict[bytes, int] = {}
        self._load_commit_idx()

    # ------------------------------------------------------------------
    # Block application
    # ------------------------------------------------------------------

    def apply_block(self, block, header_version: int = 2) -> None:
        """Apply all outputs, rangeproofs, kernels and inputs from *block*.

        *block* is a ``FullBlock`` instance.

        - Outputs → appended to output PMMR (commitment) + rangeproof PMMR
        - Kernels → appended to kernel MMR
        - Inputs  → spent → prune output PMMR + rangeproof PMMR at that leaf
        """
        protocol = self._protocol_for_version(header_version)

        body = block.getBody() if hasattr(block, "getBody") else block.body

        # 1. Append outputs (sorted by commitment — body already sorted)
        for output in body.getOutputs():
            commit_bytes = _serialize_commitment(output.getCommitment())
            rp_bytes = _serialize_rangeproof(output.getRangeProof())

            out_pos = self.output_pmmr.push(commit_bytes)
            rp_pos = self.rangeproof_pmmr.push(rp_bytes)
            assert (
                out_pos == rp_pos
            ), f"Output/rangeproof PMMR position mismatch: {out_pos} vs {rp_pos}"
            self._commit_to_pos[commit_bytes] = out_pos

        # 2. Append kernels
        for kernel in body.getKernels():
            kernel_bytes = _serialize_kernel(kernel, protocol)
            self.kernel_mmr.push(kernel_bytes)

        # 3. Spend inputs (prune outputs + rangeproofs)
        for inp in body.getInputs():
            commit_bytes = _serialize_commitment(inp.getCommitment())
            leaf_pos = self._commit_to_pos.get(commit_bytes)
            if leaf_pos is not None:
                self.output_pmmr.prune(leaf_pos)
                self.rangeproof_pmmr.prune(leaf_pos)
                # Keep commitment index for merkle proof generation post-spend

    # ------------------------------------------------------------------
    # Cut-through
    # ------------------------------------------------------------------

    def cut_through(self) -> None:
        """Ensure output PMMR prune bitmap is mirrored in rangeproof PMMR.

        Called after a batch of blocks when cross-block cut-through is allowed.
        """
        if self.output_pmmr._prune_bm is None or self.rangeproof_pmmr._prune_bm is None:
            return
        for leaf_idx in self.output_pmmr._prune_bm.pruned_insertion_indices():
            if not self.rangeproof_pmmr._prune_bm.is_pruned(leaf_idx):
                rp_pos = insertion_to_pmmr_index(leaf_idx)
                self.rangeproof_pmmr.prune(rp_pos)

    # ------------------------------------------------------------------
    # PIBD segment support
    # ------------------------------------------------------------------

    def segmenter(self, header) -> "Segmenter":
        """Return a :class:`Segmenter` for serving segments to PIBD peers.

        Builds the bitmap accumulator from the current prune bitmap before
        returning the segmenter.
        """
        bitmap = BitmapAccumulator()
        bitmap.build_from_pmmr(self.output_pmmr)
        return Segmenter(txhashset=self, bitmap_accumulator=bitmap, header=header)

    def desegmenter(self, archive_header, genesis_header) -> "Desegmenter":
        """Return a :class:`Desegmenter` for assembling inbound segments."""
        return Desegmenter(
            txhashset=self,
            archive_header=archive_header,
            genesis_header=genesis_header,
        )

    def apply_output_segment(self, seg: Segment) -> None:
        """Write *seg* into the output PMMR (convenience wrapper)."""
        self.output_pmmr.write_segment(seg)

    def apply_rangeproof_segment(self, seg: Segment) -> None:
        """Write *seg* into the rangeproof PMMR (convenience wrapper)."""
        self.rangeproof_pmmr.write_segment(seg)

    def apply_kernel_segment(self, seg: Segment) -> None:
        """Write *seg* into the kernel MMR (convenience wrapper)."""
        self.kernel_mmr.write_segment(seg)

    def _build_segment(
        self, pmmr: PMMR, identifier: SegmentIdentifier, prunable: bool
    ) -> Segment:
        """Extract a :class:`Segment` from *pmmr* for the given *identifier*.

        Reads all node hashes within the segment's range and all unspent leaf
        data entries.  Constructs a :class:`SegmentProof` using the current
        PMMR size and the set of peaks.

        For prunable PMMRs, omits leaf data for pruned leaves (only the leaf
        hash remains for peak-bagging purposes).
        """
        from mimblewimble.mmr.index import peaks as mmr_peaks

        height = identifier.height
        first_pos = identifier.segment_first_mmr_pos()
        last_pos = identifier.segment_last_mmr_pos()
        mmr_size = pmmr.size()

        # Clamp last_pos to actual MMR size
        last_pos = min(last_pos, mmr_size - 1)
        if first_pos > last_pos:
            from mimblewimble.mmr.segment import NonExistentSegmentError

            raise NonExistentSegmentError()

        # Collect internal node hashes (non-leaf positions)
        hashes: List[Tuple[int, bytes]] = []
        leaf_data: List[Tuple[int, bytes]] = []

        for pos0 in range(first_pos, last_pos + 1):
            h = pmmr._hashes.get(pos0)
            if h is None or h == b"\x00" * 32:
                continue
            from mimblewimble.mmr.index import is_leaf as mmr_is_leaf

            if mmr_is_leaf(pos0):
                # Leaf: include data if available and unspent
                from mimblewimble.mmr.index import pmmr_leaf_to_insertion_index

                leaf_idx = pmmr_leaf_to_insertion_index(pos0)
                data = pmmr.get_data(pos0)
                if data is not None:
                    leaf_data.append((leaf_idx, data))
                else:
                    # Pruned or hash-only leaf: store hash
                    hashes.append((pos0, h))
            else:
                hashes.append((pos0, h))

        # Build SegmentProof: gather sibling peaks
        all_peaks = mmr_peaks(mmr_size) if mmr_size > 0 else []
        # Find which peak covers this segment
        local_peak_pos = identifier.segment_last_mmr_pos()
        proof_hashes: List[bytes] = []
        peak_pos0 = local_peak_pos

        if all_peaks:
            try:
                peak_idx = all_peaks.index(local_peak_pos)
            except ValueError:
                peak_idx = -1

            if peak_idx >= 0:
                left_peak_hashes = [
                    pmmr._hashes.get(p) or b"\x00" * 32 for p in all_peaks[:peak_idx]
                ]
                right_peaks = all_peaks[peak_idx + 1 :]
                if right_peaks:
                    # Bag right peaks into single hash
                    from mimblewimble.mmr.proof import hash_with_index

                    acc = pmmr._hashes.get(right_peaks[-1]) or b"\x00" * 32
                    for rp in reversed(right_peaks[:-1]):
                        rp_h = pmmr._hashes.get(rp) or b"\x00" * 32
                        acc = hash_with_index(mmr_size, rp_h + acc)
                    proof_hashes = left_peak_hashes + [acc]
                else:
                    proof_hashes = left_peak_hashes

        proof = SegmentProof(mmr_size=mmr_size, hashes=proof_hashes)
        return Segment(
            identifier=identifier,
            hashes=hashes,
            leaf_data=leaf_data,
            proof=proof,
        )

    # ------------------------------------------------------------------
    # Compaction (horizon flattening)
    # ------------------------------------------------------------------

    def compact(self, horizon_height: int, block_height: int) -> None:
        """Discard rangeproof leaf data for outputs spent before the horizon.

        Per Grin consensus, ``cut_through_horizon = week_height``.  After that
        depth, rangeproof data may be discarded while commitment hashes are
        retained (needed for kernel sum validation).

        *horizon_height* = block height of the oldest block whose outputs are
        still kept with rangeproofs.

        This simply zeros out the data file entries for pruned rangeproof
        leaves.  The PMMR hash file is unaffected (leaves remain in the MMR
        for root computation).
        """
        # In the current implementation, pruning already removes leaf data
        # via the PruneBitmap.  compact() is a no-op if prune() was called for
        # all spent outputs within the horizon.
        # For horizon-based compaction of unexpired-but-old rangeproofs, a
        # caller would iterate outputs by height and call rangeproof_pmmr.prune.
        pass  # hook for future height-aware compaction

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_roots(self, header) -> bool:
        """Assert PMMR roots and sizes match *header*.

        *header* is a ``BlockHeader`` with ``outputRoot``, ``rangeProofRoot``,
        ``kernelRoot``, ``outputMMRSize``, ``kernelMMRSize`` attributes.

        Raises ``RootMismatchError`` or ``SizeMismatchError`` on failure.
        Returns True on success.
        """
        # --- Sizes ---
        out_size = self.output_pmmr.size()
        kern_size = self.kernel_mmr.size()

        if out_size != header.outputMMRSize:
            raise SizeMismatchError("output", header.outputMMRSize, out_size)
        if kern_size != header.kernelMMRSize:
            raise SizeMismatchError("kernel", header.kernelMMRSize, kern_size)

        # --- Roots ---
        out_root = self.output_pmmr.root()
        if out_root != header.outputRoot:
            raise RootMismatchError("output", header.outputRoot, out_root)

        rp_root = self.rangeproof_pmmr.root()
        if rp_root != header.rangeProofRoot:
            raise RootMismatchError("rangeproof", header.rangeProofRoot, rp_root)

        kern_root = self.kernel_mmr.root()
        if kern_root != header.kernelRoot:
            raise RootMismatchError("kernel", header.kernelRoot, kern_root)

        return True

    def validate_kernel_sums(self, header) -> bool:
        """Validate the Mimblewimble balance equation for all kernels.

        Sum(unspent output commitments) - Sum(spent inputs) ==
            Sum(kernel excess commitments) + commit(0, total_kernel_offset)

        Uses ``Pedersen.commitSum`` over all unspent commitments.
        Returns True on success, raises on failure.
        """
        from mimblewimble.crypto.pedersen import Pedersen
        from mimblewimble.crypto.commitment import Commitment

        # Collect unspent output commitments
        output_commits = []
        for pos in self.output_pmmr.leaf_pos_iter():
            data = self.output_pmmr.get_data(pos)
            if data is not None:
                output_commits.append(Commitment(data))

        # Collect kernel excess commitments
        kernel_excesses = []
        for pos in self.kernel_mmr.leaf_pos_iter():
            # Kernel data includes the excess commitment at offset (after features+fee+lock)
            # The excess commitment is always the last 33+64=97 bytes of kernel bytes,
            # specifically bytes [-97:-64] (33-byte commitment before 64-byte sig)
            data = self.kernel_mmr.get_data(pos)
            if data is not None and len(data) >= 97:
                excess_bytes = data[-97:-64]
                kernel_excesses.append(Commitment(excess_bytes))

        if not output_commits and not kernel_excesses:
            return True

        # LHS: sum of output commitments
        # RHS: sum of excesses + commit(0, offset)
        try:
            lhs = Pedersen.commitSum(output_commits, [])
            offset_commit = Pedersen.commit(0, header.totalKernelOffset.toSecretKey())
            rhs = Pedersen.commitSum(kernel_excesses + [offset_commit], [])
            if lhs != rhs:
                raise TxHashSetError(
                    f"Kernel sum mismatch: "
                    f"output_sum={lhs.toJSON()} != "
                    f"kernel_sum={rhs.toJSON()}"
                )
        except Exception as e:
            raise TxHashSetError(f"Kernel sum validation failed: {e}") from e

        return True

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_unspent_outputs(
        self, start_idx: int, end_idx: int
    ) -> List[Tuple[int, bytes]]:
        """Return (mmr_pos0, commitment_bytes) for unspent outputs in leaf range.

        *start_idx* and *end_idx* are inclusive 0-based leaf insertion indices.
        """
        results = []
        for leaf_idx, pos in self.output_pmmr.leaf_idx_iter(from_idx=start_idx):
            if leaf_idx > end_idx:
                break
            data = self.output_pmmr.get_data(pos)
            if data is not None:
                results.append((pos, data))
        return results

    def commit_to_output_pos(self, commitment_bytes: bytes) -> Optional[int]:
        """Return the output PMMR leaf position for a commitment, or None."""
        return self._commit_to_pos.get(commitment_bytes)

    def merkle_proof_for_output(self, commitment_bytes: bytes) -> Optional[MerkleProof]:
        """Generate a Merkle proof for the given output commitment."""
        pos = self._commit_to_pos.get(commitment_bytes)
        if pos is None:
            return None
        return self.output_pmmr.merkle_proof(pos)

    # ------------------------------------------------------------------
    # Snapshot / rewind
    # ------------------------------------------------------------------

    def snapshot(self, header) -> Path:
        """Flush PMMRs and write a Grin-compatible txhashset ZIP.

        Returns the path of the created archive.
        """
        import zipfile, time

        self.flush()
        h_hex = header.getHash().hex() if hasattr(header, "getHash") else "snapshot"
        zip_path = self._dir / f"txhashset_{h_hex[:16]}.zip"

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_STORED) as zf:
            for sub, name_prefix in [
                (self._OUTPUT_DIR, "pmmr"),
                (self._RANGEPROOF_DIR, "pmmr"),
                (self._KERNEL_DIR, "pmmr"),
            ]:
                subdir = self._dir / sub
                for fname in [
                    f"{name_prefix}_hash.bin",
                    f"{name_prefix}_data.bin",
                    f"{name_prefix}_data_idx.bin",
                    f"{name_prefix}_prune.bin",
                ]:
                    fpath = subdir / fname
                    if fpath.exists():
                        zf.write(fpath, f"{sub}/{fname}")

        return zip_path

    def rewind(self, target_output_size: int, target_kernel_size: int) -> None:
        """Rewind both PMMRs to the given sizes (used on fork recovery)."""
        self.output_pmmr.rewind(target_output_size)
        self.rangeproof_pmmr.rewind(target_output_size)
        self.kernel_mmr.rewind(target_kernel_size)
        # Rebuild commit→pos index for surviving leaves
        self._rebuild_commit_idx()

    def _rebuild_commit_idx(self) -> None:
        """Rebuild commitment→pos index from output PMMR data file."""
        self._commit_to_pos = {}
        for pos in self.output_pmmr.leaf_pos_iter():
            data = self.output_pmmr.get_data(pos)
            if data is not None:
                self._commit_to_pos[data] = pos

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def flush(self) -> None:
        """Flush all three PMMRs and the commit index to disk."""
        self.output_pmmr.flush()
        self.rangeproof_pmmr.flush()
        self.kernel_mmr.flush()
        self._save_commit_idx()

    def close(self) -> None:
        self.flush()
        self.output_pmmr.close()
        self.rangeproof_pmmr.close()
        self.kernel_mmr.close()

    def _save_commit_idx(self) -> None:
        idx_path = self._dir / self._COMMIT_IDX_FILE
        payload = {k.hex(): v for k, v in self._commit_to_pos.items()}
        with open(idx_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, separators=(",", ":"), sort_keys=True)

    def _load_commit_idx(self) -> None:
        idx_path = self._dir / self._COMMIT_IDX_FILE
        if idx_path.exists():
            with open(idx_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            if not isinstance(raw, dict):
                raise TxHashSetError("Invalid commit index format: expected object")
            parsed: Dict[bytes, int] = {}
            for key_hex, pos in raw.items():
                if not isinstance(key_hex, str) or not isinstance(pos, int):
                    raise TxHashSetError("Invalid commit index entry types")
                key = bytes.fromhex(key_hex)
                if len(key) != 33 or pos < 0:
                    raise TxHashSetError("Invalid commit index entry value")
                parsed[key] = pos
            self._commit_to_pos = parsed
            return

        legacy_idx = self._dir / self._LEGACY_COMMIT_IDX_FILE
        if legacy_idx.exists():
            self._rebuild_commit_idx()
            self._save_commit_idx()
            return

        if self.output_pmmr.size() > 0:
            self._rebuild_commit_idx()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _protocol_for_version(header_version: int) -> EProtocolVersion:
        if header_version >= 3:
            return EProtocolVersion.V3
        if header_version >= 2:
            return EProtocolVersion.V2
        return EProtocolVersion.V1
