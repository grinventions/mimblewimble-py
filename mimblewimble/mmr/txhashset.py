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
from io import BytesIO
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from mimblewimble.mmr.index import insertion_to_pmmr_index, n_leaves
from mimblewimble.mmr.pmmr import PMMR
from mimblewimble.mmr.proof import MerkleProof
from mimblewimble.serializer import EProtocolVersion, Serializer

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
