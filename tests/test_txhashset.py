"""
tests/test_txhashset.py

Integration tests for TxHashSet and its three underlying PMMRs.

These tests exercise the TxHashSet API using synthetic data pushed directly
through the PMMR layer — no full Grin block objects are required.
This makes the suite self-contained and runnable without a live node.

Where a realistic test is carried out (e.g. validate_roots), a minimal mock
header is constructed whose roots and sizes are derived from the actual PMMRs
contents so the assertion trivially passes — the important thing verified is
that the plumbing between PMMR.root() / PMMR.size() and TxHashSet is correct.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers shared across tests
# ---------------------------------------------------------------------------


def _make_commit(seed: int) -> bytes:
    """Return a fake 33-byte commitment deterministically from seed."""
    return hashlib.sha256(f"commit-{seed}".encode()).digest()[:32] + b"\x02"


def _make_rangeproof(seed: int) -> bytes:
    """Return fake rangeproof bytes deterministically from seed (675 bytes)."""
    raw = hashlib.sha256(f"rp-{seed}".encode()).digest()
    # Repeat to get 675 bytes (typical Grin rangeproof size)
    return (raw * 22)[:675]


def _make_kernel(seed: int) -> bytes:
    """Return fake serialised kernel bytes (97 bytes: 1 feature + 8 fee + 24 + 33 excess + 64 sig)."""
    raw = hashlib.sha256(f"kern-{seed}".encode()).digest()
    return (raw * 4)[:97]


class _MockHeader:
    """Minimal header duck-type satisfying TxHashSet.validate_roots()."""

    def __init__(
        self, output_root, rp_root, kernel_root, output_mmr_size, kernel_mmr_size
    ):
        self.outputRoot = output_root
        self.rangeProofRoot = rp_root
        self.kernelRoot = kernel_root
        self.outputMMRSize = output_mmr_size
        self.kernelMMRSize = kernel_mmr_size


# ---------------------------------------------------------------------------
# Base test case that sets up a temp directory and TxHashSet
# ---------------------------------------------------------------------------


class TxHashSetTestBase(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="txhashset_test_")
        self._data_dir = Path(self._tmpdir)
        # Import lazily so the module is not required at collection time
        from mimblewimble.mmr.txhashset import TxHashSet

        self._TxHashSet = TxHashSet
        self.txhs = TxHashSet(self._data_dir)

    def tearDown(self):
        try:
            self.txhs.close()
        except Exception:
            pass
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def _push_output(self, seed: int) -> int:
        """Push commit+rangeproof for *seed*; returns MMR leaf position."""
        commit = _make_commit(seed)
        rp = _make_rangeproof(seed)
        pos = self.txhs.output_pmmr.push(commit)
        rp_pos = self.txhs.rangeproof_pmmr.push(rp)
        self.txhs._commit_to_pos[commit] = pos
        assert pos == rp_pos
        return pos

    def _push_kernel(self, seed: int) -> int:
        """Push a fake kernel; returns MMR leaf position."""
        return self.txhs.kernel_mmr.push(_make_kernel(seed))


# ===========================================================================
# 1. Creation & empty state
# ===========================================================================


class TestTxHashSetEmpty(TxHashSetTestBase):
    """An empty TxHashSet has size 0 and raises on root() (no leaves)."""

    def test_empty_output_size(self):
        self.assertEqual(self.txhs.output_pmmr.size(), 0)

    def test_empty_rangeproof_size(self):
        self.assertEqual(self.txhs.rangeproof_pmmr.size(), 0)

    def test_empty_kernel_size(self):
        self.assertEqual(self.txhs.kernel_mmr.size(), 0)

    def test_empty_dirs_created(self):
        self.assertTrue((self._data_dir / "output").is_dir())
        self.assertTrue((self._data_dir / "rangeproof").is_dir())
        self.assertTrue((self._data_dir / "kernel").is_dir())


# ===========================================================================
# 2. Push outputs and kernels; check sizes and data retrieval
# ===========================================================================


class TestTxHashSetPush(TxHashSetTestBase):

    def setUp(self):
        super().setUp()
        # Push 5 outputs + 5 kernels
        self._out_positions = [self._push_output(i) for i in range(5)]
        self._kern_positions = [self._push_kernel(i) for i in range(5)]

    def test_output_mmr_size(self):
        # 5 leaves → MMR with internal nodes
        # n=5 leaves → nodes: 0,1,2(parent01),3,4,5(parent34) — actually
        # pmmr for 5 leaves has 8 positions (0..7)
        from mimblewimble.mmr.index import insertion_to_pmmr_index

        # The last leaf position + 1 ... just verify it's > 0
        self.assertGreater(self.txhs.output_pmmr.size(), 0)

    def test_output_leaf_count(self):
        from mimblewimble.mmr.index import n_leaves

        self.assertEqual(n_leaves(self.txhs.output_pmmr.size()), 5)

    def test_kernel_leaf_count(self):
        from mimblewimble.mmr.index import n_leaves

        self.assertEqual(n_leaves(self.txhs.kernel_mmr.size()), 5)

    def test_output_rangeproof_same_size(self):
        self.assertEqual(self.txhs.output_pmmr.size(), self.txhs.rangeproof_pmmr.size())

    def test_get_output_data(self):
        pos0 = self._out_positions[0]
        commit = _make_commit(0)
        retrieved = self.txhs.output_pmmr.get_data(pos0)
        self.assertEqual(retrieved, commit)

    def test_get_rangeproof_data(self):
        rp = _make_rangeproof(2)
        pos2 = self._out_positions[2]
        retrieved = self.txhs.rangeproof_pmmr.get_data(pos2)
        self.assertEqual(retrieved, rp)

    def test_get_kernel_data(self):
        kern = _make_kernel(1)
        pos = self._kern_positions[1]
        retrieved = self.txhs.kernel_mmr.get_data(pos)
        self.assertEqual(retrieved, kern)

    def test_commit_to_pos_index(self):
        for i, pos in enumerate(self._out_positions):
            commit = _make_commit(i)
            self.assertEqual(self.txhs.commit_to_output_pos(commit), pos)

    def test_commit_to_pos_unknown(self):
        unknown = _make_commit(99)
        self.assertIsNone(self.txhs.commit_to_output_pos(unknown))


# ===========================================================================
# 3. Root computation
# ===========================================================================


class TestTxHashSetRoot(TxHashSetTestBase):

    def setUp(self):
        super().setUp()
        for i in range(3):
            self._push_output(i)
            self._push_kernel(i)

    def test_output_root_is_bytes32(self):
        root = self.txhs.output_pmmr.root()
        self.assertIsInstance(root, bytes)
        self.assertEqual(len(root), 32)

    def test_rangeproof_root_is_bytes32(self):
        root = self.txhs.rangeproof_pmmr.root()
        self.assertIsInstance(root, bytes)
        self.assertEqual(len(root), 32)

    def test_kernel_root_is_bytes32(self):
        root = self.txhs.kernel_mmr.root()
        self.assertIsInstance(root, bytes)
        self.assertEqual(len(root), 32)

    def test_different_data_different_root(self):
        # Roots for output vs rangeproof differ because data differs
        self.assertNotEqual(
            self.txhs.output_pmmr.root(), self.txhs.rangeproof_pmmr.root()
        )

    def test_root_changes_after_push(self):
        root_before = self.txhs.output_pmmr.root()
        self._push_output(99)
        root_after = self.txhs.output_pmmr.root()
        self.assertNotEqual(root_before, root_after)

    def test_root_deterministic(self):
        # Build an identical second TxHashSet in another temp dir
        tmpdir2 = tempfile.mkdtemp(prefix="txhashset_dup_")
        try:
            from mimblewimble.mmr.txhashset import TxHashSet

            txhs2 = TxHashSet(Path(tmpdir2))
            for i in range(3):
                commit = _make_commit(i)
                rp = _make_rangeproof(i)
                txhs2.output_pmmr.push(commit)
                txhs2.rangeproof_pmmr.push(rp)
                txhs2._commit_to_pos[commit] = txhs2.output_pmmr.size() - 1
                txhs2.kernel_mmr.push(_make_kernel(i))
            self.assertEqual(self.txhs.output_pmmr.root(), txhs2.output_pmmr.root())
            txhs2.close()
        finally:
            shutil.rmtree(tmpdir2, ignore_errors=True)


# ===========================================================================
# 4. validate_roots
# ===========================================================================


class TestValidateRoots(TxHashSetTestBase):

    def setUp(self):
        super().setUp()
        for i in range(4):
            self._push_output(i)
            self._push_kernel(i)

    def _make_header(self):
        return _MockHeader(
            output_root=self.txhs.output_pmmr.root(),
            rp_root=self.txhs.rangeproof_pmmr.root(),
            kernel_root=self.txhs.kernel_mmr.root(),
            output_mmr_size=self.txhs.output_pmmr.size(),
            kernel_mmr_size=self.txhs.kernel_mmr.size(),
        )

    def test_validate_roots_pass(self):
        header = self._make_header()
        self.assertTrue(self.txhs.validate_roots(header))

    def test_validate_roots_wrong_output_root(self):
        from mimblewimble.mmr.txhashset import RootMismatchError

        header = self._make_header()
        header.outputRoot = b"\x00" * 32
        with self.assertRaises(RootMismatchError):
            self.txhs.validate_roots(header)

    def test_validate_roots_wrong_rp_root(self):
        from mimblewimble.mmr.txhashset import RootMismatchError

        header = self._make_header()
        header.rangeProofRoot = b"\xff" * 32
        with self.assertRaises(RootMismatchError):
            self.txhs.validate_roots(header)

    def test_validate_roots_wrong_kernel_root(self):
        from mimblewimble.mmr.txhashset import RootMismatchError

        header = self._make_header()
        header.kernelRoot = b"\xab" * 32
        with self.assertRaises(RootMismatchError):
            self.txhs.validate_roots(header)

    def test_validate_roots_wrong_output_size(self):
        from mimblewimble.mmr.txhashset import SizeMismatchError

        header = self._make_header()
        header.outputMMRSize += 1
        with self.assertRaises(SizeMismatchError):
            self.txhs.validate_roots(header)

    def test_validate_roots_wrong_kernel_size(self):
        from mimblewimble.mmr.txhashset import SizeMismatchError

        header = self._make_header()
        header.kernelMMRSize += 1
        with self.assertRaises(SizeMismatchError):
            self.txhs.validate_roots(header)


# ===========================================================================
# 5. Prune / cut_through
# ===========================================================================


class TestPruneAndCutThrough(TxHashSetTestBase):

    def setUp(self):
        super().setUp()
        # Push 6 outputs + kernels
        self._positions = [self._push_output(i) for i in range(6)]
        for i in range(6):
            self._push_kernel(i)

    def test_prune_output_removes_data(self):
        pos = self._positions[0]
        self.assertIsNotNone(self.txhs.output_pmmr.get_data(pos))
        self.txhs.output_pmmr.prune(pos)
        self.assertIsNone(self.txhs.output_pmmr.get_data(pos))

    def test_prune_rangeproof_removes_data(self):
        pos = self._positions[1]
        self.assertIsNotNone(self.txhs.rangeproof_pmmr.get_data(pos))
        self.txhs.rangeproof_pmmr.prune(pos)
        self.assertIsNone(self.txhs.rangeproof_pmmr.get_data(pos))

    def test_root_unchanged_after_prune_leaf(self):
        """Pruning leaf data does not alter the MMR root hash."""
        root_before = self.txhs.output_pmmr.root()
        self.txhs.output_pmmr.prune(self._positions[2])
        root_after = self.txhs.output_pmmr.root()
        self.assertEqual(root_before, root_after)

    def test_cut_through_syncs_rangeproof_prune(self):
        """output PMMR prune bitmap mirrors into rangeproof PMMR after cut_through."""
        # Prune output leaf 0 manually (don't prune rangeproof yet)
        pos0 = self._positions[0]
        self.txhs.output_pmmr.prune(pos0)
        # RangeProof still has data before cut_through
        self.assertIsNotNone(self.txhs.rangeproof_pmmr.get_data(pos0))
        # Now run cut_through
        self.txhs.cut_through()
        # RangeProof should be pruned now
        self.assertIsNone(self.txhs.rangeproof_pmmr.get_data(pos0))

    def test_unspent_outputs_excludes_pruned(self):
        """get_unspent_outputs skips pruned leaves."""
        pos = self._positions[0]
        self.txhs.output_pmmr.prune(pos)
        unspent = self.txhs.get_unspent_outputs(0, 99)
        spent_commits = {_make_commit(0)}
        retrieved_commits = {c for _, c in unspent}
        self.assertFalse(
            spent_commits & retrieved_commits,
            "Pruned commitment should not appear in unspent outputs",
        )

    def test_n_unpruned_leaves(self):
        # Prune 2 out of 6
        for i in [0, 1]:
            self.txhs.output_pmmr.prune(self._positions[i])
        self.assertEqual(self.txhs.output_pmmr.n_unpruned_leaves(), 4)


# ===========================================================================
# 6. Rewind
# ===========================================================================


class TestRewind(TxHashSetTestBase):

    def setUp(self):
        super().setUp()
        # Push 8 outputs + kernels, saving checkpoint at 4
        for i in range(8):
            self._push_output(i)
            self._push_kernel(i)
        self._size_at_4_out = None
        self._size_at_4_kern = None
        self._root_at_4_out = None
        self._root_at_4_kern = None

    def _record_checkpoint_at_4(self):
        """Build a second TxHashSet with 4 items to capture expected roots."""
        tmpdir2 = tempfile.mkdtemp(prefix="txhashset_chk_")
        try:
            from mimblewimble.mmr.txhashset import TxHashSet

            txhs2 = TxHashSet(Path(tmpdir2))
            for i in range(4):
                txhs2.output_pmmr.push(_make_commit(i))
                txhs2.rangeproof_pmmr.push(_make_rangeproof(i))
                txhs2.kernel_mmr.push(_make_kernel(i))
            result = (
                txhs2.output_pmmr.size(),
                txhs2.kernel_mmr.size(),
                txhs2.output_pmmr.root(),
                txhs2.kernel_mmr.root(),
            )
            txhs2.close()
        finally:
            shutil.rmtree(tmpdir2, ignore_errors=True)
        return result

    def test_rewind_size(self):
        expected_out_size, expected_kern_size, _, _ = self._record_checkpoint_at_4()
        self.txhs.rewind(expected_out_size, expected_kern_size)
        self.assertEqual(self.txhs.output_pmmr.size(), expected_out_size)
        self.assertEqual(self.txhs.kernel_mmr.size(), expected_kern_size)

    def test_rewind_root_matches_checkpoint(self):
        expected_out_size, expected_kern_size, exp_out_root, exp_kern_root = (
            self._record_checkpoint_at_4()
        )
        self.txhs.rewind(expected_out_size, expected_kern_size)
        self.assertEqual(self.txhs.output_pmmr.root(), exp_out_root)
        self.assertEqual(self.txhs.kernel_mmr.root(), exp_kern_root)

    def test_rewind_then_push_continues(self):
        expected_out_size, expected_kern_size, _, _ = self._record_checkpoint_at_4()
        self.txhs.rewind(expected_out_size, expected_kern_size)
        # Push one more — should succeed
        self._push_output(100)
        self._push_kernel(100)
        from mimblewimble.mmr.index import n_leaves

        self.assertEqual(n_leaves(self.txhs.output_pmmr.size()), 5)

    def test_rewind_commit_idx_rebuilt(self):
        expected_out_size, expected_kern_size, _, _ = self._record_checkpoint_at_4()
        self.txhs.rewind(expected_out_size, expected_kern_size)
        # Commits 0..3 visible; commit 4..7 gone
        for i in range(4):
            self.assertIsNotNone(
                self.txhs.commit_to_output_pos(_make_commit(i)),
                f"commit {i} should survive rewind",
            )
        for i in range(4, 8):
            self.assertIsNone(
                self.txhs.commit_to_output_pos(_make_commit(i)),
                f"commit {i} should be gone after rewind",
            )


# ===========================================================================
# 7. Merkle proofs for outputs
# ===========================================================================


class TestMerkleProofForOutput(TxHashSetTestBase):

    def setUp(self):
        super().setUp()
        self._positions = [self._push_output(i) for i in range(5)]
        for i in range(5):
            self._push_kernel(i)

    def test_merkle_proof_returns_proof(self):
        from mimblewimble.mmr.proof import MerkleProof

        commit = _make_commit(0)
        proof = self.txhs.merkle_proof_for_output(commit)
        self.assertIsInstance(proof, MerkleProof)

    def test_merkle_proof_unknown_commit(self):
        proof = self.txhs.merkle_proof_for_output(_make_commit(99))
        self.assertIsNone(proof)

    def test_merkle_proof_verify(self):
        commit = _make_commit(2)
        pos = self._positions[2]
        proof = self.txhs.merkle_proof_for_output(commit)
        self.assertIsNotNone(proof)
        root = self.txhs.output_pmmr.root()
        # Compute expected leaf hash
        from mimblewimble.mmr.proof import hash_with_index

        leaf_hash = hash_with_index(pos, commit)
        self.assertTrue(proof.verify(leaf_hash, pos, root))

    def test_merkle_proof_invalid_data_fails(self):
        commit = _make_commit(1)
        pos = self._positions[1]
        proof = self.txhs.merkle_proof_for_output(commit)
        self.assertIsNotNone(proof)
        root = self.txhs.output_pmmr.root()
        from mimblewimble.mmr.proof import hash_with_index

        bad_leaf_hash = hash_with_index(pos, _make_commit(99))  # wrong leaf
        self.assertFalse(proof.verify(bad_leaf_hash, pos, root))

    def test_merkle_proof_all_leaves(self):
        """All leaf positions should produce valid proofs."""
        root = self.txhs.output_pmmr.root()
        from mimblewimble.mmr.proof import hash_with_index

        for i, pos in enumerate(self._positions):
            commit = _make_commit(i)
            proof = self.txhs.merkle_proof_for_output(commit)
            self.assertIsNotNone(proof)
            leaf_hash = hash_with_index(pos, commit)
            self.assertTrue(
                proof.verify(leaf_hash, pos, root),
                f"Proof failed for output leaf {i} at pos {pos}",
            )


# ===========================================================================
# 8. Persistence (flush + reopen)
# ===========================================================================


class TestTxHashSetPersistence(TxHashSetTestBase):

    def test_root_survives_reopen(self):
        """Root values computed before flush match those after reopen."""
        for i in range(4):
            self._push_output(i)
            self._push_kernel(i)

        out_root_before = self.txhs.output_pmmr.root()
        rp_root_before = self.txhs.rangeproof_pmmr.root()
        kern_root_before = self.txhs.kernel_mmr.root()
        out_size_before = self.txhs.output_pmmr.size()
        kern_size_before = self.txhs.kernel_mmr.size()

        self.txhs.flush()
        self.txhs.close()

        # Reopen
        from mimblewimble.mmr.txhashset import TxHashSet

        txhs2 = TxHashSet(self._data_dir)

        self.assertEqual(txhs2.output_pmmr.root(), out_root_before)
        self.assertEqual(txhs2.rangeproof_pmmr.root(), rp_root_before)
        self.assertEqual(txhs2.kernel_mmr.root(), kern_root_before)
        self.assertEqual(txhs2.output_pmmr.size(), out_size_before)
        self.assertEqual(txhs2.kernel_mmr.size(), kern_size_before)

        txhs2.close()
        # Prevent tearDown from calling close() again
        self.txhs = txhs2

    def test_commit_idx_survives_reopen(self):
        """commit_to_output_pos mapping is persisted and reloaded."""
        commits = [_make_commit(i) for i in range(3)]
        for i in range(3):
            rp = _make_rangeproof(i)
            pos = self.txhs.output_pmmr.push(commits[i])
            self.txhs.rangeproof_pmmr.push(rp)
            self.txhs._commit_to_pos[commits[i]] = pos
            self.txhs.kernel_mmr.push(_make_kernel(i))

        self.txhs.flush()
        self.txhs.close()

        from mimblewimble.mmr.txhashset import TxHashSet

        txhs2 = TxHashSet(self._data_dir)
        for c in commits:
            self.assertIsNotNone(txhs2.commit_to_output_pos(c))
        txhs2.close()
        self.txhs = txhs2

    def test_commit_idx_persisted_as_json(self):
        for i in range(3):
            self._push_output(i)
            self._push_kernel(i)

        self.txhs.flush()
        idx_path = self._data_dir / "commit_idx.json"
        self.assertTrue(idx_path.exists())

        with open(idx_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        self.assertIsInstance(payload, dict)
        self.assertEqual(len(payload), 3)
        self.assertFalse((self._data_dir / "commit_idx.pkl").exists())


# ===========================================================================
# 9. Snapshot (ZIP archive)
# ===========================================================================


class TestSnapshot(TxHashSetTestBase):

    def test_snapshot_creates_zip(self):
        import zipfile

        for i in range(3):
            self._push_output(i)
            self._push_kernel(i)
        self.txhs.flush()

        class _H:
            def getHash(self):
                return b"\xab" * 32

        zip_path = self.txhs.snapshot(_H())
        self.assertTrue(zip_path.exists())
        self.assertGreater(zip_path.stat().st_size, 0)
        with zipfile.ZipFile(zip_path) as zf:
            names = set(zf.namelist())
        # At minimum the three hash files should be present
        self.assertIn("output/pmmr_hash.bin", names)
        self.assertIn("rangeproof/pmmr_hash.bin", names)
        self.assertIn("kernel/pmmr_hash.bin", names)


# ===========================================================================
# 10. leaf_pos_iter / leaf_idx_iter
# ===========================================================================


class TestLeafIterators(TxHashSetTestBase):

    def setUp(self):
        super().setUp()
        self._positions = [self._push_output(i) for i in range(4)]

    def test_leaf_pos_iter_count(self):
        positions = list(self.txhs.output_pmmr.leaf_pos_iter())
        self.assertEqual(len(positions), 4)

    def test_leaf_pos_iter_matches_push(self):
        positions = list(self.txhs.output_pmmr.leaf_pos_iter())
        self.assertEqual(positions, self._positions)

    def test_leaf_idx_iter_count(self):
        pairs = list(self.txhs.output_pmmr.leaf_idx_iter())
        self.assertEqual(len(pairs), 4)

    def test_leaf_idx_iter_indices(self):
        pairs = list(self.txhs.output_pmmr.leaf_idx_iter())
        indices = [idx for idx, _ in pairs]
        self.assertEqual(indices, list(range(4)))

    def test_leaf_pos_iter_skips_pruned(self):
        pos0 = self._positions[0]
        pos2 = self._positions[2]
        self.txhs.output_pmmr.prune(pos0)
        self.txhs.output_pmmr.prune(pos2)
        remaining = list(self.txhs.output_pmmr.leaf_pos_iter())
        self.assertNotIn(pos0, remaining)
        self.assertNotIn(pos2, remaining)
        self.assertEqual(len(remaining), 2)


# ===========================================================================
# 11. get_unspent_outputs range query
# ===========================================================================


class TestGetUnspentOutputs(TxHashSetTestBase):

    def setUp(self):
        super().setUp()
        self._positions = [self._push_output(i) for i in range(6)]

    def test_full_range(self):
        results = self.txhs.get_unspent_outputs(0, 99)
        self.assertEqual(len(results), 6)

    def test_partial_range(self):
        # With 6 outputs (leaf indices 0..5), request indices 2..4
        results = self.txhs.get_unspent_outputs(2, 4)
        self.assertEqual(len(results), 3)

    def test_data_matches_commit(self):
        results = self.txhs.get_unspent_outputs(0, 5)
        retrieved_commits = {c for _, c in results}
        expected_commits = {_make_commit(i) for i in range(6)}
        self.assertEqual(retrieved_commits, expected_commits)


# ===========================================================================
# 12. Validate_roots after prune — roots should remain stable
# ===========================================================================


class TestValidateRootsAfterPrune(TxHashSetTestBase):

    def test_validate_roots_stable_after_prune(self):
        from mimblewimble.mmr.txhashset import TxHashSet

        positions = [self._push_output(i) for i in range(4)]
        for i in range(4):
            self._push_kernel(i)

        # Record roots BEFORE prune
        header = _MockHeader(
            output_root=self.txhs.output_pmmr.root(),
            rp_root=self.txhs.rangeproof_pmmr.root(),
            kernel_root=self.txhs.kernel_mmr.root(),
            output_mmr_size=self.txhs.output_pmmr.size(),
            kernel_mmr_size=self.txhs.kernel_mmr.size(),
        )

        # Prune leaf 0 (simulating a spent output)
        self.txhs.output_pmmr.prune(positions[0])
        self.txhs.rangeproof_pmmr.prune(positions[0])

        # Roots should be unchanged — only leaf data is dropped, not hashes
        self.assertTrue(self.txhs.validate_roots(header))


if __name__ == "__main__":
    unittest.main()
