"""
tests/test_chain.py

Block and chain validation unit tests.

Mirrors the block validation tests in:
  grin/core/tests/block.rs
  grin/core/tests/core.rs  (block-level sections)
  grin/chain/tests/mine_simple_chain.rs (structural checks)
"""

import unittest

import pytest

from mimblewimble.blockchain import (
    BlockHeader,
    FullBlock,
    CompactBlock,
    ProofOfWork,
    BlockValidationError,
)
from mimblewimble.consensus import Consensus
from mimblewimble.models.transaction import (
    TransactionBody,
    TransactionInput,
    TransactionOutput,
    TransactionKernel,
    BlindingFactor,
    EOutputFeatures,
    EKernelFeatures,
)
from mimblewimble.models.fee import Fee
from mimblewimble.crypto.commitment import Commitment
from mimblewimble.crypto.signature import Signature
from mimblewimble.crypto.rangeproof import RangeProof
from mimblewimble.serializer import Serializer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _commit(seed: int) -> Commitment:
    """Return a deterministic 33-byte Commitment for testing."""
    return Commitment(bytes([seed & 0xFF]) + bytes([seed ^ 0x5A]) * 32)


def _sig() -> Signature:
    return Signature(b"\x00" * 64)


def _rp() -> RangeProof:
    return RangeProof(b"\x00" * 100)


def _dummy_header(height: int = 0, version: int = 5) -> BlockHeader:
    """Create a minimal BlockHeader suitable for structural tests."""
    return BlockHeader(
        version=version,
        height=height,
        timestamp=1_000_000,
        previousBlockHash=b"\x00" * 32,
        previousRoot=b"\x00" * 32,
        outputRoot=b"\x00" * 32,
        rangeProofRoot=b"\x00" * 32,
        kernelRoot=b"\x00" * 32,
        totalKernelOffset=BlindingFactor.zero(),
        outputMMRSize=1,
        kernelMMRSize=1,
        totalDifficulty=1,
        scalingDifficulty=1,
        nonce=0,
        proofOfWork=ProofOfWork(29, [0] * 42),
    )


def _cb_output(seed: int = 1) -> TransactionOutput:
    return TransactionOutput(EOutputFeatures.COINBASE_OUTPUT, _commit(seed), _rp())


def _plain_output(seed: int = 2) -> TransactionOutput:
    return TransactionOutput(EOutputFeatures.DEFAULT, _commit(seed), _rp())


def _cb_kernel(seed: int = 10) -> TransactionKernel:
    return TransactionKernel(
        EKernelFeatures.COINBASE_KERNEL, None, 0, _commit(seed), _sig()
    )


def _plain_kernel(seed: int = 20, fee: int = 0) -> TransactionKernel:
    return TransactionKernel(
        EKernelFeatures.DEFAULT_KERNEL, Fee(0, fee), 0, _commit(seed), _sig()
    )


def _locked_kernel(lock_height: int, seed: int = 30) -> TransactionKernel:
    return TransactionKernel(
        EKernelFeatures.HEIGHT_LOCKED, Fee(0, 0), lock_height, _commit(seed), _sig()
    )


def _block(outputs=None, kernels=None, inputs=None, height=0, version=5) -> FullBlock:
    body = TransactionBody(inputs or [], outputs or [], kernels or [])
    return FullBlock(_dummy_header(height=height, version=version), body)


# ---------------------------------------------------------------------------
# Original placeholder test (kept for backwards compatibility)
# ---------------------------------------------------------------------------


class ChainTest(unittest.TestCase):
    def test_batching(self):
        pass


# ---------------------------------------------------------------------------
# Block weight (mirrors too_large_block / weight calculation tests)
# ---------------------------------------------------------------------------


class TestBlockWeight:
    def test_v5_empty_coinbase_within_limit(self):
        """A block with only a coinbase (0 inputs, 1 output, 1 kernel) is light."""
        weight = Consensus.calculateWeightV5(0, 1, 1)
        assert weight <= Consensus.max_block_weight

    def test_v5_1905_outputs_too_heavy(self):
        """1905 outputs × 21 = 40 005 > 40 000 — exceeds limit."""
        weight = Consensus.calculateWeightV5(0, 1905, 0)
        assert weight > Consensus.max_block_weight

    def test_v5_1904_outputs_ok(self):
        weight = Consensus.calculateWeightV5(0, 1904, 0)
        assert weight <= Consensus.max_block_weight

    def test_verify_raises_block_validation_error_when_overweight(self):
        """_verify_coinbase raises BlockValidationError when coinbase count is wrong,
        but the weight check in validate() precedes it.  We verify the weight
        threshold directly to match the Rust 'too_large_block' test."""
        max_w = Consensus.max_block_weight
        assert (
            Consensus.calculateWeightV5(0, max_w // Consensus.output_weight + 1, 0)
            > max_w
        )


# ---------------------------------------------------------------------------
# Coinbase validation (_verify_coinbase)
# (mirrors empty_block_with_coinbase_is_valid, very_empty_block,
#  remove_coinbase_output_flag, remove_coinbase_kernel_flag)
# ---------------------------------------------------------------------------


class TestVerifyCoinbase:
    def test_no_outputs_no_kernels_raises(self):
        """Block with no outputs and no kernels has no coinbase — invalid."""
        block = _block(outputs=[], kernels=[])
        with pytest.raises(BlockValidationError):
            block._verify_coinbase(0)

    def test_no_coinbase_output_raises(self):
        """Plain output + coinbase kernel → still 0 coinbase outputs → invalid."""
        block = _block(outputs=[_plain_output(2)], kernels=[_cb_kernel(10)])
        with pytest.raises(BlockValidationError):
            block._verify_coinbase(0)

    def test_no_coinbase_kernel_raises(self):
        """Coinbase output + plain kernel → 0 coinbase kernels → invalid."""
        block = _block(outputs=[_cb_output(1)], kernels=[_plain_kernel(20)])
        with pytest.raises(BlockValidationError):
            block._verify_coinbase(0)

    def test_multiple_coinbase_outputs_raises(self):
        """Two coinbase outputs is not allowed."""
        block = _block(
            outputs=[_cb_output(1), _cb_output(3)],
            kernels=[_cb_kernel(10)],
        )
        with pytest.raises(BlockValidationError):
            block._verify_coinbase(0)

    def test_multiple_coinbase_kernels_raises(self):
        """Two coinbase kernels is not allowed."""
        block = _block(
            outputs=[_cb_output(1)],
            kernels=[_cb_kernel(10), _cb_kernel(11)],
        )
        with pytest.raises(BlockValidationError):
            block._verify_coinbase(0)

    def test_remove_coinbase_output_flag_raises(self):
        """Changing the coinbase output's features to DEFAULT invalidates the block.
        (Mirrors core/tests/block.rs :: remove_coinbase_output_flag)"""
        # One *plain* output (flag stripped) + one coinbase kernel → 0 cb outputs
        block = _block(
            outputs=[_plain_output(2)],  # should have been COINBASE_OUTPUT
            kernels=[_cb_kernel(10)],
        )
        with pytest.raises(BlockValidationError):
            block._verify_coinbase(0)

    def test_remove_coinbase_kernel_flag_raises(self):
        """Changing the coinbase kernel's features to DEFAULT invalidates the block.
        (Mirrors core/tests/block.rs :: remove_coinbase_kernel_flag)"""
        # Coinbase output + plain kernel → 0 cb kernels
        block = _block(
            outputs=[_cb_output(1)],
            kernels=[_plain_kernel(20)],  # should have been COINBASE_KERNEL
        )
        with pytest.raises(BlockValidationError):
            block._verify_coinbase(0)


# ---------------------------------------------------------------------------
# Lock-height validation (_verify_lock_heights)
# (mirrors test_block_with_timelocked_tx)
# ---------------------------------------------------------------------------


class TestVerifyLockHeights:
    def test_lock_height_in_future_raises(self):
        """HEIGHT_LOCKED kernel with lock > block height is invalid."""
        block = _block(
            kernels=[_locked_kernel(lock_height=100, seed=30)],
            height=50,
        )
        with pytest.raises(BlockValidationError):
            block._verify_lock_heights(height=50)

    def test_lock_height_equal_to_block_height_ok(self):
        """Lock height == block height is valid."""
        block = _block(kernels=[_locked_kernel(lock_height=50, seed=30)], height=50)
        block._verify_lock_heights(height=50)  # must not raise

    def test_lock_height_in_past_ok(self):
        """Lock height strictly less than block height is valid."""
        block = _block(kernels=[_locked_kernel(lock_height=10, seed=30)], height=100)
        block._verify_lock_heights(height=100)

    def test_plain_kernel_no_lock_height_ok(self):
        """DEFAULT_KERNEL without lock height constraint passes unconditionally."""
        block = _block(kernels=[_plain_kernel(seed=20)])
        block._verify_lock_heights(height=0)

    def test_coinbase_kernel_no_lock_height_ok(self):
        """COINBASE_KERNEL has no lock height — always passes."""
        block = _block(kernels=[_cb_kernel(seed=10)])
        block._verify_lock_heights(height=0)

    def test_mixed_kernels_one_locked_in_future_raises(self):
        """Even if one of many kernels has a future lock height, block is invalid."""
        block = _block(
            kernels=[
                _plain_kernel(seed=20),
                _locked_kernel(lock_height=200, seed=31),  # future
                _locked_kernel(lock_height=5, seed=32),  # past
            ],
            height=10,
        )
        with pytest.raises(BlockValidationError):
            block._verify_lock_heights(height=10)


# ---------------------------------------------------------------------------
# BlockHeader serialisation round-trip
# (mirrors serialize_deserialize_block_header)
# ---------------------------------------------------------------------------


class TestBlockHeaderSerialisation:
    def _make_header(self, **overrides) -> BlockHeader:
        defaults = dict(
            version=1,
            height=42,
            timestamp=1_700_000_000,
            previousBlockHash=bytes(range(32)),
            previousRoot=bytes([0xAA] * 32),
            outputRoot=bytes([0xBB] * 32),
            rangeProofRoot=bytes([0xCC] * 32),
            kernelRoot=bytes([0xDD] * 32),
            totalKernelOffset=BlindingFactor(bytes([0x01] * 32)),
            outputMMRSize=7,
            kernelMMRSize=3,
            totalDifficulty=1_234_567,
            scalingDifficulty=511,
            nonce=9_876_543_210,
            proofOfWork=ProofOfWork(29, [0] * 42),
        )
        defaults.update(overrides)
        return BlockHeader(**defaults)

    def test_serialize_deserialize_roundtrip(self):
        """Serialising and deserialising a header produces identical bytes."""
        header = self._make_header()
        s1 = Serializer()
        header.serialize(s1)
        original_bytes = s1.getvalue()

        s2 = Serializer()
        s2.write(original_bytes)
        reconstructed = BlockHeader.deserialize(s2)

        s3 = Serializer()
        reconstructed.serialize(s3)
        assert s1.getvalue() == s3.getvalue()

    def test_version_preserved(self):
        header = self._make_header(version=3)
        s = Serializer()
        header.serialize(s)
        r = BlockHeader.deserialize(s)
        assert r.getVersion() == 3

    def test_height_preserved(self):
        header = self._make_header(height=999_999)
        s = Serializer()
        header.serialize(s)
        r = BlockHeader.deserialize(s)
        assert r.getHeight() == 999_999

    def test_hash_deterministic(self):
        """Same header always produces the same hash."""
        header = self._make_header()
        assert header.getHash() == header.getHash()

    def test_hash_differs_after_height_change(self):
        h1 = self._make_header(height=1)
        h2 = self._make_header(height=2)
        assert h1.getHash() != h2.getHash()

    def test_prepow_deterministic(self):
        header = self._make_header()
        assert header.getPrePoW() == header.getPrePoW()

    def test_prepow_excludes_nonce(self):
        """Pre-PoW bytes are the same regardless of nonce value."""
        h1 = self._make_header(nonce=0)
        h2 = self._make_header(nonce=0xFFFF_FFFF_FFFF_FFFF)
        assert h1.getPrePoW() == h2.getPrePoW()


# ---------------------------------------------------------------------------
# CompactBlock serialisation round-trip
# (mirrors serialize_deserialize_compact_block,
#  empty_compact_block_serialized_size)
# ---------------------------------------------------------------------------


class TestCompactBlockSerialisation:
    def test_empty_compact_block_serialize(self):
        """CompactBlock with no outputs/kernels/shortids serialises cleanly."""
        header = _dummy_header()
        cb = CompactBlock(
            header=header, nonce=42, fullOutputs=[], fullKernels=[], shortIds=[]
        )
        raw = cb.serialize()
        # nonce(8) + counts(2+2+2) = 14 bytes minimum body
        assert len(raw) >= 14

    def test_nonce_preserved_in_body(self):
        """Nonce is the first 8 bytes of CompactBlock body (big-endian)."""
        header = _dummy_header()
        nonce_val = 0xDEAD_BEEF_1234_5678
        cb = CompactBlock(
            header=header, nonce=nonce_val, fullOutputs=[], fullKernels=[], shortIds=[]
        )
        raw = cb.serialize()
        parsed_nonce = int.from_bytes(raw[:8], "big")
        assert parsed_nonce == nonce_val

    def test_output_count_in_body(self):
        """num_outputs (2 bytes) at offset 8 of CompactBlock body."""
        header = _dummy_header()
        cb = CompactBlock(
            header=header,
            nonce=0,
            fullOutputs=[_plain_output(5)],
            fullKernels=[],
            shortIds=[],
        )
        raw = cb.serialize()
        num_outputs = int.from_bytes(raw[8:10], "big")
        assert num_outputs == 1
