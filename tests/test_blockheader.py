import unittest

from mimblewimble.blockchain import ProofOfWork, BlockHeader
from mimblewimble.models.transaction import BlindingFactor
from mimblewimble.serializer import Serializer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_header(**overrides) -> BlockHeader:
    """Return a fully-specified BlockHeader for round-trip tests."""
    defaults = dict(
        version=1,
        height=2,
        timestamp=3,
        previousBlockHash=bytes.fromhex(
            "0102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2021"
        ),
        previousRoot=bytes.fromhex(
            "1102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2021"
        ),
        outputRoot=bytes.fromhex(
            "2102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2021"
        ),
        rangeProofRoot=bytes.fromhex(
            "3102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2021"
        ),
        kernelRoot=bytes.fromhex(
            "4102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2021"
        ),
        totalKernelOffset=BlindingFactor(
            bytes.fromhex(
                "5102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2021"
            )
        ),
        outputMMRSize=4,
        kernelMMRSize=7,
        totalDifficulty=1000,
        scalingDifficulty=10,
        nonce=123456,
        proofOfWork=ProofOfWork(29, [0] * 42),
    )
    defaults.update(overrides)
    return BlockHeader(**defaults)


# ---------------------------------------------------------------------------
# Existing test
# ---------------------------------------------------------------------------


class BlockHeaderTest(unittest.TestCase):
    def test_deserialize(self):
        """Original test — constructs a BlockHeader and checks MMR leaf counts."""
        version = 1
        height = 2
        timestamp = 3

        previousBlockHash = bytes.fromhex(
            "0102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2021"
        )
        previousRoot = bytes.fromhex(
            "1102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2021"
        )
        outputRoot = bytes.fromhex(
            "2102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2021"
        )
        rangeProofRoot = bytes.fromhex(
            "3102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2021"
        )
        kernelRoot = bytes.fromhex(
            "4102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2021"
        )
        totalKernelOffset = bytes.fromhex(
            "5102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2021"
        )

        outputMMRSize = 4
        kernelMMRSize = 7
        totalDifficulty = 1000
        scalingDifficulty = 10
        nonce = 123456

        proofOfWork = ProofOfWork(bytes.fromhex("00001010"), [])

        block_header = BlockHeader(
            version,
            height,
            timestamp,
            previousBlockHash,
            previousRoot,
            outputRoot,
            rangeProofRoot,
            kernelRoot,
            totalKernelOffset,
            outputMMRSize,
            kernelMMRSize,
            totalDifficulty,
            scalingDifficulty,
            nonce,
            proofOfWork,
        )

        assert block_header.getNumOutputs() == 3
        assert block_header.getNumKernels() == 4


# ---------------------------------------------------------------------------
# Serialisation / deserialisation round-trip
# (mirrors core/tests/block.rs :: serialize_deserialize_block_header,
#  serialize_deserialize_header_version)
# ---------------------------------------------------------------------------


class TestBlockHeaderSerialization(unittest.TestCase):
    def test_serialize_deserialize_roundtrip(self):
        """Serialising then deserialising produces byte-identical output."""
        header = _make_header()
        s1 = Serializer()
        header.serialize(s1)
        original_bytes = s1.getvalue()

        s2 = Serializer()
        s2.write(original_bytes)
        reconstructed = BlockHeader.deserialize(s2)

        s3 = Serializer()
        reconstructed.serialize(s3)
        assert original_bytes == s3.getvalue()

    def test_version_1_roundtrip(self):
        header = _make_header(version=1)
        s = Serializer()
        header.serialize(s)
        r = BlockHeader.deserialize(s)
        assert r.getVersion() == 1

    def test_version_2_roundtrip(self):
        header = _make_header(version=2)
        s = Serializer()
        header.serialize(s)
        r = BlockHeader.deserialize(s)
        assert r.getVersion() == 2

    def test_version_5_roundtrip(self):
        header = _make_header(version=5)
        s = Serializer()
        header.serialize(s)
        r = BlockHeader.deserialize(s)
        assert r.getVersion() == 5

    def test_height_preserved(self):
        header = _make_header(height=1_234_567)
        s = Serializer()
        header.serialize(s)
        r = BlockHeader.deserialize(s)
        assert r.getHeight() == 1_234_567

    def test_total_difficulty_preserved(self):
        header = _make_header(totalDifficulty=9_999_999)
        s = Serializer()
        header.serialize(s)
        r = BlockHeader.deserialize(s)
        assert r.getTotalDifficulty() == 9_999_999

    def test_nonce_preserved(self):
        header = _make_header(nonce=0xDEAD_BEEF_CAFE_1234)
        s = Serializer()
        header.serialize(s)
        r = BlockHeader.deserialize(s)
        assert r.getNonce() == 0xDEAD_BEEF_CAFE_1234

    def test_edge_bits_preserved(self):
        header = _make_header(proofOfWork=ProofOfWork(31, [0] * 42))
        s = Serializer()
        header.serialize(s)
        r = BlockHeader.deserialize(s)
        assert r.getEdgeBits() == 31


class TestBlockHeaderHash(unittest.TestCase):
    def test_hash_is_deterministic(self):
        header = _make_header()
        assert header.getHash() == header.getHash()

    def test_hash_is_32_bytes(self):
        header = _make_header()
        assert len(header.getHash()) == 32

    def test_hash_differs_by_height(self):
        h1 = _make_header(height=100)
        h2 = _make_header(height=101)
        assert h1.getHash() != h2.getHash()

    def test_hash_differs_by_version(self):
        h1 = _make_header(version=1)
        h2 = _make_header(version=2)
        assert h1.getHash() != h2.getHash()

    def test_prepow_excludes_nonce(self):
        """Pre-PoW bytes must not depend on the nonce value (nonce slot is zeroed)."""
        h1 = _make_header(nonce=0)
        h2 = _make_header(nonce=0xFFFF_FFFF_FFFF_FFFF)
        assert h1.getPrePoW() == h2.getPrePoW()

    def test_prepow_is_deterministic(self):
        header = _make_header()
        assert header.getPrePoW() == header.getPrePoW()

    def test_prepow_is_bytes(self):
        header = _make_header()
        assert isinstance(header.getPrePoW(), bytes)
