"""
tests/test_segment.py

Unit tests for mimblewimble/mmr/segment.py:
  - SegmentIdentifier serialization round-trip
  - SegmentTypeIdentifier serialization round-trip
  - SegmentIdentifier position / leaf range helpers
  - SegmentProof.verify() — basic proof check
  - BitmapChunk / BitmapAccumulator
  - Segment.compute_root() consistency
"""

import hashlib
import struct

import pytest

from mimblewimble.mmr.bitmap import BitmapAccumulator, BitmapChunk, CHUNK_BITS
from mimblewimble.mmr.segment import (
    Segment,
    SegmentIdentifier,
    SegmentProof,
    SegmentType,
    SegmentTypeIdentifier,
)
from mimblewimble.mmr.proof import hash_with_index

# ---------------------------------------------------------------------------
# SegmentIdentifier
# ---------------------------------------------------------------------------


class TestSegmentIdentifier:
    def test_serialize_deserialize_roundtrip(self):
        for h, idx in [(0, 0), (9, 0), (11, 42), (11, 2047), (0, 65535)]:
            si = SegmentIdentifier(height=h, idx=idx)
            data = si.serialize()
            assert len(data) == 9
            si2 = SegmentIdentifier.deserialize(data)
            assert si2.height == h
            assert si2.idx == idx

    def test_wire_format_byte_order(self):
        si = SegmentIdentifier(height=9, idx=1)
        data = si.serialize()
        height_byte, idx_le = data[0], data[1:]
        assert height_byte == 9
        assert struct.unpack("<Q", idx_le)[0] == 1

    def test_segment_first_last_pos(self):
        # height=0 means 1-leaf segments; each has exactly 1 node
        si = SegmentIdentifier(height=0, idx=0)
        assert si.segment_first_mmr_pos() == 0
        assert si.segment_last_mmr_pos() == 0

        si = SegmentIdentifier(height=1, idx=0)
        # subtree_size = (1<<2)-1 = 3
        assert si.segment_first_mmr_pos() == 0
        assert si.segment_last_mmr_pos() == 2

        si = SegmentIdentifier(height=1, idx=1)
        assert si.segment_first_mmr_pos() == 3
        assert si.segment_last_mmr_pos() == 5

    def test_leaf_range(self):
        si = SegmentIdentifier(height=9, idx=0)
        first, last = si.leaf_range()
        assert first == 0
        assert last == 511  # 2^9 - 1

        si = SegmentIdentifier(height=9, idx=1)
        first, last = si.leaf_range()
        assert first == 512
        assert last == 1023

    def test_leaf_range_output(self):
        si = SegmentIdentifier(height=11, idx=3)
        first, last = si.leaf_range()
        leaves_per_seg = 1 << 11  # 2048
        assert first == 3 * leaves_per_seg
        assert last == 4 * leaves_per_seg - 1


# ---------------------------------------------------------------------------
# SegmentTypeIdentifier
# ---------------------------------------------------------------------------


class TestSegmentTypeIdentifier:
    def test_serialize_deserialize_roundtrip(self):
        for st in SegmentType:
            for h, idx in [(9, 0), (11, 7)]:
                sti = SegmentTypeIdentifier(
                    segment_type=st,
                    identifier=SegmentIdentifier(height=h, idx=idx),
                )
                data = sti.serialize()
                assert len(data) == 10
                sti2 = SegmentTypeIdentifier.deserialize(data)
                assert sti2.segment_type == st
                assert sti2.identifier.height == h
                assert sti2.identifier.idx == idx

    def test_type_byte_first(self):
        sti = SegmentTypeIdentifier(
            segment_type=SegmentType.OUTPUT,
            identifier=SegmentIdentifier(height=11, idx=0),
        )
        data = sti.serialize()
        assert data[0] == int(SegmentType.OUTPUT)


# ---------------------------------------------------------------------------
# SegmentProof
# ---------------------------------------------------------------------------


class TestSegmentProof:
    def test_empty_mmr_single_leaf(self):
        """A single-leaf MMR has root == leaf hash; proof is trivial."""
        # Leaf at pos0=0
        leaf_data = b"hello"
        leaf_h = hash_with_index(0, leaf_data)
        # root of a 1-leaf MMR (size=1) is the leaf hash
        proof = SegmentProof(mmr_size=1, hashes=[])
        assert proof.verify(leaf_h, leaf_h, 0)

    def test_proof_wrong_root_fails(self):
        leaf_data = b"hello"
        leaf_h = hash_with_index(0, leaf_data)
        proof = SegmentProof(mmr_size=1, hashes=[])
        wrong_root = b"\xff" * 32
        assert not proof.verify(leaf_h, wrong_root, 0)

    def test_serialize_deserialize_roundtrip(self):
        hashes = [bytes(range(32)), b"\xab" * 32]
        proof = SegmentProof(mmr_size=12345, hashes=hashes)
        data = proof.serialize()
        proof2 = SegmentProof.deserialize(data)
        assert proof2.mmr_size == 12345
        assert proof2.hashes == hashes


# ---------------------------------------------------------------------------
# BitmapChunk
# ---------------------------------------------------------------------------


class TestBitmapChunk:
    def test_all_zero_by_default(self):
        c = BitmapChunk()
        for i in range(CHUNK_BITS):
            assert not c.is_set(i)

    def test_set_and_read_bit(self):
        c = BitmapChunk()
        c2 = c.set_bit(7)
        assert c2.is_set(7)
        assert not c2.is_set(6)

    def test_iter_set_bits(self):
        c = BitmapChunk()
        c = c.set_bit(0).set_bit(63).set_bit(511)
        bits = sorted(c.iter_set_bits())
        assert bits == [0, 63, 511]

    def test_serialize_deserialize(self):
        c = BitmapChunk()
        c = c.set_bit(100).set_bit(200)
        data = c.serialize()
        assert len(data) == 64
        c2 = BitmapChunk.deserialize(data)
        assert c2.is_set(100)
        assert c2.is_set(200)
        assert not c2.is_set(99)

    def test_from_bytes_alias(self):
        c = BitmapChunk().set_bit(10)
        data = c.serialize()
        c2 = BitmapChunk.from_bytes(data)
        assert c2.is_set(10)

    def test_hash_leaf_is_32_bytes(self):
        c = BitmapChunk().set_bit(1)
        h = c.hash_leaf(0)
        assert len(h) == 32


# ---------------------------------------------------------------------------
# BitmapAccumulator
# ---------------------------------------------------------------------------


class TestBitmapAccumulator:
    def test_empty(self):
        acc = BitmapAccumulator()
        assert not acc.is_spent(0)
        assert acc.root(0) is None

    def test_apply_chunk_and_query(self):
        acc = BitmapAccumulator()
        chunk = BitmapChunk().set_bit(0).set_bit(5)
        acc.apply_chunk(0, chunk)
        acc.finalize()
        assert acc.is_spent(0)
        assert acc.is_spent(5)
        assert not acc.is_spent(1)

    def test_second_chunk(self):
        acc = BitmapAccumulator()
        chunk = BitmapChunk().set_bit(0)
        acc.apply_chunk(1, chunk)  # chunk index 1 → bits 512..1023
        acc.finalize()
        assert acc.is_spent(512)
        assert not acc.is_spent(0)

    def test_serialize_deserialize(self):
        acc = BitmapAccumulator()
        acc.apply_chunk(0, BitmapChunk().set_bit(3))
        acc.apply_chunk(2, BitmapChunk().set_bit(0))
        data = acc.serialize_chunks()
        acc2 = BitmapAccumulator.deserialize_chunks(data)
        acc2.finalize()
        assert acc2.is_spent(3)
        assert acc2.is_spent(2 * CHUNK_BITS)

    def test_get_chunk_bytes(self):
        acc = BitmapAccumulator()
        chunk = BitmapChunk().set_bit(7)
        acc.apply_chunk(0, chunk)
        data = acc.get_chunk_bytes(0)
        assert len(data) == 64
        # Chunk index 1 has never been set
        data2 = acc.get_chunk_bytes(1)
        assert data2 == b"\x00" * 64

    def test_root_changes_when_bit_set(self):
        acc1 = BitmapAccumulator()
        acc1.apply_chunk(0, BitmapChunk())
        r1 = acc1.root(1)

        acc2 = BitmapAccumulator()
        acc2.apply_chunk(0, BitmapChunk().set_bit(0))
        r2 = acc2.root(1)

        assert r1 != r2

    def test_reset(self):
        acc = BitmapAccumulator()
        acc.apply_chunk(0, BitmapChunk().set_bit(0))
        acc.finalize()
        acc.reset()
        assert not acc.is_spent(0)


# ---------------------------------------------------------------------------
# Segment — basic structure
# ---------------------------------------------------------------------------


class TestSegment:
    def _make_leaf_segment(self):
        """Build a minimal valid height-0 segment with one leaf."""
        identifier = SegmentIdentifier(height=0, idx=0)
        leaf_data = b"test_output_commitment_33_bytes!"[:33]
        leaf_h = hash_with_index(0, leaf_data)
        proof = SegmentProof(mmr_size=1, hashes=[])
        seg = Segment(
            identifier=identifier,
            hashes=[],
            leaf_data=[(0, leaf_data)],
            proof=proof,
        )
        return seg, leaf_h

    def test_compute_root_single_leaf(self):
        seg, expected_hash = self._make_leaf_segment()
        root = seg.compute_root()
        assert root == expected_hash

    def test_verify_against_correct_root(self):
        seg, leaf_h = self._make_leaf_segment()
        # Full MMR root of a 1-element MMR is the leaf hash
        assert seg.verify(leaf_h)

    def test_verify_against_wrong_root(self):
        seg, _ = self._make_leaf_segment()
        wrong_root = b"\x00" * 32
        assert not seg.verify(wrong_root)

    def test_hash_iter_and_leaf_iter(self):
        identifier = SegmentIdentifier(height=1, idx=0)
        seg = Segment(
            identifier=identifier,
            hashes=[(2, b"\xaa" * 32)],
            leaf_data=[(0, b"left"), (1, b"right")],
            proof=SegmentProof(mmr_size=3, hashes=[]),
        )
        hashes = list(seg.hash_iter())
        assert hashes == [(2, b"\xaa" * 32)]
        leaves = list(seg.leaf_iter())
        assert len(leaves) == 2
        assert leaves[0] == (0, b"left")
        assert leaves[1] == (1, b"right")
