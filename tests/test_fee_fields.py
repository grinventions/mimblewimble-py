"""
tests/test_fee_fields.py

Unit tests for mimblewimble/models/fee.py (FeeFields).

Mirrors the fee-field tests in:
  grin/core/tests/transaction.rs :: test_fee_fields
"""

import pytest

from mimblewimble.models.fee import Fee
from mimblewimble.serializer import Serializer


# ---------------------------------------------------------------------------
# Basic constructors and accessors
# ---------------------------------------------------------------------------


class TestFeeConstructors:
    def test_fromint_zero(self):
        f = Fee.fromInt(0)
        assert f.getFee() == 0
        assert f.getShift() == 0

    def test_fromint_nonzero(self):
        f = Fee.fromInt(1_000_000)
        assert f.getFee() == 1_000_000
        assert f.getShift() == 0

    def test_fromint_large_fee(self):
        # Fee fits in 40 bits (max ~1 099 511 627 775)
        large = 0xFF_FFFF_FFFF  # 40-bit max
        f = Fee.fromInt(large)
        assert f.getFee() == large

    def test_constructor_shift_and_fee(self):
        f = Fee(shift=3, fee=500_000)
        assert f.getShift() == 3
        assert f.getFee() == 500_000

    def test_shift_max_nibble(self):
        f = Fee(shift=15, fee=1)
        assert f.getShift() == 15


# ---------------------------------------------------------------------------
# Serialise / deserialise round-trip  (mirrors FeeFields encode/decode in Rust)
# ---------------------------------------------------------------------------


class TestFeeSerialisation:
    def _roundtrip(self, shift, fee):
        original = Fee(shift=shift, fee=fee)
        s = Serializer()
        original.serialize(s)
        reconstructed = Fee.deserialize(s)
        return reconstructed

    def test_zero_fee_roundtrip(self):
        r = self._roundtrip(0, 0)
        assert r.getFee() == 0
        assert r.getShift() == 0

    def test_nonzero_fee_roundtrip(self):
        r = self._roundtrip(0, 7_000_000)
        assert r.getFee() == 7_000_000
        assert r.getShift() == 0

    def test_shift_preserved_in_roundtrip(self):
        r = self._roundtrip(3, 1_000_000)
        assert r.getFee() == 1_000_000
        assert r.getShift() == 3

    def test_shift_max_nibble_roundtrip(self):
        r = self._roundtrip(15, 100)
        assert r.getShift() == 15
        assert r.getFee() == 100

    def test_shift_masked_to_4_bits(self):
        # Only the low 4 bits of shift survive serialisation
        original = Fee(shift=0x1F, fee=50)  # 5-bit value; only low 4 bits stored
        s = Serializer()
        original.serialize(s)
        reconstructed = Fee.deserialize(s)
        assert reconstructed.getShift() == (0x1F & 0x0F)

    def test_serialised_length_is_8_bytes(self):
        f = Fee(shift=1, fee=42)
        s = Serializer()
        f.serialize(s)
        assert len(s.getvalue()) == 8

    def test_large_fee_roundtrip(self):
        large = 0xFF_FFFF_FFFF
        r = self._roundtrip(0, large)
        assert r.getFee() == large


# ---------------------------------------------------------------------------
# Equality
# ---------------------------------------------------------------------------


class TestFeeEquality:
    def test_equal_fees(self):
        a = Fee(0, 1_000)
        b = Fee(0, 1_000)
        assert a == b

    def test_different_fee_amounts(self):
        a = Fee(0, 1_000)
        b = Fee(0, 2_000)
        assert a != b

    def test_different_shifts(self):
        a = Fee(0, 1_000)
        b = Fee(1, 1_000)
        assert a != b

    def test_zero_fees_equal(self):
        assert Fee.fromInt(0) == Fee.fromInt(0)
