"""
tests/test_pibd_params.py

Verify that all PIBD protocol constants match Grin's reference values from
chain/src/pibd_params.rs.
"""

import pytest

from mimblewimble.mmr.pibd_params import (
    BITMAP_SEGMENT_HEIGHT,
    BITMAP_SEGMENT_HEIGHT_RANGE,
    KERNEL_SEGMENT_HEIGHT,
    KERNEL_SEGMENT_HEIGHT_RANGE,
    MAX_CACHED_SEGMENTS,
    OUTPUT_SEGMENT_HEIGHT,
    OUTPUT_SEGMENT_HEIGHT_RANGE,
    RANGEPROOF_SEGMENT_HEIGHT,
    RANGEPROOF_SEGMENT_HEIGHT_RANGE,
    SEGMENT_APPLY_BATCH_SIZE,
    SEGMENT_REQUEST_COUNT,
    SEGMENT_REQUEST_TIMEOUT_SECS,
    TXHASHSET_ZIP_FALLBACK_TIME_SECS,
)

# ---------------------------------------------------------------------------
# Segment height constants (from pibd_params.rs)
# ---------------------------------------------------------------------------


def test_bitmap_segment_height():
    assert BITMAP_SEGMENT_HEIGHT == 9


def test_output_segment_height():
    assert OUTPUT_SEGMENT_HEIGHT == 11


def test_rangeproof_segment_height():
    assert RANGEPROOF_SEGMENT_HEIGHT == 11


def test_kernel_segment_height():
    assert KERNEL_SEGMENT_HEIGHT == 11


# ---------------------------------------------------------------------------
# Tuning constants
# ---------------------------------------------------------------------------


def test_max_cached_segments():
    assert MAX_CACHED_SEGMENTS == 15


def test_segment_apply_batch_size():
    assert SEGMENT_APPLY_BATCH_SIZE == 4


def test_segment_request_timeout():
    assert SEGMENT_REQUEST_TIMEOUT_SECS == 20


def test_segment_request_count():
    assert SEGMENT_REQUEST_COUNT == 15


def test_zip_fallback_time():
    assert TXHASHSET_ZIP_FALLBACK_TIME_SECS == 60


# ---------------------------------------------------------------------------
# Height ranges (must be ±1 around the nominal height)
# ---------------------------------------------------------------------------


def test_bitmap_height_range():
    lo, hi = BITMAP_SEGMENT_HEIGHT_RANGE
    assert lo == BITMAP_SEGMENT_HEIGHT - 1
    assert hi == BITMAP_SEGMENT_HEIGHT + 1


def test_output_height_range():
    lo, hi = OUTPUT_SEGMENT_HEIGHT_RANGE
    assert lo == OUTPUT_SEGMENT_HEIGHT - 1
    assert hi == OUTPUT_SEGMENT_HEIGHT + 1


def test_rangeproof_height_range():
    lo, hi = RANGEPROOF_SEGMENT_HEIGHT_RANGE
    assert lo == RANGEPROOF_SEGMENT_HEIGHT - 1
    assert hi == RANGEPROOF_SEGMENT_HEIGHT + 1


def test_kernel_height_range():
    lo, hi = KERNEL_SEGMENT_HEIGHT_RANGE
    assert lo == KERNEL_SEGMENT_HEIGHT - 1
    assert hi == KERNEL_SEGMENT_HEIGHT + 1


# ---------------------------------------------------------------------------
# Derived values
# ---------------------------------------------------------------------------


def test_leaves_per_bitmap_segment():
    """Each bitmap segment must cover 2^BITMAP_SEGMENT_HEIGHT leaves."""
    assert (1 << BITMAP_SEGMENT_HEIGHT) == 512


def test_leaves_per_output_segment():
    """Each output segment must cover 2^OUTPUT_SEGMENT_HEIGHT leaves."""
    assert (1 << OUTPUT_SEGMENT_HEIGHT) == 2048
