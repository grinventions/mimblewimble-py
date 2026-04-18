"""
mimblewimble/mmr/pibd_params.py

PIBD (Pruned In-Block-Data) sync parameters.

These constants are ported directly from Grin's reference implementation:
  chain/src/pibd_params.rs

They control segment sizes, request concurrency, timeouts, and the
ZIP fallback threshold used by the PIBD sync engine.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Segment height constants
# ---------------------------------------------------------------------------

# Bitmap segment height — each segment covers 2^9 = 512 nodes
BITMAP_SEGMENT_HEIGHT: int = 9

# Output PMMR segment height — each segment covers 2^11 = 2048 nodes
OUTPUT_SEGMENT_HEIGHT: int = 11

# Rangeproof PMMR segment height — each segment covers 2^11 = 2048 nodes
RANGEPROOF_SEGMENT_HEIGHT: int = 11

# Kernel MMR segment height — each segment covers 2^11 = 2048 nodes
KERNEL_SEGMENT_HEIGHT: int = 11

# ---------------------------------------------------------------------------
# Request / caching limits
# ---------------------------------------------------------------------------

# Maximum number of received segments to cache (across all trees) before we
# stop requesting others.
MAX_CACHED_SEGMENTS: int = 15

# Number of segments to apply in a single batch (transaction).
SEGMENT_APPLY_BATCH_SIZE: int = 4

# Number of simultaneous segment requests to issue.  Divisible by 3 to try
# and evenly spread requests among the 3 main PMMRs (bitmap segments are
# always requested first).
SEGMENT_REQUEST_COUNT: int = 15

# ---------------------------------------------------------------------------
# Timeout / fallback thresholds
# ---------------------------------------------------------------------------

# How long (seconds) to wait for a requested segment before re-requesting it.
SEGMENT_REQUEST_TIMEOUT_SECS: int = 20

# If no max-work peer supporting PIBD has been seen within this many seconds,
# abort PIBD and fall back to the txhashset.zip download method.
TXHASHSET_ZIP_FALLBACK_TIME_SECS: int = 60

# ---------------------------------------------------------------------------
# Allowed segment height ranges (for validation of incoming requests)
# ---------------------------------------------------------------------------

# Valid height range (inclusive) callers may use for each segment type.
# Tuple of (min_height_inclusive, max_height_inclusive).
BITMAP_SEGMENT_HEIGHT_RANGE = (BITMAP_SEGMENT_HEIGHT - 1, BITMAP_SEGMENT_HEIGHT + 1)
OUTPUT_SEGMENT_HEIGHT_RANGE = (OUTPUT_SEGMENT_HEIGHT - 1, OUTPUT_SEGMENT_HEIGHT + 1)
RANGEPROOF_SEGMENT_HEIGHT_RANGE = (
    RANGEPROOF_SEGMENT_HEIGHT - 1,
    RANGEPROOF_SEGMENT_HEIGHT + 1,
)
KERNEL_SEGMENT_HEIGHT_RANGE = (KERNEL_SEGMENT_HEIGHT - 1, KERNEL_SEGMENT_HEIGHT + 1)
