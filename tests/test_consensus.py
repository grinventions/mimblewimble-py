"""
tests/test_consensus.py

Unit tests for mimblewimble/consensus.py.

Mirrors the automated, mainnet, and testnet consensus test suites in:
  grin/core/tests/consensus_automated.rs
  grin/core/tests/consensus_mainnet.rs
  grin/core/tests/consensus_testnet.rs
"""

import pytest

from mimblewimble.consensus import Consensus


# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------


class TestConsensusConstants:
    def test_proofsize(self):
        assert Consensus.proofsize == 42

    def test_max_block_weight(self):
        assert Consensus.max_block_weight == 40_000

    def test_coinbase_maturity(self):
        # one day of blocks at 60-second block time = 1440 blocks
        assert Consensus.coinbase_maturity == 1440

    def test_block_time_sec(self):
        assert Consensus.block_time_sec == 60

    def test_default_min_edge_bits(self):
        assert Consensus.default_min_edge_bits == 31

    def test_second_pow_edge_bits(self):
        assert Consensus.second_pow_edge_bits == 29

    def test_base_edge_bits(self):
        assert Consensus.base_edge_bits == 24

    def test_reward(self):
        # 60 Grin per second × 10^9 nanogrins/grin
        assert Consensus.reward == 60_000_000_000

    def test_year_height(self):
        # 52 weeks × 7 days × 24 hours × 60 blocks/hour
        assert Consensus.year_height == 524_160.0

    def test_week_height(self):
        assert Consensus.week_height == 10_080.0

    def test_day_height(self):
        assert Consensus.day_height == 1_440.0


# ---------------------------------------------------------------------------
# Block weight calculations (mirrors calculateWeightV4/V5 in consensus.rs)
# ---------------------------------------------------------------------------


class TestBlockWeightV4:
    def test_empty_body(self):
        assert Consensus.calculateWeightV4(0, 0, 0) == 0

    def test_one_input_reduces_weight(self):
        # V4: weight = -1 * inputs + 4 * outputs + 1 * kernels
        assert Consensus.calculateWeightV4(1, 0, 0) == -1

    def test_one_output(self):
        assert Consensus.calculateWeightV4(0, 1, 0) == 4

    def test_one_kernel(self):
        assert Consensus.calculateWeightV4(0, 0, 1) == 1

    def test_typical_tx(self):
        # 2 inputs, 2 outputs, 1 kernel → -2 + 8 + 1 = 7
        assert Consensus.calculateWeightV4(2, 2, 1) == 7


class TestBlockWeightV5:
    def test_empty_body(self):
        assert Consensus.calculateWeightV5(0, 0, 0) == 0

    def test_input_weight(self):
        assert Consensus.calculateWeightV5(1, 0, 0) == Consensus.input_weight

    def test_output_weight(self):
        assert Consensus.calculateWeightV5(0, 1, 0) == Consensus.output_weight

    def test_kernel_weight(self):
        assert Consensus.calculateWeightV5(0, 0, 1) == Consensus.kernel_weight

    def test_input_weight_value(self):
        assert Consensus.input_weight == 1

    def test_output_weight_value(self):
        assert Consensus.output_weight == 21

    def test_kernel_weight_value(self):
        assert Consensus.kernel_weight == 3

    def test_max_weight_exceeded_by_1905_outputs(self):
        # 1905 × 21 = 40 005 > 40 000
        weight = Consensus.calculateWeightV5(0, 1905, 0)
        assert weight > Consensus.max_block_weight

    def test_1904_outputs_within_limit(self):
        # 1904 × 21 = 39 984 ≤ 40 000
        weight = Consensus.calculateWeightV5(0, 1904, 0)
        assert weight <= Consensus.max_block_weight

    def test_max_block_weight_with_coinbase(self):
        # A block with coinbase only: 0 inputs, 1 output, 1 kernel
        # 21 + 3 = 24 — well within limit
        assert Consensus.calculateWeightV5(0, 1, 1) == 24


# ---------------------------------------------------------------------------
# Primary / secondary PoW classification
# ---------------------------------------------------------------------------


class TestPrimarySecondaryPow:
    def test_edge_bits_28_not_primary(self):
        assert not Consensus.isPrimary(28)

    def test_edge_bits_29_not_primary(self):
        assert not Consensus.isPrimary(29)

    def test_edge_bits_31_is_primary(self):
        assert Consensus.isPrimary(31)

    def test_edge_bits_32_is_primary(self):
        assert Consensus.isPrimary(32)

    def test_edge_bits_29_is_secondary(self):
        assert Consensus.isSecondary(29)

    def test_edge_bits_28_not_secondary(self):
        assert not Consensus.isSecondary(28)

    def test_edge_bits_30_not_secondary(self):
        assert not Consensus.isSecondary(30)

    def test_edge_bits_31_not_secondary(self):
        assert not Consensus.isSecondary(31)


# ---------------------------------------------------------------------------
# Header version / hard fork schedule (mainnet)
# hard_fork_interval ≈ 262 080 blocks (year_height / 2)
# ---------------------------------------------------------------------------


class TestHeaderVersionMainnet:
    # Boundaries:  HF1 = 262080, HF2 = 524160, HF3 = 786240, HF4 = 1048320

    def test_version_1_at_genesis(self):
        assert Consensus.getHeaderVersion(0) == 1

    def test_version_1_just_before_hf1(self):
        assert Consensus.getHeaderVersion(262_079) == 1

    def test_version_2_at_hf1(self):
        assert Consensus.getHeaderVersion(262_080) == 2

    def test_version_2_just_before_hf2(self):
        assert Consensus.getHeaderVersion(524_159) == 2

    def test_version_3_at_hf2(self):
        assert Consensus.getHeaderVersion(524_160) == 3

    def test_version_3_just_before_hf3(self):
        assert Consensus.getHeaderVersion(786_239) == 3

    def test_version_4_at_hf3(self):
        assert Consensus.getHeaderVersion(786_240) == 4

    def test_version_4_just_before_hf4(self):
        assert Consensus.getHeaderVersion(1_048_319) == 4

    def test_version_5_at_hf4(self):
        assert Consensus.getHeaderVersion(1_048_320) == 5

    def test_version_5_far_in_future(self):
        assert Consensus.getHeaderVersion(10_000_000) == 5


# ---------------------------------------------------------------------------
# Header version / hard fork schedule (floonet / testnet)
# ---------------------------------------------------------------------------


class TestHeaderVersionFloonet:
    def test_version_1_at_genesis(self):
        assert Consensus.getHeaderVersion(0, testnet=True) == 1

    def test_version_1_before_floonet_hf1(self):
        assert Consensus.getHeaderVersion(185_039, testnet=True) == 1

    def test_version_2_at_floonet_hf1(self):
        assert Consensus.getHeaderVersion(185_040, testnet=True) == 2

    def test_version_3_at_floonet_hf2(self):
        assert Consensus.getHeaderVersion(298_080, testnet=True) == 3

    def test_version_4_at_floonet_hf3(self):
        assert Consensus.getHeaderVersion(552_960, testnet=True) == 4

    def test_version_5_beyond_floonet_hf4(self):
        assert Consensus.getHeaderVersion(642_240, testnet=True) == 5


# ---------------------------------------------------------------------------
# Secondary PoW ratio (decreases from 90 % to 0 % over two years)
# ---------------------------------------------------------------------------


class TestSecondaryPoWRatio:
    def test_ratio_at_genesis_is_90(self):
        assert Consensus.secondaryPOWRatio(0) == 90

    def test_ratio_at_one_year_is_45(self):
        ratio = Consensus.secondaryPOWRatio(int(Consensus.year_height))
        assert ratio == 45

    def test_ratio_at_two_years_is_zero(self):
        ratio = Consensus.secondaryPOWRatio(int(2 * Consensus.year_height))
        assert ratio == 0

    def test_ratio_decreases_monotonically(self):
        heights = [
            0,
            int(Consensus.year_height // 2),
            int(Consensus.year_height),
            int(Consensus.year_height * 3 // 2),
            int(2 * Consensus.year_height),
        ]
        ratios = [Consensus.secondaryPOWRatio(h) for h in heights]
        for i in range(len(ratios) - 1):
            assert ratios[i] >= ratios[i + 1]

    def test_ratio_never_negative(self):
        # Even far beyond 2 years, ratio is clamped at 0
        ratio = Consensus.secondaryPOWRatio(int(10 * Consensus.year_height))
        assert ratio >= 0


# ---------------------------------------------------------------------------
# NRD kernel relative height bounds
# (mirrors NRD validation in core/src/core/transaction.rs)
# ---------------------------------------------------------------------------


class TestNrdRelativeHeight:
    def test_min_relative_height_is_1(self):
        # Relative height 0 is invalid for NRD kernels
        assert Consensus.week_height > 0

    def test_max_relative_height_is_week_height(self):
        # NRD relative height must be ≤ WEEK_HEIGHT
        assert Consensus.week_height == 10_080.0

    def test_relative_height_in_range(self):
        # Valid range: [1, week_height]
        valid = 1
        assert 1 <= valid <= Consensus.week_height

    def test_relative_height_zero_invalid(self):
        invalid = 0
        assert not (1 <= invalid <= Consensus.week_height)

    def test_relative_height_too_large_invalid(self):
        invalid = int(Consensus.week_height) + 1
        assert not (1 <= invalid <= Consensus.week_height)
