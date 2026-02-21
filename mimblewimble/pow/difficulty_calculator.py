from typing import List
from dataclasses import dataclass

from mimblewimble.consensus import Consensus
from mimblewimble.pow.blockdb import IBlockDB


@dataclass
class HeaderInfo:
    difficulty: int
    secondary_scaling: int = 0
    timestamp: int = 0
    height: int = 0
    is_secondary: bool = False

    @classmethod
    def from_time_and_diff(cls, ts: int, diff: int) -> "HeaderInfo":
        return cls(
            timestamp=ts, difficulty=diff, secondary_scaling=0, is_secondary=False
        )

    @classmethod
    def from_diff_and_scaling(cls, diff: int, scaling: int = 0) -> "HeaderInfo":
        return cls(difficulty=diff, secondary_scaling=scaling)

    def get_difficulty(self) -> int:
        return self.difficulty

    def get_secondary_scaling(self) -> int:
        return self.secondary_scaling

    def get_timestamp(self) -> int:
        return self.timestamp

    def is_secondary(self) -> bool:
        return self.is_secondary


class DifficultyLoader:
    def __init__(self, block_db: IBlockDB):
        self.block_db = block_db  # your interface to get headers by hash

    def load_difficulty_data(self, header) -> List[HeaderInfo]:
        """
        Loads DIFFICULTY_ADJUST_WINDOW + 1 previous headers
        Returns them oldest → newest after padding + reversing
        """
        num_blocks_needed = Consensus.difficulty_adjust_window + 1
        difficulty_data: List[HeaderInfo] = []

        current = self.block_db.get_block_header(header.prev_hash)

        while len(difficulty_data) < num_blocks_needed and current is not None:
            ts = current.timestamp
            total_diff = current.total_difficulty
            scaling = current.scaling_difficulty  # or .GetScalingDifficulty()
            secondary = current.proof_of_work.is_secondary  # adapt to your real field

            prev = self.block_db.get_block_header(current.prev_hash)

            if prev is not None:
                diff = total_diff - prev.total_difficulty
            else:
                # very first block after genesis → use total difficulty as-is
                diff = total_diff

            difficulty_data.append(
                HeaderInfo(
                    timestamp=ts,
                    difficulty=diff,
                    secondary_scaling=scaling,
                    is_secondary=secondary,
                )
            )

            current = prev

        # Pad with fake pre-genesis blocks if needed + reverse order
        return self._pad_difficulty_data(difficulty_data)

    def _pad_difficulty_data(
        self, difficulty_data: List[HeaderInfo]
    ) -> List[HeaderInfo]:
        """
        Pads with simulated pre-genesis blocks if we don't have enough real data
        Returns oldest → newest order
        """
        num_needed = Consensus.difficulty_adjust_window + 1

        if len(difficulty_data) >= num_needed:
            difficulty_data.reverse()
            return difficulty_data

        # Estimate last real inter-block time delta
        last_ts_delta = Consensus.block_time_sec
        if len(difficulty_data) >= 2:
            # most recent real block - previous one
            last_ts_delta = difficulty_data[0].timestamp - difficulty_data[1].timestamp

        last_diff = difficulty_data[0].difficulty if difficulty_data else 0

        # Start from oldest real block's timestamp and go backwards
        last_ts = difficulty_data[-1].timestamp if difficulty_data else 0

        while len(difficulty_data) < num_needed:
            last_ts -= min(last_ts, last_ts_delta)
            fake = HeaderInfo.from_time_and_diff(last_ts, last_diff)
            difficulty_data.append(fake)

        difficulty_data.reverse()
        return difficulty_data


class DifficultyCalculator:
    def __init__(self, block_db: IBlockDB):
        self.block_db = block_db  # your block header database / cache / chain access

    def calculate_next_difficulty(self, header) -> HeaderInfo:
        if header.version < 5:
            return self.next_DMA(header)
        else:
            return self.next_WTEMA(header)

    def next_WTEMA(self, header) -> HeaderInfo:
        last_header = self.block_db.get_block_header(header.prev_hash)
        if last_header is None:
            raise RuntimeError("Last header not found")

        prev_header = self.block_db.get_block_header(last_header.prev_hash)
        if prev_header is None:
            raise RuntimeError("Previous header not found")

        last_block_time = last_header.timestamp - prev_header.timestamp
        last_diff = (
            last_header.total_difficulty - prev_header.total_difficulty
        )  # assuming total_difficulty exists

        # WTEMA style update
        numerator = last_diff * Consensus.wtema_half_life
        denominator = (
            Consensus.wtema_half_life - Consensus.block_time_sec + last_block_time
        )
        next_diff = numerator // denominator if denominator != 0 else last_diff

        # Very rough minimum difficulty floor (protects against very fast blocks)
        # You should replace min_wtema_graph_weight() with your real function
        min_diff = self.min_wtema_graph_weight()  # ← implement or define this

        difficulty = max(min_diff, next_diff)

        return HeaderInfo.from_diff_and_scaling(difficulty, 0)

    def next_DMA(self, header) -> HeaderInfo:
        loader = DifficultyLoader(self.block_db)  # assuming you have this class
        difficulty_data: List[HeaderInfo] = loader.load_difficulty_data(header)

        if len(difficulty_data) < 2:
            raise ValueError("Not enough difficulty data")

        # Skip first (oldest) element for secondary ratio calculation
        difficulty_data_skip_first = difficulty_data[1:]

        sec_pow_scaling = self.secondary_POW_scaling(
            header.height, difficulty_data_skip_first
        )

        # Timestamp delta over the whole window
        ts_delta = (
            difficulty_data[Consensus.difficulty_adjust_window].timestamp
            - difficulty_data[0].timestamp
        )

        # Sum of difficulties in the adjustment window (excluding oldest)
        difficulty_sum = sum(h.get_difficulty() for h in difficulty_data_skip_first)

        actual = self.damp(
            ts_delta, Consensus.block_time_window, Consensus.dma_damp_factor
        )
        adj_ts = self.clamp(actual, Consensus.block_time_window, Consensus.clamp_factor)

        difficulty = max(
            Consensus.min_dma_difficulty,
            (difficulty_sum * Consensus.block_time_sec) // adj_ts,
        )

        return HeaderInfo.from_diff_and_scaling(difficulty, sec_pow_scaling)

    def AR_count(self, difficulty_data: List[HeaderInfo]) -> int:
        num_secondary = sum(1 for h in difficulty_data if h.is_secondary())
        return num_secondary * 100

    def scaling_factor_sum(self, difficulty_data: List[HeaderInfo]) -> int:
        return sum(h.get_secondary_scaling() for h in difficulty_data)

    def secondary_POW_scaling(
        self, height: int, difficulty_data: List[HeaderInfo]
    ) -> int:
        scale_sum = self.scaling_factor_sum(difficulty_data)

        target_pct = Consensus.secondary_POW_ratio(
            height
        )  # ← you must implement / import this
        target_count = Consensus.difficulty_adjust_window * target_pct

        actual = self.damp(
            self.AR_count(difficulty_data), target_count, Consensus.ar_scale_damp_factor
        )
        adj_count = self.clamp(actual, target_count, Consensus.clamp_factor)

        if adj_count == 0:
            adj_count = 1

        scale = (scale_sum * target_pct) // adj_count

        return max(Consensus.min_ar_scale, scale)

    # ────────────────────────────────────────────────
    #          Helper functions (you need to adjust)
    # ────────────────────────────────────────────────

    def damp(self, value: int, goal: int, factor: int) -> int:
        """Very simple dampening - many coins use different formulas"""
        if factor <= 0:
            return value
        return (value * (factor - 1) + goal) // factor

    def clamp(self, value: int, goal: int, factor: int) -> int:
        """Clamp value to [goal/factor .. goal×factor] range"""
        min_val = goal // factor
        max_val = goal * factor
        return max(min_val, min(value, max_val))

    def min_wtema_graph_weight(self) -> int:
        # This is usually tied to minimal graph weight × some constant
        # Replace with your real logic
        return 16384  # placeholder – very low value
