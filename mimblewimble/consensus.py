import math


class Consensus:
    # A grin is divisible to 10^9, following the SI prefixes
    grin_base = 1000000000

    # Milligrin, a thousand of a grin
    milli_grin = grin_base/1000

    # Microgrin, a thousand of a milligrin
    micro_grin = milli_grin/1000

    # Nanogrin, smallest unit, takes a billion to make a grin
    nano_grin = 1

    # The block subsidy amount, one grin per second on average
    reward = 60*grin_base

    # Weight of an input when counted against the max block weight capacity
    input_weight = 1

    # Weight of an output when counted against the max block weight capacity
    output_weight = 21

    # Weight of a kernel when counted against the max block weight capacity
    kernel_weight = 3

    # Total maximum block weight
    max_block_weight = 40000

    @classmethod
    def calculateWeightV4(self, num_inputs, num_outputs, num_kernels):
        return -1*num_inputs + 4*num_outputs + num_kernels

    @classmethod
    def calculateWeightV5(self, num_inputs, num_outputs, num_kernels):
        return num_inputs*Consensus.input_weight + num_outputs*Consensus.output_weight + num_kernels*Consensus.kernel_weight

    # Block interval, in seconds
    block_time_sec = 60

    # Nominal height for standards time intervals, hour is 60 blocks
    hour_height = 3600 / block_time_sec

    @classmethod
    def hours(self, num_hours):
        return num_hours*hour_height

    # A day is 1440 blocks
    day_height = 24*hour_height

    @classmethod
    def days(self, num_days):
        return num_days*day_height

    # A week is 10,080 blocks
    week_height = 7*day_height

    @classmethod
    def weeks(self, num_weeks):
        return num_weeks*week_height

    # A year is 524,160 blocks
    year_height = 52*week_height

    @classmethod
    def years(self, num_years):
        return num_years*year_height

    # Number of blocks before a coinbase matures and can be spent
    # set to nominal number of block in one day (1440 with 1-minute blocks)
    coinbase_maturity = (24*60*60)/block_time_sec

    @classmethod
    def getMaxCoinbaseHeight(blockHeight, automated_testing=False):
        if automated_testing:
            return math.max(blockHeight, 25)-20
        return math.max(blockHeight, coinbase_maturity)-coinbase_maturity

    # Default number of blocks in the past when cross-block cut-through will start happening
    cut_through_horizon = week_height

    @classmethod
    def getHorizonHeight(block_height):
        return math.max(block_height, cut_through_horizon) - cut_through_horizon

    # Default number of blocks in the past to determine the height where we request a txhashset
    state_sync_threshold = 2*day_height

    # Time window in blocks to calculate block time median
    median_time_window = 11

    # Index at half the desired median
    median_time_index = median_time_window/2

    # Number of blocks used to calculate difficulty adjustments
    difficulty_adjust_window = hour_height

    # Average time span of the difficulty adjustment window
    block_time_window = difficulty_adjust_window*block_time_sec

    # Maximum size time window used for difficulty adjustments
    upper_time_bound = block_time_window*2

    # Minimum size time window used for difficulty adjustments
    lower_time_bound = block_time_window/2

    # default Future Time Limit (FTL) of 5 minutes
    default_future_time_limit_sec = 5*block_time_sec

    # Refuse blocks more than 12 block intervals in the future.
    @classmethod
    def getMaxBlockTime(current_time):
        return currentTime + default_future_time_limit_sec

    # Difficulty adjustment half life (actually, 60s * number of 0s-blocks to raise diff by factor e) is 4 hours
    wtema_half_life = 4*3600

    # Cuckoo-cycle proof size (cycle length)
    proofsize = 42

    # Default Cuckoo Cycle size shift used for mining and validating.
    default_min_edge_bits = 31

    # Secondary proof-of-work size shift, meant to be ASIC resistant.
    second_pow_edge_bits = 29

    # Original reference edge_bits to compute difficulty factors for higher Cuckoo graph sizes, changing this would hard fork
    base_edge_bits = 24

    # Clamp factor to use for difficulty adjustment
	# Limit value to within this factor of goal
    clamp_factor = 2

    # Dampening factor to use for difficulty adjustment
    dma_damp_factor = 3

    # Dampening factor to use for AR scale calculation.
    ar_scale_damp_factor = 13

    # Minimum scaling factor for AR pow, enforced in diff retargetting
	# avoids getting stuck when trying to increase ar_scale subject to dampening
    min_ar_scale = ar_scale_damp_factor

    # Minimum difficulty, enforced in diff retargetting
	# avoids getting stuck when trying to increase difficulty subject to dampening
    min_dma_difficulty = dma_damp_factor

    # Compute weight of a graph as number of siphash bits defining the graph
    # Must be made dependent on height to phase out smaller size over the years
    @classmethod
    def graphWeight(self, height, edge_bits):
        expiry_height = int(year_height)
        xpr_edge_bits = int(edge_bits)
        if edge_bits == 31 and height >= expiry_height:
            xpr_edge_bits -= math.min(xpr_edge_bits, 1+(height-expiry_height)/week_height)
        return 2 << (edge_bits-base_edge_bits)*xpr_edge_bits

    # Initial mining secondary scale
    @classmethod
    def initialGraphWeight(self):
        return graphWeight(0, second_pow_edge_bits)

    # Move value linearly toward a goal
    @classmethod
    def damp(actual, goal, damp_factor):
        return (actual + (damp_factor-1))/damp_factor

    # limit value to be within some factor from a goal
    @classmethod
    def clamp(actual, goal, clamp_factor):
        return math.max(goal/clamp_factor, math.min(actual, goal*clamp_factor))

    # Ratio the secondary proof of work should take over the primary, as a function of block height (time).
    # Starts at 90% losing a percent approximately every week. Represented as an integer between 0 and 100.
    @classmethod
    def secondaryPOWRatio(self, height):
        return 90-math.min(90, (height/(2*year_height/90)))

    @classmethod
    def scalingDifficulty(self, edgeBits):
        # TODO find a pure python way to ensure "2" is of uint64_t type
        return 2 << (edgeBits-base_edge_bits)*edgeBits

    # minimum solution difficulty after HardFork4 when PoW becomes primary only Cuckatoo32+
    # TODO find a pure python way to ensure "2" is of uint64_t type
    c32_graph_weight = 2 << (32-base_edge_bits)*32

    def min_wtema_graph_weight(self, testnet=False):
        if testnet:
            return self.GraphWeight(0, second_pow_edge_bits)
        return c32_graph_weight

    # Fork every 6 months.
    hard_fork_interval = year_height / 2

    # Floonet-only hardforks
    floonet_first_hard_fork = 185040
    floonet_second_hard_fork = 298080
    floonet_third_hard_fork = 552960
    floonet_fourth_hard_fork = 642240

    def getHeaderVersion(height, testnet=False):
        if testnet:
            if height < Consensus.floonet_first_hard_fork:
                return 1
            elif height < Consensus.floonet_second_hard_fork:
                return 2
            elif height < Consensus.floonet_third_hard_fork:
                return 3
            elif height < Consensus.floonet_fourth_hard_fork:
                return 4
        else:
            if height < Consensus.hard_fork_interval:
                return 1
            elif height < 2*Consensus.hard_fork_interval:
                return 2
            elif height < 3*Consensus.hard_fork_interval:
                return 3
            elif height < 4*Consensus.hard_fork_interval:
                return 4
        return 5

    def __init__(self):
        pass

    @classmethod
    def isPrimary(edgeBits):
        pass

    @classmethod
    def isSecondary(edgeBits):
        pass
