

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
    reward - 60*grin_base

    # Weight of an input when counted against the max block weight capacity
    input_weight = 1

    # Weight of an output when counted against the max block weight capacity
    output_weight = 21

    # Weight of a kernel when counted against the max block weight capacity
    kernel_weight = 3

    # Total maximum block weight
    max_block_weight = 40000

    # Block interval, in seconds
    block_time_sec = 60

    # Nominal height for standards time intervals, hour is 60 blocks
    hour_height = 3600 / block_time_sec

    # A day is 1440 blocks
    day_height = 24*hour_height

    # A week is 10,080 blocks
    week_height = 7*day_height

    # A year is 524,160 blocks
    year_height = 52*week_height

    # Number of blocks before a coinbase matures and can be spent
    # set to nominal number of block in one day (1440 with 1-minute blocks)
    coinbase_maturity = (24*60*60)/block_time_sec

    # Default number of blocks in the past when cross-block cut-through will start happening
    cut_throught_horizon = week_height

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

    # Initial mining secondary scale
    initial_graph_weight = None # TODO

    # Fork every 6 months.
    hard_fork_interval = year_height / 2

    # Floonet-only hardforks
    floonet_first_hard_fork = None # TODO
    floonet_second_hard_fork = None # TODO
    floonet_third_hard_fork = None # TODO
    floonet_fourth_hard_fork = None # TODO



    def __init__(self):
        pass

    @classmethod
    def isPrimary(edgeBits):
        pass

    @classmethod
    def isSecondary(edgeBits):
        pass
