from mimblewimble.consensus import Consensus


def calculateFee(fee_base: int, num_inputs: int, num_outputs: int, num_kernels: int):
    return fee_base * Consensus.calculateWeightV5(num_inputs, num_outputs, num_kernels)
