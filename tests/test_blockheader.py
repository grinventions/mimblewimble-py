import unittest

from mimblewimble.blockchain import ProofOfWork, BlockHeader


class BlockHeaderTest(unittest.TestCase):
    def test_deserialize(self):
        version = 1
        height = 2
        timestamp = 3

        previousBlockHash = bytes.fromhex('0102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2021')
        previousRoot = bytes.fromhex('1102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2021')
        outputRoot = bytes.fromhex('2102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2021')
        rangeProofRoot = bytes.fromhex('3102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2021')
        kernelRoot = bytes.fromhex('4102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2021')
        totalKernelOffset = bytes.fromhex('5102030405060708090A0B0C0D0E0F1112131415161718191A1B1C1D1E1F2021')

        outputMMRSize = 4
        kernelMMRSize = 7
        totalDifficulty = 1000
        scalingDifficulty = 10
        nonce = 123456

        proofOfWork = ProofOfWork(bytes.fromhex('00001010'), [])

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
            proofOfWork)

        assert block_header.getNumOutputs() == 3
        assert block_header.getNumKernels() == 4
