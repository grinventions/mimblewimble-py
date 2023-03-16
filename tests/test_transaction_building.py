from mimblewimble.models.transaction import TransactionKernel
from mimblewimble.models.transaction import TransactionOutput

from mimblewimble.entity import OutputDataEntity

from mimblewimble.wallet import Wallet


def test_coinbase_construction():
    w = Wallet.initialize()

    amount = 60
    kernel, output = w.createCoinbase(amount, path='m/0/1/0')

    assert isinstance(kernel, TransactionKernel)
    assert isinstance(output, OutputDataEntity)
    assert isinstance(output.output, TransactionOutput)
    assert output.path == 'm/0/1/0'

