from mimblewimble.models.transaction import TransactionKernel
from mimblewimble.models.transaction import TransactionOutput

from mimblewimble.wallet import Wallet


def test_coinbase_construction():
    w = Wallet.initialize()

    amount = 60
    kernel, output, path = w.createCoinbase(amount, path='m/0/1/0')

    assert isinstance(kernel, TransactionKernel)
    assert isinstance(output, TransactionOutput)
    assert path == 'm/0/1/0'

