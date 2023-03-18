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


def test_srs_flow():
    alice_path = 'm/0/1/0'
    alice_wallet = Wallet.initialize()
    alice_address = alice_wallet.getSlatepackAddress()

    bob_path = 'm/0/1/0'
    bob_wallet = Wallet.initialize()
    bob_address = bob_wallet.getSlatepackAddress()

    coinbase_amount = 60000000000
    kernel, output = alice_wallet.createCoinbase(
        coinbase_amount, path=alice_path)

    num_change_outputs = 1
    amount = 30000000000
    fee_base = 7000000
    block_height = 99999

    # send
    send_slate, secret_key, secret_nonce = alice_wallet.send(
        [output], num_change_outputs, amount, fee_base, block_height,
        path=alice_path, receiver_address=bob_address)

    # receive
    receive_slate = bob_wallet.receive(send_slate)

    # finalize
    finalized_slate = alice_wallet.finalize(
        receive_slate, secret_key, secret_nonce, path=alice_path)
