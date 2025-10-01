from hashlib import sha256
import time

from mimblewimble.wallet import Wallet

from mimblewimble.models.slatepack.address import SlatepackAddress
from mimblewimble.models.slatepack.metadata import SlatepackVersion
from mimblewimble.models.slatepack.metadata import SlatepackMetadata
from mimblewimble.models.slatepack.message import SlatepackMessage, EMode

def test_srs_flow_slatepacks():
    # prepare wallets
    alice_path = 'm/0/1/0'
    alice_wallet = Wallet.initialize()
    alice_address = alice_wallet.getSlatepackAddress()

    bob_path = 'm/0/1/0'
    bob_wallet = Wallet.initialize()
    bob_address = bob_wallet.getSlatepackAddress()

    # prepare transaction data
    coinbase_amount = 60000000000
    kernel, output = alice_wallet.createCoinbase(
        coinbase_amount, path=alice_path)

    num_change_outputs = 1
    amount = 30000000000
    fee_base = 7000000
    block_height = 99999

    # prepare send transaction
    send_slate, secret_key, secret_nonce = alice_wallet.send(
        [output], num_change_outputs, amount, fee_base, block_height,
        path=alice_path, receiver_address=bob_address)
    send_slate_payload = send_slate.serialize()

    # prepare S1 send slatepack
    version = SlatepackVersion(0, 0)
    metadata = SlatepackMetadata(
        sender=SlatepackAddress.fromBech32(alice_address))
    emode = EMode.PLAINTEXT
    send_slatepack_message = SlatepackMessage(
        version, metadata, emode, send_slate_payload)
    assert not send_slatepack_message.is_encrypted()

    # encrypt the S1 slatepack
    send_slatepack_message.encryptPayload(
        [SlatepackAddress.fromBech32(bob_address)])
    slatepack_S1 = send_slatepack_message.pack()
    assert send_slatepack_message.is_encrypted()
    # now Alice sends slatepack_S1 to Bob

    # Bob receives it
    received_slatepack_S1 = bob_wallet.decryptSlatepack(
        slatepack_S1, path=bob_path)
    assert received_slatepack_S1.payload == send_slate_payload
    received_send_slate = received_slatepack_S1.getSlate()

    # now Bob has decrypted slate that Alice sent him
    # he is preparing his own slate
    receive_slate = bob_wallet.receive(received_send_slate)
    receive_slate_payload = receive_slate.serialize()

    # prepare slatepack_S2 for Alice
    version = SlatepackVersion(0, 0)
    metadata = SlatepackMetadata(
        sender=SlatepackAddress.fromBech32(bob_address))
    emode = EMode.PLAINTEXT
    receive_slatepack_message = SlatepackMessage(
        version, metadata, emode, receive_slate_payload)
    assert not receive_slatepack_message.is_encrypted()

    receive_slatepack_message.encryptPayload(
        [SlatepackAddress.fromBech32(alice_address)])
    slatepack_S2 = receive_slatepack_message.pack()
    # now Bob sends slatepack_S2 back to Alice

    # Alice receive it
    received_receive_slatepack_message = alice_wallet.decryptSlatepack(
        slatepack_S2, path=alice_path)
    assert received_receive_slatepack_message.payload == receive_slate_payload
    received_receive_slate = received_receive_slatepack_message.getSlate()

    # now Alice has decrypted slate that Bob sent her
    # she is ready to finalize the transaction
    finalized_slate = alice_wallet.finalize(
        received_receive_slate, secret_key, secret_nonce, path=alice_path)
    # this is the final slate that can be broadcasted to nodes

