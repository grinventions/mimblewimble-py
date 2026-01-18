from hashlib import sha256
import time
from typing import List

import pytest

from tests.utils import MockNode

from mimblewimble.entity import OutputDataEntity
from mimblewimble.models.transaction import EOutputStatus

from mimblewimble.wallet import Wallet
from mimblewimble.wallet import WalletStorageInMemory, PersistentWallet, NodeAccess

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
    send_slate, alice_secret_key, alice_secret_nonce, change_outputs = alice_wallet.send(
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
    receive_slate, bob_secret_key, bob_secret_nonce = bob_wallet.receive(received_send_slate)
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
        received_receive_slate, path=alice_path)
    # this is the final slate that can be broadcasted to nodes

def test_srs_flow_slatepacks_persistent():
    mock_node = MockNode()

    # prepare wallets
    alice_path = 'm/0/1/0'
    alice_wallet = PersistentWallet(
        Wallet.initialize(), WalletStorageInMemory(), mock_node)

    bob_path = 'm/0/1/0'
    bob_wallet = PersistentWallet(
        Wallet.initialize(), WalletStorageInMemory(), mock_node)

    # transaction setup
    fee_base = 7000000

    # check balance, every wallet is empty
    assert alice_wallet.balance().toJSON() == {
        'locked': 0,
        'awaiting_confirmation': 0,
        'spendable': 0,
        'total': 0
    }
    assert bob_wallet.balance().toJSON() == {
        'locked': 0,
        'awaiting_confirmation': 0,
        'spendable': 0,
        'total': 0
    }

    # Alice needs some coinbase to send to Bob
    coinbase_amount = 60000000000
    coinbase_transaction = alice_wallet.createCoinbase(
        coinbase_amount, path=alice_path)

    # submit the coinbase transaction to the node
    mock_node.push_transaction(coinbase_transaction)

    # prepare S1 send slatepack, but Alice has no confirmed funds yet
    with pytest.raises(Exception, match='Insufficient funds'):
        alice_wallet.send(
            30000000000,
            bob_wallet.getSlatepackAddress(),
            fee_base=fee_base)

    # mine a block to confirm Alice's coinbase
    mock_node.mine()

    # now Alice needs to refresh her wallet to detect confirmed funds
    alice_wallet.refresh()

    # Alice should have her confirmed coinbase balance now
    assert alice_wallet.balance().toJSON() == {
        'locked': 0,
        'awaiting_confirmation': 0,
        'spendable': 60000000000,
        'total': 60000000000
    }

    # now Alice can prepare S1 send slatepack
    s1_slatepack_message = alice_wallet.send(
        30000000000,
        bob_wallet.getSlatepackAddress(),
        fee_base=fee_base)
    s1_slatepack_text = s1_slatepack_message.pack() # this text gets sent to Bob

    # extract slate from S1 slatepack to check fee
    # we use Bob's wallet as Alice encrypted the slatepack for Bob
    slate_fee = bob_wallet.decryptSlatepack(s1_slatepack_message).getSlate().getFee().getFee()
    assert slate_fee == 322000000

    # check Alice's wallet outputs, the coinbase should be there but unconfirmed
    # also we expect main output to be locked
    assert alice_wallet.balance().toJSON() == {
        'locked': 60000000000,
        'awaiting_confirmation': 30000000000 - slate_fee,
        'spendable': 0,
        'total': 30000000000 - slate_fee
    }

    # now Bob receives S1 slatepack
    s1_slatepack_message_received = SlatepackMessage.unarmor(s1_slatepack_text)
    assert s1_slatepack_message_received.is_encrypted()
    s2_slatepack_message = bob_wallet.receive(s1_slatepack_message_received, path=bob_path)
    s2_slatepack_text = s2_slatepack_message.pack()  # this text gets sent back to Alice

    # check Bob's wallet outputs, the incoming funds should be there but unconfirmed
    assert bob_wallet.balance().toJSON() == {
        'locked': 0,
        'awaiting_confirmation': 30000000000,
        'spendable': 0,
        'total': 30000000000
    }

    # now Alice receives S2 slatepack
    s2_slatepack_message_received = SlatepackMessage.unarmor(s2_slatepack_text)
    assert s2_slatepack_message_received.is_encrypted()
    finalized_slate = alice_wallet.finalize(
        s2_slatepack_message_received, path=alice_path)

    # Alice sends transaction to node
    alice_wallet.push_finalized_slatepack(finalized_slate)

    # mine a block to confirm the transaction
    mock_node.mine()

    # they both check their wallets
    alice_wallet.refresh()
    bob_wallet.refresh()

    # check their balances
    alice_balance = alice_wallet.balance().toJSON()
    assert alice_balance == {
        'locked': 0,
        'awaiting_confirmation': 0,
        'spendable': 30000000000 - slate_fee,
        'total': 30000000000 - slate_fee
    }

    bob_balance = bob_wallet.balance().toJSON()
    assert bob_balance == {
        'locked': 0,
        'awaiting_confirmation': 0,
        'spendable': 30000000000,
        'total': 30000000000
    }