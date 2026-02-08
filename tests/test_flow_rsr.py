import pytest

from tests.utils import MockNode

from mimblewimble.wallet import Wallet
from mimblewimble.wallet import WalletStorageInMemory, PersistentWallet, NodeAccess

from mimblewimble.models.slatepack.address import SlatepackAddress
from mimblewimble.models.slatepack.metadata import SlatepackVersion
from mimblewimble.models.slatepack.metadata import SlatepackMetadata
from mimblewimble.models.slatepack.message import SlatepackMessage, EMode


def test_rsr_flow_slatepacks():
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

    # prepare invoice transaction
    invoice_slate, bob_secret_key, bob_secret_nonce = bob_wallet.invoice(amount, path=bob_path, block_height=block_height)
    invoice_slate_payload = invoice_slate.serialize()

    # prepare R1 invoice slatepack
    version = SlatepackVersion(0, 0)
    metadata = SlatepackMetadata(
        sender=SlatepackAddress.fromBech32(alice_address))
    emode = EMode.PLAINTEXT
    invoice_slatepack_message = SlatepackMessage(
        version, metadata, emode, invoice_slate_payload)
    assert not invoice_slatepack_message.is_encrypted()

    # encrypt the R1 slatepack
    invoice_slatepack_message.encryptPayload(
        [SlatepackAddress.fromBech32(alice_address)])
    slatepack_R1 = invoice_slatepack_message.pack()
    assert invoice_slatepack_message.is_encrypted()
    # now Bob sends slatepack_R1 to Alice

    # Alice receives it
    received_slatepack_R1 = alice_wallet.decryptSlatepack(
        slatepack_R1, path=alice_path)
    assert received_slatepack_R1.payload == invoice_slate_payload
    received_invoice_slate = received_slatepack_R1.getSlate()

    # now Alice has decrypted slate that Bob sent her
    # she is preparing her own slate
    pay_slate, alice_secret_key, alice_secret_nonce, change_outputs = alice_wallet.pay(
        received_invoice_slate,
        [output],
        num_change_outputs,
        fee_base,
        alice_path)
    pay_slate_payload = pay_slate.serialize()

    # prepare slatepack_R2 for Bob
    version = SlatepackVersion(0, 0)
    metadata = SlatepackMetadata(
        sender=SlatepackAddress.fromBech32(alice_address))
    emode = EMode.PLAINTEXT
    pay_slatepack_message = SlatepackMessage(
        version, metadata, emode, pay_slate_payload)
    assert not pay_slatepack_message.is_encrypted()

    pay_slatepack_message.encryptPayload(
        [SlatepackAddress.fromBech32(bob_address)])
    slatepack_R2 = pay_slatepack_message.pack()
    # now Alice sends slatepack_R2 back to Bob

    # Bob receive it
    received_pay_slatepack_message = bob_wallet.decryptSlatepack(
        slatepack_R2, path=bob_path)
    assert received_pay_slatepack_message.payload == pay_slate_payload
    received_pay_slate = received_pay_slatepack_message.getSlate()

    # now Bob has decrypted slate that Alice sent him
    # he is ready to finalize the transaction
    finalized_slate = bob_wallet.finalize(
        received_pay_slate, path=bob_path)
    # this is the final slate that can be broadcasted to nodes


def test_rsr_flow_slatepacks_persistent():
    mock_node = MockNode()

    # prepare wallets
    alice_path = 'm/0/1/0'
    alice_wallet = PersistentWallet(
        Wallet.initialize(), WalletStorageInMemory(), mock_node)
    alice_recovery_phrase = alice_wallet.getSeedPhrase()

    bob_path = 'm/0/1/0'
    bob_wallet = PersistentWallet(
        Wallet.initialize(), WalletStorageInMemory(), mock_node)
    bob_recovery_phrase = bob_wallet.getSeedPhrase()

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

    # Bob prepares invoice transaction
    r1_slatepack_message = bob_wallet.invoice(
        30000000000,
        path=bob_path,
        receiver=alice_wallet.getSlatepackAddress())
    r1_slatepack_text = r1_slatepack_message.pack()  # this text gets sent back to Bob

    # now Alice receives R1 slatepack
    r1_slatepack_message_received = SlatepackMessage.unarmor(r1_slatepack_text)
    assert r1_slatepack_message_received.is_encrypted()

    # Alice attempts to pay the invoice, but has no funds yet
    with pytest.raises(Exception, match='Insufficient funds'):
        alice_wallet.pay(
            r1_slatepack_message, path=alice_path, fee_base=fee_base)

    # Alice needs some coinbase to pay Bob's invoice
    coinbase_amount = 60000000000
    coinbase_transaction = alice_wallet.createCoinbase(
        coinbase_amount, path=alice_path)

    # submit the coinbase transaction to the node
    mock_node.push_transaction(coinbase_transaction)

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

    # Alice pays the invoice
    r2_slatepack_message = alice_wallet.pay(
        r1_slatepack_message, path=alice_path, fee_base=fee_base)
    r2_slatepack_text = r2_slatepack_message.pack()  # this text gets sent back to Bob

    # extract slate from R2 slatepack to check fee
    # we use Bob's wallet as Alice encrypted the slatepack for Bob
    # unlike in SRS, in RSR flow the fee gets decided at Pay step (second step)
    slate_fee = bob_wallet.decryptSlatepack(r2_slatepack_message).getSlate().getFee().getFee()
    assert slate_fee == 322000000

    # now Bob receives R2 slatepack
    r2_slatepack_message_received = SlatepackMessage.unarmor(r2_slatepack_text)
    assert r2_slatepack_message_received.is_encrypted()

    # they both check their wallets to see locked output amounts
    alice_balance = alice_wallet.balance().toJSON()
    assert alice_balance == {
        'locked': 60000000000,
        'awaiting_confirmation': 30000000000 - slate_fee,
        'spendable': 0,
        'total': 30000000000 - slate_fee,
    }

    bob_balance = bob_wallet.balance().toJSON()
    assert bob_balance == {
        'locked': 0,
        'awaiting_confirmation': 30000000000,
        'spendable': 0,
        'total': 30000000000
    }

    # Bob finalizes the transaction
    finalized_slate = bob_wallet.finalize(
        r2_slatepack_message, path=bob_path)

    # Bob sends transaction to node
    bob_wallet.push_finalized_slatepack(finalized_slate)

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
        'total': 30000000000 - slate_fee,
    }

    bob_balance = bob_wallet.balance().toJSON()
    assert bob_balance == {
        'locked': 0,
        'awaiting_confirmation': 0,
        'spendable': 30000000000,
        'total': 30000000000
    }

    # test restoring wallet from seed phrase and syncing with node
    # first Alice
    alice_wallet_restored = PersistentWallet.restoreFromSeedPhrase(
        alice_recovery_phrase, WalletStorageInMemory(), mock_node)
    assert not alice_wallet_restored.is_synced()

    alice_wallet_restored.scan()

    alice_balance_restored = alice_wallet_restored.balance().toJSON()
    assert alice_balance_restored == {
        'locked': 0,
        'awaiting_confirmation': 0,
        'spendable': 30000000000 - slate_fee,
        'total': 30000000000 - slate_fee,
    }
    assert alice_wallet_restored.is_synced()

    # now Bob
    bob_wallet_restored = PersistentWallet.restoreFromSeedPhrase(
        bob_recovery_phrase, WalletStorageInMemory(), mock_node)
    assert not bob_wallet_restored.is_synced()

    bob_wallet_restored.scan()

    bob_balance_restored = bob_wallet.balance().toJSON()
    assert bob_balance_restored == {
        'locked': 0,
        'awaiting_confirmation': 0,
        'spendable': 30000000000,
        'total': 30000000000
    }

    assert bob_wallet_restored.is_synced()