from mimblewimble.wallet import Wallet

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
    pay_slate, alice_secret_key, alice_secret_nonce = alice_wallet.pay(
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