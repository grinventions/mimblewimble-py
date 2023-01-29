import os

from mimblewimble.crypto.secret_key import SecretKey
from mimblewimble.crypto.public_key import PublicKey

from mimblewimble.crypto.aggsig import AggSig
from mimblewimble.crypto.public_keys import PublicKeys

def test_aggsig_interaction():
    agg = AggSig()
    pks = PublicKeys()

    # random message
    message = os.urandom(32)

    # sender party
    secretKeySender = SecretKey(os.urandom(32))
    publicKeySender = pks.calculatePublicKey(secretKeySender)

    secretNonceSender = agg.generateSecureNonce()
    publicNonceSender = pks.calculatePublicKey(secretNonceSender)

    # receiver party
    secretKeyReceiver = SecretKey(os.urandom(32))
    publicKeyReceiver = pks.calculatePublicKey(secretKeyReceiver)

    secretNonceReceiver = agg.generateSecureNonce()
    publicNonceReceiver = pks.calculatePublicKey(secretNonceReceiver)

    # add public keys
    sumPubKeys = pks.publicKeySum([publicKeySender, publicKeyReceiver])
    sumPubNonces = pks.publicKeySum([publicNonceSender, publicNonceReceiver])

    # generate partial signatures
    senderPartialSignature = agg.calculatePartialSignature(
        secretKeySender, secretNonceSender, sumPubKeys, sumPubNonces, message)
    receiverPartialSignature = agg.calculatePartialSignature(
        secretKeyReceiver, secretNonceReceiver, sumPubKeys, sumPubNonces, message)

    # verify partial signatures
    senderSigValid = agg.verifyPartialSignature(
        senderPartialSignature, publicKeySender,
        sumPubKeys, sumPubNonces, message)
    receiverSigValid = agg.verifyPartialSignature(
        receiverPartialSignature, publicKeyReceiver,
        sumPubKeys, sumPubNonces, message)

    assert senderSigValid
    assert receiverSigValid

    # aggregate the partial signatures
    aggregate = agg.aggregateSignatures(
        [senderPartialSignature, receiverPartialSignature], sumPubNonces)
    aggregateValid = agg.verifyAggregateSignature(aggregate, sumPubKeys, message)

    assert aggregateValid
