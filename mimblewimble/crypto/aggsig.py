from secp256k1_zkp_mw import SECP256K1_CONTEXT_SIGN
from secp256k1_zkp_mw import SECP256K1_CONTEXT_VERIFY

from secp256k1_zkp_mw import secp256k1_context_create
from secp256k1_zkp_mw import secp256k1_context_destroy

class AggSig:
    def __init__(self):
        self.ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)

    def __del__(self):
        secp256k1_context_destroy(self.ctx)

    def generateSecureNonce(self):
        pass

    def buildSignature(self, secretKey, commitment, message):
        pass

    def calculatePartialSignature(
            self, secretKey, secretNonce, sumPubKeys, sumPubNonces, sumPubNonces):
        pass

    def verifyPartialSignature(
            self, partialSignature, publicKey, sumPubKeys, sumPubNonces, message):
        pass

    def aggregateSignatures(self, signatures, sumPubNonces):
        pass

    def verifyAggregateSignatures(self, signatures, commitments, messages):
        pass

    def verifyAggregateSignature(self, signature, commitment, message):
        pass

    def parseCompactSignatures(self, signatures):
        pass

    def toCompact(self, signature):
        pass
