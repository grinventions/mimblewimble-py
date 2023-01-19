import os

from secp256k1_zkp_mw import SECP256K1_CONTEXT_SIGN
from secp256k1_zkp_mw import SECP256K1_CONTEXT_VERIFY

from secp256k1_zkp_mw import secp256k1_context_create
from secp256k1_zkp_mw import secp256k1_context_destroy
from secp256k1_zkp_mw import secp256k1_context_randomize

from secp256k1_zkp_mw import secp256k1_aggsig_export_secnonce_single
from secp256k1_zkp_mw import secp256k1_aggsig_sign_single
from secp256k1_zkp_mw import secp256k1_aggsig_verify_single
from secp256k1_zkp_mw import secp256k1_aggsig_add_signatures_single

from secp256k1_zkp_mw import secp256k1_pedersen_commitment_parse
from secp256k1_zkp_mw import secp256k1_pedersen_commitment_to_pubkey

from secp256k1_zkp_mw import secp256k1_ec_pubkey_parse

from secp256k1_zkp_mw import secp256k1_schnorrsig_parse
from secp256k1_zkp_mw import secp256k1_schnorrsig_verify_batch

from secp256k1_zkp_mw import secp256k1_ecdsa_signature_parse_compact
from secp256k1_zkp_mw import secp256k1_ecdsa_signature_serialize_compact

from mimblewimble.crypto.commitment import Commitment
from mimblewimble.crypto.secret_key import SecretKey
from mimblewimble.crypto.public_key import PublicKey
from mimblewimble.crypto.signature import Signature

class AggSig:
    def __init__(self):
        self.ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)
        self.MAX_WIDTH = 1 << 20
        self.SCRATCH_SPACE_SIZE = 256 * self.MAX_WIDTH

    def __del__(self):
        secp256k1_context_destroy(self.ctx)

    def generateSecureNonce(self):
        seed = os.urandom(32)
        nonce = secp256k1_aggsig_export_secnonce_single(
            self.ctx, seed)
        return SecretKey(nonce)

    def buildSignature(
            self, secret_key: SecretKey,
            commitment: Commitment, message: bytes):
        seed = os.urandom(32)
        secp256k1_context_randomize(self.ctx, seed)
        parsed_commitment = secp256k1_pedersen_commitment_parse(
            self.ctx, commitment.getBytes())
        pubkey = secp256k1_pedersen_commitment_to_pubkey(
            self.ctx, parsed_commitment)
        signature_bytes = secp256k1_aggsig_sign_single(
            self.ctx, message, secret_key.getBytes(),
            None, None, None, None, pubkey, seed)
        return Signature(signature_bytes)

    def calculatePartialSignature(
            self, secretKey: SecretKey, secretNonce: SecretKey,
            sumPubKeys: PublicKey, sumPubNonces: PublicKey,
            sumPubNonces: bytes):
        seed = os.urandom(32)
        secp256k1_context_randomize(self.ctx, seed)
        pubKeyForE = secp256k1_ec_pubkey_parse(
            self.ctx, sumPubKeys.getBytes())
        pubNoncesForE = secp256k1_ec_pubkey_parse(
            self.ctx, sumPubNonces.getBytes())
        signature_bytes = secp256k1_aggsig_sign_single(
            self.ctx, message,
            secretKey.getBytes(), secretNonce.getBytes(),
            None, pubNoncesForE, pubNoncesForE, pubNoncesForE, seed)
        return Signature(signature_bytes)

    def verifyPartialSignature(
            self, partialSignature: Signature,
            publicKey: PublicKey, sumPubKeys: PublicKey,
            sumPubNonces: PublicKey, message: bytes):
        signature = secp256k1_ecdsa_signature_parse_compact(
            self.ctx, partialSignature.getBytes())
        pubkey = secp256k1_ec_pubkey_parse(
            self.ctx, publicKey.getBytes())
        sumPubKey = secp256k1_ec_pubkey_parse(
            self.ctx, sumPubKeys.getBytes())
        sumNoncesPubKey = secp256k1_ec_pubkey_parse(
            self.ctx, sumPubNonces.getBytes())
        is_valid = secp256k1_aggsig_verify_single(
            self.ctx, signature, message,
            sumNoncesPubKey, pubkey, sumPubKey, None, True)
        return is_valid

    def aggregateSignatures(self, signatures, sumPubNonces: PublicKey):
        pubNonces = secp256k1_ec_pubkey_parse(
            self.ctx, sumPubNonces.getBytes())
        parsed_signatures = self.parseCompactSignatures(signatures)
        aggregate = secp256k1_aggsig_add_signatures_single(
            self.ctx, parsed_signatures, pubNonces)
        return Signature(aggregate)

    def verifyAggregateSignatures(self, signatures, commitments, messages):
        parsedPubKeys = []
        for commitment in commitments:
            parsed_commitment = secp256k1_pedersen_commitment_parse(
                self.ctx, commitment.getBytes())
            pubkey = secp256k1_pedersen_commitment_to_pubkey(
                self.ctx, parsed_commitment)
            parsedPubKeys.append(pubkey)
        parsedSignatures = []
        for signature in signatures:
            parsed_signature = secp256k1_schnorrsig_parse(
                self.ctx, signature.getBytes())
            parsedSignatures.append(parsed_signature)
        scratch = secp256k1_scratch_space_create(
            self.ctx, self.SCRATCH_SPACE_SIZE)
        is_valid = secp256k1_schnorrsig_verify_batch(
            self.ctx, scratch, parsedSignatures, messages, parsedPubKeys)
        return is_valid

    def verifyAggregateSignature(
            self, signature: Signature, publicKey: PublicKey, message: bytes):
        parsedPubKey = secp256k1_ec_pubkey_parse(
            self.ctx, publicKey.getBytes())
        is_valid = secp256k1_aggsig_verify_single(
            self.ctx, signature.getBytes(), message,
            None, parsedPubKey, parsedPubKey, None, False)
        return is_valid

    def parseCompactSignatures(self, signatures):
        parsed_signatures = []
        for signature in signatures:
            if not signature.isCompact():
                parsed_signature = secp256k1_ecdsa_signature_parse_compact(
                    self.ctx, signature.getBytes())
                parsed_signatures.append(parsed_signature)
            else:
                parsed_signatures.append(signature.getBytes())
        return parsed_signatures

    def toCompact(self, signature: Signature):
        assert signature.isCompact()
        compact_signature = secp256k1_ecdsa_signature_serialize_compact(
            self.ctx, signature.getBytes())
        return Signature(compact_signature, compact=True)
