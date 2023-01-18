from ecdsa import SigningKey, SECP256k1

from secp256k1_zkp_mw import SECP256K1_CONTEXT_SIGN
from secp256k1_zkp_mw import SECP256K1_CONTEXT_VERIFY

from secp256k1_zkp_mw import secp256k1_generator_const_h
from secp256k1_zkp_mw import secp256k1_generator_const_g

from secp256k1_zkp_mw import secp256k1_context_create
from secp256k1_zkp_mw import secp256k1_context_destroy
from secp256k1_zkp_mw import secp256k1_pedersen_commit
from secp256k1_zkp_mw import secp256k1_pedersen_commitment_serialize
from secp256k1_zkp_mw import secp256k1_pedersen_commitment_parse
from secp256k1_zkp_mw import secp256k1_pedersen_commit_sum
from secp256k1_zkp_mw import secp256k1_pedersen_blind_sum
from secp256k1_zkp_mw import secp256k1_blind_switch
from secp256k1_zkp_mw import secp256k1_ec_pubkey_parse
from secp256k1_zkp_mw import secp256k1_pubkey_to_pedersen_commitment

from mimblewimble.models.transaction import BlindingFactor

from mimblewimble.crypto.commitment import Commitment
from mimblewimble.crypto.secret_key import SecretKey
from mimblewimble.crypto.public_key import PublicKey


class Pedersen:
    def __init__(self):
        self.ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)

        # see
        # https://github.com/mimblewimble/rust-secp256k1-zkp/blob/304ef7264a0dd9ef4efaaa0e28480cb030c18265/src/constants.rs#L138-L188
        # https://github.com/GrinPlusPlus/GrinPlusPlus/blob/b7b06a1ab6c0e7f7263878f788ea7e4203dcab7c/src/Crypto/SwitchGeneratorPoint.h#L5-L15
        self.generator_j_pub = secp256k1_ec_pubkey_parse(self.ctx, bytes([
            0x5f, 0x15, 0x21, 0x36, 0x93, 0x93, 0x01, 0x2a,
            0x8d, 0x8b, 0x39, 0x7e, 0x9b, 0xf4, 0x54, 0x29,
            0x2f, 0x5a, 0x1b, 0x3d, 0x38, 0x85, 0x16, 0xc2,
            0xf3, 0x03, 0xfc, 0x95, 0x67, 0xf5, 0x60, 0xb8,
            0x3a, 0xc4, 0xc5, 0xa6, 0xdc, 0xa2, 0x01, 0x59,
            0xfc, 0x56, 0xcf, 0x74, 0x9a, 0xa6, 0xa5, 0x65,
            0x31, 0x6a, 0xa5, 0x03, 0x74, 0x42, 0x3f, 0x42,
            0x53, 0x8f, 0xaa, 0x2c, 0xd3, 0x09, 0x3f, 0xa4
        ]))

    def __del__(self):
        secp256k1_context_destroy(self.ctx)

    def commit(self, value: int, blindingFactor: BlindingFactor):
        commitment = secp256k1_pedersen_commit(
            self.ctx,
            blindingFactor.getBytes(),
            value,
            secp256k1_generator_const_h,
            secp256k1_generator_const_g)
        serialized = secp256k1_pedersen_commitment_serialize(
            self.ctx, commitment)
        return Commitment(serialized)

    def commitSum(self, positive: Commitment, negative: Commitment):
        positive_commitments = Pedersen.convertCommitments(self.ctx, positive)
        negative_commitments = Pedersen.convertCommitments(self.ctx, negative)
        commitment = secp256k1_pedersen_commit_sum(
            self.ctx, positive_commitments, negative_commitments)
        serialized = secp256k1_pedersen_commitment_serialize(
            self.ctx, commitment)
        return Commitment(serialized)

    def blindSum(self, positive: Commitment, negative: Commitment):
        positives = [p.getBytes() for p in positive]
        negatives = [p.getBytes() for p in negative]
        blinding_factors = positives + negatives
        summed = secp256k1_pedersen_blind_sum(
            self.ctx, blinding_factors, len(positive))
        return BlindingFactor(summed)

    def blindSwitch(self, blinding_factor: SecretKey, amount: int):
        blind_switch = secp256k1_blind_switch(
            self.ctx,
            blinding_factor.getBytes(),
            amount,
            secp256k1_generator_const_h,
            secp256k1_generator_const_g,
            self.generator_j_pub)
        return SecretKey(blind_switch)

    def toCommitment(self, public: PublicKey):
        pk = secp256k1_ec_pubkey_parse(
            self.ctx, public.getBytes())
        commitment = secp256k1_pubkey_to_pedersen_commitment(
            self.ctx, pk)
        serialized = secp256k1_pedersen_commitment_serialize(
            self.ctx, commitment)
        return Commitment(serialized)

    @classmethod
    def convertCommitments(self, ctx, commitments):
        converted = []
        for commitment in commitments:
            parsed = secp256k1_pedersen_commitment_parse(
                ctx, commitment.getBytes())
            converted.append(parsed)
        return converted
