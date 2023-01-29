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
        x = bytes.fromhex(
            'b860f56795fc03f3c21685383d1b5a2f2954f49b7e398b8d2a0193933621155f')
        y = bytes.fromhex(
            'a43f09d32caa8f53423f427403a56a3165a5a69a74cf56fc5901a2dca6c5c43a')
        generator_j_pub_bytes = bytes([0x04]) + x + y
        self.generator_j_pub = secp256k1_ec_pubkey_parse(
            self.ctx, generator_j_pub_bytes)

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
