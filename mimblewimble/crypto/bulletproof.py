import os

from typing import List, Tuple
from enum import Enum

from secp256k1_zkp_mw import SECP256K1_CONTEXT_SIGN
from secp256k1_zkp_mw import SECP256K1_CONTEXT_VERIFY

from secp256k1_zkp_mw import secp256k1_generator_const_h
from secp256k1_zkp_mw import secp256k1_generator_const_g

from secp256k1_zkp_mw import secp256k1_context_create
from secp256k1_zkp_mw import secp256k1_context_destroy
from secp256k1_zkp_mw import secp256k1_context_randomize

from secp256k1_zkp_mw import secp256k1_scratch_space_create
from secp256k1_zkp_mw import secp256k1_scratch_space_destroy

from secp256k1_zkp_mw import secp256k1_bulletproof_generators_create
from secp256k1_zkp_mw import secp256k1_bulletproof_rangeproof_verify_multi
from secp256k1_zkp_mw import secp256k1_bulletproof_rangeproof_prove
from secp256k1_zkp_mw import secp256k1_bulletproof_rangeproof_rewind

from mimblewimble.crypto.commitment import Commitment
from mimblewimble.crypto.secret_key import SecretKey
from mimblewimble.crypto.rangeproof import RangeProof
from mimblewimble.crypto.pedersen import Pedersen

from mimblewimble.models.transaction import BlindingFactor


class EBulletproofType(Enum):
    ORIGINAL = 0
    ENHANCED = 1


class ProofMessage:
    def __init__(self, proof_message: bytes):
        self.proof_message = proof_message

    def getBytes(self):
        return self.proof_message

    @classmethod
    def fromKeyIndices(
        self, key_indices: List[int], bulletproof_type: EBulletproofType
    ):
        padded_path = [0x00 for i in range(20)]
        if bulletproof_type == EBulletproofType.ENHANCED:
            # padded_path[0] 0x00 reserved
            # padded_path[1] 0x00 is wallet type
            padded_path[2] = 0x01  # switch commits
            padded_path[3] = len(key_indices)

        i = 4
        for j, key_index in enumerate(key_indices):
            padded_path[j + 4] = key_index

        return ProofMessage(bytes(padded_path))

    def toKeyIndices(self, bulletproof_type: EBulletproofType):
        proof_message = list(self.proof_message)
        length = 3
        if bulletproof_type == EBulletproofType.ENHANCED:
            if proof_message[0] != 0x0:
                raise ValueError("Reserved, first value of proof message must be zero")
            wallet_type = proof_message[1]
            switch_commits = proof_message[2]
            length = proof_message[3]
        else:
            try:
                for j in range(4):
                    assert proof_message[j] == 0x0
            except:
                raise ValueError("Expected first 4 bytes of proof message to be 0x00")
        i = 4
        if length == 0:
            length = 3

        key_indices = [0x00 for j in range(length)]
        for j in range(length):
            key_indices[j] = proof_message[i + j]
        return key_indices


class RewoundProof:
    def __init__(self, amount, blinding_factor: SecretKey, message: ProofMessage):
        self.amount = amount
        self.blinding_factor = blinding_factor
        self.message = message

    def getAmount(self):
        return self.amount

    def getBlindingFactor(self):
        return self.blinding_factor

    def getProofMessage(self):
        return self.message

    def toKeyIndices(self, bulletproof_type: EBulletproofType):
        return self.message.toKeyIndices(bulletproof_type)


class Bulletproof:
    def __init__(self):
        self.cache = []
        self.ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY
        )

        self.MAX_WIDTH = 1 << 20
        self.SCRATCH_SPACE_SIZE = 256 * self.MAX_WIDTH
        self.MAX_GENERATORS = 256

        self.generators = secp256k1_bulletproof_generators_create(
            self.ctx, secp256k1_generator_const_g, self.MAX_GENERATORS
        )

    def flushCache(self):
        self.cache = []

    def __del__(self):
        secp256k1_context_destroy(self.ctx)

    def verifyBulletproofs(self, range_proofs: List[Tuple[Commitment, RangeProof]]):
        num_bits = 64

        _, first_rangeproof = range_proofs[0]
        proof_length = len(first_rangeproof.getProofBytes())

        commitments = []
        bulletproofs = []
        for commitment, rangeproof in range_proofs:
            if commitment.getBytes() in self.cache:
                continue
            commitments.append(commitment)
            bulletproofs.append(rangeproof.getProofBytes())

        if len(commitments) == 0:
            return True

        # array of generator multiplied by value in pedersen commitments
        # (cannot be NULL)
        value_generators = secp256k1_bulletproof_generators_create(
            self.ctx, secp256k1_generator_const_h, len(commitments)
        )

        parsed_commitments = Pedersen.convertCommitments(self.ctx, commitments)
        scratch = secp256k1_scratch_space_create(self.ctx, self.SCRATCH_SPACE_SIZE)
        is_valid = secp256k1_bulletproof_rangeproof_verify_multi(
            self.ctx,
            scratch,
            value_generators,
            bulletproofs,
            None,
            parsed_commitments,
            len(commitments),
            proof_length,
            [secp256k1_generator_const_h, secp256k1_generator_const_h],
            None,
        )
        secp256k1_scratch_space_destroy(scratch)

        if not is_valid:
            return False

        for commitment in commitments:
            commitment_bytes = commitment.getBytes()
            if commitment_bytes not in self.cache:
                self.cache.append(commitment_bytes)

        return True

    def generateRangeProof(
        self,
        amount: int,
        key: SecretKey,
        private_nonce: SecretKey,
        rewind_nonce: SecretKey,
        proof_message: ProofMessage,
    ):
        seed = os.urandom(32)
        secp256k1_context_randomize(self.ctx, seed)

        scratch = secp256k1_scratch_space_create(self.ctx, self.SCRATCH_SPACE_SIZE)
        proof_bytes = secp256k1_bulletproof_rangeproof_prove(
            self.ctx,
            scratch,
            self.generators,
            None,
            None,
            None,
            [amount],
            None,
            [key.getBytes()],
            None,
            secp256k1_generator_const_h,
            64,
            rewind_nonce.getBytes(),
            private_nonce.getBytes(),
            None,
            proof_message.getBytes(),
        )
        secp256k1_scratch_space_destroy(scratch)
        return RangeProof(proof_bytes)

    def rewindProof(
        self, commitment: Commitment, rangeproof: RangeProof, nonce: SecretKey
    ):
        parsed_commitments = Pedersen.convertCommitments(self.ctx, [commitment])
        commit = parsed_commitments[0]

        rewinding_result = secp256k1_bulletproof_rangeproof_rewind(
            self.ctx,
            rangeproof.getProofBytes(),
            0,
            commit,
            secp256k1_generator_const_h,
            nonce.getBytes(),
            None,
        )
        if rewinding_result is None:
            raise ValueError("Bulletproof invalid")
        value, blind, message_bytes = rewinding_result
        blinding_factor = BlindingFactor(blind)
        message = ProofMessage(message_bytes)

        return RewoundProof(value, blinding_factor, message)
