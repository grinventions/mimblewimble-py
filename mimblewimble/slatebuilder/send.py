import os

from typing import List, Tuple

from mimblewimble.entity import OutputDataEntity

from mimblewimble.consensus import Consensus

from mimblewimble.crypto.aggsig import AggSig
from mimblewimble.crypto.pedersen import Pedersen
from mimblewimble.crypto.public_keys import PublicKeys

from mimblewimble.models.transaction import BlindingFactor
from mimblewimble.models.transaction import EKernelFeatures

from mimblewimble.slatebuilder import Slate, SlatePaymentProof


class SendSlateBuilder:
    def __init__(
            self,
            master_seed: bytes):
        self.master_seed = master_seed


    def calculateSigningKeys(
            self,
            inputs: List[OutputDataEntity],
            outputs: List[OutputDataEntity],
            tx_offset: BlindingFactor):
        # cryptography utilities
        p = Pedersen()
        pks = PublicKeys()
        agg = AggSig()

        # calculate sum inputs blinding factors xI.
        input_bf_sum = p.blindSum([inp.getBlindingFactor() for inp in inputs], [])

        # calculate sum change outputs blinding factors xC.
        output_bf_sum = p.blindSum([out.getBlindingFactor() for out in outputs], [])

        # calculate total blinding excess sum for all inputs and outputs xS1 = xC - xI
        total_blind_excess = p.blindSum([output_bf_sum], [input_bf_sum])

        # subtract random kernel offset oS from xS1. Calculate xS = xS1 - oS
        secret_key = p.blindSum([total_blind_excess], [tx_offset]).toSecretKey()
        public_key = pks.calculatePublicKey(secret_key)

        # select a random nonce kS
        secret_nonce = agg.generateSecureNonce()
        public_nonce = pks.calculatePublicKey(secret_nonce)

        # clean-up
        del p
        del pks
        del agg

        # done!
        return secret_key, public_key, secret_nonce, public_nonce


    def build(
            self,
            amount: int,
            fee: int,
            block_height: int,
            inputs: List[OutputDataEntity],
            change_outputs: List[OutputDataEntity],
            slate_version=0, testnet=False,
            sender_address=None, receiver_address=None):
        # select random transaction offset,
        # and calculate secret key used in kernel signature
        transaction_offset = BlindingFactor.random()
        signing_keys = self.calculateSigningKeys(
            inputs, change_outputs, transaction_offset)
        secret_key, public_key, secret_nonce, public_nonce = signing_keys

        # payment proof
        payment_proof = None
        if None not in [sender_address, receiver_address]:
            payment_proof = SlatePaymentProof(sender_address, receiver_address)

        # add values to Slate for passing to other participants:
        # UUID, inputs, change_outputs, fee, amount, lock_height, kSG, xSG, oS
        block_version = Consensus.getHeaderVersion(block_height)
        slate = Slate(
            slate_version,
            block_version,
            amount,
            fee,
            payment_proof,
            EKernelFeatures.DEFAULT_KERNEL,
            transaction_offset, signatures=[(public_key, public_nonce)])
        return slate


    def buildWalletTx(
            self,
            tx_offset: BlindingFactor,
            inputs: List[OutputDataEntity],
            change_outputs: List[OutputDataEntity],
            slate: Slate,
            receiver_address=None,
            payment_proof=None):
        if receiver_address is not None and isinstance(payment_proof, bytes):
            raise TypeError(
                'Expected bytes type argument or None for the receipient address')
        if payment_proof is not None and isinstance(payment_proof, SlatePaymentProof):
            raise TypeError('Expected SlatePaymentProof type argument or None')

        # TODO
        pass
