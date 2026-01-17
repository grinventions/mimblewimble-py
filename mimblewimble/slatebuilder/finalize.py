from mimblewimble.serializer import Serializer
from mimblewimble.keychain import KeyChain

from mimblewimble.crypto.aggsig import AggSig
from mimblewimble.crypto.secret_key import SecretKey

from mimblewimble.models.transaction import TransactionKernel

from mimblewimble.slatebuilder import ESlateStage
from mimblewimble.slatebuilder import Slate


class FinalizeSlateBuilder:
    def __init__(
            self,
            master_seed: bytes):
        self.master_seed = master_seed

    def finalize(
            self,
            receive_slate: Slate,
            testnet=False):
        # renaming the slate object
        finalized_slate = receive_slate
        finalized_slate.setStage(ESlateStage.STANDARD_FINALIZED)

        # generate the sender's partial signature
        kernel_message = TransactionKernel.getSignatureMessage(
            finalized_slate.getKernelFeatures(),
            finalized_slate.getFee(),
            finalized_slate.getLockHeight())
        signature = finalized_slate.getSignature(0)
        agg = AggSig()
        partial_signature = agg.calculatePartialSignature(
            signature.getExcess(),
            signature.getNonce(),
            finalized_slate.calculateTotalExcess(),
            finalized_slate.calculateTotalNonce(),
            kernel_message)
        del agg
        signature.setSignature(partial_signature)
        finalized_slate.setSignature(0, signature)

        # done!
        return finalized_slate

    def verifyPaymentProof(
            self,
            finalized_slate: Slate,
            sender_address: bytes):
        # reproduce the payment proof message
        # (amount | kernel commitment | sender address)
        amount = finalized_slate.getAmount()
        kernel_commitment = finalized_slate.getKernelCommitment().getBytes()

        serializer = Serializer()
        serializer.write(amount.to_bytes(8, 'big'))
        serializer.write(kernel_commitment)
        serializer.write(sender_address)
        message = serializer.readall()

        # verify payment proof addresses & signatures
        payment_proof = finalized_slate.getPaymentProof()

        receiver_address = payment_proof.getReceiverAddress()
        receiver_signature = payment_proof.getReceiverSignature()

        try:
            KeyChain.verifyED25519(
                receiver_address, receiver_signature, message)
        except Exception as e:
            print(e)
            raise ValueError('Invalid payment proof')

