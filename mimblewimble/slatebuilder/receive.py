from mimblewimble.entity import OutputDataEntity

from mimblewimble.crypto.aggsig import AggSig

from mimblewimble.models.transaction import BlindingFactor
from mimblewimble.models.transaction import TransactionKernel

from mimblewimble.helpers.slate import calculateSigningKeys

from mimblewimble.slatebuilder import ESlateStage
from mimblewimble.slatebuilder import Slate
from mimblewimble.slatebuilder import SlateSignature
from mimblewimble.slatebuilder import SlatePaymentProof


class ReceiveSlateBuilder:
    def __init__(
            self, master_seed):
        self.master_seed = master_seed

    def addReceiverData(
            self,
            send_slate: Slate,
            output: OutputDataEntity,
            testnet=False) -> Slate:
        # renaming the slate object
        receive_slate = send_slate
        receive_slate.setStage(ESlateStage.STANDARD_RECEIVED)

        # create the receiver offset
        receiver_offset = BlindingFactor.random()
        signing_keys = calculateSigningKeys(
            [], [output], receiver_offset)
        secret_key, public_key, secret_nonce, public_nonce = signing_keys

        # adjust the receiver offset
        receive_slate.addOffset(receiver_offset)

        # generate the receiver's partial signature
        kernel_message = TransactionKernel.getSignatureMessage(
            receive_slate.getKernelFeatures(),
            receive_slate.getFee(),
            receive_slate.getLockHeight())
        signature = SlateSignature(public_key, public_nonce)
        agg = AggSig()
        partial_signature = agg.calculatePartialSignature(
            secret_key,
            secret_nonce,
            receive_slate.calculateTotalExcess(),
            receive_slate.calculateTotalNonce(),
            kernel_message)
        del agg
        signature.setSignature(partial_signature)

        # add the receiver participant data
        receive_slate.appendSignature(signature)

        # add the receiver's tx output
        receive_slate.appendOutput(
            output.getFeatures(),
            output.getCommitment(),
            output.getRangeProof())

        # done!
        return receive_slate, secret_key, secret_nonce



