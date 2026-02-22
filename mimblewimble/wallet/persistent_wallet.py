import hmac
import os

from typing import Optional, Union

from mimblewimble.crypto.rangeproof import RangeProof
from mimblewimble.models.slatepack.metadata import SlatepackVersion, SlatepackMetadata
from mimblewimble.keychain import KeyChain

from mimblewimble.crypto.commitment import Commitment
from mimblewimble.crypto.bulletproof import EBulletproofType

from mimblewimble.models.transaction import EOutputStatus
from mimblewimble.models.transaction import EOutputFeatures
from mimblewimble.models.transaction import EKernelFeatures
from mimblewimble.models.transaction import BlindingFactor
from mimblewimble.models.transaction import TransactionInput
from mimblewimble.models.transaction import TransactionOutput
from mimblewimble.models.transaction import TransactionBody
from mimblewimble.models.transaction import Transaction
from mimblewimble.models.transaction import TransactionKernel
from mimblewimble.models.fee import Fee

from mimblewimble.models.slatepack.address import SlatepackAddress
from mimblewimble.models.slatepack.message import SlatepackMessage, EMode

from mimblewimble.entity import OutputDataEntity
from mimblewimble.helpers.fee import calculateFee

from mimblewimble.slatebuilder import Slate, ESlateStage
from mimblewimble.slatebuilder import SendSlateBuilder
from mimblewimble.slatebuilder import ReceiveSlateBuilder
from mimblewimble.slatebuilder import FinalizeSlateBuilder
from mimblewimble.slatebuilder.invoice import InvoiceSlateBuilder
from mimblewimble.slatebuilder.pay import PaySlateBuilder

from mimblewimble.wallet.wallet import Wallet
from mimblewimble.wallet.storage import WalletStorage
from mimblewimble.wallet.comms import NodeAccess
from mimblewimble.wallet.balance import WalletBalance


class PersistentWallet:
    def __init__(
        self,
        wallet: Wallet,
        storage: WalletStorage,
        node: Optional[NodeAccess] = None,
        birthday_height=0,
    ):
        self._wallet = wallet
        self._storage = storage

        self.birthday_height = birthday_height
        self.tip_height = birthday_height

        if node is not None:
            self._node = node
        else:
            # TODO initialize the default local API node
            pass

    def get_tip_height(self):
        return self.tip_height

    def is_synced(self):
        return self.tip_height == self._node.get_current_block_height()

    def scan(self, window_size=100, sync_callback=None, path="m/0/1/0"):
        node_tip_height = self._node.get_current_block_height()
        if self.tip_height == node_tip_height:
            return

        # get the PMMR indices
        pmmr_indices_response = self._node.get_pmmr_indices(
            self.tip_height, node_tip_height
        )
        start_index = pmmr_indices_response["last_retrieved_index"]
        end_index = pmmr_indices_response["highest_index"]

        if sync_callback is not None:
            sync_callback.msg(
                "pmmr_indices", {"start_index": start_index, "end_index": end_index}
            )

        # scan the PMMR indices for outputs and kernels
        keychain = KeyChain.fromSeed(self._wallet.master_seed)
        while True:
            outputs_response = self._node.get_unspent_outputs(
                start_index, end_index, window_size, range_proof=True
            )
            unspent_outputs = outputs_response["outputs"]

            for unspent_output in unspent_outputs:
                commitment_bytes = bytes.fromhex(unspent_output["commit"])
                commitment = Commitment(commitment_bytes[1:])  # remove the "09" prefix

                proof_bytes = bytes.fromhex(unspent_output["proof"])
                range_proof = RangeProof.frombytes(proof_bytes)

                try:
                    # TODO should path be taken into account?
                    rewind_proof = keychain.rewindRangeProof(
                        commitment, range_proof, EBulletproofType.ENHANCED
                    )
                except Exception as e:
                    # this is not our output, skip
                    continue

                if sync_callback is not None:
                    sync_callback.msg(
                        "new_output", {"commitment": commitment_bytes.hex()}
                    )

                # this output belongs to this wallet
                # we should add it to the storage
                transaction_output = TransactionOutput(
                    EOutputFeatures.DEFAULT, commitment, range_proof
                )

                # build the output data entity
                output_data_entity = OutputDataEntity(
                    path,
                    rewind_proof.blinding_factor,
                    transaction_output,
                    rewind_proof.amount,
                    EOutputStatus.SPENDABLE,
                )

                # save this output as spendable in the local storage
                if not self._storage.is_output_known(commitment.getBytes()):
                    self._storage.add_output(output_data_entity)
                else:
                    self._storage.update_output(output_data_entity)

            if (
                outputs_response["highest_index"]
                <= outputs_response["last_retrieved_index"]
            ):
                break
            start_index = outputs_response["last_retrieved_index"] + 1

        self.tip_height = node_tip_height

    def refresh(self):
        # get all outputs awaiting confirmation
        # outputs = self._storage.get_outputs_by_status(EOutputStatus.NO_CONFIRMATIONS)
        outputs = self._storage.get_all_outputs()  # TODO make it more efficient
        if len(outputs) == 0:
            return

        # query node for their status
        commitments = []
        for output in outputs:
            if isinstance(output, OutputDataEntity):
                commit = output.output.getCommitment().getBytes()
            if isinstance(output, TransactionOutput):
                commit = output.getCommitment().getBytes()
            commitments.append(commit)
        result = self._node.get_outputs(commitments)

        # update outputs in storage
        for commitment_bytes, output_info in result.items():
            for output in outputs:
                if output.output.getCommitment().getBytes() == commitment_bytes:
                    # update output status based on node info
                    if output_info["spent"]:
                        output.status = EOutputStatus.SPENT
                    else:
                        output.status = EOutputStatus.SPENDABLE
                    output.block_height = output_info["height"]
                    output.mmr_index = output_info["mmr_index"]
                    break

    def post_transaction(self, finalized_slate: SlatepackMessage):
        self._node.post_transaction(finalized_slate)

    def shieldWallet(self, passphrase: str, salt=None, nonce=None):
        self._wallet.shieldWallet(passphrase, salt=salt, nonce=nonce)

    def unshieldWallet(self, passphrase: str, salt=None, nonce=None):
        self._wallet.unshieldWallet(passphrase, salt=salt, nonce=nonce)

    def createCoinbase(self, amount, path="m/0/1/0"):
        kernel, output = self._wallet.createCoinbase(amount, path=path)

        offset = BlindingFactor(bytes([0x00 for j in range(32)]))

        inputs = [
            TransactionInput(EKernelFeatures.COINBASE_KERNEL, output.getCommitment())
        ]
        outputs = [output]
        kernels = [kernel]
        transaction_body = TransactionBody(inputs, outputs, kernels)

        coinbase_transaction = Transaction(offset, transaction_body)

        # TODO add to storage transactions + output
        self._storage.add_output(output, kernel=kernel)

        return coinbase_transaction

    def identify_own_outputs_from_slate(
        self, slate, path="m/0/1/0", new_status=EOutputStatus.NO_CONFIRMATIONS
    ):
        slate_context = self._storage.get_slate_context(slate.slate_id)
        kernel = slate_context["kernel"]

        keychain = KeyChain.fromSeed(self._wallet.master_seed)
        for commitment in slate.commitments:
            if commitment.range_proof:
                # now we know this commitment is an output
                range_proof = commitment.range_proof
                # we will check if this output belongs to this wallet
                # this way we will know if we should store it
                try:
                    # TODO should path be taken into account?
                    rewind_proof = keychain.rewindRangeProof(
                        commitment.commitment, range_proof, EBulletproofType.ENHANCED
                    )  # ORIGINAL
                except Exception as e:
                    # this is not our output, skip
                    continue

                # this output belongs to this wallet
                # we should add it to the storage
                transaction_output = TransactionOutput(
                    EOutputFeatures.DEFAULT, commitment.commitment, range_proof
                )

                # build the output data entity
                output_data_entity = OutputDataEntity(
                    path,
                    rewind_proof.blinding_factor,
                    transaction_output,
                    rewind_proof.amount,
                    new_status,
                )

                if not self._storage.is_output_known(commitment.commitment.getBytes()):
                    self._storage.add_output(output_data_entity, kernel=kernel)
                else:
                    self._storage.update_output(output_data_entity)

    def send(
        self,
        amount: int,
        receiver: SlatepackAddress,
        path="m/0/1/0",
        num_change_outputs=1,
        fee_base=0,
        block_height=None,
        encrypt=True,
    ):
        if block_height is None:
            block_height = self._node.get_current_block_height()

        spendable_outputs = self._storage.get_outputs_by_status(EOutputStatus.SPENDABLE)
        inputs = []
        total_amount = 0
        for output in spendable_outputs:
            if total_amount >= amount + fee_base:
                break
            inputs.append(output)
            total_amount += output.getAmount()
        if total_amount < amount + fee_base:
            raise Exception("Insufficient funds")

        send_slate, secret_key, secret_nonce, change_outputs = self._wallet.send(
            inputs,
            num_change_outputs,
            amount,
            fee_base,
            block_height,
            path=path,
            receiver_address=receiver,
        )

        self._storage.save_slate_context(
            send_slate.slate_id,
            send_slate,
            secret_key=secret_key,
            secret_nonce=secret_nonce,
        )

        # mark inputs as being locked/spent
        for input in inputs:
            input.status = EOutputStatus.LOCKED
            self._storage.update_output(input)

        # mark change outputs as NO_CONFIRMATIONS
        for output in change_outputs:
            output.status = EOutputStatus.NO_CONFIRMATIONS
            self._storage.add_output(output)

        # prepare s1 slatepack
        sender_address = self.getSlatepackAddress(path=path)
        version = SlatepackVersion(0, 0)
        metadata = SlatepackMetadata(sender=SlatepackAddress.fromBech32(sender_address))
        emode = EMode.PLAINTEXT
        send_slatepack_message = SlatepackMessage(
            version, metadata, emode, send_slate.serialize()
        )

        if encrypt:
            send_slatepack_message.encryptPayload(
                [SlatepackAddress.fromBech32(receiver)]
            )
            return send_slatepack_message

        return send_slatepack_message

    def receive(self, send_slate: SlatepackMessage, path="m/0/1/0", encrypt=True):
        if send_slate.is_encrypted():
            s1 = self._wallet.decryptSlatepack(send_slate, path=path)
        else:
            s1 = send_slate

        slate = s1.getSlate()
        receive_slate, secret_key, secret_nonce = self._wallet.receive(slate, path=path)

        self._storage.save_slate_context(
            receive_slate.slate_id,
            receive_slate,
            secret_key=secret_key,
            secret_nonce=secret_nonce,
        )
        self.identify_own_outputs_from_slate(receive_slate, path=path)

        # prepare s2 slatepack
        receive_slate_payload = receive_slate.serialize()
        sender_address = self.getSlatepackAddress(path=path)
        version = SlatepackVersion(0, 0)
        metadata = SlatepackMetadata(sender=SlatepackAddress.fromBech32(sender_address))
        emode = EMode.PLAINTEXT
        receive_slatepack_message = SlatepackMessage(
            version, metadata, emode, receive_slate_payload
        )

        if encrypt:
            if not send_slate.metadata.sender:
                raise Exception(
                    "Cannot encrypt receive slatepack: original sender address missing"
                )
            original_sender_address = (
                send_slate.metadata.sender
            )  # original sender address
            receive_slatepack_message.encryptPayload([original_sender_address])

        return receive_slatepack_message

    def invoice(
        self,
        amount: int,
        receiver: SlatepackAddress,
        block_height=None,
        path="m/0/1/0",
        encrypt=True,
    ):
        if block_height is None:
            block_height = self._node.get_current_block_height()

        invoice_slate, secret_key, secret_nonce = self._wallet.invoice(
            amount, path=path, block_height=block_height
        )

        self._storage.save_slate_context(
            invoice_slate.slate_id,
            invoice_slate,
            secret_key=secret_key,
            secret_nonce=secret_nonce,
        )
        self.identify_own_outputs_from_slate(invoice_slate, path=path)

        # prepare r1 slatepack
        sender_address = self.getSlatepackAddress(path=path)
        version = SlatepackVersion(0, 0)
        metadata = SlatepackMetadata(sender=SlatepackAddress.fromBech32(sender_address))
        emode = EMode.PLAINTEXT
        invoice_slatepack_message = SlatepackMessage(
            version, metadata, emode, invoice_slate.serialize()
        )

        if encrypt:
            invoice_slatepack_message.encryptPayload(
                [SlatepackAddress.fromBech32(receiver)]
            )
            return invoice_slatepack_message

        return invoice_slatepack_message

    def pay(
        self,
        invoice_slate: SlatepackMessage,
        path="m/0/1/0",
        num_change_outputs=1,
        fee_base=0,
        encrypt=True,
    ):
        if invoice_slate.is_encrypted():
            r1 = self._wallet.decryptSlatepack(invoice_slate, path=path)
        else:
            r1 = invoice_slate

        slate = r1.getSlate()
        requested_amount = slate.getAmount()

        spendable_outputs = self._storage.get_outputs_by_status(EOutputStatus.SPENDABLE)
        inputs = []
        total_amount = 0
        for output in spendable_outputs:
            if total_amount >= requested_amount + fee_base:
                break
            inputs.append(output)
            total_amount += output.getAmount()
        if total_amount < requested_amount + fee_base:
            raise Exception("Insufficient funds")

        pay_slate, secret_key, secret_nonce, change_outputs = self._wallet.pay(
            slate, inputs, num_change_outputs, fee_base, path=path
        )

        self._storage.save_slate_context(
            pay_slate.slate_id,
            pay_slate,
            secret_key=secret_key,
            secret_nonce=secret_nonce,
        )

        # mark inputs as being locked/spent
        for input in inputs:
            input.status = EOutputStatus.LOCKED
            self._storage.update_output(input)

        # mark change outputs as NO_CONFIRMATIONS
        for output in change_outputs:
            output.status = EOutputStatus.NO_CONFIRMATIONS
            self._storage.add_output(output)
        # self.identify_own_outputs_from_slate(pay_slate, path=path)

        # prepare r2 slatepack
        receive_slate_payload = pay_slate.serialize()
        sender_address = self.getSlatepackAddress(path=path)
        version = SlatepackVersion(0, 0)
        metadata = SlatepackMetadata(sender=SlatepackAddress.fromBech32(sender_address))
        emode = EMode.PLAINTEXT
        pay_slatepack_message = SlatepackMessage(
            version, metadata, emode, receive_slate_payload
        )

        if encrypt:
            if not invoice_slate.metadata.sender:
                raise Exception(
                    "Cannot encrypt receive slatepack: original sender address missing"
                )
            original_sender_address = (
                invoice_slate.metadata.sender
            )  # original sender address
            pay_slatepack_message.encryptPayload([original_sender_address])

        return pay_slatepack_message

    def finalize(self, final_slate: SlatepackMessage, path="m/0/1/0", testnet=False):
        if final_slate.is_encrypted():
            s2 = self._wallet.decryptSlatepack(final_slate, path=path)
        else:
            s2 = final_slate

        slate = s2.getSlate()
        slate_context = self._storage.get_slate_context(slate.slate_id)
        secret_key = slate_context["secret_key"]
        secret_nonce = slate_context["secret_nonce"]
        kernel = slate_context["kernel"]
        finalized_slate = self._wallet.finalize(slate, path=path, testnet=testnet)

        self._storage.save_slate_context(
            finalized_slate.slate_id,
            finalized_slate,
            kernel=kernel,
            secret_key=secret_key,
            secret_nonce=secret_nonce,
        )
        self.identify_own_outputs_from_slate(finalized_slate, path=path)

        return finalized_slate

    def push_finalized_slatepack(self, finalized_slate: Slate):
        inputs = []
        outputs = []
        kernels = []
        for commitment in finalized_slate.commitments:
            if commitment.range_proof:
                # this is output
                output = TransactionOutput(
                    EOutputFeatures.DEFAULT,
                    commitment.commitment,
                    commitment.range_proof,
                )
                outputs.append(output)
            else:
                input = TransactionInput(EOutputFeatures.DEFAULT, commitment.commitment)
                inputs.append(input)

        kernel = TransactionKernel(
            EKernelFeatures.DEFAULT_KERNEL,
            Fee(0, finalized_slate.fee),
            finalized_slate.lock_height,
            finalized_slate.getKernelCommitment(),
            finalized_slate.getSignature(0),  # 0 ? TODO
        )
        kernels.append(kernel)

        transaction_body = TransactionBody(inputs, outputs, kernels)

        transaction = Transaction(finalized_slate.offset, transaction_body)

        self._node.push_transaction(transaction)

    def balance(self):
        locked = 0
        awaiting_confirmation = 0
        spendable = 0

        outputs = self._storage.get_all_outputs()
        for output in outputs:
            if output.status == EOutputStatus.NO_CONFIRMATIONS:
                awaiting_confirmation += output.getAmount()
            elif output.status == EOutputStatus.LOCKED:
                locked += output.getAmount()
            elif output.status == EOutputStatus.SPENDABLE:
                spendable += output.getAmount()

        return WalletBalance(locked, awaiting_confirmation, spendable)

    def decryptSlatepack(
        self, armored_slatepack_: Union[str, SlatepackMessage], path="m/0/1/0"
    ):
        return self._wallet.decryptSlatepack(armored_slatepack_, path=path)

    def ageDecrypt(self, ciphertext: bytes, path="m/0/1/0"):
        return self._wallet.ageDecrypt(ciphertext, path=path)

    def ageEncrypt(self, plaintext: bytes, receiver_address: str):
        keychain = KeyChain.fromSeed(self._wallet.master_seed)
        age_public_key = keychain.deriveAgePublicKeyFromSlatepackAddress(
            receiver_address
        )
        return keychain.ageEncrypt(plaintext, age_public_key)

    def getSlatepackAddress(self, path="m/0/1/0", testnet=False):
        return self._wallet.getSlatepackAddress(path=path, testnet=testnet)

    def getSeedPhrase(self):
        return self._wallet.getSeedPhrase()

    @classmethod
    def restoreFromSeedPhrase(
        self, phrase: str, storage: WalletStorage, node=None, birthday_height=0
    ):
        return PersistentWallet(
            Wallet.fromSeedPhrase(phrase),
            storage,
            node=node,
            birthday_height=birthday_height,
        )
