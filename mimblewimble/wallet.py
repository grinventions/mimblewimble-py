import hmac
import os

from typing import Tuple, List, Optional, Dict, Union
from uuid import UUID

from nacl import bindings

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

from hashlib import blake2b, pbkdf2_hmac, sha512

from bip32 import BIP32
from bip_utils import Bech32Encoder

from mimblewimble.models.slatepack.metadata import SlatepackVersion, SlatepackMetadata
from mimblewimble.serializer import Serializer
from mimblewimble.mnemonic import Mnemonic
from mimblewimble.keychain import KeyChain

from mimblewimble.crypto.aggsig import AggSig
from mimblewimble.crypto.commitment import Commitment
from mimblewimble.crypto.bulletproof import EBulletproofType
from mimblewimble.crypto.pedersen import Pedersen
from mimblewimble.crypto.secret_key import SecretKey

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

from mimblewimble.slatebuilder import Slate
from mimblewimble.slatebuilder import SendSlateBuilder
from mimblewimble.slatebuilder import ReceiveSlateBuilder
from mimblewimble.slatebuilder import FinalizeSlateBuilder

class Wallet:
    def __init__(self, encrypted_seed=None, salt=None, nonce=None, master_seed=None, tag=None):
        self.encrypted_seed = encrypted_seed
        self.salt = salt
        self.nonce = nonce
        self.master_seed = master_seed # 32 bytes


    def shieldWallet(self, passphrase: str, salt=None, nonce=None):
        if self.master_seed is None:
            raise Exception('The wallet is already shielded')
        if self.salt is None:
            if salt is None:
                self.salt = os.urandom(8)
            else:
                self.salt = salt
        if self.nonce is None:
            if nonce is None:
                self.nonce = os.urandom(12)
            else:
                self.nonce = nonce
        # compute encrypted_seed from master_seed
        key = pbkdf2_hmac('sha512', bytes(passphrase, 'utf-8'), self.salt, 100)
        cipher = ChaCha20_Poly1305.new(key=key[0:32], nonce=self.nonce)
        ciphertext = cipher.encrypt(self.master_seed)
        tag = cipher.digest()
        self.encrypted_seed = ciphertext + tag
        self.master_seed = None


    def unshieldWallet(self, passphrase: str, salt=None, nonce=None):
        if self.salt is None and salt is None:
            raise Exception('Missing salt')
        elif self.salt is None and salt is not None:
            self.salt = salt
        if self.nonce is None and nonce is None:
            raise Exception('Missing nonce')
        elif self.nonce is None and nonce is not None:
            self.nonce = nonce
        # compute master_seed from encrypted_seed
        key = pbkdf2_hmac('sha512', bytes(passphrase, 'utf-8'), salt, 100)
        cipher = ChaCha20_Poly1305.new(key=key[0:32], nonce=nonce)
        ciphertext = self.encrypted_seed[:32]
        tag = self.encrypted_seed[32:]
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        self.master_seed = plaintext
        del plaintext


    def getSeedPhrase(self):
        if self.master_seed is None:
            raise Exception('The wallet is shielded')
        M = Mnemonic()
        return M.mnemonicFromEntropy(self.master_seed)


    def getEncryptedSeed(self):
        if None in [self.encrypted_seed, self.salt, self.nonce]:
            raise Exception('The wallet is not shielded')
        return {
            'encrypted_seed': self.encrypted_seed.hex(),
            'salt': self.salt.hex(),
            'nonce': self.nonce.hex()
        }


    def getSlatepackAddress(self, path='m/0/1/0', testnet=False):
        if self.master_seed is None:
            raise Exception('The wallet is shielded')

        keychain = KeyChain.fromSeed(self.master_seed)
        slatepack_address = keychain.deriveSlatepackAddress(path)

        return slatepack_address


    def createCoinbase(self, amount, path='m/0/1/0'):
        if self.master_seed is None:
            raise Exception('The wallet is shielded')

        # instantiate the keychain for this wallet seed
        keychain = KeyChain.fromSeed(self.master_seed)

        # we will be needing Pedersen commitments
        # and signature aggregation
        p = Pedersen()
        agg = AggSig()

        # blinding factor and Pedersend commitment
        blinding_factor = keychain.derivePrivateKeyAmount(
            path, amount)
        commitment = p.commit(amount, blinding_factor)

        # bulletproof
        rangeproof = keychain.generateRangeProof(
            path, amount, commitment,
            blinding_factor, EBulletproofType.ENHANCED)

        # add the commitments
        transparent_factor = BlindingFactor(bytes([0x00 for j in range(32)]))
        transparent_commitment = p.commit(amount, transparent_factor)
        kernel_commitment = p.commitSum([commitment], [transparent_commitment])

        # build the output
        transaction_output = TransactionOutput(
            EOutputFeatures.COINBASE_OUTPUT,
            commitment,
            rangeproof)

        # build the output data entity
        output_data_entity = OutputDataEntity(
            path, blinding_factor, transaction_output, amount,
            EOutputStatus.NO_CONFIRMATIONS)

        # build the coinbase signature
        message = blake2b(
            EKernelFeatures.COINBASE_KERNEL.to_bytes(1, 'big'),
            digest_size=32).digest()
        coinbase_signature = agg.buildSignature(
            blinding_factor, kernel_commitment, message)

        # build the kernel
        shift = 0
        fee = 0
        transaction_kernel = TransactionKernel(
            EKernelFeatures.COINBASE_KERNEL,
            Fee(shift, fee),
            0,
            kernel_commitment,
            coinbase_signature)

        # clean-up
        del p
        del agg

        # return the result
        return transaction_kernel, output_data_entity


    def createBlindedOutput(
            self,
            amount: int,
            bulletproof_type: EBulletproofType,
            path='m/0/1/0',
            wallet_tx_id=None):
        # Pedersen commitment class
        p = Pedersen()

        # instantiate the keychain for this wallet seed
        keychain = KeyChain.fromSeed(self.master_seed)

        blinding_factor = keychain.derivePrivateKeyAmount(
            path, amount)
        commitment = p.commit(amount, blinding_factor)

        # bulletproof
        rangeproof = keychain.generateRangeProof(
            path, amount, commitment,
            blinding_factor, bulletproof_type)

        # build the output
        transaction_output = TransactionOutput(
            EOutputFeatures.DEFAULT,
            commitment,
            rangeproof)

        # clean-up
        del p

        return OutputDataEntity(
            path, blinding_factor, transaction_output, amount,
            EOutputStatus.NO_CONFIRMATIONS, wallet_tx_id=wallet_tx_id)


    def send(
            self,
            inputs: List[OutputDataEntity],
            num_change_outputs: int,
            amount: int,
            fee_base: int,
            block_height: int,
            send_entire_balance=False,
            receiver_address=None,
            path='m/0/1/0',
            wallet_tx_id=None,
            testnet=False) -> Tuple[Slate, SecretKey, SecretKey]:
        # if entire balance is sent, no change outputs
        if send_entire_balance:
            change_outputs = 0

        # the total number of outputs and number of kernels
        num_total_outputs = 1 + num_change_outputs
        num_kernels = 1

        # calculate fee
        fee = calculateFee(fee_base, len(inputs), num_total_outputs, num_kernels)

        # compute the total input
        input_total = 0
        for input_entry in inputs:
            input_total += input_entry.getAmount()

        # adjust the send amount if entire balance is being sent
        if send_entire_balance:
            amount = input_total - fee

        # compute the change amount and prepare the change outputs
        # each with own blinding factor xC
        change_amount = input_total - (amount + fee)
        change_outputs = []
        for i in range(num_change_outputs):
            coin_amount = int(change_amount / num_change_outputs)
            if i == 0:
                coin_amount += change_amount % num_change_outputs
            change_outputs.append(self.createBlindedOutput(
                coin_amount, EBulletproofType.ENHANCED,
                path=path, wallet_tx_id=wallet_tx_id))

        # prepare sender and receiver address for the payment proof
        keychain = KeyChain.fromSeed(self.master_seed)
        sender_address_bytes = keychain.deriveED25519PublicKey(path)
        receiver_address_bytes = None
        if receiver_address is not None:
            receiver = SlatepackAddress.fromBech32(receiver_address)
            receiver_address_bytes = receiver.toED25519()

        # build send slate
        slate_builder = SendSlateBuilder(self.master_seed)
        slate, secret_key, secret_nonce = slate_builder.build(
            amount,
            fee,
            block_height,
            inputs,
            change_outputs,
            sender_address=sender_address_bytes,
            receiver_address=receiver_address_bytes,
            testnet=testnet)
        return slate, secret_key, secret_nonce


    def receive(
            self,
            send_slate: Slate,
            path='m/0/1/0',
            wallet_tx_id=None,
            testnet=False) -> Slate:
        output = self.createBlindedOutput(
            send_slate.getAmount(),
            EBulletproofType.ENHANCED,
            path=path,
            wallet_tx_id=wallet_tx_id)
        # build the receive slate
        slate_builder = ReceiveSlateBuilder(self.master_seed)
        receive_slate = slate_builder.addReceiverData(
            send_slate,
            output,
            testnet=testnet)

        # update the payment proof
        payment_proof = receive_slate.getPaymentProof()
        if payment_proof is not None:
            sender_address = payment_proof.getSenderAddress()
            # prepare the receiver address to be able to update
            # the payment proof
            keychain = KeyChain.fromSeed(self.master_seed)
            receiver_address = keychain.deriveED25519PublicKey(path)

            # prepare the kernel commitment
            kernel_commitment = receive_slate.getKernelCommitment().getBytes()

            # message to be signed:
            # (amount | kernel commitment | sender address)
            serializer = Serializer()
            serializer.write(receive_slate.getAmount().to_bytes(8, 'big'))
            serializer.write(kernel_commitment)
            serializer.write(sender_address)
            message = serializer.readall()

            # produce the signature
            receiver_signature = keychain.signED25519(message, path)

            # update the payment proof data
            receive_slate.proof_opt.setReceiverAddress(receiver_address)
            receive_slate.proof_opt.setReceiverSignature(receiver_signature)

        # done!
        return receive_slate


    def invoice(self):
        raise Exception('unimplemented')


    def pay(self):
        raise Exception('unimplemented')


    def finalize(
            self,
            receive_slate: Slate,
            secret_key: SecretKey,
            secret_nonce: SecretKey,
            path='m/0/1/0',
            wallet_tx_id=None,
            testnet=False):
        # prepare the original sender address for the payment proof validation
        keychain = KeyChain.fromSeed(self.master_seed)
        sender_address_bytes = keychain.deriveED25519PublicKey(path)

        # build the receive slate
        slate_builder = FinalizeSlateBuilder(self.master_seed)
        finalized_slate = slate_builder.finalize(
            receive_slate,
            secret_key,
            secret_nonce,
            sender_address_bytes,
            testnet=testnet)
        return finalized_slate

    def ageDecrypt(self, ciphertext: bytes, path='m/0/1/0'):
        keychain = KeyChain.fromSeed(self.master_seed)
        return keychain.ageDecrypt(ciphertext, path)

    def deriveAgeSecretKey(self, path='m/0/1/0'):
        keychain = KeyChain.fromSeed(self.master_seed)
        return keychain.deriveAgeSecretKey(path)

    def decryptSlatepack(self, armored_slatepack_: Union[str, SlatepackMessage], path='m/0/1/0'):
        if isinstance(armored_slatepack_, str):
            slatepack_message = SlatepackMessage.unarmor(armored_slatepack_)
        else:
            slatepack_message = armored_slatepack_

        if not slatepack_message.is_encrypted():
            # TODO raise a warning it was not encrypted
            return slatepack_message

        keychain = KeyChain.fromSeed(self.master_seed)
        age_secret_key = keychain.deriveAgeSecretKey(path)

        slatepack_message.decryptPayload(age_secret_key)

        return slatepack_message


    @classmethod
    def initialize(self):
        master_seed = os.urandom(32)
        return Wallet(master_seed=master_seed)


    @classmethod
    def fromSeedPhrase(self, phrase: str):
        M = Mnemonic()
        master_seed = M.entropyFromMnemonic(phrase)
        return Wallet(master_seed=master_seed)


    @classmethod
    def fromEncryptedSeedDict(self, seed: dict, passphrase=None):
        return self.fromEncryptedSeed(
            seed['encrypted_seed'], seed['salt'], seed['nonce'],
            passphrase=passphrase)


    @classmethod
    def fromEncryptedSeed(
            self, encrypted_seed_hex: str, salt_hex: str, nonce_hex: str,
            passphrase=None):
        encrypted_seed = bytes.fromhex(encrypted_seed_hex)
        nonce = bytes.fromhex(nonce_hex)
        salt = bytes.fromhex(salt_hex)
        w = Wallet(encrypted_seed=encrypted_seed, salt=salt, nonce=nonce)
        if passphrase is not None:
            w.unshieldWallet(passphrase, nonce=nonce, salt=salt)
        return w

class WalletStorage:
    # Outputs
    def get_all_outputs(self) -> List[OutputDataEntity]:
        raise NotImplementedError

    def get_outputs_by_status(self, status: EOutputStatus) -> List[OutputDataEntity]:
        raise NotImplementedError

    def add_output(self, output: OutputDataEntity, kernel: Optional[TransactionKernel] = None):
        """Add new output (e.g., receive or coinbase). Kernel optional for coinbase/confirmed."""
        raise NotImplementedError

    def update_output(self, output: OutputDataEntity):
        """Update status, height, etc. (e.g., lock, spend, confirm, mature)."""
        raise NotImplementedError

    def mark_output_spent(self, commitment: bytes):
        """Helper for refresh: mark as spent."""
        raise NotImplementedError

    # Transactions / Slates
    def save_slate_context(
        self,
        slate_id: UUID,
        slate,
        secret_key: Optional[bytes] = None,
        secret_nonce: Optional[bytes] = None,
        kernel: Optional[TransactionKernel] = None
    ):
        """Save in-progress or confirmed slate + blinding secrets."""
        raise NotImplementedError

    def get_slate_context(self, slate_id: UUID) -> Optional[Dict]:
        """Return dict with slate, secrets, kernel."""
        raise NotImplementedError

    def get_tx_kernel(self, slate_id: UUID) -> Optional[TransactionKernel]:
        """Get kernel for confirmed tx."""
        raise NotImplementedError

    def delete_slate_context(self, slate_id: UUID):
        """Cleanup after cancel or full confirm."""
        raise NotImplementedError

    # Misc
    def commit(self):
        """Flush changes (useful for DB impl)."""
        pass

class WalletStorageInMemory(WalletStorage):
    def __init__(self):
        self.outputs: List[OutputDataEntity] = []  # All outputs (active + spent)
        self.txs: Dict[UUID, Dict] = {}  # slate_id -> context

    # Outputs
    def get_all_outputs(self) -> List[OutputDataEntity]:
        return self.outputs[:]

    def get_outputs_by_status(self, status: EOutputStatus) -> List[OutputDataEntity]:
        return [o for o in self.outputs if o.status == status]

    def add_output(self, output: OutputDataEntity, kernel: Optional[TransactionKernel] = None):
        # For coinbase: set status=IMMATURE, link kernel if needed
        self.outputs.append(output)

        # TODO
        #if kernel and output.is_coinbase:  # assume flag or check features
        #    # Optional: store kernel separately or in output
        #    pass

    def update_output(self, updated_output: OutputDataEntity):
        for i, o in enumerate(self.outputs):
            if o.output.commitment == updated_output.output.commitment:  # assume unique commitment
                self.outputs[i] = updated_output
                return
        raise ValueError("Output not found")

    def mark_output_spent(self, commitment: bytes):
        for o in self.outputs:
            if o.output.commitment == commitment:
                o.output.status = EOutputStatus.SPENT
                return

    # Slates / Txs
    def save_slate_context(
        self,
        slate_id: UUID,
        slate,
        secret_key=None,
        secret_nonce=None,
        kernel=None
    ):
        self.txs[slate_id] = {
            'slate': slate,
            'secret_key': secret_key,
            'secret_nonce': secret_nonce,
            'kernel': kernel  # None for in-progress, set on finalize/post
        }

    def get_slate_context(self, slate_id: UUID) -> Optional[Dict]:
        return self.txs.get(slate_id)

    def get_tx_kernel(self, slate_id: UUID) -> Optional[TransactionKernel]:
        ctx = self.txs.get(slate_id)
        return ctx['kernel'] if ctx else None

    def delete_slate_context(self, slate_id: UUID):
        self.txs.pop(slate_id, None)

class NodeAccess:
    def get_current_block_height(self):
        raise NotImplementedError

    # methods consistent with RFC
    # https://docs.grin.mw/grin-rfcs/text/0007-node-api-v2/
    def get_outputs(self, outputs: List[OutputDataEntity]):
        raise NotImplementedError

    def get_kernel(self, excess: bytes) -> TransactionKernel:
        """Check if kernel exists, return kernel info + height if found."""
        raise NotImplementedError

    def push_transaction(self, transaction: Transaction):
        raise NotImplementedError

class WalletBalance:
    def __init__(self, awaiting_finalization, awaiting_confirmation, spendable):
        self.awaiting_finalization = awaiting_finalization
        self.awaiting_confirmation = awaiting_confirmation
        self.spendable = spendable
        self.total = awaiting_finalization + awaiting_confirmation + spendable

    def toJSON(self):
        return {
            'awaiting_finalization': self.awaiting_finalization,
            'awaiting_confirmation': self.awaiting_confirmation,
            'spendable': self.spendable,
            'total': self.total
        }

class PersistentWallet:
    def __init__(self, wallet: Wallet, storage: WalletStorage, node=None):
        self._wallet = wallet
        self._storage = storage

        if node is not None:
            self._node = node
        else:
            # TODO initialize the default local API node
            pass

    def refresh(self):
        # get all outputs awaiting confirmation
        outputs = self._storage.get_outputs_by_status(EOutputStatus.NO_CONFIRMATIONS)
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
                    if output_info['spent']:
                        output.status = EOutputStatus.SPENT
                    else:
                        output.status = EOutputStatus.SPENDABLE
                    output.block_height = output_info['height']
                    output.mmr_index = output_info['mmr_index']
                    break

    def post_transaction(self, finalized_slate: SlatepackMessage):
        self._node.post_transaction(finalized_slate)

    def shieldWallet(self, passphrase: str, salt=None, nonce=None):
        self._wallet.shieldWallet(passphrase, salt=salt, nonce=nonce)

    def unshieldWallet(self, passphrase: str, salt=None, nonce=None):
        self._wallet.unshieldWallet(passphrase, salt=salt, nonce=nonce)

    def createCoinbase(self, amount, path='m/0/1/0'):
        kernel, output = self._wallet.createCoinbase(amount, path=path)

        offset = BlindingFactor(bytes([0x00 for j in range(32)]))

        inputs = [
            TransactionInput(
                EKernelFeatures.COINBASE_KERNEL,
                output.getCommitment()
            )
        ]
        outputs = [output]
        kernels = [kernel]
        transaction_body = TransactionBody(
            inputs, outputs, kernels
        )

        coinbase_transaction = Transaction(
            offset,
            transaction_body
        )

        # TODO add to storage transactions + output
        self._storage.add_output(output, kernel=kernel)

        return coinbase_transaction

    def identify_own_outputs_from_slate(self, slate, path='m/0/1/0'):
        slate_context = self._storage.get_slate_context(slate.slate_id)
        kernel = slate_context['kernel']

        keychain = KeyChain.fromSeed(self._wallet.master_seed)
        for commitment in slate.commitments:
            if commitment.range_proof:
                # now we know this commitment is an output
                range_proof = commitment.range_proof
                # we will check if this output belongs to this wallet
                # this way we will know if we should store it
                try:
                    rewind_proof = keychain.rewindRangeProof(
                        commitment.commitment,
                        range_proof,
                        EBulletproofType.ENHANCED) # ORIGINAL
                except Exception as e:
                    # this is not our output, skip
                    continue

                # this output belongs to this wallet
                # we should add it to the storage
                transaction_output = TransactionOutput(
                    EOutputFeatures.DEFAULT,
                    commitment.commitment,
                    range_proof)

                # build the output data entity
                output_data_entity = OutputDataEntity(
                    path,
                    rewind_proof.blinding_factor,
                    transaction_output,
                    rewind_proof.amount,
                    EOutputStatus.NO_CONFIRMATIONS)

                self._storage.add_output(output_data_entity, kernel=kernel)

    def send(
            self,
            amount: int,
            receiver: SlatepackAddress,
            path='m/0/1/0',
            num_change_outputs=1,
            fee_base=0,
            block_height=None,
            encrypt=True):
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
            raise Exception('Insufficient funds')

        send_slate, secret_key, secret_nonce = self._wallet.send(
            inputs,
            num_change_outputs,
            amount,
            fee_base,
            block_height,
            path=path,
            receiver_address=receiver)

        self._storage.save_slate_context(
            send_slate.slate_id,
            send_slate,
            secret_key=secret_key,
            secret_nonce=secret_nonce)

        # prepare s1 slatepack
        sender_address = self.getSlatepackAddress(path=path)
        version = SlatepackVersion(0, 0)
        metadata = SlatepackMetadata(
            sender=SlatepackAddress.fromBech32(sender_address))
        emode = EMode.PLAINTEXT
        send_slatepack_message = SlatepackMessage(
            version, metadata, emode, send_slate.serialize())

        if encrypt:
            send_slatepack_message.encryptPayload(
                [SlatepackAddress.fromBech32(receiver)])
            return send_slatepack_message

        return send_slatepack_message

    def receive(
            self,
            send_slate: SlatepackMessage,
            path='m/0/1/0',
            encrypt=True):
        if send_slate.is_encrypted():
            s1 = self._wallet.decryptSlatepack(
                send_slate, path=path)
        else:
            s1 = send_slate

        slate = s1.getSlate()
        receive_slate = self._wallet.receive(
            slate,
            path=path)

        self._storage.save_slate_context(
            receive_slate.slate_id,
            receive_slate
        )
        self.identify_own_outputs_from_slate(receive_slate, path=path)

        receive_slate_payload = receive_slate.serialize()
        sender_address = self.getSlatepackAddress(path=path)
        version = SlatepackVersion(0, 0)
        metadata = SlatepackMetadata(
            sender=SlatepackAddress.fromBech32(sender_address))
        emode = EMode.PLAINTEXT
        receive_slatepack_message = SlatepackMessage(
            version, metadata, emode, receive_slate_payload)

        if encrypt:
            if not send_slate.metadata.sender:
                raise Exception('Cannot encrypt receive slatepack: original sender address missing')
            original_sender_address = send_slate.metadata.sender  # original sender address
            receive_slatepack_message.encryptPayload(
                [original_sender_address])

        return receive_slatepack_message

    def invoice(self):
        raise Exception('unimplemented')

    def pay(self):
        raise Exception('unimplemented')

    def finalize(
            self,
            final_slate: SlatepackMessage,
            path='m/0/1/0',
            testnet=False):
        if final_slate.is_encrypted():
            s2 = self._wallet.decryptSlatepack(
                final_slate, path=path)
        else:
            s2 = final_slate

        slate = s2.getSlate()
        slate_context = self._storage.get_slate_context(slate.slate_id)
        secret_key = slate_context['secret_key']
        secret_nonce = slate_context['secret_nonce']
        kernel = slate_context['kernel']
        finalized_slate = self._wallet.finalize(
            slate,
            secret_key,
            secret_nonce,
            path=path,
            testnet=testnet)

        self._storage.save_slate_context(
            finalized_slate.slate_id,
            finalized_slate,
            kernel=kernel,
            secret_key=secret_key,
            secret_nonce=secret_nonce
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
                    commitment.range_proof)
                outputs.append(output)
            else:
                input = TransactionInput(
                    EOutputFeatures.DEFAULT,
                    commitment.commitment)
                inputs.append(input)

        kernel = TransactionKernel(
            EKernelFeatures.DEFAULT_KERNEL,
            Fee(0, finalized_slate.fee),
            finalized_slate.lock_height,
            finalized_slate.getKernelCommitment(),
            finalized_slate.getSignature(0) # 0 ? TODO
        )
        kernels.append(kernel)

        transaction_body = TransactionBody(
            inputs, outputs, kernels
        )

        transaction = Transaction(
            finalized_slate.offset,
            transaction_body
        )

        self._node.push_transaction(transaction)

    def balance(self):
        awaiting_finalization = 0
        awaiting_confirmation = 0
        spendable = 0

        outputs = self._storage.get_all_outputs()
        for output in outputs:
            if output.status == EOutputStatus.NO_CONFIRMATIONS:
                awaiting_confirmation += output.getAmount()
            elif output.status == EOutputStatus.LOCKED:
                awaiting_finalization += output.getAmount()
            elif output.status == EOutputStatus.SPENDABLE:
                spendable += output.getAmount()

        return WalletBalance(
            awaiting_finalization,
            awaiting_confirmation,
            spendable
        )

    def ageDecrypt(self, ciphertext: bytes, path='m/0/1/0'):
        return self._wallet.ageDecrypt(ciphertext, path=path)

    def ageEncrypt(self, plaintext: bytes, receiver_address: str):
        keychain = KeyChain.fromSeed(self._wallet.master_seed)
        age_public_key = keychain.deriveAgePublicKeyFromSlatepackAddress(
            receiver_address)
        return keychain.ageEncrypt(plaintext, age_public_key)

    def getSlatepackAddress(self, path='m/0/1/0', testnet=False):
        return self._wallet.getSlatepackAddress(path=path, testnet=testnet)
