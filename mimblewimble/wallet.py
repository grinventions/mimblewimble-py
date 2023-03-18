import hmac
import os

from typing import Tuple, List

from nacl import bindings

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes

from hashlib import blake2b, pbkdf2_hmac, sha512

from bip32 import BIP32
from bip_utils import Bech32Encoder

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
from mimblewimble.models.transaction import TransactionOutput
from mimblewimble.models.transaction import TransactionKernel
from mimblewimble.models.fee import Fee

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

        # build send slate
        slate_builder = SendSlateBuilder(self.master_seed)
        slate, secret_key, secret_nonce = slate_builder.build(
            amount,
            fee,
            block_height,
            inputs,
            change_outputs,
            sender_address=sender_address_bytes,
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
