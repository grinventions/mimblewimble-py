from secp256k1_zkp_mw import secp256k1_context_create
from secp256k1_zkp_mw import secp256k1_context_destroy

from secp256k1_zkp_mw import secp256k1_ec_seckey_verify
from secp256k1_zkp_mw import secp256k1_ec_pubkey_create
from secp256k1_zkp_mw import secp256k1_ec_pubkey_parse
from secp256k1_zkp_mw import secp256k1_ec_pubkey_serialize
from secp256k1_zkp_mw import secp256k1_ec_pubkey_combine

from secp256k1_zkp_mw import SECP256K1_CONTEXT_SIGN
from secp256k1_zkp_mw import SECP256K1_CONTEXT_VERIFY
from secp256k1_zkp_mw import SECP256K1_EC_COMPRESSED

from mimblewimble.crypto.secret_key import SecretKey
from mimblewimble.crypto.public_key import PublicKey

class PublicKeys:
    def __init__(self):
        self.ctx = secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)

    def __del__(self):
        secp256k1_context_destroy(self.ctx)

    def isSecretKeyValid(self, sk: SecretKey):
        is_valid = secp256k1_ec_seckey_verify(self.ctx, sk.getBytes())
        return is_valid

    def calculatePublicKey(self, sk: SecretKey, compressed=True):
        assert self.isSecretKeyValid(sk)
        pk = secp256k1_ec_pubkey_create(self.ctx, sk.getBytes())
        pk_serialized = secp256k1_ec_pubkey_serialize(
            self.ctx, pk, SECP256K1_EC_COMPRESSED)
        return PublicKey(pk_serialized)

    def publicKeySum(self, pks, compressed=False):
        parsed_pks = []
        for pk in pks:
            parsed = secp256k1_ec_pubkey_parse(self.ctx, pk.getBytes())
            parsed_pks.append(parsed)
        combined = secp256k1_ec_pubkey_combine(self.ctx, parsed_pks)
        pk_serialized = secp256k1_ec_pubkey_serialize(
            self.ctx, combined, SECP256K1_EC_COMPRESSED)
        return PublicKey(pk_serialized)
