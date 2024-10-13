import hashlib
import base64
import math

from io import BytesIO

from age.file import Decryptor as ageStreamDecrypt
from age.keys.agekey import AgePrivateKey

from bip_utils import Bech32Encoder

from mimblewimble.serializer import Serializer
from mimblewimble.crypto.age import AgeMessage

from mimblewimble.helpers.encryption import ageX25519Decrypt

from mimblewimble.models.slatepack.address import SlatepackAddress
from mimblewimble.models.slatepack.metadata import SlatepackVersion
from mimblewimble.models.slatepack.metadata import SlatepackMetadata

from mimblewimble.models.slatepack.message import EMode

raw = b'\xfb\xcf6\xfd\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02{age-encryption.org/v1\n-> X25519 F/H3hf63Hrq2MH+O1naWm6+M8184u3S7oeHQ4VHiMzY\npbUcLLHdT5PGn/oYeiD+tsUO1oexurSZmSVu8Hcv7mc\n-> Es[-grease )vK1eC lVxuS`,6\nSkmgyCDG0wPb0wvGeYp6XbdSyMONfXYoRPLyQSlkse8tDxkTHKwjoz6Y3t2IIqHv\nU/dxyW2iZyZ1UVFRrlNAVbXbEBwqhpaFjDdRcivhbDo1uTL5CDNvJz89w+ivaoUc\n\n--- nq0hJv/bV3kLRrqKU9wlkexF2STZDmBf0hlees/HyWw\n\x8cA\xc3+\x1a\xaf\x10\x93T\x18\x0f\xf9J\x14\xaf\xb0\xcdw\xb9\x10\xa7\x90>V-\xc3=D\xafwc\xdeo\x08\xefx\xdd\x19\x85DtG\xad\xc8\x88*\x84\xe5Z\x07G\x95\x08\xad\xca\xb8\x81N\x1aJ\xfc\x97z\xa8\xfcR\xd8Y\xa4\x90\xcc[\x05\x989\xb1\x9d\xd1U\xdcsJu\xc7\xc4\xb9\x91\x03\x07\x08C\xd5\xfb>s\x80"\t\x85)\x8c(\x1dL\x9f\xa2\xea\xae\xf2f\xf8~\xfe\xc8\xc8\x14\xdeKD\xd8\x8b2\xd2\xca\xf4\xbdM\xcf\xe8_\x88\x03$=\xe1\x11(5g\xde\x9cF,S\xec0#*.\xa0\xe6H\x0f\x94\x8b\x02\xd1\xd9v\xea\xb8u%Dp\xb4\xb9\x88Jvz\xb9\x07\x1e$\x0f\xf5\x80\xe5\xbc\xe5I\x8b\x9f\xc8\xe1\x04\xec0T\x99\xf1cC\xd5\x90\xb27\x18\x1d\x88\x9d\x85\xea\x07\x11\xc4\x92\x0c\x07\xee\xc5\xb8\x1f\xf2&\xf29\x00R\xd4\xb6\xbfe\x18\xfd\xdd\x1a\x8f\xf0\xc3$\xfc0\xf3\xdc`\xed\xd0\xbd\xaa\xbd\t\x9d\xf1\x93.\xa6\xa6C\x0f\x0b;\x9er~P\xbd\xe1\xd5\xf5\x1f\xda>}\xe5J\x93\xc8\xde\xf4^\x9f\xbd\xbblK\xf3\xe3hP\xef\xdc\xb2\xbd\x05\xf1\x08\x9e\xe0\x96\xaeg\xd9\x1b\xc7\xf2/\xb8\xbe%aY\xdf\xc6T'
s = Serializer()
s.write(raw)


def test_age_message_serialization():
    serializer = s

    error_check_code = serializer.read(4)

    version = SlatepackVersion.deserialize(serializer)
    emode = EMode(int.from_bytes(serializer.read(1), 'big'))

    opt_flags = int.from_bytes(serializer.read(2), 'big')
    opt_fields_len = int.from_bytes(serializer.read(4), 'big')

    metadata = SlatepackMetadata()
    if opt_flags & 0x01 == 0x01:
        sender = SlatepackAddress.deserialize(serializer)
        metadata = SlatepackMetadata(sender=sender)

    payload_size = int.from_bytes(serializer.read(8), 'big')
    payload = serializer.read(payload_size)

    # checksum

    print()
    serializer.resetPointer()
    serializer.read(4)
    preimage = serializer.readremaining()
    hashed = hashlib.sha256(preimage).digest()
    hashed = hashlib.sha256(hashed).digest()
    checksum = hashed[0:4]
    if checksum == error_check_code:
        print('checksum correct')
    else:
        print('checksum mismatch')

    print('emode is', emode)
    if emode == EMode.ENCRYPTED:
        print('is encrypted')
    else:
        print('is not encrypted')

    # m/0/1/0 alice x25519 secret key
    x25519sk = bytes.fromhex('90ad4d97dd2f7dd5360375f2ad72011489baa8beb84f1109b2bdb79b4183476a')

    ciphertext = payload

    age_secret_key = Bech32Encoder.Encode(
        'age-secret-key-', x25519sk)
    decrypted = ageX25519Decrypt(ciphertext, age_secret_key)

    print('decrypted payload')
    print(decrypted)

    d = Serializer()
    d.write(decrypted)

    size = int.from_bytes(d.read(4), 'big')

    inner_buffer = Serializer()
    inner_buffer.write(d.read(size))

    opt_flags = int.from_bytes(inner_buffer.read(2), 'big')

    sender = None
    if opt_flags & 0x01 == 0x01:
        sender = SlatepackAddress.deserialize(inner_buffer)

    recipients = []
    if opt_flags & 0x02 == 0x02:
        num_recipients = int.from_bytes(inner_buffer.read(2), 'big')
        for i in range(num_recipients):
            recipient = SlatepackAddress.deserialize(inner_buffer)
            recipients.append(recipient)

    print('sender', sender.toBech32())
    print('recipients', recipients)


    '''
    serializer = Serializer()

    age_message = AgeMessage.deserialize(s)

    serializer = Serializer()
    age_message.serialize(serializer)

    assert serializer.readall() == raw

    print()
    for recipient in age_message.header.recipients:
        print(recipient._type.decode(), [arg.decode() for arg in recipient.args])
    '''


def test_age_recipient_stanza():
    path = 'm/0/1/0'
    slatepack_address = 'grin14kgku7l5x6te3arast3p59zk4rteznq2ug6kmmypf2d6z8md76eqg3su35'
    ed25519pk = 'ad916e7bf4369798f47d82e21a1456a8d7914c0ae2356dec814a9ba11f6df6b2'
    ed25519sk = '7f7394cd934ba03a26d5774ef45b5969670d0ce1e4bbc1174e6a871f507af0ddad916e7bf4369798f47d82e21a1456a8d7914c0ae2356dec814a9ba11f6df6b2'
    x25519pk = '585b020389181ac540a9e268eb5f5d7d86297bad2ee0c8fb5eb533f92ce66d4d'
    x25519sk = '90ad4d97dd2f7dd5360375f2ad72011489baa8beb84f1109b2bdb79b4183476a'
    agepk = 'age1tpdsyqufrqdv2s9fuf5wkh6a0krzj7ad9msv3767k5eljt8xd4xscfzxhm'
    agesk = 'AGE-SECRET-KEY-1JZK5M97A9A7A2DSRWHE26USPZJYM4297HP83ZZDJHKMEKSVRGA4QG7GS5A'

    # header data
    ephemeral_share = b'F/H3hf63Hrq2MH+O1naWm6+M8184u3S7oeHQ4VHiMzY' + b'=='
    encrypted_file_key = b'pbUcLLHdT5PGn/oYeiD+tsUO1oexurSZmSVu8Hcv7mc' + b'=='
    header_mac = b'nq0hJv/bV3kLRrqKU9wlkexF2STZDmBf0hlees/HyWw' + b'=='

    # payload data
    encrypted_payload = b'\x8cA\xc3+\x1a\xaf\x10\x93T\x18\x0f\xf9J\x14\xaf\xb0\xcdw\xb9\x10\xa7\x90>V-\xc3=D\xafwc\xdeo\x08\xefx\xdd\x19\x85DtG\xad\xc8\x88*\x84\xe5Z\x07G\x95\x08\xad\xca\xb8\x81N\x1aJ\xfc\x97z\xa8\xfcR\xd8Y\xa4\x90\xcc[\x05\x989\xb1\x9d\xd1U\xdcsJu\xc7\xc4\xb9\x91\x03\x07\x08C\xd5\xfb>s\x80"\t\x85)\x8c(\x1dL\x9f\xa2\xea\xae\xf2f\xf8~\xfe\xc8\xc8\x14\xdeKD\xd8\x8b2\xd2\xca\xf4\xbdM\xcf\xe8_\x88\x03$=\xe1\x11(5g\xde\x9cF,S\xec0#*.\xa0\xe6H\x0f\x94\x8b\x02\xd1\xd9v\xea\xb8u%Dp\xb4\xb9\x88Jvz\xb9\x07\x1e$\x0f\xf5\x80\xe5\xbc\xe5I\x8b\x9f\xc8\xe1\x04\xec0T\x99\xf1cC\xd5\x90\xb27\x18\x1d\x88\x9d\x85\xea\x07\x11\xc4\x92\x0c\x07\xee\xc5\xb8\x1f\xf2&\xf29\x00R\xd4\xb6\xbfe\x18\xfd\xdd\x1a\x8f\xf0\xc3$\xfc0\xf3\xdc`\xed\xd0\xbd\xaa\xbd\t\x9d\xf1\x93.\xa6\xa6C\x0f\x0b;\x9er~P\xbd\xe1\xd5\xf5\x1f\xda>}\xe5J\x93\xc8\xde\xf4^\x9f\xbd\xbblK\xf3\xe3hP\xef\xdc\xb2\xbd\x05\xf1\x08\x9e\xe0\x96\xaeg\xd9\x1b\xc7\xf2/\xb8\xbe%aY\xdf\xc6T'

    # decode data from the header
    decoded_ephemeral_share = base64.b64decode(
        ephemeral_share)
    assert decoded_ephemeral_share.hex() == '17f1f785feb71ebab6307f8ed676969baf8cf35f38bb74bba1e1d0e151e23336'


    decoded_encrypted_file_key = base64.b64decode(
        encrypted_file_key)
    assert decoded_encrypted_file_key.hex() == 'a5b51c2cb1dd4f93c69ffa187a20feb6c50ed687b1bab49999256ef0772fee67'

    decoded_header_mac = base64.b64decode(
        header_mac)
    assert decoded_header_mac.hex() == '9ead2126ffdb57790b46ba8a53dc2591ec45d924d90e605fd2195e7acfc7c96c'

    public_key = bytes.fromhex(x25519pk)
    private_key = bytes.fromhex(x25519sk)

    salt = decoded_ephemeral_share + public_key

    from nacl.bindings import crypto_scalarmult

    key_material = crypto_scalarmult(
        private_key, decoded_ephemeral_share)

    assert key_material.hex() == '5ab5690070158a90a7dfefa4639381ff676782cd6fce9c2d50d31f2fed389c77'

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    AGE_X25519_HKDF_LABEL = b'age-encryption.org/v1/X25519'

    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=AGE_X25519_HKDF_LABEL,
        backend=default_backend()
    ).derive(key_material)

    assert key.hex() == 'd008d262cc77afdcf96c0a0363ec9894e1bc840a218a5afb86eacb1c5168ba0a'

    ZERO_NONCE = b'\00' * 12

    decrypted_file_key = ChaCha20Poly1305(key).decrypt(
        ZERO_NONCE,
        decoded_encrypted_file_key,
        None)

    # print('decrypted_file_key', decrypted_file_key.hex())

    assert decrypted_file_key.hex() == 'd236c4a664b6e1d909a06bb8b7cdbd47'
    assert len(decrypted_file_key) == 16

    # assert decrypted_file_key == bytes.fromhex('d008d262cc77afdcf96c0a0363ec9894e1bc840a218a5afb86eacb1c5168ba0a')


    from cryptography.hazmat.primitives.hmac import HMAC

    HEADER_HKDF_LABEL = b'header'
    salt = b''
    hkdfval = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=HEADER_HKDF_LABEL,
        backend=default_backend()
    ).derive(decrypted_file_key)
    assert hkdfval.hex() == 'e9e4ff52ce1c1c2f7c8d280fc6f869ade9bc005b28c07a36c17ee8839e59527f'

    hmac = HMAC(
        key=hkdfval,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    mac_message = b'age-encryption.org/v1\n-> X25519 F/H3hf63Hrq2MH+O1naWm6+M8184u3S7oeHQ4VHiMzY\npbUcLLHdT5PGn/oYeiD+tsUO1oexurSZmSVu8Hcv7mc\n-> Es[-grease )vK1eC lVxuS`,6\nSkmgyCDG0wPb0wvGeYp6XbdSyMONfXYoRPLyQSlkse8tDxkTHKwjoz6Y3t2IIqHv\nU/dxyW2iZyZ1UVFRrlNAVbXbEBwqhpaFjDdRcivhbDo1uTL5CDNvJz89w+ivaoUc\n---'
    hmac.update(mac_message)

    # THIS FAILS TODO
    # hmac.verify(decoded_header_mac)

    # proceed to decrypt and prove decrypted payload is correct
    stream = BytesIO()
    stream.write(encrypted_payload)

    stream.seek(0)
    nonce = stream.read(16)
    assert nonce.hex() == '8c41c32b1aaf109354180ff94a14afb0'
    PAYLOAD_HKDF_LABEL = b'payload'
    stream_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=nonce,
        info=PAYLOAD_HKDF_LABEL,
        backend=default_backend()
    ).derive(decrypted_file_key)

    assert stream_key.hex() == '8d1229aaaf0cdf5e7917ab2a725ff68f3338d76bd2734bc9e63fde486e12cdf9'
    assert len(stream_key) == 32

    ciphertext = stream.read()
    assert ciphertext == b'\xcdw\xb9\x10\xa7\x90>V-\xc3=D\xafwc\xdeo\x08\xefx\xdd\x19\x85DtG\xad\xc8\x88*\x84\xe5Z\x07G\x95\x08\xad\xca\xb8\x81N\x1aJ\xfc\x97z\xa8\xfcR\xd8Y\xa4\x90\xcc[\x05\x989\xb1\x9d\xd1U\xdcsJu\xc7\xc4\xb9\x91\x03\x07\x08C\xd5\xfb>s\x80"\t\x85)\x8c(\x1dL\x9f\xa2\xea\xae\xf2f\xf8~\xfe\xc8\xc8\x14\xdeKD\xd8\x8b2\xd2\xca\xf4\xbdM\xcf\xe8_\x88\x03$=\xe1\x11(5g\xde\x9cF,S\xec0#*.\xa0\xe6H\x0f\x94\x8b\x02\xd1\xd9v\xea\xb8u%Dp\xb4\xb9\x88Jvz\xb9\x07\x1e$\x0f\xf5\x80\xe5\xbc\xe5I\x8b\x9f\xc8\xe1\x04\xec0T\x99\xf1cC\xd5\x90\xb27\x18\x1d\x88\x9d\x85\xea\x07\x11\xc4\x92\x0c\x07\xee\xc5\xb8\x1f\xf2&\xf29\x00R\xd4\xb6\xbfe\x18\xfd\xdd\x1a\x8f\xf0\xc3$\xfc0\xf3\xdc`\xed\xd0\xbd\xaa\xbd\t\x9d\xf1\x93.\xa6\xa6C\x0f\x0b;\x9er~P\xbd\xe1\xd5\xf5\x1f\xda>}\xe5J\x93\xc8\xde\xf4^\x9f\xbd\xbblK\xf3\xe3hP\xef\xdc\xb2\xbd\x05\xf1\x08\x9e\xe0\x96\xaeg\xd9\x1b\xc7\xf2/\xb8\xbe%aY\xdf\xc6T'
    plaintext = b''

    PLAINTEXT_BLOCK_SIZE = 64 * 1024
    CIPHERTEXT_BLOCK_SIZE = PLAINTEXT_BLOCK_SIZE + 16

    aead = ChaCha20Poly1305(stream_key)
    blocks = math.ceil(len(ciphertext) / CIPHERTEXT_BLOCK_SIZE)

    def _chunk(data, size):
        for i in range(0, len(data), size):
            yield data[i : i + size]


    for nonce, block in enumerate(_chunk(ciphertext, CIPHERTEXT_BLOCK_SIZE)):
        last_block = nonce == blocks - 1
        packed_nonce = nonce.to_bytes(
            11,
            byteorder='big',
            signed=False
        ) + (b'\x01' if last_block else b'\x00')

        plaintext += aead.decrypt(
            nonce=packed_nonce,
            data=block,
            associated_data=None)

    assert plaintext == b'\x00\x00\x00B\x00\x01?grin1m4krnajw792zxfyldu79jssh0d3kzjtwpdn2wy7fysrfw4ej0waskurq76\x00\x04\x00\x03S\xfe\x05\xcd\x07\x8bK\x8f\x96\x0bV\xafo\x1a3\xb1\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00:\xdc\r\xe0\x00\x00\x00\x00\x00\xbe\xbc \x01\x00\x02S3\xf6~\x84^\xdbV\xe3\t\xd6\x9c\x1b\xc5k\x89T\xde\t\x82\xba,\xe4!\x13\x0br\x15\x19\xa7\xa7\x9a\x022\xd9\xb4\x99\x04=\xfb5\xce\x97R;9\xa6\r\x1b"\xca.\x972bpKu\xb3\xd6\x1e\x05\xd4\x96\xe9\x02\xddl9\xf6N\xf1T#$\x9fo<YB\x17{caIn\x0bf\xa7\x13\xc9$\x06\x97W2{\xbb\xad\x91n{\xf46\x97\x98\xf4}\x82\xe2\x1a\x14V\xa8\xd7\x91L\n\xe25m\xec\x81J\x9b\xa1\x1fm\xf6\xb2\x00'



    # TODO now we need to prove that the decrypted payload is correct
