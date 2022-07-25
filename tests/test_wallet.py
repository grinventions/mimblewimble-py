import pytest

from hashlib import blake2b

from bip32 import BIP32
from bip_utils import Bech32Encoder

from nacl import bindings

from mimblewimble.wallet import Wallet
from mimblewimble.mnemonic import Mnemonic


# this wallet contains no funds, was generated using grin-wallet 5.0.3 for test purposes,
# do NOT send any funds to this wallet and if you do, consider them lost as the seed is publicly disclosed

seed = {
    'encrypted_seed': '839773da8062af7dc51714fd98a7f9a72750e17aa54541d5317b5ea1be5c5751db85497aa630380dd984e2ecd603ae0b',
    'salt': '356f045acf2b2787',
    'nonce': 'b5a490e1c942e6a5147bb740'
}

password = 'grinventions'

recovery_phrase = 'sign interest obtain raw window monster jump bring nice crunch toward grunt prosper recycle sphere battle mother fold reject velvet emotion similar romance govern'

accounts = [
    (
        'default',
        'm/0/0',
        'grin14kgku7l5x6te3arast3p59zk4rteznq2ug6kmmypf2d6z8md76eqg3su35'
    ),
    (
        'alice',
        'm/1/0',
        'grin1uqan8sf49yf0369ezef9jhl25jll9fc8xc5wjkcg0w6nv6v85v2sp4wgwy'
    ),
    (
        'bob',
        'm/2/0',
        'grin1guszgjsjlt9vrppu42l03xx080epzzvse5nev3nvdh632explc0sj8ylja'
    ),
]

# this simply tests if runs, does not check any correctness
def test_decrypt():
    M = Mnemonic()
    master_seed_ref = M.entropyFromMnemonic(recovery_phrase)

    encrypted_seed = bytes.fromhex(seed['encrypted_seed'])
    nonce = bytes.fromhex(seed['nonce'])
    salt = bytes.fromhex(seed['salt'])

    w = Wallet(encrypted_seed=encrypted_seed, nonce=nonce, salt=salt)
    w.unshieldWallet(password, nonce=nonce, salt=salt)

    assert w.master_seed == master_seed_ref
    assert recovery_phrase == w.getSeedPhrase()

    w.encryptWallet(password, nonce=nonce, salt=salt)

    assert w.encrypted_seed == encrypted_seed


@pytest.mark.skip(reason='wip')
def test_from_seed_phrase():
    w = Wallet.fromSeedPhrase(recovery_phrase)
    for label, path, expected_address in accounts:
        address = w.getSlatepackAddress(path=path)
        print()
        print(address)
        print(expected_address)


@pytest.mark.skip(reason='wip')
def test_grin_plusplus():
    seed_words = 'dehydrate opened lilac elapse subtly prying swept ruby liar veteran wife afloat strained camp tugs pager dual tomorrow aimless boxes saucepan invoke utensils vapidly lilac'
    just_seed_words = ' '.join(seed_words.split(' ')[0:-1])
    print(len(seed_words.split(' ')))
    M = Mnemonic()
    master_seed = M.entropyFromMnemonic(just_seed_words)

    # print('by', bindings.crypto_sign_SECRETKEYBYTES)
    seed = bytes.fromhex('f9a0e73d3cd533368f75ff63cbd97b2100beffbc339cdfa5c203c1a022d9cf11')
    assert seed == master_seed

    bip32 = BIP32.from_seed(seed)
    path = 'm/0/1/0'
    print()
    sk_der = bip32.get_privkey_from_path(path)
    print(sk_der.hex())
    sk_der_blake = blake2b(sk_der, digest_size=64).digest()
    pk = bindings.crypto_sign_ed25519_sk_to_pk(sk_der_blake)
    print()
    print(pk.hex())
    print('068131549ec5c3bdcb3d13a855e1b76d179919efd974669292b322f5d59a4ccc')
    slatepack_address = Bech32Encoder.Encode('grin', pk)
    print(slatepack_address)
    print('grin1q6qnz4y7chpmmjeazw59tcdhd5tejx00m96xdy5jkv30t4v6fnxqv9kwer')
