from mimblewimble.helpers.tor import TorAddress
from mimblewimble.keychain import KeyChain

# test data from https://github.com/GrinPlusPlus/GrinPlusPlus/blob/fa3705f5558f0372410aa4222f5f1d97a0ab2247/tests/src/Wallet/Test_Slatepack.cpp

test_data = [
    (
        'm/0/1/0',
        'eae22f4149ef8ba1601c1dc9225bf70a4cf1a265c089385d85181e406bd5759a',
        '5lrc6qkj56f2cya4dxesew7xbjgpditfycetqxmfdapea26vownfpnid.onion',
        'grin1at3z7s2fa796zcqurhyjyklhpfx0rgn9czynshv9rq0yq674wkdq5qdy6w'
    ),
    (
        'm/0/1/1',
        '38ca1ccde9967778414b4954db6f670f3a9fb94a67c795bb7cb03cbca5a04772',
        'hdfbztpjsz3xqqkljfknw33hb45j7okkm7dzlo34wa6lzjnai5zj25yd.onion',
        'grin18r9pen0fjemhss2tf92dkmm8puaflw22vlretwmukq7tefdqgaeqyve0qy'
    ),
    (
        'm/0/1/2',
        '0741a2aca1e20772dd4ceef0505f0f2b03fef54222b9613b0d79d51d4a80409d',
        'a5a2flfb4idxfxkm53yfaxypfmb755kcek4wcoynphkr2suaicotbyad.onion',
        'grin1qaq69t9pugrh9h2vamc9qhc09vplaa2zy2ukzwcd08236j5qgzwsmasmf5'
    ),
    (
        'm/0/1/3',
        '897bdd8906a2e6ed5e0b545f5edb765502f48d4d8ce130ad4fa307425d7b4ded',
        'rf553cigulto2xqlkrpv5w3wkubpjdknrtqtblkpumduexl3jxw5v2qd.onion',
        'grin139aamzgx5tnw6hst2304akmk25p0fr2d3nsnpt205vr5yhtmfhksd4wg9s'
    ),
    (
        'm/0/1/4',
        'dc716e256fffdc5f73e2de5b6a53cb7127ed3ac83746b9ebe148286695d8c2aa',
        '3ryw4jlp77of647c3znwuu6loet62owig5dlt27bjaugnfoyykvneayd.onion',
        'grin1m3ckuft0llw97ulzmedk557twyn76wkgxartn6lpfq5xd9wcc24qnpwde5'
    )
]

def test_slatepacks():
    seed = bytes.fromhex(
        '09e626b6322a9459ed1dd6bbfcacda2e4d3558d7a1631576ff104e04fb387710')
    keychain = KeyChain.fromSeed(seed)

    for path, expected_ed25519, expected_onion, expected_slatepack_address in test_data:
        ed25519 = keychain.deriveED25519PublicKey(path).hex()
        onion = keychain.deriveOnionAddress(path)
        slatepack_address = keychain.deriveSlatepackAddress(path)
        assert ed25519 == expected_ed25519
        assert onion == expected_onion
        assert slatepack_address == expected_slatepack_address

        # validate the TOR address
        TorAddress.parse(onion)
