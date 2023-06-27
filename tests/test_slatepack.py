from mimblewimble.wallet import Wallet
from mimblewimble.keychain import KeyChain
from mimblewimble.models.slatepack.address import SlatepackAddress

# data
# https://github.com/GrinPlusPlus/GrinPlusPlus/blob/master/tests/src/Wallet/Test_Slatepack.cpp

cases = [
    (
        'm/0/1/0',
        'eae22f4149ef8ba1601c1dc9225bf70a4cf1a265c089385d85181e406bd5759a',
        'grin1at3z7s2fa796zcqurhyjyklhpfx0rgn9czynshv9rq0yq674wkdq5qdy6w',
        '5lrc6qkj56f2cya4dxesew7xbjgpditfycetqxmfdapea26vownfpnid'
    ),
    (
        'm/0/1/1',
        '38ca1ccde9967778414b4954db6f670f3a9fb94a67c795bb7cb03cbca5a04772',
        'grin18r9pen0fjemhss2tf92dkmm8puaflw22vlretwmukq7tefdqgaeqyve0qy',
        'hdfbztpjsz3xqqkljfknw33hb45j7okkm7dzlo34wa6lzjnai5zj25yd'
    ),
    (
        'm/0/1/2',
        '0741a2aca1e20772dd4ceef0505f0f2b03fef54222b9613b0d79d51d4a80409d',
        'grin1qaq69t9pugrh9h2vamc9qhc09vplaa2zy2ukzwcd08236j5qgzwsmasmf5',
        'a5a2flfb4idxfxkm53yfaxypfmb755kcek4wcoynphkr2suaicotbyad'
    ),
    (
        'm/0/1/3',
        '897bdd8906a2e6ed5e0b545f5edb765502f48d4d8ce130ad4fa307425d7b4ded',
        'grin139aamzgx5tnw6hst2304akmk25p0fr2d3nsnpt205vr5yhtmfhksd4wg9s',
        'rf553cigulto2xqlkrpv5w3wkubpjdknrtqtblkpumduexl3jxw5v2qd'
    ),
    (
        'm/0/1/4',
        'dc716e256fffdc5f73e2de5b6a53cb7127ed3ac83746b9ebe148286695d8c2aa',
        'grin1m3ckuft0llw97ulzmedk557twyn76wkgxartn6lpfq5xd9wcc24qnpwde5',
        '3ryw4jlp77of647c3znwuu6loet62owig5dlt27bjaugnfoyykvneayd'
    )
]

def test_address_derivation():
    path = 'm/0/1/0'

    mnemonic = [
        'antique couple pulse gold',
        'power coconut refuse river',
        'room tornado custom frame',
        'spy property future cluster',
        'betray retire series orchard',
        'exile order sword bid']
    recovery_phrase = ' '.join(mnemonic)
    w = Wallet.fromSeedPhrase(recovery_phrase)

    master_seed = bytes.fromhex(
        '09e626b6322a9459ed1dd6bbfcacda2e4d3558d7a1631576ff104e04fb387710')
    kc = KeyChain.fromSeed(master_seed)
    assert w.getSlatepackAddress(path=path) == kc.deriveSlatepackAddress(path=path)

    for path, ed25519, bech32, tor in cases:
        ed25519pk = kc.deriveED25519PublicKey(path=path)
        sa = SlatepackAddress(ed25519pk)

        assert ed25519pk.hex() == ed25519
        assert sa.toBech32() == bech32
        assert sa.toTOR() == tor

