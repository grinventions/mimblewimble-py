"""Tests for BIP39 password-protected seed derivation.

Tests the BIP39 passphrase (extension word) functionality that enables
password-protected wallet derivation. Same mnemonic + different passphrase
= entirely different wallet, providing plausible deniability.

Test vectors sourced from:
- BIP39 specification: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
- Grin Rust reference: grin/keychain/src/mnemonic.rs
"""

import unittest

from mimblewimble.mnemonic import Mnemonic
from mimblewimble.keychain import KeyChain
from mimblewimble.wallet import Wallet

# BIP39 test vectors with passphrase "TREZOR"
# From https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#Test_vectors
# These are the same vectors used by grin/keychain/src/mnemonic.rs
BIP39_TEST_VECTORS = [
    (
        "00000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    ),
    (
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
    ),
    (
        "80808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
    ),
    (
        "ffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
    ),
    (
        "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
        "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
        "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
    ),
    (
        "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
        "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
        "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
    ),
    (
        "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
        "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
        "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
    ),
]


class TestMnemonicToSeed(unittest.TestCase):
    """Test Mnemonic.mnemonicToSeed BIP39 seed derivation."""

    def test_bip39_vectors_with_trezor_passphrase(self):
        """Verify BIP39 test vectors with passphrase 'TREZOR'.

        These are the canonical test vectors from the BIP39 spec, also
        used by Grin's Rust implementation for validation.
        """
        M = Mnemonic()
        for entropy_hex, mnemonic, expected_seed_hex in BIP39_TEST_VECTORS:
            with self.subTest(mnemonic=mnemonic[:40]):
                seed = M.mnemonicToSeed(mnemonic, passphrase="TREZOR")
                self.assertEqual(seed.hex(), expected_seed_hex)
                self.assertEqual(len(seed), 64)

    def test_empty_passphrase_differs_from_no_passphrase(self):
        """BIP39 seed with empty passphrase differs from raw entropy."""
        M = Mnemonic()
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        entropy = M.entropyFromMnemonic(mnemonic)

        # BIP39 seed with empty passphrase
        bip39_seed = M.mnemonicToSeed(mnemonic, passphrase="")

        # Raw entropy (legacy mode) is 16 bytes, BIP39 seed is 64 bytes
        self.assertNotEqual(entropy, bip39_seed[: len(entropy)])
        self.assertEqual(len(bip39_seed), 64)

    def test_different_passphrases_produce_different_seeds(self):
        """Same mnemonic + different passphrase = different BIP39 seed."""
        M = Mnemonic()
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

        seed_no_pass = M.mnemonicToSeed(mnemonic, passphrase="")
        seed_pass_a = M.mnemonicToSeed(mnemonic, passphrase="alpha")
        seed_pass_b = M.mnemonicToSeed(mnemonic, passphrase="beta")

        self.assertNotEqual(seed_no_pass, seed_pass_a)
        self.assertNotEqual(seed_no_pass, seed_pass_b)
        self.assertNotEqual(seed_pass_a, seed_pass_b)

    def test_mnemonicToSeed_validates_mnemonic(self):
        """mnemonicToSeed should reject invalid mnemonics."""
        M = Mnemonic()
        with self.assertRaises(ValueError):
            M.mnemonicToSeed("invalid words not in list bloop", passphrase="test")
        with self.assertRaises(ValueError):
            M.mnemonicToSeed("abandon abandon abandon", passphrase="test")

    def test_mnemonicToSeed_returns_bytes(self):
        """mnemonicToSeed should return bytes, not hex string."""
        M = Mnemonic()
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        seed = M.mnemonicToSeed(mnemonic)
        self.assertIsInstance(seed, bytes)
        self.assertEqual(len(seed), 64)

    def test_legacy_toSeed_compatibility(self):
        """Verify mnemonicToSeed matches the legacy toSeed method."""
        M = Mnemonic()
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        passphrase = "TREZOR"

        # Legacy method
        legacy_seed_hex = M.toSeed(mnemonic.encode("utf-8"), passphrase=passphrase)
        # New method
        new_seed = M.mnemonicToSeed(mnemonic, passphrase=passphrase)

        self.assertEqual(legacy_seed_hex, new_seed.hex())

    def test_mnemonicToSeed_normalizes_whitespace(self):
        """Equivalent whitespace-only mnemonic formatting yields same seed."""
        M = Mnemonic()
        canonical = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        with_extra_spaces = "  abandon   abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about  "

        seed_a = M.mnemonicToSeed(canonical, passphrase="TREZOR")
        seed_b = M.mnemonicToSeed(with_extra_spaces, passphrase="TREZOR")

        self.assertEqual(seed_a, seed_b)


class TestKeyChainFromMnemonic(unittest.TestCase):
    """Test KeyChain.fromMnemonic BIP39 passphrase-aware keychain creation."""

    def test_from_mnemonic_without_passphrase(self):
        """fromMnemonic with empty passphrase creates a valid keychain."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        kc = KeyChain.fromMnemonic(mnemonic, passphrase="")
        # Should be able to derive keys
        sk = kc.derivePrivateKey("m/0/1/0")
        self.assertIsNotNone(sk)

    def test_from_mnemonic_with_passphrase(self):
        """fromMnemonic with passphrase creates a valid keychain."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        kc = KeyChain.fromMnemonic(mnemonic, passphrase="my_secret_password")
        sk = kc.derivePrivateKey("m/0/1/0")
        self.assertIsNotNone(sk)

    def test_different_passphrases_produce_different_keys(self):
        """Same mnemonic + different passphrase = different derived keys."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

        kc_empty = KeyChain.fromMnemonic(mnemonic, passphrase="")
        kc_pass = KeyChain.fromMnemonic(mnemonic, passphrase="secret")

        sk_empty = kc_empty.derivePrivateKey("m/0/1/0")
        sk_pass = kc_pass.derivePrivateKey("m/0/1/0")

        self.assertNotEqual(sk_empty.getBytes(), sk_pass.getBytes())

    def test_from_mnemonic_differs_from_from_seed(self):
        """fromMnemonic path differs from legacy fromSeed (raw entropy) path."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        M = Mnemonic()
        entropy = M.entropyFromMnemonic(mnemonic)

        # Legacy path: raw entropy → KeyChain
        kc_legacy = KeyChain.fromSeed(entropy)
        # BIP39 path: mnemonic + passphrase → BIP39 seed → KeyChain
        kc_bip39 = KeyChain.fromMnemonic(mnemonic, passphrase="")

        sk_legacy = kc_legacy.derivePrivateKey("m/0/1/0")
        sk_bip39 = kc_bip39.derivePrivateKey("m/0/1/0")

        # These must produce different keys (different derivation paths)
        self.assertNotEqual(sk_legacy.getBytes(), sk_bip39.getBytes())

    def test_from_mnemonic_consistency(self):
        """fromMnemonic with same inputs always produces same keychain."""
        mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
        passphrase = "consistent"

        kc1 = KeyChain.fromMnemonic(mnemonic, passphrase)
        kc2 = KeyChain.fromMnemonic(mnemonic, passphrase)

        sk1 = kc1.derivePrivateKey("m/0/1/0")
        sk2 = kc2.derivePrivateKey("m/0/1/0")

        self.assertEqual(sk1.getBytes(), sk2.getBytes())

    def test_from_mnemonic_matches_manual_derivation(self):
        """fromMnemonic should match manual BIP39 seed → fromSeed pipeline."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        passphrase = "TREZOR"

        # Manual: BIP39 seed derivation then fromSeed
        M = Mnemonic()
        bip39_seed = M.mnemonicToSeed(mnemonic, passphrase)
        kc_manual = KeyChain.fromSeed(bip39_seed)

        # Using fromMnemonic
        kc_from_mnemonic = KeyChain.fromMnemonic(mnemonic, passphrase)

        sk_manual = kc_manual.derivePrivateKey("m/0/1/0")
        sk_from_mnemonic = kc_from_mnemonic.derivePrivateKey("m/0/1/0")

        self.assertEqual(sk_manual.getBytes(), sk_from_mnemonic.getBytes())

    def test_slatepack_address_with_passphrase(self):
        """BIP39 passphrase-derived keychain produces different slatepack addresses."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

        kc_no_pass = KeyChain.fromMnemonic(mnemonic, passphrase="")
        kc_with_pass = KeyChain.fromMnemonic(mnemonic, passphrase="hidden_wallet")

        addr_no_pass = kc_no_pass.deriveSlatepackAddress("m/0/1/0")
        addr_with_pass = kc_with_pass.deriveSlatepackAddress("m/0/1/0")

        self.assertNotEqual(addr_no_pass, addr_with_pass)
        # Both should be valid grin addresses
        self.assertTrue(addr_no_pass.startswith("grin"))
        self.assertTrue(addr_with_pass.startswith("grin"))


class TestWalletBIP39Passphrase(unittest.TestCase):
    """Test Wallet class BIP39 passphrase integration."""

    def test_initialize_with_passphrase(self):
        """Wallet.initialize with bip39_passphrase creates a BIP39-protected wallet."""
        w = Wallet.initialize(bip39_passphrase="my_secret")

        self.assertTrue(w.bip39_passphrase_protected)
        self.assertIsNotNone(w.mnemonic_phrase)
        self.assertIsNotNone(w.master_seed)
        self.assertEqual(len(w.master_seed), 64)  # BIP39 seed is 64 bytes

        # Should be able to get seed phrase
        phrase = w.getSeedPhrase()
        self.assertIsNotNone(phrase)
        words = phrase.split(" ")
        self.assertIn(len(words), [12, 15, 18, 21, 24])

    def test_initialize_without_passphrase_legacy(self):
        """Wallet.initialize without passphrase maintains legacy behavior."""
        w = Wallet.initialize()

        self.assertFalse(w.bip39_passphrase_protected)
        self.assertIsNone(w.mnemonic_phrase)
        self.assertIsNotNone(w.master_seed)
        self.assertEqual(len(w.master_seed), 32)  # Legacy: raw entropy

    def test_from_seed_phrase_with_passphrase(self):
        """Wallet.fromSeedPhrase with bip39_passphrase creates a BIP39 wallet."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

        w = Wallet.fromSeedPhrase(mnemonic, bip39_passphrase="test123")

        self.assertTrue(w.bip39_passphrase_protected)
        self.assertEqual(w.mnemonic_phrase, mnemonic)
        self.assertEqual(len(w.master_seed), 64)

    def test_from_seed_phrase_without_passphrase_legacy(self):
        """Wallet.fromSeedPhrase without passphrase maintains legacy behavior."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

        w = Wallet.fromSeedPhrase(mnemonic)

        self.assertFalse(w.bip39_passphrase_protected)
        self.assertIsNone(w.mnemonic_phrase)
        self.assertEqual(len(w.master_seed), 16)  # 12 words = 16 bytes entropy

    def test_passphrase_produces_different_wallet(self):
        """Same mnemonic with vs. without passphrase produces different wallets."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

        w_legacy = Wallet.fromSeedPhrase(mnemonic)
        w_bip39_empty = Wallet.fromSeedPhrase(mnemonic, bip39_passphrase="")
        w_bip39_secret = Wallet.fromSeedPhrase(mnemonic, bip39_passphrase="secret")

        addr_legacy = w_legacy.getSlatepackAddress()
        addr_bip39_empty = w_bip39_empty.getSlatepackAddress()
        addr_bip39_secret = w_bip39_secret.getSlatepackAddress()

        # All three should produce different addresses
        self.assertNotEqual(addr_legacy, addr_bip39_empty)
        self.assertNotEqual(addr_legacy, addr_bip39_secret)
        self.assertNotEqual(addr_bip39_empty, addr_bip39_secret)

    def test_bip39_wallet_reflexivity(self):
        """BIP39 wallet can be restored from its seed phrase + same passphrase."""
        passphrase = "my_secret_passphrase"
        w1 = Wallet.initialize(bip39_passphrase=passphrase)

        mnemonic = w1.getSeedPhrase()
        addr1 = w1.getSlatepackAddress()

        # Restore from seed phrase + same passphrase
        w2 = Wallet.fromSeedPhrase(mnemonic, bip39_passphrase=passphrase)
        addr2 = w2.getSlatepackAddress()

        self.assertEqual(addr1, addr2)

    def test_wrong_passphrase_produces_different_wallet(self):
        """Restoring with wrong passphrase silently produces a different wallet."""
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        w_correct = Wallet.fromSeedPhrase(mnemonic, bip39_passphrase="correct_password")
        w_wrong = Wallet.fromSeedPhrase(mnemonic, bip39_passphrase="wrong_password")

        # Different passphrases = different wallets (plausible deniability)
        self.assertNotEqual(
            w_correct.getSlatepackAddress(), w_wrong.getSlatepackAddress()
        )

    def test_bip39_wallet_get_seed_phrase(self):
        """BIP39 wallet getSeedPhrase returns stored mnemonic."""
        mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
        w = Wallet.fromSeedPhrase(mnemonic, bip39_passphrase="test")
        self.assertEqual(w.getSeedPhrase(), mnemonic)

    def test_bip39_wallet_shield_unshield(self):
        """BIP39 wallet can be shielded and unshielded."""
        passphrase = "bip39_pass"
        shield_password = "shield_pass"

        w = Wallet.initialize(bip39_passphrase=passphrase)
        mnemonic = w.getSeedPhrase()
        addr_before = w.getSlatepackAddress()
        seed_before = w.master_seed

        # Shield
        w.shieldWallet(shield_password)
        self.assertIsNone(w.master_seed)

        # Unshield
        w.unshieldWallet(shield_password, salt=w.salt, nonce=w.nonce)
        self.assertEqual(w.master_seed, seed_before)

        # Address should match
        addr_after = w.getSlatepackAddress()
        self.assertEqual(addr_before, addr_after)

    def test_bip39_wallet_encrypted_seed(self):
        """BIP39 wallet encrypted seed has correct size for 64-byte master seed."""
        w = Wallet.initialize(bip39_passphrase="test")
        w.shieldWallet("password")

        encrypted = w.getEncryptedSeed()
        # 64 bytes ciphertext + 16 bytes tag = 80 bytes = 160 hex chars
        self.assertEqual(len(bytes.fromhex(encrypted["encrypted_seed"])), 80)

    def test_bip39_wallet_unshield_uses_stored_salt_nonce(self):
        """Unshield should work without explicitly passing salt/nonce again."""
        w = Wallet.initialize(bip39_passphrase="test")
        addr_before = w.getSlatepackAddress()

        w.shieldWallet("password")
        self.assertIsNotNone(w.salt)
        self.assertIsNotNone(w.nonce)

        # Should use self.salt/self.nonce internally.
        w.unshieldWallet("password")

        self.assertEqual(addr_before, w.getSlatepackAddress())


class TestBIP39PlausibleDeniability(unittest.TestCase):
    """Test plausible deniability use case of BIP39 passphrase."""

    def test_plausible_deniability_scenario(self):
        """Demonstrates the plausible deniability feature.

        A user can have one mnemonic that produces different wallets
        depending on the passphrase used. Under duress, they can reveal
        the mnemonic + a decoy passphrase (or no passphrase), which
        opens a wallet with minimal funds, while the real wallet with
        the actual passphrase remains hidden.
        """
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

        # "Decoy" wallet: no passphrase
        w_decoy = Wallet.fromSeedPhrase(mnemonic, bip39_passphrase="")
        # "Real" wallet: with secret passphrase
        w_real = Wallet.fromSeedPhrase(
            mnemonic, bip39_passphrase="real_secret_passphrase"
        )

        addr_decoy = w_decoy.getSlatepackAddress()
        addr_real = w_real.getSlatepackAddress()

        # They are completely different wallets
        self.assertNotEqual(addr_decoy, addr_real)

        # Both are valid, functional wallets
        self.assertTrue(addr_decoy.startswith("grin"))
        self.assertTrue(addr_real.startswith("grin"))

        # Restoring with the correct passphrase gives back the same wallet
        w_restored = Wallet.fromSeedPhrase(
            mnemonic, bip39_passphrase="real_secret_passphrase"
        )
        self.assertEqual(w_restored.getSlatepackAddress(), addr_real)


if __name__ == "__main__":
    unittest.main()
