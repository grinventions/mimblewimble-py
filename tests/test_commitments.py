import pytest

from mimblewimble.crypto.commitment import Commitment
from mimblewimble.crypto.public_key import PublicKey
from mimblewimble.crypto.pedersen import Pedersen

# test adding blinded commitment with transparent one
@pytest.mark.skip(reason='TODO')
def test_adding_blinded_commitments_with_transparent():
    pass

# test adding 2 blinded commitment
@pytest.mark.skip(reason='TODO')
def test_adding_two_blinded_commitment():
    pass

# test adding negative blinded commitment
@pytest.mark.skip(reason='TODO')
def test_adding_negative_blinded_commitment():
    pass

# test public key to commitment
def test_public_key_to_commitment():
    p = Pedersen()
    public_key = PublicKey.fromHex(
        '02f434a6b929d0aa6ac757bbe387075066d51ee5308d5be91d2fb478a494d38bdf')

    commitment = p.toCommitment(public_key)
    commitment_bytes = commitment.getBytes()

    # commitment = Commitment.fromPublicKey(public_key)
    expected_commitment = Commitment.fromHex(
        '08f434a6b929d0aa6ac757bbe387075066d51ee5308d5be91d2fb478a494d38bdf')
    assert commitment == expected_commitment
