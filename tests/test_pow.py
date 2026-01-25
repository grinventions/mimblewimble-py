import pytest

from mimblewimble.pow.algos.cuckaroom import cuckaroom_validate
from mimblewimble.pow.algos.cuckarooz import cuckarooz_validate
from mimblewimble.pow.algos.cuckatoo import cuckatoo_validate
from mimblewimble.pow.prepow import serialize_pre_pow

from tests.fixtures import block_42_header, block_600000_header, block_3685850_header

from hashlib import blake2b

@pytest.mark.skip(reason='Cuckaroom needs to be debugged further')
def test_cuckaroom_verification():
    edge_bits = block_42_header['edge_bits']
    solution = block_42_header['cuckoo_solution']
    pre_pow = serialize_pre_pow(block_42_header)
    keybuf = blake2b(pre_pow, digest_size=32).digest()
    valid, msg = cuckaroom_validate(solution, keybuf)
    assert valid
    assert msg == 'POW_OK'

@pytest.mark.skip(reason='Cuckarooz needs to be debugged further')
def test_cuckarooz_verification():
    edge_bits = block_600000_header['edge_bits']
    solution = block_600000_header['cuckoo_solution']
    pre_pow = serialize_pre_pow(block_600000_header)
    keybuf = blake2b(pre_pow, digest_size=32).digest()
    valid, msg = cuckarooz_validate(solution, keybuf)
    assert valid
    assert msg == 'POW_OK'

def test_cuckatoo_verification():
    edge_bits = block_3685850_header['edge_bits']
    solution = block_3685850_header['cuckoo_solution']
    pre_pow = serialize_pre_pow(block_3685850_header)
    keybuf = blake2b(pre_pow, digest_size=32).digest()
    valid, msg = cuckatoo_validate(solution, keybuf, edge_bits)
    assert valid
    assert msg == 'POW_OK'