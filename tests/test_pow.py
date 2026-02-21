import pytest

from mimblewimble.pow.algos.cuckaroo import cuckaroo_validate
from mimblewimble.pow.algos.cuckarood import cuckarood_validate
from mimblewimble.pow.algos.cuckaroom import cuckaroom_validate
from mimblewimble.pow.algos.cuckarooz import cuckarooz_validate
from mimblewimble.pow.algos.cuckatoo import cuckatoo_validate
from mimblewimble.pow.prepow import serialize_pre_pow
from mimblewimble.pow.common import EPoWStatus
from mimblewimble.pow.algos import pow_validate

from tests.fixtures import block_42_header

# cuckaroo
from tests.fixtures import block_174001_header as cuckaroo_header

# cuckarood
from tests.fixtures import block_275001_header as cuckarood_header

# cuckaroom
from tests.fixtures import block_600000_header as cuckaroom_header

# cuckarooz
from tests.fixtures import block_800015_header as cuckarooz_header

# cuckatoo
from tests.fixtures import block_604850_header as cuckatoo_header

from hashlib import blake2b


def test_cuckaroo_verification():
    edge_bits = cuckaroo_header["edge_bits"]
    solution = cuckaroo_header["cuckoo_solution"]
    pre_pow = serialize_pre_pow(cuckaroo_header)
    keybuf = blake2b(pre_pow, digest_size=32).digest()
    valid, msg = cuckaroo_validate(solution, keybuf, edge_bits)
    assert valid
    assert msg == EPoWStatus.POW_OK


def test_cuckarood_verification():
    solution = cuckarood_header["cuckoo_solution"]
    pre_pow = serialize_pre_pow(cuckarood_header)
    keybuf = blake2b(pre_pow, digest_size=32).digest()
    valid, msg = cuckarood_validate(solution, keybuf)
    assert valid
    assert msg == EPoWStatus.POW_OK


def test_cuckaroom_verification():
    solution = cuckaroom_header["cuckoo_solution"]
    pre_pow = serialize_pre_pow(cuckaroom_header)
    keybuf = blake2b(pre_pow, digest_size=32).digest()
    valid, msg = cuckaroom_validate(solution, keybuf)
    assert valid
    assert msg == EPoWStatus.POW_OK


def test_cuckarooz_verification():
    solution = cuckarooz_header["cuckoo_solution"]
    pre_pow = serialize_pre_pow(cuckarooz_header)
    keybuf = blake2b(pre_pow, digest_size=32).digest()
    valid, msg = cuckarooz_validate(solution, keybuf)
    assert valid
    assert msg == EPoWStatus.POW_OK


def test_cuckatoo_verification():
    edge_bits = cuckatoo_header["edge_bits"]
    solution = cuckatoo_header["cuckoo_solution"]
    pre_pow = serialize_pre_pow(cuckatoo_header)
    keybuf = blake2b(pre_pow, digest_size=32).digest()
    valid, msg = cuckatoo_validate(solution, keybuf, edge_bits)
    assert valid
    assert msg == EPoWStatus.POW_OK


def test_pow_algo_auto():
    assert pow_validate(cuckaroo_header) == (True, EPoWStatus.POW_OK)
    assert pow_validate(cuckarood_header) == (True, EPoWStatus.POW_OK)
    assert pow_validate(cuckaroom_header) == (True, EPoWStatus.POW_OK)
    assert pow_validate(cuckarooz_header) == (True, EPoWStatus.POW_OK)
    assert pow_validate(cuckatoo_header) == (True, EPoWStatus.POW_OK)
