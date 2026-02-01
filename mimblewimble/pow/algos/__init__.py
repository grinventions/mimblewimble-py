from typing import List

from mimblewimble.pow.algos.cuckaroo import cuckaroo_validate
from mimblewimble.pow.algos.cuckarood import cuckarood_validate
from mimblewimble.pow.algos.cuckaroom import cuckaroom_validate
from mimblewimble.pow.algos.cuckarooz import cuckarooz_validate
from mimblewimble.pow.algos.cuckatoo import cuckatoo_validate
from mimblewimble.pow.prepow import serialize_pre_pow

from hashlib import blake2b

def pow_validate(header: dict):
    edge_bits = header['edge_bits']
    solution = header['cuckoo_solution']
    header_version = header['version']
    pre_pow = serialize_pre_pow(header)
    keybuf = blake2b(pre_pow, digest_size=32).digest()
    if edge_bits == 29:
        if header_version == 1:
            return cuckaroo_validate(solution, keybuf, edge_bits)
        if header_version == 2:
            return cuckarood_validate(solution, keybuf)
        if header_version == 3:
            return cuckaroom_validate(solution, keybuf)
        return cuckarooz_validate(solution, keybuf)
    else:
        return cuckatoo_validate(solution, keybuf, edge_bits)
