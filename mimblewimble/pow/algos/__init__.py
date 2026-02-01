from typing import List

from mimblewimble.pow.algos.cuckaroom import cuckaroom_validate
from mimblewimble.pow.algos.cuckarooz import cuckarooz_validate
from mimblewimble.pow.algos.cuckatoo import cuckatoo_validate


def pow_validate(
        header_version: int,
        edge_bits: int,
        proof_nonces: List[int],
        pre_pow_hash: bytes):
    if edge_bits == 29:
        if header_version == 1:
            raise ValueError('cuckaroo unsupported')
        if header_version == 2:
            raise ValueError('cuckarood unsupported')
        if header_version == 3:
            return cuckaroom_validate(proof_nonces, pre_pow_hash)
        return cuckarooz_validate(proof_nonces, pre_pow_hash)
    else:
        return cuckatoo_validate(proof_nonces, pre_pow_hash)
