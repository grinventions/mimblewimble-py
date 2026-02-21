from typing import List

from mimblewimble.entity import OutputDataEntity

from mimblewimble.models.transaction import BlindingFactor

from mimblewimble.crypto.aggsig import AggSig
from mimblewimble.crypto.pedersen import Pedersen
from mimblewimble.crypto.public_keys import PublicKeys


def calculateSigningKeys(
    inputs: List[OutputDataEntity],
    outputs: List[OutputDataEntity],
    tx_offset: BlindingFactor,
):
    # cryptography utilities
    p = Pedersen()
    pks = PublicKeys()
    agg = AggSig()

    # calculate sum inputs blinding factors xI.
    input_bf_sum = p.blindSum([inp.getBlindingFactor() for inp in inputs], [])

    # calculate sum change outputs blinding factors xC.
    output_bf_sum = p.blindSum([out.getBlindingFactor() for out in outputs], [])

    # calculate total blinding excess sum for all inputs and outputs xS1 = xC - xI
    total_blind_excess = p.blindSum([output_bf_sum], [input_bf_sum])

    # subtract random kernel offset oS from xS1. Calculate xS = xS1 - oS
    secret_key = p.blindSum([total_blind_excess], [tx_offset]).toSecretKey()
    public_key = pks.calculatePublicKey(secret_key)

    # select a random nonce kS
    secret_nonce = agg.generateSecureNonce()
    public_nonce = pks.calculatePublicKey(secret_nonce)

    # clean-up
    del p
    del pks
    del agg

    # done!
    return secret_key, public_key, secret_nonce, public_nonce
