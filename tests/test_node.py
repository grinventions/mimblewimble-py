import pytest

from mimblewimble.genesis import floonet, mainnet
from mimblewimble.node import GrinChainTip, GrinNode, InMemoryGrinNodeStorage


@pytest.mark.asyncio
async def test_memory_node_returns_genesis_tip():
    testnet = False
    storage = InMemoryGrinNodeStorage(testnet=testnet)
    node = GrinNode(
        storage,
        testnet=testnet)

    tip = await node.get_tip()

    assert isinstance(tip, GrinChainTip)
    assert tip.height == 0
    assert len(tip.hash) == 32
    assert tip.hash == mainnet.getHeader().getHash()
