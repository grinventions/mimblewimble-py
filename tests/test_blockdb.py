from mimblewimble.pow.blockdb import InMemoryBlockDB
from mimblewimble.genesis import mainnet


def test_in_memory_blockdb():
    blockdb = InMemoryBlockDB()

    assert blockdb.get_block_header("nonexistent_hash") is None

    assert blockdb.get_header_by_height(0) is None
    assert blockdb.size() == 0

    blockdb.add_header(mainnet.getHeader())

    assert blockdb.get_header_by_height(0).getHash().hex() == mainnet.getHash().hex()
    assert blockdb.get_block_header(mainnet.getHash().hex()) is not None
