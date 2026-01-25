from typing import Dict, Optional

from abc import ABC, abstractmethod
from mimblewimble.blockchain import BlockHeader


class IBlockDB(ABC):
    """Interface that DifficultyCalculator / DifficultyLoader expects"""

    @abstractmethod
    def get_block_header(self, block_hash: str) -> Optional[BlockHeader]:
        """Return header by its hash or None if not found"""
        pass

    # Optional: useful for testing / debugging
    @abstractmethod
    def get_header_by_height(self, height: int) -> Optional[BlockHeader]:
        """Optional – not required by difficulty logic, but helpful"""
        pass

class InMemoryBlockDB(IBlockDB):
    """
    Simple in-memory block database for unit tests
    Stores headers by hash + optional height index
    """

    def __init__(self):
        # hash → BlockHeader
        self.by_hash: Dict[str, BlockHeader] = {}
        # height → hash (for optional height lookups)
        self.by_height: Dict[int, str] = {}

    def add_header(self, header: BlockHeader):
        """Add or overwrite a header"""
        self.by_hash[header.getHash().hex()] = header
        print('height', header.getHeight())
        self.by_height[header.getHeight()] = header.getHash().hex()

    def get_block_header(self, block_hash: str) -> Optional[BlockHeader]:
        return self.by_hash.get(block_hash)

    def get_header_by_height(self, height: int) -> Optional[BlockHeader]:
        h = self.by_height.get(height)
        if h is None:
            return None
        return self.by_hash.get(h)

    def clear(self):
        """Reset database – useful between tests"""
        self.by_hash.clear()
        self.by_height.clear()

    def size(self) -> int:
        return len(self.by_hash)