from abc import ABC, abstractmethod
from typing import Awaitable
from dataclasses import dataclass

from mimblewimble.genesis import floonet, mainnet

@dataclass
class GrinChainTip:
    height: int
    hash: bytes             # 32 bytes

class GrinNodeStorage(ABC):
    @abstractmethod
    async def get_tip(self) -> GrinChainTip:
        pass

class InMemoryGrinNodeStorage(GrinNodeStorage):
    def __init__(self, testnet: bool = False) -> None:
        if testnet:
            genesis_blockheader = floonet.getHeader()
        else:
            genesis_blockheader = mainnet.getHeader()
        self._tip = GrinChainTip(height=0, hash=genesis_blockheader.getHash())

    async def get_tip(self) -> GrinChainTip:
        return self._tip

class GrinNode(ABC):
    def __init__(self, storage: GrinNodeStorage, testnet: bool = False) -> None:
        self.storage = storage
        self.testnet = testnet

    async def get_tip(self) -> GrinChainTip:
        return await self.storage.get_tip()

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    async def close(self) -> None:
        await self.stop()