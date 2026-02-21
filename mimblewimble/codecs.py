import base58
import base64


class Codec:
    @classmethod
    def encode(self, data: bytes, encoding="utf-8") -> str:
        raise Exception("unimplemented")

    @classmethod
    def decode(self, data: str) -> bytes:
        raise Exception("unimplemented")


class HexCodec(Codec):
    @classmethod
    def encode(self, data: bytes, encoding="utf-8") -> str:
        return data.hex()

    @classmethod
    def decode(self, data: str) -> bytes:
        return bytes.fromhex(data)


class Base58Codec(Codec):
    @classmethod
    def encode(self, data: bytes, encoding="utf-8") -> str:
        return base58.b58encode(data).decode(encoding)

    @classmethod
    def decode(self, data: str) -> bytes:
        return base58.b58decode(data)


class Base64Codec(Codec):
    @classmethod
    def encode(self, data: bytes, encoding="utf-8") -> str:
        return base64.b64encode(data).decode(encoding)

    @classmethod
    def decode(self, data: str) -> bytes:
        return base64.b64decode(data)
