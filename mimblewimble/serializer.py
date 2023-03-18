from io import BytesIO
from enum import Enum

class EProtocolVersion(Enum):
    V1 = 1
    V2 = 2
    V3 = 3
    V1000 = 1000

class Serializer:
    def __init__(self, protocol=EProtocolVersion.V1):
        self.pnt = 0
        self.protocol = protocol
        self.raw = BytesIO()

    def resetPointer():
        self.pnt = 0

    def read(self, n):
        self.raw.seek(self.pnt)
        self.pnt += n
        return self.raw.read(n)

    def write(self, b: bytes):
        self.raw.write(b)

    def getvalue(self):
        return self.raw.getvalue()

    def getProtocol(self):
        return self.protocol

    def readall(self):
        self.raw.seek(0)
        value = self.raw.read()
        self.raw.seek(self.pnt)
        return value
