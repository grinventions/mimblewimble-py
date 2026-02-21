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

    def resetPointer(self, n=None):
        if n is None:
            self.pnt = 0
        else:
            self.pnt = n

    def read(self, n):
        self.raw.seek(self.pnt)
        self.pnt += n
        return self.raw.read(n)

    def write(self, b: bytes):
        self.raw.write(b)

    def readline(self, clean_newline=False):
        self.raw.seek(self.pnt)
        line = self.raw.readline()
        self.pnt = self.raw.tell()
        if clean_newline:
            if line[-1] == ord("\n"):
                return line[0:-1]
        return line

    def readlines(self):
        lines = []
        line = self.readline()
        while line != b"":
            lines.append(line)
            line = self.readline()
        if line != b"":
            lines.append(line)
        return lines

    def readString(self, n, encoding="ascii"):
        as_bytes = self.read(n)
        return as_bytes.decode(encoding)

    def writeString(self, value: str, encoding="ascii"):
        as_bytes = value.encode(encoding)
        self.write(as_bytes)

    def getvalue(self):
        return self.raw.getvalue()

    def getProtocol(self):
        return self.protocol

    def readremaining(self):
        self.raw.seek(self.pnt)
        value = self.raw.read()
        self.pnt = self.raw.tell()
        return value

    def readall(self):
        self.raw.seek(0)
        value = self.raw.read()
        self.raw.seek(self.pnt)
        return value

    def getStream(self):
        return self.raw

    def __len__(self):
        return self.raw.getbuffer().nbytes
