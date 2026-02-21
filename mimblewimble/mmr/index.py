from mimblewimble.helpers import fillOnesToRight


class MMRIndex:
    def __init__(self, position: int, height: int):
        self.position = position
        self.height = height

    def isLeaf(self):
        return self.height == 0

    @classmethod
    def at(self, position: int):
        return MMRIndex(position, self.calculateHeight(position))

    # operators
    def __eq__(self, other):
        return self.position == other.position and self.height == other.height

    def __ne__(self, other):
        return self.position != other.position or self.height != other.height

    def __lt__(self, other):
        return self.position < other.position

    def __leq__(self, other):
        return self.position <= other.position

    def __gt__(self, other):
        return self.position > other.position

    def __geq__(self, other):
        return self.position >= other.position

    def getLeafIndex(self):
        assert self.isLeaf()
        return self.calculateLeafIndex(self.position)

    def getParent(self):
        if self.calculateHeight(self.position + 1) == self.height + 1:
            return MMRIndex(self.position + 1, self.height + 1)
        else:
            return MMRIndex(self.position + (1 << (self.height + 1)), self.height + 1)

    def getSibling(self):
        if self.calculateHeight(self.position + 1) == self.height + 1:
            return MMRIndex(self.position + 1 - (1 << (self.height + 1)), self.height)
        else:
            return MMRIndex(
                self.position + (1 << (self.height + 1)) - 1, self.height + 1
            )

    def getLeftChild(self):
        assert self.height > 0
        return MMRIndex(self.position - (1 << height), self.height - 1)

    def getRightChild(self):
        assert self.height > 0
        return MMRIndex(self.position - 1, self.height - 1)

    @classmethod
    def calculateHeight(self, position: int):
        height = position
        peakSize = fillOnesToRight(position + 1)
        while peakSize != 0:
            if height >= peakSize:
                height -= peakSize
            peakSize >>= 1
        return height

    def calculateLeafIndex(self, position: int):
        leafIndex = 0
        peakSize = fillOnesToRight(position)
        numLeft = position
        while peakSize != 0:
            if numLeft >= peakSize:
                leafIndex += (peakSize + 1) / 2
                numLeft -= peakSize
            peakSize >>= 1
        return leafIndex
