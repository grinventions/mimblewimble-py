

class ChildNumber:
    def __init__(self, is_normal: bool, index: int):
        self.is_normal = is_normal
        self.index = index


    def isNormal(self):
        return self.is_normal


    def isHardened(self):
        return not self.is_normal


    @classmethod
    def from_normal_idx(self, index):
        assert 0 <= index <= 2**31
        return ChildNumber(True, index)


    @classmethod
    def from_hardened_idx(self, index):
        assert 0 <= index <= 2**31
        return ChildNumber(False, index)
