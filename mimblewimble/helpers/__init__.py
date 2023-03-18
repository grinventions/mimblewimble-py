def fillOnesToRight(input: int):
    x = input
    x = x | (x >> 1)
    x = x | (x >> 2)
    x = x | (x >> 4)
    x = x | (x >> 8)
    x = x | (x >> 16)
    x = x | (x >> 32)
    return x
