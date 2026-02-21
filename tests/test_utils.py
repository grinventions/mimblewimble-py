from mimblewimble.slatebuilder.slate import SettableByte


def test_settable_bytes():
    #        76543210
    # 0xb5 = 10110101 = 181
    b = SettableByte(0xB5)
    assert b.get_bit(0) == 1
    assert b.get_bit(1) == 0
    assert b.get_bit(2) == 1
    assert b.get_bit(3) == 0
    assert b.get_bit(4) == 1
    assert b.get_bit(5) == 1
    assert b.get_bit(6) == 0
    assert b.get_bit(7) == 1
    assert b.get_value() == 181

    #        76543210
    # 0xff = 11111111 = 255
    b.set_bit(1, 1)
    b.set_bit(3, 1)
    b.set_bit(6, 1)
    assert b.get_value() == 255

    #        76543210
    # 0x4a = 01001010 = 74
    b.set_bit(0, 0)
    b.set_bit(2, 0)
    b.set_bit(4, 0)
    b.set_bit(5, 0)
    b.set_bit(7, 0)
    assert b.get_value() == 74
