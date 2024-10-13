from mimblewimble.slatebuilder.slate import OptionalFieldStatus


def test_optional_field_status_0():
    field_status_byte = 0
    field_status = OptionalFieldStatus.fromByte(field_status_byte)
    assert field_status.include_num_parts == 0
    assert field_status.include_amt == 0
    assert field_status.include_fee == 0
    assert field_status.include_feat == 0
    assert field_status.include_ttl == 0
    as_byte = field_status.toByte()
    assert as_byte == field_status_byte


def test_optional_field_status_2():
    field_status_byte = 2
    field_status = OptionalFieldStatus.fromByte(field_status_byte)
    assert field_status.include_num_parts == 0
    assert field_status.include_amt == 1
    assert field_status.include_fee == 0
    assert field_status.include_feat == 0
    assert field_status.include_ttl == 0
    as_byte = field_status.toByte()
    assert as_byte == field_status_byte
