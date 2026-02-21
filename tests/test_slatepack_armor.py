from mimblewimble.models.slatepack.message import slatepack_pack
from mimblewimble.models.slatepack.message import slatepack_unpack
from mimblewimble.models.slatepack.message import slatepack_spacing

# example from the grin wiki
# https://docs.grin.mw/wiki/transactions/slatepack/
example = """
BEGINSLATEPACK. 4H1qx1wHe668tFW yC2gfL8PPd8kSgv
pcXQhyRkHbyKHZg GN75o7uWoT3dkib R2tj1fFGN2FoRLY
GWmtgsneoXf7N4D uVWuyZSamPhfF1u AHRaYWvhF7jQvKx
wNJAc7qmVm9JVcm NJLEw4k5BU7jY6S eb.
ENDSLATEPACK.
"""[1:]

example_raw = bytes.fromhex(
    "".join(
        [
            "4d047e46000400034bea",
            "91b819b84f0081f925b6",
            "edd81537010600000000",
            "4fb1004000000000007a",
            "120001000225418cd179",
            "18870cc7be5b629cd7e5",
            "3188e08dfb6b043cf112",
            "14af1e77b2ee730391b7",
            "9272fca73ed341e0c033",
            "935799b4493d3273064a",
            "4c2d6fa9c1c4050271cc",
            "00",
        ]
    )
)

# my own example
raw = bytes.fromhex(
    "".join(
        [
            "0f28c78a7c2e6b9c1fe3",
            "7abfbf1baf8a161cb2cd",
            "95670e3091aaef9c9d5f",
            "dc2fa11338c352284cf6",
            "157fa05b2da153b581ab",
            "5076605d783add8d9e2d",
            "0dfb07d323f85f50a121",
            "05fe69e78edc338fcfa1",
            "d45e99054b31ac385a57",
            "94a934ea0bc977b7f949",
            "49180ec8f1dc10b6b177",
            "720ced24621dae7e5ab4",
            "5ef7413761cb4211",
        ]
    )
)

encoded_slatepack = """
BEGINSLATEPACK. 2YyRpvomiRisAo6 uhtewqXgRsk3Cdk
rBduskjuuXSur5V gJTb911QXf9WdMe P5Rz4J3r15U6tmb
jFdV36xjimQDzmq M3C3DrRGUyNJu7x nDJTv8swDVnEgwN
QS4bcbA9DPmoJCE S6zfBNWkDoKzu9P z1ZaReA84i6173X
k6DZ6kiLhW. ENDSLATEPACK.
"""[1:]


def test_slatepack_armor_official():
    decoded = slatepack_unpack(example)
    assert decoded == example_raw

    packed = slatepack_pack(decoded, words_per_line=3)
    assert packed == example


def test_slatepack_armor():
    packed = slatepack_pack(raw, words_per_line=3)
    assert packed == encoded_slatepack

    decoded = slatepack_unpack(packed)
    assert decoded == raw
