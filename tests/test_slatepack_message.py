from mimblewimble.models.slatepack.address import SlatepackAddress
from mimblewimble.models.slatepack.metadata import SlatepackVersion
from mimblewimble.models.slatepack.metadata import SlatepackMetadata
from mimblewimble.models.slatepack.message import SlatepackMessage, EMode

sender = "grin1m3ckuft0llw97ulzmedk557twyn76wkgxartn6lpfq5xd9wcc24qnpwde5"

recipients = [
    "grin1at3z7s2fa796zcqurhyjyklhpfx0rgn9czynshv9rq0yq674wkdq5qdy6w",
    "grin18r9pen0fjemhss2tf92dkmm8puaflw22vlretwmukq7tefdqgaeqyve0qy",
    "grin1qaq69t9pugrh9h2vamc9qhc09vplaa2zy2ukzwcd08236j5qgzwsmasmf5",
]

payload_hex = "7513a0cafc4a87ecef0144c3ca93f9f5a2e4a3cdc143993029525c060ae80904"


def test_slatepack_message():
    version = SlatepackVersion(0, 0)
    metadata = SlatepackMetadata(
        sender=SlatepackAddress.fromBech32(sender),
        recipients=[SlatepackAddress.fromBech32(recipient) for recipient in recipients],
    )
    emode = EMode.ENCRYPTED
    payload = bytes.fromhex(payload_hex)
    slatepack_message = SlatepackMessage(version, metadata, emode, payload)

    assert slatepack_message.is_encrypted()
    assert slatepack_message.toJSON() == {
        "slatepack": [0, 0],
        "mode": 1,
        "payload": "dROgyvxKh+zvAUTDypP59aLko83BQ5kwKVJcBgroCQQ=",
    }
