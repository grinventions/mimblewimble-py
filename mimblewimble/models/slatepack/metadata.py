from typing import List, Optional

from mimblewimble.serializer import Serializer

from mimblewimble.models.slatepack.address import SlatepackAddress


class SlatepackVersion:
    def __init__(self, major, minor):
        self.major = major
        self.minor = minor

    def serialize(self, serializer: Serializer):
        serializer.write(self.major.to_bytes(1, 'big'))
        serializer.write(self.minor.to_bytes(1, 'big'))

    @classmethod
    def deserialize(self, serializer: Serializer):
        major = int.from_bytes(serializer.read(1), 'big')
        minor = int.from_bytes(serializer.read(1), 'big')
        return SlatepackVersion(major, minor)

    def __str__(self):
        return '{0}:{1}'.format(str(self.major), str(self.minor))


# https://github.com/GrinPlusPlus/GrinPlusPlus/blob/master/include/Wallet/Models/Slatepack/SlatepackMessage.h#L52
# https://github.com/mimblewimble/grin-wallet/blob/75363a9a258bc1fb0cf60bfb4c88a8a653b122f2/libwallet/src/slatepack/types.rs#L503

class SlatepackMetadata:
    def __init__(
            self,
            sender: Optional[SlatepackAddress] = None,
            recipients: Optional[List[SlatepackAddress]] = []):
        self.sender = sender
        self.recipients = recipients

    def serialize(self, serializer: Serializer):
        inner_buffer = Serializer()

        opt_flags = 0x00
        if self.sender is not None:
            opt_flags |= 0x01
        if len(self.recipients) == 0:
            opt_flags |= 0x02
        inner_buffer.write(opt_flags.to_bytes(2, 'big'))

        if opt_flags & 0x01 == 0x01:
            self.sender.serialize(inner_buffer)

        num_recipients = len(self.recipients)
        if num_recipients > 0:
            inner_buffer.write(num_recipients.to_bytes(2, 'big'))
            for recipient in self.recipients:
                recipient.serialize(inner_buffer)

        inner_buffer_length = len(inner_buffer)
        serializer.write(inner_buffer_length.to_bytes(4, 'big'))
        serializer.write(inner_buffer.readall())

    @classmethod
    def deserialize(self, serializer: Serializer):
        size = int.from_bytes(serializer.read(4), 'big')

        inner_buffer = Serializer()
        inner_buffer.write(serializer.read(size))

        opt_flags = int.from_bytes(inner_buffer.read(2), 'big')
        sender = None
        if opt_flags & 0x01 == 0x01:
            sender = SlatepackAddress.deserialize(inner_buffer)

        recipients = []
        if opt_flags & 0x02 == 0x02:
            num_recipients = int.from_bytes(inner_buffer.read(2), 'big')
            for i in range(num_recipients):
                recipient = SlatepackAddress.deserialize(inner_buffer)
                recipients.append(recipient)

        return SlatepackMetadata(sender, recipients)

    def encrypt(self):
        pass

    def decrypt(self):
        pass
