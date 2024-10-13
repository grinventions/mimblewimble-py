from typing import List

from mimblewimble.serializer import Serializer

AGE_INTRO = b'age-encryption.org/v1'
AGE_RECIPIENT_PREFIX = b'->'
AGE_FOOTER_PREFIX = b'---'
AGE_AEAD = b'ChaChaPoly'


class AgeRecipientBody:
    def __init__(self, body: bytes):
        self.body = body

    def serialize(self, serializer: Serializer):
        serializer.write(self.body + b'\n')

    @classmethod
    def deserialize(self, serializer: Serializer):
        pnt = serializer.pnt
        line = serializer.readline(clean_newline=True)

        is_recipient = line.startswith(
                AGE_RECIPIENT_PREFIX)
        is_footer = line.startswith(
                AGE_FOOTER_PREFIX)

        if is_recipient or is_footer or line == b'':
            serializer.resetPointer(n=pnt)
            return None

        return AgeRecipientBody(line)


class AgeRecipient:
    def __init__(self, _type, args=[], body=[]):
        self._type = _type
        self.args = args
        self.body = body

    def append_body(self, body: AgeRecipientBody):
        self.body.append(body)

    def serialize(self, serializer: Serializer):
        serializer.write(
            b'-> ' + self._type + b' ' + b' '.join(
                self.args) + b'\n')
        if len(self.body) > 0:
            for body in self.body:
                body.serialize(serializer)

    @classmethod
    def deserialize(self, serializer: Serializer):
        pnt = serializer.pnt
        line = serializer.readline(clean_newline=True)

        if not line.startswith(
                AGE_RECIPIENT_PREFIX):
            serializer.resetPointer(n=pnt)
            return None

        splitted = line.split()
        if len(splitted) < 2:
            serializer.resetPointer(n=pnt)
            return None

        _type, *args = splitted[1:]
        recipient = AgeRecipient(_type, args, body=[])

        body = AgeRecipientBody.deserialize(serializer)
        while body is not None:
            recipient.append_body(body)
            body = AgeRecipientBody.deserialize(
                serializer)

        return recipient


class AgeHeader:
    def __init__(self, recipients=[]):
        self.recipients = recipients

    def serialize(self, serializer: Serializer):
        for recipient in self.recipients:
            recipient.serialize(serializer)

    @classmethod
    def deserialize(self, serializer: Serializer):
        recipients = []

        recipient = AgeRecipient.deserialize(serializer)
        while recipient is not None:
            recipients.append(recipient)
            recipient = AgeRecipient.deserialize(
                serializer)

        return AgeHeader(recipients=recipients)


class AgeBody:
    def __init__(self, body: bytes):
        self.body = body

    def serialize(self, serializer: Serializer):
        serializer.write(
            b'\n' + AGE_FOOTER_PREFIX + b' ' + self.body)

    @classmethod
    def deserialize(self, serializer: Serializer):
        remaining = serializer.readremaining()
        splitted = remaining.split(AGE_FOOTER_PREFIX)
        if len(splitted) < 2:
            return None
        return AgeBody(splitted[1].strip())


class AgeMessage:
    def __init__(self, pre: bytes, header: AgeHeader, body: AgeBody):
        self.pre = pre
        self.header = header
        self.body = body

    def serialize(self, serializer: Serializer):
        serializer.write(self.pre + AGE_INTRO + b'\n')
        self.header.serialize(serializer)
        self.body.serialize(serializer)

    @classmethod
    def deserialize(self, serializer: Serializer):
        line = serializer.readline(clean_newline=True)
        if not line.find(AGE_INTRO):
            return None
        splitted = line.split(AGE_INTRO)
        if len(splitted) > 1:
            pre = splitted[0]
        else:
            pre = b''
        header = AgeHeader.deserialize(serializer)
        if header is None:
            return None
        body = AgeBody.deserialize(serializer)
        if body is None:
            return None
        return AgeMessage(pre, header, body)
