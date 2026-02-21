from mimblewimble.serializer import Serializer


# https://github.com/GrinPlusPlus/GrinPlusPlus/blob/fa3705f5558f0372410aa4222f5f1d97a0ab2247/include/Wallet/Models/Slate/SlatePaymentProof.h#L8
# TODO define types:
#  ed25519_public_key_t for the addresses
#  ed25519_signature_t for the signature
class SlatePaymentProof:
    def __init__(self, sender_address, receiver_address, receiver_signature=None):
        self.sender_address = sender_address
        self.receiver_address = receiver_address
        self.receiver_signature = receiver_signature

    def getSenderAddress(self):
        return self.sender_address

    def getReceiverAddress(self):
        return self.receiver_address

    def getReceiverSignature(self):
        return self.receiver_signature

    def setSenderAddress(self, sender_address):
        self.sender_address = sender_address

    def setReceiverAddress(self, receiver_address):
        self.receiver_address = receiver_address

    def setReceiverSignature(self, receiver_signature):
        self.receiver_signature = receiver_signature

    def serialize(self, serializer: Serializer):
        serializer.write(self.sender_address)
        serializer.write(self.receiver_address)
        has_sig = 0
        if self.receiver_signature is not None:
            has_sig = 1
        serializer.write(has_sig.to_bytes(1, "big"))
        if has_sig > 0:
            serializer.write(self.receiver_signature)

    @classmethod
    def deserialize(self, serializer: Serializer):
        ed25519_sender = serializer.read(32)
        ed25519_receiver = serializer.read(32)
        ed25519_signature = None
        has_sig = int.from_bytes(serializer.read(1), "big")
        if has_sig > 0:
            ed25519_signature = serializer.read(64)
        return SlatePaymentProof(
            ed25519_sender, ed25519_receiver, receiver_signature=ed25519_signature
        )

    def toJSON(self):
        obj = {}
        if self.sender_address is not None:
            obj["saddr"] = self.sender_address.hex()
        if self.receiver_address is not None:
            obj["raddr"] = self.receiver_address.hex()
        if self.receiver_signature is not None:
            obj["rsig"] = self.receiver_signature.hex()
        return obj

    @classmethod
    def fromJSON(self):
        raise Exception("unimplemented")
