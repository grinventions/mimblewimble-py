# https://github.com/GrinPlusPlus/GrinPlusPlus/blob/fa3705f5558f0372410aa4222f5f1d97a0ab2247/include/Wallet/Models/Slate/SlatePaymentProof.h#L8
# TODO define types:
#  ed25519_public_key_t for the addresses
#  ed25519_signature_t for the signature
class SlatePaymentProof:
    def __init__(self, sender_address, receiver_address):
        self.sender_address = sender_address
        self.receiver_address = receiver_address
        self.receiver_signature = None

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

    def serialize(self):
        raise Exception('unimplemented')

    @classmethod
    def deserialize(self):
        raise Exception('unimplemented')

    def toJSON(self):
        saddr = None
        if self.sender_address is not None:
            saddr = self.sender_address.hex()
        raddr = None
        if self.receiver_address is not None:
            raddr = self.receiver_address.hex()
        rsig = None
        if self.receiver_signature is not None:
            rsig = self.receiver_signature.hex()
        return {
            'saddr': saddr,
            'raddr': raddr,
            'rsig': rsig
        }

    @classmethod
    def fromJSON(self):
        raise Exception('unimplemented')
