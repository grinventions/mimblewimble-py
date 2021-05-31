import operator


class BlindingFactor:
    def __init__(self, blindingFactorBytes):
        self.blindingFactorBytes = blidningFactorBytes # 32 bytes

    def serialize(self):
        return int(self.blindingFactorBytes)

    def deserialize(self, blindingFactorInt):
        self.blindingFactorBytes = blindingFactorInt.to_bytes(32, byteorder='big')

    def toJSON(self):
        return self.serialize()


class TransactionInput:
    def __init__(self):
        # TODO
        pass

    def __lt__(self, other):
         return self.hash() < other.hash()


class TransactionOutput:
    def __init__(self):
        # TODO
        pass

    def __lt__(self, other):
        return self.hash() < other.hash()


class TransactionBody:
    def __init__(self, inputs, outputs, kernels):
        self.inputs = inputs
        self.outputs = outputs
        self.kernels = kernels

    def calcFee(self):
        # TODO
        pass

    def getFeeShift(self):
        # TODO
        pass

    def getWeight(self):
        # TODO
        pass

    def serialize(self):
        # TODO
        pass

    def deserialize(self):
        # TODO
        pass

    def toJSON(self):
        return {
            'inputs': [_input.toJSON() for _input in self.inputs],
            'outputs': [_outputs.toJSON() for _output in self.outputs],
            'kernels': [_kernel.toJSON() for _kernel in self.kernels]
        }

    @classmethod
    def fromJSON(self, transactionBodyJSON):
        inputs = []
        for _input in transactionBodyJSON.get('inputs', []):
            transaction_input = TransactionInput()
            transaction_input.fromJSON(_input)
            self.inputs.append(transaction_input)
        self.inputs.sort()

        outputs = []
        for _output in transactionBodyJSON.get('outputs', []):
            transaction_output = TransactionOutput()
            transaction_output.fromJSON(_output)
            self.outputs.append(transaction_output)
         self.outputs.sort()

        kernels = []
        for _kernel in transactionBodyJSON.get('kernels', []):
            transaction_kernel = TransactionKernel()
            transaction_kernel.fromJSON(_kernel)
            self.kernels.append(transaction_kernel)
         self.kernels.sort()

         return TransactionBody(inputs, outputs, kernels)

class Transaction:
    def __init__(self, offset, body: TransactionBody):
        self.offset = offset # 32 bytes
        self.body = body # arbitrary size bytes

    def serialize(self):
        return self.offset + self.body

    def deserialize(self, byteString: bytes):
        # Read BlindingFactor/Offset (32 bytes)
        self.offset = byteString[0: 32]
        # Read Transaction Body (variable size)
        self.body = byteString[32:]

    def toJSON(self):
        return {
            'offset': self.offset.toJSON(),
            'body': self.body.toJSON()
        }


class TransactionPrivate:
    def __init__(self, amount, excess, recipient_address, recipient_signature, sender_address, sender_signature, slate_id):
        self.amount = amount # 8 bytes
        self.excess = excess # 33 bytes
        self.recipient_address = recipient_address # 32 bytes
        self.recipient_signature = recipient_signature # 64 bytes
        self.sender_address = sender_address # 32 bytes
        self.sender_signature = sender_signature # 64 bytes
        self.slate_id = slate_id
