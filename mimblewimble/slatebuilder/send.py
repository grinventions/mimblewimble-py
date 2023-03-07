
class SendSlateBuilder:
    def __init__(
            self,
            master_seed: bytes):
        self.master_seed = master_seed

    def build(
            self,
            amount: int,
            feeBase: int,
            changeOutputs: int,
            sendEntireBalance: bool,
            recipients: List[str],
            slateVersion=0, strategy=0, addressOpt={}):
        numChangeOutputs = 0
        if not sendEntireBalance:
            numChangeOutputs = changeOutputs

        totalNumOutputs = 1 + numChangeOutputs
        numKernels = 1

        
        pass

    def buildWalletTx(
            self,
            tx_offset: BlindingFactor,
            inputs: List[Nugget],
            change_outputs: List[Nugget],
            slate: Slate,
            address=None,
            proof=None):
        # TODO
        pass
