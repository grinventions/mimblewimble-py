class WalletBalance:
    def __init__(self, locked, awaiting_confirmation, spendable):
        self.locked = locked
        self.awaiting_confirmation = awaiting_confirmation
        self.spendable = spendable
        self.total = awaiting_confirmation + spendable

    def toJSON(self):
        return {
            "locked": self.locked,
            "awaiting_confirmation": self.awaiting_confirmation,
            "spendable": self.spendable,
            "total": self.total,
        }
