from mimblewimble.models.data import SQLService

from mimblewimble.models.data.models import AccountsModel
from mimblewimble.models.data.models import MetadataModel
from mimblewimble.models.data.models import OutputsModel
from mimblewimble.models.data.models import SlateContextModel
from mimblewimble.models.data.models import SlateModel
from mimblewimble.models.data.models import TransactionsModel
from mimblewimble.models.data.models import VersionModel


def SQLWalletService(SQLService):
    def getNextChildPath(self, parent_path: str):
        q = self.session.query(AccountsModel).filter_by(
            parent_path=parent_path)
        return self.select(q, only_first=True)

    def updateNextChildIndex(self, parent_path: str, index: int):
        account_record = self.getNextChildPath(parent_path)
        account_record.next_child_index = index
        self.update(account_record)

    def getCurrentAddressIndex(self, parent_path: str):
        account_record = self.getNextChildPath(parent_path)
        return account_record.current_address_index

    def updateCurrentAddressIndex(self, parent_path: str, index: int):
        account_record = self.getNextChildPath(parent_path)
        account_record.current_address_index = index
        self.update(account_record)

    def increaseAddressIndex(self, parent_path: str):
        current_index = self.getCurrentAddressIndex(parent_path)
        next_index = current_index + 1
        updateCurrentAddressIndex(parent_path, next_index)
        return next_index

    def addOutputs(self):
        pass

    def getOutputs(self):
        pass

    def getRefreshBlockHeight(self):
        pass

    def updateRefreshBlockHeight(self):
        pass

    def getRestoreLeafIndex(self):
        pass

    def updateRestoreLeafIndex(self):
        pass

    def loadSlate(self):
        pass

    def loadLatestSlate(self):
        pass

    def loadArmoredSlatepack(self):
        pass

    def saveSlate(self):
        pass

    def loadSlateContext(self):
        pass

    def saveSlateContext(self):
        pass

    def addTransaction(self):
        pass

    def getTransactions(self):
        pass

    def getTransactionByID(self):
        pass

    def getNextTransactionID(self):
        pass

    def getMetadata(self):
        pass

    def saveMetadata(self):
        pass
