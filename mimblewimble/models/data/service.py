from mimblewimble.models.data import SQLService

from mimblewimble.models.data.models import AccountsModel
from mimblewimble.models.data.models import MetadataModel
from mimblewimble.models.data.models import OutputsModel
from mimblewimble.models.data.models import SlateContextModel
from mimblewimble.models.data.models import SlateModel
from mimblewimble.models.data.models import TransactionsModel
from mimblewimble.models.data.models import VersionModel


def SQLWalletService(SQLService):
    def getNextChildPath(self):
        pass

    def getCurrentAddressIndex(self):
        pass

    def increaseAddressIndex(self):
        pass

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
