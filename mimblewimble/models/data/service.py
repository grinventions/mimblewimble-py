from sqlalchemy import insert, update
from sqlalchemy.sql import bindparam
from sqlalchemy.exc import IntegrityError

from mimblewimble.models.data import SQLService

from mimblewimble.models.data.models import AccountsModel
from mimblewimble.models.data.models import MetadataModel
from mimblewimble.models.data.models import OutputsModel
from mimblewimble.models.data.models import SlateContextModel
from mimblewimble.models.data.models import SlateModel
from mimblewimble.models.data.models import TransactionsModel
from mimblewimble.models.data.models import VersionModel


class SQLWalletService(SQLService):
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

    def updateOutput(
            self, commitment, status, transaction_id, encrypted):
        try:
            stmt = update(OutputsModel).where(
                OutputsModel.commitment==commitment
            ).values(
                    status=status,
                transaction_id=transaction_id,
                encrypted=encrypted)
            self.session.execute(stmt)
            self.session.commit()
        except Exception as e:
            self.session.rollback()
            raise e

    def addOutputs(
            self, commitment, status, transaction_id, encrypted,
            auto_update=True):
        record = OutputsModel(
            commitment=commitment,
            status=status,
            transaction_id=transaction_id,
            encrypted=encrypted)
        try:
            self.insert(record)
        except IntegrityError as e:
            if 'UNIQUE constraint failed: outputs.commitment' in str(e):
                self.updateOutput(
                    commitment, status, transaction_id, encrypted)
            else:
                raise e
        except Exception as e:
            raise e

    def getOutputs(self):
        q = self.session.query(OutputsModel)
        return self.select(q)

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

    def saveSlateContext(self, master_seed, slate_id, slate_context):
        pass

    def addTransaction(self):
        pass

    def getTransactions(self):
        pass

    def getTransactionByID(self):
        pass

    def getNextTransactionID(self):
        pass

    def getMetadataRecord(self):
        q = self.session.query(MetadataModel).filter_by(
            id=1)
        record = self.select(q)
        if record is None:
            raise ValueError('No metadata found')
        return record

    def getMetadata(self):
        record = self.getMetadataRecord()
        next_tx_id = record.next_tx_id
        refresh_block_height = record.refresh_block_height
        restore_leaf_index = record.restore_leaf_index
        return next_tx_id, refresh_block_height, restore_leaf_index

    def saveMetadata(
            self, next_tx_id, refresh_block_height, restore_leaf_index):
        metadata_record = self.getMetadataRecord()
        metadata_record.next_tx_id = next_tx_id
        metadata_record.refresh_block_height = refresh_block_height
        metadata_record.restore_leaf_index = restore_leaf_index
        self.update(metadata_record)
