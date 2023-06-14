from sqlalchemy import Column, Integer, String, Binary
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class AccountsModel(Base):
    __tablename__ = 'accounts'

    parent_path = Column(String, primary_key=True)
    account_name = Column(String, nullable=False)
    next_child_index = Column(Integer, nullable=False)
    current_address_index = Column(Integer, nullable=False)

    def __init__(self):
        self.current_address_index = 0


class MetadataModel(Base):
    __tablename__ = 'metadata'

    id = Column(Integer, primary_key=True)
    next_tx_id = Column(Integer, nullable=False)
    refresh_block_height = Column(Integer, nullable=False)
    restore_leaf_index = Column(Integer, nullable=False)


class OutputsModel(Base):
    __tablename__ = 'outputs'
    id = Column(Integer, primary_key=True)
    commitment = Column(String, unique=True, nullable=False)
    status = Column(Integer, nullable=False)
    transaction_id = Column(Integer)
    encrypted = Column(Binary, nullable=False)


class SlateContextModel(Base):
    __tablename__ = 'slate_contexts'

    slate_id = Column(String, primary_key=True)
    iv = Column(Binary, nullable=False)
    enc_context = Column(Binary, nullable=False)


class SlateModel(Base):
    __tablename__ = 'slate'

    slate_id = Column(String, nullable=False)
    stage = Column(String, nullable=False)
    iv = Column(Binary, nullable=False)
    armored_slatepack = Column(String)


class TransactionsModel(Base):
    __tablename__ = 'transactions'

    id = Column(Integer, primary_key=True)
    slate_id = Column(String)
    encrypted = Column(Binary, nullable=False)


class VersionModel(Base):
    __tablename__ = 'version'

    schema_version = Column(Integer, primary_key=True)
