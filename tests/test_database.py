import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mimblewimble.models.data.models import Base
from mimblewimble.models.data.service import SQLWalletService


class DBTest(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            'sqlite:///:memory:', echo=False)

        Session = sessionmaker(bind=self.engine)
        self.session = Session()

        Base.metadata.create_all(self.engine)
        self.s = SQLWalletService(self.session)


    def tearDown(self):
        self.session.close()

        Base.metadata.drop_all(self.engine)


    def test1(self):
        commitment = 'ijtrijekrmmmmm'

        # first record
        status = 12
        transaction_id = 13
        encrypted = b'0x12'
        self.s.addOutputs(
            commitment, status, transaction_id, encrypted)

        # update record
        status = 13
        transaction_id = 14
        encrypted = b'0x13'
        self.s.addOutputs(
            commitment, status, transaction_id, encrypted)
