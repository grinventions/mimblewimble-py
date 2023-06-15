class SQLService:
    def __init__(self, session):
        self.session = session

    def insertRecord(self, new_record):
        _id = None
        try:
            self.session.add(new_record)
            self.session.commit()
            self.session.refresh(new_record)
            self.session.expire_all()
            _id = new_record.id
        except Exception as e:
            self.session.rollback()
            raise e
        return _id
