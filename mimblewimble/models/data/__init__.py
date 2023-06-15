from sqlalchemy.exc import PendingRollbackError


class SQLService:
    def __init__(self, session):
        self.session = session

   def select(self, q, only_first=False, count=False):
        try:
            if only_first:
                return q.first()
            elif count:
                return q.count()
            return q.all()
        except PendingRollbackError as e:
            self.app.db.session.rollback()
            # try again after rollback
            return self.select(q, only_first=only_first, count=count)

    def insert(self, new_record):
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

    def update(self, record):
        try:
            self.session.execute(record)
            self.session.commit()
            self.session.refresh(record)
            self.session.expire_all()
        except PendingRollbackError as e:
            self.app.db.session.rollback()
            # try again after rollback
            return self.update(record)
