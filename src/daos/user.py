from typing import List
from src.basic import get_logger
from src.daos import Session, session_commit
from src.daos.models import User

logger = get_logger(__name__)


class IDaoUser:
    def commit(self):
        raise NotImplementedError()

    def get_user_by_username(self, username: str) -> User:
        raise NotImplementedError()

    def get_user_list_by_username(self, username: List[str]) -> List[User]:
        raise NotImplementedError()


class DaoUser(IDaoUser):
    session: Session

    def __init__(self):
        self.session = Session()

    def commit(self):
        session_commit(self.session)

    def get_user_by_username(self, username: str) -> User:
        logger.debug(username)
        return self.session.query(User).filter(User.username == username).first()

    def get_user_list_by_username(self, username: List[str]) -> List[User]:
        return self.session.query(User).filter(User.username.in_(username)).all()
