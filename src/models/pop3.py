from src.daos.user import IDaoUser, DaoUser
from src.models.errors import UserNotFound, PasswordError


class IPOP3Model:
    def confirm_user(self, username):
        raise NotImplementedError()

    def login(self, username, password):
        raise NotImplementedError()


class POP3Model(IPOP3Model):
    _dao_user: IDaoUser

    def __init__(self):
        self._dao_user = DaoUser()

    def confirm_user(self, username: str):
        user = self._dao_user.get_user_by_username(username.split('@')[0])
        if user is None:
            raise UserNotFound('用户未找到')

    def login(self, username, password):
        user = self._dao_user.get_user_by_username(username.split('@')[0])
        if user.password != password:
            raise PasswordError('用户密码错误')
