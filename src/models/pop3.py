from src.basic import get_logger
from src.daos.user import IDaoUser, DaoUser
from src.models.errors import UserNotFound, PasswordError

logger = get_logger(__name__)


class IPOP3Model:
    def confirm_user(self, username):
        raise NotImplementedError()

    def login(self, username, password):
        raise NotImplementedError()

    def get_mail_number_and_size(self, username):
        raise NotImplementedError()

    def get_mail_uidl(self, user, which):
        raise NotImplementedError()

    def get_mail_list(self, user, which):
        raise NotImplementedError()


class POP3Model(IPOP3Model):
    _dao_user: IDaoUser

    def __init__(self, dao_user=None):
        self._dao_user = dao_user

    def confirm_user(self, username: str):
        user = self._dao_user.get_user_by_username(username.split('@')[0])
        if user is None:
            raise UserNotFound('用户未找到')
        return user

    def login(self, user, password):
        if user.password != password:
            raise PasswordError('用户密码错误')

    def get_mail_number_and_size(self, user) -> tuple:
        sum_size = 0
        for item in user.to_list:
            sum_size += item.mail.size
        return len(user.to_list), sum_size

    def get_mail_uidl(self, user, which):
        if which is None:
            status_list = ['+OK core mail']
            for index, item in enumerate(user.to_list):
                logger.debug(index)
                status_list.append(f'{index + 1} {item.mail.file_name}')
            return status_list
        else:
            temp = int(which)
            return f'+OK {temp} {user.to_list[temp - 1].mail.file_name}'

    def get_mail_list(self, user, which):
        if which is None:
            status_list = ['+OK core mail']
            for index, item in enumerate(user.to_list):
                logger.debug(index)
                status_list.append(f'{index + 1} {item.mail.size}')
            return status_list
        else:
            temp = int(which)
            return f'+OK {temp} {user.to_list[temp - 1].mail.size}'
