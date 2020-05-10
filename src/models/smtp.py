import email
import mailbox
import pathlib
from src.basic.logger import get_logger
from src.daos.models import UserMail, Mail
from src.daos.user import IDaoUser, DaoUser
from src.models.errors import UserNotFound

logger = get_logger(__name__)


class ISMTPModel:
    def store_email(self):
        raise NotImplementedError()


class SMTPModel(ISMTPModel):
    _dao_user: IDaoUser
    mail_name: str
    _path = pathlib.Path.joinpath(pathlib.Path(__file__).parent.parent.parent, 'mail')
    _box = mailbox.Maildir(_path, create=True)

    def __init__(self, mail_from, rcpt_to, data):
        self._dao_user = DaoUser()
        self.mail_from = mail_from
        self.rcpt_to = rcpt_to
        self.data = data

    def _save_file(self):
        self.mail_name = self._box.add(self.data)

    def store_email(self):
        # 保存邮件文件
        self._save_file()
        # 邮件信息写入数据库
        # 得到邮件标题
        content = email.message_from_bytes(self.data)
        title = content['Subject'] if content['Subject'] is not None else '新建邮件'
        # 发送关系写入数据库
        # 得到发送方
        from_user = self._dao_user.get_user_by_username(self.mail_from.split('@')[0])
        if from_user is None:
            raise UserNotFound('用户未找到')

        # 得到发送方
        rcpt_to = [item.split('@')[0] for item in self.rcpt_to]
        rcpt_user = self._dao_user.get_user_list_by_username(rcpt_to)
        # 构建用户电子邮件关系
        mail = Mail(
            title=title,
            file_name=self.mail_name,
            content=self.data,
            dir_name_id=1,
            size=len(self.data)
        )
        # 添加到发送方
        from_user.from_list.append(mail)
        # 添加到接收方
        for item in rcpt_user:
            logger.debug(item.id)
            user_mail = UserMail(mail=mail)
            item.to_list.append(user_mail)
        self._dao_user.commit()
