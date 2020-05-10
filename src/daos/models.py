import datetime
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, autoincrement=True, primary_key=True)
    create_at = Column(DateTime, nullable=False, default=datetime.datetime.now)
    update_at = Column(DateTime, nullable=False, default=datetime.datetime.now, onupdate=datetime.datetime.now)
    delete_at = Column(DateTime, nullable=True)
    username = Column(String, nullable=False)
    password = Column(String, nullable=False)
    nickname = Column(String, default='新建用户')
    sex = Column(Integer, nullable=False, default=1)
    user_type = Column(Integer, nullable=False, default=2)
    from_list: list = relationship('Mail', backref='user')
    to_list: list = relationship('UserMail', backref='to_user', foreign_keys='UserMail.to_user_id')


class DirName(Base):
    __tablename__ = 'dir_name'
    id = Column(Integer, autoincrement=True, primary_key=True)
    create_at = Column(DateTime, nullable=False, default=datetime.datetime.now)
    update_at = Column(DateTime, nullable=False, default=datetime.datetime.now, onupdate=datetime.datetime.now)
    delete_at = Column(DateTime, nullable=True)
    name = Column(String, nullable=False)


class Mail(Base):
    __tablename__ = 'mail'
    id = Column(Integer, autoincrement=True, primary_key=True)
    create_at = Column(DateTime, nullable=False, default=datetime.datetime.now)
    update_at = Column(DateTime, nullable=False, default=datetime.datetime.now, onupdate=datetime.datetime.now)
    delete_at = Column(DateTime, nullable=True)
    title = Column(String, nullable=False, default='无标题')
    file_name = Column(String, nullable=False)
    content = Column(String, nullable=True)
    size = Column(Integer, nullable=False)
    dir_name_id = Column(Integer, ForeignKey('dir_name.id'))
    user_id = Column(Integer, ForeignKey('user.id'))
    is_from_del = Column(Integer, nullable=False, default=0)


class UserMail(Base):
    __tablename__ = 'user_mail'
    to_user_id = Column(Integer, ForeignKey('user.id'), name='to', nullable=False, primary_key=True)
    mail_id = Column(Integer, ForeignKey('mail.id'), nullable=False, primary_key=True)
    is_to_del = Column(Integer, nullable=False, default=0)
    mail = relationship('Mail', foreign_keys=[mail_id])
