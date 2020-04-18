from sqlalchemy import create_engine, event, exc, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from src.basic import Config, get_logger

logger = get_logger(__name__)

db_uri = Config.get_instance()['DATABASE_URI']
engine = create_engine(db_uri)


@event.listens_for(engine, "engine_connect")
def ping_connection(connection, branch):
    if branch:
        return

    try:
        connection.scalar(select([1]))
        logger.info('成功连接数据库')
    except exc.DBAPIError as err:
        if err.connection_invalidated:
            connection.scalar(select([1]))
            logger.info('成功连接数据库')
        else:
            logger.error('连接数据库失败', err)
            raise


Session = sessionmaker(bind=engine)


def session_commit(session: Session):
    try:
        session.commit()
    except SQLAlchemyError as e:
        session.rollback()
        raise e
