import logging
import pathlib

from logging.handlers import TimedRotatingFileHandler


def get_logger(name) -> logging.Logger:
    logger = logging.getLogger(name)

    path = pathlib.Path(__file__).parent.parent.parent
    path = pathlib.Path.joinpath(path, 'log', 'flask.log')

    handler_file = TimedRotatingFileHandler(
        path, when='D', interval=1, backupCount=15,
        encoding='UTF-8', delay=False, utc=False,
    )
    handler_file.setLevel(logging.INFO)

    handler_stream = logging.StreamHandler()
    handler_stream.setLevel(logging.DEBUG)

    formatter = logging.Formatter('[%(asctime)s][%(filename)s:%(lineno)d][%(levelname)s][%(thread)d] - %(message)s')

    handler_file.setFormatter(formatter)
    handler_stream.setFormatter(formatter)
    logger.addHandler(handler_file)
    logger.addHandler(handler_stream)
    logger.setLevel(level=logging.DEBUG)
    return logger
