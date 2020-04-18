from src.basic import get_logger, Config
from src.lib import amain

logger = get_logger(__name__)


def run_server():
    logger.info('服务开始启动')
    print(Config.get_instance())
