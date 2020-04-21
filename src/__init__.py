import asyncio
from src.basic import get_logger, Config
from src.handler import smtp_main, pop3_main

logger = get_logger(__name__)


def run_server():
    logger.info('服务开始启动')
    loop = asyncio.get_event_loop()
    loop.create_task(smtp_main(loop=loop))
    logger.info('注册 smtp 完成')
    loop.create_task(pop3_main(loop=loop))
    logger.info('注册 pop3 完成')
    try:
        logger.info('服务启动完成')
        loop.run_forever()
    except KeyboardInterrupt:
        pass
