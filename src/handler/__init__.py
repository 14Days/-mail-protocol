from src.handler.smtp_handle import SaveMail
from src.lib.smtp_server.controller import Controller as SController


async def smtp_main(loop):
    cont = SController(SaveMail(), hostname='::0', port=8025)
    cont.start()
