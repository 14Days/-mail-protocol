from src.handler.smtp_handle import SaveMail
from src.lib.smtp_server.controller import Controller as SController
from src.handler.pop3_handle import SendMail
from src.lib.pop_server.controller import Controller as PController


async def smtp_main(loop):
    cont = SController(SaveMail(), hostname='0.0.0.0', port=8025)
    cont.start()


async def pop3_main(loop):
    cont = PController(SendMail(), hostname='0.0.0.0', port=8026)
    cont.start()
