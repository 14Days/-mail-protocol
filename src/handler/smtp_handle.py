import re
from src.basic.logger import get_logger
from src.models.smtp import SMTPModel

logger = get_logger(__name__)

NLCRE = re.compile(br'\r\n|\r|\n')
EMPTYBYTES = b''


class SaveMail:
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if not address.endswith('@wghtstudio.cn'):
            return '550 not relaying to that domain'
        envelope.rcpt_tos.append(address)
        envelope.rcpt_options.extend(rcpt_options)
        return '250 OK'

    async def handle_DATA(self, server, session, envelope):
        if isinstance(envelope.content, str):
            content = envelope.original_content
        else:
            content = envelope.content

        lines = content.splitlines(keepends=True)
        data = EMPTYBYTES.join(lines)

        SMTPModel(envelope.mail_from, envelope.rcpt_tos, data).store_email()

        return '250 OK'
