import mailbox
import pathlib
import re
from src.basic.logger import get_logger

logger = get_logger(__name__)

NLCRE = re.compile(br'\r\n|\r|\n')
EMPTYBYTES = b''


class SaveMail:
    path = pathlib.Path.joinpath(pathlib.Path(__file__).parent.parent.parent, 'mail')

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

        for item in envelope.rcpt_tos:
            self._save(envelope.mail_from, item, data)
        return '250 OK'

    def _save(self, mail_from, rcpt_tos, data):
        box = mailbox.Maildir(self.path, create=True)
        box.add(data)
