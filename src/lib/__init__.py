import asyncio
import logging
import mailbox
import re

from src.lib.smtp_server.controller import Controller

CRLF = b'\r\n'
NLCRE = re.compile(br'\r\n|\r|\n')
EMPTYBYTES = b''


class SaveMail:
    def __init__(self):
        self.mailbox = mailbox.Maildir('./tmp', create=True)

    async def handle_DATA(self, server, session, envelope):
        if isinstance(envelope.content, str):
            content = envelope.original_content
        else:
            content = envelope.content
        lines = content.splitlines(keepends=True)
        # Look for the last header
        i = 0
        ending = CRLF
        for line in lines:  # pragma: nobranch
            if NLCRE.match(line):
                ending = line
                break
            i += 1
        data = EMPTYBYTES.join(lines)
        self._save(envelope.mail_from, envelope.rcpt_tos, data)
        # TBD: what to do with refused addresses?
        return '250 OK'

    def _save(self, mail_from, rcpt_tos, data):
        self.mailbox.add(data)


async def amain(loop):
    cont = Controller(SaveMail(), hostname='::0', port=8025)
    cont.start()
