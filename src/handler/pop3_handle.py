from src.models.pop3 import POP3Model


class SendMail:
    async def handle_USER(self, server, session, username):
        session.user = POP3Model().confirm_user(username)
        return f'+OK ({server.hostname}): {username}'

    async def handle_PASS(self, server, session, username, password):
        POP3Model().login(session.user, password)
        return f'+OK welcome {username}'

    async def handle_STAT(self, server, session):
        count, size = POP3Model().get_mail_number_and_size(session.user)
        return f'+OK {count} {size}'

    async def handle_UIDL(self, server, session, which):
        return POP3Model().get_mail_uidl(session.user)
