from src.models.pop3 import POP3Model


class SendMail:
    async def handle_USER(self, server, session, username):
        POP3Model().confirm_user(username)
        return f'+OK ({server.hostname}): {username}'

    async def handle_PASS(self, server, session, username, password):
        POP3Model().login(username, password)
        return f'+OK welcome {username}'


