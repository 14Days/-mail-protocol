# Imports
import base64
import datetime
import email.utils
import re
import socket
import sys

from email.base64mime import body_encode as encode_base64

# import io
# import email.message
# import email.generator
# import hmac
# import copy


#
# __all__ = ["SMTPException", "SMTPNotSupportedError", "SMTPServerDisconnected", "SMTPResponseException",
#            "SMTPSenderRefused", "SMTPRecipientsRefused", "SMTPDataError",
#            "SMTPConnectError", "SMTPHeloError", "SMTPAuthenticationError",
#            "quoteaddr", "quotedata", "SMTP"]

# 定义服务标准端口
SMTP_PORT = 25
SMTP_SSL_PORT = 465
# 定义结束符
CRLF = '\r\n'
bCRLF = b'\r\n'
# 比 RFC 821, 4.5.3 大 8 倍
_MAX_LINE = 8192

OLDSTYLE_AUTH = re.compile(r"auth=(.*)", re.I)


# 定义本模块需要的异常
class SMTPException(OSError):
    """本模块所有异常的基类"""
    pass


class SMTPNotSupportedError(SMTPException):
    """命令或者选项不被 SMTP 支持时抛出的异常"""
    pass


class SMTPServerDisconnected(SMTPException):
    """当丢失连接或者在未建立连接时尝试执行命令抛出的异常"""
    pass


class SMTPResponseException(SMTPException):
    """当 SMTP 服务返回错误代码时抛出的异常"""

    def __init__(self, code, msg):
        self.smtp_code = code
        self.smtp_error = msg
        self.args = (code, msg)


class SMTPSenderRefused(SMTPResponseException):
    """当 Sender address 拒绝时抛出的异常
    比 SMTPResponseException 多出了 sender 属性
    """

    def __init__(self, code, msg, sender):
        self.smtp_code = code
        self.smtp_error = msg
        self.sender = sender
        self.args = (code, msg, sender)


class SMTPRecipientsRefused(SMTPException):
    """所有收件人均拒绝时抛出的异常

    通过属性可以访问每个收件人的错误 "收件人"
    是与 "字典” 类型完全相同的字典 SMTP.sendmail() 返回
    """

    def __init__(self, recipients):
        self.recipients = recipients
        self.args = (recipients,)


class SMTPDataError(SMTPResponseException):
    """SMTP 服务没有接受数据抛出的数据"""
    pass


class SMTPConnectError(SMTPResponseException):
    """建立连接时错误抛出的异常"""
    pass


class SMTPHeloError(SMTPResponseException):
    """服务器拒绝了我们 HELO 回应"""
    pass


class SMTPAuthenticationError(SMTPResponseException):
    """权限鉴定错误

    服务器未接受 username / password
    """
    pass


def quoteaddr(addr_string):
    """引用由 RFC 821 定义的电子邮件地址的子集。
    应该能够处理 email.utils.parseaddr 可以处理的任何事情。
    """
    display_name, addr = email.utils.parseaddr(addr_string)
    if (display_name, addr) == ('', ''):
        # 如果无法解析, 则按照原样使用
        if addr_string.strip().startswith('<'):
            return addr_string
        return f'<{addr_string}>'
    return f'<{addr}>'


#
def _addr_only(addr_string):
    display_name, addr = email.utils.parseaddr(addr_string)
    if (display_name, addr) == ('', ''):
        # parseaddr couldn't parse it, so use it as is.
        return addr_string
    return addr


#
# # Legacy method kept for backward compatibility.
# def quotedata(data):
#     """Quote data for email.
#
#     Double leading '.', and change Unix newline '\\n', or Mac '\\r' into
#     Internet CRLF end-of-line.
#     """
#     return re.sub(r'(?m)^\.', '..',
#         re.sub(r'(?:\r\n|\n|\r(?!\n))', CRLF, data))
#
def _quote_periods(bin_data):
    return re.sub(br'(?m)^\.', b'..', bin_data)


def _fix_eols(data):
    return re.sub(r'(?:\r\n|\n|\r(?!\n))', CRLF, data)


try:
    import ssl
except ImportError:
    _have_ssl = False
else:
    _have_ssl = True


class SMTP:
    debuglevel = 0
    file = None
    helo_resp = None
    ehlo_msg = "ehlo"
    ehlo_resp = None
    does_esmtp = 0
    default_port = SMTP_PORT

    def __init__(self, host='', port=0, local_hostname=None,
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                 source_address=None):
        self._host = host
        self.timeout = timeout
        self.esmtp_features = {}
        self.command_encoding = 'ascii'
        self.source_address = source_address

        if host:
            code, msg = self.connect(host, port)
            if code != 220:
                self.close()
                raise SMTPConnectError(code, msg)
        if local_hostname is not None:
            self.local_hostname = local_hostname
        else:
            # RFC 2821 表示我们应该在 EHLO / HELO动词中使用 fqdn
            # 如果无法计算出 fqdn，则应该改用域文字
            fqdn = socket.getfqdn()
            if '.' in fqdn:
                self.local_hostname = fqdn
            else:
                addr = '127.0.0.1'
                try:
                    addr = socket.gethostbyname(socket.gethostname())
                except socket.gaierror:
                    pass
                self.local_hostname = f'[{addr}]'

    def __enter__(self):
        return self

    def __exit__(self, *args):
        try:
            code, message = self.docmd("QUIT")
            if code != 221:
                raise SMTPResponseException(code, message)
        except SMTPServerDisconnected:
            pass
        finally:
            self.close()

    def set_debuglevel(self, debuglevel):
        """设置 debug 等级, 大于 0 即输出 log"""
        self.debuglevel = debuglevel

    def _print_debug(self, *args):
        """打印 debug 信息"""
        if self.debuglevel > 1:
            print(datetime.datetime.now().time(), *args, file=sys.stderr)
        else:
            print(*args, file=sys.stderr)

    def _get_socket(self, host, port, timeout):
        """获取 socket"""
        if self.debuglevel > 0:
            self._print_debug('connect: to', (host, port), self.source_address)
        return socket.create_connection((host, port), timeout,
                                        self.source_address)

    def connect(self, host='localhost', port=0, source_address=None):
        """连接 host"""
        if source_address:
            self.source_address = source_address

        # 如果未传端口号, 并且可以在 host 地址中找到端口的格式那么提取端口
        if not port and (host.find(':') == host.rfind(':')):
            i = host.rfind(':')
            if i >= 0:
                host, port = host[:i], host[i + 1:]
                try:
                    port = int(port)
                except ValueError:
                    raise OSError('no numeric port')
        if not port:
            port = self.default_port
        if self.debuglevel > 0:
            self._print_debug('connect:', (host, port))

        self.sock = self._get_socket(host, port, self.timeout)
        self.file = None
        (code, msg) = self.getreply()
        if self.debuglevel > 0:
            self._print_debug('connect:', repr(msg))
        return code, msg

    def send(self, s):
        """发送 's' 到服务器"""
        if self.debuglevel > 0:
            self._print_debug('send:', repr(s))
        if hasattr(self, 'sock') and self.sock:
            if isinstance(s, str):
                s = s.encode(self.command_encoding)
            try:
                self.sock.sendall(s)
            except OSError:
                self.close()
                raise SMTPServerDisconnected('Server not connected')
        else:
            raise SMTPServerDisconnected('please run connect() first')

    def putcmd(self, cmd, args=""):
        """发送命令给服务器"""
        if args == '':
            command = f'{cmd}{CRLF}'
        else:
            command = f'{cmd} {args}{CRLF}'
        self.send(command)

    def getreply(self):
        """从服务器获得响应

        返回包含下面元素的元组

            - 服务响应代码 (e.g. '250')
              Note: 当读取 code 失败时返回 -1

            - 与响应代码相对应的服务器响应字符串 (多行响应转换为单个多行字符串)

        如果到达文件末尾, 则抛出 SMTPServerDisconnected。
        """
        resp = []
        if self.file is None:
            self.file = self.sock.makefile('rb')
        while 1:
            try:
                line = self.file.readline(_MAX_LINE + 1)
            except OSError as e:
                self.close()
                raise SMTPServerDisconnected(f'Connection unexpectedly closed: {e}')
            if not line:
                self.close()
                raise SMTPServerDisconnected('Connection unexpectedly closed')
            if self.debuglevel > 0:
                self._print_debug('reply:', repr(line))
            if len(line) > _MAX_LINE:
                self.close()
                raise SMTPResponseException(500, 'Line too long')
            resp.append(line[4:].strip(b' \t\r\n'))
            code = line[:3]
            # 检查错误代码在语法上是否正确
            try:
                errcode = int(code)
            except ValueError:
                errcode = -1
                break
            # 检查多行响应
            if line[3:4] == b'-':
                break
        errmsg = b'\n'.join(resp)
        if self.debuglevel > 0:
            self._print_debug(f'reply: retcode ({errcode}); Msg: {errmsg}')
        return errcode, errmsg

    def docmd(self, cmd, args=""):
        """发送命令并得到响应"""
        self.putcmd(cmd, args)
        return self.getreply()

    # SMTP 标准命令

    def helo(self, name=''):
        """SMTP 'helo' command."""
        self.putcmd("helo", name or self.local_hostname)
        (code, msg) = self.getreply()
        self.helo_resp = msg
        return code, msg

    def ehlo(self, name=''):
        """ SMTP 'ehlo' command."""
        self.esmtp_features = {}
        self.putcmd(self.ehlo_msg, name or self.local_hostname)
        (code, msg) = self.getreply()

        # 根据 RFC1869 一些 (badly written) MTA 在接收到 ehlo 后会关闭连接
        # Toss an exception if that happens -ddm
        if code == -1 and len(msg) == 0:
            self.close()
            raise SMTPServerDisconnected("Server not connected")
        self.ehlo_resp = msg
        if code != 250:
            return code, msg
        self.does_esmtp = 1

        # 格式化 ehlo 响应
        assert isinstance(self.ehlo_resp, bytes), repr(self.ehlo_resp)
        resp = self.ehlo_resp.decode("latin-1").split('\n')
        del resp[0]
        for each in resp:
            # 为了能够与尽可能多的 SMTP 服务器进行通信, 我们必须考虑老式的身份验证方式, 因为:
            # 1）否则 SMTP 功能解析器会出现错误
            # 2）有些服务器仅支持旧版的 auth 方法
            auth_match = OLDSTYLE_AUTH.match(each)
            if auth_match:
                # 这不会删除重复项, 但这没问题
                self.esmtp_features["auth"] = self.esmtp_features.get("auth", "") \
                                              + " " + auth_match.groups(0)[0]
                continue

            # RFC 1869 要求在 ehlo 关键字和参数之间需要一个空格
            # 实际上它非常严格, 因为参数之间只能有空格
            # 如果没有参数, 则不存在空格。
            m = re.match(r'(?P<feature>[A-Za-z0-9][A-Za-z0-9\-]*) ?', each)
            if m:
                feature = m.group("feature").lower()
                params = m.string[m.end("feature"):].strip()
                if feature == "auth":
                    self.esmtp_features[feature] = self.esmtp_features.get(feature, "") \
                                                   + " " + params
                else:
                    self.esmtp_features[feature] = params
        return code, msg

    def has_extn(self, opt):
        """Does the server support a given SMTP service extension?"""
        return opt.lower() in self.esmtp_features

    def help(self, args=''):
        """SMTP 'help' command.
        Returns help text from server."""
        self.putcmd("help", args)
        return self.getreply()[1]

    def rset(self):
        """SMTP 'rset' command -- resets session."""
        self.command_encoding = 'ascii'
        return self.docmd("rset")

    def _rset(self):
        """Internal 'rset' command which ignores any SMTPServerDisconnected error.

        Used internally in the library, since the server disconnected error
        should appear to the application when the *next* command is issued, if
        we are doing an internal "safety" reset.
        """
        try:
            self.rset()
        except SMTPServerDisconnected:
            pass

    def noop(self):
        """SMTP 'noop' command -- doesn't do anything :>"""
        return self.docmd("noop")

    def mail(self, sender, options=()):
        """SMTP 'mail' command -- begins mail xfer session."""

        option_list = ''
        if options and self.does_esmtp:
            if any(x.lower() == 'smtputf8' for x in options):
                if self.has_extn('smtputf8'):
                    self.command_encoding = 'utf-8'
                else:
                    raise SMTPNotSupportedError('SMTPUTF8 not supported by server')
            option_list = ' ' + ' '.join(options)
        self.putcmd(f'mail", "FROM:{quoteaddr(sender)}{option_list}')
        return self.getreply()

    def rcpt(self, recip, options=()):
        """SMTP 'rcpt' command -- indicates 1 recipient for this mail."""
        option_list = ''
        if options and self.does_esmtp:
            option_list = ' ' + ' '.join(options)
        self.putcmd('rcpt', f'TO:{quoteaddr(recip)}{option_list}')
        return self.getreply()

    def data(self, msg):
        """SMTP 'DATA' command -- sends message data to server.

        每个 RFC 821 自动引用以句点开头的行
        如果对 DATA 命令有意外答复, 则引发 SMTPDataError
        此方法的返回值是发送所有数据时收到的最终响应代码
        如果 msg 是字符串, 则将单独的'\\ r'和'\\ n'字符转换为'\\ r \\ n'字符
        如果msg是字节, 则按原样发送。
        """
        self.putcmd("data")
        (code, repl) = self.getreply()
        if self.debuglevel > 0:
            self._print_debug('data:', (code, repl))
        if code != 354:
            raise SMTPDataError(code, repl)
        else:
            if isinstance(msg, str):
                msg = _fix_eols(msg).encode('ascii')
            q = _quote_periods(msg)
            if q[-2:] != bCRLF:
                q = q + bCRLF
            q = q + b"." + bCRLF
            self.send(q)
            (code, msg) = self.getreply()
            if self.debuglevel > 0:
                self._print_debug('data:', (code, msg))
            return code, msg

    def verify(self, address):
        """SMTP 'verify' command -- checks for address validity."""
        self.putcmd("vrfy", _addr_only(address))
        return self.getreply()

    # a.k.a.
    vrfy = verify

    def expn(self, address):
        """SMTP 'expn' command -- expands a mailing list."""
        self.putcmd("expn", _addr_only(address))
        return self.getreply()

    # 封装一些常见的操作

    def ehlo_or_helo_if_needed(self):
        """Call self.ehlo() and/or self.helo() if needed.

        依次尝试 ehlo 与 helo 命令
        当服务器对上面两个命令都没有回应时抛出 SMTPHeloError 异常
        """
        if self.helo_resp is None and self.ehlo_resp is None:
            if not (200 <= self.ehlo()[0] <= 299):
                (code, resp) = self.helo()
                if not (200 <= code <= 299):
                    raise SMTPHeloError(code, resp)

    def auth(self, mechanism, authobject, *, initial_response_ok=True):
        """Authentication command - requires response processing.

        'mechanism' specifies which authentication mechanism is to
        be used - the valid values are those listed in the 'auth'
        element of 'esmtp_features'.

        'authobject' must be a callable object taking a single argument:

                data = authobject(challenge)

        It will be called to process the server's challenge response; the
        challenge argument it is passed will be a bytes.  It should return
        an ASCII string that will be base64 encoded and sent to the server.

        Keyword arguments:
            - initial_response_ok: Allow sending the RFC 4954 initial-response
              to the AUTH command, if the authentication methods supports it.
        """
        # RFC 4954 allows auth methods to provide an initial response.  Not all
        # methods support it.  By definition, if they return something other
        # than None when challenge is None, then they do.  See issue #15014.
        mechanism = mechanism.upper()
        initial_response = (authobject() if initial_response_ok else None)
        if initial_response is not None:
            response = encode_base64(initial_response.encode('ascii'), eol='')
            (code, resp) = self.docmd("AUTH", mechanism + " " + response)
        else:
            (code, resp) = self.docmd("AUTH", mechanism)
        # If server responds with a challenge, send the response.
        if code == 334:
            challenge = base64.decodebytes(resp)
            response = encode_base64(
                authobject(challenge).encode('ascii'), eol='')
            (code, resp) = self.docmd(response)
        if code in (235, 503):
            return code, resp
        raise SMTPAuthenticationError(code, resp)

    #
    #     def auth_cram_md5(self, challenge=None):
    #         """ Authobject to use with CRAM-MD5 authentication. Requires self.user
    #         and self.password to be set."""
    #         # CRAM-MD5 does not support initial-response.
    #         if challenge is None:
    #             return None
    #         return self.user + " " + hmac.HMAC(
    #             self.password.encode('ascii'), challenge, 'md5').hexdigest()
    #
    #     def auth_plain(self, challenge=None):
    #         """ Authobject to use with PLAIN authentication. Requires self.user and
    #         self.password to be set."""
    #         return "\0%s\0%s" % (self.user, self.password)
    #
    #     def auth_login(self, challenge=None):
    #         """ Authobject to use with LOGIN authentication. Requires self.user and
    #         self.password to be set."""
    #         if challenge is None:
    #             return self.user
    #         else:
    #             return self.password
    #
    #     def login(self, user, password, *, initial_response_ok=True):
    #         """Log in on an SMTP server that requires authentication.
    #
    #         The arguments are:
    #             - user:         The user name to authenticate with.
    #             - password:     The password for the authentication.
    #
    #         Keyword arguments:
    #             - initial_response_ok: Allow sending the RFC 4954 initial-response
    #               to the AUTH command, if the authentication methods supports it.
    #
    #         If there has been no previous EHLO or HELO command this session, this
    #         method tries ESMTP EHLO first.
    #
    #         This method will return normally if the authentication was successful.
    #
    #         This method may raise the following exceptions:
    #
    #          SMTPHeloError            The server didn't reply properly to
    #                                   the helo greeting.
    #          SMTPAuthenticationError  The server didn't accept the username/
    #                                   password combination.
    #          SMTPNotSupportedError    The AUTH command is not supported by the
    #                                   server.
    #          SMTPException            No suitable authentication method was
    #                                   found.
    #         """
    #
    #         self.ehlo_or_helo_if_needed()
    #         if not self.has_extn("auth"):
    #             raise SMTPNotSupportedError(
    #                 "SMTP AUTH extension not supported by server.")
    #
    #         # Authentication methods the server claims to support
    #         advertised_authlist = self.esmtp_features["auth"].split()
    #
    #         # Authentication methods we can handle in our preferred order:
    #         preferred_auths = ['CRAM-MD5', 'PLAIN', 'LOGIN']
    #
    #         # We try the supported authentications in our preferred order, if
    #         # the server supports them.
    #         authlist = [auth for auth in preferred_auths
    #                     if auth in advertised_authlist]
    #         if not authlist:
    #             raise SMTPException("No suitable authentication method found.")
    #
    #         # Some servers advertise authentication methods they don't really
    #         # support, so if authentication fails, we continue until we've tried
    #         # all methods.
    #         self.user, self.password = user, password
    #         for authmethod in authlist:
    #             method_name = 'auth_' + authmethod.lower().replace('-', '_')
    #             try:
    #                 (code, resp) = self.auth(
    #                     authmethod, getattr(self, method_name),
    #                     initial_response_ok=initial_response_ok)
    #                 # 235 == 'Authentication successful'
    #                 # 503 == 'Error: already authenticated'
    #                 if code in (235, 503):
    #                     return (code, resp)
    #             except SMTPAuthenticationError as e:
    #                 last_exception = e
    #
    #         # We could not login successfully.  Return result of last attempt.
    #         raise last_exception
    #
    #     def starttls(self, keyfile=None, certfile=None, context=None):
    #         """Puts the connection to the SMTP server into TLS mode.
    #
    #         If there has been no previous EHLO or HELO command this session, this
    #         method tries ESMTP EHLO first.
    #
    #         If the server supports TLS, this will encrypt the rest of the SMTP
    #         session. If you provide the keyfile and certfile parameters,
    #         the identity of the SMTP server and client can be checked. This,
    #         however, depends on whether the socket module really checks the
    #         certificates.
    #
    #         This method may raise the following exceptions:
    #
    #          SMTPHeloError            The server didn't reply properly to
    #                                   the helo greeting.
    #         """
    #         self.ehlo_or_helo_if_needed()
    #         if not self.has_extn("starttls"):
    #             raise SMTPNotSupportedError(
    #                 "STARTTLS extension not supported by server.")
    #         (resp, reply) = self.docmd("STARTTLS")
    #         if resp == 220:
    #             if not _have_ssl:
    #                 raise RuntimeError("No SSL support included in this Python")
    #             if context is not None and keyfile is not None:
    #                 raise ValueError("context and keyfile arguments are mutually "
    #                                  "exclusive")
    #             if context is not None and certfile is not None:
    #                 raise ValueError("context and certfile arguments are mutually "
    #                                  "exclusive")
    #             if keyfile is not None or certfile is not None:
    #                 import warnings
    #                 warnings.warn("keyfile and certfile are deprecated, use a "
    #                               "custom context instead", DeprecationWarning, 2)
    #             if context is None:
    #                 context = ssl._create_stdlib_context(certfile=certfile,
    #                                                      keyfile=keyfile)
    #             self.sock = context.wrap_socket(self.sock,
    #                                             server_hostname=self._host)
    #             self.file = None
    #             # RFC 3207:
    #             # The client MUST discard any knowledge obtained from
    #             # the server, such as the list of SMTP service extensions,
    #             # which was not obtained from the TLS negotiation itself.
    #             self.helo_resp = None
    #             self.ehlo_resp = None
    #             self.esmtp_features = {}
    #             self.does_esmtp = 0
    #         else:
    #             # RFC 3207:
    #             # 501 Syntax error (no parameters allowed)
    #             # 454 TLS not available due to temporary reason
    #             raise SMTPResponseException(resp, reply)
    #         return (resp, reply)
    #
    #     def sendmail(self, from_addr, to_addrs, msg, mail_options=(),
    #                  rcpt_options=()):
    #         """This command performs an entire mail transaction.
    #
    #         The arguments are:
    #             - from_addr    : The address sending this mail.
    #             - to_addrs     : A list of addresses to send this mail to.  A bare
    #                              string will be treated as a list with 1 address.
    #             - msg          : The message to send.
    #             - mail_options : List of ESMTP options (such as 8bitmime) for the
    #                              mail command.
    #             - rcpt_options : List of ESMTP options (such as DSN commands) for
    #                              all the rcpt commands.
    #
    #         msg may be a string containing characters in the ASCII range, or a byte
    #         string.  A string is encoded to bytes using the ascii codec, and lone
    #         \\r and \\n characters are converted to \\r\\n characters.
    #
    #         If there has been no previous EHLO or HELO command this session, this
    #         method tries ESMTP EHLO first.  If the server does ESMTP, message size
    #         and each of the specified options will be passed to it.  If EHLO
    #         fails, HELO will be tried and ESMTP options suppressed.
    #
    #         This method will return normally if the mail is accepted for at least
    #         one recipient.  It returns a dictionary, with one entry for each
    #         recipient that was refused.  Each entry contains a tuple of the SMTP
    #         error code and the accompanying error message sent by the server.
    #
    #         This method may raise the following exceptions:
    #
    #          SMTPHeloError          The server didn't reply properly to
    #                                 the helo greeting.
    #          SMTPRecipientsRefused  The server rejected ALL recipients
    #                                 (no mail was sent).
    #          SMTPSenderRefused      The server didn't accept the from_addr.
    #          SMTPDataError          The server replied with an unexpected
    #                                 error code (other than a refusal of
    #                                 a recipient).
    #          SMTPNotSupportedError  The mail_options parameter includes 'SMTPUTF8'
    #                                 but the SMTPUTF8 extension is not supported by
    #                                 the server.
    #
    #         Note: the connection will be open even after an exception is raised.
    #
    #         Example:
    #
    #          >>> import smtplib
    #          >>> s=smtplib.SMTP("localhost")
    #          >>> tolist=["one@one.org","two@two.org","three@three.org","four@four.org"]
    #          >>> msg = '''\\
    #          ... From: Me@my.org
    #          ... Subject: testin'...
    #          ...
    #          ... This is a test '''
    #          >>> s.sendmail("me@my.org",tolist,msg)
    #          { "three@three.org" : ( 550 ,"User unknown" ) }
    #          >>> s.quit()
    #
    #         In the above example, the message was accepted for delivery to three
    #         of the four addresses, and one was rejected, with the error code
    #         550.  If all addresses are accepted, then the method will return an
    #         empty dictionary.
    #
    #         """
    #         self.ehlo_or_helo_if_needed()
    #         esmtp_opts = []
    #         if isinstance(msg, str):
    #             msg = _fix_eols(msg).encode('ascii')
    #         if self.does_esmtp:
    #             if self.has_extn('size'):
    #                 esmtp_opts.append("size=%d" % len(msg))
    #             for option in mail_options:
    #                 esmtp_opts.append(option)
    #         (code, resp) = self.mail(from_addr, esmtp_opts)
    #         if code != 250:
    #             if code == 421:
    #                 self.close()
    #             else:
    #                 self._rset()
    #             raise SMTPSenderRefused(code, resp, from_addr)
    #         senderrs = {}
    #         if isinstance(to_addrs, str):
    #             to_addrs = [to_addrs]
    #         for each in to_addrs:
    #             (code, resp) = self.rcpt(each, rcpt_options)
    #             if (code != 250) and (code != 251):
    #                 senderrs[each] = (code, resp)
    #             if code == 421:
    #                 self.close()
    #                 raise SMTPRecipientsRefused(senderrs)
    #         if len(senderrs) == len(to_addrs):
    #             # the server refused all our recipients
    #             self._rset()
    #             raise SMTPRecipientsRefused(senderrs)
    #         (code, resp) = self.data(msg)
    #         if code != 250:
    #             if code == 421:
    #                 self.close()
    #             else:
    #                 self._rset()
    #             raise SMTPDataError(code, resp)
    #         #if we got here then somebody got our mail
    #         return senderrs
    #
    #     def send_message(self, msg, from_addr=None, to_addrs=None,
    #                      mail_options=(), rcpt_options=()):
    #         """Converts message to a bytestring and passes it to sendmail.
    #
    #         The arguments are as for sendmail, except that msg is an
    #         email.message.Message object.  If from_addr is None or to_addrs is
    #         None, these arguments are taken from the headers of the Message as
    #         described in RFC 2822 (a ValueError is raised if there is more than
    #         one set of 'Resent-' headers).  Regardless of the values of from_addr and
    #         to_addr, any Bcc field (or Resent-Bcc field, when the Message is a
    #         resent) of the Message object won't be transmitted.  The Message
    #         object is then serialized using email.generator.BytesGenerator and
    #         sendmail is called to transmit the message.  If the sender or any of
    #         the recipient addresses contain non-ASCII and the server advertises the
    #         SMTPUTF8 capability, the policy is cloned with utf8 set to True for the
    #         serialization, and SMTPUTF8 and BODY=8BITMIME are asserted on the send.
    #         If the server does not support SMTPUTF8, an SMTPNotSupported error is
    #         raised.  Otherwise the generator is called without modifying the
    #         policy.
    #
    #         """
    #         # 'Resent-Date' is a mandatory field if the Message is resent (RFC 2822
    #         # Section 3.6.6). In such a case, we use the 'Resent-*' fields.  However,
    #         # if there is more than one 'Resent-' block there's no way to
    #         # unambiguously determine which one is the most recent in all cases,
    #         # so rather than guess we raise a ValueError in that case.
    #         #
    #         # TODO implement heuristics to guess the correct Resent-* block with an
    #         # option allowing the user to enable the heuristics.  (It should be
    #         # possible to guess correctly almost all of the time.)
    #
    #         self.ehlo_or_helo_if_needed()
    #         resent = msg.get_all('Resent-Date')
    #         if resent is None:
    #             header_prefix = ''
    #         elif len(resent) == 1:
    #             header_prefix = 'Resent-'
    #         else:
    #             raise ValueError("message has more than one 'Resent-' header block")
    #         if from_addr is None:
    #             # Prefer the sender field per RFC 2822:3.6.2.
    #             from_addr = (msg[header_prefix + 'Sender']
    #                            if (header_prefix + 'Sender') in msg
    #                            else msg[header_prefix + 'From'])
    #             from_addr = email.utils.getaddresses([from_addr])[0][1]
    #         if to_addrs is None:
    #             addr_fields = [f for f in (msg[header_prefix + 'To'],
    #                                        msg[header_prefix + 'Bcc'],
    #                                        msg[header_prefix + 'Cc'])
    #                            if f is not None]
    #             to_addrs = [a[1] for a in email.utils.getaddresses(addr_fields)]
    #         # Make a local copy so we can delete the bcc headers.
    #         msg_copy = copy.copy(msg)
    #         del msg_copy['Bcc']
    #         del msg_copy['Resent-Bcc']
    #         international = False
    #         try:
    #             ''.join([from_addr, *to_addrs]).encode('ascii')
    #         except UnicodeEncodeError:
    #             if not self.has_extn('smtputf8'):
    #                 raise SMTPNotSupportedError(
    #                     "One or more source or delivery addresses require"
    #                     " internationalized email support, but the server"
    #                     " does not advertise the required SMTPUTF8 capability")
    #             international = True
    #         with io.BytesIO() as bytesmsg:
    #             if international:
    #                 g = email.generator.BytesGenerator(
    #                     bytesmsg, policy=msg.policy.clone(utf8=True))
    #                 mail_options = (*mail_options, 'SMTPUTF8', 'BODY=8BITMIME')
    #             else:
    #                 g = email.generator.BytesGenerator(bytesmsg)
    #             g.flatten(msg_copy, linesep='\r\n')
    #             flatmsg = bytesmsg.getvalue()
    #         return self.sendmail(from_addr, to_addrs, flatmsg, mail_options,
    #                              rcpt_options)
    #
    def close(self):
        """关闭 SMTP 服务的连接"""
        try:
            file = self.file
            self.file = None
            if file:
                file.close()
        finally:
            sock = self.sock
            self.sock = None
            if sock:
                sock.close()


#
#     def quit(self):
#         """Terminate the SMTP session."""
#         res = self.docmd("quit")
#         # A new EHLO is required after reconnecting with connect()
#         self.ehlo_resp = self.helo_resp = None
#         self.esmtp_features = {}
#         self.does_esmtp = False
#         self.close()
#         return res

# if _have_ssl:
#
#     class SMTP_SSL(SMTP):
#         """ This is a subclass derived from SMTP that connects over an SSL
#         encrypted socket (to use this class you need a socket module that was
#         compiled with SSL support). If host is not specified, '' (the local
#         host) is used. If port is omitted, the standard SMTP-over-SSL port
#         (465) is used.  local_hostname and source_address have the same meaning
#         as they do in the SMTP class.  keyfile and certfile are also optional -
#         they can contain a PEM formatted private key and certificate chain file
#         for the SSL connection. context also optional, can contain a
#         SSLContext, and is an alternative to keyfile and certfile; If it is
#         specified both keyfile and certfile must be None.
#
#         """
#
#         default_port = SMTP_SSL_PORT
#
#         def __init__(self, host='', port=0, local_hostname=None,
#                      keyfile=None, certfile=None,
#                      timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
#                      source_address=None, context=None):
#             if context is not None and keyfile is not None:
#                 raise ValueError("context and keyfile arguments are mutually "
#                                  "exclusive")
#             if context is not None and certfile is not None:
#                 raise ValueError("context and certfile arguments are mutually "
#                                  "exclusive")
#             if keyfile is not None or certfile is not None:
#                 import warnings
#                 warnings.warn("keyfile and certfile are deprecated, use a "
#                               "custom context instead", DeprecationWarning, 2)
#             self.keyfile = keyfile
#             self.certfile = certfile
#             if context is None:
#                 context = ssl._create_stdlib_context(certfile=certfile,
#                                                      keyfile=keyfile)
#             self.context = context
#             SMTP.__init__(self, host, port, local_hostname, timeout,
#                     source_address)
#
#         def _get_socket(self, host, port, timeout):
#             if self.debuglevel > 0:
#                 self._print_debug('connect:', (host, port))
#             new_socket = socket.create_connection((host, port), timeout,
#                     self.source_address)
#             new_socket = self.context.wrap_socket(new_socket,
#                                                   server_hostname=self._host)
#             return new_socket
#
#     __all__.append("SMTP_SSL")
#
# #
# # LMTP extension
# #
# LMTP_PORT = 2003
#
# class LMTP(SMTP):
#     """LMTP - Local Mail Transfer Protocol
#
#     The LMTP protocol, which is very similar to ESMTP, is heavily based
#     on the standard SMTP client. It's common to use Unix sockets for
#     LMTP, so our connect() method must support that as well as a regular
#     host:port server.  local_hostname and source_address have the same
#     meaning as they do in the SMTP class.  To specify a Unix socket,
#     you must use an absolute path as the host, starting with a '/'.
#
#     Authentication is supported, using the regular SMTP mechanism. When
#     using a Unix socket, LMTP generally don't support or require any
#     authentication, but your mileage might vary."""
#
#     ehlo_msg = "lhlo"
#
#     def __init__(self, host='', port=LMTP_PORT, local_hostname=None,
#             source_address=None):
#         """Initialize a new instance."""
#         SMTP.__init__(self, host, port, local_hostname=local_hostname,
#                       source_address=source_address)
#
#     def connect(self, host='localhost', port=0, source_address=None):
#         """Connect to the LMTP daemon, on either a Unix or a TCP socket."""
#         if host[0] != '/':
#             return SMTP.connect(self, host, port, source_address=source_address)
#
#         # Handle Unix-domain sockets.
#         try:
#             self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
#             self.file = None
#             self.sock.connect(host)
#         except OSError:
#             if self.debuglevel > 0:
#                 self._print_debug('connect fail:', host)
#             if self.sock:
#                 self.sock.close()
#             self.sock = None
#             raise
#         (code, msg) = self.getreply()
#         if self.debuglevel > 0:
#             self._print_debug('connect:', msg)
#         return (code, msg)
#
#
# Test the sendmail method, which tests most of the others.
# Note: This always sends to localhost.
if __name__ == '__main__':
    def prompt(prompt):
        sys.stdout.write(prompt + ": ")
        sys.stdout.flush()
        return sys.stdin.readline().strip()


    fromaddr = prompt("From")
    toaddrs = prompt("To").split(',')
    print("Enter message, end with ^D:")
    msg = ''
    while 1:
        line = sys.stdin.readline()
        if not line:
            break
        msg = msg + line
    print("Message length is %d" % len(msg))

    server = SMTP('localhost')
    server.set_debuglevel(1)
    server.sendmail(fromaddr, toaddrs, msg)
    server.quit()
