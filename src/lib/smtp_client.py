# Imports
import base64
import copy
import datetime
import email.message
import email.generator
import email.utils
import hmac
import io
import re
import socket
import sys

from email.base64mime import body_encode as encode_base64
from email.mime.text import MIMEText

__all__ = ['SMTPException', 'SMTPNotSupportedError', 'SMTPServerDisconnected', 'SMTPResponseException',
           'SMTPSenderRefused', 'SMTPRecipientsRefused', 'SMTPDataError',
           'SMTPConnectError', 'SMTPHeloError', 'SMTPAuthenticationError',
           'quoteaddr', 'quotedata', 'SMTP']

# 定义服务标准端口
SMTP_PORT = 25
SMTP_SSL_PORT = 465
# 定义结束符
CRLF = '\r\n'
bCRLF = b'\r\n'
# 比 RFC 821, 4.5.3 大 8 倍
_MAX_LINE = 8192

OLDSTYLE_AUTH = re.compile(r'auth=(.*)', re.I)


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

    通过属性可以访问每个收件人的错误 '收件人'
    是与 '字典” 类型完全相同的字典 SMTP.sendmail() 返回
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


# Legacy method kept for backward compatibility.
def quotedata(data):
    """Quote data for email."""
    return re.sub(r'(?m)^\.', '..',
                  re.sub(r'(?:\r\n|\n|\r(?!\n))', CRLF, data))


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
    ehlo_msg = 'ehlo'
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
            code, message = self.docmd('QUIT')
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
                raise SMTPServerDisconnected(
                    f'Connection unexpectedly closed: {e}')
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
            if line[3:4] != b'-':
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
        self.putcmd('helo', name or self.local_hostname)
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
            raise SMTPServerDisconnected('Server not connected')
        self.ehlo_resp = msg
        if code != 250:
            return code, msg
        self.does_esmtp = 1

        # 格式化 ehlo 响应
        assert isinstance(self.ehlo_resp, bytes), repr(self.ehlo_resp)
        resp = self.ehlo_resp.decode('latin-1').split('\n')
        del resp[0]
        for each in resp:
            # 为了能够与尽可能多的 SMTP 服务器进行通信, 我们必须考虑老式的身份验证方式, 因为:
            # 1）否则 SMTP 功能解析器会出现错误
            # 2）有些服务器仅支持旧版的 auth 方法
            auth_match = OLDSTYLE_AUTH.match(each)
            if auth_match:
                # 这不会删除重复项, 但这没问题
                self.esmtp_features['auth'] = self.esmtp_features.get('auth', "") \
                                              + ' ' + auth_match.groups(0)[0]
                continue

            # RFC 1869 要求在 ehlo 关键字和参数之间需要一个空格
            # 实际上它非常严格, 因为参数之间只能有空格
            # 如果没有参数, 则不存在空格。
            m = re.match(r'(?P<feature>[A-Za-z0-9][A-Za-z0-9\-]*) ?', each)
            if m:
                feature = m.group('feature').lower()
                params = m.string[m.end('feature'):].strip()
                if feature == 'auth':
                    self.esmtp_features[feature] = self.esmtp_features.get(feature, "") \
                                                   + ' ' + params
                else:
                    self.esmtp_features[feature] = params
        return code, msg

    def has_extn(self, opt):
        """Does the server support a given SMTP service extension?"""
        return opt.lower() in self.esmtp_features

    def help(self, args=''):
        """SMTP 'help' command.
        Returns help text from server."""
        self.putcmd('help', args)
        return self.getreply()[1]

    def rset(self):
        """SMTP 'rset' command -- resets session."""
        self.command_encoding = 'ascii'
        return self.docmd('rset')

    def _rset(self):
        """Internal 'rset' command which ignores any SMTPServerDisconnected error.

        Used internally in the library, since the server disconnected error
        should appear to the application when the *next* command is issued, if
        we are doing an internal 'safety' reset.
        """
        try:
            self.rset()
        except SMTPServerDisconnected:
            pass

    def noop(self):
        """SMTP 'noop' command -- doesn't do anything :>"""
        return self.docmd('noop')

    def mail(self, sender, options=()):
        """SMTP 'mail' command -- begins mail xfer session."""

        option_list = ''
        if options and self.does_esmtp:
            if any(x.lower() == 'smtputf8' for x in options):
                if self.has_extn('smtputf8'):
                    self.command_encoding = 'utf-8'
                else:
                    raise SMTPNotSupportedError(
                        'SMTPUTF8 not supported by server')
            option_list = ' ' + ' '.join(options)
        self.putcmd('mail', f'FROM:{quoteaddr(sender)}{option_list}')
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
        self.putcmd('data')
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
            q = q + b'.' + bCRLF
            self.send(q)
            (code, msg) = self.getreply()
            if self.debuglevel > 0:
                self._print_debug('data:', (code, msg))
            return code, msg

    def verify(self, address):
        """SMTP 'verify' command -- checks for address validity."""
        self.putcmd('vrfy', _addr_only(address))
        return self.getreply()

    # a.k.a.
    vrfy = verify

    def expn(self, address):
        """SMTP 'expn' command -- expands a mailing list."""
        self.putcmd('expn', _addr_only(address))
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
        """Authentication command - requires response processing."""
        mechanism = mechanism.upper()
        initial_response = (authobject() if initial_response_ok else None)
        if initial_response is not None:
            response = encode_base64(initial_response.encode('ascii'), eol='')
            (code, resp) = self.docmd('AUTH', mechanism + ' ' + response)
        else:
            (code, resp) = self.docmd('AUTH', mechanism)
        # If server responds with a challenge, send the response.
        if code == 334:
            challenge = base64.decodebytes(resp)
            response = encode_base64(
                authobject(challenge).encode('ascii'), eol='')
            (code, resp) = self.docmd(response)
        if code in (235, 503):
            return code, resp
        raise SMTPAuthenticationError(code, resp)

    def auth_cram_md5(self, challenge=None):
        """ Authobject to use with CRAM-MD5 authentication. Requires self.user
        and self.password to be set."""
        if challenge is None:
            return None
        return self.user + ' ' + hmac.HMAC(
            self.password.encode('ascii'), challenge, 'md5').hexdigest()

    def auth_plain(self, challenge=None):
        """ Authobject to use with PLAIN authentication. Requires self.user and
        self.password to be set."""
        return '\0%s\0%s' % (self.user, self.password)

    def auth_login(self, challenge=None):
        """ Authobject to use with LOGIN authentication. Requires self.user and
        self.password to be set."""
        if challenge is None:
            return self.user
        else:
            return self.password

    def login(self, user, password, *, initial_response_ok=True):
        """Log in on an SMTP server that requires authentication.

        The arguments are:
            - user:         The user name to authenticate with.
            - password:     The password for the authentication.
        """

        self.ehlo_or_helo_if_needed()
        if not self.has_extn('auth'):
            raise SMTPNotSupportedError(
                'SMTP AUTH extension not supported by server.')

        # 服务器声明支持 Auth
        advertised_authlist = self.esmtp_features['auth'].split()

        # 推荐的鉴权方法, 按照推荐与否排序
        preferred_auths = ['CRAM-MD5', 'PLAIN', 'LOGIN']

        # 实验上面的 auth 方法是否可以使用
        authlist = [auth for auth in preferred_auths
                    if auth in advertised_authlist]
        if not authlist:
            raise SMTPException('No suitable authentication method found.')

        # 使用所有支持的方法进行登录测试
        self.user, self.password = user, password
        for authmethod in authlist:
            method_name = 'auth_' + authmethod.lower().replace('-', '_')
            try:
                (code, resp) = self.auth(
                    authmethod, getattr(self, method_name),
                    initial_response_ok=initial_response_ok)
                # 235 == 'Authentication successful'
                # 503 == 'Error: already authenticated'
                if code in (235, 503):
                    return (code, resp)
            except SMTPAuthenticationError as e:
                last_exception = e

        # 没有登录成功, 抛出最后一次的异常
        raise last_exception

    def starttls(self, keyfile=None, certfile=None, context=None):
        """将会话转换为 TLS 模式"""
        self.ehlo_or_helo_if_needed()
        if not self.has_extn('starttls'):
            raise SMTPNotSupportedError(
                'STARTTLS extension not supported by server.')
        (resp, reply) = self.docmd('STARTTLS')
        if resp == 220:
            if not _have_ssl:
                raise RuntimeError('No SSL support included in this Python')
            if context is not None and keyfile is not None:
                raise ValueError(
                    'context and keyfile arguments are mutually exclusive')
            if context is not None and certfile is not None:
                raise ValueError(
                    'context and certfile arguments are mutually exclusive')
            if keyfile is not None or certfile is not None:
                import warnings
                warnings.warn('keyfile and certfile are deprecated, use a '
                              'custom context instead', DeprecationWarning, 2)
            if context is None:
                context = ssl._create_stdlib_context(certfile=certfile,
                                                     keyfile=keyfile)
            self.sock = context.wrap_socket(self.sock,
                                            server_hostname=self._host)
            self.file = None
            # RFC 3207:
            # The client MUST discard any knowledge obtained from
            # the server, such as the list of SMTP service extensions,
            # which was not obtained from the TLS negotiation itself.
            self.helo_resp = None
            self.ehlo_resp = None
            self.esmtp_features = {}
            self.does_esmtp = 0
        else:
            # RFC 3207:
            # 501 Syntax error (no parameters allowed)
            # 454 TLS not available due to temporary reason
            raise SMTPResponseException(resp, reply)
        return resp, reply

    def sendmail(self, from_addr, to_addrs, msg, mail_options=(), rcpt_options=()):
        """发送邮件的命令

        The arguments are:
            - from_addr    : 寄件人
            - to_addrs     : 收件人列表, 至少有一个
            - msg          : 需要发送的信息
            - mail_options : ESMTP 邮件命令选项 (例如 8bitmime) for the
                             mail command.
            - rcpt_options : ESMTP rcpt命令选项 (例如 DSN 命令)
        """
        self.ehlo_or_helo_if_needed()
        esmtp_opts = []
        if isinstance(msg, str):
            msg = _fix_eols(msg).encode('ascii')
        if self.does_esmtp:
            if self.has_extn('size'):
                esmtp_opts.append('size=%d' % len(msg))
            for option in mail_options:
                esmtp_opts.append(option)
        (code, resp) = self.mail(from_addr, esmtp_opts)
        if code != 250:
            if code == 421:
                self.close()
            else:
                self._rset()
            raise SMTPSenderRefused(code, resp, from_addr)
        senderrs = {}
        if isinstance(to_addrs, str):
            to_addrs = [to_addrs]
        for each in to_addrs:
            (code, resp) = self.rcpt(each, rcpt_options)
            if (code != 250) and (code != 251):
                senderrs[each] = (code, resp)
            if code == 421:
                self.close()
                raise SMTPRecipientsRefused(senderrs)
        if len(senderrs) == len(to_addrs):
            # 服务器拒绝我们所有请求
            self._rset()
            raise SMTPRecipientsRefused(senderrs)
        (code, resp) = self.data(msg)
        if code != 250:
            if code == 421:
                self.close()
            else:
                self._rset()
            raise SMTPDataError(code, resp)
        # 成功发送邮件
        return senderrs

    def send_message(self, msg, from_addr=None, to_addrs=None, mail_options=(), rcpt_options=()):
        """将消息转换为 bytes 字符串"""
        self.ehlo_or_helo_if_needed()
        resent = msg.get_all('Resent-Date')
        if resent is None:
            header_prefix = ''
        elif len(resent) == 1:
            header_prefix = 'Resent-'
        else:
            raise ValueError(
                'message has more than one "Resent - " header block')
        if from_addr is None:
            # Prefer the sender field per RFC 2822:3.6.2.
            from_addr = (msg[header_prefix + 'Sender']
                         if (header_prefix + 'Sender') in msg
                         else msg[header_prefix + 'From'])
            from_addr = email.utils.getaddresses([from_addr])[0][1]
        if to_addrs is None:
            addr_fields = [f for f in (msg[header_prefix + 'To'],
                                       msg[header_prefix + 'Bcc'],
                                       msg[header_prefix + 'Cc'])
                           if f is not None]
            to_addrs = [a[1] for a in email.utils.getaddresses(addr_fields)]
        # Make a local copy so we can delete the bcc headers.
        msg_copy = copy.copy(msg)
        del msg_copy['Bcc']
        del msg_copy['Resent-Bcc']
        international = False
        try:
            ''.join([from_addr, *to_addrs]).encode('ascii')
        except UnicodeEncodeError:
            if not self.has_extn('smtputf8'):
                raise SMTPNotSupportedError(
                    'One or more source or delivery addresses require'
                    ' internationalized email support, but the server'
                    ' does not advertise the required SMTPUTF8 capability')
            international = True
        with io.BytesIO() as bytesmsg:
            if international:
                g = email.generator.BytesGenerator(
                    bytesmsg, policy=msg.policy.clone(utf8=True))
                mail_options = (*mail_options, 'SMTPUTF8', 'BODY=8BITMIME')
            else:
                g = email.generator.BytesGenerator(bytesmsg)
            g.flatten(msg_copy, linesep='\r\n')
            flatmsg = bytesmsg.getvalue()
        return self.sendmail(from_addr, to_addrs, flatmsg, mail_options, rcpt_options)

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

    def quit(self):
        """关闭 SMTP 回话"""
        res = self.docmd('quit')
        # A new EHLO is required after reconnecting with connect()
        self.ehlo_resp = self.helo_resp = None
        self.esmtp_features = {}
        self.does_esmtp = False
        self.close()
        return res


if _have_ssl:

    class SMTP_SSL(SMTP):
        """SMTP 的 SSL 方法"""

        default_port = SMTP_SSL_PORT

        def __init__(self, host='', port=0, local_hostname=None,
                     keyfile=None, certfile=None,
                     timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                     source_address=None, context=None):
            if context is not None and keyfile is not None:
                raise ValueError('context and keyfile arguments are mutually '
                                 'exclusive')
            if context is not None and certfile is not None:
                raise ValueError('context and certfile arguments are mutually '
                                 'exclusive')
            if keyfile is not None or certfile is not None:
                import warnings
                warnings.warn('keyfile and certfile are deprecated, use a '
                              'custom context instead', DeprecationWarning, 2)
            self.keyfile = keyfile
            self.certfile = certfile
            if context is None:
                context = ssl._create_stdlib_context(certfile=certfile,
                                                     keyfile=keyfile)
            self.context = context
            SMTP.__init__(self, host, port, local_hostname, timeout,
                          source_address)

        def _get_socket(self, host, port, timeout):
            if self.debuglevel > 0:
                self._print_debug('connect:', (host, port))
            new_socket = socket.create_connection((host, port), timeout,
                                                  self.source_address)
            new_socket = self.context.wrap_socket(new_socket,
                                                  server_hostname=self._host)
            return new_socket


    __all__.append('SMTP_SSL')

#
# LMTP extension
#
LMTP_PORT = 2003


class LMTP(SMTP):
    """LMTP - Local Mail Transfer Protocol"""

    ehlo_msg = 'lhlo'

    def __init__(self, host='', port=LMTP_PORT, local_hostname=None,
                 source_address=None):
        """Initialize a new instance."""
        SMTP.__init__(self, host, port, local_hostname=local_hostname,
                      source_address=source_address)

    def connect(self, host='localhost', port=0, source_address=None):
        """Connect to the LMTP daemon, on either a Unix or a TCP socket."""
        if host[0] != '/':
            return SMTP.connect(self, host, port, source_address=source_address)

        # Handle Unix-domain sockets.
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.file = None
            self.sock.connect(host)
        except OSError:
            if self.debuglevel > 0:
                self._print_debug('connect fail:', host)
            if self.sock:
                self.sock.close()
            self.sock = None
            raise
        (code, msg) = self.getreply()
        if self.debuglevel > 0:
            self._print_debug('connect:', msg)
        return code, msg


if __name__ == '__main__':
    fromaddr = 'from@runoob.com'
    toaddrs = ['w1637894214@163.com']
    message = MIMEText('Python 邮件发送测试...', 'plain', 'utf-8')

    server = SMTP('localhost', 8025)
    server.set_debuglevel(1)
    server.sendmail(fromaddr, toaddrs, message.as_string())
    server.quit()
