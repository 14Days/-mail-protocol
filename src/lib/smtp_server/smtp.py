import asyncio
import collections
import logging
import socket
import ssl

from asyncio import sslproto
from email._header_value_parser import get_addr_spec, get_angle_addr
from email.errors import HeaderParseError
from warnings import warn

__version__ = '1.0+'
__ident__ = f'Python SMTP {__version__}'
log = logging.getLogger('mail.log')

DATA_SIZE_DEFAULT = 33554432
EMPTYBYTES = b''
NEWLINE = '\n'
MISSING = object()


class Session:
    def __init__(self, loop):
        self.peer = None
        self.ssl = None
        self.host_name = None
        self.extended_smtp = False
        self.loop = loop


class Envelope:
    def __init__(self):
        self.mail_from = None
        self.mail_options = []
        self.smtp_utf8 = False
        self.content = None
        self.original_content = None
        self.rcpt_tos = []
        self.rcpt_options = []


# 创建事件循环
def _make_loop():
    return asyncio.get_event_loop()


def syntax(text, extended=None, when=None):
    def decorator(f):
        f.__smtp_syntax__ = text
        f.__smtp_syntax_extended__ = extended
        f.__smtp_syntax_when__ = when
        return f

    return decorator


class SMTP(asyncio.StreamReaderProtocol):
    """SMTP 服务器的主要内容"""
    command_size_limit = 512
    command_size_limits = collections.defaultdict(
        lambda x=command_size_limit: x)

    def __init__(self, handler,
                 *,
                 data_size_limit=DATA_SIZE_DEFAULT,
                 enable_SMTPUTF8=False,
                 decode_data=False,
                 hostname=None,
                 ident=None,
                 tls_context=None,
                 require_starttls=False,
                 timeout=300,
                 loop=None):
        self.__ident__ = ident or __ident__
        self.loop = loop if loop else _make_loop()
        super().__init__(
            asyncio.StreamReader(loop=self.loop),
            client_connected_cb=self._client_connected_cb,
            loop=self.loop
        )
        self.event_handler = handler
        self.data_size_limit = data_size_limit
        self.enable_SMTPUTF8 = enable_SMTPUTF8
        self._decode_data = decode_data
        self.command_size_limits.clear()
        if hostname:
            self.hostname = hostname
        else:
            self.hostname = socket.getfqdn()
        self.tls_context = tls_context
        if tls_context:
            # 证书检查是SMTP协议的一部分, 而不是SSL层
            self.tls_context.check_hostname = False
            self.tls_context.verify_mode = ssl.CERT_NONE
        self.require_starttls = tls_context and require_starttls
        self._timeout_duration = timeout
        self._timeout_handle = None
        self._tls_handshake_okay = True
        self._tls_protocol = None
        self._original_transport = None
        self.session = None
        self.envelope = None
        self.transport = None
        self._handler_coroutine = None

    def _client_connected_cb(self, reader, writer):
        """其实就是将 client_connected_cb 函数包装了一下不是必要的"""
        self._reader = reader
        self._writer = writer

    def _create_session(self):
        return Session(self.loop)

    def _create_envelope(self):
        return Envelope()

    async def _call_handler_hook(self, command, *args):
        """调用传入的 handler"""
        hook = getattr(self.event_handler, 'handle_' + command, None)
        if hook is None:
            return MISSING
        status = await hook(self, self.session, self.envelope, *args)
        return status

    def _set_post_data_state(self):
        """将状态变量重置为其 post-DATA 状态。"""
        self.envelope = self._create_envelope()

    def _set_rset_state(self):
        """重置除 HELO 之外的所有状态变量"""
        self._set_post_data_state()

    def _timeout_cb(self):
        log.info(f'{self.session.peer} connection timeout')

        # 对 transport 调用 close() 将触发 connection_lost()
        # 这将在需要时正常关闭 SSL 传输并清除状态。
        self.transport.close()

    def _reset_timeout(self):
        if self._timeout_handle is not None:
            self._timeout_handle.cancel()

        self._timeout_handle = self.loop.call_later(self._timeout_duration, self._timeout_cb)

    async def _handle_client(self):
        log.info(f'{self.session.peer} handling connection')
        await self.push(f'220 {self.hostname} {self.__ident__}')
        while self.transport is not None:
            # 如果有数据正在传输
            try:
                # 对命令进行合法性验证
                line = await self._reader.readline()
                log.debug('_handle_client readline: %s', line)
                # 去除行末尾的换行符
                line = line.rstrip(b'\r\n')
                log.info('%r Data: %s', self.session.peer, line)
                if not line:
                    await self.push('500 Error: bad syntax')
                    continue
                i = line.find(b' ')
                # 仅对命令名部分解码为字符串, 该部分必须是符合 RFC 的 ASCII
                # 如果存在参数, 则将其解码为 UTF-8/surrogatescape
                # 以便在处理 SMTP 命令时可以将非 UTF-8 数据重新编码回原始字节。
                if i < 0:
                    try:
                        command = line.upper().decode(encoding='ascii')
                    except UnicodeDecodeError:
                        await self.push('500 Error: bad syntax')
                        continue

                    arg = None
                else:
                    try:
                        command = line[:i].upper().decode(encoding='ascii')
                    except UnicodeDecodeError:
                        await self.push('500 Error: bad syntax')
                        continue

                    arg = line[i + 1:].strip()
                    # 远程 SMTP 服务器可以向我们发送 UTF-8 内容, 不管它们是否已声明这样做
                    # 一些旧服务器可以发送 8 位数据
                    # 使用 SurrogateScape, 以便保留解码的保真度, 并且可以检索原始字节
                    if self.enable_SMTPUTF8:
                        arg = str(arg, encoding='utf-8', errors='surrogateescape')
                    else:
                        try:
                            arg = str(arg, encoding='ascii', errors='strict')
                        except UnicodeDecodeError:
                            # 如果 enable_SMTPUTF8 为 false, 这意味着服务器不想接受非 ASCII
                            # 但是客户端忽略了它并发送非 ASCII
                            await self.push('500 Error: strict ASCII mode')
                            continue
                max_sz = (self.command_size_limits[command]
                          if self.session.extended_smtp
                          else self.command_size_limit)
                # 检查命令是否过长
                if len(line) > max_sz:
                    await self.push('500 Error: line too long')
                    continue
                # 检查是否使用 TLS
                if not self._tls_handshake_okay and command != 'QUIT':
                    await self.push('554 Command refused due to lack of security')
                    continue
                if (self.require_starttls
                        and not self._tls_protocol
                        and command not in ['EHLO', 'STARTTLS', 'QUIT']):
                    # RFC3207 part 4
                    await self.push('530 Must issue a STARTTLS command first')
                    continue
                # 得到对应命令的方法
                method = getattr(self, 'smtp_' + command, None)
                if method is None:
                    await self.push(f'500 Error: command "{command}" not recognized')
                    continue

                # 收到命令, 重置 timer
                self._reset_timeout()
                # 执行对应的方法
                await method(arg)
            except asyncio.CancelledError:
                # 在执行 DATA 命令时, 连接被重置
                # 如果抛出 ConnectionResetError, 我们要验证是否 self._reader 真的被重置
                log.info('Connection lost during _handle_client()')
                self._writer.close()
                raise
            except Exception as error:
                try:
                    status = await self.handle_exception(error)
                    await self.push(status)
                except Exception as error:
                    try:
                        log.exception('Exception in handle_exception()')
                        status = '500 Error: ({}) {}'.format(
                            error.__class__.__name__, str(error))
                    except Exception:
                        status = '500 Error: Cannot describe error'
                    await self.push(status)

    def _strip_command_keyword(self, keyword, arg):
        keylen = len(keyword)
        if arg[:keylen].upper() == keyword:
            return arg[keylen:].strip()
        return None

    def _getaddr(self, arg):
        if not arg:
            return '', ''
        if arg.lstrip().startswith('<'):
            address, rest = get_angle_addr(arg)
        else:
            address, rest = get_addr_spec(arg)
        try:
            address = address.addr_spec
        except IndexError:
            # Workaround http://bugs.python.org/issue27931
            address = None
        return address, rest

    def _getparams(self, params):
        result = {}
        for param in params:
            param, eq, value = param.partition('=')
            if not param.isalnum() or eq and not value:
                return None
            result[param] = value if eq else True
        return result

    def _syntax_available(self, method):
        if getattr(method, '__smtp_syntax__', None) is None:
            return False
        if method.__smtp_syntax_when__:
            return bool(getattr(self, method.__smtp_syntax_when__))
        return True

    @property
    def max_command_size_limit(self):
        try:
            return max(self.command_size_limits.values())
        except ValueError:
            return self.command_size_limit

    async def push(self, status):
        """为客户端返回数据"""
        response = bytes(status + '\r\n', 'utf-8' if self.enable_SMTPUTF8 else 'ascii')
        self._writer.write(response)
        log.debug(response)
        await self._writer.drain()

    async def handle_exception(self, error):
        if hasattr(self.event_handler, 'handle_exception'):
            status = await self.event_handler.handle_exception(error)
            return status
        else:
            log.exception('SMTP session exception')
            status = '500 Error: ({}) {}'.format(error.__class__.__name__, str(error))
            return status

    def connection_made(self, transport) -> None:
        """根据 RFC 3207 重置状态"""
        self._set_rset_state()
        self.session = self._create_session()
        self.session.peer = transport.get_extra_info('peername')
        self._reset_timeout()
        seen_starttls = (self._original_transport is not None)
        if self.transport is not None and seen_starttls:
            # TLS 连接，而不是普通连接
            self._reader._transport = transport
            self._writer._transport = transport
            self.transport = transport
            self.session.ssl = self._tls_protocol._extra
            handler = getattr(self.event_handler, 'handle_STARTTLS', None)
            if handler is None:
                self._tls_handshake_okay = True
            else:
                self._tls_handshake_okay = handler(self, self.session, self.envelope)
        else:
            super().connection_made(transport)
            self.transport = transport
            log.info('Peer: %r', self.session.peer)
            # 处理客户请求
            self._handler_coroutine = self.loop.create_task(self._handle_client())

    def connection_lost(self, error):
        """连接丢失执行的方法"""
        log.info('%r connection lost', self.session.peer)
        self._timeout_handle.cancel()
        # 为了兼容 TLS
        if self._original_transport is not None:
            self._original_transport.close()
        super().connection_lost(error)
        # 取消正在执行的异步方法
        self._handler_coroutine.cancel()
        self.transport = None

    def eof_received(self):
        """收到文件尾执行的操作"""
        log.info('%r EOF received', self.session.peer)
        # 取消正在执行的异步方法
        self._handler_coroutine.cancel()
        if self.session.ssl is not None:
            return False
        return super().eof_received()

    # SMTP and ESMTP commands
    @syntax('HELO hostname')
    async def smtp_HELO(self, hostname):
        if not hostname:
            await self.push('501 Syntax: HELO hostname')
            return
        self._set_rset_state()
        self.session.extended_smtp = False
        status = await self._call_handler_hook('HELO', hostname)
        if status is MISSING:
            self.session.host_name = hostname
            status = '250 {}'.format(self.hostname)
        await self.push(status)

    @syntax('EHLO hostname')
    async def smtp_EHLO(self, hostname):
        if not hostname:
            await self.push('501 Syntax: EHLO hostname')
            return
        self._set_rset_state()
        self.session.extended_smtp = True
        await self.push(f'250-{self.hostname}')
        if self.data_size_limit:
            await self.push(f'250-SIZE {self.data_size_limit}')
            self.command_size_limits['MAIL'] += 26
        if not self._decode_data:
            await self.push('250-8BITMIME')
        if self.enable_SMTPUTF8:
            await self.push('250-SMTPUTF8')
            self.command_size_limits['MAIL'] += 10
        if self.tls_context and not self._tls_protocol:
            await self.push('250-STARTTLS')
        if hasattr(self, 'ehlo_hook'):
            warn('Use handler.handle_EHLO() instead of .ehlo_hook()', DeprecationWarning)
            await self.ehlo_hook()
        status = await self._call_handler_hook('EHLO', hostname)
        if status is MISSING:
            self.session.host_name = hostname
            status = '250 HELP'
        await self.push(status)

    @syntax('NOOP [ignored]')
    async def smtp_NOOP(self, arg):
        status = await self._call_handler_hook('NOOP', arg)
        await self.push('250 OK' if status is MISSING else status)

    @syntax('QUIT')
    async def smtp_QUIT(self, arg):
        if arg:
            await self.push('501 Syntax: QUIT')
        else:
            status = await self._call_handler_hook('QUIT')
            await self.push('221 Bye' if status is MISSING else status)
            self._handler_coroutine.cancel()
            self.transport.close()

    @syntax('STARTTLS', when='tls_context')
    async def smtp_STARTTLS(self, arg):
        log.info('%r STARTTLS', self.session.peer)
        if arg:
            await self.push('501 Syntax: STARTTLS')
            return
        if not self.tls_context:
            await self.push('454 TLS not available')
            return
        await self.push('220 Ready to start TLS')
        # 创建 TLS 层
        self._tls_protocol = sslproto.SSLProtocol(
            self.loop,
            self,
            self.tls_context,
            None,
            server_side=True)
        # 重新配置传输层, 保留对原始传输的引用
        # 以便在连接 lost 时显式关闭
        self._original_transport = self.transport
        self._original_transport._protocol = self._tls_protocol
        # Reconfigure the protocol layer.  Why is the app transport a protected
        # property, if it MUST be used externally?
        self.transport = self._tls_protocol._app_transport
        self._tls_protocol.connection_made(self._original_transport)

    @syntax('HELP [command]')
    async def smtp_HELP(self, arg):
        code = 250
        if arg:
            method = getattr(self, 'smtp_' + arg.upper(), None)
            if method and self._syntax_available(method):
                help_str = method.__smtp_syntax__
                if (self.session.extended_smtp
                        and method.__smtp_syntax_extended__):
                    help_str += method.__smtp_syntax_extended__
                await self.push('250 Syntax: ' + help_str)
                return
            code = 501
        commands = []
        for name in dir(self):
            if not name.startswith('smtp_'):
                continue
            method = getattr(self, name)
            if self._syntax_available(method):
                commands.append(name.lstrip('smtp_'))
        commands.sort()
        await self.push('{} Supported commands: {}'.format(code, ' '.join(commands)))

    @syntax('VRFY <address>')
    async def smtp_VRFY(self, arg):
        if arg:
            try:
                address, params = self._getaddr(arg)
            except HeaderParseError:
                address = None
            if address is None:
                await self.push(f'502 Could not VRFY {arg}')
            else:
                status = await self._call_handler_hook('VRFY', address)
                await self.push('252 Cannot VRFY user, but will accept message and attempt delivery'
                                if status is MISSING else status)
        else:
            await self.push('501 Syntax: VRFY <address>')

    @syntax('MAIL FROM: <address>', extended=' [SP <mail-parameters>]')
    async def smtp_MAIL(self, arg):
        if not self.session.host_name:
            await self.push('503 Error: send HELO first')
            return
        log.debug('===> MAIL %s', arg)
        syntaxerr = '501 Syntax: MAIL FROM: <address>'
        if self.session.extended_smtp:
            syntaxerr += ' [SP <mail-parameters>]'
        if arg is None:
            await self.push(syntaxerr)
            return
        arg = self._strip_command_keyword('FROM:', arg)
        if arg is None:
            await self.push(syntaxerr)
            return
        address, params = self._getaddr(arg)
        if address is None:
            await self.push(syntaxerr)
            return
        if not self.session.extended_smtp and params:
            await self.push(syntaxerr)
            return
        if self.envelope.mail_from:
            await self.push('503 Error: nested MAIL command')
            return
        mail_options = params.upper().split()
        params = self._getparams(mail_options)
        if params is None:
            await self.push(syntaxerr)
            return
        if not self._decode_data:
            body = params.pop('BODY', '7BIT')
            if body not in ['7BIT', '8BITMIME']:
                await self.push(
                    '501 Error: BODY can only be one of 7BIT, 8BITMIME')
                return
        smtputf8 = params.pop('SMTPUTF8', False)
        if not isinstance(smtputf8, bool):
            await self.push('501 Error: SMTPUTF8 takes no arguments')
            return
        if smtputf8 and not self.enable_SMTPUTF8:
            await self.push('501 Error: SMTPUTF8 disabled')
            return
        self.envelope.smtp_utf8 = smtputf8
        size = params.pop('SIZE', None)
        if size:
            if isinstance(size, bool) or not size.isdigit():
                await self.push(syntaxerr)
                return
            elif self.data_size_limit and int(size) > self.data_size_limit:
                await self.push(
                    '552 Error: message size exceeds fixed maximum message '
                    'size')
                return
        if len(params) > 0:
            await self.push(
                '555 MAIL FROM parameters not recognized or not implemented')
            return
        status = await self._call_handler_hook('MAIL', address, mail_options)
        if status is MISSING:
            self.envelope.mail_from = address
            self.envelope.mail_options.extend(mail_options)
            status = '250 OK'
        log.info('%r sender: %s', self.session.peer, address)
        await self.push(status)

    @syntax('RCPT TO: <address>', extended=' [SP <mail-parameters>]')
    async def smtp_RCPT(self, arg):
        if not self.session.host_name:
            await self.push('503 Error: send HELO first')
            return
        log.debug('===> RCPT %s', arg)
        if not self.envelope.mail_from:
            await self.push('503 Error: need MAIL command')
            return
        syntaxerr = '501 Syntax: RCPT TO: <address>'
        if self.session.extended_smtp:
            syntaxerr += ' [SP <mail-parameters>]'
        if arg is None:
            await self.push(syntaxerr)
            return
        arg = self._strip_command_keyword('TO:', arg)
        if arg is None:
            await self.push(syntaxerr)
            return
        address, params = self._getaddr(arg)
        if address is None:
            await self.push(syntaxerr)
            return
        if not address:
            await self.push(syntaxerr)
            return
        if not self.session.extended_smtp and params:
            await self.push(syntaxerr)
            return
        rcpt_options = params.upper().split()
        params = self._getparams(rcpt_options)
        if params is None:
            await self.push(syntaxerr)
            return
        # XXX currently there are no options we recognize.
        if len(params) > 0:
            await self.push(
                '555 RCPT TO parameters not recognized or not implemented')
            return
        status = await self._call_handler_hook('RCPT', address, rcpt_options)
        if status is MISSING:
            self.envelope.rcpt_tos.append(address)
            self.envelope.rcpt_options.extend(rcpt_options)
            status = '250 OK'
        log.info('%r recip: %s', self.session.peer, address)
        await self.push(status)

    @syntax('RSET')
    async def smtp_RSET(self, arg):
        if arg:
            await self.push('501 Syntax: RSET')
            return
        self._set_rset_state()
        if hasattr(self, 'rset_hook'):
            warn('Use handler.handle_RSET() instead of .rset_hook()',
                 DeprecationWarning)
            await self.rset_hook()
        status = await self._call_handler_hook('RSET')
        await self.push('250 OK' if status is MISSING else status)

    @syntax('DATA')
    async def smtp_DATA(self, arg):
        if not self.session.host_name:
            await self.push('503 Error: send HELO first')
            return
        if not self.envelope.rcpt_tos:
            await self.push('503 Error: need RCPT command')
            return
        if arg:
            await self.push('501 Syntax: DATA')
            return
        await self.push('354 End data with <CR><LF>.<CR><LF>')
        data = []
        num_bytes = 0
        size_exceeded = False
        while self.transport is not None:  # pragma: nobranch
            try:
                line = await self._reader.readline()
                log.debug('DATA readline: %s', line)
            except asyncio.CancelledError:
                # The connection got reset during the DATA command.
                log.info('Connection lost during DATA')
                self._writer.close()
                raise
            if line == b'.\r\n':
                break
            num_bytes += len(line)
            if (not size_exceeded and
                    self.data_size_limit and
                    num_bytes > self.data_size_limit):
                size_exceeded = True
                await self.push('552 Error: Too much mail data')
            if not size_exceeded:
                data.append(line)
        if size_exceeded:
            self._set_post_data_state()
            return
        # Remove extraneous carriage returns and de-transparency
        # according to RFC 5321, Section 4.5.2.
        for i in range(len(data)):
            text = data[i]
            if text and text[:1] == b'.':
                data[i] = text[1:]
        content = original_content = EMPTYBYTES.join(data)
        if self._decode_data:
            if self.enable_SMTPUTF8:
                content = original_content.decode(
                    'utf-8', errors='surrogateescape')
            else:
                try:
                    content = original_content.decode('ascii', errors='strict')
                except UnicodeDecodeError:
                    # This happens if enable_smtputf8 is false, meaning that
                    # the server explicitly does not want to accept non-ascii,
                    # but the client ignores that and sends non-ascii anyway.
                    await self.push('500 Error: strict ASCII mode')
                    return
        self.envelope.content = content
        self.envelope.original_content = original_content
        # Call the new API first if it's implemented.
        if hasattr(self.event_handler, 'handle_DATA'):
            status = await self._call_handler_hook('DATA')
        else:
            # Backward compatibility.
            status = MISSING
            if hasattr(self.event_handler, 'process_message'):
                warn('Use handler.handle_DATA() instead of .process_message()',
                     DeprecationWarning)
                args = (self.session.peer, self.envelope.mail_from,
                        self.envelope.rcpt_tos, self.envelope.content)
                if asyncio.iscoroutinefunction(self.event_handler.process_message):
                    status = await self.event_handler.process_message(*args)
                else:
                    status = self.event_handler.process_message(*args)
                # The deprecated API can return None which means, return the
                # default status.  Don't worry about coverage for this case as
                # it's a deprecated API that will go away after 1.0.
                if status is None:  # pragma: nocover
                    status = MISSING
        self._set_post_data_state()
        await self.push('250 OK' if status is MISSING else status)

    # Commands that have not been implemented.
    async def smtp_EXPN(self, arg):
        await self.push('502 EXPN not implemented')
