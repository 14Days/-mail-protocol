import asyncio
import logging
import socket

__version__ = '1.0+'
__ident__ = f'Python POP3 {__version__}'
log = logging.getLogger('pop.log')

# 定义行结束符 (为了接受出 CRLF 的结束符, 所以分开定义)
CR = b'\r'
LF = b'\n'
CRLF = CR + LF

# 定义客户端 readline 时可以读取的最大的字符数
# 这是为了防止读取任意的行数
# RFC 1939 中限制 POP3 一行最多包含 512 个字符, 包括 CRLF
# 我们选择 2048 作为一个安全的取值
_MAX_LINE = 2048
MISSING = object()


class Session:
    def __init__(self, loop):
        self.peer = None
        self.status = 0
        self.username = None
        self.del_list = []
        self.loop = loop


# 创建事件循环
def _make_loop():
    return asyncio.get_event_loop()


class POP3(asyncio.StreamReaderProtocol):
    line_size_limit = _MAX_LINE
    command_size_limit = 512
    encoding = 'UTF-8'

    def __init__(self, handler,
                 *,
                 hostname=None,
                 ident=None,
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
        if hostname:
            self.hostname = hostname
        else:
            self.hostname = socket.getfqdn()
        self._timeout_duration = timeout
        self._timeout_handle = None
        self.session = None
        self.transport = None
        self._handler_coroutine = None

    def _client_connected_cb(self, reader, writer):
        """其实就是将 client_connected_cb 函数包装了一下不是必要的"""
        self._reader = reader
        self._writer = writer

    def _create_session(self):
        return Session(self.loop)

    async def _call_handler_hook(self, command, *args):
        """调用传入的 handler"""
        hook = getattr(self.event_handler, 'handle_' + command, None)
        if hook is None:
            return MISSING
        status = await hook(self, self.session, *args)
        return status

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
        await self.push(f'+OK {self.hostname} {self.__ident__}')
        while self.transport is not None:
            # 如果有数据正在传输
            try:
                line = await self._reader.readline()
                log.debug('_handle_client readline: %s', line)
                # 去除行末尾的换行符
                line = line.rstrip(b'\r\n')
                log.info('%r Data: %s', self.session.peer, line)
                if not line:
                    await self.push('-ERR bad syntax')
                    continue
                # 对 bytes 进行编码
                try:
                    line = line.decode(encoding='ascii')
                except UnicodeDecodeError:
                    await self.push('-ERR bad syntax')
                    continue
                # 判断命令是否带参数
                i = line.find(' ')
                if i < 0:
                    command = line.upper()
                    arg = None
                else:
                    command = line[:i].upper()
                    arg = line[i + 1:].strip()
                # 检查命令是否过长
                if len(line) > self.command_size_limit:
                    await self.push('-ERR line too long')
                    continue
                # 得到对应命令的方法
                method = getattr(self, 'pop3_' + command, None)
                if method is None:
                    await self.push(f'-ERR command "{command}" not recognized')
                    continue

                # 收到命令, 重置 timer
                self._reset_timeout()
                # 执行对应的方法
                await method(arg)
            except asyncio.CancelledError:
                # 执行 _handle_client 时连接丢失
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
                        status = f'-ERR ({error.__class__.__name__}) {str(error)}'
                    except Exception:
                        status = '-ERR Cannot describe error'
                    await self.push(status)

    async def push(self, status):
        """为客户端返回数据"""
        response = bytes(status + '\r\n', 'utf-8')
        self._writer.write(response)
        log.debug(response)
        await self._writer.drain()

    async def long_push(self, status):
        for item in status:
            await self.push(item)
        await self.push('.')

    async def choose_push(self, status):
        if isinstance(status, list):
            await self.long_push(status)
        else:
            await self.push(status)

    async def handle_exception(self, error):
        if hasattr(self.event_handler, 'handle_exception'):
            status = await self.event_handler.handle_exception(error)
            return status
        else:
            log.exception('POP3 session exception')
            status = f'-ERR ({error.__class__.__name__}) {str(error)}'
            return status

    def connection_made(self, transport: asyncio.transports.BaseTransport) -> None:
        self.session = self._create_session()
        self.session.peer = transport.get_extra_info('peername')
        self._reset_timeout()

        super().connection_made(transport)
        self.transport = transport
        log.info('Peer: %r', self.session.peer)
        # 处理客户请求
        self._handler_coroutine = self.loop.create_task(self._handle_client())

    def connection_lost(self, exc) -> None:
        """连接丢失执行的方法"""
        log.info('%r connection lost', self.session.peer)
        self._timeout_handle.cancel()

        super().connection_lost(exc)
        # 取消正在执行的异步方法
        self._handler_coroutine.cancel()
        self.transport = None

    def eof_received(self) -> bool:
        """收到文件尾执行的操作"""
        log.info('%r EOF received', self.session.peer)
        # 取消正在执行的异步方法
        self._handler_coroutine.cancel()
        return super().eof_received()

    async def pop3_USER(self, username):
        if not username:
            await self.push('-ERR Syntax: username')
            return
        if self.session.status != 0:
            await self.push('-ERR Syntax: error command')
            return
        status = await self._call_handler_hook('USER', username)
        if status is MISSING:
            status = f'+OK ({self.hostname}): {username}'
        self.session.username = username
        await self.push(status)

    async def pop3_PASS(self, password):
        if not password:
            await self.push('-ERR Syntax: password')
            return
        if self.session.status != 0:
            await self.push('-ERR Syntax: error command')
            return
        if self.session.username is None:
            await self.push('-ERR Please send username first')
            return
        status = await self._call_handler_hook('PASS', self.session.username, password)
        if status is MISSING:
            status = f'+OK welcome {self.session.username}'
        self.session.status = 1
        await self.push(status)

    async def pop3_APOP(self, *args):
        await self.push('-ERR APOP not implemented')

    async def pop3_STAT(self, *args):
        if self.session.status != 1:
            await self.push('-ERR Please auth')
            return
        status = await self._call_handler_hook('STAT')
        if status is MISSING:
            status = f'+OK 0 1000'
        await self.push(status)

    async def pop3_UIDL(self, which):
        if self.session.status != 1:
            await self.push('-ERR Please auth')
            return
        status = await self._call_handler_hook('UIDL', which)
        if status is MISSING:
            status = f'-ERR UIDL not implemented'
            await self.push(status)
        await self.choose_push(status)

    async def pop3_LIST(self, which):
        if self.session.status != 1:
            await self.push('-ERR Please auth')
            return
        status = await self._call_handler_hook('LIST', which)
        if status is MISSING:
            status = f'-ERR LIST not implemented'
            await self.push(status)
        await self.choose_push(status)

    async def pop3_RETR(self, which):
        if self.session.status != 1:
            await self.push('-ERR Please auth')
            return
        if which is None:
            await self.push('-ERR Must send No.')
            return
        try:
            which = int(which)
        except ValueError:
            await self.push('-ERR args error')
            return
        status = await self._call_handler_hook('RETR', which)
        if status is MISSING:
            status = f'-ERR RETR not implemented'
            await self.push(status)
        await self.push(status)

    async def pop3_DELE(self, which):
        if self.session.status != 1:
            await self.push('-ERR Please auth')
            return
        if which is None:
            await self.push('-ERR Must send No.')
            return
        try:
            which = int(which)
        except ValueError:
            await self.push('-ERR args error')
            return
        self.session.del_list.append(which)
        await self.push('+OK core mail')

    async def pop3_RSET(self):
        if self.session.status != 1:
            await self.push('-ERR Please auth')
            return

        self.session.del_list.clear()
        await self.push('+OK core mail')

    async def pop3_TOP(self, arg):
        if self.session.status != 1:
            await self.push('-ERR Please auth')
            return
        if arg:
            which, num = arg.split(' ')
            try:
                which, num = int(which), int(num)
            except ValueError:
                await self.push('-ERR args error')
                return
            status = await self._call_handler_hook('TOP', which, num)
            if status is MISSING:
                status = f'-ERR TOP not implemented'
                await self.push(status)
            await self.push(status)
        else:
            await self.push('-ERR Must send mail ID and line number')

    async def pop3_NOOP(self):
        await self.push('+OK core mail')

    async def pop3_QUIT(self, arg):
        if self.session.status != 1:
            await self.push('-ERR Please auth')
            return
        if arg:
            await self.push('501 Syntax: QUIT')
        else:
            status = await self._call_handler_hook('QUIT')
            await self.push('+OK core mail' if status is MISSING else status)
            self._handler_coroutine.cancel()
            self.transport.close()
