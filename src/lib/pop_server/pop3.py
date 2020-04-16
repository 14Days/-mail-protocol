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
        self.ssl = None
        self.host_name = None
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
        self._tls_handshake_okay = True
        self._tls_protocol = None
        self._original_transport = None
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

    def connection_made(self, transport: asyncio.transports.BaseTransport) -> None:
        self.session = self._create_session()
        self.session.peer = transport.get_extra_info('peername')
        self._reset_timeout()
