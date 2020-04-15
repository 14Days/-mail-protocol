# Imports
import errno
import re
import socket

try:
    import ssl

    HAVE_SSL = True
except ImportError:
    HAVE_SSL = False

__all__ = ["POP3", "ErrorProto"]


# 本模块抛出的 Exception:
class ErrorProto(Exception):
    pass


# POP3 的标准端口
POP3_PORT = 110

# POP3 的加密端口
POP3_SSL_PORT = 995

# 定义行结束符 (为了接受出 CRLF 的结束符, 所以分开定义)
CR = b'\r'
LF = b'\n'
CRLF = CR + LF

# 定义调用 readline() 时可以读取的最大的字符数
# 这是为了防止读取任意的行数
# RFC 1939 中限制 POP3 一行最多包含 512 个字符, 包括 CRLF
# 我们选择 2048 作为一个安全的取值
_MAX_LINE = 2048


class POP3:
    encoding = 'UTF-8'

    def __init__(self, host, port=POP3_PORT, timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        self.host = host
        self.port = port
        self._tls_established = False
        self.sock = self._create_socket(timeout)
        self.file = self.sock.makefile('rb')
        self._debugging = 0
        self.welcome = self._get_resp()

    def _create_socket(self, timeout):
        return socket.create_connection((self.host, self.port), timeout)

    # 发送一行消息
    def _put_line(self, line):
        if self._debugging > 0:
            print('*put*', repr(line))
        self.sock.sendall(line + CRLF)

    # 发送 POP3 命令
    def _put_cmd(self, line):
        if self._debugging:
            print('*cmd*', repr(line))
        line = bytes(line, self.encoding)
        self._put_line(line)

    # 从服务中读取一行, 并且剔除 CRLF
    def _get_line(self):
        line = self.file.readline(_MAX_LINE + 1)
        if len(line) > _MAX_LINE:
            raise ErrorProto('line too long')

        if self._debugging > 0:
            print('*get*', repr(line))
        # 表示断开连接
        if not line:
            raise ErrorProto('_ERR EOF')
        octets = len(line)

        # 服务器可以发送 CR 和 LF 的任意组合
        # 但是, "readline()" 返回以 LF 结尾的行
        # 所以只有可能性是 ...LF, ...CRLF, CR...LF
        if line[-2:] == CRLF:
            return line[:-2], octets
        if line[:1] == CR:
            return line[1:-1], octets
        return line[:-1], octets

    # 从服务器得到响应
    def _get_resp(self):
        resp, o = self._get_line()
        if self._debugging > 0:
            print('*resp*', repr(resp))
        # 当响应不是以 + 开始时抛出错误
        if not resp.startswith(b'+'):
            raise ErrorProto(resp)
        return resp

    # 得到较长的响应
    def _getlongresp(self):
        resp = self._get_resp()
        content = []
        octets = 0
        line, o = self._get_line()
        while line != b'.':
            if line.startswith(b'..'):
                o = o - 1
                line = line[1:]
            octets = octets + o
            content.append(line)
            line, o = self._get_line()
        return resp, content, octets

    # 发送一个命令后得到响应
    def _shortcmd(self, line):
        self._put_cmd(line)
        return self._get_resp()

    # 发送命令后得到较长的响应
    def _longcmd(self, line):
        self._put_cmd(line)
        return self._getlongresp()

    # 以下为公开方法

    def getwelcome(self):
        return self.welcome

    def set_debuglevel(self, level):
        self._debugging = level

    # 以下是 POP3 命令

    # 发送用户名
    def user(self, user):
        return self._shortcmd(f'USER {user}')

    # 发送密码
    # 响应中包括消息的条数和邮箱大小
    def pass_(self, password):
        return self._shortcmd(f'PASS {password}')

    # 得到邮箱状态
    def stat(self):
        retval = self._shortcmd('STAT')
        rets = retval.split()
        if self._debugging:
            print('*stat*', repr(rets))
        num_messages = int(rets[1])
        size_messages = int(rets[2])
        return num_messages, size_messages

    # 得到邮件列表
    def list(self, which=None):
        if which is not None:
            return self._shortcmd(f'LIST {which}')
        return self._longcmd('LIST')

    # 取回邮件
    def retr(self, which):
        return self._longcmd(f'RETR {which}')

    # 删除邮件
    def dele(self, which):
        return self._shortcmd(f'DELE {which}')

    # 检测服务是否可用
    def noop(self):
        return self._shortcmd('NOOP')

    # 取消标记所有标记为删除的邮件
    def rset(self):
        return self._shortcmd('RSET')

    # 退出邮件服务
    def quit(self):
        resp = self._shortcmd('QUIT')
        self.close()
        return resp

    # 在不做任何准备的情况下关闭连接
    def close(self):
        try:
            file = self.file
            self.file = None
            if file is not None:
                file.close()
        finally:
            sock = self.sock
            self.sock = None
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError as exc:
                    if (exc.errno != errno.ENOTCONN
                            and getattr(exc, 'winerror', 0) != 10022):
                        raise
                finally:
                    sock.close()

    __del__ = quit

    # 可选的命令

    # 不知道这是做什么的
    def rpop(self, user):
        return self._shortcmd('RPOP %s' % user)

    timestamp = re.compile(br'\+OK.[^<]*(<.*>)')

    # 仅服务器在初始问候语中提供了时间戳才可用
    def apop(self, user, password):
        secret = bytes(password, self.encoding)
        m = self.timestamp.match(self.welcome)
        if not m:
            raise ErrorProto('-ERR APOP not supported by server')

        import hashlib
        digest = m.group(1) + secret
        digest = hashlib.md5(digest).hexdigest()
        return self._shortcmd(f'APOP {user} {digest}')

    # 检索指定消息的开始任意行
    def top(self, which, how_much):
        return self._longcmd(f'TOP {which} {how_much}')

    # 仅仅返回消息标号
    def uidl(self, which=None):
        if which is not None:
            return self._shortcmd(f'UIDL {which}')
        return self._longcmd('UIDL')

    # 尝试使用 UTF-8 编码
    def utf8(self):
        return self._shortcmd('UTF8')

    # 返回服务器能力
    def capa(self):
        def _parse_cap(line):
            lst = line.decode('ascii').split()
            return lst[0], lst[1:]

        caps = {}
        try:
            resp = self._longcmd('CAPA')
            raw_caps = resp[1]
            for cap_line in raw_caps:
                capnm, cap_args = _parse_cap(cap_line)
                caps[capnm] = cap_args
        except ErrorProto as _err:
            raise ErrorProto('-ERR CAPA not supported by server')
        return caps

    # 激活一个 TLS 会话
    def stls(self, context=None):
        if not HAVE_SSL:
            raise ErrorProto('-ERR TLS support missing')
        if self._tls_established:
            raise ErrorProto('-ERR TLS session already established')
        caps = self.capa()
        if 'STLS' not in caps:
            raise ErrorProto('-ERR STLS not supported by server')
        if context is None:
            context = ssl._create_stdlib_context()
        resp = self._shortcmd('STLS')
        self.sock = context.wrap_socket(self.sock,
                                        server_hostname=self.host)
        self.file = self.sock.makefile('rb')
        self._tls_established = True
        return resp


if HAVE_SSL:
    # POP3 的 SSL版本
    class POP3_SSL(POP3):
        def __init__(self, host, port=POP3_SSL_PORT, keyfile=None, certfile=None,
                     timeout=socket._GLOBAL_DEFAULT_TIMEOUT, context=None):
            if context is not None and keyfile is not None:
                raise ValueError("context and keyfile arguments are mutually exclusive")
            if context is not None and certfile is not None:
                raise ValueError("context and certfile arguments are mutually exclusive")
            if keyfile is not None or certfile is not None:
                import warnings
                warnings.warn("keyfile and certfile are deprecated, use a custom context instead", DeprecationWarning,
                              2)
            self.keyfile = keyfile
            self.certfile = certfile
            if context is None:
                context = ssl._create_stdlib_context(certfile=certfile,
                                                     keyfile=keyfile)
            self.context = context
            POP3.__init__(self, host, port, timeout)

        def _create_socket(self, timeout):
            sock = POP3._create_socket(self, timeout)
            sock = self.context.wrap_socket(sock,
                                            server_hostname=self.host)
            return sock

        def stls(self, keyfile=None, certfile=None, context=None):
            # SSL 模式下不能再次建立 SSL 连接
            raise ErrorProto('-ERR TLS session already established')


    __all__.append("POP3_SSL")

if __name__ == "__main__":
    import sys

    a = POP3(sys.argv[1])
    print(a.getwelcome())
    a.user(sys.argv[2])
    a.pass_(sys.argv[3])
    a.list()
    (numMsgs, totalSize) = a.stat()
    for i in range(1, numMsgs + 1):
        (header, msg, octets) = a.retr(i)
        print("Message %d:" % i)
        for line in msg:
            print('   ' + str(line))
        print('-----------------------')
    a.quit()
