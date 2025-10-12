# This module provides partial functionality of the CPython "socket" module for
# MicroPython.

import sys as _sys
_path = _sys.path
_sys.path = ()
try:
    import socket as _usocket
finally:
    _sys.path = _path
    del _path

import _posix


class TimeoutError(OSError):
    pass


class gaierror(OSError):
    def __init__(self, *args):
        if len(args) == 1 and isinstance(args[0], int):
            errno = args[0]
            msg = "[Errno %d] %s" %(errno, _posix.gai_strerror(args[0]))
            super().__init__(msg)
            self.errno = errno
        else:
            super().__init__(*args)


class socket(object):
    def __init__(self, family=_posix.AF_INET, type=_posix.SOCK_STREAM,
                 proto=0, *, _sock=None):
        if _sock is not None:
            self._s = _sock
        else:
            self._s = _usocket.socket(family, type, proto)
        self.family = family
        self.type = type
        self.proto = proto
        self._closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        if not self._closed:
            self.close()

    def _is_timeouterror(self, oserr):
        return oserr.errno in [_posix.ETIMEDOUT, _posix.EAGAIN]

    def _arg_addr(self, addr):
        host, port = addr
        if host == '':
            if self.family == _posix.AF_INET:
                host = '0.0.0.0'
            elif self.family == _posix.AF_INET6:
                host = '::'
        if isinstance(port, int):
            port = str(port)
        return _getaddrinfo(
            host, port, self.family, self.type, self.proto,
            _posix.AI_NUMERICSERV
        )[0][4]

    def _ret_addr(self, addr):
        host, serv = _getnameinfo(
            addr, _posix.NI_NUMERICHOST | _posix.NI_NUMERICSERV
        )
        return host, int(serv)

    def fileno(self):
        if self._closed:
            return -1
        return self._s.fileno()

    def bind(self, addr):
        addr = self._arg_addr(addr)
        self._s.bind(addr)

    def listen(self, backlog):
        self._s.listen(backlog)

    def accept(self):
        s, addr = self._s.accept()
        s = socket(self.family, self.type, self.proto, _sock=s)
        addr = self._ret_addr(addr)
        return s, addr

    def connect(self, addr):
        addr = self._arg_addr(addr)
        try:
            self._s.connect(addr)
        except OSError as ex:
            if self._is_timeouterror(ex):
                raise timeout(ex) from None
            raise

    def connect_ex(self, addr):
        try:
            self.connect(addr)
        except OSError as ex:
            return ex.errno
        else:
            return 0

    def send(self, data):
        try:
            return self._s.send(data)
        except OSError as ex:
            if self._is_timeouterror(ex):
                raise timeout(ex) from None
            raise

    def sendto(self, data, addr):
        addr = self._arg_addr(addr)
        try:
            return self._s.sendto(data, addr)
        except OSError as ex:
            if self._is_timeouterror(ex):
                raise timeout(ex) from None
            raise

    def sendall(self, data):
        try:
            tosend = data
            while tosend:
                size = self.send(tosend)
                tosend = tosend[size:]
        except OSError as ex:
            if self._is_timeouterror(ex):
                raise timeout(ex) from None
            raise

    def recv(self, bufsize):
        try:
            return self._s.recv(bufsize)
        except OSError as ex:
            if self._is_timeouterror(ex):
                raise timeout(ex) from None
            raise

    def recvfrom(self, bufsize):
        try:
            data, addr = self._s.recvfrom(bufsize)
        except OSError as ex:
            if self._is_timeouterror(ex):
                raise timeout(ex) from None
            raise
        addr = self._ret_addr(addr)
        return data, addr

    def shutdown(self, how):
        _posix.shutdown(self.fileno(), how)

    def close(self):
        if not self._closed:
            self._s.close()
            self._closed = True

    def getsockname(self):
        addr = _posix.getsockname(self.fileno())
        return self._ret_addr(addr)

    def getpeername(self):
        addr = _posix.getpeername(self.fileno())
        return self._ret_addr(addr)

    def setsockopt(self, level, optname, value):
        return self._s.setsockopt(level, optname, value)

    def settimeout(self, value):
        return self._s.settimeout(value)

    def setblocking(self, flag):
        return self._s.setblocking(flag)


def inet_aton(ip_addr):
    return _usocket.inet_pton(_posix.AF_INET, ip_addr)


def inet_ntoa(packed_ip):
    return _usocket.inet_ntop(_posix.AF_INET, packed_ip)


def gethostbyname_ex(hostname):
    res = _getaddrinfo(
        hostname, "0", _posix.AF_INET, _posix.SOCK_DGRAM, 0,
        _posix.AI_NUMERICSERV
    )
    ipstrs = [
        _getnameinfo(
            rec[4], _posix.NI_NUMERICHOST | _posix.NI_NUMERICSERV
        )[0] for rec in res
    ]
    return (hostname, [], ipstrs)


def _getaddrinfo(*args, **kwargs):
    try:
        return _posix.getaddrinfo(*args, **kwargs)
    except OSError as ex:
        raise gaierror(ex.errno) from None


def _getnameinfo(*args, **kwargs):
    try:
        return _posix.getnameinfo(*args, **kwargs)
    except OSError as ex:
        raise gaierror(ex.errno) from None


error = OSError
timeout = TimeoutError

inet_pton = _usocket.inet_pton
inet_ntop = _usocket.inet_ntop


SOCK_DGRAM          = _posix.SOCK_DGRAM
SOCK_RAW            = _posix.SOCK_RAW
SOCK_SEQPACKET      = _posix.SOCK_SEQPACKET
SOCK_STREAM         = _posix.SOCK_STREAM
SOL_SOCKET          = _posix.SOL_SOCKET
SO_ACCEPTCONN       = _posix.SO_ACCEPTCONN
if hasattr(_posix, 'SO_BINDTODEVICE'):
    SO_BINDTODEVICE = _posix.SO_BINDTODEVICE
SO_BROADCAST        = _posix.SO_BROADCAST
SO_DEBUG            = _posix.SO_DEBUG
SO_DONTROUTE        = _posix.SO_DONTROUTE
SO_ERROR            = _posix.SO_ERROR
SO_KEEPALIVE        = _posix.SO_KEEPALIVE
SO_LINGER           = _posix.SO_LINGER
SO_OOBINLINE        = _posix.SO_OOBINLINE
SO_RCVBUF           = _posix.SO_RCVBUF
SO_RCVLOWAT         = _posix.SO_RCVLOWAT
SO_RCVTIMEO         = _posix.SO_RCVTIMEO
SO_REUSEADDR        = _posix.SO_REUSEADDR
if hasattr(_posix, 'SO_REUSEPORT'):
    SO_REUSEPORT    = _posix.SO_REUSEPORT
SO_SNDBUF           = _posix.SO_SNDBUF
SO_SNDLOWAT         = _posix.SO_SNDLOWAT
SO_SNDTIMEO         = _posix.SO_SNDTIMEO
SO_TYPE             = _posix.SO_TYPE
SOMAXCONN           = _posix.SOMAXCONN
MSG_CTRUNC          = _posix.MSG_CTRUNC
MSG_DONTROUTE       = _posix.MSG_DONTROUTE
MSG_EOR             = _posix.MSG_EOR
MSG_OOB             = _posix.MSG_OOB
MSG_PEEK            = _posix.MSG_PEEK
MSG_TRUNC           = _posix.MSG_TRUNC
MSG_WAITALL         = _posix.MSG_WAITALL
AF_INET             = _posix.AF_INET
AF_INET6            = _posix.AF_INET6
AF_UNIX             = _posix.AF_UNIX
AF_UNSPEC           = _posix.AF_UNSPEC
SHUT_RD             = _posix.SHUT_RD
SHUT_RDWR           = _posix.SHUT_RDWR
SHUT_WR             = _posix.SHUT_WR
IPPROTO_IP          = _posix.IPPROTO_IP
IPPROTO_IPV6        = _posix.IPPROTO_IPV6
IPPROTO_ICMP        = _posix.IPPROTO_ICMP
IPPROTO_RAW         = _posix.IPPROTO_RAW
IPPROTO_TCP         = _posix.IPPROTO_TCP
IPPROTO_UDP         = _posix.IPPROTO_UDP
INADDR_ANY          = _posix.INADDR_ANY
INADDR_BROADCAST    = _posix.INADDR_BROADCAST
INET_ADDRSTRLEN     = _posix.INET_ADDRSTRLEN
INET6_ADDRSTRLEN    = _posix.INET6_ADDRSTRLEN
IPV6_JOIN_GROUP     = _posix.IPV6_JOIN_GROUP
IPV6_LEAVE_GROUP    = _posix.IPV6_LEAVE_GROUP
IPV6_MULTICAST_HOPS = _posix.IPV6_MULTICAST_HOPS
IPV6_MULTICAST_IF   = _posix.IPV6_MULTICAST_IF
IPV6_MULTICAST_LOOP = _posix.IPV6_MULTICAST_LOOP
IPV6_UNICAST_HOPS   = _posix.IPV6_UNICAST_HOPS
IPV6_V6ONLY         = _posix.IPV6_V6ONLY
TCP_NODELAY         = _posix.TCP_NODELAY
