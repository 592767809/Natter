# This module provides partial functionality of the CPython "errno" module for
# MicroPython.

import _posix

E2BIG               = _posix.E2BIG
EACCES              = _posix.EACCES
EADDRINUSE          = _posix.EADDRINUSE
EADDRNOTAVAIL       = _posix.EADDRNOTAVAIL
EAFNOSUPPORT        = _posix.EAFNOSUPPORT
EAGAIN              = _posix.EAGAIN
EALREADY            = _posix.EALREADY
EBADF               = _posix.EBADF
EBADMSG             = _posix.EBADMSG
EBUSY               = _posix.EBUSY
ECANCELED           = _posix.ECANCELED
ECHILD              = _posix.ECHILD
ECONNABORTED        = _posix.ECONNABORTED
ECONNREFUSED        = _posix.ECONNREFUSED
ECONNRESET          = _posix.ECONNRESET
EDEADLK             = _posix.EDEADLK
EDESTADDRREQ        = _posix.EDESTADDRREQ
EDOM                = _posix.EDOM
EDQUOT              = _posix.EDQUOT
EEXIST              = _posix.EEXIST
EFAULT              = _posix.EFAULT
EFBIG               = _posix.EFBIG
EHOSTUNREACH        = _posix.EHOSTUNREACH
EIDRM               = _posix.EIDRM
EILSEQ              = _posix.EILSEQ
EINPROGRESS         = _posix.EINPROGRESS
EINTR               = _posix.EINTR
EINVAL              = _posix.EINVAL
EIO                 = _posix.EIO
EISCONN             = _posix.EISCONN
EISDIR              = _posix.EISDIR
ELOOP               = _posix.ELOOP
EMFILE              = _posix.EMFILE
EMLINK              = _posix.EMLINK
EMSGSIZE            = _posix.EMSGSIZE
EMULTIHOP           = _posix.EMULTIHOP
ENAMETOOLONG        = _posix.ENAMETOOLONG
ENETDOWN            = _posix.ENETDOWN
ENETRESET           = _posix.ENETRESET
ENETUNREACH         = _posix.ENETUNREACH
ENFILE              = _posix.ENFILE
ENOBUFS             = _posix.ENOBUFS
ENODATA             = _posix.ENODATA
ENODEV              = _posix.ENODEV
ENOENT              = _posix.ENOENT
ENOEXEC             = _posix.ENOEXEC
ENOLCK              = _posix.ENOLCK
ENOLINK             = _posix.ENOLINK
ENOMEM              = _posix.ENOMEM
ENOMSG              = _posix.ENOMSG
ENOPROTOOPT         = _posix.ENOPROTOOPT
ENOSPC              = _posix.ENOSPC
ENOSR               = _posix.ENOSR
ENOSTR              = _posix.ENOSTR
ENOSYS              = _posix.ENOSYS
ENOTCONN            = _posix.ENOTCONN
ENOTDIR             = _posix.ENOTDIR
ENOTEMPTY           = _posix.ENOTEMPTY
ENOTRECOVERABLE     = _posix.ENOTRECOVERABLE
ENOTSOCK            = _posix.ENOTSOCK
ENOTSUP             = _posix.ENOTSUP
ENOTTY              = _posix.ENOTTY
ENXIO               = _posix.ENXIO
EOPNOTSUPP          = _posix.EOPNOTSUPP
EOVERFLOW           = _posix.EOVERFLOW
EOWNERDEAD          = _posix.EOWNERDEAD
EPERM               = _posix.EPERM
EPIPE               = _posix.EPIPE
EPROTO              = _posix.EPROTO
EPROTONOSUPPORT     = _posix.EPROTONOSUPPORT
EPROTOTYPE          = _posix.EPROTOTYPE
ERANGE              = _posix.ERANGE
EROFS               = _posix.EROFS
ESPIPE              = _posix.ESPIPE
ESRCH               = _posix.ESRCH
ESTALE              = _posix.ESTALE
ETIME               = _posix.ETIME
ETIMEDOUT           = _posix.ETIMEDOUT
ETXTBSY             = _posix.ETXTBSY
EWOULDBLOCK         = _posix.EWOULDBLOCK
EXDEV               = _posix.EXDEV


errorcode = dict()

for name, value in locals().items():
    if name.startswith('E') and isinstance(value, int):
        errorcode[value] = name
