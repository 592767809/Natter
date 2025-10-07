# This module provides partial functionality of the CPython "signal" module for
# MicroPython.
import _posix


def signal(signalnum, handler):
    return _posix.signal(signalnum, handler)


SIG_IGN     = _posix.SIG_IGN
SIG_DFL     = _posix.SIG_DFL
SIGABRT     = _posix.SIGABRT
SIGALRM     = _posix.SIGALRM
SIGBUS      = _posix.SIGBUS
SIGCHLD     = _posix.SIGCHLD
SIGCONT     = _posix.SIGCONT
SIGFPE      = _posix.SIGFPE
SIGHUP      = _posix.SIGHUP
SIGILL      = _posix.SIGILL
SIGINT      = _posix.SIGINT
SIGKILL     = _posix.SIGKILL
SIGPIPE     = _posix.SIGPIPE
SIGQUIT     = _posix.SIGQUIT
SIGSEGV     = _posix.SIGSEGV
SIGSTOP     = _posix.SIGSTOP
SIGTERM     = _posix.SIGTERM
SIGTSTP     = _posix.SIGTSTP
SIGTTIN     = _posix.SIGTTIN
SIGTTOU     = _posix.SIGTTOU
SIGUSR1     = _posix.SIGUSR1
SIGUSR2     = _posix.SIGUSR2
SIGPOLL     = _posix.SIGPOLL
SIGPROF     = _posix.SIGPROF
SIGSYS      = _posix.SIGSYS
SIGTRAP     = _posix.SIGTRAP
SIGURG      = _posix.SIGURG
SIGVTALRM   = _posix.SIGVTALRM
SIGXCPU     = _posix.SIGXCPU
SIGXFSZ     = _posix.SIGXFSZ
