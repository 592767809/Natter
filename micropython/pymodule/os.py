# This module provides partial functionality of the CPython "os" module for
# MicroPython.

import sys as _sys
_path = _sys.path
_sys.path = ()
try:
    import os as _uos
finally:
    _sys.path = _path
    del _path

import _posix
import posixpath as path

__all__ = [
    '_Environ', 'altsep', 'chdir', 'curdir', 'defpath', 'devnull', 'environ',
    'extsep', 'getcwd', 'getcwdb', 'getenv', 'linesep', 'listdir', 'lstat',
    'mkdir', 'mount', 'name', 'pardir', 'path', 'pathsep', 'putenv', 'remove',
    'rename', 'rmdir', 'sep', 'stat', 'stat_result', 'system', 'umount',
    'uname', 'uname_result', 'unlink', 'unsetenv', 'urandom'
]


class _Environ(dict):
    def __setitem__(self, key, value):
        _uos.putenv(key, value)
        super().__setitem__(key, value)

    def __delitem__(self, key):
        _uos.unsetenv(key)
        super().__delitem__(key)

    def __repr__(self):
        return 'environ({%s})' % (
            ', '.join(
                '%s: %s' % (repr(key), repr(value))
                for key, value in self.items()
            )
        )


def _createenviron():
    envdict = dict()
    envlist = _posix._environ()
    for env in envlist:
        kv = env.split('=', 1)
        if len(kv) < 2:
            envdict[kv[0]] = ''
        else:
            envdict[kv[0]] = kv[1]
    return _Environ(envdict)


# unicode environ
environ = _createenviron()


del _createenviron


class stat_result(tuple):
    # MicroPython note:
    #   tuple subclass data is passed to __init__ in MicroPython, not __new__,
    #   so attributes are set here.
    def __init__(self, t):
        super().__init__(t)
        self.st_mode  = t[0]
        self.st_ino   = t[1]
        self.st_dev   = t[2]
        self.st_nlink = t[3]
        self.st_uid   = t[4]
        self.st_gid   = t[5]
        self.st_size  = t[6]
        self.st_atime = t[7]
        self.st_mtime = t[8]
        self.st_ctime = t[9]
        self.__frozen__ = True

    def __setattr__(self, name, value):
        if hasattr(self, '__frozen__') and self.__frozen__:
            raise AttributeError("Assignment is not allowed")
        object.__setattr__(self, name, value)

    def __repr__(self):
        return "stat_result(%s)" % repr(super())


class uname_result(tuple):
    # MicroPython note:
    #   tuple subclass data is passed to __init__ in MicroPython, not __new__,
    #   so attributes are set here.
    def __init__(self, t):
        super().__init__(t)
        self.sysname  = t[0]
        self.nodename = t[1]
        self.release  = t[2]
        self.version  = t[3]
        self.machine  = t[4]
        self.__frozen__ = True

    def __setattr__(self, name, value):
        if hasattr(self, '__frozen__') and self.__frozen__:
            raise AttributeError("Assignment is not allowed")
        object.__setattr__(self, name, value)

    def __repr__(self):
        return "uname_result(%s)" % repr(super())


name        = 'posix'
linesep     = '\n'
curdir      = path.curdir
pardir      = path.pardir
extsep      = path.extsep
sep         = path.sep
pathsep     = path.pathsep
defpath     = path.defpath
altsep      = path.altsep
devnull     = path.devnull

chdir       = _uos.chdir
getcwd      = _uos.getcwd
listdir     = _uos.listdir
mkdir       = _uos.mkdir
mount       = _uos.mount
putenv      = _uos.putenv
remove      = _uos.remove
rename      = _uos.rename
rmdir       = _uos.rmdir
system      = _uos.system
umount      = _uos.umount
unlink      = _uos.unlink
unsetenv    = _uos.unsetenv
urandom     = _uos.urandom

isatty = _posix.isatty
getuid = _posix.getuid


def getcwdb():
    return _uos.getcwd().encode()


def getenv(key, default=None):
    return _uos.getenv(key, default)


def stat(path):
    result = _posix.stat(path)
    return stat_result(result)


def lstat(path):
    result = _posix.lstat(path)
    return stat_result(result)


def uname():
    result = _posix.uname()
    return uname_result(result)


def strerror(code):
    return _posix.strerror(code)
