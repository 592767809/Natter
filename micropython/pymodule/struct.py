# This module provides partial functionality of the CPython "struct" module for
# MicroPython.

import sys as _sys
_path = _sys.path
_sys.path = ()
try:
    import struct as _ustruct
finally:
    _sys.path = _path
    del _path

__all__ = [
    'calcsize', 'pack', 'pack_into', 'unpack', 'unpack_from'
]


class _StructError(Exception):
    pass


error = _StructError


def pack(format, *args):
    try:
        return _ustruct.pack(format, *args)
    except Exception as ex:
        raise error(ex) from None


def unpack(format, buffer):
    try:
        return _ustruct.unpack(format, buffer)
    except Exception as ex:
        raise error(ex) from None


def pack_into(format, buffer, offset, *args):
    try:
        return _ustruct.pack_into(format, buffer, offset, *args)
    except Exception as ex:
        raise error(ex) from None


def unpack_from(format, buffer, offset=0):
    try:
        return _ustruct.unpack_from(format, buffer, offset)
    except Exception as ex:
        raise error(ex) from None


def calcsize(format):
    try:
        return _ustruct.calcsize(format)
    except Exception as ex:
        raise error(ex) from None
