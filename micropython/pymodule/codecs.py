# This module provides partial functionality of the CPython "codecs" module for
# MicroPython.

__all__ = [
    'CodecInfo', 'lookup', 'register', 'ascii_encode', 'ascii_decode'
]


class CodecInfo(object):
    def __init__(self, *args, **kwargs):
        pass


_dummy = CodecInfo()


def lookup(encoding):
    return _dummy


def register(search_function):
    pass


def ascii_encode(string, errors=None):
    if errors is not None:
        data = string.encode('ascii', errors)
    else:
        data = string.encode('ascii')
    return data, len(data)


def ascii_decode(data, errors=None):
    if errors is not None:
        string = data.decode('ascii', errors)
    else:
        string = data.decode('ascii')
    return string, len(string)
