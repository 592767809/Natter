# This module provides partial functionality of the CPython "re" module for
# MicroPython.
# Notes:
#   This module uses MicroPython's builtin regex engine "re1.5".
#   Regular expression syntax supported is a subset of CPython re module.

import sys as _sys
_path = _sys.path
_sys.path = ()
try:
    import re as _ure
finally:
    _sys.path = _path
    del _path

__all__ = [
    'Match', 'Pattern', 'compile', 'findall', 'match', 'search', 'split', 'sub'
]


_default = object()


class Pattern(object):
    _Pattern = type(_ure.compile(''))

    def __init__(self, p, pstring, flags):
        if not isinstance(p, Pattern._Pattern):
            raise TypeError
        self._p = p
        self.pattern = pstring
        self.flags = flags

    def search(self, string, pos=0, endpos=_default):
        if endpos is _default:
            m = self._p.search(string, pos)
        else:
            m = self._p.search(string, pos, endpos)
        if m:
            return Match(m, self, string)

    def match(self, string, pos=0, endpos=_default):
        if endpos is _default:
            m = self._p.match(string, pos)
        else:
            m = self._p.match(string, pos, endpos)
        if m:
            return Match(m, self, string)

    def split(self, string, maxsplit=0):
        return self._p.split(string, maxsplit)

    def sub(self, repl, string, count=0):
        if callable(repl):
            return self._p.sub(lambda m: repl(Match(m, self, string)), string, count)
        else:
            return self._p.sub(repl, string, count)

    def findall(self, string, pos=0, endpos=_default):
        all = []
        def cb(m):
            groups = m.groups()
            if groups and len(groups) > 2:
                all.append(groups)
            else:
                all.append(m.group(0))
            return type(m.string)()

        if endpos is not _default:
            if endpos < pos:
                endpos = pos
            if pos < 0:
                pos = 0
            string = string[pos:endpos]
        elif pos > 0:
            string = string[pos:]
        self.sub(cb, string)
        return all


class Match(object):
    _Match = type(_ure.match('',''))

    def __init__(self, m, re, string):
        if not isinstance(m, Match._Match):
            raise TypeError
        if not isinstance(re, Pattern):
            raise TypeError
        self._m = m
        self.re = re
        self.string = string

    def group(self, *args):
        if not args:
            return self._m.group(0)
        elif len(args) == 1:
            return self._m.group(args[0])
        glist = []
        for idx in args:
            glist.append(self._m.group(idx))
        return tuple(glist)

    def groups(self, default=None):
        if default is None:
            return self._m.groups()
        else:
            glist = list(self._m.groups())
            for i, value in enumerate(glist):
                if value is None:
                    glist[i] = default
            return tuple(glist)


def compile(pattern, flags=0):
    if isinstance(pattern, Pattern):
        return compile(pattern.pattern, flags)
    p = _ure.compile(pattern, flags)
    return Pattern(p, pattern, flags)


def search(pattern, string, flags=0):
    return compile(pattern, flags).search(string)


def match(pattern, string, flags=0):
    return compile(pattern, flags).match(string)


def split(pattern, string, maxsplit=0, flags=0):
    return compile(pattern, flags).split(string, maxsplit)


def sub(pattern, repl, string, count=0, flags=0):
    return compile(pattern, flags).sub(repl, string, count)


def findall(pattern, string, flags=0):
    return compile(pattern, flags).findall(string)
