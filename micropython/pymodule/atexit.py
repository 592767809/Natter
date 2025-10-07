# This module provides partial functionality of the CPython "atexit" module for
# MicroPython.

import sys as _usys

__all__ = [
    'register', 'unregister'
]


class _AtExit(object):
    def __init__(self):
        self.regs = []
        _usys.atexit(self._onexit)

    def register(self, func, *args, **kwargs):
        self.regs.append((func, args, kwargs))
        return func

    def unregister(self, func):
        regs_new = []
        for reg in self.regs:
            if reg[0] != func:
                regs_new.append(reg)
        self.regs = regs_new

    def _onexit(self):
        last_ex = None
        for func, args, kwargs in reversed(self.regs):
            try:
                func(*args, **kwargs)
            except Exception as ex:
                last_ex = ex
                _usys.print_exception(ex, _usys.stderr)

        if last_ex:
            raise last_ex from None


_atexit = _AtExit()

register = _atexit.register
unregister = _atexit.unregister
