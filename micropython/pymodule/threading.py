# This module provides partial functionality of the CPython "threading" module
# for MicroPython.

import _thread

__all__ = [
    'Thread', 'active_count', 'current_thread', 'main_thread'
]


class Thread(object):
    _lock = _thread.allocate_lock()
    _active = dict()

    def __init__(self, group=None, target=None, name=None, args=(),
                 kwargs=None):
        if group is not None:
            raise NotImplementedError("group argument must be None for now")
        if kwargs is None:
            kwargs = {}
        self.name = str(name or "unnamed thread")
        self.ident = None
        self._target = target
        self._args = args
        self._kwargs = kwargs
        self._start_called = False
        self._is_started = False
        self._is_stopped = False
        self._initialized = True
        self._join_lck = _thread.allocate_lock()

    def _pre_run(self):
        # this method is internally called inside the child thread
        self._join_lck.acquire()
        self.ident = _thread.get_ident()
        Thread._lock.acquire()
        Thread._active[self.ident] = self
        Thread._lock.release()
        self._is_started = True

    def _post_run(self):
        # this method is internally called inside the child thread
        self._is_stopped = True
        Thread._lock.acquire()
        del Thread._active[self.ident]
        Thread._lock.release()
        self._join_lck.release()

    def run(self):
        try:
            if self._target:
                self._target(*self._args, **self._kwargs)
        finally:
            del self._target, self._args, self._kwargs

    def start(self):
        if not self._initialized:
            raise RuntimeError("thread.__init__() not called")
        if self._start_called:
            raise RuntimeError("threads can only be started once")
        def _entry():
            self._pre_run()
            try:
                self.run()
            finally:
                self._post_run()
        self._start_called = True
        _thread.start_new_thread(_entry, ())

    def is_alive(self):
        if not self._initialized:
            raise RuntimeError("thread.__init__() not called")
        return self._is_started and not self._is_stopped

    def join(self):
        if not self._initialized:
            raise RuntimeError("thread.__init__() not called")
        if not self._is_started:
            raise RuntimeError("cannot join thread before it is started")
        if self.ident == _thread.get_ident():
            raise RuntimeError("cannot join current thread")
        self._join_lck.acquire()
        self._join_lck.release()


class _MainThread(Thread):
    def __init__(self):
        super().__init__(name="MainThread")
        self._start_called = True
        self._pre_run()


_main_thread = _MainThread()


def active_count():
    return len(Thread._active)


def current_thread():
    ident = _thread.get_ident()
    return Thread._active[ident]


def main_thread():
    return _main_thread
