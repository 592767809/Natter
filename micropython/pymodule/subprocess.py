# This module provides partial functionality of the CPython "subprocess" module
# for MicroPython.
# Note: Thread safety is not guaranteed.

import sys as _usys
import _posix

__all__ = [
    'CalledProcessError', 'Popen', 'STDOUT', 'SubprocessError', 'check_output'
]


STDOUT = -2


class SubprocessError(Exception):
    pass


class CalledProcessError(SubprocessError):
    def __init__(self, returncode, cmd, output=None):
        self.returncode = returncode
        self.cmd = cmd
        self.output = output

    def __str__(self):
        return "Command '%s' returned non-zero exit status %d" % (
            self.cmd, self.returncode
        )


def _handle_exitstatus(sts):
    if _posix.WIFSIGNALED(sts):
        return -(_posix.WTERMSIG(sts))
    elif _posix.WIFEXITED(sts):
        return _posix.WEXITSTATUS(sts)
    else:
        # Should never happen
        raise SubprocessError("Unknown child exit status!")


def _close_fd(fd):
    if fd < 0:
        return
    try:
        _posix.close(fd)
        fd = -1
    except OSError as ex:
        _usys.stderr.write('close(): %s\n' % str(ex))
    return fd


def _kill_child(pid, signal):
    if pid <= 0:
        return
    _, sts = _posix.waitpid(pid, _posix.WNOHANG)
    if not sts:
        try:
            _posix.kill(pid, signal)
        except OSError as ex:
            if ex.errno != _posix.ESRCH:
                raise
        _posix.waitpid(pid, 0)


def _set_fd_cloexec(fd):
    flags = _posix.fcntl(fd, _posix.F_GETFD, None)
    _posix.fcntl(fd, _posix.F_SETFD, flags | _posix.FD_CLOEXEC)


def check_output(args, *, stderr=None):
    if stderr is not None and stderr != STDOUT:
        raise NotImplementedError("Unsupported stderr redirection")

    executable = args[0]
    r, w = _posix.pipe()
    er, ew = _posix.pipe()
    _set_fd_cloexec(er)
    _set_fd_cloexec(ew)

    try:
        pid = _posix.fork()
    except Exception:
        _close_fd(r)
        _close_fd(w)
        raise

    if pid == 0:
        # child
        try:
            r = _close_fd(r)
            er = _close_fd(er)
            _posix.dup2(w, _posix.STDOUT_FILENO)
            if stderr == STDOUT:
                _posix.dup2(w, _posix.STDERR_FILENO)
            w = _close_fd(w)
            _posix.execvp(executable, args)
        except OSError as ex:
            _posix.write(ew, str(ex.errno).encode())
        finally:
            _close_fd(r)
            _close_fd(er)
            _close_fd(w)
            _close_fd(ew)
            _posix._exit(1)
    else:
        # parent
        try:
            w = _close_fd(w)
            ew = _close_fd(ew)

            output_l = []
            while True:
                chunk = _posix.read(r, _posix.BUFSIZ)
                if not chunk:
                    break
                output_l.append(chunk)

            errno_l = []
            while True:
                chunk = _posix.read(er, _posix.BUFSIZ)
                if not chunk:
                    break
                errno_l.append(chunk)

            r = _close_fd(r)
            er = _close_fd(er)

            output = b''.join(output_l)
            errno_b = b''.join(errno_l)

            _, status = _posix.waitpid(pid, 0)
            pid = -1

            if errno_b:
                errno = int(errno_b.decode())
                raise OSError(errno)

            retcode = _handle_exitstatus(status)
            if retcode:
                raise CalledProcessError(retcode, args, output)
            return output
        finally:
            _close_fd(r)
            _close_fd(er)
            _close_fd(w)
            _close_fd(ew)
            _kill_child(pid, _posix.SIGKILL)


def call(*args, **kwargs):
    with Popen(args[0]) as p:
        try:
            return p.wait()
        except:
            p.kill()
            p.wait()
            raise


class Popen(object):
    def __init__(self, args):
        self.args = args
        self.pid = None
        self.returncode = None
        self._start_child()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.wait()

    def _start_child(self):
        executable = self.args[0]

        er, ew = _posix.pipe()
        _set_fd_cloexec(er)
        _set_fd_cloexec(ew)

        try:
            pid = _posix.fork()
        except Exception:
            _close_fd(er)
            _close_fd(ew)
            raise

        if pid == 0:
            # child
            try:
                er = _close_fd(er)
                _posix.execvp(executable, self.args)
            except OSError as ex:
                _posix.write(ew, str(ex.errno).encode())
            finally:
                _close_fd(er)
                _close_fd(ew)
                _posix._exit(1)
        else:
            # parent
            self.pid = pid
            try:
                ew = _close_fd(ew)

                errno_l = []
                while True:
                    chunk = _posix.read(er, _posix.BUFSIZ)
                    if not chunk:
                        break
                    errno_l.append(chunk)

                er = _close_fd(er)

                errno_b = b''.join(errno_l)
                if errno_b:
                    errno = int(errno_b.decode())
                    raise OSError(errno)
            except Exception:
                _kill_child(pid, _posix.SIGKILL)
                raise

            finally:
                _close_fd(er)
                _close_fd(ew)

    def poll(self):
        if self.returncode is not None:
            return self.returncode
        try:
            pid, sts = _posix.waitpid(self.pid, _posix.WNOHANG)
            if pid == self.pid:
                self.returncode = _handle_exitstatus(sts)
        except OSError as e:
            if e.errno == _posix.ECHILD:
                self.returncode = 0
        return self.returncode

    def wait(self):
        if self.returncode is not None:
            return self.returncode
        try:
            _, sts = _posix.waitpid(self.pid, 0)
            self.returncode = _handle_exitstatus(sts)
        except OSError as ex:
            if ex.errno != _posix.ECHILD:
                raise
            self.returncode = 0
        return self.returncode

    def send_signal(self, sig):
        self.poll()
        if self.returncode is not None:
            return
        try:
            _posix.kill(self.pid, sig)
        except OSError as ex:
            if ex.errno != _posix.ESRCH:
                raise

    def terminate(self):
        self.send_signal(_posix.SIGTERM)

    def kill(self):
        self.send_signal(_posix.SIGKILL)
