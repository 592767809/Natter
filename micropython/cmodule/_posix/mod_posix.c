#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>

#include "py/runtime.h"
#include "py/smallint.h"


/*
    Module "_posix".
    This module provides the most common POSIX functions and system calls for
    MicroPython.
*/


#define MP_OBJ_NEW_INT_LL(value) \
    ((MP_SMALL_INT_FITS(value)) ? (mp_obj_new_int(value)) : \
                                  (mp_obj_new_int_from_ll(value)))

/*
    extern char **environ;
*/

static mp_obj_t posixmod__environ(void) {
    extern char **environ;

    mp_obj_t environ_list_obj;
    char **ptr;

    environ_list_obj = mp_obj_new_list(0, NULL);
    for (ptr = environ; *ptr; ptr++) {
        mp_obj_list_append(environ_list_obj,
                           mp_obj_new_str_from_cstr(*ptr));
    }

    return environ_list_obj;
}
static MP_DEFINE_CONST_FUN_OBJ_0(posixmod__environ_obj, posixmod__environ);


/*
    <fcntl.h>
*/

static mp_obj_t posixmod_fcntl(mp_obj_t fd_obj, mp_obj_t cmd_obj,
                              mp_obj_t flags_obj) {
    int res, fd, cmd, flags;

    fd = mp_obj_get_int(fd_obj);
    cmd = mp_obj_get_int(cmd_obj);

    switch (cmd)
    {
    case F_DUPFD:
    case F_GETFL:
    case F_GETFD:
    case F_GETOWN:
        res = fcntl(fd, cmd);
        if (res == -1) {
            mp_raise_OSError(errno);
        }
        return mp_obj_new_int(res);

    case F_SETFL:
    case F_SETFD:
    case F_SETOWN:
        flags = mp_obj_get_int(flags_obj);
        res = fcntl(fd, cmd, flags);
        if (res == -1) {
            mp_raise_OSError(errno);
        }
        return mp_obj_new_int(res);

    default:
        mp_raise_NotImplementedError(MP_ERROR_TEXT("fcntl() for specified cmd "
                                                   "is not implemented"));
        return mp_const_none;
    }
}
static MP_DEFINE_CONST_FUN_OBJ_3(posixmod_fcntl_obj, posixmod_fcntl);


static mp_obj_t posixmod_open(mp_obj_t path_obj, mp_obj_t flags_obj,
                             mp_obj_t mode_obj) {
    int fd, flags;
    long long mode_ll;
    mode_t mode;
    const char *path;

    path = mp_obj_str_get_str(path_obj);
    flags = mp_obj_get_int(flags_obj);
    mode_ll = mp_obj_get_ll(mode_obj);
    mode = (mode_t) mode_ll;
    if (mode_ll != mode /* overflow */) {
        mp_raise_msg(&mp_type_OverflowError,
                     MP_ERROR_TEXT("overflow converting integer to mode_t"));
    }

    fd = open(path, flags, mode);
    if (fd < 0) {
        mp_raise_OSError(errno);
    }

    return mp_obj_new_int(fd);
}
static MP_DEFINE_CONST_FUN_OBJ_3(posixmod_open_obj, posixmod_open);


/*
    <netdb.h>
*/

static mp_obj_t posixmod_gai_strerror(mp_obj_t errnum_obj) {
    char buf[64];
    int errnum;
    const char *errstr;

    errnum = mp_obj_get_int(errnum_obj);
    errno = 0;
    errstr = gai_strerror(errnum);
    if (errno || !errstr) {
        snprintf(buf, sizeof(buf), "Unknown error %d", errnum);
        errstr = buf;
    }

    return mp_obj_new_str_from_cstr(errstr);
}
static MP_DEFINE_CONST_FUN_OBJ_1(posixmod_gai_strerror_obj,
                                 posixmod_gai_strerror);


static mp_obj_t posixmod_getaddrinfo(size_t n_args, const mp_obj_t *args) {
    int res, family, type, proto, flags;
    const char *host, *port;
    struct addrinfo hints, *pai, *p;
    mp_obj_t ai_items[5], tuple_obj, ret_obj;

    if (n_args != 6) {
        mp_raise_ValueError(NULL);
    }

    ret_obj = mp_obj_new_list(0, NULL);

    host = mp_obj_str_get_str(args[0]);
    port = mp_obj_str_get_str(args[1]);
    family = mp_obj_get_int(args[2]);
    type = mp_obj_get_int(args[3]);
    proto = mp_obj_get_int(args[4]);
    flags = mp_obj_get_int(args[5]);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = type;
    hints.ai_protocol = proto;
    hints.ai_flags = flags;

    res = getaddrinfo(host, port, &hints, &pai);
    if (res) {
        mp_raise_OSError(res);
    }

    for (p = pai; p; p = p->ai_next) {
        ai_items[0] = mp_obj_new_int(pai->ai_family);
        ai_items[1] = mp_obj_new_int(pai->ai_socktype);
        ai_items[2] = mp_obj_new_int(pai->ai_protocol);
        if (pai->ai_canonname) {
            ai_items[3] = mp_obj_new_str_from_cstr(pai->ai_canonname);
        } else {
            ai_items[3] = mp_obj_new_str(NULL, 0);
        }
        ai_items[4] = mp_obj_new_bytearray(pai->ai_addrlen, pai->ai_addr);

        tuple_obj = mp_obj_new_tuple(5, ai_items);
        mp_obj_list_append(ret_obj, tuple_obj);
    }

    freeaddrinfo(pai);

    return ret_obj;
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(posixmod_getaddrinfo_obj, 6, 6,
                                           posixmod_getaddrinfo);


static mp_obj_t posixmod_getnameinfo(mp_obj_t sockaddr_obj,
                                    mp_obj_t flags_obj) {
    int res, flags;
    mp_buffer_info_t bufinfo;
    char host[NI_MAXHOST] = {0}, service[NI_MAXSERV] = {0};
    mp_obj_t ret_items[2];

    mp_get_buffer_raise(sockaddr_obj, &bufinfo, MP_BUFFER_READ);
    flags = mp_obj_get_int(flags_obj);

    res = getnameinfo((struct sockaddr *) bufinfo.buf, bufinfo.len, host,
                      sizeof(host), service, sizeof(service), flags);
    if (res) {
        mp_raise_OSError(res);
    }

    ret_items[0] = mp_obj_new_str_from_cstr(host);
    ret_items[1] = mp_obj_new_str_from_cstr(service);

    return mp_obj_new_tuple(2, ret_items);
}
static MP_DEFINE_CONST_FUN_OBJ_2(posixmod_getnameinfo_obj,
                                 posixmod_getnameinfo);


/*
    <signal.h>
*/

static mp_obj_t sigdict_obj = NULL;

static void sighandler(int signalnum) {
    if (!sigdict_obj) {
        return;
    }
    mp_obj_t signalnum_obj = mp_obj_new_int(signalnum);
    mp_map_elem_t *elem = mp_map_lookup(&((mp_obj_dict_t *) sigdict_obj)->map,
                                        signalnum_obj, MP_MAP_LOOKUP);
    if (!elem || !elem->value || !mp_obj_is_callable(elem->value)) {
        return;
    }
    mp_call_function_2(elem->value, signalnum_obj, mp_const_none);
}

static mp_obj_t posixmod_signal(mp_obj_t signalnum_obj, mp_obj_t handler_obj) {
    int signalnum;
    long long handler_ll;
    sighandler_t handler;
    mp_map_elem_t *elem;
    mp_obj_t old_handler_obj;

    if (!sigdict_obj) {
        sigdict_obj = mp_obj_new_dict(0);
    }

    if (!mp_obj_is_int(signalnum_obj)) {
        mp_raise_TypeError(MP_ERROR_TEXT("signalnum must be an interger"));
    }
    signalnum = mp_obj_get_int(signalnum_obj);

    elem = mp_map_lookup(&((mp_obj_dict_t *) sigdict_obj)->map, signalnum_obj,
                         MP_MAP_LOOKUP);
    if (elem && elem->value) {
        old_handler_obj = elem->value;
    } else {
        old_handler_obj = MP_OBJ_NEW_INT_LL((intptr_t) SIG_DFL);
    }

    if (mp_obj_is_callable(handler_obj)) {
        handler = sighandler;
    } else {
        handler_ll = mp_obj_get_ll(handler_obj);
        handler = (sighandler_t) (intptr_t) handler_ll;
        if ((handler_ll != (intptr_t) handler /* overflow */) ||
            (handler != SIG_IGN && handler != SIG_DFL)) {
            mp_raise_TypeError(MP_ERROR_TEXT("signal handler must be SIG_IGN, "
                                             "SIG_DFL, or a callable object"));
        }
    }

    if (signal(signalnum, handler) == SIG_ERR) {
        mp_raise_OSError(errno);
    }

    mp_obj_dict_store(sigdict_obj, signalnum_obj, handler_obj);

    return old_handler_obj;
}
static MP_DEFINE_CONST_FUN_OBJ_2(posixmod_signal_obj, posixmod_signal);


static mp_obj_t posixmod_kill(mp_obj_t pid_obj, mp_obj_t sig_obj) {
    int res, sig;
    long long pid_ll;
    pid_t pid;

    pid_ll = mp_obj_get_ll(pid_obj);
    pid = (pid_t) pid_ll;
    if (pid != pid_ll /* overflow */) {
        mp_raise_msg(&mp_type_OverflowError,
                     MP_ERROR_TEXT("overflow converting integer to pid_t"));
    }
    sig = mp_obj_get_int(sig_obj);

    res = kill(pid, sig);
    if (res) {
        mp_raise_OSError(errno);
    }

    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_2(posixmod_kill_obj, posixmod_kill);


/*
    <string.h>
*/

static mp_obj_t posixmod_strerror(mp_obj_t errnum_obj) {
    char buf[64];
    int errnum;
    const char *errstr;

    errnum = mp_obj_get_int(errnum_obj);
    errno = 0;
    errstr = strerror(errnum);
    if (errno || !errstr) {
        snprintf(buf, sizeof(buf), "Unknown error %d", errnum);
        errstr = buf;
    }

    return mp_obj_new_str_from_cstr(errstr);
}
static MP_DEFINE_CONST_FUN_OBJ_1(posixmod_strerror_obj, posixmod_strerror);


/*
    <sys/socket.h>
*/

static mp_obj_t posixmod_getpeername(mp_obj_t fd_obj) {
    int res, fd;
    struct sockaddr_storage addr;
    socklen_t addr_len;

    fd = mp_obj_get_int(fd_obj);
    addr_len = sizeof(addr);

    res = getpeername(fd, (struct sockaddr *) &addr, &addr_len);
    if (res) {
        mp_raise_OSError(errno);
    }

    return mp_obj_new_bytearray(addr_len, &addr);
}
static MP_DEFINE_CONST_FUN_OBJ_1(posixmod_getpeername_obj,
                                 posixmod_getpeername);


static mp_obj_t posixmod_getsockname(mp_obj_t fd_obj) {
    int res, fd;
    struct sockaddr_storage addr;
    socklen_t addr_len;

    fd = mp_obj_get_int(fd_obj);
    addr_len = sizeof(addr);

    res = getsockname(fd, (struct sockaddr *) &addr, &addr_len);
    if (res) {
        mp_raise_OSError(errno);
    }

    return mp_obj_new_bytearray(addr_len, &addr);
}
static MP_DEFINE_CONST_FUN_OBJ_1(posixmod_getsockname_obj,
                                 posixmod_getsockname);


static mp_obj_t posixmod_shutdown(mp_obj_t fd_obj, mp_obj_t how_obj) {
    int res, fd, how;

    fd = mp_obj_get_int(fd_obj);
    how = mp_obj_get_int(how_obj);

    res = shutdown(fd, how);
    if (res) {
        mp_raise_OSError(errno);
    }

    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_2(posixmod_shutdown_obj, posixmod_shutdown);


/*
    <sys/stat.h>
*/

static mp_obj_t posixmod_lstat(mp_obj_t path_obj) {
    int res;
    const char *path;
    struct stat statbuf;
    mp_obj_t ret[10];

    path = mp_obj_str_get_str(path_obj);

    res = lstat(path, &statbuf);
    if (res) {
        mp_raise_OSError(errno);
    }

    ret[0] = MP_OBJ_NEW_INT_LL(statbuf.st_mode);
    ret[1] = MP_OBJ_NEW_INT_LL(statbuf.st_ino);
    ret[2] = MP_OBJ_NEW_INT_LL(statbuf.st_dev);
    ret[3] = MP_OBJ_NEW_INT_LL(statbuf.st_nlink);
    ret[4] = MP_OBJ_NEW_INT_LL(statbuf.st_uid);
    ret[5] = MP_OBJ_NEW_INT_LL(statbuf.st_gid);
    ret[6] = MP_OBJ_NEW_INT_LL(statbuf.st_size);
    ret[7] = MP_OBJ_NEW_INT_LL(statbuf.st_atime);
    ret[8] = MP_OBJ_NEW_INT_LL(statbuf.st_mtime);
    ret[9] = MP_OBJ_NEW_INT_LL(statbuf.st_ctime);

    return mp_obj_new_tuple(10, ret);
}
static MP_DEFINE_CONST_FUN_OBJ_1(posixmod_lstat_obj, posixmod_lstat);


static mp_obj_t posixmod_stat(mp_obj_t path_obj) {
    int res;
    const char *path;
    struct stat statbuf;
    mp_obj_t ret[10];

    path = mp_obj_str_get_str(path_obj);

    res = stat(path, &statbuf);
    if (res) {
        mp_raise_OSError(errno);
    }

    ret[0] = MP_OBJ_NEW_INT_LL(statbuf.st_mode);
    ret[1] = MP_OBJ_NEW_INT_LL(statbuf.st_ino);
    ret[2] = MP_OBJ_NEW_INT_LL(statbuf.st_dev);
    ret[3] = MP_OBJ_NEW_INT_LL(statbuf.st_nlink);
    ret[4] = MP_OBJ_NEW_INT_LL(statbuf.st_uid);
    ret[5] = MP_OBJ_NEW_INT_LL(statbuf.st_gid);
    ret[6] = MP_OBJ_NEW_INT_LL(statbuf.st_size);
    ret[7] = MP_OBJ_NEW_INT_LL(statbuf.st_atime);
    ret[8] = MP_OBJ_NEW_INT_LL(statbuf.st_mtime);
    ret[9] = MP_OBJ_NEW_INT_LL(statbuf.st_ctime);

    return mp_obj_new_tuple(10, ret);
}
static MP_DEFINE_CONST_FUN_OBJ_1(posixmod_stat_obj, posixmod_stat);


/*
    <sys/utsname.h>
*/

static mp_obj_t posixmod_uname(void) {
    int res;
    struct utsname name;
    mp_obj_t ret[5];

    res = uname(&name);
    if (res < 0) {
        mp_raise_OSError(errno);
    }

    ret[0] = mp_obj_new_str_from_cstr(name.sysname);
    ret[1] = mp_obj_new_str_from_cstr(name.nodename);
    ret[2] = mp_obj_new_str_from_cstr(name.release);
    ret[3] = mp_obj_new_str_from_cstr(name.version);
    ret[4] = mp_obj_new_str_from_cstr(name.machine);

    return mp_obj_new_tuple(5, ret);
}
static MP_DEFINE_CONST_FUN_OBJ_0(posixmod_uname_obj, posixmod_uname);


/*
    <sys/wait.h>
*/

static mp_obj_t posixmod_waitpid(mp_obj_t pid_obj, mp_obj_t options_obj) {
    int status, options;
    long long pid_ll;
    pid_t pid, pid_ret;
    mp_obj_t ret[2];

    pid_ll = mp_obj_get_ll(pid_obj);
    pid = (pid_t) pid_ll;
    if (pid != pid_ll /* overflow */) {
        mp_raise_msg(&mp_type_OverflowError,
                     MP_ERROR_TEXT("overflow converting integer to pid_t"));
    }
    options = mp_obj_get_int(options_obj);

    pid_ret = waitpid(pid, &status, options);
    if (pid_ret < 0) {
        mp_raise_OSError(errno);
    }

    ret[0] = MP_OBJ_NEW_INT_LL(pid_ret);
    ret[1] = mp_obj_new_int(status);

    return mp_obj_new_tuple(2, ret);
}
static MP_DEFINE_CONST_FUN_OBJ_2(posixmod_waitpid_obj, posixmod_waitpid);


/*
    <unistd.h>
*/

static mp_obj_t posixmod__exit(mp_obj_t status_obj) {
    int status;

    status = mp_obj_get_int(status_obj);
    _exit(status);

    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_1(posixmod__exit_obj, posixmod__exit);


static mp_obj_t posixmod_access(mp_obj_t path_obj, mp_obj_t mode_obj) {
    int res, mode;
    const char *path;

    path = mp_obj_str_get_str(path_obj);
    mode = mp_obj_get_int(mode_obj);

    res = access(path, mode);

    return mp_obj_new_bool(!res);
}
static MP_DEFINE_CONST_FUN_OBJ_2(posixmod_access_obj, posixmod_access);


static mp_obj_t posixmod_close(mp_obj_t fd_obj) {
    int res, fd;

    fd = mp_obj_get_int(fd_obj);

    res = close(fd);
    if (res) {
        mp_raise_OSError(errno);
    }

    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_1(posixmod_close_obj, posixmod_close);


static mp_obj_t posixmod_dup(mp_obj_t fd_obj) {
    int fd, fd2;

    fd = mp_obj_get_int(fd_obj);

    fd2 = dup(fd);
    if (fd2 < 0) {
        mp_raise_OSError(errno);
    }

    return mp_obj_new_int(fd2);
}
static MP_DEFINE_CONST_FUN_OBJ_1(posixmod_dup_obj, posixmod_dup);


static mp_obj_t posixmod_dup2(mp_obj_t fd_obj, mp_obj_t fd2_obj) {
    int fd, fd2;

    fd = mp_obj_get_int(fd_obj);
    fd2 = mp_obj_get_int(fd2_obj);

    fd2 = dup2(fd, fd2);
    if (fd2 < 0) {
        mp_raise_OSError(errno);
    }

    return mp_obj_new_int(fd2);
}
static MP_DEFINE_CONST_FUN_OBJ_2(posixmod_dup2_obj, posixmod_dup2);


static mp_obj_t posixmod_execv(mp_obj_t path_obj, mp_obj_t args_obj) {
    int err;
    const char *path, **argv;
    size_t len_args, i;
    mp_obj_t len_args_obj, iter_args, item;
    mp_obj_iter_buf_t iter_buf_args;

    path = mp_obj_str_get_str(path_obj);

    len_args_obj = mp_obj_len(args_obj);
    len_args = mp_obj_get_int(len_args_obj);

    argv = m_new(const char *, len_args + 1);

    i = 0;
    iter_args = mp_getiter(args_obj, &iter_buf_args);
    while (i < len_args &&
           ((item = mp_iternext(iter_args)) != MP_OBJ_STOP_ITERATION)) {
        argv[i++] = mp_obj_str_get_str(item);
    }
    argv[i] = NULL;

    execv(path, (char * const *) argv);

    err = errno;
    m_del(const char *, argv, len_args + 1);
    mp_raise_OSError(err);

    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_2(posixmod_execv_obj, posixmod_execv);


static mp_obj_t posixmod_execve(mp_obj_t path_obj, mp_obj_t args_obj,
                               mp_obj_t env_obj) {
    int err;
    const char *path, **argv, **envp;
    size_t len_args, len_env, i;
    mp_obj_t len_args_obj, len_env_obj, iter_args, iter_env, item;
    mp_obj_iter_buf_t iter_buf_args, iter_buf_env;

    path = mp_obj_str_get_str(path_obj);

    len_args_obj = mp_obj_len(args_obj);
    len_args = mp_obj_get_int(len_args_obj);

    len_env_obj = mp_obj_len(env_obj);
    len_env = mp_obj_get_int(len_env_obj);

    argv = m_new(const char *, len_args + 1);
    envp = m_new(const char *, len_env + 1);

    i = 0;
    iter_args = mp_getiter(args_obj, &iter_buf_args);
    while (i < len_args &&
           ((item = mp_iternext(iter_args)) != MP_OBJ_STOP_ITERATION)) {
        argv[i++] = mp_obj_str_get_str(item);
    }
    argv[i] = NULL;

    i = 0;
    iter_env = mp_getiter(env_obj, &iter_buf_env);
    while (i < len_env &&
           ((item = mp_iternext(iter_env)) != MP_OBJ_STOP_ITERATION)) {
        envp[i++] = mp_obj_str_get_str(item);
    }
    envp[i] = NULL;

    execve(path, (char * const *) argv,
           (char * const *) envp);

    err = errno;

    m_del(const char *, argv, len_args + 1);
    m_del(const char *, envp, len_env + 1);
    mp_raise_OSError(err);

    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_3(posixmod_execve_obj, posixmod_execve);


static mp_obj_t posixmod_execvp(mp_obj_t path_obj, mp_obj_t args_obj) {
    int err;
    const char *path, **argv;
    size_t len_args, i;
    mp_obj_t len_args_obj, iter_args, item;
    mp_obj_iter_buf_t iter_buf_args;

    path = mp_obj_str_get_str(path_obj);

    len_args_obj = mp_obj_len(args_obj);
    len_args = mp_obj_get_int(len_args_obj);

    argv = m_new(const char *, len_args + 1);

    i = 0;
    iter_args = mp_getiter(args_obj, &iter_buf_args);
    while (i < len_args &&
           ((item = mp_iternext(iter_args)) != MP_OBJ_STOP_ITERATION)) {
        argv[i++] = mp_obj_str_get_str(item);
    }
    argv[i] = NULL;

    execvp(path, (char * const *) argv);

    err = errno;
    m_del(const char *, argv, len_args + 1);
    mp_raise_OSError(err);

    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_2(posixmod_execvp_obj, posixmod_execvp);


static mp_obj_t posixmod_execvpe(mp_obj_t path_obj, mp_obj_t args_obj,
                               mp_obj_t env_obj) {
    int err;
    const char *path, **argv, **envp;
    size_t len_args, len_env, i;
    mp_obj_t len_args_obj, len_env_obj, iter_args, iter_env, item;
    mp_obj_iter_buf_t iter_buf_args, iter_buf_env;

    path = mp_obj_str_get_str(path_obj);

    len_args_obj = mp_obj_len(args_obj);
    len_args = mp_obj_get_int(len_args_obj);

    len_env_obj = mp_obj_len(env_obj);
    len_env = mp_obj_get_int(len_env_obj);

    argv = m_new(const char *, len_args + 1);
    envp = m_new(const char *, len_env + 1);

    i = 0;
    iter_args = mp_getiter(args_obj, &iter_buf_args);
    while (i < len_args &&
           ((item = mp_iternext(iter_args)) != MP_OBJ_STOP_ITERATION)) {
        argv[i++] = mp_obj_str_get_str(item);
    }
    argv[i] = NULL;

    i = 0;
    iter_env = mp_getiter(env_obj, &iter_buf_env);
    while (i < len_env &&
           ((item = mp_iternext(iter_env)) != MP_OBJ_STOP_ITERATION)) {
        envp[i++] = mp_obj_str_get_str(item);
    }
    envp[i] = NULL;

    execvpe(path, (char * const *) argv,
           (char * const *) envp);

    err = errno;
    m_del(const char *, argv, len_args + 1);
    m_del(const char *, envp, len_env + 1);
    mp_raise_OSError(err);

    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_3(posixmod_execvpe_obj, posixmod_execvpe);


static mp_obj_t posixmod_fork(void) {
    pid_t child;

    child = fork();
    if (child < 0) {
        mp_raise_OSError(errno);
    }

    return mp_obj_new_int(child);
}
static MP_DEFINE_CONST_FUN_OBJ_0(posixmod_fork_obj, posixmod_fork);


static mp_obj_t posixmod_getuid(void) {
    long long uid;

    uid = getuid();
    return mp_obj_new_int(uid);
}
static MP_DEFINE_CONST_FUN_OBJ_0(posixmod_getuid_obj, posixmod_getuid);


static mp_obj_t posixmod_isatty(mp_obj_t fd_obj) {
    int fd;

    fd = mp_obj_get_int(fd_obj);

    return mp_obj_new_bool(isatty(fd));
}
static MP_DEFINE_CONST_FUN_OBJ_1(posixmod_isatty_obj, posixmod_isatty);


static mp_obj_t posixmod_pipe(void) {
    int res, pipefd[2];
    mp_obj_t pipefd_obj[2];

    res = pipe(pipefd);
    if (res) {
        mp_raise_OSError(errno);
    }
    pipefd_obj[0] = mp_obj_new_int(pipefd[0]);
    pipefd_obj[1] = mp_obj_new_int(pipefd[1]);

    return mp_obj_new_tuple(2, pipefd_obj);
}
static MP_DEFINE_CONST_FUN_OBJ_0(posixmod_pipe_obj, posixmod_pipe);


static mp_obj_t posixmod_read(mp_obj_t fd_obj, mp_obj_t nbyte_obj) {
    int fd, err;
    long long nbyte_ll;
    size_t nbyte;
    ssize_t nread;
    byte *buf;
    mp_obj_t ret;

    fd = mp_obj_get_int(fd_obj);
    nbyte_ll = mp_obj_get_ll(nbyte_obj);
    nbyte = (size_t) nbyte_ll;
    if (nbyte_ll != (long long) nbyte /* overflow */) {
        mp_raise_msg(&mp_type_OverflowError,
                     MP_ERROR_TEXT("overflow converting integer to size_t"));
    }

    buf = m_new(byte, nbyte);
    nread = read(fd, buf, nbyte);
    if (nread < 0) {
        err = errno;
        m_del(byte, buf, nbyte);
        mp_raise_OSError(err);
    }

    ret = mp_obj_new_bytes(buf, nread);
    m_del(byte, buf, nbyte);

    return ret;
}
static MP_DEFINE_CONST_FUN_OBJ_2(posixmod_read_obj, posixmod_read);


static mp_obj_t posixmod_readlink(mp_obj_t path_obj) {
    const char *path;
    char buf[PATH_MAX + 1];
    ssize_t len;

    path = mp_obj_str_get_str(path_obj);

    len = readlink(path, buf, sizeof(buf));
    if (len < 0) {
        mp_raise_OSError(errno);
    } else if (len > PATH_MAX) {
        mp_raise_OSError(ENAMETOOLONG);
    }
    buf[len] = 0;

    return mp_obj_new_str_from_cstr(buf);
}
static MP_DEFINE_CONST_FUN_OBJ_1(posixmod_readlink_obj, posixmod_readlink);


static mp_obj_t posixmod_write(mp_obj_t fd_obj, mp_obj_t str_obj) {
    int fd;
    ssize_t written;
    mp_buffer_info_t bufinfo;

    fd = mp_obj_get_int(fd_obj);
    mp_get_buffer_raise(str_obj, &bufinfo, MP_BUFFER_READ);

    written = write(fd, bufinfo.buf, bufinfo.len);
    if (written < 0) {
        mp_raise_OSError(errno);
    }

    return MP_OBJ_NEW_INT_LL(written);
}
static MP_DEFINE_CONST_FUN_OBJ_2(posixmod_write_obj, posixmod_write);


#define DEFINE_FUN_FOR_MACRO(name, type) \
    static mp_obj_t posixmod_##name(mp_obj_t in) { \
        return mp_obj_new_##type(name(mp_obj_get_int(in))); \
    } \
    static MP_DEFINE_CONST_FUN_OBJ_1(posixmod_##name##_obj, posixmod_##name)

/*
    <sys/stat.h>
*/
DEFINE_FUN_FOR_MACRO(S_ISBLK, bool);
DEFINE_FUN_FOR_MACRO(S_ISCHR, bool);
DEFINE_FUN_FOR_MACRO(S_ISDIR, bool);
DEFINE_FUN_FOR_MACRO(S_ISFIFO, bool);
DEFINE_FUN_FOR_MACRO(S_ISREG, bool);
DEFINE_FUN_FOR_MACRO(S_ISLNK, bool);
DEFINE_FUN_FOR_MACRO(S_ISSOCK, bool);

/*
    <sys/wait.h>
*/
DEFINE_FUN_FOR_MACRO(WIFEXITED, bool);
DEFINE_FUN_FOR_MACRO(WEXITSTATUS, int);
DEFINE_FUN_FOR_MACRO(WIFSIGNALED, bool);
DEFINE_FUN_FOR_MACRO(WTERMSIG, int);
DEFINE_FUN_FOR_MACRO(WIFSTOPPED, bool);
DEFINE_FUN_FOR_MACRO(WSTOPSIG, int);
DEFINE_FUN_FOR_MACRO(WIFCONTINUED, bool);

#undef DEFINE_FUN_FOR_MACRO

static const mp_rom_map_elem_t posixmod_module_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_posix) },
#define F(name) { MP_ROM_QSTR(MP_QSTR_##name), \
                  MP_ROM_PTR(&posixmod_##name##_obj) }
    /* extern char **environ; */
    F(_environ),

    /* <fcntl.h> */
    F(fcntl),
    F(open),

    /* <netdb.h> */
    F(gai_strerror),
    F(getaddrinfo),
    F(getnameinfo),

    /* <signal.h> */
    F(signal),
    F(kill),

    /* <string.h> */
    F(strerror),

    /* <sys/socket.h> */
    F(getpeername),
    F(getsockname),
    F(shutdown),

    /* <sys/stat.h> */
    F(lstat),
    F(stat),

    /* <sys/utsname.h> */
    F(uname),

    /* <sys/wait.h> */
    F(waitpid),

    /* <unistd.h> */
    F(_exit),
    F(access),
    F(close),
    F(dup),
    F(dup2),
    F(execv),
    F(execve),
    F(execvp),
    F(execvpe),
    F(fork),
    F(getuid),
    F(isatty),
    F(pipe),
    F(read),
    F(readlink),
    F(write),

    /* <sys/stat.h> function-like macros */
    F(S_ISBLK),
    F(S_ISCHR),
    F(S_ISDIR),
    F(S_ISFIFO),
    F(S_ISREG),
    F(S_ISLNK),
    F(S_ISSOCK),

    /* <sys/wait.h> function-like macros */
    F(WIFEXITED),
    F(WEXITSTATUS),
    F(WIFSIGNALED),
    F(WTERMSIG),
    F(WIFSTOPPED),
    F(WSTOPSIG),
    F(WIFCONTINUED),
#undef F

#define C(name) { MP_ROM_QSTR(MP_QSTR_##name), MP_ROM_INT(name) }
    /* <errno.h> */
    C(E2BIG),
    C(EACCES),
    C(EADDRINUSE),
    C(EADDRNOTAVAIL),
    C(EAFNOSUPPORT),
    C(EAGAIN),
    C(EALREADY),
    C(EBADF),
    C(EBADMSG),
    C(EBUSY),
    C(ECANCELED),
    C(ECHILD),
    C(ECONNABORTED),
    C(ECONNREFUSED),
    C(ECONNRESET),
    C(EDEADLK),
    C(EDESTADDRREQ),
    C(EDOM),
    C(EDQUOT),
    C(EEXIST),
    C(EFAULT),
    C(EFBIG),
    C(EHOSTUNREACH),
    C(EIDRM),
    C(EILSEQ),
    C(EINPROGRESS),
    C(EINTR),
    C(EINVAL),
    C(EIO),
    C(EISCONN),
    C(EISDIR),
    C(ELOOP),
    C(EMFILE),
    C(EMLINK),
    C(EMSGSIZE),
    C(EMULTIHOP),
    C(ENAMETOOLONG),
    C(ENETDOWN),
    C(ENETRESET),
    C(ENETUNREACH),
    C(ENFILE),
    C(ENOBUFS),
    C(ENODATA),
    C(ENODEV),
    C(ENOENT),
    C(ENOEXEC),
    C(ENOLCK),
    C(ENOLINK),
    C(ENOMEM),
    C(ENOMSG),
    C(ENOPROTOOPT),
    C(ENOSPC),
    C(ENOSR),
    C(ENOSTR),
    C(ENOSYS),
    C(ENOTCONN),
    C(ENOTDIR),
    C(ENOTEMPTY),
    C(ENOTRECOVERABLE),
    C(ENOTSOCK),
    C(ENOTSUP),
    C(ENOTTY),
    C(ENXIO),
    C(EOPNOTSUPP),
    C(EOVERFLOW),
    C(EOWNERDEAD),
    C(EPERM),
    C(EPIPE),
    C(EPROTO),
    C(EPROTONOSUPPORT),
    C(EPROTOTYPE),
    C(ERANGE),
    C(EROFS),
    C(ESPIPE),
    C(ESRCH),
    C(ESTALE),
    C(ETIME),
    C(ETIMEDOUT),
    C(ETXTBSY),
    C(EWOULDBLOCK),
    C(EXDEV),

    /* <fcntl.h> */
    C(F_DUPFD),
    C(F_GETFD),
    C(F_SETFD),
    C(F_GETFL),
    C(F_SETFL),
    C(F_GETOWN),
    C(F_SETOWN),
    C(FD_CLOEXEC),
    C(O_CREAT),
    C(O_EXCL),
    C(O_NOCTTY),
    C(O_TRUNC),
    C(O_APPEND),
    C(O_DSYNC),
    C(O_NONBLOCK),
    C(O_RSYNC),
    C(O_SYNC),
    C(O_ACCMODE),
    C(O_RDONLY),
    C(O_RDWR),
    C(O_WRONLY),

    /* <netdb.h> */
    C(AI_PASSIVE),
    C(AI_CANONNAME),
    C(AI_NUMERICHOST),
    C(AI_NUMERICSERV),
    C(AI_V4MAPPED),
    C(AI_ALL),
    C(AI_ADDRCONFIG),
    C(NI_NOFQDN),
    C(NI_NUMERICHOST),
    C(NI_NAMEREQD),
    C(NI_NUMERICSERV),
#ifdef NI_NUMERICSCOPE /* IEEE Std 1003.1-2001/Cor 1-2002 */
    C(NI_NUMERICSCOPE),
#endif
    C(NI_DGRAM),
    C(EAI_AGAIN),
    C(EAI_BADFLAGS),
    C(EAI_FAIL),
    C(EAI_FAMILY),
    C(EAI_MEMORY),
    C(EAI_NONAME),
    C(EAI_SERVICE),
    C(EAI_SOCKTYPE),
    C(EAI_SYSTEM),
    C(EAI_OVERFLOW),

    /* <signal.h> */
    C(SIG_IGN),
    C(SIG_DFL),
    C(SIGABRT),
    C(SIGALRM),
    C(SIGBUS),
    C(SIGCHLD),
    C(SIGCONT),
    C(SIGFPE),
    C(SIGHUP),
    C(SIGILL),
    C(SIGINT),
    C(SIGKILL),
    C(SIGPIPE),
    C(SIGQUIT),
    C(SIGSEGV),
    C(SIGSTOP),
    C(SIGTERM),
    C(SIGTSTP),
    C(SIGTTIN),
    C(SIGTTOU),
    C(SIGUSR1),
    C(SIGUSR2),
    C(SIGPOLL),
    C(SIGPROF),
    C(SIGSYS),
    C(SIGTRAP),
    C(SIGURG),
    C(SIGVTALRM),
    C(SIGXCPU),
    C(SIGXFSZ),

    /* <stdio.h> */
    C(BUFSIZ),

    /* <sys/socket.h> */
    C(AF_INET),
    C(AF_INET6),
    C(AF_UNIX),
    C(AF_UNSPEC),
    C(SHUT_RD),
    C(SHUT_RDWR),
    C(SHUT_WR),
    C(SOCK_DGRAM),
    C(SOCK_RAW),
    C(SOCK_SEQPACKET),
    C(SOCK_STREAM),
    C(SOL_SOCKET),
    C(SO_ACCEPTCONN),
#ifdef SO_BINDTODEVICE /* non-POSIX, Linux >= 2.0.30 */
    C(SO_BINDTODEVICE),
#endif
    C(SO_BROADCAST),
    C(SO_DEBUG),
    C(SO_DONTROUTE),
    C(SO_ERROR),
    C(SO_KEEPALIVE),
    C(SO_LINGER),
    C(SO_OOBINLINE),
    C(SO_RCVBUF),
    C(SO_RCVLOWAT),
    C(SO_RCVTIMEO),
    C(SO_REUSEADDR),
#ifdef SO_REUSEPORT /* non-POSIX, Linux >= 3.9 */
    C(SO_REUSEPORT),
#endif
    C(SO_SNDBUF),
    C(SO_SNDLOWAT),
    C(SO_SNDTIMEO),
    C(SO_TYPE),
    C(SOMAXCONN),
    C(MSG_CTRUNC),
    C(MSG_DONTROUTE),
    C(MSG_EOR),
    C(MSG_OOB),
    C(MSG_PEEK),
    C(MSG_TRUNC),
    C(MSG_WAITALL),

    /* <sys/stat.h> */
    C(S_IFMT),
    C(S_IFBLK),
    C(S_IFCHR),
    C(S_IFIFO),
    C(S_IFREG),
    C(S_IFDIR),
    C(S_IFLNK),
    C(S_IFSOCK),
    C(S_IRWXU),
    C(S_IRUSR),
    C(S_IWUSR),
    C(S_IXUSR),
    C(S_IRWXG),
    C(S_IRGRP),
    C(S_IWGRP),
    C(S_IXGRP),
    C(S_IRWXO),
    C(S_IROTH),
    C(S_IWOTH),
    C(S_IXOTH),
    C(S_ISUID),
    C(S_ISGID),
    C(S_ISVTX),

    /* <sys/wait.h> */
    C(WNOHANG),
    C(WUNTRACED),
    C(WEXITED),
    C(WSTOPPED),
    C(WCONTINUED),
    C(WNOWAIT),

    /* <netinet/in.h> */
    C(IPPROTO_IP),
    C(IPPROTO_IPV6),
    C(IPPROTO_ICMP),
    C(IPPROTO_RAW),
    C(IPPROTO_TCP),
    C(IPPROTO_UDP),
    C(INADDR_ANY),
    C(INADDR_BROADCAST),
    C(INET_ADDRSTRLEN),
    C(INET6_ADDRSTRLEN),
    C(IPV6_JOIN_GROUP),
    C(IPV6_LEAVE_GROUP),
    C(IPV6_MULTICAST_HOPS),
    C(IPV6_MULTICAST_IF),
    C(IPV6_MULTICAST_LOOP),
    C(IPV6_UNICAST_HOPS),
    C(IPV6_V6ONLY),

    /* <netinet/tcp.h> */
    C(TCP_NODELAY),

    /* <unistd.h> */
    C(STDIN_FILENO),
    C(STDOUT_FILENO),
    C(STDERR_FILENO),
    C(F_OK),
    C(R_OK),
    C(W_OK),
    C(X_OK),
#undef C
};
static MP_DEFINE_CONST_DICT(posixmod_module_globals,
                            posixmod_module_globals_table);


const mp_obj_module_t posixmod_user_cmodule = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *) &posixmod_module_globals,
};

MP_REGISTER_MODULE(MP_QSTR__posix, posixmod_user_cmodule);
