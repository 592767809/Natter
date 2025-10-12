#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#if defined(__linux__)
#include <netinet/in.h>
#include <sys/syscall.h>
#include <netinet/tcp.h>
#endif

#include "py/runtime.h"
#include "py/smallint.h"

#if defined(__linux__) && defined(SYS_pidfd_open) && defined(SYS_pidfd_getfd)
#define NATTERUTILS_HAVE_REUSE_PORT
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

#ifdef NATTERUTILS_HAVE_REUSE_PORT
static unsigned long get_inode(int port, int family) {
    const char *paths[] = {
        "/proc/net/tcp",
        "/proc/net/tcp6",
    };
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    FILE *fp;
    int i;

    i = (family == AF_INET6) ? 1 : 0;

    fp = fopen(paths[i], "r");
    if (!fp) {
        return 0;
    }

    nread = getline(&line, &len, fp);
    if (nread < 0) {
        fclose(fp);
        return 0;
    }

    while ((nread = getline(&line, &len, fp)) != -1) {
        int res, local_port, rem_port, d, state, uid, timer_run, timeout;
        unsigned long rxq, txq, time_len, retr, inode;
        char rem_addr[128], local_addr[128];

        res = sscanf(line,
                     "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X "
                     "%X %lX:%lX %X:%lX %lX %d %d %lu %*s\n",
                     &d, local_addr, &local_port, rem_addr, &rem_port, &state,
                     &txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout,
                     &inode);
        if ((res >= 14) && (state == 10) && (local_port == port)) {
            fclose(fp);
            return inode;
        }
    }

    free(line);
    fclose(fp);

    return 0;
}

static int get_pid_fd(unsigned long inode, pid_t *pid, int *fd) {
    struct dirent *dpe;
    char match[256];
    DIR *dp;

    dp = opendir("/proc");
    if (!dp) {
        return -1;
    }

    snprintf(match, sizeof(match) - 1, "socket:[%lu]", inode);

    while ((dpe = readdir(dp))) {
        char path[1024];
        struct dirent *dfe;
        DIR *df;

        if (dpe->d_type != DT_DIR) {
            continue;
        }

        snprintf(path, sizeof(path) - 1, "/proc/%s/fd", dpe->d_name);
        df = opendir(path);
        if (!df) {
            continue;
        }

        while ((dfe = readdir(df))) {
            char name[256];
            int len;

            if (dfe->d_type != DT_LNK) {
                continue;
            }

            snprintf(path, sizeof(path) - 1, "/proc/%s/fd/%s", dpe->d_name,
                     dfe->d_name);
            len = readlink(path, name, sizeof(name) - 1);
            if (len < 0) {
                continue;
            }

            name[len] = '\0';
            if (strcmp(name, match) == 0) {
                *fd = strtoul(dfe->d_name, NULL, 10);
                *pid = strtoul(dpe->d_name, NULL, 10);
                closedir(df);
                closedir(dp);
                return 0;
            }
        }

        closedir(df);
    }

    closedir(dp);

    return -1;
}

static int set_reuse_port(pid_t pid, int fd) {
    const int reuse = 1;
    int pfd;
    int sfd;

    pfd = syscall(SYS_pidfd_open, pid, 0);
    if (pfd < 0) {
        return -1;
    }

    sfd = syscall(SYS_pidfd_getfd, pfd, fd, 0);
    if (sfd < 0) {
        close(pfd);
        return -1;
    }

    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));
    setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(int));

    close(sfd);
    close(pfd);
    return 0;
}

static mp_obj_t natterutils_reuse_port(mp_obj_t port_obj) {
    int types[] = {AF_INET, AF_INET6};
    int result = 0;
    int p;
    size_t i;

    p = mp_obj_get_int(port_obj);

    for (i = 0; i < ARRAY_SIZE(types); i++) {
        unsigned long inode;

        inode = get_inode(p, types[i]);
        if (inode > 0) {
            pid_t pid;
            int res;
            int sfd;

            res = get_pid_fd(inode, &pid, &sfd);
            if (res == 0) {
                result |= set_reuse_port(pid, sfd);
            }
        }
    }

    if (result) {
        mp_raise_OSError(EINVAL);
    }

    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_1(natterutils_reuse_port_obj,
                                 natterutils_reuse_port);
#endif /* NATTERUTILS_HAVE_REUSE_PORT */


static const mp_rom_map_elem_t natterutils_module_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_posix) },

#ifdef NATTERUTILS_HAVE_REUSE_PORT
    { MP_ROM_QSTR(MP_QSTR_reuse_port),
      MP_ROM_PTR(&natterutils_reuse_port_obj) },
#endif /* NATTERUTILS_HAVE_REUSE_PORT */
};
static MP_DEFINE_CONST_DICT(natterutils_module_globals,
                            natterutils_module_globals_table);


const mp_obj_module_t natterutils_user_cmodule = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *) &natterutils_module_globals,
};

MP_REGISTER_MODULE(MP_QSTR_natterutils, natterutils_user_cmodule);
