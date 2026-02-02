#include <sys/ioctl.h>
#include <errno.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/socket.h>
#include <assert.h>
#include <sys/types.h>
#include <string.h>
#include <stdarg.h>

#include "log.h"
#include "../kernel/inspector.h"

uint64_t kslide = 0;
uint64_t get_kslide(int fd);

int inspector_connect()
{
    struct ctl_info     kernctl_info;
    struct sockaddr_ctl   kernctl_addr;
    int error = 0;

    int sockfd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    assert(sockfd != -1);

    memset(&kernctl_info, 0, sizeof(kernctl_info));
    strlcpy(kernctl_info.ctl_name, INSPECTOR_CONTROL_SOCKET, sizeof(kernctl_info.ctl_name));

    error = ioctl(sockfd, CTLIOCGINFO, &kernctl_info);
    if (error) {
        ERROR("Failed to get the control info for control named \"%s\": %s\n", INSPECTOR_CONTROL_SOCKET, strerror(errno));
        goto done;
    }

    memset(&kernctl_addr, 0, sizeof(kernctl_addr));
    kernctl_addr.sc_len = sizeof(kernctl_addr);
    kernctl_addr.sc_family = AF_SYSTEM;
    kernctl_addr.ss_sysaddr = AF_SYS_CONTROL;
    kernctl_addr.sc_id = kernctl_info.ctl_id;
    kernctl_addr.sc_unit = 0;

    error = connect(sockfd, (struct sockaddr *)&kernctl_addr, sizeof(kernctl_addr));
    if (error) {
        ERROR("Failed to connect to the control socket: %s", strerror(errno));
        goto done;
    }

    kslide = get_kslide(sockfd);
    assert(kslide != 0);

    done:
    if (error && sockfd >= 0) {
        close(sockfd);
        sockfd = -1;
    }

    return sockfd;
}

uint64_t get_kslide(int fd) {
    int error = 0;
    uint64_t slide = 0;
    socklen_t len = sizeof(uint64_t);
    error = getsockopt(fd, SYSPROTO_CONTROL, INSPECTOR_OPT_KSLIDE, &slide, &len);
    if (error != 0) {
        ERROR("kslide error : 0x%x", error);
        return 0;
    }
    return slide;
}


uint64_t get_current_proc(int fd) {
    int error = 0;
    uint64_t proc = 0;
    socklen_t len = sizeof(uint64_t);
    error = getsockopt(fd, SYSPROTO_CONTROL, INSPECTOR_OPT_CURRENT_PROC, &proc, &len);
    if (error != 0) {
        ERROR("current_proc error : 0x%x", error);
        return 0;
    }
    return proc;
}


void *kbase(int fd) {
    if (kslide == 0) {
        kslide = get_kslide(fd);
    }
    return (void*)(KERNEL_BASE + kslide);
}

void kread64(int fd, void *address, uint64_t *value)
{
    struct inspector_opt_krw64 req = {
        .address = address,
        .value = 0
    };
    socklen_t len = sizeof(struct inspector_opt_krw64);
    int error = getsockopt(fd, SYSPROTO_CONTROL, INSPECTOR_OPT_KREAD64, &req, &len);
    if (error != 0) {
        ERROR("kread64 at 0x%016llx, error : 0x%x", (uint64_t)address, error);
        return;
    }

    *value = req.value;
    return;
}

void kwrite64(int fd, uint64_t address, uint64_t value)
{
    struct inspector_opt_krw64 req = {
        .address = (void*)address,
        .value = value
    };

    socklen_t len = sizeof(struct inspector_opt_krw64);
    int error = setsockopt(fd, SYSPROTO_CONTROL, INSPECTOR_OPT_KWRITE64, &req, len);
    if (error != 0) {
        ERROR("kwrite at 0x%016llx, error : 0x%x", address, error);
    }

    return;
}

void kcopyin(int fd, void *kaddress, void *uaddress, uint64_t length)
{
    struct inspector_opt_copy req = {
        .kaddress = kaddress,
        .uaddress = (user_addr_t)uaddress,
        .length = length
    };

    socklen_t len = sizeof(struct inspector_opt_copy);
    int error = setsockopt(fd, SYSPROTO_CONTROL, INSPECTOR_OPT_COPYIN, &req, len);
    if (error != 0) {
        ERROR("kcopyin to 0x%016llx from 0x%016llx, error : 0x%x", (uint64_t)kaddress, (uint64_t)uaddress, error);
    }

    return;
}

void kcopyout(int fd, void *kaddress, void *uaddress, uint64_t length)
{
    struct inspector_opt_copy req = {
        .kaddress = kaddress,
        .uaddress = (user_addr_t)uaddress,
        .length = length
    };

    socklen_t len = sizeof(struct inspector_opt_copy);
    int error = getsockopt(fd, SYSPROTO_CONTROL, INSPECTOR_OPT_COPYOUT, &req, &len);
    if (error != 0) {
        ERROR("kcopyin to 0x%016llx from 0x%016llx, error : 0x%x", (uint64_t)kaddress, (uint64_t)uaddress, error);
    }

    return;
}

uint64_t kcall(int fd, uint64_t func, int num, ...)
{
    va_list ap;
    struct inspector_opt_kcall req = {0};

    req.function = func;

    va_start (ap, num);

    assert(num <= sizeof(req.arg));
    for (int i = 0; i < num; i++) {
        req.arg[i] = va_arg(ap, uint64_t);
    }

    socklen_t len = sizeof(struct inspector_opt_kcall);
    int error = getsockopt(fd, SYSPROTO_CONTROL, INSPECTOR_OPT_KCALL, &req, &len);
    if (error != 0) {
        ERROR("kcall 0x%llx, error : 0x%x", (uint64_t)func, error);
    }

    return req.ret;
}
