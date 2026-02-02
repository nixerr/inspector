//
//  inspector.c
//  inspector
//
//  Created by Valentin Shilnenkov on 21/6/24.
//

// #include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <sys/kern_control.h>
#include <sys/errno.h>
#include <os/log.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <sys/vm.h>

#include "mod.h"
#include "inspector.h"
#include "kcall.h"

// #include <libkern/copyio.h>

// #include <vm/pmap.h>
// #include <sys/sysproto.h>


kern_return_t inspector_start(kmod_info_t * ki, void *d);
kern_return_t inspector_stop(kmod_info_t *ki, void *d);

extern task_t kernel_task;
extern void *kernproc;
// extern void *task_get_proc_raw(task_t task);

vm_offset_t kernel_slide = 0;


#define DO_LOG 1

#ifdef DO_LOG
#define LOG(S, format, ...) os_log_error(S, format __VA_OPT__(,) __VA_ARGS__)
#else
#define LOG(S, format, ...)
#endif

uint64_t bruteforce_kslide(void)
{
    uint64_t kslide = 0;
    uint64_t start = KERNEL_BASE;
    uint64_t step = 0x4000;
    uint64_t end = start + step * 0x100000;
    while (start < end) {
        vm_offset_t unslide = 0;
        vm_kernel_unslide_or_perm_external(start, &unslide);
        if ((unslide & 1) != 1 && unslide != 0 && unslide != start) {
            kslide = start - unslide;
            break;
        }
        start += step;
    }
    return kslide;
}

vm_offset_t get_kslide()
{
    if (kernel_slide == 0) {
        LOG(OS_LOG_DEFAULT, "kernel_slide is 0. Running bruteforce_kslide... *****************\n");
        kernel_slide = bruteforce_kslide();
    }
    LOG(OS_LOG_DEFAULT, "kernel_slide is 0x%llx *****************\n", (uint64_t)kernel_slide);
    return kernel_slide;
}

uint64_t kbase(void)
{
    return 0;
}

void kwrite64(inspector_opt_krw64_t request)
{
    *(uint64_t*)request->address = request->value;
}

void kread64(inspector_opt_krw64_t request)
{
    request->value = *(uint64_t*)(request->address);
}

/* A simple setsockopt handler */
errno_t EPHandleSet(kern_ctl_ref ctlref, unsigned int unit, void *userdata, int opt, void *data, size_t len)
{
    int    error = EINVAL;
    LOG(OS_LOG_DEFAULT, "EPHandleSet opt is %d\n", opt);

    switch ( opt ) {
        case INSPECTOR_OPT_COPYIN: {
            if (data == NULL || len != sizeof(struct inspector_opt_copy)) {
                error = EINVAL;
                break;
            }
            inspector_opt_copy_t req = (inspector_opt_copy_t)data;
            error = copyin(req->uaddress, req->kaddress, req->length);
            break;
        }

        case INSPECTOR_OPT_KWRITE64: {
            if (data == NULL || len != sizeof(struct inspector_opt_krw64)) {
                error = EINVAL;
                break;
            }
            error = 0;
            inspector_opt_krw64_t req = (inspector_opt_krw64_t)data;
            kwrite64(req);
            break;
        }
    }
    return error;
}

/* A simple A simple getsockopt handler */
errno_t EPHandleGet(kern_ctl_ref ctlref, unsigned int unit, void *userdata, int opt, void *data, size_t *len)
{
    int    error = EINVAL;
    LOG(OS_LOG_DEFAULT, "EPHandleGet opt is %d *****************\n", opt);
    switch ( opt ) {
        case INSPECTOR_OPT_KSLIDE: {
            if (data == NULL || *len != sizeof(uint64_t)) {
                error = 0x1337;
                break;
            }
            error = 0;
            *(uint64_t*)data = get_kslide();
            break;
        }

        case INSPECTOR_OPT_COPYOUT: {
            if (data == NULL || *len != sizeof(struct inspector_opt_copy)) {
                error = EINVAL;
                break;
            }

            inspector_opt_copy_t req = (inspector_opt_copy_t)data;
            error = copyout(req->kaddress, req->uaddress, req->length);
            break;
        }

        case INSPECTOR_OPT_KREAD64: {
            if (data == NULL || *len != sizeof(struct inspector_opt_krw64)) {
                error = EINVAL;
                break;
            }
            error = 0;

            inspector_opt_krw64_t req = (inspector_opt_krw64_t)data;
            struct inspector_opt_krw64 lreq = {
                .address = req->address,
                .value = 0
            };
            kread64(&lreq);
            memcpy(data, &lreq, sizeof(struct inspector_opt_krw64));
            break;
        }

        case INSPECTOR_OPT_CURRENT_PROC: {
            if (data == NULL || *len != sizeof(uint64_t)) {
                error = EINVAL;
                break;
            }
            error = 0;
            *(uint64_t*)data = (uint64_t)current_proc();
            break;
        }

        case INSPECTOR_OPT_KCALL: {
            if (data == NULL || *len != sizeof(struct inspector_opt_kcall)) {
                error = EINVAL;
                break;
            }
            error = 0;
            inspector_opt_kcall_t req = (inspector_opt_kcall_t)data;
            uint64_t ret = kcall(req);
            req->ret = ret;
            break;
        }
    }
    return error;
}

/* A minimalist connect handler */
errno_t
EPHandleConnect(kern_ctl_ref ctlref, struct sockaddr_ctl *sac, void **unitinfo)
{
    LOG(OS_LOG_DEFAULT, "EPHandleConnect called\n");
    return (0);
}

/* A minimalist disconnect handler */
errno_t
EPHandleDisconnect(kern_ctl_ref ctlref, unsigned int unit, void *unitinfo)
{
    LOG(OS_LOG_DEFAULT, "EPHandleDisconnect called\n");
    return (0);
}

/* A minimalist write handler */
errno_t EPHandleWrite(kern_ctl_ref ctlref, unsigned int unit, void *userdata, mbuf_t m, int flags)
{
    LOG(OS_LOG_DEFAULT, "EPHandleWrite called\n");
    return (0);
}


kern_ctl_ref kctlref;
kern_return_t inspector_start(kmod_info_t * ki, void *d)
{
    errno_t error;
    struct kern_ctl_reg     ep_ctl; // Initialize control
    bzero(&ep_ctl, sizeof(ep_ctl));  // sets ctl_unit to 0
    ep_ctl.ctl_id = 0; /* OLD STYLE: ep_ctl.ctl_id = kEPCommID; */
    ep_ctl.ctl_unit = 0;
    strcpy(ep_ctl.ctl_name, INSPECTOR_CONTROL_SOCKET, sizeof(ep_ctl.ctl_name));
    ep_ctl.ctl_flags = CTL_FLAG_REG_ID_UNIT; // & CTL_FLAG_PRIVILEGED;
    ep_ctl.ctl_send = EPHandleWrite;
    ep_ctl.ctl_getopt = EPHandleGet;
    ep_ctl.ctl_setopt = EPHandleSet;
    ep_ctl.ctl_connect = EPHandleConnect;
    ep_ctl.ctl_disconnect = EPHandleDisconnect;
    error = ctl_register(&ep_ctl, &kctlref);
    LOG(OS_LOG_DEFAULT, "inspector is loaded!\n");

    return error;
}

kern_return_t inspector_stop(kmod_info_t *ki, void *d)
{
    LOG(OS_LOG_DEFAULT, "inspector is unloaded!\n");
    errno_t error;
    error = ctl_deregister(kctlref);
    return error;
}
