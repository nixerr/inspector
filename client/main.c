#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <sys/syscall.h>


#include "../kernel/inspector.h"
#include "inspector.h"
#include "log.h"

int main(int argc, char *argv[])
{
    int error = 0;
    int sockfd = 0;
    uint64_t value = 0;
    uint64_t dt = 0;
    char buf[0x1000] = {0};

    sockfd = inspector_connect();
    assert(sockfd != -1);

    void *kernel_base = kbase(sockfd);
    assert((uint64_t) kernel_base != KERNEL_BASE);

    INFO("kernel_slide : 0x%llx", kslide);
    INFO("kernel base : 0x%016llx", (uint64_t)kernel_base);

    if (argc == 3 && strncmp(argv[1], "read", strlen(argv[1])) == 0) {
        uint64_t readat = 0;
        sscanf(argv[2], "0x%llx", &readat);
        kread64(sockfd, (void*)readat, &value);
        INFO("where: 0x%llx, what : 0x%016llx", readat, value);
    } else if (argc == 3 && strncmp(argv[1], "rread", strlen(argv[1])) == 0) {
        uint64_t readat = 0;
        sscanf(argv[2], "0x%llx", &readat);
        readat += kslide;
        kread64(sockfd, (void*)readat, &value);
        INFO("where: 0x%llx, what : 0x%016llx", readat, value);
        INFO("value : 0x%x", (uint8_t)value);
    } else if (argc == 4 && strncmp(argv[1], "write", strlen(argv[1])) == 0) {
        uint64_t writeat = 0;
        uint64_t value = 0;
        sscanf(argv[2], "0x%llx", &writeat);
        sscanf(argv[3], "0x%llx", &value);
        kwrite64(sockfd, writeat, value);
        INFO("where: 0x%llx, what : 0x%016llx", writeat, value);
    } else if (argc == 2 && strncmp(argv[1], "proc", strlen(argv[1])) == 0) {
        uint64_t proc = get_current_proc(sockfd);
        INFO("proc: 0x%016llx", proc);
    } else if (argc == 2 && strncmp(argv[1], "test_kcall", strlen(argv[1])) == 0) {
        uint64_t proc = get_current_proc(sockfd);
        uint64_t _ = kcall(sockfd, 0x4141414141414141, 8, 0x4242424242424242, 0x4343434343434343, 0x4444444444444444, 0x4545454545454545, 0x4646464646464646, 0x4747474747474747, 0x4848484848484848, 0x4949494949494949);
        // uint64_t kr = kcall(sockfd, getpid_addr, 3, proc, NULL, kmem);
        // assert(kr == 0);

        // getpid(proc_t p, __unused struct getpid_args * uap, int32_t *retval)
    }

#if 0
    kread64(sockfd, kernel_base, &value);
    INFO("where: %p, what : 0x%016llx", kernel_base, value);

    kcopyout(sockfd, kernel_base, &buf, sizeof(buf));

    for (int i = 0; i < 0x1000; i+=8) {
        INFO("where: 0x%016llx, what : 0x%016llx", (uint64_t)kernel_base + i, *(uint64_t*)(buf+i));
    }
#endif

    return 0;
}
