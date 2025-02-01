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