#ifdef __KERNEL__
#include <sys/unistd.h>
#include <sys/types.h>
#else
#include <unistd.h>
#endif

#define INSPECTOR_CONTROL_SOCKET "com.home.inspector"
#define KERNEL_BASE 0xfffffe0007004000

enum INSPECTOR_SOCK_OPT {
    INSPECTOR_OPT_KSLIDE,
    INSPECTOR_OPT_COPYIN,
    INSPECTOR_OPT_COPYOUT,
    INSPECTOR_OPT_KREAD64,
    INSPECTOR_OPT_KWRITE64,
    INSPECTOR_OPT_KREAD32,
    INSPECTOR_OPT_KWRITE32,
    INSPECTOR_OPT_KCALL,
    INSPECTOR_OPT_KPATCH
};

struct inspector_opt_krw64{
    void *address;
    uint64_t value;
} inspector_opt_krw64;

struct inspector_opt_krw32{
    void *address;
    uint32_t value;
} inspector_opt_krw32;

struct inspector_opt_copy {
    void *kaddress;
    user_addr_t uaddress;
    uint64_t length;
} inspector_opt_copy;

typedef struct inspector_opt_krw64 *inspector_opt_krw64_t;
typedef struct inspector_opt_krw32 *inspector_opt_krw32_t;
typedef struct inspector_opt_copy *inspector_opt_copy_t;