#include <mach/mach_types.h>

extern "C" kern_return_t _start(kmod_info_t *ki, void *data);
extern "C" kern_return_t _stop(kmod_info_t *ki, void *data);
__private_extern__ kern_return_t inspector_start(kmod_info_t *ki, void *data);
__private_extern__ kern_return_t inspector_stop(kmod_info_t *ki, void *data);

__attribute__((visibility("default"))) KMOD_EXPLICIT_DECL(com.inspector, "1.0.0d1", _start, _stop)
extern "C" {
__private_extern__ kmod_start_func_t *_realmain = inspector_start;
__private_extern__ kmod_stop_func_t *_antimain = inspector_stop;
__private_extern__ int _kext_apple_cc = __APPLE_CC__ ;
}
