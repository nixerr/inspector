#include <stdio.h>

#define INFO(fmt, ...) printf("[I] " fmt "\n", __VA_ARGS__);
#define ERROR(fmt, ...) printf("[E] " fmt "\n", __VA_ARGS__);
