#include <unistd.h>

#ifndef INSPECTOR_H
#define INSPECTOR_H

extern uint64_t kslide;

int inspector_connect(void);
uint64_t get_kslide(int fd);
uint64_t get_current_proc(int fd);
uint64_t get_current_task(int fd);
void *kbase(int fd);

void kwrite64(int fd, uint64_t address, uint64_t value);
void kread64(int fd, uint64_t address, uint64_t *value);

void kcopyin(int fd, void *kaddress, void *uaddress, uint64_t length);
void kcopyout(int fd, void *kaddress, void *uaddress, uint64_t length);

uint64_t kcall(int fd, uint64_t func, uint32_t num, ...);

#endif
