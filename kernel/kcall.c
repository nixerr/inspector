#include <libkern/libkern.h>

#include "inspector.h"

uint64_t kcall(inspector_opt_kcall_t p)
{
  __asm__("STP X29,X30, [SP, #-16]!");
  __asm__("SUB SP, SP, 0x100");
  __asm__("STP X19, X20, [SP, 0xF0]");

  __asm__("MOV X19, X0");
  __asm__("LDR X20, [X19]");

  __asm__("LDR X0, [X19, 0x8]");
  __asm__("LDR X1, [X19, 0x10]");
  __asm__("LDR X2, [X19, 0x18]");
  __asm__("LDR X3, [X19, 0x20]");
  __asm__("LDR X4, [X19, 0x28]");
  __asm__("LDR X5, [X19, 0x30]");
  __asm__("LDR X6, [X19, 0x38]");
  __asm__("LDR X7, [X19, 0x40]");
  __asm__("BLR X20");

  __asm__("LDP X19, X20, [SP, 0xF0]");
  __asm__("ADD SP, SP, 0x100");
  __asm__("LDP X29,X30, [SP], #16");
  __asm__("RET");
}
