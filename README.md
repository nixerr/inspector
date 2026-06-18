# Inspector

A macOS kernel extension (KEXT) that provides kernel memory introspection and function execution from user space on Apple Silicon (arm64e).

## Overview

Inspector consists of two components:

- **Kernel extension** (`kernel/`) -- Registers a kernel control socket (`com.home.inspector`) that exposes read/write/call primitives to user-space clients.
- **User-space client** (`client/`) -- A C library and CLI tool that connects to the KEXT and provides a convenient API. Python bindings are also included.

### Capabilities

- Read and write kernel memory (64-bit and 32-bit)
- Bulk memory copy between kernel and user space (`copyin`/`copyout`)
- Call arbitrary kernel functions with up to 8 arguments (`kcall`)
- Retrieve kernel slide (KASLR offset), kernel base, current process, and current task
- Automatic KASLR slide detection via brute-force search
- Attach a real debugger (lldb/gdb) to the live kernel via a built-in GDB Remote Serial Protocol server

## Requirements

- macOS 15.2+ on Apple Silicon (arm64e)
- Xcode Command Line Tools (`xcrun`)
- Root privileges (for KEXT ownership and loading)

## Building

```bash
# Build the kernel extension (requires sudo for chown)
make all

# Build only the client CLI tool
make client

# Build the client as a shared library (libinspector.dylib)
make client_lib

# Clean everything
make clean
```

Build artifacts are placed in the `build/` directory:

| Artifact | Path |
|---|---|
| Kernel extension | `build/inspector.kext/` |
| Client CLI | `build/inspector` |
| Shared library | `build/libinspector.dylib` |

## Usage

### CLI

```bash
# Read 64-bit value at an absolute kernel address
./build/inspector read 0x<address>

# Read 64-bit value at a kernel-slide-relative address
./build/inspector rread 0x<address>

# Write a 64-bit value to a kernel address
./build/inspector write 0x<address> 0x<value>

# Get current process structure address
./build/inspector proc

# Test kcall functionality
./build/inspector test_kcall

# Serve the GDB remote protocol for lldb/gdb (default port 1234)
./build/inspector gdb

# ...or on a custom port
./build/inspector gdb 4455
```

### Debugging with lldb

Start the stub in one terminal (it connects to the loaded KEXT), then attach
from lldb:

```bash
./build/inspector gdb 1234
```

```text
(lldb) gdb-remote 127.0.0.1:1234
(lldb) memory read 0xfffffe0007004000
(lldb) memory write 0xfffffe0007004000 0x41
(lldb) register write pc 0x<kernel-addr>    # only lldb's local view; see note below
```

The stub binds to **loopback only** (it exposes raw kernel read/write, so it is
not put on the network). Memory accesses are serviced live by the KEXT via
`copyin`/`copyout`. Because the KEXT cannot halt CPUs or recover per-core saved
state, the register file is **synthetic**: it lives entirely in the stub's own
memory (`g_reg` in `gdbstub.c`), starts zeroed, and a `register write` only
updates that local copy -- it does **not** modify any real kernel CPU register.
With only read/write/call primitives there is no way to alter the live register
state of a running core. The synthetic registers exist solely so you can seed
`pc`/`sp`/`fp`/`lr` to values you located in memory and have lldb walk a stack
for you; `continue`/`step` simply re-report "stopped". This is a
memory-inspection bridge, not an execution-control debugger. For symbolicated
structure browsing, point lldb at a matching KDK kernel and slide it by the
`kernel_slide` value the tool prints on startup.

### C API

```c
#include "inspector.h"

int fd = inspector_connect();
uint64_t slide = get_kslide(fd);
uint64_t proc  = get_current_proc(fd);

uint64_t value;
kread64(fd, address, &value);
kwrite64(fd, address, new_value);

kcopyin(fd, kaddr, ubuf, len);
kcopyout(fd, kaddr, ubuf, len);

uint64_t ret = kcall(fd, func_addr, num_args, ...);
```

### Python

```python
from inspector import Inspector

i = Inspector("build/libinspector.dylib")
slide = i.kslide()
base  = i.kbase()
value = i.kread64(base)
i.kcall(func_addr, num_args, arg0, arg1)
```

## Project Structure

```
inspector/
  kernel/
    main.cpp        # KEXT entry point, socket handlers
    inspector.h     # Shared data structures and protocol constants
    kcall.c         # ARM64 inline assembly for kernel function calls
    kcall.h         # kcall declaration
    mod.h           # KMOD declarations
  client/
    main.c          # CLI tool
    inspector.c     # Client library implementation
    inspector.h     # Client API header
    gdbstub.c       # GDB remote serial protocol server (for lldb/gdb)
    gdbstub.h       # gdb stub declaration
    inspector.py    # Python bindings
    log.h           # Logging macros
  Makefile          # Build system
  Info.plist        # KEXT bundle metadata
```
