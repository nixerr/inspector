#ifndef GDBSTUB_H
#define GDBSTUB_H

#include <stdint.h>

/*
 * Serve the GDB Remote Serial Protocol on 127.0.0.1:<port>, bridging packets
 * to the inspector kext over the already-connected control socket <inspector_fd>.
 *
 * Blocks forever, accepting one client at a time (reconnect is allowed).
 * Connect from lldb with:  (lldb) gdb-remote 127.0.0.1:<port>
 *
 * When <verbose> is non-zero, every RSP packet exchanged with lldb is logged:
 * "-> $..." for requests received and "<- $..." for replies sent.
 *
 * Returns non-zero only on a fatal setup error (bind/listen).
 */
int gdb_serve(int inspector_fd, uint16_t port, int verbose);

#endif
