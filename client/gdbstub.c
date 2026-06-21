//
//  gdbstub.c
//  inspector
//
//  GDB Remote Serial Protocol (RSP) bridge so a real debugger (lldb / gdb)
//  can attach to the live kernel and read/write memory through the inspector
//  kext.
//
//  This is a *memory* introspection stub, not an execution-control debugger:
//  the kext has no way to halt cores or recover per-CPU saved state, so the
//  register file exposed here is synthetic (zeroed, but writable). Memory
//  reads/writes are real. Set pc/sp/fp/lr yourself (e.g. `reg write pc 0x...`)
//  to make lldb unwind a stack you already located. `continue`/`step` simply
//  report "stopped" again -- there is nothing to run.
//
//  Connect from lldb:  (lldb) gdb-remote 127.0.0.1:1234
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../kernel/inspector.h"
#include "inspector.h"
#include "log.h"
#include "gdbstub.h"

#define PKT_MAX 20480   /* RSP packet scratch (hex of MEM_MAX fits with room)   */
#define MEM_MAX 8192    /* max bytes per memory op; lldb chunks to PacketSize    */

/* arm64 cpu identifiers reported via qHostInfo / qProcessInfo */
#define CPUTYPE_ARM64    16777228   /* CPU_TYPE_ARM64  (0x0100000c)              */
#define CPUSUBTYPE_ARM64E 2         /* CPU_SUBTYPE_ARM64E                        */

/*
 * Synthetic register file. Layout (matches the offsets reported by
 * qRegisterInfo and the order of the 'g' packet):
 *   index 0..28 -> x0..x28   (64-bit, offset i*8)
 *   index 29    -> fp  (x29) (64-bit, offset 232)
 *   index 30    -> lr  (x30) (64-bit, offset 240)
 *   index 31    -> sp        (64-bit, offset 248)
 *   index 32    -> pc        (64-bit, offset 256)
 *   index 33    -> cpsr      (32-bit, offset 264)
 */
#define NREG64 33               /* x0..x28, fp, lr, sp, pc                       */
#define NREG   34               /* + cpsr                                        */
static uint64_t g_reg[NREG];

static int g_noack = 0;         /* QStartNoAckMode negotiated                    */
static int g_pending_noack = 0; /* flip to no-ack *after* the OK is acked        */

static const char hexchars[] = "0123456789abcdef";

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void mem2hex(const uint8_t *m, size_t n, char *o)
{
    for (size_t i = 0; i < n; i++) {
        o[i * 2]     = hexchars[m[i] >> 4];
        o[i * 2 + 1] = hexchars[m[i] & 0xf];
    }
    o[n * 2] = 0;
}

static size_t hex2mem(const char *h, uint8_t *m, size_t maxn)
{
    size_t i = 0;
    while (i < maxn) {
        int hi = hexval(h[i * 2]);
        int lo = hexval(h[i * 2 + 1]);
        if (hi < 0 || lo < 0) break;
        m[i] = (uint8_t)((hi << 4) | lo);
        i++;
    }
    return i;
}

/* little-endian (arm64 target order) register <-> hex */
static void reg2hex(uint64_t v, int bytes, char *o)
{
    for (int i = 0; i < bytes; i++) {
        uint8_t b = (v >> (i * 8)) & 0xff;
        o[i * 2]     = hexchars[b >> 4];
        o[i * 2 + 1] = hexchars[b & 0xf];
    }
    o[bytes * 2] = 0;
}

static uint64_t hex2reg(const char *h, int bytes)
{
    uint64_t v = 0;
    for (int i = 0; i < bytes; i++) {
        int hi = hexval(h[i * 2]);
        int lo = hexval(h[i * 2 + 1]);
        if (hi < 0 || lo < 0) break;
        v |= (uint64_t)((hi << 4) | lo) << (i * 8);
    }
    return v;
}

/* ---- kext memory bridge (returns 0 on success, -1 with errno set) -------- */

static int kmem_read(int fd, uint64_t kaddr, void *ubuf, uint64_t len)
{
    struct inspector_opt_copy req = {
        .kaddress = (void *)kaddr,
        .uaddress = (user_addr_t)(uintptr_t)ubuf,
        .length   = len,
    };
    socklen_t l = sizeof(req);
    return getsockopt(fd, SYSPROTO_CONTROL, INSPECTOR_OPT_COPYOUT, &req, &l);
}

static int kmem_write(int fd, uint64_t kaddr, const void *ubuf, uint64_t len)
{
    struct inspector_opt_copy req = {
        .kaddress = (void *)kaddr,
        .uaddress = (user_addr_t)(uintptr_t)ubuf,
        .length   = len,
    };
    return setsockopt(fd, SYSPROTO_CONTROL, INSPECTOR_OPT_COPYIN, &req, sizeof(req));
}

/* ---- packet i/o ---------------------------------------------------------- */

static int sendraw(int s, const char *b, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(s, b + off, n - off);
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

/* Wrap payload as $<data>#<cksum> and send. Consume the peer ack while in
 * ack mode so it does not desync the next read. */
static int sendpkt(int s, const char *data)
{
    size_t n = strlen(data);
    char *buf = malloc(n + 4);
    if (!buf) return -1;

    uint8_t sum = 0;
    buf[0] = '$';
    for (size_t i = 0; i < n; i++) {
        buf[1 + i] = data[i];
        sum += (uint8_t)data[i];
    }
    buf[1 + n]     = '#';
    buf[1 + n + 1] = hexchars[(sum >> 4) & 0xf];
    buf[1 + n + 2] = hexchars[sum & 0xf];

    int rc = sendraw(s, buf, n + 4);
    free(buf);
    if (rc) return -1;

    if (!g_noack) {
        char ack;
        if (read(s, &ack, 1) != 1) return -1;  /* '+' (or '-' = resend, ignored) */
    }
    return 0;
}

/* Read one packet body into buf (NUL-terminated). Returns body length, 0 for
 * an interrupt (0x03), or -1 on disconnect. Acks the peer while in ack mode. */
static int recvpkt(int s, char *buf, size_t bufsz)
{
    char c;

    for (;;) {                       /* sync to '$' (or a raw interrupt) */
        if (read(s, &c, 1) != 1) return -1;
        if (c == '$') break;
        if (c == 0x03) { buf[0] = 0; return 0; }
        /* '+', '-', stray bytes: ignore */
    }

    size_t n = 0;
    for (;;) {                       /* body up to (unescaped) '#' */
        if (read(s, &c, 1) != 1) return -1;
        if (c == '#') break;
        if (n < bufsz - 1) buf[n++] = c;
    }
    buf[n] = 0;

    char h1, h2;                     /* checksum digits (not verified) */
    if (read(s, &h1, 1) != 1) return -1;
    if (read(s, &h2, 1) != 1) return -1;

    if (!g_noack) {
        char ack = '+';
        if (sendraw(s, &ack, 1)) return -1;
    }
    return (int)n;
}

/* ---- register packets ---------------------------------------------------- */

static void build_g(char *out)
{
    int len = 0;
    for (int i = 0; i < NREG64; i++) {     /* 33 x 64-bit */
        reg2hex(g_reg[i], 8, out + len);
        len += 16;
    }
    reg2hex(g_reg[33], 4, out + len);      /* cpsr, 32-bit */
}

static void parse_G(const char *h, char *out)
{
    size_t need = (size_t)NREG64 * 16 + 8;
    if (strlen(h) < need) { strcpy(out, "E16"); return; }
    for (int i = 0; i < NREG64; i++)
        g_reg[i] = hex2reg(h + i * 16, 8);
    g_reg[33] = hex2reg(h + NREG64 * 16, 4) & 0xffffffff;
    strcpy(out, "OK");
}

static void handle_p(const char *s, char *out)
{
    unsigned long n = strtoul(s, NULL, 16);
    if (n < (unsigned long)NREG64) reg2hex(g_reg[n], 8, out);
    else if (n == 33)              reg2hex(g_reg[33], 4, out);
    else                           strcpy(out, "E45");
}

static void handle_P(const char *s, char *out)
{
    const char *eq = strchr(s, '=');
    if (!eq) { strcpy(out, "E16"); return; }
    unsigned long n = strtoul(s, NULL, 16);
    if (n < (unsigned long)NREG64) g_reg[n] = hex2reg(eq + 1, 8);
    else if (n == 33)              g_reg[33] = hex2reg(eq + 1, 4) & 0xffffffff;
    else { strcpy(out, "E45"); return; }
    strcpy(out, "OK");
}

/* qRegisterInfo<hexN> -- lldb autoconfigures arm64 from these. */
static void reg_info(const char *s, char *out)
{
    unsigned long n = strtoul(s, NULL, 16);
    if (n >= NREG) { strcpy(out, "E45"); return; }

    char name[8];
    int bitsize = 64;
    int offset;
    int dwarf = (int)n;
    const char *generic = NULL;

    if (n < 29)       { snprintf(name, sizeof(name), "x%lu", n); offset = (int)n * 8; }
    else if (n == 29) { strcpy(name, "fp");   offset = 232; generic = "fp"; }
    else if (n == 30) { strcpy(name, "lr");   offset = 240; generic = "ra"; }
    else if (n == 31) { strcpy(name, "sp");   offset = 248; generic = "sp"; }
    else if (n == 32) { strcpy(name, "pc");   offset = 256; generic = "pc"; }
    else              { strcpy(name, "cpsr"); offset = 264; bitsize = 32; dwarf = -1; }

    int len = sprintf(out,
        "name:%s;bitsize:%d;offset:%d;encoding:uint;format:hex;"
        "set:General Purpose Registers;", name, bitsize, offset);
    if (dwarf >= 0)  len += sprintf(out + len, "gcc:%d;dwarf:%d;", dwarf, dwarf);
    if (generic)     sprintf(out + len, "generic:%s;", generic);
}

/* ---- memory packets ------------------------------------------------------ */

static void handle_m(int fd, const char *s, char *out, uint8_t *mem)
{
    char *p;
    uint64_t addr = strtoull(s, &p, 16);
    uint64_t len  = (*p == ',') ? strtoull(p + 1, NULL, 16) : 0;
    if (len == 0)        { out[0] = 0; return; }
    if (len > MEM_MAX)   len = MEM_MAX;          /* lldb re-requests the rest */

    if (kmem_read(fd, addr, mem, len) != 0) { sprintf(out, "E%02x", errno & 0xff); return; }
    mem2hex(mem, len, out);
}

static void handle_M(int fd, const char *s, char *out, uint8_t *mem)
{
    char *p;
    uint64_t addr = strtoull(s, &p, 16);
    if (*p != ',') { strcpy(out, "E16"); return; }
    uint64_t len  = strtoull(p + 1, &p, 16);
    if (*p != ':') { strcpy(out, "E16"); return; }
    if (len > MEM_MAX) { strcpy(out, "E16"); return; }

    if (len) hex2mem(p + 1, mem, len);
    if (kmem_write(fd, addr, mem, len) != 0) { sprintf(out, "E%02x", errno & 0xff); return; }
    strcpy(out, "OK");
}

/* X<addr>,<len>:<binary> -- binary write (0x7d-escaped payload). */
static void handle_X(int fd, const char *body, char *out, uint8_t *mem)
{
    const char *s = body + 1;                    /* skip 'X' */
    char *p;
    uint64_t addr = strtoull(s, &p, 16);
    if (*p != ',') { strcpy(out, "E16"); return; }
    uint64_t len  = strtoull(p + 1, &p, 16);
    const char *bin = strchr(p, ':');
    if (!bin) { strcpy(out, "E16"); return; }
    bin++;

    if (len == 0) { strcpy(out, "OK"); return; } /* lldb probes X support with len 0 */
    if (len > MEM_MAX) { strcpy(out, "E16"); return; }

    uint64_t i = 0;                              /* un-escape 0x7d sequences */
    for (const char *q = bin; *q && i < len; q++) {
        uint8_t b = (uint8_t)*q;
        if (b == 0x7d) { q++; if (!*q) break; b = (uint8_t)*q ^ 0x20; }
        mem[i++] = b;
    }
    if (kmem_write(fd, addr, mem, len) != 0) { sprintf(out, "E%02x", errno & 0xff); return; }
    strcpy(out, "OK");
}

/* ---- query packets ------------------------------------------------------- */

static void handle_query(const char *in, char *out)
{
    if (strncmp(in, "qSupported", 10) == 0) {
        strcpy(out, "PacketSize=1000;QStartNoAckMode+");
    } else if (strncmp(in, "QStartNoAckMode", 15) == 0) {
        strcpy(out, "OK");
        g_pending_noack = 1;                     /* flip after this OK is acked */
    } else if (strncmp(in, "qHostInfo", 9) == 0) {
        sprintf(out, "cputype:%d;cpusubtype:%d;ostype:macosx;vendor:apple;"
                     "endian:little;ptrsize:8;", CPUTYPE_ARM64, CPUSUBTYPE_ARM64E);
    } else if (strncmp(in, "qProcessInfo", 12) == 0) {
        sprintf(out, "pid:01;cputype:%d;cpusubtype:%d;ostype:macosx;vendor:apple;"
                     "endian:little;ptrsize:8;", CPUTYPE_ARM64, CPUSUBTYPE_ARM64E);
    } else if (strncmp(in, "qRegisterInfo", 13) == 0) {
        reg_info(in + 13, out);
    } else if (strncmp(in, "qfThreadInfo", 12) == 0) {
        strcpy(out, "m01");
    } else if (strncmp(in, "qsThreadInfo", 12) == 0) {
        strcpy(out, "l");
    } else if (strcmp(in, "qC") == 0) {
        strcpy(out, "QC01");
    } else if (strncmp(in, "qAttached", 9) == 0) {
        strcpy(out, "1");
    } else if (strncmp(in, "qThreadStopInfo", 15) == 0) {
        strcpy(out, "T02thread:01;");
    } else if (strncmp(in, "QEnableErrorStrings", 19) == 0) {
        strcpy(out, "OK");
    } else {
        out[0] = 0;                              /* unsupported -> empty reply */
    }
}

/* ---- per-connection loop ------------------------------------------------- */

static void handle_client(int cs, int kfd)
{
    char *in  = malloc(PKT_MAX);
    char *out = malloc(PKT_MAX);
    uint8_t *mem = malloc(MEM_MAX);
    if (!in || !out || !mem) goto done;

    g_noack = 0;
    g_pending_noack = 0;
    memset(g_reg, 0, sizeof(g_reg));

    for (;;) {
        int n = recvpkt(cs, in, PKT_MAX);
        if (n < 0) break;
        out[0] = 0;

        switch (n == 0 ? 0x03 : in[0]) {
        case 0x03:                                /* interrupt */
        case '?':                                 /* halt reason */
        case 'c': case 'C': case 's': case 'S':   /* (no real execution) */
            strcpy(out, "T02thread:01;");
            break;
        case 'H':                                 /* set thread */
        case 'T':                                 /* thread alive? */
        case '!':                                 /* extended mode */
            strcpy(out, "OK");
            break;
        case 'g': build_g(out);            break;
        case 'G': parse_G(in + 1, out);    break;
        case 'p': handle_p(in + 1, out);   break;
        case 'P': handle_P(in + 1, out);   break;
        case 'm': handle_m(kfd, in + 1, out, mem); break;
        case 'M': handle_M(kfd, in + 1, out, mem); break;
        case 'X': handle_X(kfd, in, out, mem);     break;
        case 'q':
        case 'Q': handle_query(in, out);   break;
        case 'v':
            if (strncmp(in, "vCont?", 6) == 0)      out[0] = 0;        /* use c/s */
            else if (strncmp(in, "vCont", 5) == 0)  strcpy(out, "T02thread:01;");
            else                                    out[0] = 0;
            break;
        case 'D':                                 /* detach */
            sendpkt(cs, "OK");
            goto done;
        case 'k':                                 /* kill -> just drop client */
            goto done;
        default:
            out[0] = 0;                           /* unsupported -> empty reply */
            break;
        }

        if (sendpkt(cs, out) != 0) break;
        if (g_pending_noack) { g_noack = 1; g_pending_noack = 0; }
    }

done:
    free(in);
    free(out);
    free(mem);
}

/* ---- server -------------------------------------------------------------- */

int gdb_serve(int inspector_fd, uint16_t port)
{
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) { ERROR("socket: %s", strerror(errno)); return -1; }

    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   /* loopback only: this is kernel RW */

    if (bind(ls, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        ERROR("bind :%d : %s", port, strerror(errno));
        close(ls);
        return -1;
    }
    if (listen(ls, 1) != 0) {
        ERROR("listen : %s", strerror(errno));
        close(ls);
        return -1;
    }

    INFO("gdb stub listening on 127.0.0.1:%d", port);
    INFO("attach with:  (lldb) gdb-remote 127.0.0.1:%d", port);

    for (;;) {
        struct sockaddr_in ca;
        socklen_t cl = sizeof(ca);
        int cs = accept(ls, (struct sockaddr *)&ca, &cl);
        if (cs < 0) {
            if (errno == EINTR) continue;
            ERROR("accept : %s", strerror(errno));
            break;
        }
        INFO("%s", "client connected");
        handle_client(cs, inspector_fd);
        close(cs);
        INFO("%s", "client disconnected");
    }

    close(ls);
    return 0;
}
