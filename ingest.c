/* Stage 1 -- the ingestion muscle.
 *
 * Sits at the wire (or reads a capture file), throws away every payload, and
 * streams one fixed 24-byte record per packet to stdout (little-endian):
 *     double  ts       timestamp, seconds
 *     uint32  src      source IPv4, raw network-order bytes (0 if not IPv4)
 *     uint32  dst      destination IPv4, same encoding
 *     uint16  dport    destination port (0 if not TCP/UDP)
 *     uint16  proto    IP protocol number (6 tcp, 17 udp, ...)
 *     uint32  len      original on-wire length
 * Python keys each conversation by (src, dst) so an implant's check-ins to its
 * C2 host stay in their own lane, apart from the same machine's normal traffic.
 *
 *   build:  cc -O2 ingest.c -lpcap -o ingest     (or: make)
 *   file:   ./ingest capture.pcap
 *   live:   sudo ./ingest -i en0 'udp'           (live needs root)
 */

#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma pack(push, 1)
struct rec {
    double   ts;
    uint32_t src;
    uint32_t dst;
    uint16_t dport;
    uint16_t proto;
    uint32_t len;
};
#pragma pack(pop)

static int l2off_for(int linktype) {
    switch (linktype) {
        case DLT_EN10MB:    return 14;   /* ethernet */
        case DLT_NULL:      return 4;    /* bsd/macos loopback */
        case DLT_RAW:       return 0;    /* raw IP */
        case DLT_LINUX_SLL: return 16;
        default:            return 14;   /* assume ethernet */
    }
}

static void on_packet(u_char *user, const struct pcap_pkthdr *h,
                      const u_char *bytes) {
    int l2 = *(int *)user;
    struct rec r = {0};
    r.ts = (double)h->ts.tv_sec + (double)h->ts.tv_usec / 1e6;
    r.len = (uint32_t)h->len;

    if (h->caplen >= (bpf_u_int32)(l2 + 20)) {
        const u_char *ip = bytes + l2;
        if ((ip[0] >> 4) == 4) {                  /* IPv4 */
            int ihl = (ip[0] & 0x0f) * 4;
            r.proto = ip[9];
            memcpy(&r.src, ip + 12, 4);           /* left in network order */
            memcpy(&r.dst, ip + 16, 4);
            if ((r.proto == 6 || r.proto == 17) &&
                h->caplen >= (bpf_u_int32)(l2 + ihl + 4))
                r.dport = (uint16_t)((ip[ihl + 2] << 8) | ip[ihl + 3]);
        }
    }
    fwrite(&r, sizeof r, 1, stdout);
}

static void usage(const char *prog) {
    fprintf(stderr,
        "usage: %s <capture.pcap> [bpf filter]\n"
        "       %s -i <iface> [bpf filter]   (live, needs root)\n",
        prog, prog);
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 2; }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pc;
    const char *filter = NULL;
    int live = 0;

    if (strcmp(argv[1], "-i") == 0) {
        if (argc < 3) { usage(argv[0]); return 2; }
        pc = pcap_open_live(argv[2], 65535, 1, 200, errbuf);
        live = 1;
        if (argc >= 4) filter = argv[3];
    } else {
        pc = pcap_open_offline(argv[1], errbuf);
        if (argc >= 3) filter = argv[2];
    }
    if (!pc) {
        fprintf(stderr, "ingest: %s\n", errbuf);
        return 1;
    }

    if (filter) {
        struct bpf_program prog;
        if (pcap_compile(pc, &prog, filter, 1, 0) < 0 ||
            pcap_setfilter(pc, &prog) < 0) {
            fprintf(stderr, "ingest: bad filter: %s\n", pcap_geterr(pc));
            return 1;
        }
    }

    int l2 = l2off_for(pcap_datalink(pc));
    if (live) setvbuf(stdout, NULL, _IONBF, 0);

    int rc = pcap_loop(pc, -1, on_packet, (u_char *)&l2);
    pcap_close(pc);
    fflush(stdout);
    return rc == -1 ? 1 : 0;
}
