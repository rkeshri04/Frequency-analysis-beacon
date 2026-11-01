"""Glue between the C ingest agent (Stage 1) and the lane analysis (Stage 2).

Builds ./ingest if needed, runs it on a capture file (or a live interface), and
reads its fixed 24-byte records in big blocks straight into numpy
(np.frombuffer -- no per-packet Python). Each block becomes (time, lane) pairs,
lane = (src IP, dst IP), and goes through logAnalsys's single-pass lane engine:
what / when / who come out of the same pass, so live capture gets them too.

    python3 ingest_run.py --gen-pcap test.pcap     # make a capture to try
    python3 ingest_run.py test.pcap                # per-conversation analysis
    python3 ingest_run.py test.pcap --by-source    # lanes per source IP only
    python3 ingest_run.py test.pcap --global       # one lane (naive, for comparison)
    python3 ingest_run.py test.pcap --heatmap      # 2D interval x size view
    sudo python3 ingest_run.py -i en0 'udp'        # live (needs root), Ctrl-C to report
"""

import argparse
import os
import socket
import struct
import subprocess

import numpy as np

import logAnalsys as la

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "ingest")
SRC = os.path.join(HERE, "ingest.c")
DTYPE = np.dtype([("ts", "<f8"), ("src", "<u4"), ("dst", "<u4"),
                  ("dport", "<u2"), ("proto", "<u2"), ("len", "<u4")])   # 24 bytes
REC = struct.Struct("<dIIHHI")
BLOCK = 16384                            # measured sweet spot: small sorts, low overhead


def ensure_binary():
    if os.path.exists(BIN) and os.path.getmtime(BIN) >= os.path.getmtime(SRC):
        return
    print("[build] compiling ingest.c ...")
    subprocess.run(["cc", "-O2", "-Wall", SRC, "-lpcap", "-o", BIN], check=True)


def _lanes(src, dst, mode):
    if mode == "global":
        return np.zeros(src.size, np.int64)
    if mode == "src":
        return la.lane_keys(src, np.zeros_like(dst))
    return la.lane_keys(src, dst)


def read_blocks(proc, mode="conv"):
    """(ts, lane) numpy blocks straight off the agent's pipe. Ctrl-C ends the
    stream cleanly so a live run still reports what it saw."""
    buf = b""
    want = DTYPE.itemsize * BLOCK
    try:
        while True:
            chunk = proc.stdout.read(want)
            if not chunk:
                break
            buf += chunk
            n = len(buf) // DTYPE.itemsize
            if not n:
                continue
            recs = np.frombuffer(buf[:n * DTYPE.itemsize], dtype=DTYPE)
            buf = buf[n * DTYPE.itemsize:]
            yield recs["ts"], _lanes(recs["src"], recs["dst"], mode)
    except KeyboardInterrupt:
        proc.terminate()


def heatmap_triples(proc, mode="conv"):
    """(ts, lane, size) one record at a time -- only the heatmap path needs size."""
    buf = b""
    while True:
        chunk = proc.stdout.read(REC.size * 8192)
        if not chunk:
            break
        buf += chunk
        n = len(buf) // REC.size
        if n:
            whole, buf = buf[:n * REC.size], buf[n * REC.size:]
            for ts, src, dst, _dport, _proto, size in REC.iter_unpack(whole):
                lane = 0 if mode == "global" else src if mode == "src" else (src, dst)
                yield ts, lane, size


# ---- a realistic test capture ------------------------------------------------

def _frame(src_ip, dst_ip, sport, dport, size):
    payload = b"\x00" * max(0, size - 42)
    eth = b"\xff\xff\xff\xff\xff\xff" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    return eth + ip + udp


def gen_pcap(path, **kw):
    """Valid .pcap (opens in Wireshark) of la.scenario_rows: infected laptops whose
    implant beacons to one C2 host while their users also browse, plus clean
    laptops. Frames are snapped to 64 bytes on disk (headers only, the way a
    capture with a snaplen would be) but keep their real on-wire length."""
    import random
    rng = random.Random(1234)
    rows = la.scenario_rows(seed=1234, **kw)
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 64, 1))
        for ts, src, dst, size, dport in rows:
            frame = _frame(src, dst, rng.randint(1024, 65535), dport, size)
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            if usec >= 1_000_000:
                sec, usec = sec + 1, usec - 1_000_000
            cap = frame[:64]
            f.write(struct.pack("<IIII", sec, usec, len(cap), len(frame)))
            f.write(cap)
    return len(rows)


# ---- runs -------------------------------------------------------------------

def run_lanes(args, cmd, mode):
    grid = la.Grid(args.fmin, args.fmax)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    spec, groups, stats = la.analyze(read_blocks(proc, mode), grid,
                                     args.regularity, args.min_hits)
    proc.wait()
    la.print_report(groups, stats)
    if not args.no_plot:
        try:
            la.plot_lanes(spec, grid, groups,
                          f"{len(groups)} beacon(s) found" if groups else "no beacon found")
        except Exception as e:
            print(f"(plot skipped: {e})")


def run_heatmap(args, cmd, mode):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    M, st = la.matrix_from_triples(heatmap_triples(proc, mode), args.bins,
                                   args.max_interval, args.max_size)
    proc.wait()
    print(f"[grid] {args.bins}x{args.bins}  packets used={st['used']}  lanes={st['sources']}")
    clusters, _ = la.find_clusters(M, args.bins, args.max_interval, args.max_size,
                                   args.top, args.min_frac, args.min_prom)
    flagged = [c for c in clusters if c["flagged"]]
    print()
    if flagged:
        prof = {}
        if not args.iface:
            p2 = subprocess.Popen(cmd, stdout=subprocess.PIPE)
            prof = la.profile_clusters(heatmap_triples(p2, mode),
                                       [(c["xbin"], c["ybin"]) for c in flagged],
                                       args.bins, args.max_interval, args.max_size)
            p2.wait()
        for c in flagged:
            print(la.describe(c, prof.get((c["xbin"], c["ybin"]))))
    else:
        print("[ok] no concentrated cluster -> traffic looks human.")
    if not args.no_plot:
        try:
            la.plot_matrix(M, clusters, args.max_interval, args.max_size,
                           f"{len(flagged)} beacon(s) found" if flagged else "no beacon")
        except Exception as e:
            print(f"(plot skipped: {e})")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source", nargs="?", help="capture .pcap file to analyze")
    ap.add_argument("filter", nargs="?", help="optional BPF filter, e.g. 'udp'")
    ap.add_argument("-i", "--iface", help="live capture on this interface (needs root)")
    ap.add_argument("--gen-pcap", metavar="PATH", dest="gen_pcap",
                    help="write a sample capture here and exit")
    ap.add_argument("--by-source", action="store_true", dest="by_source",
                    help="lanes per source IP only (ignore destination)")
    ap.add_argument("--global", action="store_true", dest="glob",
                    help="one lane for everything (the naive way, for comparison)")
    ap.add_argument("--fmin", type=float, default=1e-4)
    ap.add_argument("--fmax", type=float, default=100.0)
    ap.add_argument("--regularity", type=float, default=0.7)
    ap.add_argument("--min-hits", type=int, default=20, dest="min_hits")
    ap.add_argument("--heatmap", action="store_true",
                    help="2D interval-vs-size view instead of the lane analysis")
    ap.add_argument("--bins", type=int, default=256)
    ap.add_argument("--max-interval", type=float, default=1.0, dest="max_interval")
    ap.add_argument("--max-size", type=int, default=1500, dest="max_size")
    ap.add_argument("--top", type=int, default=5)
    ap.add_argument("--min-frac", type=float, default=0.06, dest="min_frac")
    ap.add_argument("--min-prom", type=float, default=8.0, dest="min_prom")
    ap.add_argument("--no-plot", action="store_true", dest="no_plot")
    args = ap.parse_args()

    if args.gen_pcap:
        n = gen_pcap(args.gen_pcap)
        print(f"wrote {n} packets to {args.gen_pcap}")
        return

    ensure_binary()
    mode = "global" if args.glob else "src" if args.by_source else "conv"
    if args.iface:
        cmd = [BIN, "-i", args.iface] + ([args.source] if args.source else [])
        print(f"[ingest] live on {args.iface} (root required). Ctrl-C to stop and report.")
    elif args.source:
        cmd = [BIN, args.source] + ([args.filter] if args.filter else [])
        print(f"[ingest] reading {args.source} via compiled agent  [lanes: {mode}]")
    else:
        ap.error("give a .pcap file, or -i <iface> for live, or --gen-pcap")

    (run_heatmap if args.heatmap else run_lanes)(args, cmd, mode)


if __name__ == "__main__":
    main()
