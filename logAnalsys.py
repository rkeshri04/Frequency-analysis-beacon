"""Offline beacon hunting from logs, by frequency, one conversation at a time.

Automated check-ins (C2 beacons, implants phoning home) repeat on a clock.
Humans don't. So for every conversation -- a (source IP, destination IP) pair --
we turn each gap between its packets into a frequency (1/gap) and drop it into
that conversation's own small log-frequency histogram. A beacon's gaps all land
in one narrow band; a person's are smeared across orders of magnitude.

Why per conversation and not one big spectrum for the whole log:
  * an infected laptop also browses -- keyed by (src, dst), the implant's lane
    holds only implant traffic, so the user's browsing can't shred its rhythm
  * a beacon that is 0.01% of a busy network still owns 100% of its own lane;
    the decision never depends on how much other traffic there is
  * "when" and "who" fall straight out of the lane -- no second pass

Pipeline:
  1. ingest      -- each packet becomes (time, src, dst); payload and text dropped
  2. lanes       -- gap = this packet - same conversation's previous packet
  3. accumulate  -- each gap lands in its lane's log-frequency histogram
  4. regular?    -- does most of the lane fall in one narrow band?
  5. group       -- regular lanes on the same cadence = one beacon
  6. report      -- what (cadence), when (first/last), who (hosts -> destinations)

Memory is the per-lane histograms: it grows with the number of conversations,
never with the number of packets. Processing runs on numpy blocks.

    python3 logAnalsys.py --gen-sample sample.log     # make test data
    python3 logAnalsys.py sample.log                  # analyze it
"""

import argparse
import math
import random
import re
import socket
import struct
import zlib
from datetime import datetime, timezone

import numpy as np


# ---- parsing: figure out whatever shape the log is in ----------------------

def parse_ts(s):
    """Return epoch seconds from an epoch number OR an ISO string, else None."""
    s = s.strip()
    try:
        v = float(s)
        if v > 1e8:                      # looks like an epoch, pick the unit
            if v > 1e14:
                return v / 1e6           # microseconds
            if v > 1e11:
                return v / 1e3           # milliseconds
            return v                     # seconds
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


DELIMS = [",", "\t", ";", "|"]


def split_line(line, delim):
    if delim == "ws":
        return re.split(r"\s+", line.strip())
    return [c.strip() for c in line.split(delim)]


def sniff_delim(lines):
    """Pick the delimiter that carves every sample line into the same number of
    columns (>=2). Whitespace is the fallback for space/tab-aligned logs."""
    best, best_score = None, (0, 0)
    for d in DELIMS + ["ws"]:
        counts = [len(split_line(l, d)) for l in lines]
        modal = max(set(counts), key=counts.count)
        if modal < 2:
            continue
        score = (counts.count(modal), modal)
        if score > best_score:
            best, best_score = d, score
    return best


IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def sniff_columns(rows):
    """Find the timestamp, size, source and destination columns.
    Returns (time_col, size_col, src_col, dst_col); the last two may be None.
    With two IP columns the first is taken as source (that's how conn logs and
    flow exports order them) -- override with --src-col / --dst-col."""
    ncol = len(rows[0])
    ts_hits = [0] * ncol
    ip_hits = [0] * ncol
    int_vals = [[] for _ in range(ncol)]
    for r in rows:
        if len(r) != ncol:
            continue
        for i, val in enumerate(r):
            if parse_ts(val) is not None:
                ts_hits[i] += 1
            if IPV4.match(val.strip()):
                ip_hits[i] += 1
            try:
                iv = int(val)
                if iv >= 0:
                    int_vals[i].append(iv)
            except ValueError:
                pass

    time_col = int(np.argmax(ts_hits))
    if ts_hits[time_col] < len(rows) * 0.6:
        raise ValueError("couldn't find a timestamp column")

    # size = an all-integer column that isn't the time, preferring the one whose
    # values vary the most (a real size moves around; a port tends to sit still)
    size_col, best_spread = None, -1
    for i in range(ncol):
        if i == time_col or len(int_vals[i]) < len(rows) * 0.9:
            continue
        spread = len(set(int_vals[i]))
        if spread > best_spread:
            size_col, best_spread = i, spread

    ip_cols = [i for i in range(ncol) if ip_hits[i] >= len(rows) * 0.6]
    src_col = ip_cols[0] if ip_cols else None
    dst_col = ip_cols[1] if len(ip_cols) > 1 else None
    return time_col, size_col, src_col, dst_col


def read_header(path, n=60):
    out = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            out.append(line)
            if len(out) >= n:
                break
    if not out:
        raise ValueError("log is empty")
    return out


# ---- addresses and lane keys ------------------------------------------------
# IPs are carried as uint32 in the same byte order the C agent emits (network
# bytes read little-endian), and a lane key packs (src, dst) into one int64.

_NAMES = {}                              # non-IP identifiers we had to hash


def ip_to_u32(s):
    try:
        return struct.unpack("<I", socket.inet_aton(s))[0]
    except OSError:
        v = zlib.crc32(s.encode())
        _NAMES[v] = s
        return v


def u32_to_ip(v):
    v = int(v)
    return _NAMES.get(v) or socket.inet_ntoa(struct.pack("<I", v))


def lane_keys(src, dst):
    k = (src.astype(np.uint64) << np.uint64(32)) | dst.astype(np.uint64)
    return k.view(np.int64)


def split_lanes(keys):
    k = np.asarray(keys, dtype=np.int64).view(np.uint64)
    return ((k >> np.uint64(32)).astype(np.uint32),
            (k & np.uint64(0xFFFFFFFF)).astype(np.uint32))


def text_blocks(path, delim, time_col, src_col, dst_col, mode="conv", block=16384):
    """Parse a text log into numpy blocks of (ts, lane_key).
    mode: conv = (src, dst) lanes, src = per source only, global = one lane."""
    cache = {}

    def u32(s):
        v = cache.get(s)
        if v is None:
            v = cache[s] = ip_to_u32(s)
        return v

    use_src = src_col is not None and mode != "global"
    use_dst = dst_col is not None and mode == "conv"
    need = max(c for c in (time_col, src_col, dst_col) if c is not None) + 1
    ts, sk, dk = [], [], []
    with open(path, "r", errors="replace") as f:
        for line in f:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            cells = split_line(line.rstrip("\n"), delim)
            if len(cells) < need:
                continue
            t = parse_ts(cells[time_col])
            if t is None:
                continue
            ts.append(t)
            sk.append(u32(cells[src_col].strip()) if use_src else 0)
            dk.append(u32(cells[dst_col].strip()) if use_dst else 0)
            if len(ts) >= block:
                yield _pack(ts, sk, dk)
                ts, sk, dk = [], [], []
    if ts:
        yield _pack(ts, sk, dk)


def _pack(ts, sk, dk):
    return (np.asarray(ts, np.float64),
            lane_keys(np.asarray(sk, np.uint32), np.asarray(dk, np.uint32)))


# ---- the lane engine -------------------------------------------------------

class Grid:
    """Log-frequency layout. Each lane gets `coarse` bins of fixed relative width
    (default 0.125 decades, ~33% wide); the all-traffic spectrum splits each of
    those into SUB finer bins for the chart. Relative width matters: jitter on a
    beacon is a percentage of its period, so it covers the same number of bins
    whether the beacon is hourly or every 20 ms."""

    SUB = 8

    def __init__(self, fmin=1e-4, fmax=100.0, coarse_width=0.125):
        self.fmin, self.fmax = fmin, fmax
        self.lf0 = math.log10(fmin)
        decades = math.log10(fmax) - self.lf0
        self.coarse = max(4, round(decades / coarse_width))
        self.fine = self.coarse * self.SUB
        self.per_decade = self.fine / decades

    def centers(self):
        edges = np.logspace(self.lf0, self.lf0 + self.fine / self.per_decade,
                            self.fine + 1)
        return np.sqrt(edges[:-1] * edges[1:])

    def fine_bin(self, lf):
        return np.floor((lf - self.lf0) * self.per_decade).astype(np.int64)


class _LaneTable:
    """A vectorized dict: lane key -> row. Rows are append-only, so the per-lane
    histograms never get shuffled around; a sorted index on the side answers a
    whole block of lookups with one searchsorted. Grows with lanes, not packets."""

    def __init__(self, **cols):
        self.spec = {"last": (np.float64, np.nan, None),
                     "born": (np.float64, np.nan, None)}
        for k, s in cols.items():
            self.spec[k] = s if len(s) == 3 else (*s, None)
        self.n = self.cap = 0
        self.keys = np.empty(0, np.int64)        # row -> key
        self.sorted = np.empty(0, np.int64)      # sorted keys
        self.rows = np.empty(0, np.int64)        # sorted position -> row
        self.cols = {k: self._alloc(k, 0) for k in self.spec}

    def _alloc(self, name, cap):
        dt, fill, width = self.spec[name]
        return np.full((cap, width) if width else cap, fill, dt)

    def find(self, q):
        pos = np.searchsorted(self.sorted, q)
        ok = pos < self.sorted.size
        ok[ok] = self.sorted[pos[ok]] == q[ok]
        rows = np.zeros(q.size, np.int64)
        rows[ok] = self.rows[pos[ok]]
        return rows, ok

    def add(self, new_keys):
        k = new_keys.size
        if self.n + k > self.cap:
            cap = max(2 * self.cap, self.n + k, 1024)
            for name in self.spec:
                grown = self._alloc(name, cap)
                grown[:self.n] = self.cols[name][:self.n]
                self.cols[name] = grown
            keys = np.empty(cap, np.int64)
            keys[:self.n] = self.keys[:self.n]
            self.keys, self.cap = keys, cap
        new_rows = np.arange(self.n, self.n + k)
        self.keys[self.n:self.n + k] = new_keys
        self.n += k
        order = np.argsort(new_keys, kind="stable")
        nk, nr = new_keys[order], new_rows[order]
        at = np.searchsorted(self.sorted, nk)
        self.sorted = np.insert(self.sorted, at, nk)
        self.rows = np.insert(self.rows, at, nr)
        return new_rows


def _chunk_gaps(ts, key, table):
    """Per-lane gaps for one block -> (gap, table_row). Gaps inside the block come
    from grouping by lane; each lane's first packet here is stitched to its last
    packet from earlier blocks through the table. Lanes are looked up once per
    block (not once per gap) and their rows fanned back out to the gaps."""
    key = key.astype(np.int64, copy=False)
    n = ts.size
    if n > 1 and np.all(ts[1:] >= ts[:-1]):
        order = np.argsort(key, kind="stable")    # time-sorted in, stable keeps it
    else:
        order = np.lexsort((ts, key))
    ts_s, key_s = ts[order], key[order]

    start = np.empty(n, dtype=bool)
    start[0] = True
    start[1:] = key_s[1:] != key_s[:-1]
    group = np.cumsum(start) - 1                  # which lane each position is
    inner = ~start[1:]
    gap = np.diff(ts_s)[inner]
    gap_group = group[1:][inner]

    firsts = np.flatnonzero(start)
    ends = np.append(firsts[1:] - 1, n - 1)
    fkey, fts, ets = key_s[firsts], ts_s[firsts], ts_s[ends]
    rows, seen = table.find(fkey)
    last = table.cols["last"]
    bridge = fts[seen] - last[rows[seen]]
    last[rows[seen]] = ets[seen]
    if not seen.all():
        new = table.add(fkey[~seen])
        table.cols["last"][new] = ets[~seen]
        table.cols["born"][new] = fts[~seen]
        rows[~seen] = new

    return np.concatenate([gap, bridge]), np.concatenate([rows[gap_group], rows[seen]])


def scan_lanes(blocks, grid):
    """The one pass. Every gap lands in its lane's coarse histogram (count, plus
    the sum of log-frequencies so we can read an exact cadence back out) and in
    the all-traffic fine spectrum used for the chart."""
    spec = np.zeros(grid.fine, np.int64)
    table = _LaneTable(hist=(np.uint32, 0, grid.coarse),
                       lsum=(np.float64, 0.0, grid.coarse))
    used = 0
    for ts, key in blocks:
        if ts.size == 0:
            continue
        gap, rows = _chunk_gaps(ts, key, table)
        ok = gap > 0
        lf = -np.log10(gap[ok])                  # log10 of frequency
        rows = rows[ok]
        idx = grid.fine_bin(lf)
        ok = (idx >= 0) & (idx < grid.fine)
        idx, lf, rows = idx[ok], lf[ok], rows[ok]
        if idx.size == 0:
            continue
        spec += np.bincount(idx, minlength=grid.fine)
        flat = rows * grid.coarse + idx // grid.SUB
        np.add.at(table.cols["hist"].reshape(-1), flat, 1)
        np.add.at(table.cols["lsum"].reshape(-1), flat, lf)
        used += idx.size
    return spec, table, {"intervals": used, "lanes": table.n}


def _wilson_lower(k, n, z):
    """Lower confidence bound on a proportion k/n. 14 of 20 is weaker evidence
    than 1000 of 1430 even though both read ~70% -- this says how sure we are."""
    n = np.maximum(n, 1).astype(np.float64)
    p = k / n
    z2 = z * z
    center = p + z2 / (2 * n)
    margin = z * np.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    return (center - margin) / (1 + z2 / n)


def regular_lanes(table, regularity=0.7, min_hits=20, z=2.33):
    """A lane is regular when most of its own gaps sit in one narrow band: the
    best pair of neighbouring coarse bins (~0.25 decades). We require the 99%
    lower bound of that share (not just the raw share) to clear `regularity`,
    so a short human lane that got lucky can't pass, while a perfectly steady
    beacon still does with as few as 20 gaps. Its cadence is the mean
    log-frequency inside that band, so a missed check-in (a gap twice as long,
    0.3 decades away) can't drag it off."""
    n = table.n
    empty = {k: np.empty(0) for k in ("key", "lf", "hits", "total", "conc", "born", "last")}
    if n == 0:
        return empty, {"eligible": 0}
    H = table.cols["hist"][:n].astype(np.int64)
    S = table.cols["lsum"][:n]
    total = H.sum(axis=1)
    win = H[:, :-1] + H[:, 1:]
    best = win.argmax(axis=1)
    r = np.arange(n)
    hits = win[r, best]
    conc = hits / np.maximum(total, 1)
    eligible = total >= min_hits
    ok = eligible & (_wilson_lower(hits, total, z) >= regularity)
    lf = (S[r, best] + S[r, best + 1]) / np.maximum(hits, 1)
    out = {"key": table.keys[:n][ok], "lf": lf[ok], "hits": hits[ok],
           "total": total[ok], "conc": conc[ok],
           "born": table.cols["born"][:n][ok], "last": table.cols["last"][:n][ok]}
    return out, {"eligible": int(eligible.sum())}


def group_cadences(reg, tol=0.06):
    """Regular lanes whose cadences sit within `tol` decades (~15%) of each other
    are one beacon -- many infected hosts, one clock."""
    if reg["lf"].size == 0:
        return []
    order = np.argsort(reg["lf"])
    cuts = np.flatnonzero(np.diff(reg["lf"][order]) > tol) + 1
    groups = []
    for ids in np.split(order, cuts):
        src, dst = split_lanes(reg["key"][ids])
        f = 10 ** float(np.median(reg["lf"][ids]))
        groups.append({
            "freq": f, "period": 1.0 / f,
            "lanes": int(ids.size),
            "hits": int(reg["hits"][ids].sum()),
            "regularity": float(np.average(reg["conc"][ids], weights=reg["hits"][ids])),
            "first": float(reg["born"][ids].min()),
            "last": float(reg["last"][ids].max()),
            "srcs": np.unique(src), "dsts": np.unique(dst),
            "lf": reg["lf"][ids], "w": reg["hits"][ids],
        })
    groups.sort(key=lambda g: g["hits"], reverse=True)
    return groups


def analyze(blocks, grid, regularity=0.7, min_hits=20):
    spec, table, stats = scan_lanes(blocks, grid)
    reg, more = regular_lanes(table, regularity, min_hits)
    stats.update(more)
    stats["regular"] = int(reg["key"].size)
    stats["min_hits"] = min_hits
    return spec, group_cadences(reg), stats


# ---- reporting -------------------------------------------------------------

def _fmt_period(p):
    if p >= 3600:
        return f"{p/3600:.2f} h"
    if p >= 60:
        return f"{p/60:.2f} min"
    if p >= 1:
        return f"{p:.2f} s"
    return f"{p*1000:.1f} ms"


def _fmt_dur(s):
    s = int(round(s))
    if s >= 86400:
        return f"{s // 86400}d {s % 86400 // 3600}h"
    if s >= 3600:
        return f"{s // 3600}h {s % 3600 // 60}m"
    if s >= 60:
        return f"{s // 60}m {s % 60}s"
    return f"{s}s"


def _ips(vals, limit=6):
    vals = [v for v in vals.tolist() if v]       # 0 == not in the log
    if not vals:
        return "(not in log)"
    shown = ", ".join(u32_to_ip(v) for v in vals[:limit])
    return shown + (f"  (+{len(vals) - limit} more)" if len(vals) > limit else "")


def describe_cadence(g):
    t0 = datetime.fromtimestamp(g["first"])
    t1 = datetime.fromtimestamp(g["last"])
    nsrc = int((g["srcs"] != 0).sum()) or len(g["srcs"])
    ndst = int((g["dsts"] != 0).sum())
    return "\n".join([
        f"[BEACON] ~{g['freq']:.3g} Hz  (every ~{_fmt_period(g['period'])})   "
        f"{g['lanes']} conversation(s), {g['hits']:,} on-beat check-ins, "
        f"{g['regularity']:.0%} on the beat",
        "         what : a steady periodic beacon -> automated, not human",
        f"         when : {t0:%Y-%m-%d %H:%M:%S} -> {t1:%Y-%m-%d %H:%M:%S} "
        f"(active {_fmt_dur(g['last'] - g['first'])})",
        f"         who  : {nsrc} host(s) -> {ndst or '?'} destination(s)",
        f"         src  : {_ips(g['srcs'])}",
        f"         dst  : {_ips(g['dsts'])}",
    ])


def print_report(groups, stats):
    print(f"[lanes] {stats['lanes']:,} conversations, {stats['eligible']:,} with "
          f">= {stats['min_hits']} intervals, {stats['regular']:,} regular   "
          f"({stats['intervals']:,} intervals)")
    print()
    if not groups:
        print("[ok] no regular conversation -> nothing beacon-like here.")
    for g in groups:
        print(describe_cadence(g))


def plot_lanes(spec, grid, groups, title):
    """Top: every interval in the log (context -- a quiet beacon can be invisible
    here). Bottom: only the regular conversations, placed at their cadence and
    weighted by on-beat check-ins. Flat except where a beacon lives."""
    import matplotlib.pyplot as plt
    centers = grid.centers()
    reg = np.zeros(grid.fine)
    for g in groups:
        idx = np.clip(grid.fine_bin(g["lf"]), 0, grid.fine - 1)
        np.add.at(reg, idx, g["w"])

    fig, (top, bot) = plt.subplots(2, 1, sharex=True, figsize=(11, 7),
                                   gridspec_kw={"height_ratios": [1, 1.4]})
    fig.canvas.manager.set_window_title("logAnalsys")
    top.fill_between(centers, spec, step="mid", color="#9aa5b1", alpha=0.45)
    top.plot(centers, spec, color="#7b8794", lw=0.9)
    top.set_ylabel("all traffic\n(intervals)")
    top.set_title(title)
    bot.fill_between(centers, reg, step="mid", color="#4a6fa5", alpha=0.35)
    bot.plot(centers, reg, color="#4a6fa5", lw=1.1)
    for g in groups:
        bot.axvline(g["freq"], color="#d64545", ls="--", lw=1.0, alpha=0.6)
        bot.annotate(f"{g['freq']:.3g} Hz\nevery {_fmt_period(g['period'])}\n"
                     f"{g['lanes']} conv.", (g["freq"], reg.max() or 1),
                     color="#d64545", fontsize=9, xytext=(6, -30),
                     textcoords="offset points")
    bot.set_ylabel("regular conversations\n(on-beat check-ins)")
    bot.set_xscale("log")
    bot.set_xlabel("frequency (Hz)  [log scale]   <- slower beacons   faster ->")
    plt.tight_layout()
    plt.show()


# ---- the 2D interval x size view (--heatmap) --------------------------------

def stream_rows(path, delim, time_col, size_col, src_col, dst_col, mode="conv"):
    """(ts, lane, size) per parseable line, for the heatmap path."""
    need = max(c for c in (time_col, size_col, src_col, dst_col) if c is not None) + 1
    with open(path, "r", errors="replace") as f:
        for line in f:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            cells = split_line(line.rstrip("\n"), delim)
            if len(cells) < need:
                continue
            ts = parse_ts(cells[time_col])
            if ts is None:
                continue
            try:
                size = int(cells[size_col])
            except ValueError:
                continue
            if mode == "global" or src_col is None:
                lane = 0
            elif mode == "src" or dst_col is None:
                lane = cells[src_col].strip()
            else:
                lane = (cells[src_col].strip(), cells[dst_col].strip())
            yield ts, lane, size


def matrix_from_triples(triples, bins, max_interval, max_size):
    """Fold (ts, lane, size) into a fixed bins x bins grid, interval measured
    per lane. Grid is fixed; one last-timestamp per lane."""
    M = np.zeros((bins, bins), dtype=np.int64)
    last = {}
    used = reorder = overflow = 0
    for ts, src, size in triples:
        prev = last.get(src)
        last[src] = ts
        if prev is None:
            continue
        gap = ts - prev
        if gap < 0:
            reorder += 1
            continue
        xi = int(gap / max_interval * bins)
        yi = int(size / max_size * bins)
        if 0 <= xi < bins and 0 <= yi < bins:
            M[xi, yi] += 1
            used += 1
        else:                            # off the chart -- don't fake an edge line
            overflow += 1
    return M, {"used": used, "reorder": reorder, "overflow": overflow,
               "sources": len(last)}


def find_clusters(M, bins, max_interval, max_size, top, min_frac, min_prom):
    """Hottest cells first, each scored by how far it towers over a typical cell
    and its share of traffic; wipe its 3x3 patch and look again."""
    total = int(M.sum())
    if total == 0:
        return [], 0
    nz = M[M > 0]
    floor = float(np.median(nz)) if nz.size else 1.0
    work = M.astype(float).copy()
    out = []
    for _ in range(top):
        xi, yi = np.unravel_index(int(np.argmax(work)), work.shape)
        peak = work[xi, yi]
        if peak <= 0:
            break
        x0, x1 = max(0, xi - 1), min(bins, xi + 2)
        y0, y1 = max(0, yi - 1), min(bins, yi + 2)
        cell = float(work[x0:x1, y0:y1].sum())
        work[x0:x1, y0:y1] = 0.0
        interval = (xi + 0.5) / bins * max_interval
        out.append({
            "xbin": int(xi), "ybin": int(yi),
            "interval": interval,
            "freq": (1.0 / interval) if interval > 0 else float("inf"),
            "size": (yi + 0.5) / bins * max_size,
            "count": int(cell),
            "frac": cell / total,
            "prom": peak / max(floor, 1e-9),
            "flagged": (cell / total >= min_frac) and (peak / max(floor, 1e-9) >= min_prom),
        })
    return out, total


def profile_clusters(triples, targets, bins, max_interval, max_size):
    """Second pass for the heatmap: time window and lanes feeding each cell."""
    center = {}
    for (cx, cy) in targets:
        for dx in (-1, 0, 1):
            for dy in (-1, 0, 1):
                center[(cx + dx, cy + dy)] = (cx, cy)
    acc = {t: {"count": 0, "srcs": set(),
               "first": float("inf"), "last": float("-inf")} for t in targets}
    last = {}
    for ts, src, size in triples:
        prev = last.get(src)
        last[src] = ts
        if prev is None:
            continue
        gap = ts - prev
        if gap < 0:
            continue
        tgt = center.get((int(gap / max_interval * bins), int(size / max_size * bins)))
        if tgt is None:
            continue
        a = acc[tgt]
        a["count"] += 1
        a["srcs"].add(src)
        a["first"] = min(a["first"], ts)
        a["last"] = max(a["last"], ts)
    return acc


def describe(c, prof=None):
    lines = [
        f"[BEACON] every ~{c['interval']*1000:.1f} ms (~{c['freq']:.2f} Hz), "
        f"~{c['size']:.0f} B packets   {c['count']} hits, {c['frac']:.0%} of traffic, "
        f"prominence {c['prom']:.0f}x"
    ]
    if prof and prof["count"]:
        t0 = datetime.fromtimestamp(prof["first"])
        t1 = datetime.fromtimestamp(prof["last"])
        lines.append("         what : a steady periodic beacon -> automated, not human")
        lines.append(f"         when : {t0:%Y-%m-%d %H:%M:%S} -> {t1:%Y-%m-%d %H:%M:%S} "
                     f"(active {_fmt_dur(prof['last'] - prof['first'])})")
        lines.append(f"         who  : {len(prof['srcs'])} conversation(s) on this cell")
    return "\n".join(lines)


def plot_matrix(M, clusters, max_interval, max_size, title):
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(9, 6))
    fig.canvas.manager.set_window_title("logAnalsys")
    im = ax.imshow(np.log1p(M.T), origin="lower", aspect="auto", cmap="magma",
                   extent=[0, max_interval, 0, max_size])
    fig.colorbar(im, ax=ax, label="log(1 + packet count)")
    ax.set_xlabel("inter-arrival interval (s)")
    ax.set_ylabel("packet size (bytes)")
    ax.set_title(title)
    for c in clusters:
        if not c["flagged"]:
            continue
        ax.scatter([c["interval"]], [c["size"]], s=260, facecolors="none",
                   edgecolors="#36d399", linewidths=2.0)
        ax.annotate(f"{c['freq']:.2f} Hz\n{c['size']:.0f} B",
                    (c["interval"], c["size"]), color="#36d399",
                    fontsize=9, xytext=(8, 8), textcoords="offset points")
    plt.tight_layout()
    plt.show()


# ---- sample data -----------------------------------------------------------

def scenario_rows(infected=12, clean=60, minutes=20, period=5.0, seed=None):
    """A realistic-ish office: `infected` laptops each run an implant checking in
    to one C2 host every `period` seconds -- AND their users browse normally from
    the same IP. `clean` laptops just browse. The beacon is a small slice of the
    traffic and shares its source IPs with human browsing.
    Rows: (ts, src_ip, dst_ip, size, dport), time-sorted."""
    rng = random.Random(seed)
    t0, span = 1790961600.0, minutes * 60
    c2 = "203.0.113.5"
    sites = [f"198.51.100.{i}" for i in range(1, 80)]
    rows = []

    def browse(host):
        t = t0 + rng.uniform(0, 30)
        while t < t0 + span:
            site = rng.choice(sites)                 # a page load: quick burst
            for _ in range(rng.randint(3, 25)):
                rows.append((t, host, site, rng.randint(200, 1400), 443))
                t += rng.uniform(0.02, 0.6)
            t += rng.expovariate(1 / 20)             # reading time

    for i in range(infected):
        host = f"10.0.0.{101 + i}"
        t = t0 + rng.uniform(0, period)
        while t < t0 + span:
            rows.append((t, host, c2, 44 + rng.randint(-2, 2), 443))
            t += period + rng.gauss(0, period * 0.01)
        browse(host)
    for i in range(clean):
        browse(f"10.0.1.{1 + i}")
    rows.sort(key=lambda r: r[0])
    return rows


def gen_sample(path, fmt=None, **kw):
    fmt = fmt or random.choice(["epoch_comma", "iso_tab", "epoch_ws", "ms_semicolon"])
    rows = scenario_rows(**kw)

    def fmt_ts(ts):
        if fmt == "iso_tab":
            return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z")
        if fmt == "ms_semicolon":
            return str(int(ts * 1000))
        return f"{ts:.6f}"

    sep = {"epoch_comma": ",", "iso_tab": "\t", "epoch_ws": " ", "ms_semicolon": ";"}[fmt]
    with open(path, "w") as f:
        f.write("# sample traffic log: timestamp, src, dst, bytes\n")
        for ts, src, dst, size, _ in rows:
            f.write(f"{fmt_ts(ts)}{sep}{src}{sep}{dst}{sep}{size}\n")
    return fmt, len(rows)


# ---- cli -------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logfile", nargs="?", help="log to analyze")
    ap.add_argument("--gen-sample", metavar="PATH", dest="gen_sample",
                    help="write a sample log here and exit")
    ap.add_argument("--fmin", type=float, default=1e-4,
                    help="slowest cadence to look for, Hz (default 1e-4 = ~2.8 h period)")
    ap.add_argument("--fmax", type=float, default=100.0,
                    help="fastest cadence to look for, Hz (default 100 = 10 ms)")
    ap.add_argument("--regularity", type=float, default=0.7,
                    help="share of a conversation's gaps that must sit in one band (default 0.7)")
    ap.add_argument("--min-hits", type=int, default=20, dest="min_hits",
                    help="gaps a conversation needs before it's judged (default 20)")
    ap.add_argument("--time-col", type=int, dest="time_col")
    ap.add_argument("--size-col", type=int, dest="size_col")
    ap.add_argument("--src-col", type=int, dest="src_col")
    ap.add_argument("--dst-col", type=int, dest="dst_col")
    ap.add_argument("--by-source", action="store_true", dest="by_source",
                    help="lanes per source IP only (ignore destination)")
    ap.add_argument("--global", action="store_true", dest="glob",
                    help="one lane for everything (the naive way, for comparison)")
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

    if args.gen_sample:
        fmt, n = gen_sample(args.gen_sample)
        print(f"wrote {n} rows to {args.gen_sample} (format: {fmt})")
        return
    if not args.logfile:
        ap.error("give a logfile to analyze, or use --gen-sample to make one")

    header = read_header(args.logfile)
    delim = sniff_delim(header)
    if delim is None:
        ap.error("couldn't figure out the delimiter; check the file")
    rows = [split_line(l, delim) for l in header]
    rows = [r for r in rows if len(r) == len(rows[0])]
    try:
        time_col, size_col, src_col, dst_col = sniff_columns(rows)
    except ValueError as e:
        ap.error(f"{e}; set the columns by hand with --time-col etc.")
    time_col =args.time_col if args.time_col is not None else time_col
    size_col = args.size_col if args.size_col is not None else size_col
    src_col = args.src_col if args.src_col is not None else src_col
    dst_col = args.dst_col if args.dst_col is not None else dst_col
    mode = "global" if args.glob else "src" if args.by_source else "conv"

    pretty = {",": "comma", "\t": "tab", ";": "semicolon", "|": "pipe", "ws": "whitespace"}[delim]
    ts_style = "ISO" if not rows[0][time_col].strip().replace(".", "").isdigit() else "epoch"
    lanes = {"global": "one global lane",
             "src": f"per source (col {src_col})",
             "conv": f"per conversation (src col {src_col} -> dst col {dst_col})"}[mode]
    print(f"[parse] delimiter={pretty}  time_col={time_col} ({ts_style})  "
          f"size_col={size_col}  lanes: {lanes}")
    if mode == "conv" and dst_col is None:
        print("[warn ] no destination column -- lanes fall back to per-source, so an "
              "implant on a busy laptop can hide in its user's browsing")

    if args.heatmap:
        if size_col is None:
            ap.error("the heatmap needs a size column")
        make = lambda: stream_rows(args.logfile, delim, time_col, size_col,
                                   src_col, dst_col, mode)
        M, st = matrix_from_triples(make(), args.bins, args.max_interval, args.max_size)
        print(f"[grid]  {args.bins}x{args.bins}  packets used={st['used']}  lanes={st['sources']}")
        clusters, _ = find_clusters(M, args.bins, args.max_interval, args.max_size,
                                    args.top, args.min_frac, args.min_prom)
        flagged = [c for c in clusters if c["flagged"]]
        print()
        if flagged:
            prof = profile_clusters(make(), [(c["xbin"], c["ybin"]) for c in flagged],
                                    args.bins, args.max_interval, args.max_size)
            for c in flagged:
                print(describe(c, prof.get((c["xbin"], c["ybin"]))))
        else:
            print("[ok] no concentrated interval/size cluster -> traffic looks human.")
        if not args.no_plot:
            try:
                plot_matrix(M, clusters, args.max_interval, args.max_size,
                            f"{len(flagged)} beacon(s) found" if flagged else "no beacon")
            except Exception as e:
                print(f"(plot skipped: {e})")
        return

    grid = Grid(args.fmin, args.fmax)
    spec, groups, stats = analyze(
        text_blocks(args.logfile, delim, time_col, src_col, dst_col, mode),
        grid, args.regularity, args.min_hits)
    print_report(groups, stats)
    if not args.no_plot:
        try:
            plot_lanes(spec, grid, groups,
                       f"{len(groups)} beacon(s) found" if groups else "no beacon found")
        except Exception as e:
            print(f"(plot skipped: {e})")


if __name__ == "__main__":
    main()
