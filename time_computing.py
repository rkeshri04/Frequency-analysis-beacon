"""Us vs the industry standard: cost of the full beacon hunt over a big log.

  OURS  -- logAnalsys's lane engine: one streaming pass, every conversation
           (src, dst) gets a small log-frequency histogram; regular lanes are
           grouped by cadence. Out comes what (cadence), when (first/last) and
           who (hosts -> destinations) -- the whole answer, one pass.

  RITA-style -- the common open-source approach (Active Countermeasures' RITA and
           friends): keep every connection grouped by (src, dst), sort each
           group's timestamps, score regularity with MADM. Correct, but it holds
           every timestamp, so memory grows with the log.

Both get identical events keyed by conversation, and both return the list of
beaconing conversations -- same job, same output.
Data is generated in RAM so you can push --scale.
"""

import argparse
import random
import time
import tracemalloc

import numpy as np

import logAnalsys as la

CHUNK = 16384                            # measured sweet spot: small sorts, low overhead
C2 = 0xCB007105                          # any fixed destination id


def gen_events(bots, per_bot, humans, per_human, seed=1234):
    """`bots` hosts beaconing to one C2 every 0.15s (1% jitter), plus `humans`
    hosts browsing in bursts. Time-sorted (ts, lane, size)."""
    rng = random.Random(seed)
    t0 = 1790961600.0
    ev = []
    for b in range(bots):
        lane = (b + 1) << 32 | C2
        t = t0 + rng.uniform(0, 0.15)
        for _ in range(per_bot):
            t += 0.15 + rng.gauss(0, 0.0015)
            ev.append((t, lane, 44))
    for h in range(humans):
        lane = (1_000_000 + h) << 32 | (h % 80 + 1)
        t = t0 + rng.uniform(0, 5)
        for _ in range(per_human):
            t += rng.uniform(0.02, 0.6) if rng.random() < 0.75 else rng.expovariate(1 / 20)
            ev.append((t, lane, rng.randint(200, 1400)))
    ev.sort(key=lambda e: e[0])
    return ev


# ---- ours ----------------------------------------------------------------

def ours(ts, lanes):
    blocks = ((ts[i:i + CHUNK], lanes[i:i + CHUNK]) for i in range(0, ts.size, CHUNK))
    _, groups, _ = la.analyze(blocks, la.Grid())
    return groups                                 # what / when / who per cadence


def ours_found(groups):
    return sum(g["lanes"] for g in groups)


# ---- RITA-style baseline --------------------------------------------------

def _regular(deltas, min_conn=20, regularity=0.7):
    if deltas.size < min_conn:
        return False
    med = np.median(deltas)
    if med <= 0:
        return False
    madm = np.median(np.abs(deltas - med))
    return 1.0 - madm / med >= regularity


def rita_lists(events):
    from collections import defaultdict
    by_lane = defaultdict(list)
    for ts, lane, size in events:
        by_lane[lane].append(ts)
    return [lane for lane, tss in by_lane.items()
            if _regular(np.diff(np.sort(np.asarray(tss))))]


def rita_numpy(ts, lanes):
    order = np.lexsort((ts, lanes))
    ts_s, ln_s = ts[order], lanes[order]
    cuts = np.flatnonzero(ln_s[1:] != ln_s[:-1]) + 1
    return [int(l[0]) for g, l in zip(np.split(ts_s, cuts), np.split(ln_s, cuts))
            if _regular(np.diff(g))]


# ---- harness --------------------------------------------------------------

def measure(fn, *a):
    best = float("inf")
    for _ in range(3):
        t0 = time.perf_counter()
        out = fn(*a)
        best = min(best, time.perf_counter() - t0)
    tracemalloc.start()
    fn(*a)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return best, peak, out


def scenario(title, bots, per_bot, humans, per_human):
    ev = gen_events(bots, per_bot, humans, per_human)
    n = len(ev)
    ts = np.fromiter((e[0] for e in ev), np.float64, n)
    lanes = np.fromiter((e[1] for e in ev), np.uint64, n).view(np.int64)

    print(f"\n=== {title}: {bots} beaconing hosts + {humans} browsing hosts, "
          f"{n:,} events ===")
    ot, om, groups = measure(ours, ts, lanes)
    lt, lm, lf = measure(rita_lists, ev)
    nt, nm, nf = measure(rita_numpy, ts, lanes)
    rt, rm, rf = (lt, lm, lf) if lt <= nt else (nt, nm, nf)

    print(f"  {'method':<14}{'found':>16}{'time':>11}{'throughput':>13}{'peak mem':>11}")
    print(f"  {'OURS':<14}{ours_found(groups):>6} beacon lanes{ot*1e3:>9.1f}ms"
          f"{n/ot/1e6:>10.2f}M/s{om/1e6:>9.2f}MB")
    print(f"  {'RITA (best)':<14}{len(rf):>6} beacon lanes{rt*1e3:>9.1f}ms"
          f"{n/rt/1e6:>10.2f}M/s{rm/1e6:>9.2f}MB")
    print(f"  -> {rt/ot:.2f}x RITA's speed, {rm/max(om,1):.1f}x less memory   "
          f"(ours also returns cadence + when, in the same pass)")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scale", type=int, default=1, help="multiplier on dataset size")
    s = ap.parse_args().scale
    scenario("few hosts", 30, 4000 * s, 200, 2400 * s)
    # scenario("big botnet", 5000, 60 * s, 2000, 200 * s)
    # scenario("bigger botnet", 20000, 60 * s, 8000, 200 * s)
    scenario("even bigger botnet", 100000, 60 * s, 40000, 200 * s)

    print("\nour memory grows with the number of conversations; RITA's grows with")
    print("every connection it keeps -- run --scale 4 / 8 and watch the gap widen.")


if __name__ == "__main__":
    main()
