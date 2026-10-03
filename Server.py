#!/usr/bin/env python3
"""Spots periodic traffic (beacons, cron check-ins, polling loops) by watching
the frequency domain instead of individual packets.

The trick: anything on a clock keeps dumping energy into the same frequency bin
window after window, so if we keep a decaying running sum of the spectrum
(acc = acc*decay + fft) the repeating stuff piles up while random human traffic
just bleeds away. We don't trust a single tall bin though -- a real periodic
signal at f0 also shows up at 2*f0, 3*f0, ... so we only flag it when a few of
those harmonics light up together for a couple of windows. The fundamental is
searched for, nothing is hardcoded to a particular rate.

Run this first, then fire up hacker_botnet.py. Needs numpy + matplotlib.
"""

import argparse
import socket
import threading
import time

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation


class SpectralMemory:
    """Holds the socket, the sampling loop and the running spectrum. Everything
    is fixed-size arrays so memory stays flat; the GUI just reads snapshots."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.dt = 1.0 / cfg.fs
        self.nbins = cfg.window // 2 + 1
        self.bin_hz = cfg.fs / cfg.window
        self.freqs = np.arange(self.nbins) * self.bin_hz
        self.win_fn = np.hanning(cfg.window)

        self.acc = np.zeros(self.nbins)
        self._buf = np.zeros(cfg.window)       # last `window` samples, sliding
        self._filled = 0
        self._since_fft = 0

        self.cand = np.arange(cfg.fmin, cfg.fmax + 1e-9, cfg.fstep)

        self._streak = 0
        self._last_f0 = None
        self.blocked = []          # cadences we've already quarantined
        self.lock = threading.Lock()
        self.result = self._blank()
        self._running = False

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((cfg.host, cfg.port))
        self.sock.setblocking(False)

    @staticmethod
    def _blank():
        return {"fundamental": None, "teeth": [], "teeth_hz": [],
                "proms": [], "hits": 0, "score": 0.0, "confirmed": False,
                "blocked_f0": [], "blocked_bins": []}

    def _prominence(self, acc, b, mask, gfloor):
        # how tall bin b is vs its neighbours. skip already-blocked bins and
        # keep a floor so a notched (zeroed) gap doesn't blow the ratio up
        lo = max(1, b - 6)
        hi = min(self.nbins, b + 7)
        nb = [acc[j] for j in range(lo, hi) if abs(j - b) > 1 and not mask[j]]
        base = max(np.median(nb) if nb else gfloor, gfloor)
        return acc[b] / base

    def _detect(self, acc):
        best = self._blank()
        H = self.cfg.harmonics
        mask = np.zeros(self.nbins, dtype=bool)
        for r in self.blocked:
            mask[list(r["band"])] = True
        live = acc[1:][~mask[1:]]
        gfloor = max(float(np.median(live)) if live.size else 1.0, 1e-3)
        for f0 in self.cand:
            teeth = []
            for h in range(1, H + 1):
                b = int(round(h * f0 / self.bin_hz))
                if 1 <= b < self.nbins:
                    teeth.append(b)
            if not teeth:
                continue
            proms = [self._prominence(acc, b, mask, gfloor) for b in teeth]
            hits = sum(1 for p in proms if p >= self.cfg.prom_ratio)
            score = float(sum(acc[b] for b in teeth))
            # most teeth wins, energy breaks the tie
            if (hits, score) > (best["hits"], best["score"]):
                best = {"fundamental": round(float(f0), 2), "teeth": teeth,
                        "teeth_hz": [round(float(self.freqs[b]), 2) for b in teeth],
                        "proms": [round(float(p), 1) for p in proms],
                        "hits": hits, "score": score, "confirmed": False,
                        "blocked_f0": [], "blocked_bins": []}

        # don't fire on a single lucky window -- same f0 has to hold for a few
        enough = best["hits"] >= self.cfg.min_hits
        same = (self._last_f0 is not None and best["fundamental"] is not None
                and abs(best["fundamental"] - self._last_f0) <= 2 * self.cfg.fstep)
        self._streak = self._streak + 1 if (enough and same) else (1 if enough else 0)
        self._last_f0 = best["fundamental"]
        best["confirmed"] = enough and self._streak >= self.cfg.confirm_streak
        return best

    def _is_blocked(self, f0):
        return any(abs(f0 - r["f0"]) <= self.cfg.block_tol for r in self.blocked)

    def _apply_safeguards(self, acc):
        # zero the comb bins of anything we've quarantined so it can't build up
        # in memory again. the packets still arrive, they just can't resonate.
        # a real deployment would also push a firewall/IPS rule here -- we keep
        # it in-process and reversible instead of poking the system firewall.
        for r in self.blocked:
            acc[list(r["band"])] = 0.0

    def _maybe_block(self, acc, res):
        if self.cfg.detect_only or not res["confirmed"]:
            return
        f0 = res["fundamental"]
        if self._is_blocked(f0):
            return                              # seen it, stay quiet

        band = {b + d for b in res["teeth"] for d in (-1, 0, 1)}
        band = {b for b in band if 1 <= b < self.nbins}
        rule = {"id": len(self.blocked) + 1, "f0": f0, "band": band,
                "teeth_hz": res["teeth_hz"], "t": time.time()}
        self.blocked.append(rule)
        self._apply_safeguards(acc)             # crush it right now
        self._streak = 0                        # fresh start for the next one

        ts = time.strftime("%H:%M:%S")
        print(f"\n[{ts}] [ALERT] new periodic pattern locked "
              f"-> fundamental ~{f0} Hz (period ~{1.0/f0:.3f}s)")
        print(f"          harmonic comb {res['teeth_hz']} Hz   "
              f"prominence {res['proms']}   {res['hits']}/{self.cfg.harmonics} teeth")
        print(f"[{ts}] [SAFEGUARD] rule #{rule['id']} installed against ~{f0} Hz "
              f"-> this cadence is now suppressed; it will not alert again.")
        active = ", ".join(f"#{r['id']}~{r['f0']}Hz" for r in self.blocked)
        print(f"          active safeguards: {active}")

    def _drain_slot(self):
        # count whatever showed up this tick. we never look at the payload, so
        # there's nothing untrusted to parse.
        count = 0
        while True:
            try:
                self.sock.recvfrom(2048)
                count += 1
            except BlockingIOError:
                break
        return count

    def run(self):
        self._running = True
        next_tick = time.perf_counter()
        while self._running:
            next_tick += self.dt

            sample = self._drain_slot()
            self._buf[:-1] = self._buf[1:]
            self._buf[-1] = sample
            self._filled = min(self._filled + 1, self.cfg.window)
            self._since_fft += 1

            if self._filled >= self.cfg.window and self._since_fft >= self.cfg.hop:
                self._since_fft = 0
                x = (self._buf - self._buf.mean()) * self.win_fn
                mag = np.abs(np.fft.rfft(x))
                acc = self.acc * self.cfg.decay + mag
                self._apply_safeguards(acc)
                res = self._detect(acc)
                self._maybe_block(acc, res)
                res["blocked_f0"] = [r["f0"] for r in self.blocked]
                res["blocked_bins"] = sorted({b for r in self.blocked
                                              for b in r["band"]})
                with self.lock:
                    self.acc = acc
                    self.result = res

            now = time.perf_counter()
            if now < next_tick:
                time.sleep(next_tick - now)
            else:
                next_tick = now                 # we're behind, don't spiral

    def stop(self):
        self._running = False

    def snapshot(self):
        with self.lock:
            return self.acc.copy(), dict(self.result)


def build_gui(mem):
    fig, ax = plt.subplots(figsize=(11, 5))
    fig.canvas.manager.set_window_title("net_resonance_defender")

    freqs = mem.freqs[1:]                        # drop DC
    bars = ax.bar(freqs, np.zeros(len(freqs)), width=mem.bin_hz * 0.9,
                  color="#4a6fa5", align="center")
    ax.set_xlim(0, min(mem.cfg.fs / 2, mem.cfg.fmax * mem.cfg.harmonics + 3))
    ax.set_xlabel("frequency (Hz)")
    ax.set_ylabel("accumulated energy (decaying memory)")
    status = ax.text(0.015, 0.96, "", transform=ax.transAxes, va="top",
                     fontsize=11, family="monospace")

    def update(_):
        acc, res = mem.snapshot()
        vals = acc[1:]
        teeth = set(res["teeth"])
        blocked_bins = set(res["blocked_bins"])
        blocked_f0 = res["blocked_f0"]
        # it's only a "new" alert until the safeguard kicks in for it
        new_alert = res["confirmed"] and res["fundamental"] not in blocked_f0
        for i, bar in enumerate(bars):
            k = i + 1
            if k in blocked_bins:
                bar.set_color("#3aa76d")             # green = handled
            elif k in teeth:
                bar.set_color("#d64545" if new_alert else "#e0a458")
            else:
                bar.set_color("#4a6fa5")
            bar.set_height(vals[i])
        ax.set_ylim(0, max(vals.max(), 1.0) * 1.15)

        guard = ""
        if blocked_f0:
            guard = ("SAFEGUARDS ACTIVE (cadence suppressed): "
                     + "  ".join(f"~{f} Hz" for f in blocked_f0) + "\n")
        if new_alert:
            f0 = res["fundamental"]
            body = (f"ALERT  periodic signal ~{f0} Hz  (period ~{1.0/f0:.3f}s)\n"
                    f"comb {res['teeth_hz']} Hz  prominence {res['proms']}\n"
                    f"{res['hits']}/{mem.cfg.harmonics} teeth aligned -> automated, not human")
            color = "#d64545"
            ax.set_facecolor("#fff5f5")
        elif res["fundamental"] and res["hits"]:
            body = (f"watching ~{res['fundamental']} Hz  "
                    f"{res['hits']}/{mem.cfg.harmonics} teeth  (comb still forming)")
            color = "#8a6d1a"
            ax.set_facecolor("#fffdf5")
        else:
            body = "listening... no new harmonic comb"
            color = "#2d6a4f" if blocked_f0 else "#444444"
            ax.set_facecolor("#f4fbf6" if blocked_f0 else "white")
        status.set_text(guard + body)
        status.set_color(color)
        return list(bars) + [status]

    anim = FuncAnimation(fig, update, interval=200, blit=False,
                         cache_frame_data=False)
    fig._anim = anim
    return fig


def parse_args():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--fs", type=int, default=100,
                    help="sampling rate Hz; detects up to fs/2 (default 100)")
    ap.add_argument("--window", type=int, default=256,
                    help="FFT size; fs/window = bin width (default 256 -> ~0.39 Hz)")
    ap.add_argument("--hop", type=int, default=64,
                    help="samples between FFTs; smaller = smoother updates (default 64)")
    ap.add_argument("--decay", type=float, default=0.90,
                    help="memory decay per FFT, 0..1 (default 0.90)")
    ap.add_argument("--harmonics", type=int, default=4,
                    help="comb teeth scored per candidate (default 4)")
    ap.add_argument("--min-hits", type=int, default=3, dest="min_hits",
                    help="teeth that must align to confirm (default 3)")
    ap.add_argument("--prom-ratio", type=float, default=2.0, dest="prom_ratio",
                    help="how far a tooth must rise above local noise (default 2.0)")
    ap.add_argument("--fmin", type=float, default=2.0,
                    help="lowest fundamental to scan, Hz (default 2.0)")
    ap.add_argument("--fmax", type=float, default=9.0,
                    help="highest fundamental to scan, Hz (default 9.0)")
    ap.add_argument("--fstep", type=float, default=0.05,
                    help="fundamental scan step, Hz (default 0.05)")
    ap.add_argument("--confirm-streak", type=int, default=2, dest="confirm_streak",
                    help="consecutive windows needed to confirm (default 2)")
    ap.add_argument("--block-tol", type=float, default=0.25, dest="block_tol",
                    help="Hz tolerance for treating a cadence as already-blocked (default 0.25)")
    ap.add_argument("--detect-only", action="store_true", dest="detect_only",
                    help="only detect and alert; do not install safeguards")
    cfg = ap.parse_args()

    if cfg.host not in ("127.0.0.1", "localhost", "::1"):
        ap.error("local demo only: --host must be loopback")
    if not 0.0 < cfg.decay < 1.0:
        ap.error("--decay must be between 0 and 1")
    if cfg.min_hits > cfg.harmonics:
        ap.error("--min-hits cannot exceed --harmonics")
    if cfg.hop < 1 or cfg.hop > cfg.window:
        ap.error("--hop must be between 1 and --window")
    if cfg.fmax * cfg.harmonics > cfg.fs / 2:
        ap.error("fmax*harmonics exceeds Nyquist (fs/2); raise --fs or lower --fmax/--harmonics")
    return cfg


def main():
    cfg = parse_args()
    mem = SpectralMemory(cfg)
    print(f"[defender] listening on {cfg.host}:{cfg.port} (UDP)")
    print(f"[defender] fs={cfg.fs}Hz window={cfg.window} hop={cfg.hop} "
          f"(bin {mem.bin_hz:.3f} Hz, up to {cfg.fs//2} Hz), decay={cfg.decay}")
    print(f"[defender] scanning fundamentals {cfg.fmin}-{cfg.fmax} Hz; confirm on "
          f">= {cfg.min_hits}/{cfg.harmonics} teeth for {cfg.confirm_streak} windows.")
    if cfg.detect_only:
        print("[defender] detect-only mode: safeguards disabled.")
    else:
        print(f"[defender] safeguards ON: a confirmed cadence is quarantined once "
              f"(+/-{cfg.block_tol} Hz) and muted thereafter.")
    print("[defender] close the chart window to stop.")

    worker = threading.Thread(target=mem.run, daemon=True)
    worker.start()

    build_gui(mem)
    try:
        plt.show()                               # blocks until the window closes
    finally:
        mem.stop()
        worker.join(timeout=1.0)
        mem.sock.close()
        print("[defender] stopped.")


if __name__ == "__main__":
    main()
