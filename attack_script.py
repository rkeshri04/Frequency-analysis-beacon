#!/usr/bin/env python3
"""hacker_botnet.py — benign local *beacon timing* simulator (loopback only).

This does NOT do anything a real C2 beacon does: there is no payload, no real
remote host, no data exfiltration, no evasion. All it emulates is the *timing
pattern* of a periodic check-in so you can test the companion detector
(net_resonance_defender.py). It fires an empty UDP datagram at 127.0.0.1 on a
fixed period with a little pseudo-random jitter, exactly like the worked
example:

    period 0.15 s  ->  1 / 0.15  ==  ~6.667 Hz   (the "hidden heartbeat")
    jitter +/- 0.005 s           ->  arrival times look chaotic to the eye

Run the defender first, then run this. Ctrl-C to stop.
"""

import argparse
import random
import socket
import time


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1",
                    help="loopback target (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=9999,
                    help="UDP port the defender is listening on (default: 9999)")
    ap.add_argument("--period", type=float, default=0.15,
                    help="mean seconds between check-ins (default: 0.15 -> ~6.67 Hz)")
    ap.add_argument("--jitter", type=float, default=0.005,
                    help="uniform +/- jitter in seconds (default: 0.005)")
    ap.add_argument("--count", type=int, default=0,
                    help="packets to send, 0 = run until Ctrl-C (default: 0)")
    ap.add_argument("--seed", type=int, default=None,
                    help="PRNG seed, for reproducible jitter")
    args = ap.parse_args()

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        ap.error("this is a local demo; --host must be loopback (127.0.0.1 / localhost / ::1)")

    rng = random.Random(args.seed)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target = (args.host, args.port)

    heartbeat_hz = 1.0 / args.period
    print(f"[beacon] -> {args.host}:{args.port}  period={args.period}s "
          f"(~{heartbeat_hz:.3f} Hz)  jitter=+/-{args.jitter}s")
    print("[beacon] sending timed datagrams... Ctrl-C to stop\n")

    # Schedule on an absolute clock so jitter perturbs each packet but does NOT
    # accumulate: the long-run average frequency stays pinned at 1/period.
    sent = 0
    next_at = time.perf_counter()
    try:
        while args.count == 0 or sent < args.count:
            now = time.perf_counter()
            if now < next_at:
                time.sleep(next_at - now)

            sock.sendto(b"", target)          # empty datagram: timing only
            sent += 1

            delay = args.period + rng.uniform(-args.jitter, args.jitter)
            next_at += delay
            if sent % 20 == 0:
                print(f"[beacon] sent {sent} check-ins "
                      f"(last interval {delay*1000:.1f} ms)")
    except KeyboardInterrupt:
        print(f"\n[beacon] stopped after {sent} check-ins.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
