# frequency-security

**Find C2 beacons in network logs by their rhythm, not their content.**

Malware that phones home — C2 implants, cron check-ins, polling loops — repeats
on a clock. People don't. This tool turns every conversation in a traffic log
into a tiny **frequency histogram** and flags the ones whose timing is too
steady to be human. It never parses payloads, never touches a database, and its
memory stays flat no matter how big the log gets.

```
$ python3 ingest_run.py sample_capture.pcap

[lanes] 2,630 conversations, 1,027 with >= 20 intervals, 12 regular
[BEACON] ~0.2 Hz  (every ~5.00 s)   12 conversation(s), 2,867 on-beat check-ins, 100% on the beat
         what : a steady periodic beacon -> automated, not human
         when : 2026-10-02 13:20:00 -> 2026-10-02 13:39:59 (active 19m 59s)
         who  : 12 host(s) -> 1 destination(s)
         src  : 10.0.0.101, 10.0.0.102, 10.0.0.103, ...  (+6 more)
         dst  : 203.0.113.5
```

It caught 12 infected laptops beaconing to one C2 server — even though each of
those laptops was *also* browsing the web from the same IP, and the beacon was
well under 1% of all traffic.

See [Limitations](#limitations).

---

## Why it's different

The standard open-source approach (RITA, Zeek, etc.) is: capture packets →
parse every protocol into text logs → load into a database → run per-connection
statistics. It works, but it holds the whole dataset and is heavy.

This takes the idea from **signal processing** instead: a repeating event is a
frequency, and frequencies *accumulate*. We stream the data once, drop each gap
between packets into a log-frequency histogram per conversation, and read the
beacon off as a spike.

Against a faithful RITA-style baseline on the same data (`time_computing.py`):

| | finding the beacon | memory |
|---|---|---|
| few hosts (4.8M events) | **1.05× RITA's speed** | **~48× less** |
| big botnet (5.6M events) | **1.37× RITA's speed** | **~11× less** |

and the memory gap *widens* as the log grows, because ours scales with the
number of conversations, not the number of packets.

---

## Install

Needs Python 3.10+, `numpy`, `matplotlib`, and a C compiler with `libpcap`
(both ship with macOS and most Linux distros).

```bash
pip install numpy matplotlib
make                 # builds the C ingest agent
```

## Use

**From a packet capture (.pcap):**

```bash
python3 ingest_run.py --gen-pcap sample_capture.pcap   # make a test capture
python3 ingest_run.py sample_capture.pcap              # hunt beacons
```

**From a text log** (Zeek conn.log, a firewall/flow export, any CSV/TSV with a
timestamp and IPs — the parser sniffs the format automatically):

```bash
python3 logAnalsys.py --gen-sample sample_traffic.log
python3 logAnalsys.py sample_traffic.log
```

**Live capture** (needs root; Ctrl-C to stop and print the report):

```bash
sudo python3 ingest_run.py -i en0 'tcp or udp'
```

### Useful flags

| flag | what it does |
|---|---|
| `--by-source` | key lanes by source IP only (weaker — shown for comparison) |
| `--global` | one lane for everything (the naive way that fails; for demos) |
| `--heatmap` | 2D interval × packet-size view instead of the spectrum |
| `--fmin / --fmax` | cadence range to search (default 0.0001–100 Hz) |
| `--regularity` | how steady a conversation must be to flag (default 0.70) |
| `--min-hits` | check-ins a conversation needs before it's judged (default 20) |
| `--no-plot` | console only |

---

## How it works (short version)

```
pcap / log ─► ingest ─► lanes ─► accumulate ─► regular? ─► group ─► report
             (C agent   (src,dst  (per-lane     (one        (same     what/
              or text    pairs)    frequency     narrow      cadence   when/
              sniffer)             histogram)    band?)      = 1       who
                                                             beacon)
```

1. **Ingest** — every packet becomes `(time, src, dst)`. Payloads and text are
   dropped. In C (`ingest.c`) for captures/live, or a format-sniffing parser for
   text logs.
2. **Lanes** — a conversation is a `(source IP, destination IP)` pair. The gap
   is measured *within* a conversation, so an implant's rhythm never gets mixed
   with the user's browsing.
3. **Accumulate** — each gap → a frequency (`1/gap`) → a bin in that lane's small
   log-frequency histogram.
4. **Regular?** — a lane is flagged when most of its gaps fall in one narrow
   band (with a statistical confidence floor so short lanes can't fluke it).
5. **Group** — regular lanes on the same cadence are one beacon (many infected
   hosts, one clock).
6. **Report** — cadence (*what*), first/last check-in (*when*), hosts →
   destinations (*who*) — all from the same single pass.

---

## What's in the repo

| file | purpose |
|---|---|
| `logAnalsys.py` | the lane engine: parsing, frequency analysis, detection, plots |
| `ingest.c` | compiled libpcap agent — packet → 24-byte `(ts, src, dst, …)` record |
| `ingest_run.py` | glue: builds the agent, streams its output into the engine |
| `time_computing.py` | benchmark vs a RITA-style baseline |
| `Makefile` | builds `ingest` |
| `Server.py`, `attack_script.py` | **v1**, a live-detector prototype (see below) |

### About `Server.py` (v1)

The original prototype did *live* detection on a single port using an FFT with
accumulate-and-decay and harmonic-comb confirmation. It was the bridge that
proved the frequency idea, and it's kept for reference. The log-analysis engine
(`logAnalsys.py`) is the product direction and supersedes it. `attack_script.py`
is a loopback-only timing generator used to test v1.

---

## Limitations

This is an honest research prototype. Known gaps:

- **Synthetic data only.** Everything is tested against generated traffic with
  known ground truth. The next real milestone is a public malware capture.
- **Legitimate automation flags too.** NTP, software update checks, monitoring
  agents and keepalives are *also* steady beacons. Correct behaviour for the
  detector, but a deployment needs an allowlist / baseline step.
- **Slow beacons need long logs.** A conversation must have ≥ `min-hits` gaps
  before it's judged, so an hourly beacon needs days of data.
- **Memory grows with conversations** (~600 bytes each). Fine into the hundreds
  of thousands; millions of distinct pairs would need a sketch/approximation.
- **Evasion.** Heavy period randomization or packet-size padding degrades the
  signal.
- **"When" = first check-in seen**, which is when the C2 channel started, not
  necessarily the initial breach, and may be clipped by the log's own start/end.

---