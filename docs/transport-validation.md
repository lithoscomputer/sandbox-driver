# Transport validation

The generated-provider transport passed the Linux concurrency, control-latency,
overload, and 30-minute endurance gates on September 5, 2026. This validates the
configuration below. Sandbox compute and remote provider latency are separate.

## Configuration and scope

- Apple M5 Max host; aarch64 OrbStack Linux VM, kernel
  `7.0.11-orbstack-00360-gc9bc4d96ac70`.
- Client and plugin share a container restricted to CPUs `0-7`, a quota of eight
  CPUs (`cpu.max: 800000 100000`), and 16 GiB (`memory.max: 17179869184`).
  The VM reports 16,423,852 KiB of physical memory after kernel reservation.
- Descriptor soft and hard limits: 16,384 per process.
- Native cached Rust 1.95.0, locked dependencies, release build. The routine
  macOS gate uses pinned Rust 1.97.1; the minimum-version check uses Rust 1.85.0.
- Default `TransportLimits`, except the burst fixture sets client `active_io`
  to exactly 1,000 so its 10,000 additional attempts exceed admission.
- Shared VM on the local host. No agent builds, correctness tests, or other
  benchmark workloads ran concurrently with these measurements. These are
  results for this constrained VM, not a claim about every Linux machine.

The test provider returns immediate control responses and generated output. It
creates no sandbox compute or persistent provider metadata. Rate workloads offer
1,024 bytes per operation every 10 ms (102,400 bytes/s per operation). Bulk
workloads offer 64 KiB chunks as fast as backpressure allows. The client counts
bytes immediately and retains no output. Startup ramps in batches of at most 32.

Rate workloads run for 30 seconds at 1, 100, and 1,000 concurrent operations.
Bulk runs use 1,000 operations for 30 seconds. Tiny runs execute 10,000 one-chunk
operations in batches of 32. Cycle runs perform 10,000 sequential
create/attach/exec/delete cycles. Burst runs hold 1,000 active rate streams,
launch 10,000 excess attempts, and exercise health calls while draining rejected
results before another 30 seconds of output. Each short workload has three
repetitions. Endurance uses 1,000 rate streams for 1,800 seconds after startup.

## Latency measurements

All latency values are microseconds. Each triple is p50/p95/p99 from that run;
percentiles are not pooled across repetitions. Control sample counts appear
below. Setup and first-byte sample counts equal the admitted operation count
(10,000 for tiny and cycles). No setup samples were lost.

Authenticated setup starts before admission and ends when the authenticated
channel is available. First-byte time starts when the operation task begins.
Cold startup includes process launch and initialization. The benchmark uses
sorted samples at `floor(sample_count * percentile / 100)`, clamped to the last
sample. One-operation setup measurements have one sample per repetition.

| Workload / operations / repetition | Control samples | Control p50/p95/p99 | Setup p50/p95/p99 | First byte p50/p95/p99 | Cold startup |
| --- | ---: | ---: | ---: | ---: | ---: |
| rate / 1 / 1 | 2479 | 197/300/360 | 297/297/297 | 1521/1521/1521 | 1255 |
| rate / 1 / 2 | 2500 | 184/277/368 | 214/214/214 | 1948/1948/1948 | 1673 |
| rate / 1 / 3 | 2492 | 181/264/338 | 262/262/262 | 2077/2077/2077 | 1918 |
| rate / 100 / 1 | 2577 | 201/409/639 | 705/1037/1203 | 2645/2900/2950 | 1678 |
| rate / 100 / 2 | 2575 | 194/431/587 | 398/568/615 | 1885/2702/2747 | 1976 |
| rate / 100 / 3 | 2592 | 218/435/551 | 696/1178/1300 | 2631/3107/3156 | 1201 |
| rate / 1000 / 1 | 2519 | 482/1468/2690 | 417/763/995 | 2189/2992/3155 | 2000 |
| rate / 1000 / 2 | 2549 | 408/1386/2245 | 697/1762/1873 | 2831/4432/5077 | 2270 |
| rate / 1000 / 3 | 2485 | 512/1551/3018 | 736/1620/1779 | 2700/4277/4527 | 1922 |
| bulk / 1000 / 1 | 1647 | 5966/17345/23343 | 4752/17790/25608 | 8738/24656/44869 | 1368 |
| bulk / 1000 / 2 | 1409 | 7448/25160/41532 | 5030/12964/15478 | 9661/20939/27352 | 1368 |
| bulk / 1000 / 3 | 1597 | 6516/18246/23811 | 5095/14306/15906 | 8341/20366/28275 | 1992 |
| tiny / 32 / 1 | 313 | 61/99/171 | 327/649/855 | 491/840/1116 | 675 |
| tiny / 32 / 2 | 313 | 61/88/109 | 324/622/811 | 482/804/1072 | 958 |
| tiny / 32 / 3 | 313 | 60/117/227 | 341/660/934 | 526/889/1428 | 1157 |
| cycles / 1 / 1 | 10000 | 58/88/148 | 77/109/170 | 97/139/231 | 626 |
| cycles / 1 / 2 | 10000 | 58/85/147 | 76/111/209 | 96/143/265 | 1082 |
| cycles / 1 / 3 | 10000 | 58/87/149 | 77/113/189 | 96/141/238 | 2017 |
| burst / 1000 / 1 | 12495 | 51/939/1832 | 601/1689/1867 | 2728/4201/5829 | 719 |
| burst / 1000 / 2 | 12511 | 50/823/1689 | 741/1323/1509 | 2834/4868/5990 | 1706 |
| burst / 1000 / 3 | 12549 | 52/812/1611 | 799/2152/2902 | 2850/4293/4850 | 1470 |
| endurance / 1000 / 1 | 149404 | 504/1865/3385 | 550/1423/2895 | 2734/3563/5517 | 674 |

At 1,000 rate streams, the three short-run control p99 values were
2.245–3.018 ms. Bulk control p99 was 23.343–41.532 ms while throughput reached
18.0–22.8 GB/s. All runs stayed below the 100 ms control p99 gate.

## Throughput and resources

Throughput uses bytes delivered during the full active interval, excluding
startup and cleanup. Tiny and cycle rates use completed operations divided by
their workload duration. CPU cost uses sampled `/proc` client and plugin CPU
counters; it excludes the `ss` sampler and the final process shutdown tail.
The raw records also retain child CPU usage that includes sampler children.

RSS, descriptors, threads, and socket memory are sampled about once per second.
These are observed peaks, not hard maxima; short-lived churn can occur between
samples. Client and plugin RSS peaks can occur at different instants, so their
sum need not equal the peak combined RSS. `ss` socket `t` (send-memory allocation) is reported separately
from RSS. The raw records retain each `skmem` field; `rb` and `tb` are buffer
limits, and overlapping fields must not be added as allocated memory. These counters
exclude other kernel structures, such as socket and descriptor metadata.

| Workload / operations / repetition | Active GB/s or operations/s | CPU seconds/GiB | Peak combined RSS MiB | Client/plugin RSS MiB | Peak descriptors | Peak socket t MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| rate / 1 / 1 | 0.000102 GB/s | 342.421 | 11.02 | 5.66/5.36 | 25 | 0.003 |
| rate / 1 / 2 | 0.000102 GB/s | 345.915 | 11.01 | 5.66/5.34 | 25 | 0.000 |
| rate / 1 / 3 | 0.000102 GB/s | 349.409 | 10.98 | 5.67/5.31 | 25 | 0.000 |
| rate / 100 / 1 | 0.010239 GB/s | 19.838 | 13.37 | 6.75/6.62 | 223 | 0.064 |
| rate / 100 / 2 | 0.010239 GB/s | 19.809 | 13.45 | 6.75/6.70 | 223 | 0.091 |
| rate / 100 / 3 | 0.010238 GB/s | 19.707 | 13.41 | 6.72/6.70 | 223 | 0.076 |
| rate / 1000 / 1 | 0.102392 GB/s | 11.380 | 29.13 | 14.70/14.43 | 2023 | 0.765 |
| rate / 1000 / 2 | 0.102398 GB/s | 11.457 | 29.38 | 14.72/14.66 | 2023 | 0.538 |
| rate / 1000 / 3 | 0.102390 GB/s | 11.572 | 29.05 | 14.66/14.39 | 2023 | 0.530 |
| bulk / 1000 / 1 | 22.751628 GB/s | 0.371 | 152.74 | 60.45/92.30 | 2023 | 214.114 |
| bulk / 1000 / 2 | 18.019029 GB/s | 0.461 | 153.95 | 60.49/93.45 | 2023 | 199.971 |
| bulk / 1000 / 3 | 22.134093 GB/s | 0.381 | 148.82 | 60.25/90.96 | 2023 | 212.510 |
| tiny / 32 / 1 | 23083.4 ops/s | 68.157 | 14.81 | 8.38/6.43 | 31 | 0.009 |
| tiny / 32 / 2 | 23778.4 ops/s | 67.109 | 14.75 | 8.36/6.39 | 23 | 0.000 |
| tiny / 32 / 3 | 22009.6 ops/s | 69.206 | 14.87 | 8.38/6.48 | 23 | 0.000 |
| cycles / 1 / 1 | 2202.1 ops/s | 543.162 | 11.61 | 6.14/5.47 | 24 | 0.000 |
| cycles / 1 / 2 | 2212.8 ops/s | 541.065 | 11.67 | 6.12/5.55 | 24 | 0.000 |
| cycles / 1 / 3 | 2219.6 ops/s | 541.065 | 11.71 | 6.14/5.57 | 23 | 0.000 |
| burst / 1000 / 1 | 0.102393 GB/s | 11.872 | 34.18 | 19.79/14.40 | 2023 | 0.583 |
| burst / 1000 / 2 | 0.102396 GB/s | 12.054 | 34.23 | 19.80/14.50 | 2023 | 0.606 |
| burst / 1000 / 3 | 0.102395 GB/s | 11.789 | 34.21 | 19.79/14.42 | 2023 | 0.694 |
| endurance / 1000 / 1 | 0.102100 GB/s | 12.248 | 29.08 | 14.88/14.21 | 2023 | 1.570 |

Every completed run returned to 23 combined descriptors while both processes
remained alive. Runtime tasks returned to four in the client and two in the
plugin. Active I/O, pending opens, exec/stdio/PTY/stream registries, cached
transport handles, owned cleanup tasks, and unresolved cleanup all returned to
zero. One private socket directory existed while the connection was alive;
none remained after shutdown.

## Cancellation and overload

Each burst rejected all 10,000 excess attempts with `Overloaded`. Separate
client and server admission regressions verify rejection before command effects
and successful work after pressure falls. Every stopped benchmark stream
reported `Killed`, and none reported abandoned output.

Acknowledgment counts below are successful stop-response waits, not the number
of commands that terminated. Provider completion can finish an operation and
cancel its remaining acknowledgment wait. Local completion includes output
drain; cleanup is then checked separately through both registries and resource
samples.

| Workload / operations / repetition | Stop deliveries | Acknowledgments | Longest acknowledged delivery ms | Stop to local completion ms | Confirmed killed |
| --- | ---: | ---: | ---: | ---: | ---: |
| rate / 1 / 1 | 1 | 1 | 0.309 | 0.490 | 1 |
| rate / 1 / 2 | 1 | 1 | 0.176 | 0.297 | 1 |
| rate / 1 / 3 | 1 | 0 | 0.000 | 0.354 | 1 |
| rate / 100 / 1 | 100 | 1 | 0.225 | 6.515 | 100 |
| rate / 100 / 2 | 100 | 0 | 0.000 | 6.567 | 100 |
| rate / 100 / 3 | 100 | 3 | 0.923 | 6.643 | 100 |
| rate / 1000 / 1 | 1000 | 1 | 44.704 | 66.069 | 1000 |
| rate / 1000 / 2 | 1000 | 0 | 0.000 | 64.794 | 1000 |
| rate / 1000 / 3 | 1000 | 3 | 3.222 | 69.340 | 1000 |
| bulk / 1000 / 1 | 1000 | 102 | 136.999 | 204.117 | 1000 |
| bulk / 1000 / 2 | 1000 | 115 | 166.905 | 187.507 | 1000 |
| bulk / 1000 / 3 | 1000 | 261 | 100.103 | 126.109 | 1000 |
| burst / 1000 / 1 | 1000 | 1 | 0.103 | 64.162 | 1000 |
| burst / 1000 / 2 | 1000 | 3 | 36.520 | 59.129 | 1000 |
| burst / 1000 / 3 | 1000 | 2 | 2.124 | 61.068 | 1000 |
| endurance / 1000 / 1 | 1000 | 1 | 1.497 | 82.027 | 1000 |

## Endurance

The sustained active interval lasted 1800.010
seconds and delivered 171.159 GiB.
Control p99 was 3.385 ms from
149,404 samples. All 1,788
active diagnostic snapshots contained 1,000 operations on both sides and the
same live task counts: 2,004 client tasks and 1,002 plugin tasks.

Every process resource sample from seconds 10 through 1,800 contained 2,023
descriptors. After cleanup, descriptors returned to 23, tasks returned to six,
and all operation and handle registries were empty. Socket paths were removed
at shutdown.

| Elapsed seconds | Resource samples | Median combined RSS MiB | Maximum combined RSS MiB |
| --- | ---: | ---: | ---: |
| 60–120 | 58 | 28.891 | 28.977 |
| 300–360 | 58 | 24.453 | 24.469 |
| 600–660 | 58 | 24.582 | 24.598 |
| 900–960 | 58 | 24.777 | 24.793 |
| 1200–1260 | 58 | 24.965 | 24.980 |
| 1500–1560 | 58 | 25.152 | 25.168 |
| 1740–1800 | 58 | 25.312 | 25.328 |

RSS stayed bounded despite continued output. The benchmark itself retains one
8-byte control-latency sample per query until final percentile calculation;
this small measurement buffer is separate from output retention. RSS need not
return to its initial value because allocators can retain freed pages. The
resource and ownership counters establish cleanup separately.

## Functional validation

The final `LITHOS_CLI_E2E_REQUIRE_LIVE=1 mise run check` passed 334 tests,
with two explicitly ignored live Daytona suites. Formatting, Clippy, workflow audits, whitespace checks, and the
Rust 1.85 minimum-version check passed. Linux release checks passed 55 protocol
tests and four Host unit tests.

The regressions cover:

- Cancellation before open, during stdin, during output, after the provider
  result, and during a partial final EOF. Missing acknowledgment and blocked
  output have bounded local completion and explicit incomplete outcomes.
- Event floods and blocked observers, with explicit subscription failure and
  continued control responses. Quiet commands do not trigger output deadlines.
- Actual descriptor exhaustion in an isolated subprocess, bounded accept
  backoff, and recovery. The test retries only authentication on macOS, where
  descriptor exhaustion can close the first queued connection.
- Invalid and stalled connection bursts, wrong and replayed tokens, unknown
  channel IDs, unexpected peer processes, malformed frames, private permissions,
  and cleanup after socket bind failure.
- Repeated stdio wait/drop cycles, plugin death and one replacement without
  replay, and ordinary Daytona attachment that preserves active nested work.
- Repeated Host create/attach/delete cycles. Deleted handles leave the memory
  cache; managed workspaces are removed; durable tombstones remain, as required
  by the Host registry contract. Drained process groups start no drop cleanup.

Real Host and Docker conformance, their protocol paths, and the available
Daytona CLI Container workflow passed in the routine gate. The ignored tests
require a regional Daytona snapshot or nested-Docker snapshot and credentials;
they are not claimed here. The full nightly release suite was not run.

## Reproduction and artifacts

On a Linux machine with the constraints above, build the locked release example
and run these explicit workloads. They are separate from ordinary CI gates:

```sh
bin/bench-transport --operations 1 100 1000 --modes rate --seconds 30 --repetitions 3 --max-control-p99-ms 100 --output .ai/benchmarks/transport-linux-rate.jsonl
bin/bench-transport --operations 1000 --modes bulk --seconds 30 --repetitions 3 --max-control-p99-ms 100 --output .ai/benchmarks/transport-linux-bulk.jsonl
bin/bench-transport --operations 32 --modes tiny --cycles 10000 --repetitions 3 --max-control-p99-ms 100 --output .ai/benchmarks/transport-linux-tiny.jsonl
bin/bench-transport --operations 1 --modes cycles --cycles 10000 --repetitions 3 --max-control-p99-ms 100 --output .ai/benchmarks/transport-linux-cycles.jsonl
bin/bench-transport --operations 1000 --modes burst --seconds 30 --repetitions 3 --max-control-p99-ms 100 --output .ai/benchmarks/transport-linux-burst.jsonl
bin/bench-transport --operations 1000 --modes rate --seconds 1800 --repetitions 1 --max-control-p99-ms 100 --output .ai/benchmarks/transport-linux-endurance.jsonl
```

The measured container used `--cpuset-cpus=0-7 --cpus=8 --memory=16g
--memory-swap=16g --ulimit nofile=16384:16384`. It was built from cached native
Rust and Ubuntu images, with no downloaded packages. Its image ID was
`sha256:ae72fc35076786c552a74ca7c2260fea2a5d48295c80adc119b43cfb911b6500`.
Inside it, `cargo build --offline --locked --release -p sandbox-driver-protocol
--example transport_bench` built the fixture. The runner used
`--binary /target/release/examples/transport_bench` and wrote to `/results`,
bound to `.ai/benchmarks` on the host. The full environment and exact command
for each repetition are in its JSONL record. The Dockerfile and base-image IDs
are saved as `transport-validation.Dockerfile` and `transport-base-images.txt`.

Each summary has matching `.resources.jsonl` and `.transport.jsonl` time series.
`transport-linux-analysis.json` records the derived comparisons, and
`analyze-transport.py` reproduces them. The runner leaves
`reference_capacity_validated: false` in individual records: a latency pass
alone does not establish that all acceptance gates passed. This report combines
the functional, workload, endurance, and cleanup evidence.

The local bundle `.ai/benchmarks/transport-linux-validation.tar.gz` contains
the raw results, time series, analysis, verification summary, and source archive.

The local source archive `transport-measured-source.tar.gz` preserves the
measured fixture and transport sources. The later Host cache cleanup fix and
additional bind-failure regression are covered by the final correctness gate;
the generated provider does not execute Host code. Rebuilding the fixture
after those changes produced the identical measured binary SHA-256.

Measured source SHA-256: `cc639373f5e8f40c2abdd08af64fc240371296b14bd5bd308229210bf1afd12c`.

Measured binary SHA-256: `9ce9bc2dd86f0227b556e22ecca4798aabff459b622a074943abd9c77b4f2b0f`.

The earlier macOS smoke measurements remain in
`.ai/benchmarks/transport-local-final.jsonl`. They ran during other development
work and are superseded by these Linux measurements for capacity validation.

The supported result is 1,000 active generated-output operations in the tested
configuration. Ten thousand attempts establish overload behavior, not 10,000
active-operation capacity. Provider compute, remote network latency, explicit
capture budgets, smaller machines, durable execution, and cross-node recovery
need their own limits and validation.
