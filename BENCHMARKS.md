# Benchmarks

These numbers show how often each engine catches the races of the demo shop and how tightly the requests reach the server. They describe the demo shop on one kind of machine. They are not a promise about any other target.

## Setup

- **Machine.** A GitHub Actions `ubuntu-24.04` runner with 4 CPUs, Linux 7.0 and Go 1.27.4. This is run 45034083335 of [.github/workflows/bench.yml](.github/workflows/bench.yml), started by hand on 2026-11-22 at commit 07f9183.
- **Target.** The demo shop runs as `photofinish demo` with window 0, so there is no artificial pause. The race window is the ordinary gap between two SQLite statements. The shop and PhotoFinish run on the same runner and talk over loopback.
- **Network profiles.** There are three. The first is plain loopback. The other two add delay with jitter to loopback using `tc netem`: `delay 1ms 500us` and `delay 5ms 2ms`, with a normal distribution. netem delays every packet on its own, which is what a real network does to requests that travel in separate packets.
- **Trials.** Every example scenario ran with every engine for 30 trials of 20 copies, with a reset before each trial.
- **Server arrival spread.** This is the spread of `X-Arrival-Ns` within one race. It marks the moment the demo shop has the whole request, body included. The tables give the median over the 30 races.

To reproduce, run the Benchmark workflow from the Actions tab. To run it locally instead, start the demo shop, then run `bash bench/run.sh ./bin/photofinish out local 30` and `python bench/table.py out`.

## Server arrival spread

This table gives the median spread of server arrival times within a race, in ms. Each cell is the range over the eight scenarios.

| Network | h2 | h1 | burst |
|---|---|---|---|
| loopback | 0.05–0.14 | 0.05–0.13 | 0.49–2.37 |
| 1 ms ± 0.5 ms | 0.05–0.17 | 1.36–1.85 | 0.76–2.09 |
| 5 ms ± 2 ms | 0.08–0.21 | 6.05–7.43 | 3.06–4.82 |

This is the property the single-packet attack is about. With `h2`, the final frames of all 20 requests leave in one TCP packet, so network jitter cannot pull them apart. The requests complete within 0.2 ms whatever the network does. `h1` sends its last bytes on 20 connections, one packet each, and every packet gets its own delay. On plain loopback the two engines are equal.

## Trials that broke the rule

This table counts the trials, out of 30, in which the invariant was violated on the vulnerable variants:

| Scenario | Network | h2 | h1 | burst |
|---|---|---|---|---|
| coupon | loopback | 18 | 17 | 6 |
| coupon | 1 ms ± 0.5 ms | 16 | 10 | 4 |
| coupon | 5 ms ± 2 ms | 7 | 4 | 14 |
| giftcard | loopback | 29 | 28 | 10 |
| giftcard | 1 ms ± 0.5 ms | 25 | 9 | 12 |
| giftcard | 5 ms ± 2 ms | 27 | 1 | 25 |
| transfer | loopback | 19 | 25 | 5 |
| transfer | 1 ms ± 0.5 ms | 22 | 7 | 9 |
| transfer | 5 ms ± 2 ms | 14 | 4 | 13 |
| twofa | loopback | 28 | 29 | 23 |
| twofa | 1 ms ± 0.5 ms | 29 | 9 | 19 |
| twofa | 5 ms ± 2 ms | 29 | 0 | 14 |

Every fixed variant was HELD in all 30 trials with every engine and every profile. That is 1,080 trials with no false positive.

## What this shows and what it does not

- **Synchronized engines beat plain concurrency on loopback.** In three of the four scenarios, `h2` and `h1` broke the rules two to three times as often as `burst`.
- **`h1` falls apart under jitter; `h2` does not.** At 5 ms, `h1` broke the rules in 0 to 4 of 30 trials. `h2` kept its arrival spread and most of its hit rate.
- **A tight arrival is necessary, not sufficient.** Once all requests are at the server, whether they interleave inside the race window depends on the server. Here, that means 20 goroutines taking turns on one SQLite connection. At 5 ms jitter, `burst` caught the coupon race twice as often as `h2` (14 against 7) and matched it on transfer. Thirty trials also leave noise of several trials either way. Use more trials and compare engines on your own target. The arrival spread in the report tells you whether the synchronization worked.
- **Loopback with netem only stands in for a network; it is not a measurement of one.** It has no real router, no TLS terminator in front of the application and no load balancer. Measurements against real deployments are welcome.

## Full results

<details>
<summary>All scenarios, engines and profiles</summary>

#### Loopback

| Scenario | Engine | Verdict | Trials broken | Median response spread, ms | Median server arrival spread, ms |
|---|---|---|---|---|---|
| coupon-fixed | h2 | HELD | 0 of 30 | 1.68 | 0.14 |
| coupon-fixed | h1 | HELD | 0 of 30 | 1.55 | 0.10 |
| coupon-fixed | burst | HELD | 0 of 30 | 2.02 | 2.37 |
| coupon-vuln | h2 | VIOLATED | 18 of 30 | 1.21 | 0.12 |
| coupon-vuln | h1 | VIOLATED | 17 of 30 | 1.24 | 0.11 |
| coupon-vuln | burst | VIOLATED | 6 of 30 | 1.80 | 1.74 |
| giftcard-fixed | h2 | HELD | 0 of 30 | 1.68 | 0.05 |
| giftcard-fixed | h1 | HELD | 0 of 30 | 1.42 | 0.13 |
| giftcard-fixed | burst | HELD | 0 of 30 | 1.79 | 1.87 |
| giftcard-vuln | h2 | VIOLATED | 29 of 30 | 0.91 | 0.05 |
| giftcard-vuln | h1 | VIOLATED | 28 of 30 | 0.95 | 0.12 |
| giftcard-vuln | burst | VIOLATED | 10 of 30 | 1.82 | 1.84 |
| transfer-fixed | h2 | HELD | 0 of 30 | 1.36 | 0.14 |
| transfer-fixed | h1 | HELD | 0 of 30 | 1.22 | 0.10 |
| transfer-fixed | burst | HELD | 0 of 30 | 1.65 | 1.69 |
| transfer-vuln | h2 | VIOLATED | 19 of 30 | 1.04 | 0.12 |
| transfer-vuln | h1 | VIOLATED | 25 of 30 | 1.06 | 0.10 |
| transfer-vuln | burst | VIOLATED | 5 of 30 | 1.52 | 1.94 |
| twofa-fixed | h2 | HELD | 0 of 30 | 0.75 | 0.11 |
| twofa-fixed | h1 | HELD | 0 of 30 | 0.74 | 0.05 |
| twofa-fixed | burst | HELD | 0 of 30 | 0.60 | 0.49 |
| twofa-vuln | h2 | VIOLATED | 28 of 30 | 0.65 | 0.10 |
| twofa-vuln | h1 | VIOLATED | 29 of 30 | 0.61 | 0.05 |
| twofa-vuln | burst | VIOLATED | 23 of 30 | 0.73 | 0.69 |

#### Loopback, delay 1 ms ± 0.5 ms

| Scenario | Engine | Verdict | Trials broken | Median response spread, ms | Median server arrival spread, ms |
|---|---|---|---|---|---|
| coupon-fixed | h2 | HELD | 0 of 30 | 1.80 | 0.16 |
| coupon-fixed | h1 | HELD | 0 of 30 | 2.88 | 1.71 |
| coupon-fixed | burst | HELD | 0 of 30 | 3.48 | 1.85 |
| coupon-vuln | h2 | VIOLATED | 16 of 30 | 1.62 | 0.17 |
| coupon-vuln | h1 | VIOLATED | 10 of 30 | 2.61 | 1.83 |
| coupon-vuln | burst | VIOLATED | 4 of 30 | 2.49 | 1.76 |
| giftcard-fixed | h2 | HELD | 0 of 30 | 1.93 | 0.05 |
| giftcard-fixed | h1 | HELD | 0 of 30 | 2.65 | 1.85 |
| giftcard-fixed | burst | HELD | 0 of 30 | 2.65 | 1.81 |
| giftcard-vuln | h2 | VIOLATED | 25 of 30 | 1.44 | 0.05 |
| giftcard-vuln | h1 | VIOLATED | 9 of 30 | 2.55 | 1.66 |
| giftcard-vuln | burst | VIOLATED | 12 of 30 | 1.87 | 1.77 |
| transfer-fixed | h2 | HELD | 0 of 30 | 1.69 | 0.14 |
| transfer-fixed | h1 | HELD | 0 of 30 | 2.50 | 1.75 |
| transfer-fixed | burst | HELD | 0 of 30 | 2.54 | 2.09 |
| transfer-vuln | h2 | VIOLATED | 22 of 30 | 1.52 | 0.15 |
| transfer-vuln | h1 | VIOLATED | 7 of 30 | 2.52 | 1.79 |
| transfer-vuln | burst | VIOLATED | 9 of 30 | 2.11 | 1.65 |
| twofa-fixed | h2 | HELD | 0 of 30 | 1.28 | 0.11 |
| twofa-fixed | h1 | HELD | 0 of 30 | 2.10 | 1.39 |
| twofa-fixed | burst | HELD | 0 of 30 | 1.31 | 0.76 |
| twofa-vuln | h2 | VIOLATED | 29 of 30 | 1.40 | 0.10 |
| twofa-vuln | h1 | VIOLATED | 9 of 30 | 1.94 | 1.36 |
| twofa-vuln | burst | VIOLATED | 19 of 30 | 1.43 | 0.79 |

#### Loopback, delay 5 ms ± 2 ms

| Scenario | Engine | Verdict | Trials broken | Median response spread, ms | Median server arrival spread, ms |
|---|---|---|---|---|---|
| coupon-fixed | h2 | HELD | 0 of 30 | 5.34 | 0.18 |
| coupon-fixed | h1 | HELD | 0 of 30 | 11.11 | 7.37 |
| coupon-fixed | burst | HELD | 0 of 30 | 8.72 | 4.82 |
| coupon-vuln | h2 | VIOLATED | 7 of 30 | 5.68 | 0.21 |
| coupon-vuln | h1 | VIOLATED | 4 of 30 | 10.15 | 7.06 |
| coupon-vuln | burst | VIOLATED | 14 of 30 | 8.16 | 4.73 |
| giftcard-fixed | h2 | HELD | 0 of 30 | 7.14 | 0.08 |
| giftcard-fixed | h1 | HELD | 0 of 30 | 9.65 | 7.13 |
| giftcard-fixed | burst | HELD | 0 of 30 | 7.49 | 3.06 |
| giftcard-vuln | h2 | VIOLATED | 27 of 30 | 6.25 | 0.09 |
| giftcard-vuln | h1 | VIOLATED | 1 of 30 | 10.22 | 7.43 |
| giftcard-vuln | burst | VIOLATED | 25 of 30 | 7.34 | 3.95 |
| transfer-fixed | h2 | HELD | 0 of 30 | 6.21 | 0.18 |
| transfer-fixed | h1 | HELD | 0 of 30 | 9.99 | 6.95 |
| transfer-fixed | burst | HELD | 0 of 30 | 6.43 | 3.13 |
| transfer-vuln | h2 | VIOLATED | 14 of 30 | 5.82 | 0.19 |
| transfer-vuln | h1 | VIOLATED | 4 of 30 | 10.52 | 7.10 |
| transfer-vuln | burst | VIOLATED | 13 of 30 | 7.14 | 3.91 |
| twofa-fixed | h2 | HELD | 0 of 30 | 5.32 | 0.16 |
| twofa-fixed | h1 | HELD | 0 of 30 | 8.15 | 6.43 |
| twofa-fixed | burst | HELD | 0 of 30 | 6.56 | 3.97 |
| twofa-vuln | h2 | VIOLATED | 29 of 30 | 5.96 | 0.16 |
| twofa-vuln | h1 | HELD | 0 of 30 | 8.83 | 6.05 |
| twofa-vuln | burst | VIOLATED | 14 of 30 | 6.12 | 3.31 |

</details>
