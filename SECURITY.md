# Security policy

## Reporting a vulnerability in PhotoFinish

Please do not open a public issue for security problems in PhotoFinish itself. Use GitHub's private vulnerability
reporting on <https://github.com/TroubieD3v/PhotoFinish/security/advisories/new> instead.

Include the version (`photofinish version`), the command you ran and steps to reproduce. You will get an answer
within a week.

The race conditions in the `/vuln` routes of the demo shop are intentional and are not vulnerabilities of this
project. A race in a `/fixed` route, a way to reach the shop from another host without `--expose`, or a crash of
the binary are.

## Using PhotoFinish responsibly

- The demo shop (`photofinish demo`) is intentionally vulnerable. It binds to `127.0.0.1` by default and refuses a
  non-loopback address unless you pass `--expose`. Use `--expose` only on an isolated lab network.
- The demo tokens (`demo-alice`, `demo-bob`) and the certificate are throwaway values for local testing.
- Test only systems you own or are explicitly authorized to test. Race testing sends bursts of synchronized
  requests and can change real state: balances, orders, coupons, account lockouts.
