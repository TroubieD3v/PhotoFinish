# Security policy

## Reporting a vulnerability in PhotoFinish

Please do not open a public issue for security problems in PhotoFinish itself. Use GitHub's private vulnerability
reporting on <https://github.com/TroubieD3v/PhotoFinish/security/advisories/new> instead.

Include the version (`photofinish version`), the command you ran and steps to reproduce. You will get an answer
within a week.

The race conditions in the `/vuln` routes of the demo shop are intentional and are not vulnerabilities of this
project. A race in a `/fixed` route, a way to reach the shop from another host without `--expose`, or a crash of
the binary are. So is any way to drive `photofinish serve` without its session token, to read or write a file
outside its workspace, or to send a request that the scope of the scenario does not allow.

## The web UI (`photofinish serve`)

`serve` is a local HTTP server that, on request, sends race traffic to the target of a scenario and reads and
writes scenario files. Whoever controls it controls those requests, so the threat model is about who can reach its
API.

### What it protects against

| Threat | Defence |
|---|---|
| A web page you visit sends requests to `http://127.0.0.1:7340` (CSRF) | Every `/api/` request except `GET /api/health` needs `Authorization: Bearer <token>`. A page on another origin cannot read the token and cannot add the header without a CORS preflight, which the server does not answer with CORS headers. There are no cookies, so the browser has nothing to attach on its own. Writes (POST, PUT, DELETE) with an `Origin` that does not match the host are refused (403) as a second line. |
| DNS rebinding: a hostile name that resolves to `127.0.0.1` after the page has loaded | The `Host` header must be `127.0.0.1:<port>`, `localhost:<port>` or `[::1]:<port>`; anything else is refused (421 or 403). With `--expose` any host is accepted and the token alone protects the API. |
| Another host on the network | The server binds to loopback only. A non-loopback `--addr` is a usage error (exit 64) unless `--expose` is given, and then a warning is printed. |
| The token leaking through the URL | It is printed in the fragment (`#token=`), which the browser does not send to the server and which does not appear in server logs or `Referer` headers. The UI moves it into the `sessionStorage` of the tab and removes it from the address bar with `history.replaceState`. It is compared in constant time. |
| Script injection into the UI, framing, content sniffing | `Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` (no inline or remote scripts), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store` on the API. |
| Reading or overwriting other files through the scenario routes | Only `*.yaml` and `*.yml` files inside the workspace: relative paths with forward slashes, no `..`, no absolute or drive paths, symlinks resolved and refused when they leave the workspace, at most 256 KiB per file. Every name must be spelled as it is on disk, so other letter case and Windows 8.3 short names (`GITHUB~1` for `.github`) are refused, and dot files stay out of reach. Report downloads read the scenario file through the same checks. The listing goes at most 4 levels deep and 500 files and skips dot directories, `node_modules` and `vendor`. |
| Exhausting memory or flooding a target | Request bodies are capped at 1 MiB; only one race runs at a time (409 otherwise) and a run can be cancelled. A run from the UI goes through the same runner as `photofinish run`, which enforces `scope.allow_hosts` and the request budget of the scenario. |

### What it does not protect against

- **Anyone who has the token.** The token is the only credential, and it grants everything the UI can do,
  including writing a scenario with any `allow_hosts` and running it: the scope protects you from a wrong scenario,
  not from a hostile user of the server. Treat the token like a password. It is visible in your terminal, in its
  scrollback, and in any log the output of `serve` goes to; `PHOTOFINISH_TOKEN` is visible to processes of the
  same user. A new token is generated at every start unless `PHOTOFINISH_TOKEN` is set.
- **The browser history with `--open`.** `--open` does not put the link on a command line, where other local
  users could read it (`ps`, `/proc/<pid>/cmdline`): it writes a redirect page, readable by you only, into a new
  private temporary directory, opens that file and removes it when the server stops (after two minutes at the
  latest). The browser then keeps the link, token included, in its history like any address you open.
- **Other local users and malware running as you.** Loopback is reachable by every process on the machine. They
  still need the token, but a process running as your user can read your terminal, environment and files.
- **The network with `--expose`.** The server speaks plain HTTP. On a non-loopback address the token and the
  evidence cross the network unencrypted. Use `--expose` only on an isolated lab network, or inside a container
  whose port is published to the loopback of the host only (`-p 127.0.0.1:7340:7340`); for remote access use an
  SSH tunnel instead.
- **The contents of the data directory.** `<data>/photofinish.db` keeps every run with its masked report, which
  still contains response bodies, headers and URLs of the target (see below). It is readable by whoever can read
  your user config directory; delete runs you no longer need, or use `--data :memory:`.

The demo shop started with `--demo` or from the sidebar is the same intentionally vulnerable shop as
`photofinish demo`, on `--demo-addr` (default `127.0.0.1:8443`, which the examples expect; loopback only).

## Using PhotoFinish responsibly

- The demo shop (`photofinish demo`) is intentionally vulnerable. It binds to `127.0.0.1` by default and refuses a
  non-loopback address unless you pass `--expose`. Use `--expose` only on an isolated lab network.
- The demo tokens (`demo-alice`, `demo-bob`) and the certificate are throwaway values for local testing.
- Test only systems you own or are explicitly authorized to test. Race testing sends bursts of synchronized
  requests and can change real state: balances, orders, coupons, account lockouts.

## Reports contain evidence

- The JSON, HTML, SARIF and JUnit reports are built from the same evidence. Credential headers, identity headers,
  `${env:...}` values, sensitive query parameters and JSON keys such as `password` or `token` are masked in all of
  them, but the reports still include response bodies, headers, URLs and the values of the invariant, which can
  contain personal or business data of the target. Review a report before you share it, attach it to a bug bounty
  submission or upload it to code scanning.
- Uploading SARIF to GitHub code scanning makes the results visible to everyone who can read the repository's
  security alerts. Upload only results of systems you are allowed to disclose to that audience.
- The GitHub Action keeps the reports in the workspace and in `RUNNER_TEMP`; uploaded artifacts are readable by
  everyone with read access to the repository's Actions. Pass secrets to scenarios through the step's `env:` and
  `${env:NAME}`, never as literal values in scenario files.
