# Media

Scripts that make the screenshots in `docs/screenshots/`, `docs/report-html.png`
and `docs/demo.gif`.
They are not tests: the e2e suite (`web/playwright.config.ts`) reads only
`web/e2e`, and CI does not run anything here.

## Requirements

- Node.js 22.18 or later (runs the `.ts` files directly) and the packages of
  `web/` (`npm --prefix web ci`), with the Playwright Chromium installed
  (`npx --prefix web playwright install chromium`).
- Python 3 with Pillow 9.1 or later, for the GIF.
- Free ports: 7360 for the UI and 8443 for the demo shop.

## Build

From the repository root:

```sh
npm --prefix web run build
go build -ldflags "-X main.version=v0.1.0" -o bin/photofinish$(go env GOEXE) ./cmd/photofinish
```

`$(go env GOEXE)` adds `.exe` on Windows: `go build -o` does not add it, and
the scripts start `bin/photofinish.exe` there. The version in the sidebar and
in the HTML report comes from the binary, so set it with `-ldflags`. The
scripts run `<binary> version` first and stop unless it reports a release
version such as `photofinish v0.1.0`; a development build reports
`0.0.0-dev` or a pseudo-version.

## Screenshots

```sh
node web/media/shots.ts
```

The script starts `photofinish serve --demo --demo-window 0s` on an empty
temporary workspace with the history in memory, copies the coupon, giftcard
and twofa examples, runs coupon-vuln, coupon-fixed and twofa-vuln, and writes
1440x900 images at device scale 1:

| File | Shows |
| --- | --- |
| `scenarios.png` | the workspace with six examples and their last verdicts |
| `editor.png` | `coupon-vuln.yaml` in the editor |
| `run.png` | the finished coupon-vuln run, a violated trial selected |
| `runs.png` | the run history |
| `probe.png` | a probe of the demo shop |
| `import.png` | a raw request turned into a scenario |
| `run-light.png` | `run.png` in the light theme |

It also downloads the HTML report of the coupon-vuln run from the API and
writes a full-page screenshot of it, 1440 px wide, to `docs/report-html.png`.

## GIF

```sh
node web/media/gif-frames.ts
python web/media/make_gif.py
```

`gif-frames.ts` records PNG frames at 1440x900 with the demo shop on
`--demo-window 0s`: open coupon-vuln, run 30 trials, watch them arrive, hover
a red stream row. `make_gif.py` scales the frames to 960x600, merges
duplicates, uses one adaptive palette, holds the last frame for at least 3 s
(3.2 s as recorded) and writes `docs/demo.gif`. Both read `PF_MEDIA_FRAMES` for the frame directory;
the default is `photofinish-gif-frames` in the system temp directory.

## Local paths

The UI shows the workspace path from `GET /api/info`. Both scripts intercept
that reply and replace `workspace` with `/work`, the path of the Docker
example in the README. Before each screenshot and each GIF frame they check
the page text, the attributes and the values of form fields for local paths
(`C:\`, `Users`, `/home/`, `/var/folders`, `tmp`), the name of the temporary
workspace, pseudo-versions and `0.0.0-dev`, and stop if one is found.

## Settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `PF_MEDIA_BIN` | `bin/photofinish` (`.exe` on Windows) | the binary to start |
| `PF_MEDIA_VERSION` | | the exact version the binary must report, for example `v0.1.0` |
| `PF_MEDIA_PORT` | `7360` | UI port |
| `PF_MEDIA_WINDOW` | `0s` | `--demo-window` of the demo shop |
| `PF_MEDIA_FRAMES` | temp dir | where `gif-frames.ts` writes the frames |
| `PW_CHANNEL` | | a Playwright browser channel, for example `chrome` |

The runs are real races, so verdict counts and timings differ between runs.
