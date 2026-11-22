import { mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "@playwright/test";
import { E2E_TOKEN } from "./e2e/constants";

// The e2e tests drive the prebuilt binary (API, embedded UI and the demo
// shop); nothing is built here. Build first:
//
//   npm --prefix web run build && go build -o bin/photofinish$(go env GOEXE) ./cmd/photofinish
//
// PF_E2E_BIN overrides the binary, PF_E2E_PORT the UI port. The examples
// target the demo shop on 127.0.0.1:8443, so that port must be free. The
// 2 ms demo window makes the coupon-vuln race reproduce in every trial, as
// the examples job in CI does with "demo --window 2ms".
// Locally an installed Chrome can be used: PW_CHANNEL=chrome.

const here = fileURLToPath(new URL(".", import.meta.url));
const exe = process.platform === "win32" ? ".exe" : "";
const bin = process.env.PF_E2E_BIN || join(here, "..", "bin", `photofinish${exe}`);
const port = Number(process.env.PF_E2E_PORT || 7341);

// One empty workspace per test run; workers inherit it through the environment.
// On Windows the teardown cannot remove the workspace while the server still
// holds it open, so workspaces that earlier runs left behind are removed here.
// Only those older than STALE_MS: on Linux and macOS an open directory can be
// removed, and a younger one may belong to an e2e run that is in progress in
// another checkout.
const STALE_MS = 60 * 60 * 1000;
if (!process.env.PF_E2E_WORKSPACE) {
  for (const name of readdirSync(tmpdir())) {
    if (!name.startsWith("photofinish-e2e-")) continue;
    const dir = join(tmpdir(), name);
    try {
      if (Date.now() - statSync(dir).mtimeMs < STALE_MS) continue;
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // Gone already, or still in use (Windows).
    }
  }
  process.env.PF_E2E_WORKSPACE = mkdtempSync(join(tmpdir(), "photofinish-e2e-"));
}
const workspace = process.env.PF_E2E_WORKSPACE;

export default defineConfig({
  testDir: "./e2e",
  globalTeardown: "./e2e/teardown.ts",
  timeout: 120_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: !!process.env.CI,
  reporter: [["list"]],
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    channel: process.env.PW_CHANNEL || undefined,
    viewport: { width: 1440, height: 900 },
    trace: "retain-on-failure",
    acceptDownloads: true,
  },
  webServer: {
    command: `"${bin}" serve --addr 127.0.0.1:${port} --demo --demo-window 2ms --data :memory: --workspace "${workspace}"`,
    url: `http://127.0.0.1:${port}/api/health`,
    env: { PHOTOFINISH_TOKEN: E2E_TOKEN },
    reuseExistingServer: false,
    timeout: 60_000,
    stdout: "pipe",
    stderr: "pipe",
  },
});
