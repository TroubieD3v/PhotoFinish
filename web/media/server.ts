// Shared helpers of the media scripts: start "photofinish serve --demo" on an
// empty temporary workspace, call its API and prepare browser contexts.
//
// Not part of the e2e suite: web/playwright.config.ts only reads web/e2e.

import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Browser, BrowserContext, Page } from "@playwright/test";

const here = dirname(fileURLToPath(import.meta.url));
export const repo = resolve(here, "..", "..");
export const docs = join(repo, "docs");

/** Fixed session token of the throwaway media server. Not a secret. */
export const TOKEN = "photofinish-media-session-token-000000000";

/** The workspace path the UI shows in the images (the README's Docker example uses /work). */
export const SHOWN_WORKSPACE = "/work";

export interface Server {
  base: string;
  /** Calls the API with the session token; throws on a non-2xx reply. */
  api: (method: string, path: string, body?: unknown) => Promise<any>;
  /** Starts a run and waits until it is finished; returns its id. */
  run: (req: Record<string, unknown>) => Promise<string>;
  stop: () => Promise<void>;
}

/**
 * The binary to start: PF_MEDIA_BIN, default bin/photofinish (.exe on
 * Windows). Fails unless it exists and reports a release version, so that a
 * stale build or a development build ("0.0.0-dev", a pseudo-version) does
 * not end up in the images. PF_MEDIA_VERSION pins the exact version.
 */
export function mediaBinary(): string {
  const exe = process.platform === "win32" ? ".exe" : "";
  const bin = resolve(process.env.PF_MEDIA_BIN || join(repo, "bin", `photofinish${exe}`));
  if (!existsSync(bin)) {
    throw new Error(`${bin} does not exist; build it as web/media/README.md says, or set PF_MEDIA_BIN`);
  }
  const out = execFileSync(bin, ["version"], { encoding: "utf8" }).trim();
  const want = process.env.PF_MEDIA_VERSION;
  const ok = want ? out === `photofinish ${want}` : /^photofinish v\d+\.\d+\.\d+$/.test(out);
  if (!ok) {
    const expected = want ? `"photofinish ${want}"` : "a release version such as photofinish v0.1.0";
    throw new Error(`${bin} reports "${out}", expected ${expected}; build it with -ldflags "-X main.version=vX.Y.Z"`);
  }
  return bin;
}

/**
 * Starts the binary (see mediaBinary) with the demo shop on 127.0.0.1:8443,
 * the history in memory and a new temporary workspace. PF_MEDIA_PORT sets
 * the UI port (default 7360).
 */
export async function startServer(demoWindow: string): Promise<Server> {
  const bin = mediaBinary();
  const port = Number(process.env.PF_MEDIA_PORT || 7360);
  const base = `http://127.0.0.1:${port}`;
  const workspace = mkdtempSync(join(tmpdir(), "photofinish-media-"));
  const args = ["serve", "--addr", `127.0.0.1:${port}`, "--demo", "--demo-window", demoWindow, "--data", "", "--workspace", workspace];
  const child: ChildProcess = spawn(bin, args, {
    env: { ...process.env, PHOTOFINISH_TOKEN: TOKEN },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  let spawnError: Error | undefined;
  child.stdout?.on("data", (d) => (log += d));
  child.stderr?.on("data", (d) => (log += d));
  const exited = new Promise<void>((res) => {
    child.once("exit", () => res());
    child.once("error", (e) => {
      spawnError = e;
      res();
    });
  });

  const stop = async () => {
    if (child.exitCode === null) {
      child.kill();
      await Promise.race([exited, new Promise((r) => setTimeout(r, 5000))]);
    }
    // Windows keeps the directory busy for a moment after the exit.
    for (let i = 0; i < 10; i++) {
      try {
        rmSync(workspace, { recursive: true, force: true });
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 300));
      }
    }
  };

  const api = async (method: string, path: string, body?: unknown) => {
    const res = await fetch(base + path, {
      method,
      headers: {
        Authorization: `Bearer ${TOKEN}`,
        Origin: base,
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${text}`);
    return text ? JSON.parse(text) : null;
  };

  const run = async (req: Record<string, unknown>) => {
    const { id } = await api("POST", "/api/runs", req);
    for (let i = 0; i < 600; i++) {
      const d = await api("GET", `/api/runs/${id}`);
      if (d.run.status !== "running") {
        if (d.run.status !== "finished") throw new Error(`run ${id}: ${d.run.status}`);
        return id as string;
      }
      await new Promise((r) => setTimeout(r, 250));
    }
    throw new Error(`run ${id} did not finish`);
  };

  try {
    for (let i = 0; ; i++) {
      if (spawnError) throw new Error(`${bin} did not start: ${spawnError.message}`);
      if (child.exitCode !== null) throw new Error(`serve exited:\n${log}`);
      try {
        if ((await fetch(`${base}/api/health`)).ok) break;
      } catch {
        // not listening yet
      }
      if (i > 100) throw new Error(`serve did not start:\n${log}`);
      await new Promise((r) => setTimeout(r, 200));
    }
  } catch (e) {
    await stop();
    throw e;
  }
  return { base, api, run, stop };
}

/**
 * A browser context for the UI. GET /api/info names the workspace, which the
 * sidebar footer and the Scenarios page show. The real value is a temporary
 * directory of this machine, so the reply is rewritten here: "workspace"
 * becomes "/work", the path of the README's Docker example. No other reply
 * is changed.
 */
export async function uiContext(
  browser: Browser,
  opts: { width: number; height: number; colorScheme: "dark" | "light" },
): Promise<BrowserContext> {
  const ctx = await browser.newContext({
    viewport: { width: opts.width, height: opts.height },
    deviceScaleFactor: 1,
    colorScheme: opts.colorScheme,
    reducedMotion: "reduce",
  });
  await ctx.route("**/api/info", async (route) => {
    const res = await route.fetch();
    const info = await res.json();
    info.workspace = SHOWN_WORKSPACE;
    await route.fulfill({ response: res, json: info });
  });
  return ctx;
}

/** Opens the UI with the token link and waits for the Scenarios page. */
export async function openUI(page: Page, base: string): Promise<void> {
  await page.goto(`${base}/#token=${TOKEN}`);
  await page.getByRole("heading", { name: "Scenarios", level: 1 }).waitFor();
}

/** Waits for the fonts, a quiet network and two animation frames. */
export async function settle(page: Page): Promise<void> {
  await page.waitForLoadState("networkidle", { timeout: 10_000 }).catch(() => {});
  await page.evaluate(() => document.fonts.ready.then(() => undefined));
  await page.evaluate(() => new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => r()))));
  await page.waitForTimeout(250);
}

/** Local paths, the temporary workspace, pseudo-versions and the development version. */
const FORBIDDEN = ["C:\\", "Users", "/home/", "/var/folders", "tmp", "v0.0.0-", "0.0.0-dev", "photofinish-media-"];

/**
 * Fails when the page text, an attribute or the value of a form field
 * contains a local path, a pseudo-version or the development version, so
 * that no image shows one.
 */
export async function assertClean(page: Page, name: string): Promise<void> {
  const text: string = await page.evaluate(() => {
    const parts = [document.body.innerText];
    for (const el of Array.from(document.querySelectorAll("*"))) {
      for (const a of Array.from(el.attributes)) parts.push(a.value);
      if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement) {
        parts.push(el.value);
      }
    }
    return parts.join("\n");
  });
  const hit = FORBIDDEN.find((f) => text.includes(f));
  if (hit) throw new Error(`${name}: the page shows "${hit}"`);
}
