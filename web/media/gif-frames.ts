// PNG frames for docs/demo.gif; web/media/make_gif.py assembles them.
//
//   node web/media/gif-frames.ts            # frames in PF_MEDIA_FRAMES
//   python web/media/make_gif.py            # writes docs/demo.gif
//
// The walk-through: Scenarios page, open coupon-vuln, set 30 trials, Run,
// trials arrive live, the VIOLATED report with its timeline, hover a red
// stream row to show its timings. The demo shop runs with --demo-window 0s,
// so the race is real and not every trial breaks the rule.
//
// The viewport is 1440x900, as in the screenshots; make_gif.py scales the
// frames to 960x600. At 1280 px the timeline column is too narrow and
// scrolls sideways.
//
// Headless screenshots have no mouse pointer, so the page draws one that
// follows the mouse events. As in shots.ts, GET /api/info is intercepted with
// page.route and "workspace" becomes "/work", so that no local path shows,
// and every frame is checked for local paths and versions before it is taken.
//
// frames.json lists every frame with the time it stays on screen in ms.

import { mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { chromium, type Locator, type Page } from "@playwright/test";
import { assertClean, openUI, settle, startServer, uiContext } from "./server.ts";

const dir = resolve(process.env.PF_MEDIA_FRAMES || join(tmpdir(), "photofinish-gif-frames"));
mkdirSync(dir, { recursive: true });
for (const f of readdirSync(dir)) if (/^f\d+\.png$/.test(f) || f === "frames.json") rmSync(join(dir, f));

const W = 1440;
const H = 900;
const TRIALS = "30";

/** Draws a pointer that follows the mouse; screenshots do not show the real one. */
function pointerScript() {
  const svg =
    '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="24" viewBox="0 0 20 24">' +
    '<path d="M2 2 L2 19 L6.5 14.8 L9.6 21.6 L12.6 20.3 L9.6 13.6 L15.6 13.6 Z" fill="#fff" stroke="#000" stroke-width="1.4" stroke-linejoin="round"/></svg>';
  const add = () => {
    const el = document.createElement("div");
    el.id = "media-pointer";
    el.innerHTML = svg;
    el.style.cssText = "position:fixed;left:-40px;top:-40px;z-index:2147483647;pointer-events:none;width:20px;height:24px";
    document.body.appendChild(el);
    window.addEventListener(
      "mousemove",
      (e) => {
        el.style.left = `${e.clientX - 2}px`;
        el.style.top = `${e.clientY - 2}px`;
      },
      true,
    );
  };
  if (document.body) add();
  else document.addEventListener("DOMContentLoaded", add);
}

const frames: { file: string; ms: number }[] = [];
// The pointer starts on the empty part of the top bar, where it hovers nothing.
let mouse = { x: 640, y: 22 };

/** Checks the page for local paths and versions (see assertClean), then takes a frame. */
async function frame(page: Page, ms: number): Promise<void> {
  const file = `f${String(frames.length).padStart(4, "0")}.png`;
  await assertClean(page, file);
  await page.screenshot({ path: join(dir, file) });
  frames.push({ file, ms });
}

/**
 * Glides the pointer to the target in a few frames. Each frame stays 70 ms,
 * longer than MIN_MS of make_gif.py, so that none of them is dropped.
 */
async function glide(page: Page, x: number, y: number, steps = 6): Promise<void> {
  const from = mouse;
  for (let i = 1; i <= steps; i++) {
    const t = i / steps;
    const e = t < 0.5 ? 2 * t * t : 1 - (-2 * t + 2) ** 2 / 2;
    await page.mouse.move(from.x + (x - from.x) * e, from.y + (y - from.y) * e);
    await frame(page, 70);
  }
  mouse = { x, y };
}

async function center(loc: Locator, dx = 0.5): Promise<{ x: number; y: number }> {
  const b = await loc.boundingBox();
  if (!b) throw new Error("element has no box");
  return { x: Math.round(b.x + b.width * dx), y: Math.round(b.y + b.height / 2) };
}

async function clickAt(page: Page, loc: Locator, dx = 0.5): Promise<void> {
  const p = await center(loc, dx);
  await glide(page, p.x, p.y);
  await frame(page, 250);
  await page.mouse.down();
  await page.mouse.up();
}

const server = await startServer(process.env.PF_MEDIA_WINDOW || "0s");
const browser = await chromium.launch({ channel: process.env.PW_CHANNEL || undefined });
try {
  for (const name of ["coupon-vuln", "coupon-fixed", "giftcard-vuln", "giftcard-fixed", "twofa-vuln", "twofa-fixed"]) {
    await server.api("POST", `/api/examples/${name}/copy`);
  }
  const ctx = await uiContext(browser, { width: W, height: H, colorScheme: "dark" });
  await ctx.addInitScript(pointerScript);
  const page = await ctx.newPage();
  await openUI(page, server.base);
  await page.getByTestId("scenario-row-examples/coupon-vuln.yaml").waitFor();
  await page.mouse.move(mouse.x, mouse.y);
  await settle(page);
  await frame(page, 1500);

  // Open coupon-vuln.
  await clickAt(page, page.getByTestId("scenario-row-examples/coupon-vuln.yaml").getByRole("link", { name: "coupon-vuln" }), 0.3);
  await page.getByTestId("problems").filter({ hasText: "Valid scenario" }).waitFor();
  await settle(page);
  await frame(page, 1400);

  // 30 trials instead of the 10 of the file, so the live view lasts a moment.
  const trials = page.getByTestId("run-trials");
  await clickAt(page, trials, 0.7);
  await trials.selectText();
  for (const ch of TRIALS) {
    await page.keyboard.type(ch);
    await frame(page, 120);
  }
  await frame(page, 400);

  // Run, then record the live view until the report replaces it.
  await clickAt(page, page.getByTestId("run"), 0.5);
  const report = page.getByTestId("run-report");
  // Each live frame stays on screen until the next one was taken, so the
  // GIF plays the run at its real speed.
  let last = 0;
  while (!(await report.isVisible())) {
    const now = Date.now();
    if (last) frames[frames.length - 1].ms = now - last;
    last = now;
    await frame(page, 100);
  }
  if (last) frames[frames.length - 1].ms = Math.max(100, Date.now() - last);
  await settle(page);
  await frame(page, 1800);

  // Hover a red stream row: its exact timings.
  const bad = page.getByTestId("timeline").locator("g.tl-row.bad");
  const row = bad.nth(Math.min(1, (await bad.count()) - 1));
  const at = await center(row.locator("rect.bar"), 0.7);
  await glide(page, at.x, at.y, 8);
  await page.getByTestId("timeline-tooltip").waitFor();
  await page.waitForTimeout(150);
  await frame(page, 3200);

  writeFileSync(join(dir, "frames.json"), JSON.stringify(frames, null, 1));
  console.log(`${frames.length} frames in ${dir}`);
  await ctx.close();
} finally {
  await browser.close();
  await server.stop();
}
