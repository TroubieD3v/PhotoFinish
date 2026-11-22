// Screenshots of the web UI for the README: docs/screenshots/*.png, and the
// HTML report of the coupon-vuln run: docs/report-html.png.
//
//   npm --prefix web run build
//   go build -ldflags "-X main.version=v0.1.0" -o bin/photofinish$(go env GOEXE) ./cmd/photofinish
//   node web/media/shots.ts
//
// The script starts "photofinish serve --demo" on an empty temporary
// workspace, copies three examples, runs them so that the history has
// entries, and takes 1440x900 screenshots at device scale 1. Clicks are sent
// as DOM clicks so that the mouse never hovers anything in a picture.
//
// Local paths stay out of the images: GET /api/info is intercepted with
// page.route and its "workspace" field is replaced with "/work" (see
// uiContext in server.ts). Every page is checked for local paths,
// pseudo-versions and the development version before its screenshot is taken.

import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { chromium, type Page } from "@playwright/test";
import { assertClean, docs, openUI, settle, startServer, TOKEN, uiContext } from "./server.ts";

const out = join(docs, "screenshots");
mkdirSync(out, { recursive: true });

const W = 1440;
const H = 900;

async function shot(page: Page, name: string): Promise<void> {
  await settle(page);
  await assertClean(page, name);
  await page.screenshot({ path: join(out, name) });
  console.log("wrote", join("docs", "screenshots", name));
}

/** Clicks an element without moving the mouse (no hover state in the image). */
async function domClick(page: Page, selector: string): Promise<void> {
  await page.locator(selector).first().evaluate((el) => (el as HTMLElement).click());
}

/** Opens a finished run and selects its first VIOLATED trial. */
async function openViolatedRun(page: Page, id: string): Promise<void> {
  await page.evaluate((h) => (window.location.hash = h), `#/run?id=${id}`);
  await page.getByTestId("run-report").waitFor({ timeout: 30_000 });
  await domClick(page, 'button.trial-btn[aria-label$="VIOLATED"]');
  await page.getByTestId("timeline").locator("g.tl-row.bad").first().waitFor();
  await page.getByTestId("terms").locator('tr[data-state="fail"]').first().waitFor();
}

const server = await startServer(process.env.PF_MEDIA_WINDOW || "0s");
const browser = await chromium.launch({ channel: process.env.PW_CHANNEL || undefined });
try {
  for (const name of ["coupon-vuln", "coupon-fixed", "giftcard-vuln", "giftcard-fixed", "twofa-vuln", "twofa-fixed"]) {
    await server.api("POST", `/api/examples/${name}/copy`);
  }
  const vuln = await server.run({ path: "examples/coupon-vuln.yaml" });
  await server.run({ path: "examples/coupon-fixed.yaml" });
  await server.run({ path: "examples/twofa-vuln.yaml" });

  const dark = await uiContext(browser, { width: W, height: H, colorScheme: "dark" });
  const page = await dark.newPage();
  await openUI(page, server.base);
  await page.getByTestId("scenario-row-examples/coupon-vuln.yaml").waitFor();
  await shot(page, "scenarios.png");

  await page.evaluate(() => (window.location.hash = "#/scenario?path=examples/coupon-vuln.yaml"));
  await page.getByTestId("editor-title").filter({ hasText: "examples/coupon-vuln.yaml" }).waitFor();
  await page.getByTestId("problems").filter({ hasText: "Valid scenario" }).waitFor();
  await shot(page, "editor.png");

  await openViolatedRun(page, vuln);
  await shot(page, "run.png");

  await page.evaluate(() => (window.location.hash = "#/runs"));
  await page.getByTestId("run-row").nth(2).waitFor();
  await shot(page, "runs.png");

  await page.evaluate(() => (window.location.hash = "#/probe"));
  await page.getByTestId("probe-url").fill("https://127.0.0.1:8443/");
  await page.getByTestId("probe-insecure").check();
  await domClick(page, '[data-testid="probe-submit"]');
  await page.getByTestId("probe-recommended").filter({ hasText: "h2" }).waitFor({ timeout: 30_000 });
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
  await shot(page, "probe.png");

  await page.evaluate(() => (window.location.hash = "#/import"));
  await page.getByTestId("import-text").fill(
    [
      "POST /vuln/api/carts/c-1/coupons HTTP/2",
      "Host: 127.0.0.1:8443",
      "Authorization: Bearer demo-alice",
      "Content-Type: application/json",
      "",
      '{"code":"WELCOME10"}',
    ].join("\n"),
  );
  await domClick(page, '[data-testid="import-generate"]');
  await page.getByTestId("import-yaml").filter({ hasText: "race:" }).waitFor();
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
  await page.evaluate(() => window.scrollTo(0, 0));
  await shot(page, "import.png");
  await dark.close();

  const light = await uiContext(browser, { width: W, height: H, colorScheme: "light" });
  const lp = await light.newPage();
  await openUI(lp, server.base);
  await openViolatedRun(lp, vuln);
  await shot(lp, "run-light.png");
  await light.close();

  // The HTML report of the same run, as "Report: HTML" downloads it, full page.
  const res = await fetch(`${server.base}/api/runs/${vuln}/report.html`, {
    headers: { Authorization: `Bearer ${TOKEN}`, Origin: server.base },
  });
  if (!res.ok) throw new Error(`report.html: ${res.status}`);
  const html = await res.text();
  const rctx = await browser.newContext({ viewport: { width: W, height: H }, deviceScaleFactor: 1, colorScheme: "dark", reducedMotion: "reduce" });
  const rp = await rctx.newPage();
  await rp.setContent(html, { waitUntil: "load" });
  await settle(rp);
  await assertClean(rp, "report-html.png");
  await rp.screenshot({ path: join(docs, "report-html.png"), fullPage: true });
  console.log("wrote", join("docs", "report-html.png"));
  await rctx.close();
} finally {
  await browser.close();
  await server.stop();
}
