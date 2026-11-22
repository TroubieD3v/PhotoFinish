import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { expect, test, type Page } from "@playwright/test";
import { E2E_TOKEN } from "./constants";

// One browser page goes through the whole workflow in order, as a person
// would: copy the examples, edit, run, inspect, download, probe, import.
// The server is the real binary with the demo shop on 127.0.0.1:8443 and an
// empty workspace (see playwright.config.ts).

const exampleLine = (file: string, text: string): number => {
  const path = fileURLToPath(new URL(`../../examples/${file}`, import.meta.url));
  const lines = readFileSync(path, "utf8").split(/\r?\n/);
  const i = lines.indexOf(text);
  if (i < 0) throw new Error(`${file} has no line ${JSON.stringify(text)}`);
  return i + 1;
};

test.describe.configure({ mode: "serial" });

let page: Page;
const consoleErrors: string[] = [];

test.beforeAll(async ({ browser }) => {
  page = await browser.newPage();
  page.on("console", (m) => {
    if (m.type() === "error") consoleErrors.push(m.text());
  });
  page.on("pageerror", (e) => consoleErrors.push(e.message));
});

test.afterAll(async () => {
  await page.close();
});

test("without a token the token screen explains what to open", async ({ browser }) => {
  const fresh = await browser.newPage();
  const errors: string[] = [];
  fresh.on("pageerror", (e) => errors.push(e.message));
  await fresh.goto("/");
  await expect(fresh.getByTestId("token-screen")).toBeVisible();
  await expect(fresh.getByRole("heading", { name: /Session token missing: open the link printed by photofinish serve/ })).toBeVisible();
  // A wrong token is refused by the server.
  await fresh.getByLabel("Token or link").fill("not-the-right-token-but-long-enough-000000");
  await fresh.getByRole("button", { name: "Continue" }).click();
  await expect(fresh.getByText("The server did not accept this token.")).toBeVisible();
  // Pasting the printed link into the open tab changes only the fragment.
  await fresh.goto(`/#token=${E2E_TOKEN}`);
  await expect(fresh.getByRole("heading", { name: "Scenarios", level: 1 })).toBeVisible();
  expect(fresh.url()).not.toContain(E2E_TOKEN);
  expect(errors).toEqual([]);
  await fresh.close();
});

test("opens with the token from the link and removes it from the address", async () => {
  await page.goto(`/#token=${E2E_TOKEN}`);
  await expect(page.getByRole("heading", { name: "Scenarios", level: 1 })).toBeVisible();
  expect(page.url()).not.toContain(E2E_TOKEN);
  await expect(page.getByTestId("demo-state")).toHaveText("running");
  await expect(page.getByText("No scenarios in this workspace yet")).toBeVisible();
});

test("copies the coupon examples into the workspace", async () => {
  await page.getByTestId("copy-example-coupon-vuln").click();
  await expect(page.getByTestId("scenario-row-examples/coupon-vuln.yaml")).toBeVisible();
  await page.getByTestId("copy-example-coupon-fixed").click();
  await expect(page.getByTestId("scenario-row-examples/coupon-fixed.yaml")).toBeVisible();
});

test("shows a YAML error at its line and clears it when fixed", async () => {
  const line = exampleLine("coupon-vuln.yaml", "  copies: 20");
  await page.getByTestId("scenario-row-examples/coupon-vuln.yaml").getByRole("link", { name: "coupon-vuln" }).click();
  await expect(page.getByTestId("editor-title")).toHaveText("examples/coupon-vuln.yaml");
  await expect(page.getByTestId("problems")).toContainText("Valid scenario");

  const target = page.locator(".cm-line", { hasText: /^\s+copies: 20$/ }).first();
  await target.click();
  await page.keyboard.press("End");
  await page.keyboard.type("x");
  await expect(page.getByTestId("dirty")).toBeVisible();

  const problem = page.getByTestId("problem").first();
  await expect(problem).toHaveAttribute("data-line", String(line));
  await expect(problem).toContainText("race.copies");
  await expect(page.locator(".cm-lint-marker-error")).toHaveCount(1);

  await page.keyboard.press("Backspace");
  await expect(page.getByTestId("problem-count")).toHaveText("0");
  await expect(page.getByTestId("problems")).toContainText("Valid scenario");
  await expect(page.locator(".cm-lint-marker-error")).toHaveCount(0);
  await expect(page.getByTestId("dirty")).toHaveCount(0);
});

/** Starts the open scenario with 3 trials and waits for the finished report. */
async function runThreeTrials(): Promise<void> {
  await page.getByTestId("run-trials").fill("3");
  await page.getByTestId("run").click();
  await expect(page).toHaveURL(/#\/run\?id=[0-9a-f]+/);
  await expect(page.getByTestId("run-report")).toBeVisible({ timeout: 90_000 });
}

test("runs coupon-vuln: VIOLATED with a timeline and failing terms", async () => {
  await runThreeTrials();
  await expect(page.getByTestId("verdict")).toHaveText("VIOLATED");
  await expect(page.getByTestId("summary")).toContainText("trials broke the rule");
  await expect(page.getByTestId("trials").locator("tbody tr")).toHaveCount(3);
  const rows = page.getByTestId("timeline").locator("g.tl-row");
  await expect(rows).toHaveCount(20);
  await expect(page.getByTestId("terms").locator('tr[data-state="fail"]').first()).toBeVisible();
  await expect(page.getByTestId("reproduce")).toContainText("photofinish run examples/coupon-vuln.yaml");

  // "1 write · 200 B" wraps between its parts in a narrow cell, and the
  // separator shows only between two parts on the same line.
  const release = page.locator(".metric", { has: page.locator(".label", { hasText: "Release" }) }).locator(".value");
  await expect(release).toContainText("200 B");
  const misplaced = await release.evaluate((value) => {
    const left = value.getBoundingClientRect().left;
    const parts = Array.from(value.querySelectorAll(":scope > span > .nowrap"));
    const bad: number[] = [];
    parts.forEach((part, i) => {
      if (i === 0) return;
      const sep = part.querySelector(".sep")!.getBoundingClientRect();
      const sameLine = Math.abs(parts[i - 1].getBoundingClientRect().top - sep.top) < 1;
      const shown = sep.right > left + 0.5;
      if (sameLine !== shown) bad.push(i);
    });
    // A separator left of the cell is hidden only because the cell clips it.
    if (getComputedStyle(value).overflowX !== "hidden") bad.push(-2);
    return parts.length > 1 ? bad : [-1];
  });
  expect(misplaced).toEqual([]);

  // Hovering a request shows its exact timings.
  await rows.nth(0).hover();
  await expect(page.getByRole("tooltip")).toContainText("First byte");
});

test("the timeline is one tab stop with arrow keys, Escape and an unclipped tooltip", async () => {
  const rows = page.getByTestId("timeline").locator("g.tl-row");
  await expect(page.getByTestId("timeline").locator('g.tl-row[tabindex="0"]')).toHaveCount(1);
  await rows.nth(0).focus();
  await page.keyboard.press("ArrowDown");
  await expect(rows.nth(1)).toBeFocused();
  await expect(page.getByTestId("timeline").locator('g.tl-row[tabindex="0"]')).toHaveCount(1);
  await expect(rows.nth(1)).toHaveAttribute("tabindex", "0");
  await expect(page.getByRole("tooltip")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("tooltip")).toHaveCount(0);

  // The last row's tooltip opens above it, inside the plot.
  await page.keyboard.press("End");
  await expect(rows.nth(19)).toBeFocused();
  const tip = page.getByTestId("timeline-tooltip");
  await expect(tip).toBeVisible();
  const plot = page.locator(".timeline-plot");
  const [t, b] = [await tip.boundingBox(), await plot.boundingBox()];
  expect(t && b && t.y + t.height <= b.y + b.height + 1).toBe(true);
  expect(await plot.evaluate((el) => el.scrollHeight <= el.clientHeight + 1)).toBe(true);
  await page.keyboard.press("Escape");
});

test("downloads the SARIF report", async () => {
  const [download] = await Promise.all([page.waitForEvent("download"), page.getByTestId("download-sarif").click()]);
  expect(download.suggestedFilename()).toMatch(/\.sarif$/);
  const path = await download.path();
  const sarif = JSON.parse(readFileSync(path, "utf8")) as { version?: string; runs?: unknown[] };
  expect(sarif.version).toBe("2.1.0");
  expect(sarif.runs?.length).toBe(1);
});

test("runs coupon-fixed: HELD", async () => {
  await page.getByRole("link", { name: "Scenarios", exact: true }).click();
  await page.getByTestId("scenario-row-examples/coupon-fixed.yaml").getByRole("link", { name: "coupon-fixed" }).click();
  await expect(page.getByTestId("problems")).toContainText("Valid scenario");
  await page.locator("#run-copies").fill("6");
  await runThreeTrials();
  await expect(page.getByTestId("verdict")).toHaveText("HELD");
  await expect(page.getByTestId("summary")).toContainText("not reproduced");
  await expect(page.getByTestId("reproduce")).toContainText("--copies 6");
});

test("run again sends what the reproduce command says", async () => {
  // Answer the start request here, so that no third run is made.
  let sent: Record<string, unknown> | null = null;
  await page.route("**/api/runs", async (route) => {
    if (route.request().method() !== "POST") return route.fallback();
    sent = route.request().postDataJSON() as Record<string, unknown>;
    await route.fulfill({ status: 409, contentType: "application/json", body: JSON.stringify({ error: "busy", id: "000000000000" }) });
  });
  await page.getByTestId("run-again").click();
  await expect(page.getByText("Another run is in progress")).toBeVisible();
  await page.unroute("**/api/runs");
  // The browser logs the faked 409 response; it is not an error of the app.
  for (let i = consoleErrors.length - 1; i >= 0; i--) if (consoleErrors[i].includes("409 (Conflict)")) consoleErrors.splice(i, 1);
  expect(sent).toMatchObject({ path: "examples/coupon-fixed.yaml", trials: 3, copies: 6 });
});

test("lists both runs in the history", async () => {
  await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  const rows = page.getByTestId("run-row");
  await expect(rows).toHaveCount(2);
  await expect(page.locator('[data-testid="run-row"][data-scenario="coupon-vuln"]')).toContainText("VIOLATED");
  await expect(page.locator('[data-testid="run-row"][data-scenario="coupon-fixed"]')).toContainText("HELD");

  await page.getByTestId("filter-verdict").selectOption("HELD");
  await expect(rows).toHaveCount(1);
  await page.getByTestId("filter-verdict").selectOption("");
  await expect(rows).toHaveCount(2);

  // A link to a filtered history from the same document applies the filter.
  await page.evaluate(() => {
    window.location.hash = "#/runs?scenario=coupon-fixed";
  });
  await expect(rows).toHaveCount(1);
  await expect(page.getByTestId("filter-scenario")).toHaveValue("coupon-fixed");
  await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  await expect(rows).toHaveCount(2);
});

test("probes the demo shop and recommends h2", async () => {
  await page.getByRole("link", { name: "Probe", exact: true }).click();
  await page.getByTestId("probe-url").fill("https://127.0.0.1:8443/");
  await page.getByTestId("probe-insecure").check();
  await page.getByTestId("probe-submit").click();
  await expect(page.getByTestId("probe-recommended")).toHaveText("h2", { timeout: 30_000 });
  const result = page.getByTestId("probe-result");
  await expect(result).toContainText("ALPN");
  await expect(result).toContainText("TLS 1.3");
  await expect(result).toContainText("200, 200, 200");
  await expect(result).toContainText(/median \d/);
});

test("the import format picker follows the radio group pattern", async () => {
  await page.getByRole("link", { name: "Import", exact: true }).first().click();
  const group = page.getByRole("radiogroup", { name: "Format" });
  const detect = group.getByRole("radio", { name: "Detect" });
  await expect(detect).toHaveAttribute("aria-checked", "true");
  await expect(group.locator('[tabindex="0"]')).toHaveCount(1);
  await detect.focus();
  await page.keyboard.press("ArrowRight");
  const raw = group.getByRole("radio", { name: "Raw request" });
  await expect(raw).toBeFocused();
  await expect(raw).toHaveAttribute("aria-checked", "true");
  await page.keyboard.press("ArrowLeft");
  await expect(detect).toHaveAttribute("aria-checked", "true");
});

test("imports a raw request into YAML with a to-do list", async () => {
  await page.getByRole("link", { name: "Import", exact: true }).first().click();
  await page.getByTestId("import-text").fill(
    [
      "POST /vuln/api/carts/c-1/coupons HTTP/2",
      "Host: 127.0.0.1:8443",
      "Content-Type: application/json",
      "",
      '{"code":"WELCOME10"}',
    ].join("\n"),
  );
  await page.getByTestId("import-generate").click();
  await expect(page.getByTestId("import-yaml")).toContainText("race:");
  await expect(page.getByTestId("import-yaml")).toContainText("allow_hosts");
  await expect(page.getByTestId("import-todo").locator("li").first()).toBeVisible();

  await page.getByTestId("import-save").click();
  await expect(page).toHaveURL(/#\/scenario\?path=/);
  await expect(page.getByTestId("editor-title")).toHaveText(/\.yaml$/);
});

test("a new scenario is saved before it runs", async () => {
  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Scenarios" }).click();
  await page.getByTestId("new-scenario").click();
  await expect(page.getByTestId("editor-title")).toHaveText("New scenario");
  await expect(page.getByTestId("problems")).toContainText("Valid scenario");
  await expect(page.getByTestId("run")).toHaveText(/Save and run/);
  await page.getByTestId("run").click();
  await expect(page.getByTestId("save-as-confirm")).toHaveText("Save and run");
  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(page).toHaveURL(/#\/scenario$/);
});

test("after Save as, a refused navigation keeps the file in the address", async () => {
  // Still on the new scenario: make it dirty and save it under a name.
  await page.locator(".cm-content").click();
  await page.keyboard.press("Control+End");
  await page.keyboard.type("# first\n");
  await page.keyboard.press("Control+s");
  await page.getByTestId("save-path").fill("e2e-saved.yaml");
  await page.getByTestId("save-as-confirm").click();
  await expect(page).toHaveURL(/#\/scenario\?path=e2e-saved\.yaml$/);
  await page.keyboard.type("# second\n");
  await expect(page.getByTestId("dirty")).toBeVisible();

  // Leave, then keep editing: the address still names the file.
  await page.getByRole("link", { name: "Runs", exact: true }).first().click();
  await page.getByRole("button", { name: "Keep editing" }).click();
  await expect(page).toHaveURL(/#\/scenario\?path=e2e-saved\.yaml$/);

  // The first Back asks again instead of doing nothing.
  await page.goBack();
  await expect(page.getByRole("button", { name: "Keep editing" })).toBeVisible();
  await page.getByRole("button", { name: "Keep editing" }).click();
  await expect(page).toHaveURL(/#\/scenario\?path=e2e-saved\.yaml$/);

  // Saved and reloaded, the editor opens the file, not the template.
  await page.keyboard.press("Control+s");
  await expect(page.getByTestId("dirty")).toHaveCount(0);
  await page.reload();
  await expect(page.getByTestId("editor-title")).toHaveText("e2e-saved.yaml");
});

test("logged no console errors", async () => {
  expect(consoleErrors).toEqual([]);
});
