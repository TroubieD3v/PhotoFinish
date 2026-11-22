import { rmSync } from "node:fs";

/** Removes the temporary workspace created by playwright.config.ts. */
export default function teardown(): void {
  const dir = process.env.PF_E2E_WORKSPACE;
  if (!dir) return;
  try {
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  } catch {
    // The server may still hold a file open on Windows; the OS cleans its temp dir.
  }
}
