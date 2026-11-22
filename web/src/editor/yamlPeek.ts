// A few scenario fields read straight from the YAML text, for the parts of
// the editor summary that the validate route may not report (scope and
// tls.insecure). The server stays the authority on what the file means;
// this only fills in the summary and decides whether to offer --insecure.

/** Fields read from the YAML text. */
export interface Peek {
  name: string;
  insecure: boolean;
  allowHosts: string[];
  budgetRequests: number;
  budgetRps: number;
}

function stripComment(line: string): string {
  // Drop "# comment" outside quotes.
  let quote = "";
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === quote) quote = "";
    } else if (c === '"' || c === "'") quote = c;
    else if (c === "#" && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i);
  }
  return line;
}

function unquote(s: string): string {
  const v = s.trim();
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) return v.slice(1, -1);
  return v;
}

/** Returns the lines of the top-level block key (its own line included), comments removed. */
function block(lines: string[], key: string): string[] {
  const start = lines.findIndex((l) => new RegExp(`^${key}\\s*:`).test(l));
  if (start < 0) return [];
  const out = [lines[start]];
  for (let i = start + 1; i < lines.length; i++) {
    const l = lines[i];
    if (l.trim() === "") continue;
    if (!/^\s/.test(l)) break;
    out.push(l);
  }
  return out;
}

function flowList(s: string): string[] {
  const m = /\[([^\]]*)\]/.exec(s);
  if (!m) return [];
  return m[1]
    .split(",")
    .map(unquote)
    .filter((x) => x !== "");
}

/** Reads name, tls.insecure, scope.allow_hosts and scope.budget from scenario YAML. */
export function peekYaml(text: string): Peek {
  const lines = text.split(/\r?\n/).map(stripComment);
  const peek: Peek = { name: "", insecure: false, allowHosts: [], budgetRequests: 0, budgetRps: 0 };

  const name = lines.find((l) => /^name\s*:/.test(l));
  if (name) peek.name = unquote(name.replace(/^name\s*:/, ""));

  const tls = block(lines, "tls").join("\n");
  peek.insecure = /\binsecure\s*:\s*(true|yes|on)\b/i.test(tls);

  const scope = block(lines, "scope");
  for (let i = 0; i < scope.length; i++) {
    const l = scope[i];
    if (/\ballow_hosts\s*:/.test(l)) {
      const rest = l.slice(l.indexOf("allow_hosts") + "allow_hosts".length).replace(/^\s*:/, "");
      if (rest.includes("[")) peek.allowHosts = flowList(rest);
      else {
        const indent = /^\s*/.exec(l)?.[0].length ?? 0;
        for (let j = i + 1; j < scope.length; j++) {
          const item = /^(\s*)-\s*(.+)$/.exec(scope[j]);
          if (!item || item[1].length < indent) break;
          peek.allowHosts.push(unquote(item[2]));
        }
      }
    }
    const req = /\brequests\s*:\s*(\d+)/.exec(l);
    if (req && /budget|^\s{4,}|\{/.test(l)) peek.budgetRequests = Number(req[1]);
    const rps = /\brps\s*:\s*([\d.]+)/.exec(l);
    if (rps) peek.budgetRps = Number(rps[1]);
  }
  return peek;
}

/** Suggests a workspace file path for a scenario name: "coupon-applied-twice.yaml". */
export function suggestPath(name: string, fallback = "scenario"): string {
  const base =
    name
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, "-")
      .replace(/^-+|-+$/g, "") || fallback;
  return `${base}.yaml`;
}

/** Checks a workspace path the way the server does; returns a problem or "". */
export function pathProblem(path: string): string {
  const p = path.trim();
  if (!p) return "Enter a file name.";
  if (p.startsWith("/") || /^[A-Za-z]:/.test(p) || p.includes("\\")) return "Use a relative path with forward slashes.";
  if (p.split("/").some((s) => s === ".." || s === "." || s === "")) return "The path must stay inside the workspace.";
  if (!/\.ya?ml$/i.test(p)) return "Scenario files end in .yaml or .yml.";
  return "";
}
