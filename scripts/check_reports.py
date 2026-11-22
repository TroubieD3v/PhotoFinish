#!/usr/bin/env python3
"""Checks the reports of "photofinish run" in CI.

  python scripts/check_reports.py --sarif vuln.sarif --schema sarif-schema.json --results 4 \
      --junit vuln-reports/junit.xml --suites 4 --html vuln-reports/report.html

SARIF: valid against the official 2.1.0 schema (needs the jsonschema package),
the PhotoFinish driver with rules PF001 and PF002, and exactly --results
results, every one a PF001 error with a scenario location, a start line and a
fingerprint. JUnit: well-formed, a <testsuites> root with --suites suites whose
counters match their test cases, and at least one failure in every suite. HTML:
one self-contained file that loads nothing from the network.

Exits 1 with a list of problems, 0 when everything holds.
"""

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET


def check_sarif(path, schema_path, want_results):
    problems = []
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if schema_path:
        import jsonschema

        with open(schema_path, encoding="utf-8") as f:
            schema = json.load(f)
        validator_cls = jsonschema.validators.validator_for(schema)
        validator = validator_cls(schema)
        for err in sorted(validator.iter_errors(doc), key=lambda e: list(e.path)):
            where = "/".join(str(p) for p in err.path) or "(root)"
            problems.append(f"sarif schema: {where}: {err.message}")

    if doc.get("version") != "2.1.0":
        problems.append(f"sarif: version {doc.get('version')!r}, want '2.1.0'")
    runs = doc.get("runs") or []
    if len(runs) != 1:
        return problems + [f"sarif: {len(runs)} runs, want 1"]
    run = runs[0]
    driver = run.get("tool", {}).get("driver", {})
    if driver.get("name") != "PhotoFinish":
        problems.append(f"sarif: driver name {driver.get('name')!r}, want 'PhotoFinish'")
    rule_ids = [r.get("id") for r in driver.get("rules", [])]
    for rid in ("PF001", "PF002"):
        if rid not in rule_ids:
            problems.append(f"sarif: rule {rid} missing (rules {rule_ids})")
    if "%SRCROOT%" not in run.get("originalUriBaseIds", {}):
        problems.append("sarif: originalUriBaseIds has no %SRCROOT%")

    results = run.get("results") or []
    if len(results) != want_results:
        problems.append(f"sarif: {len(results)} results, want {want_results}")
    for i, res in enumerate(results):
        label = f"sarif: result {i}"
        if res.get("ruleId") != "PF001" or res.get("level") != "error":
            problems.append(f"{label}: ruleId {res.get('ruleId')!r} level {res.get('level')!r}, want PF001 error")
        if not res.get("message", {}).get("text"):
            problems.append(f"{label}: empty message")
        locs = res.get("locations") or []
        phys = locs[0].get("physicalLocation", {}) if locs else {}
        uri = phys.get("artifactLocation", {}).get("uri", "")
        line = phys.get("region", {}).get("startLine", 0)
        if not uri.endswith(".yaml") or "\\" in uri or uri.startswith("/"):
            problems.append(f"{label}: location uri {uri!r}, want a relative scenario path with forward slashes")
        if not isinstance(line, int) or line < 1:
            problems.append(f"{label}: startLine {line!r}, want >= 1")
        fp = res.get("partialFingerprints", {}).get("photofinish/v1", "")
        if not re.fullmatch(r"[0-9a-f]{64}", fp):
            problems.append(f"{label}: fingerprint photofinish/v1 {fp!r}, want a sha256 hex digest")
    return problems


def check_junit(path, want_suites):
    problems = []
    root = ET.parse(path).getroot()
    if root.tag != "testsuites":
        return [f"junit: root <{root.tag}>, want <testsuites>"]
    if root.get("name") != "photofinish":
        problems.append(f"junit: testsuites name {root.get('name')!r}, want 'photofinish'")
    suites = root.findall("testsuite")
    if len(suites) != want_suites:
        problems.append(f"junit: {len(suites)} test suites, want {want_suites}")
    total = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    for suite in suites:
        name = suite.get("name", "?")
        cases = suite.findall("testcase")
        counts = {
            "tests": len(cases),
            "failures": sum(1 for c in cases if c.find("failure") is not None),
            "errors": sum(1 for c in cases if c.find("error") is not None),
            "skipped": sum(1 for c in cases if c.find("skipped") is not None),
        }
        for key, n in counts.items():
            total[key] += n
            if suite.get(key) is not None and int(suite.get(key)) != n:
                problems.append(f"junit: suite {name}: {key}={suite.get(key)}, but {n} test cases")
        if counts["failures"] == 0:
            problems.append(f"junit: suite {name} has no failure")
        for c in cases:
            if not c.get("classname", "").startswith("photofinish."):
                problems.append(f"junit: suite {name}: classname {c.get('classname')!r}, want photofinish.<scenario>")
                break
    for key, n in total.items():
        if root.get(key) is not None and int(root.get(key)) != n:
            problems.append(f"junit: testsuites {key}={root.get(key)}, but {n} test cases")
    return problems


# Anything that would make a browser fetch from another host when the report
# is opened: scripts, styles, images, fonts and frames with absolute URLs.
EXTERNAL = re.compile(
    r"""(?:\b(?:src|srcset|poster|data)\s*=\s*["']?\s*(?:https?:)?//)"""
    r"""|(?:<link\b[^>]*\bhref\s*=\s*["']?\s*(?:https?:)?//)"""
    r"""|(?:url\(\s*["']?\s*(?:https?:)?//)"""
    r"""|(?:@import\b)""",
    re.IGNORECASE,
)


def check_html(path):
    problems = []
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if not text.lstrip().lower().startswith("<!doctype html"):
        problems.append("html: does not start with <!doctype html>")
    m = EXTERNAL.search(text)
    if m:
        problems.append(f"html: loads an external resource near {text[max(0, m.start() - 40):m.end() + 40]!r}")
    if "<svg" not in text:
        problems.append("html: no inline SVG timeline")
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--sarif")
    ap.add_argument("--schema", help="SARIF 2.1.0 JSON schema to validate against")
    ap.add_argument("--results", type=int, default=0, help="expected number of SARIF results")
    ap.add_argument("--junit")
    ap.add_argument("--suites", type=int, default=0, help="expected number of JUnit test suites")
    ap.add_argument("--html")
    args = ap.parse_args()

    problems = []
    if args.sarif:
        problems += check_sarif(args.sarif, args.schema, args.results)
    if args.junit:
        problems += check_junit(args.junit, args.suites)
    if args.html:
        problems += check_html(args.html)
    for p in problems:
        print(p)
    if problems:
        print(f"{len(problems)} problems")
        return 1
    print("reports ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
