"""Builds the BENCHMARKS.md tables from the reports written by bench/run.sh.

Usage: python bench/table.py OUT > table.md
OUT/<profile>/<engine>/<scenario>.json, as written by `photofinish run --out`.
"""
import json
import pathlib
import sys

ENGINES = ["h2", "h1", "burst"]


def ms(ns):
    return "–" if ns is None else f"{ns / 1e6:.2f}"


def main(root):
    root = pathlib.Path(root)
    for profile in sorted(p for p in root.iterdir() if p.is_dir()):
        print(f"### {profile.name}\n")
        print("| Scenario | Engine | Verdict | Trials broken | Median response spread, ms | Median server arrival spread, ms |")
        print("|---|---|---|---|---|---|")
        names = sorted({f.stem for e in ENGINES for f in (profile / e).glob("*.json")})
        for name in names:
            for engine in ENGINES:
                f = profile / engine / f"{name}.json"
                if not f.exists():
                    continue
                r = json.loads(f.read_text(encoding="utf-8"))
                s = r["stats"]
                print(f"| {name} | {engine} | {r['verdict']} | {s['violated']} of {s['ran']} | "
                      f"{ms(s.get('median_response_spread_ns'))} | {ms(s.get('median_server_arrival_spread_ns'))} |")
        print()


if __name__ == "__main__":
    main(sys.argv[1])
