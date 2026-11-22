#!/usr/bin/env bash
# Runs every demo scenario with every engine and writes the JSON reports to
# OUT/<profile>/<engine>/. The demo shop must already be listening on
# 127.0.0.1:8443. Usage: bench/run.sh BIN OUT PROFILE [TRIALS]
set -euo pipefail

bin=$1 out=$2 profile=$3 trials=${4:-30}

for engine in h2 h1 burst; do
  dir="$out/$profile/$engine"
  mkdir -p "$dir"
  for f in examples/*.yaml; do
    # Exit codes 1 (VIOLATED) and 2 (INCONCLUSIVE) are results, not failures.
    rc=0
    "$bin" run "$f" --engine "$engine" --trials "$trials" --out "$dir" --quiet >/dev/null || rc=$?
    if [ "$rc" -ge 3 ]; then
      echo "error: $f with $engine exited $rc" >&2
      exit 1
    fi
    echo "$profile $engine $(basename "$f" .yaml) exit $rc"
  done
done
