#!/usr/bin/env bash
# Run every benchmark and write JSON results to benchmark/results/<name>/.
#   benchmark/run_all.sh <name> <cassettes-dir> [gretel-cache]
# Presidio runs need presidio-analyzer and en_core_web_lg in the same environment.
set -euo pipefail
cd "$(dirname "$0")"
name=$1 cassettes=$2 gretel=${3:-data/gretel}
out=results/$name
mkdir -p "$out"
py=${PYTHON:-python}

$py evaluate.py dev --json "$out/synthetic-dev.json" > /dev/null
$py evaluate.py test --json "$out/synthetic-test.json" > /dev/null
$py evaluate.py test --shared --json "$out/synthetic-test-shared.json" > /dev/null
$py evaluate.py test --shared --engine presidio --json "$out/synthetic-test-shared-presidio.json" > /dev/null
$py gretel.py --cache "$gretel" --json "$out/gretel-medium.json" > /dev/null
$py gretel.py --cache "$gretel" --floor low --json "$out/gretel-low.json" > /dev/null
$py gretel.py --cache "$gretel" --engine presidio --json "$out/gretel-presidio.json" > /dev/null
$py cassettes.py "$cassettes" --json "$out/cassettes.json" --out "$out/cassettes-findings.jsonl" > /dev/null
echo "wrote $out"
