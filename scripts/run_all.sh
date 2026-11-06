#!/usr/bin/env bash
# The committed runs: each target with each budget, plus the max_steps demo.
# Writes runs/<run>/ with report.json, trace.jsonl, a copy of the config used,
# and exit.txt (exit status and wall time). Works with macOS's bash 3.2.
#   scripts/run_all.sh                          # all of them, in this order
#   RUNS="radicale-low owasp-full" scripts/run_all.sh
set -u
cd "$(dirname "$0")/.."
for spec in ${RUNS:-radicale-low radicale-full owasp-low owasp-full sglang-low sglang-full radicale-max-steps}; do
  case "$spec" in
    radicale-low)       input=targets/radicale;               cfg=configs/low.toml ;;
    radicale-full)      input=targets/radicale;               cfg=configs/full.toml ;;
    radicale-max-steps) input=targets/radicale;               cfg=configs/demo-max-steps.toml ;;
    owasp-low|owasp-full)
                        input=targets/owasp-benchmark-python; cfg=configs/$spec.toml ;;
    sglang-low|sglang-full)
                        input=targets/sglang;                 cfg=configs/$spec.toml ;;
    *) echo "unknown run $spec" >&2; exit 1 ;;
  esac
  out=runs/$spec
  rm -rf "$out"; mkdir -p "$out"; cp "$cfg" "$out/config.toml"
  echo "== $spec: $cfg"
  start=$(date +%s)
  uv run sio2 --input "$input" --output "$out" --config "$cfg" --quiet
  echo "exit=$? seconds=$(( $(date +%s) - start ))" | tee "$out/exit.txt"
  uv run python -m sio2.check "$out"
done
