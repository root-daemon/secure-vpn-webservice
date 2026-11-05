#!/usr/bin/env bash
# Builds build/bundle: application code + an offline wheelhouse for Amazon
# Linux 2023 (CPython 3.9, x86_64). The instance has no internet access, so
# every Python dependency ships inside the bundle.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/build/bundle"
PYTHON="${PYTHON:-python3}"

rm -rf "$OUT"
mkdir -p "$OUT/wheels"

cp -R "$ROOT/app/vault" "$ROOT/app/deploy" "$ROOT/app/wsgi.py" "$ROOT/app/requirements.lock" "$OUT/"
find "$OUT" -name '__pycache__' -type d -prune -exec rm -rf {} +

# Browser UI: static files built on this machine (the instance has no Node
# and no internet). npm ci keeps the build reproducible from package-lock.json.
command -v npm >/dev/null || { echo "[bundle] npm not found; install Node.js 20+" >&2; exit 1; }
(cd "$ROOT/fe" && npm ci --no-audit --no-fund --silent && npm run build --silent)
cp -R "$ROOT/fe/dist" "$OUT/fe"

"$PYTHON" -m pip --version >/dev/null 2>&1 || { echo "[bundle] $PYTHON has no pip; set PYTHON=/path/to/python3" >&2; exit 1; }

# --no-deps + a full lock file: pip evaluates dependency markers against the
# build machine's Python, not the target's 3.9, so we never let it resolve.
"$PYTHON" -m pip download --quiet --disable-pip-version-check \
  --dest "$OUT/wheels" \
  --no-deps \
  --only-binary=:all: \
  --implementation cp \
  --python-version 3.9 \
  --platform manylinux2014_x86_64 \
  --platform manylinux_2_17_x86_64 \
  -r "$ROOT/app/requirements.lock"

# Fixed timestamps keep the zip (and so the instance) stable across rebuilds.
find "$OUT" -exec touch -h -t 202001010000 {} +

echo "[bundle] $(find "$OUT/wheels" -name '*.whl' | wc -l | tr -d ' ') wheels, $(find "$OUT/fe" -type f | wc -l | tr -d ' ') UI files, ready at $OUT"
