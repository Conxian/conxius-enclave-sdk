#!/usr/bin/env bash
# Build the Conxian Nitro enclave image (EIF) and emit its PCR measurements.
#
# Part of the #242 provision-nitro attestation pipeline. Produces:
#   .nitro/enclave.eif          — the enclave image file
#   .nitro/pcrs.json            — {"0":"<hex48>","1":"...","2":"...","8":"..."}
#
# The parent instance later pins these exact PCRs and verifies the runtime
# attestation document against them (fail-closed via examples/nitro_attest_verify.rs).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="$ROOT/.nitro"
ENCLAVE_DIR="$ROOT/scripts/nitro/enclave"
IMAGE="conxian-nitro-attestation-probe"

mkdir -p "$OUT_DIR"

echo "==> building enclave app docker image ($IMAGE)"
docker build -t "$IMAGE:latest" "$ENCLAVE_DIR"

echo "==> building EIF with nitro-cli"
nitro-cli build-enclave \
  --docker-uri "$IMAGE:latest" \
  --output-file "$OUT_DIR/enclave.eif"

echo "==> capturing EIF PCR measurements"
# `describe-eif` prints a JSON document with PCR0/PCR1/PCR2/PCR8 (SHA384).
nitro-cli describe-eif --eif-path "$OUT_DIR/enclave.eif" > "$OUT_DIR/eif-description.json"

python3 - <<'PY'
import json, pathlib
out = pathlib.Path(".nitro")
desc = json.loads((out / "eif-description.json").read_text())
# Normalize to the exact "index" -> "hex48" map the verifier expects.
# describe-eif emits measurements under either "Measurements" or top-level keys.
raw = desc.get("Measurements", desc)
pcrs = {}
for key, value in raw.items():
    k = key.upper()
    if k.startswith("PCR"):
        idx = int(key[3:])
        pcrs[str(idx)] = str(value).replace("0x", "").replace("0X", "").strip().lower()
(out / "pcrs.json").write_text(json.dumps(pcrs, indent=2))
print("wrote .nitro/pcrs.json:", json.dumps(pcrs, indent=2))
PY
