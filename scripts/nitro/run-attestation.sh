#!/usr/bin/env bash
# Provision a Nitro enclave instance, run the attestation probe, capture the
# attestation document over vsock, and tear the instance down.
#
# This is the "request + capture" half of the #242 pipeline. Verification is a
# separate, offline step (cargo run --example nitro_attest_verify) so the
# instance can be terminated as soon as the document is captured.
#
# Capture path: the probe (inside the enclave) connects out to the parent over
# vsock and returns the document on that socket. `nitro-cli run-enclave` does
# NOT print the enclave's stdout, and the enclave console is only readable in
# `--debug-mode` — which zeroes the PCRs and therefore cannot produce
# production evidence. So the document must travel over vsock, and the enclave
# must NOT be launched in debug mode.
#
# Environment (expected to be scoped to conxian-sdk-signer, NOT the account root):
#   AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_DEFAULT_REGION
#   NITRO_AMI           — Nitro-capable AMI (Amazon Linux 2 or Ubuntu + nitro)
#   NITRO_SUBNET_ID     — subnet for the instance
#   NITRO_KEY_NAME      — EC2 key-pair name (must pre-exist)
#   NITRO_SG_ID         — security group id (allow SSH + vsock)
#   NITRO_INSTANCE_PROFILE — IAM instance profile name (conxian-nitro-enclave-profile)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="$ROOT/.nitro"
INSTANCE_TYPE="${INSTANCE_TYPE:-m5.xlarge}"
VSOCK_PORT="${VSOCK_PORT:-5005}"
CAPTURE_TIMEOUT="${CAPTURE_TIMEOUT:-120}"

: "${NITRO_AMI:?set NITRO_AMI}"
: "${NITRO_SUBNET_ID:?set NITRO_SUBNET_ID}"
: "${NITRO_KEY_NAME:?set NITRO_KEY_NAME}"
: "${NITRO_SG_ID:?set NITRO_SG_ID}"
: "${NITRO_INSTANCE_PROFILE:?set NITRO_INSTANCE_PROFILE}"

mkdir -p "$OUT_DIR"

# Parent-chosen nonce binds freshness; written before capture so the request
# document and the captured attestation document agree on it.
if [[ ! -f "$OUT_DIR/nonce.hex" ]]; then
  python3 -c 'import secrets;print(secrets.token_hex(32))' > "$OUT_DIR/nonce.hex"
fi

INSTANCE_ID=""
cleanup() {
  if [[ -n "$INSTANCE_ID" ]]; then
    echo "==> tearing down instance $INSTANCE_ID"
    aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" >/dev/null || true
  fi
}
trap cleanup EXIT

echo "==> launching Nitro enclave instance"
launch_json="$(aws ec2 run-instances \
  --image-id "$NITRO_AMI" \
  --instance-type "$INSTANCE_TYPE" \
  --subnet-id "$NITRO_SUBNET_ID" \
  --key-name "$NITRO_KEY_NAME" \
  --security-group-ids "$NITRO_SG_ID" \
  --iam-instance-profile "Name=$NITRO_INSTANCE_PROFILE" \
  --enclave-options 'Enabled=true' \
  --tag-specifications "ResourceType=instance,Tags=[{Key=conxian:role,Value=nitro-enclave}]" \
  --min-count 1 --max-count 1 \
  --output json)"
INSTANCE_ID="$(echo "$launch_json" | python3 -c 'import sys,json;print(json.load(sys.stdin)["Instances"][0]["InstanceId"])')"
echo "    instance: $INSTANCE_ID"

echo "==> waiting for running"
aws ec2 wait instance-running --instance-ids "$INSTANCE_ID"

PUBLIC_IP="$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)"
SSH=(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "ec2-user@$PUBLIC_IP")
SCP=(scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

echo "==> uploading EIF, capture client, and nonce to $PUBLIC_IP"
"${SCP[@]}" "$OUT_DIR/enclave.eif" "ec2-user@$PUBLIC_IP:/tmp/enclave.eif"
"${SCP[@]}" "$ROOT/scripts/nitro/vsock-capture.py" "ec2-user@$PUBLIC_IP:/tmp/vsock-capture.py"
"${SCP[@]}" "$OUT_DIR/nonce.hex" "ec2-user@$PUBLIC_IP:/tmp/nonce.hex"

# Optional inputs: user_data (e.g. the release-binding digest) and the
# recipient public key. Absent files are simply not forwarded.
USER_DATA_ARG=""
if [[ -f "$OUT_DIR/user-data.bin" ]]; then
  "${SCP[@]}" "$OUT_DIR/user-data.bin" "ec2-user@$PUBLIC_IP:/tmp/user-data.bin"
  USER_DATA_ARG="/tmp/user-data.bin"
fi
PUBKEY_ARG=""
if [[ -f "$OUT_DIR/recipient-public-key.bin" ]]; then
  "${SCP[@]}" "$OUT_DIR/recipient-public-key.bin" "ec2-user@$PUBLIC_IP:/tmp/recipient-public-key.bin"
  PUBKEY_ARG="/tmp/recipient-public-key.bin"
fi

echo "==> starting parent-side vsock listener"
"${SSH[@]}" "sudo nohup python3 /tmp/vsock-capture.py /tmp/attestation.b64 $VSOCK_PORT $CAPTURE_TIMEOUT '${USER_DATA_ARG}' /tmp/nonce.hex '${PUBKEY_ARG}' > /tmp/capture.log 2>&1 & echo started"

# Production mode: NOT --debug-mode, so the PCRs are real.
echo "==> running enclave (production mode; document returns over vsock)"
"${SSH[@]}" "sudo nitro-cli run-enclave --eif-path /tmp/enclave.eif --cpu-count 2 --memory 512"

echo "==> waiting for attestation capture"
"${SSH[@]}" "for i in \$(seq 1 $CAPTURE_TIMEOUT); do [ -s /tmp/attestation.b64 ] && break; sleep 1; done; cat /tmp/capture.log >&2; test -s /tmp/attestation.b64"

echo "==> retrieving attestation document"
"${SCP[@]}" "ec2-user@$PUBLIC_IP:/tmp/attestation.b64" "$OUT_DIR/attestation.b64"

echo "==> writing attestation document + verification request"
python3 - "$OUT_DIR" <<'PY'
import base64, json, pathlib, sys
out = pathlib.Path(sys.argv[1])
b64 = (out / "attestation.b64").read_text().strip()
(out / "attestation.cbor").write_bytes(base64.b64decode(b64))
pcrs = json.loads((out / "pcrs.json").read_text())
request = {
    "attestation_document_path": str(out / "attestation.cbor"),
    # module_id is discovered from the document; verification can pin it via
    # this optional field once the expected module_id is known for the release.
    "module_id": None,
    "nonce": (out / "nonce.hex").read_text().strip() if (out / "nonce.hex").exists() else "",
    "recipient_public_key_hash": (out / "recipient-key-hash.hex").read_text().strip(),
    "operation_digest": (out / "operation-digest.hex").read_text().strip(),
    "purpose": "KMS_RELEASE",
    "kms_key_identifier_hash": (out / "kms-key-hash.hex").read_text().strip(),
    "policy_version": 1,
    "policy_digest": (out / "policy-digest.hex").read_text().strip(),
    "expires_at_ms": int((out / "expires-at-ms.txt").read_text().strip()),
    "replay_identity": (out / "replay-identity.hex").read_text().strip(),
    "pcrs": [{"index": int(k), "value": v} for k, v in sorted(pcrs.items(), key=lambda kv: int(kv[0]))],
}
(out / "request.json").write_text(json.dumps(request, indent=2))
print("wrote .nitro/request.json")
PY

echo "DONE — attestation document captured; instance will be torn down on exit"
