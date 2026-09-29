#!/usr/bin/env bash
# Phase 1 M-of-N quorum signing (2-of-3 KMS, ECDSA_SHA_256).
#
# Signs a file with M of N KMS keys and emits a signature bundle. Each
# signature is verified against its key before it is included, so the bundle
# always contains M valid, distinct signatures. No single key (and no single
# IAM principal) can produce a valid bundle.
set -euo pipefail

REGION="${AWS_DEFAULT_REGION:-eu-central-1}"
M="${QUORUM_M:-2}"
KEYS=("alias/conxian-release-1" "alias/conxian-release-2" "alias/conxian-release-3")

[ $# -eq 1 ] || { echo "usage: $0 <file>" >&2; exit 2; }
FILE="$1"
[ -f "$FILE" ] || { echo "no such file: $FILE" >&2; exit 2; }

DIGEST_BIN="$(mktemp)"; trap 'rm -f "$DIGEST_BIN"' EXIT
SHA="$(sha256sum "$FILE" | cut -d' ' -f1)"
openssl dgst -sha256 -binary "$FILE" > "$DIGEST_BIN"

declare -a SIGS=()
for KEY in "${KEYS[@]}"; do
  SIG="$(aws kms sign --key-id "$KEY" --message-type DIGEST --message "fileb://$DIGEST_BIN" \
    --signing-algorithm ECDSA_SHA_256 --region "$REGION" --query Signature --output text 2>/dev/null)" || continue
  OK="$(aws kms verify --key-id "$KEY" --message-type DIGEST --message "fileb://$DIGEST_BIN" \
    --signing-algorithm ECDSA_SHA_256 --signature "$SIG" --region "$REGION" --query SignatureValid --output text 2>/dev/null)"
  [ "$OK" = "True" ] || continue
  SIGS+=("$KEY:$SIG")
  [ "${#SIGS[@]}" -ge "$M" ] && break
done

[ "${#SIGS[@]}" -ge "$M" ] || { echo "quorum not reached: ${#SIGS[@]}/$M valid signatures" >&2; exit 1; }

{
  echo "file: $(basename "$FILE")"
  echo "sha256: $SHA"
  echo "algorithm: ECDSA_SHA_256"
  echo "m: $M n: ${#KEYS[@]}"
  for S in "${SIGS[@]}"; do echo "signature: $S"; done
}
