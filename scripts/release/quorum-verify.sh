#!/usr/bin/env bash
# Verify an M-of-N quorum signature bundle produced by quorum-sign.sh.
# Fails closed unless >= M signatures verify against the file's digest and the
# bundle digest matches the file digest.
set -euo pipefail

REGION="${AWS_DEFAULT_REGION:-eu-central-1}"
M="${QUORUM_M:-2}"

[ $# -eq 2 ] || { echo "usage: $0 <file> <bundle>" >&2; exit 2; }
FILE="$1"; BUNDLE="$2"
[ -f "$FILE" ] || { echo "no such file: $FILE" >&2; exit 2; }
[ -f "$BUNDLE" ] || { echo "no such bundle: $BUNDLE" >&2; exit 2; }

DIGEST_BIN="$(mktemp)"; trap 'rm -f "$DIGEST_BIN"' EXIT
sha256sum "$FILE" | cut -d' ' -f1 | xxd -r -p > "$DIGEST_BIN"
SHA="$(sha256sum "$FILE" | cut -d' ' -f1)"

BUNDLE_SHA="$(awk '/^sha256:/{print $2}' "$BUNDLE")"
[ "$SHA" = "$BUNDLE_SHA" ] || { echo "digest mismatch: bundle=$BUNDLE_SHA file=$SHA" >&2; exit 1; }

COUNT=0
while IFS= read -r line; do
  case "$line" in
    signature:*) PAIR="${line#signature: }"; KEY="${PAIR%%:*}"; SIG="${PAIR#*:}";;
    *) continue;;
  esac
  OK="$(aws kms verify --key-id "$KEY" --message-type DIGEST --message "fileb://$DIGEST_BIN" \
    --signing-algorithm ECDSA_SHA_256 --signature "$SIG" --region "$REGION" --query SignatureValid --output text 2>/dev/null)"
  [ "$OK" = "True" ] && COUNT=$((COUNT+1))
done < "$BUNDLE"

[ "$COUNT" -ge "$M" ] || { echo "quorum verify failed: $COUNT/$M valid signatures" >&2; exit 1; }
echo "quorum verified: $COUNT/$M valid signatures"
