#!/usr/bin/env python3
"""Recompute the release-ceremony countdown (`rc.N`) from public evidence (#721).

Claim under test: the ceremony countdown is recomputable from public evidence
alone - `rc.N` = N validated signer proofs - with no trust in Conxian.

Where the published `dkg-ceremony/latest/` objects are readable:
  - R2 (`s3://conxian-wasm-runtime`, endpoint in `.env.example`) only answers
    signed reads; an unauthenticated GET returns HTTP 400 `InvalidArgument
    (Authorization)`. No anonymous public-gateway URL is referenced anywhere
    in the repo or org.
  - The byte-identical mirror of `latest/` is the 90-day GitHub Actions build
    artifact `dkg-ceremony-evidence-<sha>` published by
    `.github/workflows/dkg-ceremony.yml`: the workflow uploads one directory
    (`evidence.json` + `rehearsal.txt`) to both the per-sha and `latest/` R2
    prefixes, so the artifact holds exactly the same bytes.

This script fetches that evidence with public read only (downloading an
artifact needs a free GitHub token: set GITHUB_TOKEN), then independently:
  1. counts real operator signer proofs - round packages recorded in
     `rehearsal.txt` ("operator pickup: X/Y") and present under `ceremony/`;
  2. re-verifies every published aggregate signature from the fields of
     `evidence.json` alone, using a pure-Python standard BIP340 check over
     secp256k1 (the frost-secp256k1-tr variant verifies as plain BIP340 over
     the raw message bytes under the untweaked x-only group key);
  3. compares the aggregate public key across recent runs for drift.

Prints a transcript and the recomputed `rc.N`. Exit codes: 0 = recompute done
(counterexamples are reported as findings, not failures), 1 = evidence could
not be fetched.

Usage:
  python3 scripts/recompute_ceremony_countdown.py [--runs N]
  python3 scripts/recompute_ceremony_countdown.py --evidence-dir DIR
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import sys
import urllib.request
import zipfile
from pathlib import Path

REPO = "Conxian/conxius-enclave-sdk"
WORKFLOW = "dkg-ceremony.yml"
API = "https://api.github.com"
REPO_ROOT = Path(__file__).resolve().parents[1]

# secp256k1 / BIP340 curve parameters
P_CURVE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G_POINT = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _get(url: str, token: str | None = None) -> tuple[int, bytes]:
    """GET a URL; follow one redirect without leaking the token off-host."""

    def build(target: str, with_token: bool) -> urllib.request.Request:
        req = urllib.request.Request(target, headers={"User-Agent": "dspaid-solver"})
        if with_token and token:
            req.add_header("Authorization", f"Bearer {token}")
        return req

    class _StopAt3xx(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            return None

    opener = urllib.request.build_opener(_StopAt3xx)
    try:
        with opener.open(build(url, True), timeout=60) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        location = err.headers.get("Location")
        if err.code in (301, 302, 303, 307, 308) and location:
            with urllib.request.urlopen(build(location, False), timeout=60) as blob:
                return blob.status, blob.read()
        return err.code, err.read()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── pure-Python BIP340 verification over secp256k1 ───────────────────

def _tagged(tag: str, data: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def _point_add(p1: tuple | None, p2: tuple | None) -> tuple | None:
    if p1 is None:
        return p2
    if p2 is None or (p1[0] == p2[0] and (p1[1] + p2[1]) % P_CURVE == 0):
        return None
    if p1 == p2:
        lam = 3 * p1[0] * p1[0] * pow(2 * p1[1], P_CURVE - 2, P_CURVE) % P_CURVE
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], P_CURVE - 2, P_CURVE) % P_CURVE
    x = (lam * lam - p1[0] - p2[0]) % P_CURVE
    return (x, (lam * (p1[0] - x) - p1[1]) % P_CURVE)


def _point_mul(k: int, point: tuple) -> tuple | None:
    acc, cur = None, point
    while k:
        if k & 1:
            acc = _point_add(acc, cur)
        cur = _point_add(cur, cur)
        k >>= 1
    return acc


def _lift_x(x: int, even_y: bool = True) -> tuple | None:
    if x >= P_CURVE:
        return None
    y_sq = (pow(x, 3, P_CURVE) + 7) % P_CURVE
    y = pow(y_sq, (P_CURVE + 1) // 4, P_CURVE)
    if pow(y, 2, P_CURVE) != y_sq:
        return None
    if (y % 2 == 0) != even_y:
        y = P_CURVE - y
    return (x, y)


def verify_bip340(msg: bytes, pubkey_x: bytes, sig: bytes) -> bool:
    """Standard BIP340 check: R = sG - eQ must match r with even Y."""
    r_int, s_int = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (0 < s_int < N_ORDER) or r_int >= P_CURVE:
        return False
    q_point = _lift_x(int.from_bytes(pubkey_x, "big"))
    if q_point is None:
        return False
    e_int = int.from_bytes(
        _tagged("BIP0340/challenge", sig[:32] + pubkey_x + msg), "big"
    ) % N_ORDER
    r_point = _point_add(
        _point_mul(s_int, G_POINT), _point_mul((N_ORDER - e_int) % N_ORDER, q_point)
    )
    return r_point is not None and r_point[0] == r_int and r_point[1] % 2 == 0


def sign_bip340(msg: bytes, secret: int) -> tuple[bytes, bytes]:
    """Minimal BIP340 sign (self-test helper); returns (pubkey_x, sig)."""
    d = secret % N_ORDER
    pub = _point_mul(d, G_POINT)
    assert pub is not None
    if pub[1] % 2:
        d = N_ORDER - d
    k = 12345
    while True:
        r_point = _point_mul(k, G_POINT)
        assert r_point is not None
        if r_point[1] % 2 == 0:
            break
        k += 1
    e_int = int.from_bytes(
        _tagged(
            "BIP0340/challenge",
            r_point[0].to_bytes(32, "big") + pub[0].to_bytes(32, "big") + msg,
        ),
        "big",
    ) % N_ORDER
    s = (k + e_int * d) % N_ORDER
    sig = r_point[0].to_bytes(32, "big") + s.to_bytes(32, "big")
    return pub[0].to_bytes(32, "big"), sig


def verify_variants(evidence: dict) -> list[str]:
    """Names of key/message variants under which the published sig verifies.

    frost-secp256k1-tr builds its challenge as H2(R.x || P.x || m); empirically
    `m` is the raw message bytes, so the aggregate signature verifies as a
    standard BIP340 signature under the untweaked x-only group key. The
    tweaked-Q branch (BIP341 reading) is tried as well and must be reported.
    """
    pkx = bytes.fromhex(evidence["public_key_x_only"])
    sig = bytes.fromhex(evidence["signature"])
    message = evidence["message"].encode()
    p_point = _lift_x(int.from_bytes(pkx, "big"))
    keys = {"P(published)": p_point}
    if p_point is not None:
        tweak = int.from_bytes(_tagged("TapTweak", pkx), "big") % N_ORDER
        keys["Q(tweaked)"] = _point_add(p_point, _point_mul(tweak, G_POINT))
    messages = {"raw": message, "sha256(msg)": hashlib.sha256(message).digest()}
    verified = []
    for key_name, key_point in keys.items():
        if key_point is None:
            continue
        key_x = key_point[0].to_bytes(32, "big")
        for msg_name, msg_bytes in messages.items():
            if verify_bip340(msg_bytes, key_x, sig):
                verified.append(f"{key_name} x {msg_name}")
    return verified


# ── evidence acquisition ──────────────────────────────────────────────

def fetch_samples(runs: int, token: str | None) -> list[dict]:
    """Download the last `runs` successful ceremony-evidence artifacts."""
    status, body = _get(
        f"{API}/repos/{REPO}/actions/workflows/{WORKFLOW}/runs?per_page=20", token
    )
    if status != 200:
        raise RuntimeError(f"workflow runs listing failed: HTTP {status}")
    samples = []
    for run in json.loads(body)["workflow_runs"]:
        if len(samples) >= runs:
            break
        if run["status"] != "completed" or run["conclusion"] != "success":
            continue
        status, body = _get(run["artifacts_url"], token)
        if status != 200:
            continue
        for artifact in json.loads(body)["artifacts"]:
            if not artifact["name"].startswith("dkg-ceremony-evidence-"):
                continue
            status, blob = _get(artifact["archive_download_url"], token)
            if status != 200:
                raise RuntimeError(
                    f"artifact download failed: HTTP {status}; set GITHUB_TOKEN "
                    "to a free read-only GitHub token (public_repo)"
                )
            zf = zipfile.ZipFile(io.BytesIO(blob))
            evidence_raw = zf.read("evidence.json")
            samples.append(
                {
                    "label": f"run {run['id']} ({run['created_at']}) artifact {artifact['id']}",
                    "evidence": json.loads(evidence_raw),
                    "rehearsal": zf.read("rehearsal.txt").decode(),
                    "sha256_evidence": sha256_hex(evidence_raw),
                }
            )
            break
    if not samples:
        raise RuntimeError("no ceremony evidence artifacts found")
    return samples


def sample_from_dir(directory: Path) -> dict:
    evidence_raw = (directory / "evidence.json").read_bytes()
    rehearsal_path = directory / "rehearsal.txt"
    return {
        "label": f"local dir {directory}",
        "evidence": json.loads(evidence_raw),
        "rehearsal": rehearsal_path.read_text() if rehearsal_path.exists() else "",
        "sha256_evidence": sha256_hex(evidence_raw),
    }


# ── recompute ─────────────────────────────────────────────────────────

def pickup_counts(rehearsal: str) -> tuple[int, int] | None:
    """Parse the recorded 'operator pickup: X/Y package(s) valid' line."""
    match = re.search(r"operator pickup: (\d+)/(\d+) package", rehearsal)
    return (int(match.group(1)), int(match.group(2))) if match else None


def repo_package_count(ceremony_dir: Path) -> int:
    return len(sorted(ceremony_dir.rglob("*.pkg"))) if ceremony_dir.is_dir() else 0


def recount(samples: list[dict], packages_in_repo: int) -> dict:
    """Recompute the countdown from published evidence; no Conxian code used.

    `rc_n` counts validated signer proofs from real operators: the recorded
    pickup count, corroborated by the round packages actually present under
    ceremony/. The rehearsal aggregate signature is counted separately - it is
    one verifiable threshold proof per run, but over ephemeral local shares,
    not operator shares.
    """
    latest = samples[0]
    recorded = pickup_counts(latest.get("rehearsal", ""))
    verifiable = sum(1 for s in samples if verify_variants(s["evidence"]))
    pubkeys = [s["evidence"]["public_key_x_only"] for s in samples]
    return {
        "rc_n": min(recorded[0], packages_in_repo) if recorded else packages_in_repo,
        "operator_proofs_recorded": recorded,
        "packages_in_ceremony_dir": packages_in_repo,
        "aggregate_proofs_verifiable": verifiable,
        "samples": len(samples),
        "distinct_aggregate_pubkeys": sorted(set(pubkeys)),
        "aggregate_key_drift": len(set(pubkeys)) > 1,
        "modes": sorted({s["evidence"].get("mode", "?") for s in samples}),
        "statuses": sorted({s["evidence"].get("status", "?") for s in samples}),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=3, help="recent runs to compare")
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="local dir with evidence.json (+rehearsal.txt); skips the network",
    )
    parser.add_argument(
        "--ceremony-dir",
        type=Path,
        default=REPO_ROOT / "ceremony",
        help="ceremony/ directory of a repo checkout (counts *.pkg)",
    )
    args = parser.parse_args(argv)

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_PAT")
    try:
        samples = (
            [sample_from_dir(args.evidence_dir)]
            if args.evidence_dir
            else fetch_samples(args.runs, token)
        )
    except (RuntimeError, OSError, KeyError, zipfile.BadZipFile) as err:
        print(f"ERROR: {err}", file=sys.stderr)
        return 1

    for sample in samples:
        evidence = sample["evidence"]
        variants = verify_variants(evidence)
        print(f"source: {sample['label']}")
        print(f"  sha256(evidence.json) = {sample['sha256_evidence']}")
        print(
            f"  mode={evidence.get('mode')} status={evidence.get('status')} "
            f"t={evidence.get('t')} n={evidence.get('n')}"
        )
        print(f"  aggregate pubkey x-only = {evidence['public_key_x_only']}")
        print(
            f"  BIP340 re-verification from published fields: "
            f"{'VERIFIED (' + ', '.join(variants) + ')' if variants else 'FAILED'}"
        )
        recorded = pickup_counts(sample.get("rehearsal", ""))
        if recorded:
            print(f"  operator pickup recorded: {recorded[0]}/{recorded[1]} valid")

    result = recount(samples, repo_package_count(args.ceremony_dir))
    print()
    print(
        f"aggregate rehearsal proofs verifiable from public fields alone: "
        f"{result['aggregate_proofs_verifiable']}/{len(samples)}"
    )
    drift = "DRIFT:" if result["aggregate_key_drift"] else "stable"
    print(
        f"aggregate public key across {len(samples)} sample(s): {drift} "
        f"{', '.join(k[:16] + '...' for k in result['distinct_aggregate_pubkeys'])}"
    )
    print(f"operator round packages under ceremony/: {result['packages_in_ceremony_dir']}")
    print()
    print(f"RECOMPUTED rc.N = {result['rc_n']} validated operator signer proofs")

    if result["statuses"] == ["PASS"] and result["rc_n"] == 0:
        print(
            "COUNTEREXAMPLE: latest/ records status=PASS while the recomputed "
            "validated-operator-signer-proof count is 0 - the only evidence is a "
            "self-generated rehearsal (mode=rehearsal), verifiable but over "
            "throwaway local shares, with no real operator round packages."
        )
    if result["aggregate_key_drift"]:
        print(
            "COUNTEREXAMPLE: the 'latest' aggregate key re-randomizes every CI "
            "run, so it pins no stable release signer key to countdown toward."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
