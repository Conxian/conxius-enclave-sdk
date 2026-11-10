# ISSUE-721: Release-ceremony countdown recomputed from public evidence (2026-11-10)

Challenge: [Conxian/conxius-enclave-sdk#721](https://github.com/Conxian/conxius-enclave-sdk/issues/721) -
"the release ceremony countdown is recomputable from public evidence alone,
`rc.N` = N validated signer proofs, no trust in Conxian required."

## Reproduction (reproducible artifact, not prose)

```bash
# free read-only GitHub token (public_repo) - only needed for the artifact download
GITHUB_TOKEN=... python3 scripts/recompute_ceremony_countdown.py --runs 3
```

The script uses no Conxian code and no third-party crypto: it pulls the
published `dkg-ceremony/latest/` evidence and independently (a) re-verifies
each aggregate signature with a pure-Python standard BIP340 verifier pinned
to the official BIP-340 test vectors, (b) inventories recorded operator-proof
claims and `*.pkg` files under `ceremony/` while failing the validated count
closed because the package bytes are not cryptographically verified, and (c) compares the aggregate public key across recent runs.

`dkg-ceremony/latest/` in R2 is not anonymously readable: an unauthenticated
GET against the `.env.example` endpoint (`https://c00b56fd07e91f358f2a512b2f23b9cf.r2.cloudflarestorage.com`)
returns HTTP 400 `InvalidArgument (Authorization)`, and no public-gateway URL
is referenced anywhere in the repo or org. The byte-identical public mirror is
the 90-day GitHub Actions artifact from `.github/workflows/dkg-ceremony.yml`
(the workflow uploads one directory to both the per-sha prefix and `latest/`),
which is what the script consumes.

## Transcript (captured 2026-11-10)

```text
source: run 42814649948 (2026-11-10T12:18:38Z) artifact 13763039199
  sha256(evidence.json) = b46696c794a04cf7dd171a6a5b4f03fbdae75d5613378dd73859763b9c129c8e
  mode=rehearsal status=PASS t=2 n=3
  aggregate pubkey x-only = 0d3984528205e9b4d61a213e033efc6166758793f3da8deab2c9dc2cc8c85b0f
  BIP340 re-verification from published fields: VERIFIED (P(published) x raw)
  operator pickup recorded: 0/0 valid
source: run 42814617052 (2026-11-10T12:18:24Z) artifact 13762944256
  sha256(evidence.json) = 4d762910e92e17f935b02737880fcd6871217bb628cf532071f0dcaed5f5af34
  mode=rehearsal status=PASS t=2 n=3
  aggregate pubkey x-only = c29cdf40b46095997a2d459a142363a16a650683e33d9ac90417b6306751dad6
  BIP340 re-verification from published fields: VERIFIED (P(published) x raw)
  operator pickup recorded: 0/0 valid
source: run 42813164268 (2026-11-10T12:08:05Z) artifact 13762742389
  sha256(evidence.json) = ff808ad4e81b2f4ac81e5a75f1f7371f51ae0b4c66f54179c326cd96bd9e1ca2
  mode=rehearsal status=PASS t=2 n=3
  aggregate pubkey x-only = 77d0796c23934dbddb70af61c36353c1fefb876680da99aeb1b55841cdf717a2
  BIP340 re-verification from published fields: VERIFIED (P(published) x raw)
  operator pickup recorded: 0/0 valid

aggregate rehearsal proofs verifiable from public fields alone: 3/3
aggregate public key across 3 sample(s): DRIFT: 0d3984528205e9b4..., 77d0796c23934dbd..., c29cdf40b4609599...
operator round packages under ceremony/: 0

RECOMPUTED rc.N = 0 validated operator signer proofs
```

## Findings

1. **Rehearsal proof is reproducible.** The `latest/evidence.json` aggregate
   signature verifies as a standard BIP340 Schnorr signature over the raw
   message bytes under the published x-only group key, with no Conxian code
   involved. The "no trust required" half of the claim holds for that proof.
2. **Counterexample - the recorded count does not match the proof set.**
   `latest/` records `status=PASS`, but `mode=rehearsal` and the recorded
   pickup is `0/0`; `ceremony/` contains no `*.pkg`. Recomputed
   `rc.N = 0` validated operator signer proofs: the PASS signature proves the
   2-of-3 code path over throwaway in-process shares, not real signer proofs.
3. **Counterexample - `latest/` pins nothing stable.** The aggregate key
   re-randomizes every CI run (distinct keys above; five distinct keys observed
   across five distinct runs on 2026-11-09/10), so there is no stable release
   signer key for a countdown to converge on until the real-operator ceremony
   (#720) completes.
4. **Public read boundary.** The R2 objects themselves require signed S3
   reads (HTTP 400 `InvalidArgument` unauthenticated); the credential-free
   mirror is the GitHub artifact, which expires after 90 days. Evidence older
   than that window is not retrievable by "public read" alone today.
5. **Pickup mechanism mismatch.** `ceremony/README.md` tells operators to
   publish `round1/pN.pkg` / `round2/pN.pkg`, but the pickup scan in
   `examples/dkg_ceremony.rs` lists only top-level `*.pkg` under
   `DKG_OPERATOR_DIR` (`std::fs::read_dir` is not recursive). If operators
   follow the README, the recorded countdown would stay `0/0` even with all
   three packages present.
6. Minor: `generated_at` records as `""` in every published artifact despite
   the workflow setting `DKG_GENERATED_AT`, so the freshness field is unusable.

## Verdict

The claim is true only for the self-generated rehearsal proof (verifiable, and
this script verifies it). For the release ceremony itself, `rc.N` recomputes to
**0** validated signer proofs from public evidence, `latest/` carries no
operator-reproducible object, and finding 5 would keep the recorded countdown
at zero even when README-conformant packages land. A counterexample object is
cited above by run/artifact id and `sha256(evidence.json)` digest.
