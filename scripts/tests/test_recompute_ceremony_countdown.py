#!/usr/bin/env python3

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import recompute_ceremony_countdown as rc  # noqa: E402

# The published 'latest' evidence (dkg-ceremony/latest/evidence.json, run 42813164268)
PUBLISHED_EVIDENCE = {
    "schema": "conxian.dkg-ceremony.rehearsal.v1",
    "mode": "rehearsal",
    "generated_at": "",
    "git_sha": "f5b31499be77219600bcb64493354e20c4125d8d",
    "curve": "secp256k1-tr (RFC 9591)",
    "t": 2,
    "n": 3,
    "public_key_x_only": "77d0796c23934dbddb70af61c36353c1fefb876680da99aeb1b55841cdf717a2",
    "message": "conxian-dkg-ceremony-rehearsal",
    "signature": (
        "b5152344d55ae5706ecbd1195692bd6163de9f6d2c788dd616b7c2e098824297"
        "ee11368364368f3cd282aa29acf4585fbe42df948f2663763437483bb5cdddaa"
    ),
    "status": "PASS",
}

PUBLISHED_REHEARSAL = (
    "DKG ceremony rehearsal: 2-of-3 FROST (secp256k1-tr, RFC 9591)\n"
    "operator pickup: 0/0 package(s) valid in ceremony\n"
    "CEREMONY REHEARSAL OK\n"
)

# BIP-340 official test vectors (bitcoin/bips bip-0340/test-vectors.csv)
BIP340_VECTORS = [
    (
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
        True,
    ),
    (
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
        True,
    ),
    (
        "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
        "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
        "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
        True,
    ),
    (
        "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
        False,
    ),
    (
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
        False,
    ),
    (
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6",
        False,
    ),
]


def published_sample(pubkey: str | None = None) -> dict:
    evidence = dict(PUBLISHED_EVIDENCE)
    if pubkey:
        evidence["public_key_x_only"] = pubkey
    return {
        "label": "published-latest",
        "evidence": evidence,
        "rehearsal": PUBLISHED_REHEARSAL,
        "sha256_evidence": "",
    }


class RecomputeCeremonyCountdownTests(unittest.TestCase):
    def test_bip340_matches_official_vectors(self) -> None:
        for pubkey, msg, sig, expected in BIP340_VECTORS:
            with self.subTest(pubkey=pubkey[:12]):
                result = rc.verify_bip340(
                    bytes.fromhex(msg), bytes.fromhex(pubkey), bytes.fromhex(sig)
                )
                self.assertEqual(result, expected)

    def test_bip340_sign_and_verify_roundtrip(self) -> None:
        msg = b"countdown recompute self-test"
        pubkey_x, sig = rc.sign_bip340(msg, secret=987654321)
        self.assertTrue(rc.verify_bip340(msg, pubkey_x, sig))
        tampered = bytearray(sig)
        tampered[-1] ^= 1
        self.assertFalse(rc.verify_bip340(msg, pubkey_x, bytes(tampered)))

    def test_pickup_line_parsing(self) -> None:
        self.assertEqual(rc.pickup_counts(PUBLISHED_REHEARSAL), (0, 0))
        self.assertEqual(
            rc.pickup_counts("operator pickup: 2/3 package(s) valid in ceremony"),
            (2, 3),
        )
        self.assertIsNone(rc.pickup_counts("no pickup line"))

    def test_published_signature_verifies_as_plain_bip340(self) -> None:
        # The frost-secp256k1-tr aggregate verifies as standard BIP340 over the
        # raw message bytes under the untweaked x-only group key.
        self.assertEqual(rc.verify_variants(PUBLISHED_EVIDENCE), ["P(published) x raw"])

    def test_recount_on_latest_evidence_is_zero(self) -> None:
        result = rc.recount([published_sample()], packages_in_repo=0)
        self.assertEqual(result["rc_n"], 0)
        self.assertEqual(result["operator_proofs_recorded"], (0, 0))
        self.assertEqual(result["aggregate_proofs_verifiable"], 1)
        self.assertFalse(result["aggregate_key_drift"])
        self.assertEqual(result["modes"], ["rehearsal"])

    def test_recount_detects_aggregate_key_drift(self) -> None:
        other = "beadd504d9fd842a86596b76a59c22625657e7705bd6cc7cbc5fcc7db1f4241a"
        result = rc.recount(
            [published_sample(), published_sample(other)], packages_in_repo=0
        )
        self.assertTrue(result["aggregate_key_drift"])
        self.assertEqual(len(result["distinct_aggregate_pubkeys"]), 2)

    def test_recount_does_not_treat_claims_and_filenames_as_validated_proofs(self) -> None:
        sample = published_sample()
        sample["rehearsal"] = "operator pickup: 3/3 package(s) valid in ceremony\n"
        result = rc.recount([sample], packages_in_repo=3)
        self.assertEqual(result["rc_n"], 0)
        self.assertEqual(result["operator_proofs_recorded"], (3, 3))
        self.assertEqual(result["packages_in_ceremony_dir"], 3)
        self.assertEqual(result["operator_package_validation"], "unavailable")

    def test_repo_package_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "round1").mkdir()
            (root / "round1" / "p1.pkg").write_bytes(b"x")
            (root / "README.md").write_text("not a package")
            self.assertEqual(rc.repo_package_count(root), 1)
            self.assertEqual(rc.repo_package_count(root / "missing"), 0)


if __name__ == "__main__":
    unittest.main()
