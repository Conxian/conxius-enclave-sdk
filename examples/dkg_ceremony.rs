//! DKG ceremony rehearsal (2-of-3 FROST, RFC 9591).
//!
//! Runs the full three-round distributed key generation with three local
//! participants — a rehearsal of the `conxian-release` ceremony (Share 1 =
//! Conxian infra/Nitro, Share 2 = owner, Share 3 = co-signer) — verifying each
//! round package, confirming every participant derives the same public key,
//! then running a 2-of-3 threshold signing round and emitting the aggregated
//! Schnorr signature.
//!
//! Run: `cargo run --example dkg_ceremony --features frost-crypto`

#[cfg(feature = "frost-crypto")]
fn main() {
    use conxius_enclave_sdk::protocol::frost_crypto::{
        aggregate, create_nonces_and_commitments, create_signature_share, create_signing_package,
        dkg_part1, dkg_part2, dkg_part3, public_key_x_only, verify_dkg_round1_package,
        verify_dkg_round2_package,
    };
    use frost_secp256k1_tr::Identifier;
    use std::collections::BTreeMap;

    let n: u16 = 3;
    let t: u16 = 2;
    let labels = ["Conxian-infra/Nitro", "owner/StrongBox", "co-signer/HSM"];

    let ids: Vec<Vec<u8>> = (1..=n)
        .map(|i| Identifier::try_from(i).unwrap().serialize().to_vec())
        .collect();

    println!("DKG ceremony rehearsal: {t}-of-{n} FROST (secp256k1-tr, RFC 9591)");

    // ---- Operator pickup: validate any real-operator round packages ----
    // Real operators drop their round packages into $DKG_OPERATOR_DIR; this
    // validates whatever is present so the ceremony status is recorded as it
    // fills in. A rehearsal runs either way (the production ceremony is a
    // superset of this).
    if let Ok(dir) = std::env::var("DKG_OPERATOR_DIR") {
        let mut found = 0usize;
        let mut valid = 0usize;
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("pkg") {
                    continue;
                }
                let bytes = std::fs::read(&path).unwrap_or_default();
                let ok = verify_dkg_round1_package(&bytes).unwrap_or(false)
                    || verify_dkg_round2_package(&bytes).unwrap_or(false);
                println!(
                    "operator package {}: {}",
                    path.file_name().unwrap_or_default().to_string_lossy(),
                    if ok { "VALID" } else { "INVALID" }
                );
                found += 1;
                valid += usize::from(ok);
            }
        }
        println!("operator pickup: {valid}/{found} package(s) valid in {dir}");
    }

    // ---- Round 1: each participant publishes a commitment package ----
    let mut r1_secrets: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    let mut r1_packages: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for id in &ids {
        let (secret, package) = dkg_part1(id, n, t).expect("dkg_part1");
        assert!(verify_dkg_round1_package(&package).expect("verify r1"));
        r1_secrets.insert(id.clone(), secret);
        r1_packages.insert(id.clone(), package);
    }
    println!("round1: {n} participants generated + verified round-1 packages");

    // ---- Round 2: each participant answers every peer's round-1 package ----
    let mut r2_secrets: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    let mut all_r2: BTreeMap<Vec<u8>, BTreeMap<Vec<u8>, Vec<u8>>> = BTreeMap::new();
    for my_id in &ids {
        let mut peers: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        for (id, pkg) in &r1_packages {
            if id != my_id {
                peers.insert(id.clone(), pkg.clone());
            }
        }
        let (secret, out) = dkg_part2(r1_secrets.get(my_id).unwrap(), &peers).expect("dkg_part2");
        for v in out.values() {
            assert!(verify_dkg_round2_package(v).expect("verify r2"));
        }
        r2_secrets.insert(my_id.clone(), secret);
        all_r2.insert(my_id.clone(), out);
    }
    println!("round2: peers exchanged + verified round-2 packages");

    // ---- Round 3: finalize each key package + the shared public key ----
    let mut key_packages: Vec<Vec<u8>> = Vec::new();
    let mut public_key_package: Option<Vec<u8>> = None;
    for my_id in &ids {
        let mut peers_r1: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        for (id, pkg) in &r1_packages {
            if id != my_id {
                peers_r1.insert(id.clone(), pkg.clone());
            }
        }
        let mut my_r2: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        for (sender, out) in &all_r2 {
            if sender == my_id {
                continue;
            }
            if let Some(p) = out.get(my_id) {
                my_r2.insert(sender.clone(), p.clone());
            }
        }
        let (kp, pp) =
            dkg_part3(r2_secrets.get(my_id).unwrap(), &peers_r1, &my_r2).expect("dkg_part3");
        if let Some(prev) = &public_key_package {
            assert_eq!(prev, &pp, "public key package mismatch across participants");
        }
        key_packages.push(kp);
        public_key_package = Some(pp);
    }
    let pubkey = public_key_package.expect("pubkey");
    let xonly = public_key_x_only(&pubkey).expect("xonly");
    println!("round3: {n} key packages; all participants agree on the public key");
    println!("aggregated x-only public key: {}", hex::encode(&xonly));

    // ---- Threshold signing (any t-of-n subset) ----
    let message = b"conxian-dkg-ceremony-rehearsal";
    let (n1, c1) = create_nonces_and_commitments(&key_packages[0]).expect("nonces 1");
    let (n2, c2) = create_nonces_and_commitments(&key_packages[1]).expect("nonces 2");
    let sigpkg = create_signing_package(message, &[c1, c2]).expect("sigpkg");
    let s1 = create_signature_share(&key_packages[0], &n1, &sigpkg, message).expect("share 1");
    let s2 = create_signature_share(&key_packages[1], &n2, &sigpkg, message).expect("share 2");
    let sig = aggregate(&sigpkg, &[(1, s1), (2, s2)], &pubkey).expect("aggregate");
    println!(
        "threshold signature ({t}-of-{n}) over {:?}: {sig}",
        String::from_utf8_lossy(message)
    );
    println!("signing shares used: {} + {}", labels[0], labels[1]);

    // ---- Machine-readable evidence (consumed by other agents / CI) ----
    let generated_at = std::env::var("DKG_GENERATED_AT").unwrap_or_else(|_| "unknown".to_string());
    let git_sha = std::env::var("GITHUB_SHA").unwrap_or_else(|_| "local".to_string());
    let evidence = format!(
        "{{\n  \"schema\": \"conxian.dkg-ceremony.rehearsal.v1\",\n  \"mode\": \"rehearsal\",\n  \"generated_at\": \"{generated_at}\",\n  \"git_sha\": \"{git_sha}\",\n  \"curve\": \"secp256k1-tr (RFC 9591)\",\n  \"t\": {t},\n  \"n\": {n},\n  \"public_key_x_only\": \"{pubkey_hex}\",\n  \"message\": \"{message_str}\",\n  \"signature\": \"{sig}\",\n  \"status\": \"PASS\"\n}}",
        generated_at = generated_at,
        git_sha = git_sha,
        t = t,
        n = n,
        pubkey_hex = hex::encode(&xonly),
        message_str = String::from_utf8_lossy(message),
        sig = sig,
    );
    if let Ok(path) = std::env::var("DKG_EVIDENCE_PATH") {
        std::fs::write(&path, &evidence).expect("write evidence");
        println!("evidence written to {path}");
    }
    println!("{evidence}");
    println!("CEREMONY REHEARSAL OK");
}

#[cfg(not(feature = "frost-crypto"))]
fn main() {
    eprintln!(
        "dkg_ceremony requires the frost-crypto feature: \
         cargo run --example dkg_ceremony --features frost-crypto"
    );
    std::process::exit(2);
}
