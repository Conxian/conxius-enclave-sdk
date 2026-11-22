//! `conxian-threshold` — separated-share FROST threshold signing operator CLI.
//!
//! Each subcommand performs **one** step of a 2-of-N threshold ceremony as a
//! separate process, so no single process ever holds more than one key package
//! (Issue #726 finding F4, #745). Secret material stays in the operator's own
//! files; only public values (commitments, signature shares, the public key
//! package) are exchanged between steps.
//!
//! ```text
//! # Trusted-dealer keygen for local testing only (real deployments use DKG):
//! conxian-threshold dkg --n 3 --t 2 --dir ./ceremony
//!
//! # Operator 1 and operator 3 sign; operator 2 is offline:
//! conxian-threshold commit --keypkg ceremony/share1.keypkg --id 1 --nonce n1 --commit c1
//! conxian-threshold commit --keypkg ceremony/share3.keypkg --id 3 --nonce n3 --commit c3
//! conxian-threshold sigpkg --ids 1,3 --commits c1,c3 --msg <32-byte-hex> --out sp
//! conxian-threshold sign   --keypkg ceremony/share1.keypkg --id 1 --nonce n1 --sigpkg sp --out s1
//! conxian-threshold sign   --keypkg ceremony/share3.keypkg --id 3 --nonce n3 --sigpkg sp --out s3
//! conxian-threshold aggregate --pubkey ceremony/pubkey.pkg --sigpkg sp --ids 1,3 --shares s1,s3
//! ```
//!
//! `--msg` takes the message as a hex literal (the digest you want signed);
//! use `--msg-file` instead to read the hex from a file. Every other value is a
//! hex-encoded file. The message must be exactly 32 bytes of hex
//! (a digest) so the result verifies as a standard BIP-340 Schnorr signature.

use conxius_enclave_sdk::enclave::separated::{ThresholdCoordinator, ThresholdOperator};
use conxius_enclave_sdk::protocol::frost_crypto::{
    create_signing_package_with_ids, dkg_part1, dkg_part2, dkg_part3, public_key_x_only,
    trusted_dealer_keygen, verify_dkg_round1_package, verify_dkg_round2_package,
};
use frost_secp256k1_tr::Identifier;
use std::collections::BTreeMap;
use std::process::ExitCode;

fn read_hex(path: &str) -> Result<Vec<u8>, String> {
    let s = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    hex::decode(s.trim()).map_err(|e| format!("hex {path}: {e}"))
}

fn write_hex(path: &str, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, hex::encode(bytes)).map_err(|e| format!("write {path}: {e}"))
}

fn opt<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

fn req<'a>(args: &'a [String], key: &str) -> Result<&'a str, String> {
    opt(args, key).ok_or_else(|| format!("missing required {key}"))
}

fn parse_ids(s: &str) -> Result<Vec<u16>, String> {
    s.split(',')
        .map(|x| x.trim().parse::<u16>().map_err(|e| format!("id {x}: {e}")))
        .collect()
}

fn parse_u16(args: &[String], key: &str, default: u16) -> Result<u16, String> {
    match opt(args, key) {
        Some(v) => v.parse().map_err(|e| format!("{key}: {e}")),
        None => Ok(default),
    }
}

fn id_bytes(pid: u16) -> Result<Vec<u8>, String> {
    Ok(Identifier::try_from(pid)
        .map_err(|e| format!("id: {e}"))?
        .serialize()
        .to_vec())
}

fn pid_from_identifier(bytes: &[u8]) -> Result<u16, String> {
    let ser = Identifier::deserialize(bytes)
        .map_err(|e| format!("id: {e}"))?
        .serialize();
    Ok(u16::from_be_bytes([ser[ser.len() - 2], ser[ser.len() - 1]]))
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("");
    match cmd {
        // Trusted-dealer keygen for local testing. Real deployments run the DKG
        // ceremony so no single party ever sees every share.
        "dkg" => {
            let n = parse_u16(&args, "--n", 3)?;
            let t = parse_u16(&args, "--t", 2)?;
            let dir = req(&args, "--dir")?;
            std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {dir}: {e}"))?;
            let (key_packages, pubkey_pkg) =
                trusted_dealer_keygen(t, n).map_err(|e| format!("keygen: {e}"))?;
            for (i, kp) in key_packages.iter().enumerate() {
                write_hex(&format!("{dir}/share{}.keypkg", i + 1), kp)?;
            }
            write_hex(&format!("{dir}/pubkey.pkg"), &pubkey_pkg)?;
            let xonly = public_key_x_only(&pubkey_pkg).map_err(|e| format!("xonly: {e}"))?;
            println!(
                "dkg: {n} shares (t={t}) + pubkey.pkg written to {dir}; x-only {}",
                hex::encode(xonly)
            );
        }
        // Real DKG, one participant per process:
        //   dkg-round1 -> publish round1/<id>.pkg
        //   dkg-round2 -> send round2 packages point-to-point (they carry secrets)
        //   dkg-round3 -> hold key package locally, publish the public key package
        "dkg-round1" => {
            let id = req(&args, "--id")?
                .parse::<u16>()
                .map_err(|e| format!("{e}"))?;
            let n = parse_u16(&args, "--n", 3)?;
            let t = parse_u16(&args, "--t", 2)?;
            let (secret, package) =
                dkg_part1(&id_bytes(id)?, n, t).map_err(|e| format!("dkg1: {e}"))?;
            write_hex(&format!("{id}.secret.r1"), &secret)?;
            write_hex(&format!("{id}.round1.pkg"), &package)?;
            if !verify_dkg_round1_package(&package).map_err(|e| format!("{e}"))? {
                return Err("round1 package failed verification".to_string());
            }
            println!("dkg-round1: wrote {id}.secret.r1 (keep) + {id}.round1.pkg (publish)");
        }
        "dkg-round2" => {
            let id = req(&args, "--id")?
                .parse::<u16>()
                .map_err(|e| format!("{e}"))?;
            let dir = req(&args, "--round1-dir")?;
            let secret = read_hex(&format!("{id}.secret.r1"))?;
            let mut peers = BTreeMap::new();
            for entry in std::fs::read_dir(dir).map_err(|e| format!("read_dir {dir}: {e}"))? {
                let path = entry.map_err(|e| format!("{e}"))?.path();
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if let Some(stem) = name.strip_suffix(".round1.pkg") {
                    let pid = stem
                        .parse::<u16>()
                        .map_err(|e| format!("peer id {stem}: {e}"))?;
                    if pid == id {
                        continue;
                    }
                    peers.insert(id_bytes(pid)?, read_hex(&path.to_string_lossy())?);
                }
            }
            let (secret2, out) = dkg_part2(&secret, &peers).map_err(|e| format!("dkg2: {e}"))?;
            write_hex(&format!("{id}.secret.r2"), &secret2)?;
            for (pid_b, pkg) in &out {
                if !verify_dkg_round2_package(pkg).map_err(|e| format!("{e}"))? {
                    return Err("round2 package failed verification".to_string());
                }
                // A round-2 package is secret for its recipient: deliver it
                // point-to-point, never commit or post it.
                write_hex(
                    &format!("to-{}.round2.pkg", pid_from_identifier(pid_b)?),
                    pkg,
                )?;
            }
            println!("dkg-round2: wrote {id}.secret.r2 + to-<peer>.round2.pkg (deliver privately)");
        }
        "dkg-round3" => {
            let id = req(&args, "--id")?
                .parse::<u16>()
                .map_err(|e| format!("{e}"))?;
            let dir = req(&args, "--round1-dir")?;
            let r2dir = req(&args, "--round2-dir")?;
            let secret2 = read_hex(&format!("{id}.secret.r2"))?;
            let mut r1 = BTreeMap::new();
            for entry in std::fs::read_dir(dir).map_err(|e| format!("{e}"))? {
                let path = entry.map_err(|e| format!("{e}"))?.path();
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if let Some(stem) = name.strip_suffix(".round1.pkg") {
                    let pid = stem.parse::<u16>().map_err(|e| format!("{e}"))?;
                    if pid == id {
                        continue;
                    }
                    r1.insert(id_bytes(pid)?, read_hex(&path.to_string_lossy())?);
                }
            }
            let mut r2 = BTreeMap::new();
            for entry in std::fs::read_dir(r2dir).map_err(|e| format!("{e}"))? {
                let path = entry.map_err(|e| format!("{e}"))?.path();
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                // Only consume inbound packages (`from-<peer>.round2.pkg`); skip
                // this operator's own outbound `to-<peer>.round2.pkg` files.
                if let Some(stem) = name
                    .strip_suffix(".round2.pkg")
                    .and_then(|s| s.strip_prefix("from-"))
                {
                    let pid = stem.parse::<u16>().map_err(|e| format!("{e}"))?;
                    r2.insert(id_bytes(pid)?, read_hex(&path.to_string_lossy())?);
                }
            }
            let (key_pkg, pubkey_pkg) =
                dkg_part3(&secret2, &r1, &r2).map_err(|e| format!("dkg3: {e}"))?;
            write_hex(&format!("{id}.keypkg"), &key_pkg)?;
            write_hex(&format!("{id}.pubkey.pkg"), &pubkey_pkg)?;
            let xonly = public_key_x_only(&pubkey_pkg).map_err(|e| format!("{e}"))?;
            println!(
                "dkg-round3: wrote {id}.keypkg (keep) + {id}.pubkey.pkg; x-only {}",
                hex::encode(xonly)
            );
        }
        "commit" => {
            let id = req(&args, "--id")?
                .parse::<u16>()
                .map_err(|e| format!("{e}"))?;
            let keypkg = read_hex(req(&args, "--keypkg")?)?;
            let mut op = ThresholdOperator::from_key_package(id, keypkg)
                .map_err(|e| format!("operator: {e}"))?;
            let (nonce, commitment) = op.commit().map_err(|e| format!("commit: {e}"))?;
            write_hex(req(&args, "--nonce")?, &nonce)?;
            write_hex(req(&args, "--commit")?, &commitment)?;
            println!("commit: ok (participant {id})");
        }
        "sigpkg" => {
            let ids = parse_ids(req(&args, "--ids")?)?;
            let commits: Vec<Vec<u8>> = req(&args, "--commits")?
                .split(',')
                .map(read_hex)
                .collect::<Result<_, _>>()?;
            if ids.len() != commits.len() {
                return Err("--ids and --commits must have the same length".to_string());
            }
            let msg = match (opt(&args, "--msg"), opt(&args, "--msg-file")) {
                (Some(hex), None) => {
                    hex::decode(hex.trim()).map_err(|e| format!("--msg must be hex: {e}"))?
                }
                (None, Some(path)) => read_hex(path)?,
                (Some(_), Some(_)) => {
                    return Err("pass either --msg or --msg-file, not both".to_string())
                }
                (None, None) => return Err("missing required --msg <hex>".to_string()),
            };
            let commitments: Vec<(u16, Vec<u8>)> = ids.iter().cloned().zip(commits).collect();
            let signing_package = match opt(&args, "--pubkey") {
                Some(p) => {
                    let t = parse_u16(&args, "--t", ids.len() as u16)?;
                    ThresholdCoordinator::new(read_hex(p)?, t)
                        .map_err(|e| format!("coordinator: {e}"))?
                        .signing_package(&msg, &commitments)
                        .map_err(|e| format!("sigpkg: {e}"))?
                }
                None => {
                    let id_vec: Vec<u16> = commitments.iter().map(|(i, _)| *i).collect();
                    let commit_vec: Vec<Vec<u8>> =
                        commitments.iter().map(|(_, c)| c.clone()).collect();
                    create_signing_package_with_ids(&msg, &id_vec, &commit_vec)
                        .map_err(|e| format!("sigpkg: {e}"))?
                }
            };
            write_hex(req(&args, "--out")?, &signing_package)?;
            println!("sigpkg: ok (ids {ids:?})");
        }
        "sign" => {
            let id = req(&args, "--id")?
                .parse::<u16>()
                .map_err(|e| format!("{e}"))?;
            let keypkg = read_hex(req(&args, "--keypkg")?)?;
            let nonce = read_hex(req(&args, "--nonce")?)?;
            let sigpkg = read_hex(req(&args, "--sigpkg")?)?;
            let mut op = ThresholdOperator::from_key_package(id, keypkg)
                .map_err(|e| format!("operator: {e}"))?;
            op.load_nonce(nonce).map_err(|e| format!("nonce: {e}"))?;
            let share = op.sign(&sigpkg).map_err(|e| format!("sign: {e}"))?;
            write_hex(req(&args, "--out")?, &share)?;
            println!("sign: ok (participant {id})");
        }
        "aggregate" => {
            let pubkey = read_hex(req(&args, "--pubkey")?)?;
            let sigpkg = read_hex(req(&args, "--sigpkg")?)?;
            let ids = parse_ids(req(&args, "--ids")?)?;
            let shares: Vec<Vec<u8>> = req(&args, "--shares")?
                .split(',')
                .map(read_hex)
                .collect::<Result<_, _>>()?;
            if ids.len() != shares.len() {
                return Err("--ids and --shares must have the same length".to_string());
            }
            let t = parse_u16(&args, "--t", ids.len() as u16)?;
            let coordinator =
                ThresholdCoordinator::new(pubkey, t).map_err(|e| format!("coordinator: {e}"))?;
            let shares: Vec<(u16, Vec<u8>)> = ids.into_iter().zip(shares).collect();
            let signature = coordinator
                .aggregate(&sigpkg, &shares)
                .map_err(|e| format!("aggregate: {e}"))?;
            println!("signature: {signature}");
        }
        _ => {
            eprintln!(
                "usage: conxian-threshold <dkg|dkg-round1|dkg-round2|dkg-round3|\
                 commit|sigpkg|sign|aggregate> [options]\n\
                 See the module docs for the full separated-share flow."
            );
            return Err("no subcommand".to_string());
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
