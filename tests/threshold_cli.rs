//! End-to-end tests for the `conxian-threshold` operator CLI.
//!
//! The CLI's own docs promise `sigpkg --msg <32-byte-hex>`, so the message is a
//! hex literal. These tests drive the real binary through a full 2-of-3 ceremony
//! and assert the aggregated signature verifies, so a regression that treats
//! `--msg` as a file path (the bug this file was added for) fails here.

#![cfg(feature = "frost-crypto")]

use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_conxian-threshold"))
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("failed to spawn conxian-threshold")
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "conxian-threshold-test-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn msg_accepts_a_hex_literal_not_only_a_file_path() {
    let dir = scratch_dir("msg-hex");
    let d = dir.to_str().unwrap();
    let msg = "ab".repeat(32);

    assert!(run(&["dkg", "--n", "3", "--t", "2", "--dir", d])
        .status
        .success());

    let s1 = dir.join("share1.keypkg");
    let s3 = dir.join("share3.keypkg");
    let n1 = dir.join("n1");
    let n3 = dir.join("n3");
    let c1 = dir.join("c1");
    let c3 = dir.join("c3");

    assert!(run(&[
        "commit",
        "--keypkg",
        s1.to_str().unwrap(),
        "--id",
        "1",
        "--nonce",
        n1.to_str().unwrap(),
        "--commit",
        c1.to_str().unwrap(),
    ])
    .status
    .success());
    assert!(run(&[
        "commit",
        "--keypkg",
        s3.to_str().unwrap(),
        "--id",
        "3",
        "--nonce",
        n3.to_str().unwrap(),
        "--commit",
        c3.to_str().unwrap(),
    ])
    .status
    .success());

    let sp = dir.join("sp");
    let commits = format!("{},{}", c1.display(), c3.display());
    let sigpkg = run(&[
        "sigpkg",
        "--ids",
        "1,3",
        "--commits",
        &commits,
        "--msg",
        &msg,
        "--out",
        sp.to_str().unwrap(),
    ]);
    assert!(
        sigpkg.status.success(),
        "sigpkg rejected a hex --msg: {}",
        String::from_utf8_lossy(&sigpkg.stderr)
    );

    let sh1 = dir.join("s1");
    let sh3 = dir.join("s3");
    assert!(run(&[
        "sign",
        "--keypkg",
        s1.to_str().unwrap(),
        "--id",
        "1",
        "--nonce",
        n1.to_str().unwrap(),
        "--sigpkg",
        sp.to_str().unwrap(),
        "--out",
        sh1.to_str().unwrap(),
    ])
    .status
    .success());
    assert!(run(&[
        "sign",
        "--keypkg",
        s3.to_str().unwrap(),
        "--id",
        "3",
        "--nonce",
        n3.to_str().unwrap(),
        "--sigpkg",
        sp.to_str().unwrap(),
        "--out",
        sh3.to_str().unwrap(),
    ])
    .status
    .success());

    let shares = format!("{},{}", sh1.display(), sh3.display());
    let agg = run(&[
        "aggregate",
        "--pubkey",
        dir.join("pubkey.pkg").to_str().unwrap(),
        "--sigpkg",
        sp.to_str().unwrap(),
        "--ids",
        "1,3",
        "--shares",
        &shares,
    ]);
    assert!(
        agg.status.success(),
        "aggregate failed: {}",
        String::from_utf8_lossy(&agg.stderr)
    );
    let stdout = String::from_utf8_lossy(&agg.stdout);
    let sig = stdout
        .split_whitespace()
        .find(|t| t.len() == 128 && t.chars().all(|c| c.is_ascii_hexdigit()))
        .expect("no 64-byte signature in aggregate output");
    assert_eq!(sig.len(), 128);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_non_hex_msg_fails_with_a_hex_error_not_a_read_error() {
    let dir = scratch_dir("bad-msg");
    let d = dir.to_str().unwrap();
    assert!(run(&["dkg", "--n", "3", "--t", "2", "--dir", d])
        .status
        .success());

    let c1 = dir.join("c1");
    let c3 = dir.join("c3");
    assert!(run(&[
        "commit",
        "--keypkg",
        dir.join("share1.keypkg").to_str().unwrap(),
        "--id",
        "1",
        "--nonce",
        dir.join("n1").to_str().unwrap(),
        "--commit",
        c1.to_str().unwrap(),
    ])
    .status
    .success());
    assert!(run(&[
        "commit",
        "--keypkg",
        dir.join("share3.keypkg").to_str().unwrap(),
        "--id",
        "3",
        "--nonce",
        dir.join("n3").to_str().unwrap(),
        "--commit",
        c3.to_str().unwrap(),
    ])
    .status
    .success());

    let commits = format!("{},{}", c1.display(), c3.display());
    let out = run(&[
        "sigpkg",
        "--ids",
        "1,3",
        "--commits",
        &commits,
        "--msg",
        "not-hex",
        "--out",
        dir.join("sp").to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--msg must be hex"),
        "expected a hex error, got: {stderr}"
    );

    std::fs::remove_dir_all(&dir).ok();
}
