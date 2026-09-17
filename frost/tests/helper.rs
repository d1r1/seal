//! The helper at its seam: argv, stdin, stdout, the files it reads under `SEAL_FROST_HOME`, and the
//! `.sig` it writes. OpenSSH's `ssh-keygen -Y check-novalidate` is the oracle for the envelope.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

const HELPER: &str = env!("CARGO_BIN_EXE_seal-frost");

fn keygen() -> Value {
    let output = Command::new(HELPER).arg("keygen").output().expect("run keygen");
    assert!(output.status.success(), "keygen failed: {}", String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice(&output.stdout).expect("keygen prints one JSON object")
}

/// A support directory as Seal lays it out: the coordinator's share and the public key package.
struct Home {
    dir: tempfile::TempDir,
    keys: Value,
}

impl Home {
    fn new() -> Home {
        let keys = keygen();
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("share-mac.json"), keys["shares"][1].to_string()).unwrap();
        fs::write(dir.path().join("group.json"), keys["public_key_package"].to_string()).unwrap();
        fs::write(dir.path().join("group.pub"), format!("{}\n", keys["group_public_key"].as_str().unwrap())).unwrap();
        Home { dir, keys }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn share(&self, index: usize) -> String {
        self.keys["shares"][index].to_string()
    }

    fn write_message(&self, name: &str, body: &[u8]) -> PathBuf {
        let path = self.path().join(name);
        fs::write(&path, body).unwrap();
        path
    }

    /// `seal-frost sign -n git -f <keyfile> -U <buffer>` with `stdin_share` on stdin.
    fn sign(&self, keyfile: &Path, buffer: &Path, stdin_share: &str) -> std::process::Output {
        let mut child = Command::new(HELPER)
            .args(["sign", "-n", "git", "-f"])
            .arg(keyfile)
            .arg("-U")
            .arg(buffer)
            .env("SEAL_FROST_HOME", self.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run sign");
        child.stdin.take().unwrap().write_all(stdin_share.as_bytes()).unwrap();
        child.wait_with_output().unwrap()
    }
}

fn check_novalidate(buffer: &Path) -> std::process::Output {
    let sig = buffer.with_extension("sig");
    Command::new("ssh-keygen")
        .args(["-Y", "check-novalidate", "-n", "git", "-s"])
        .arg(&sig)
        .stdin(fs::File::open(buffer).unwrap())
        .output()
        .unwrap()
}

#[test]
fn keygen_prints_group_key_public_package_and_three_shares_and_writes_nothing() {
    let cwd = tempfile::tempdir().unwrap();
    let output = Command::new(HELPER).arg("keygen").current_dir(cwd.path()).output().unwrap();
    assert!(output.status.success());
    let keys: Value = serde_json::from_slice(&output.stdout).unwrap();

    let line = keys["group_public_key"].as_str().expect("one OpenSSH line");
    assert!(line.starts_with("ssh-ed25519 AAAA"), "{line}");
    assert_eq!(line.lines().count(), 1);
    assert_eq!(keys["shares"].as_array().unwrap().len(), 3);
    assert!(keys["public_key_package"].is_object());
    assert_eq!(fs::read_dir(cwd.path()).unwrap().count(), 0, "keygen must not write files");
}

#[test]
fn sign_with_user_share_on_stdin_writes_an_envelope_openssh_accepts() {
    let home = Home::new();
    let buffer = home.write_message("buffer", b"tree 0000000000000000000000000000000000000000\n\nhello\n");

    let output = home.sign(&home.path().join("group.pub"), &buffer, &home.share(0));

    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let sig = fs::read_to_string(buffer.with_extension("sig")).unwrap();
    assert!(sig.starts_with("-----BEGIN SSH SIGNATURE-----"), "{sig}");
    let check = check_novalidate(&buffer);
    assert!(check.status.success(), "{}", String::from_utf8_lossy(&check.stderr));
    let said = format!("{}{}", String::from_utf8_lossy(&check.stdout), String::from_utf8_lossy(&check.stderr));
    assert!(said.contains("Good \"git\" signature with ED25519 key"), "{said}");
}

#[test]
fn the_recovery_share_on_stdin_signs_too() {
    let home = Home::new();
    let buffer = home.write_message("buffer", b"recovery\n");

    let output = home.sign(&home.path().join("group.pub"), &buffer, &home.share(2));

    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(check_novalidate(&buffer).status.success());
}

#[test]
fn a_key_file_that_is_not_the_group_key_fails_with_no_signature_file() {
    let home = Home::new();
    let other = keygen();
    let other_key = home.write_message("other.pub", format!("{}\n", other["group_public_key"].as_str().unwrap()).as_bytes());
    let buffer = home.write_message("buffer", b"wrong key\n");

    let output = home.sign(&other_key, &buffer, &home.share(0));

    assert!(!output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stderr).lines().count(), 1, "one line on stderr");
    assert!(String::from_utf8_lossy(&output.stderr).contains("not the group key"));
    assert!(!buffer.with_extension("sig").exists());
}

#[test]
fn a_stdin_share_with_the_coordinators_identifier_fails() {
    let home = Home::new();
    let buffer = home.write_message("buffer", b"same share twice\n");

    let output = home.sign(&home.path().join("group.pub"), &buffer, &home.share(1));

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("same identifier"));
    assert!(!buffer.with_extension("sig").exists());
}

#[test]
fn a_share_from_another_group_fails_and_leaves_no_signature() {
    let home = Home::new();
    let other = keygen();
    let buffer = home.write_message("buffer", b"foreign share\n");

    let output = home.sign(&home.path().join("group.pub"), &buffer, &other["shares"][0].to_string());

    assert!(!output.status.success());
    assert!(!buffer.with_extension("sig").exists());
}

#[test]
fn a_missing_coordinator_share_fails_with_one_line() {
    let home = Home::new();
    fs::remove_file(home.path().join("share-mac.json")).unwrap();
    let buffer = home.write_message("buffer", b"no mac share\n");

    let output = home.sign(&home.path().join("group.pub"), &buffer, &home.share(0));

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(stderr.contains("share-mac.json"), "{stderr}");
}

#[test]
fn a_stale_signature_file_is_removed_on_failure() {
    let home = Home::new();
    let buffer = home.write_message("buffer", b"stale\n");
    fs::write(buffer.with_extension("sig"), "stale").unwrap();

    let output = home.sign(&home.path().join("group.pub"), &buffer, "not json");

    assert!(!output.status.success());
    assert!(!buffer.with_extension("sig").exists());
}
