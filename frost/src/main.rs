//! Seal's FROST helper (ADR 0002). A 2-of-3 FROST Ed25519 group key signs git's buffer file inside
//! an SSHSIG envelope, so that git, `ssh-keygen -Y verify` and GitHub see an ordinary `ssh-ed25519`
//! signature. Grown from the `seal-frost` pilot signer, which proved the format end to end.
//!
//! Commands:
//!   seal-frost keygen
//!       Trusted dealer (RFC 9591 Appendix C): three shares, threshold two. Prints one JSON object
//!       on stdout, `{"group_public_key", "public_key_package", "shares": [..3 key packages..]}`,
//!       and writes nothing to disk. Seal lays the pieces out.
//!   seal-frost sign -n <namespace> -f <keyfile> [-U] <buffer>
//!       git's `-Y sign` arguments. Reads the coordinator's share from `$SEAL_FROST_HOME/share-mac.json`
//!       and the group's public key package from `$SEAL_FROST_HOME/group.json`; reads the second key
//!       package as JSON from stdin; writes `<buffer>.sig`. Shares never appear in arguments or the
//!       environment.
//!
//! Failure: exit 2, one line on stderr, no `.sig` left behind.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use frost_ed25519 as frost;
use frost::keys::{IdentifierList, KeyPackage, PublicKeyPackage};
use frost::Identifier;
use rand::rngs::OsRng;
use serde::Serialize;
use ssh_key::public::{Ed25519PublicKey, KeyData};
use ssh_key::{Algorithm, HashAlg, LineEnding, PublicKey, Signature, SshSig};

type Failure = Box<dyn Error>;

const USAGE: &str = "usage: seal-frost keygen | seal-frost sign -n <namespace> -f <keyfile> [-U] <buffer>";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let outcome = match args.first().map(String::as_str) {
        Some("keygen") if args.len() == 1 => keygen(),
        Some("sign") => sign(&args[1..]),
        _ => Err(USAGE.into()),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            eprintln!("seal-frost: {}", failure.to_string().replace('\n', " "));
            ExitCode::from(2)
        }
    }
}

#[derive(Serialize)]
struct Generated {
    group_public_key: String,
    public_key_package: PublicKeyPackage,
    shares: Vec<KeyPackage>,
}

/// Trusted dealer: the whole key exists in this process once and is discarded with it.
fn keygen() -> Result<(), Failure> {
    let rng = OsRng;
    let (shares, public_key_package) =
        frost::keys::generate_with_dealer(3, 2, IdentifierList::Default, rng)?;
    // With IdentifierList::Default the identifiers are 1, 2, 3 and the map iterates in that order.
    let shares = shares
        .into_values()
        .map(KeyPackage::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    let group_public_key = PublicKey::new(group_key_data(&public_key_package)?, "").to_openssh()?;
    let generated = Generated { group_public_key, public_key_package, shares };
    println!("{}", serde_json::to_string(&generated)?);
    Ok(())
}

/// Signs `<buffer>` with the group key and writes the SSHSIG to `<buffer>.sig`, exactly where
/// `ssh-keygen -Y sign` would. Any failure removes a stale `.sig` first.
fn sign(args: &[String]) -> Result<(), Failure> {
    let request = SignRequest::parse(args)?;
    let signature_file = {
        let mut path = request.buffer.clone().into_os_string();
        path.push(".sig");
        PathBuf::from(path)
    };
    let outcome = sign_request(&request, &signature_file);
    if outcome.is_err() {
        let _ = fs::remove_file(&signature_file);
    }
    outcome
}

fn sign_request(request: &SignRequest, signature_file: &Path) -> Result<(), Failure> {
    let home = PathBuf::from(std::env::var_os("SEAL_FROST_HOME").ok_or("SEAL_FROST_HOME is not set")?);
    let public_key_package: PublicKeyPackage = read_json(&home.join("group.json"))?;
    let coordinator: KeyPackage = read_json(&home.join("share-mac.json"))?;
    let key_data = group_key_data(&public_key_package)?;

    // The key git named in -f must be the group key; otherwise git and GitHub would look up the
    // wrong public key for a signature that is nevertheless valid.
    let named = fs::read_to_string(&request.key_file)
        .map_err(|e| format!("cannot read {}: {e}", request.key_file.display()))?;
    let named = PublicKey::from_openssh(named.trim()).map_err(|e| format!("{}: {e}", request.key_file.display()))?;
    if named.key_data() != &key_data {
        return Err(format!("{} is not the group key", request.key_file.display()).into());
    }

    let mut stdin = String::new();
    std::io::stdin().read_to_string(&mut stdin)?;
    let second: KeyPackage = serde_json::from_str(stdin.trim()).map_err(|e| format!("share on stdin: {e}"))?;
    if second.identifier() == coordinator.identifier() {
        return Err("the share on stdin has the same identifier as the coordinator's share".into());
    }

    let body = fs::read(&request.buffer).map_err(|e| format!("cannot read {}: {e}", request.buffer.display()))?;
    let signed_data = SshSig::signed_data(&request.namespace, HashAlg::Sha512, &body)?;
    let group_signature = frost_sign(&[coordinator, second], &public_key_package, &signed_data)?;

    let signature = Signature::new(Algorithm::Ed25519, group_signature.serialize()?)?;
    let sshsig = SshSig::new(key_data, request.namespace.as_str(), HashAlg::Sha512, signature)?;
    fs::write(signature_file, sshsig.to_pem(LineEnding::LF)?)?;
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, Failure> {
    let text = fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()).into())
}

/// FROST two-round signing with every given participant, coordinator and participants in one
/// process. Round 1: each participant commits to fresh nonces. Round 2: each produces a signature
/// share over the same signing package. Then the coordinator aggregates and checks the result.
fn frost_sign(
    signers: &[KeyPackage],
    public_key_package: &PublicKeyPackage,
    message: &[u8],
) -> Result<frost::Signature, Failure> {
    let mut rng = OsRng;
    let mut nonces_by_id = BTreeMap::new();
    let mut commitments: BTreeMap<Identifier, frost::round1::SigningCommitments> = BTreeMap::new();
    for key_package in signers {
        let (nonces, commitment) = frost::round1::commit(key_package.signing_share(), &mut rng);
        nonces_by_id.insert(*key_package.identifier(), nonces);
        commitments.insert(*key_package.identifier(), commitment);
    }

    let signing_package = frost::SigningPackage::new(commitments, message);

    let mut signature_shares: BTreeMap<Identifier, frost::round2::SignatureShare> = BTreeMap::new();
    for key_package in signers {
        let nonces = &nonces_by_id[key_package.identifier()];
        let share = frost::round2::sign(&signing_package, nonces, key_package)?;
        signature_shares.insert(*key_package.identifier(), share);
    }

    let group_signature = frost::aggregate(&signing_package, &signature_shares, public_key_package)?;
    public_key_package.verifying_key().verify(message, &group_signature)?;
    Ok(group_signature)
}

/// The group's verifying key as the SSH `ssh-ed25519` key data: the 32-byte compressed point.
fn group_key_data(public_key_package: &PublicKeyPackage) -> Result<KeyData, Failure> {
    let bytes = public_key_package.verifying_key().serialize()?;
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("verifying key is {} bytes, expected 32", bytes.len()))?;
    Ok(KeyData::Ed25519(Ed25519PublicKey(bytes)))
}

/// The arguments git gives for `-Y sign`, parsed the way Seal parses them: `-U` is a bare flag,
/// every other option takes a value, and exactly one positional is the buffer file.
struct SignRequest {
    namespace: String,
    key_file: PathBuf,
    buffer: PathBuf,
}

impl SignRequest {
    fn parse(args: &[String]) -> Result<Self, Failure> {
        let mut namespace = None;
        let mut key_file = None;
        let mut positional = Vec::new();
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "-U" => {}
                "-n" => {
                    index += 1;
                    namespace = args.get(index).cloned();
                }
                "-f" => {
                    index += 1;
                    key_file = args.get(index).map(PathBuf::from);
                }
                option if option.starts_with('-') => index += 1,
                file => positional.push(PathBuf::from(file)),
            }
            index += 1;
        }
        let namespace = namespace.ok_or("no -n namespace given")?;
        if namespace.is_empty() {
            return Err("empty namespace".into());
        }
        let key_file = key_file.ok_or("no -f key file given")?;
        if positional.len() != 1 {
            return Err(format!("expected exactly one buffer file, got {}", positional.len()).into());
        }
        Ok(SignRequest { namespace, key_file, buffer: positional.remove(0) })
    }
}
