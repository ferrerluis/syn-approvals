use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use minicbor::bytes::ByteVec;
use syn_protocol::{
    digest_environment, generate_signing_key, key_id_hex, sign_decision, sign_request,
    signing_key_from_pem, signing_key_to_pem, sorted_environment_names, verify_request,
    verifying_key_from_pem, verifying_key_to_pem, ApprovalRequestV1, AuthenticationClass,
    CommandInfoEntry, DecisionAction, DecisionV1, SudoIntentV1,
};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(name = "syn-sim", about = "Offline Syn protocol simulator")]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate an ES256 signing keypair.
    Keygen {
        #[arg(long)]
        private: PathBuf,
        #[arg(long)]
        public: PathBuf,
    },
    /// Create a target-signed sudo request without executing it.
    Request {
        #[arg(long)]
        target_private: PathBuf,
        #[arg(long)]
        target_id: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(required = true, trailing_var_arg = true)]
        argv: Vec<String>,
    },
    /// Inspect and verify a signed request.
    Inspect {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        target_public: PathBuf,
    },
    /// Sign an approve-once or deny decision.
    Decide {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        target_public: PathBuf,
        #[arg(long)]
        approver_private: PathBuf,
        #[arg(long, value_enum)]
        action: Action,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Action {
    Approve,
    Deny,
}

fn main() -> Result<()> {
    match Arguments::parse().command {
        Command::Keygen { private, public } => keygen(&private, &public),
        Command::Request {
            target_private,
            target_id,
            out,
            argv,
        } => request(&target_private, target_id, &out, argv),
        Command::Inspect {
            request,
            target_public,
        } => inspect(&request, &target_public),
        Command::Decide {
            request,
            target_public,
            approver_private,
            action,
            out,
        } => decide(&request, &target_public, &approver_private, action, &out),
    }
}

fn keygen(private: &Path, public: &Path) -> Result<()> {
    if private.exists() || public.exists() {
        bail!("refusing to overwrite an existing key file");
    }
    let key = generate_signing_key();
    write_private(private, signing_key_to_pem(&key)?.as_bytes())?;
    write_public(
        public,
        verifying_key_to_pem(key.verifying_key())?.as_bytes(),
    )?;
    println!("key_id={}", key_id_hex(key.verifying_key()));
    Ok(())
}

fn request(private: &Path, target_id: String, out: &Path, argv: Vec<String>) -> Result<()> {
    if out.exists() {
        bail!("refusing to overwrite {}", out.display());
    }
    let key = read_signing_key(private)?;
    let executable = argv[0].as_bytes().to_vec();
    let environment: Vec<Vec<u8>> = std::env::vars_os()
        .map(|(key, value)| {
            let mut entry = os_bytes(&key);
            entry.push(b'=');
            entry.extend(os_bytes(&value));
            entry
        })
        .collect();
    let intent = SudoIntentV1 {
        invoking_uid: unsafe { libc::getuid() },
        invoking_gid: unsafe { libc::getgid() },
        invoking_user: std::env::var("USER").unwrap_or_else(|_| "simulator".into()),
        pid: std::process::id(),
        parent_pid: unsafe { libc::getppid() as u32 },
        tty: None,
        non_interactive: true,
        working_directory: ByteVec::from(os_bytes(std::env::current_dir()?.as_os_str())),
        run_as_uid: 0,
        run_as_gid: 0,
        run_as_user: "root".into(),
        run_as_group: "root".into(),
        sudo_mode: "run".into(),
        executable: ByteVec::from(executable.clone()),
        argv: argv
            .into_iter()
            .map(|argument| ByteVec::from(argument.into_bytes()))
            .collect(),
        command_info: vec![CommandInfoEntry {
            key: "command".into(),
            value: ByteVec::from(executable),
        }],
        environment_digest: ByteVec::from(digest_environment(&environment).to_vec()),
        environment_names: sorted_environment_names(&environment),
        policy_version: 1,
        sudo_provider: "syn-sim".into(),
        risk_markers: vec!["simulation_only".into()],
    };
    let request = ApprovalRequestV1::new(target_id, key.verifying_key(), intent);
    fs::write(out, sign_request(&request, &key)?)?;
    println!("request_id={}", hex::encode(request.request_id.as_slice()));
    Ok(())
}

fn inspect(request: &Path, target_public: &Path) -> Result<()> {
    let public = read_verifying_key(target_public)?;
    let verified = verify_request(&fs::read(request)?, &public)?;
    println!("target={}", verified.request.target_id);
    println!(
        "request_id={}",
        hex::encode(verified.request.request_id.as_slice())
    );
    println!("request_hash={}", hex::encode(verified.payload_hash));
    println!("user={}", verified.request.sudo.invoking_user);
    println!("run_as={}", verified.request.sudo.run_as_user);
    println!(
        "executable={}",
        escaped(verified.request.sudo.executable.as_slice())
    );
    for (index, argument) in verified.request.sudo.argv.iter().enumerate() {
        println!("argv[{index}]={}", escaped(argument));
    }
    Ok(())
}

fn decide(
    request_path: &Path,
    target_public: &Path,
    approver_private: &Path,
    action: Action,
    out: &Path,
) -> Result<()> {
    if out.exists() {
        bail!("refusing to overwrite {}", out.display());
    }
    let target = read_verifying_key(target_public)?;
    let request = verify_request(&fs::read(request_path)?, &target)?;
    let approver = read_signing_key(approver_private)?;
    let (action, class) = match action {
        Action::Approve => (
            DecisionAction::ApproveOnce,
            AuthenticationClass::SystemUserPresence,
        ),
        Action::Deny => (
            DecisionAction::Deny,
            AuthenticationClass::DeviceAuthenticated,
        ),
    };
    let decision = DecisionV1::for_request(&request, action, class, approver.verifying_key());
    fs::write(out, sign_decision(&decision, &approver)?)?;
    println!("decision={action}");
    Ok(())
}

fn read_signing_key(path: &Path) -> Result<p256::ecdsa::SigningKey> {
    let pem = Zeroizing::new(
        fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?,
    );
    Ok(signing_key_from_pem(&pem)?)
}

fn read_verifying_key(path: &Path) -> Result<p256::ecdsa::VerifyingKey> {
    let pem = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(verifying_key_from_pem(&pem)?)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    std::io::Write::write_all(&mut options.open(path)?, bytes)?;
    Ok(())
}

fn write_public(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
    Ok(())
}

#[cfg(unix)]
fn os_bytes(value: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    value.as_bytes().to_vec()
}

fn escaped(value: &[u8]) -> String {
    value
        .iter()
        .flat_map(|byte| std::ascii::escape_default(*byte))
        .map(char::from)
        .collect()
}
