use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::require_root;

const PROTOCOL: u16 = 1;
const ROOT: &str = "/var/lib/syn/maintenance";
const RETAINED: &str = "/var/lib/syn/maintenance/synctl";
const CONFIG: &str = "/var/lib/syn/maintenance/config.json";
const AUTHORIZED_KEYS: &str = "/root/.ssh/authorized_keys";
const BOOTSTRAP_ROOT: &str = "/var/lib/syn/onboarding-bootstrap";
const HELPER: &str = "synctl-bootstrap";
const MAX_HELPER: u64 = 128 * 1024 * 1024;
const KEY_TAG: &str = "syn-maintenance-v1";
const FORCED_COMMAND: &str = "/var/lib/syn/maintenance/synctl --json maintenance serve";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Config {
    protocol: u16,
    managed_user: String,
    managed_uid: u32,
    public_key: String,
    authorized_keys_entry: String,
}

#[derive(Debug, Serialize)]
pub struct Report {
    protocol: u16,
    managed_user: String,
    action: &'static str,
    applied: bool,
}

#[derive(Debug, Eq, PartialEq)]
enum Request {
    Probe,
    Retain {
        operation: String,
        hash: String,
        size: u64,
    },
    Prepare {
        operation: String,
        request_hash: String,
        source_hash: String,
    },
    Phase {
        name: &'static str,
        operation: String,
    },
    Recover,
}

pub fn install(user: &str, public_key: &str, apply: bool) -> Result<Report> {
    validate_user(user)?;
    let (uid, _) = account(user)?;
    if uid == 0 {
        bail!("managed user must not be root");
    }
    let key = validate_public_key(public_key)?;
    let entry = authorized_entry(&key);
    if !apply {
        return Ok(Report {
            protocol: PROTOCOL,
            managed_user: user.into(),
            action: "install",
            applied: false,
        });
    }
    require_root()?;
    verify_sshd_and_root_shell()?;
    verify_current_bootstrap()?;
    if Path::new(CONFIG).try_exists()? {
        let existing = load_config()?;
        if existing.managed_user != user
            || existing.public_key != key
            || existing.authorized_keys_entry != entry
        {
            bail!("a different Syn maintenance identity is already installed; revoke it explicitly first");
        }
    }
    ensure_root_parent(Path::new("/var/lib/syn"))?;
    create_root_dir(Path::new(ROOT), 0o700)?;
    retain_current_executable()?;
    let config = Config {
        protocol: PROTOCOL,
        managed_user: user.into(),
        managed_uid: uid,
        public_key: key,
        authorized_keys_entry: entry.clone(),
    };
    write_config_once_or_exact(&config)?;
    install_authorized_entry(&entry)?;
    Ok(Report {
        protocol: PROTOCOL,
        managed_user: user.into(),
        action: "install",
        applied: true,
    })
}

pub fn revoke(apply: bool) -> Result<Report> {
    if apply {
        require_root()?;
    }
    let config = load_config()?;
    if apply {
        remove_exact_authorized_entry(&config.authorized_keys_entry)?;
        fs::remove_file(CONFIG)?;
        fs::remove_file(RETAINED)?;
        File::open(ROOT)?.sync_all()?;
    }
    Ok(Report {
        protocol: PROTOCOL,
        managed_user: config.managed_user,
        action: "revoke",
        applied: apply,
    })
}

pub fn serve() -> Result<()> {
    require_root()?;
    verify_protected_file(Path::new(RETAINED), Some(0o500), MAX_HELPER)?;
    let config = load_config()?;
    let original = std::env::var("SSH_ORIGINAL_COMMAND")
        .context("maintenance endpoint requires a forced SSH command")?;
    match parse_original(&original)? {
        Request::Probe => {
            println!(
                "{}",
                serde_json::json!({"ok": true, "data": {"protocol_version": PROTOCOL, "managed_user": config.managed_user}})
            );
            Ok(())
        }
        Request::Retain {
            operation,
            hash,
            size,
        } => {
            retain_incoming(&config, &operation, &hash, size)?;
            Ok(())
        }
        Request::Prepare {
            operation,
            request_hash,
            source_hash,
        } => {
            run_helper(
                &config,
                &operation,
                &[
                    "--json",
                    "onboard",
                    "prepare",
                    "--request-sha256",
                    &request_hash,
                    "--source-sha256",
                    &source_hash,
                    "--apply",
                ],
            )?;
            Ok(())
        }
        Request::Phase { name, operation } => {
            run_helper(
                &config,
                &operation,
                &[
                    "--json",
                    "onboard",
                    name,
                    "--operation-id",
                    &operation,
                    "--apply",
                ],
            )?;
            Ok(())
        }
        Request::Recover => {
            run_retained(
                &config,
                &["--json", "recover", "--restore-local-sudo", "--apply"],
            )?;
            Ok(())
        }
    }
}

fn parse_original(value: &str) -> Result<Request> {
    if value.len() > 512 {
        bail!("maintenance command is too large");
    }
    let words: Vec<_> = value.split(' ').collect();
    if words.iter().any(|word| word.is_empty()) || words.first() != Some(&KEY_TAG) {
        bail!("unauthorized maintenance command");
    }
    match words.as_slice() {
        [_, "probe"] => Ok(Request::Probe),
        [_, "retain", operation, hash, size] => {
            validate_hex(operation, 32, "operation ID")?;
            validate_hex(hash, 64, "helper hash")?;
            let size = size.parse::<u64>().context("helper size is invalid")?;
            if size == 0 || size > MAX_HELPER {
                bail!("helper size is outside the supported range");
            }
            Ok(Request::Retain {
                operation: (*operation).into(),
                hash: (*hash).into(),
                size,
            })
        }
        [_, "prepare", operation, request_hash, source_hash] => {
            validate_hex(operation, 32, "operation ID")?;
            validate_hex(request_hash, 64, "request hash")?;
            validate_hex(source_hash, 64, "source hash")?;
            Ok(Request::Prepare {
                operation: (*operation).into(),
                request_hash: (*request_hash).into(),
                source_hash: (*source_hash).into(),
            })
        }
        [_, name @ ("cleanup" | "build" | "configure" | "activate" | "complete"), operation] => {
            validate_hex(operation, 32, "operation ID")?;
            let name = match *name {
                "cleanup" => "cleanup",
                "build" => "build",
                "configure" => "configure",
                "activate" => "activate",
                "complete" => "complete",
                _ => unreachable!(),
            };
            Ok(Request::Phase {
                name,
                operation: (*operation).into(),
            })
        }
        [_, "recover"] => Ok(Request::Recover),
        _ => bail!("unauthorized maintenance command"),
    }
}

fn retain_incoming(
    config: &Config,
    operation: &str,
    expected_hash: &str,
    expected_size: u64,
) -> Result<()> {
    let (_, home) = account(&config.managed_user)?;
    let incoming = home.join(".cache/syn-setup/synctl-bootstrap.incoming");
    let source = open_user_file(&incoming, config.managed_uid, expected_size)?;
    create_root_dir(Path::new(BOOTSTRAP_ROOT), 0o700)?;
    let operation_dir = Path::new(BOOTSTRAP_ROOT).join(operation);
    if operation_dir.try_exists()? {
        let destination = operation_dir.join(HELPER);
        verify_operation_helper(&destination, operation, expected_size, expected_hash)?;
        return Ok(());
    }
    fs::create_dir(&operation_dir)?;
    fs::set_permissions(&operation_dir, fs::Permissions::from_mode(0o700))?;
    let destination = operation_dir.join(HELPER);
    if let Err(error) = copy_and_hash(source, &destination, expected_size, expected_hash) {
        let _ = fs::remove_file(&destination);
        let _ = fs::remove_dir(&operation_dir);
        return Err(error);
    }
    verify_operation_helper(&destination, operation, expected_size, expected_hash)
}

fn run_helper(config: &Config, operation: &str, arguments: &[&str]) -> Result<()> {
    let path = if arguments.get(2) == Some(&"prepare") {
        Path::new(BOOTSTRAP_ROOT).join(operation).join(HELPER)
    } else {
        Path::new("/var/lib/syn/onboarding")
            .join(operation)
            .join(HELPER)
    };
    verify_phase_helper(&path, operation, arguments.get(2) == Some(&"prepare"))?;
    run_clean(&path, config, arguments)
}

fn verify_phase_helper(path: &Path, operation: &str, bootstrap: bool) -> Result<()> {
    validate_hex(operation, 32, "operation ID")?;
    let expected = if bootstrap {
        Path::new(BOOTSTRAP_ROOT).join(operation).join(HELPER)
    } else {
        Path::new("/var/lib/syn/onboarding")
            .join(operation)
            .join(HELPER)
    };
    if path != expected {
        bail!("helper path does not match operation phase");
    }
    verify_protected_file(
        path,
        Some(if bootstrap { 0o500 } else { 0o700 }),
        MAX_HELPER,
    )?;
    Ok(())
}

fn run_retained(config: &Config, arguments: &[&str]) -> Result<()> {
    verify_protected_file(Path::new(RETAINED), Some(0o500), MAX_HELPER)?;
    run_clean(Path::new(RETAINED), config, arguments)
}

fn run_clean(program: &Path, config: &Config, arguments: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("SUDO_USER", &config.managed_user)
        .env("SUDO_UID", config.managed_uid.to_string())
        .current_dir("/")
        .args(arguments)
        .stdin(Stdio::null())
        .status()?;
    if !status.success() {
        bail!("maintenance operation failed");
    }
    Ok(())
}

fn verify_operation_helper(
    path: &Path,
    operation: &str,
    maximum_or_size: u64,
    expected_hash: &str,
) -> Result<()> {
    validate_hex(operation, 32, "operation ID")?;
    if path != Path::new(BOOTSTRAP_ROOT).join(operation).join(HELPER) {
        bail!("helper path does not match operation");
    }
    let meta = verify_protected_file(path, Some(0o500), maximum_or_size)?;
    if maximum_or_size != MAX_HELPER && meta.len() != maximum_or_size {
        bail!("helper size changed");
    }
    if !expected_hash.is_empty() && hash_file(path, maximum_or_size)? != expected_hash {
        bail!("helper hash does not match trusted command");
    }
    Ok(())
}

fn retain_current_executable() -> Result<()> {
    let source = fs::canonicalize(std::env::current_exe()?)?;
    verify_current_bootstrap()?;
    if Path::new(RETAINED).try_exists()? {
        verify_protected_file(Path::new(RETAINED), Some(0o500), MAX_HELPER)?;
        if hash_file(Path::new(RETAINED), MAX_HELPER)? != hash_file(&source, MAX_HELPER)? {
            bail!("retained maintenance helper differs; refusing replacement");
        }
        return Ok(());
    }
    let size = fs::metadata(&source)?.len();
    let hash = hash_file(&source, MAX_HELPER)?;
    copy_and_hash(File::open(&source)?, Path::new(RETAINED), size, &hash)
}

fn verify_current_bootstrap() -> Result<()> {
    let source = fs::canonicalize(std::env::current_exe()?)?;
    let parent = source.parent().context("helper has no parent")?;
    if parent.parent() == Some(Path::new(BOOTSTRAP_ROOT)) {
        let operation = parent
            .file_name()
            .and_then(|v| v.to_str())
            .context("invalid bootstrap operation")?;
        verify_operation_helper(&source, operation, MAX_HELPER, "")?;
    } else {
        if parent.parent() != Some(Path::new("/var/tmp"))
            || !parent
                .file_name()
                .and_then(|v| v.to_str())
                .is_some_and(|v| v.starts_with("syn-bootstrap."))
            || source.file_name().and_then(|v| v.to_str()) != Some("synctl")
        {
            bail!("initial maintenance helper is outside its private bootstrap directory");
        }
        let parent_meta = fs::symlink_metadata(parent)?;
        if !parent_meta.is_dir()
            || parent_meta.uid() != 0
            || parent_meta.gid() != 0
            || parent_meta.mode() & 0o7777 != 0o700
        {
            bail!("initial bootstrap directory is not private root-owned state");
        }
        let temporary = fs::symlink_metadata("/var/tmp")?;
        if !temporary.is_dir()
            || temporary.uid() != 0
            || temporary.gid() != 0
            || temporary.mode() & 0o7777 != 0o1777
        {
            bail!("bootstrap temporary parent must be root-owned and sticky");
        }
        verify_root_directory(Path::new("/var"))?;
        verify_protected_file_allowing_var_tmp(&source, 0o500, MAX_HELPER)?;
    }
    #[cfg(target_os = "linux")]
    {
        let path_meta = fs::metadata(&source)?;
        let loaded = fs::metadata("/proc/self/exe")?;
        if path_meta.dev() != loaded.dev() || path_meta.ino() != loaded.ino() {
            bail!("the executing maintenance helper changed before installation");
        }
    }
    Ok(())
}

fn verify_protected_file_allowing_var_tmp(path: &Path, mode: u32, maximum: u64) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.gid() != 0
        || meta.mode() & 0o7777 != mode
        || meta.len() == 0
        || meta.len() > maximum
    {
        bail!("initial helper is not protected root-owned state");
    }
    Ok(())
}

fn authorized_entry(key: &str) -> String {
    format!("restrict,no-user-rc,command=\"{FORCED_COMMAND}\" {key} {KEY_TAG}")
}

fn validate_public_key(value: &str) -> Result<String> {
    let words: Vec<_> = value.split_ascii_whitespace().collect();
    if words.len() != 2 || words[0] != "ssh-ed25519" {
        bail!("maintenance key must be one Ed25519 public key without a comment");
    }
    let decoded = STANDARD
        .decode(words[1])
        .context("maintenance public key is invalid base64")?;
    let algorithm = ssh_field(&decoded, 0)?;
    let key_offset = 4 + algorithm.len();
    let key = ssh_field(&decoded, key_offset)?;
    if algorithm != b"ssh-ed25519" || key.len() != 32 || key_offset + 4 + key.len() != decoded.len()
    {
        bail!("maintenance public key blob is invalid");
    }
    Ok(format!("ssh-ed25519 {}", words[1]))
}

fn ssh_field(bytes: &[u8], offset: usize) -> Result<&[u8]> {
    let length_bytes: [u8; 4] = bytes
        .get(offset..offset + 4)
        .context("maintenance public key blob is truncated")?
        .try_into()?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    bytes
        .get(offset + 4..offset + 4 + length)
        .context("maintenance public key blob is truncated")
}

fn install_authorized_entry(entry: &str) -> Result<()> {
    create_root_dir(Path::new("/root/.ssh"), 0o700)?;
    if Path::new(AUTHORIZED_KEYS).try_exists()? {
        verify_protected_file(Path::new(AUTHORIZED_KEYS), Some(0o600), 1024 * 1024)?;
        let text = fs::read_to_string(AUTHORIZED_KEYS)?;
        let tagged: Vec<_> = text
            .lines()
            .filter(|line| line.ends_with(KEY_TAG))
            .collect();
        if tagged.iter().any(|line| *line != entry) {
            bail!("a different Syn maintenance key entry already exists");
        }
        if tagged.len() > 1 {
            bail!("duplicate Syn maintenance key entries exist");
        }
        if tagged.len() == 1 {
            return Ok(());
        }
        let mut file = OpenOptions::new()
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(AUTHORIZED_KEYS)?;
        if !text.is_empty() && !text.ends_with('\n') {
            file.write_all(b"\n")?;
        }
        writeln!(file, "{entry}")?;
        file.sync_all()?;
        return Ok(());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(AUTHORIZED_KEYS)?;
    writeln!(file, "{entry}")?;
    file.sync_all()?;
    Ok(())
}

fn remove_exact_authorized_entry(entry: &str) -> Result<()> {
    verify_protected_file(Path::new(AUTHORIZED_KEYS), Some(0o600), 1024 * 1024)?;
    let text = fs::read_to_string(AUTHORIZED_KEYS)?;
    let mut removed = 0;
    let kept: Vec<_> = text
        .lines()
        .filter(|line| {
            if *line == entry {
                removed += 1;
                false
            } else {
                true
            }
        })
        .collect();
    if removed != 1 {
        bail!("exact installed maintenance key entry was not found once");
    }
    atomic_write(
        Path::new(AUTHORIZED_KEYS),
        format!(
            "{}{}",
            kept.join("\n"),
            if kept.is_empty() { "" } else { "\n" }
        )
        .as_bytes(),
        0o600,
    )
}

fn load_config() -> Result<Config> {
    verify_protected_file(Path::new(CONFIG), Some(0o600), 64 * 1024)?;
    let value: Config = serde_json::from_slice(&fs::read(CONFIG)?)?;
    if value.protocol != PROTOCOL
        || value.authorized_keys_entry != authorized_entry(&value.public_key)
    {
        bail!("maintenance configuration is invalid");
    }
    validate_user(&value.managed_user)?;
    validate_public_key(&value.public_key)?;
    let (uid, _) = account(&value.managed_user)?;
    if uid != value.managed_uid {
        bail!("managed account identity changed");
    }
    Ok(value)
}

fn write_config_once_or_exact(config: &Config) -> Result<()> {
    let bytes = serde_json::to_vec(config)?;
    if Path::new(CONFIG).try_exists()? {
        if fs::read(CONFIG)? != bytes {
            bail!("maintenance configuration differs; refusing replacement");
        }
        return Ok(());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(CONFIG)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn verify_sshd_and_root_shell() -> Result<()> {
    let (uid, _) = account("root")?;
    if uid != 0 {
        bail!("root account record is invalid");
    }
    let shell = root_shell()?;
    if matches!(
        shell.file_name().and_then(|value| value.to_str()),
        Some("nologin" | "false")
    ) {
        bail!("root account does not have a usable login shell");
    }
    for parent in shell
        .ancestors()
        .skip(1)
        .take_while(|path| *path != Path::new("/"))
    {
        verify_root_directory(parent)?;
    }
    let meta = fs::symlink_metadata(&shell)?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 || meta.mode() & 0o111 == 0 {
        bail!("root login shell is not trusted executable state");
    }
    let output = Command::new("/usr/sbin/sshd")
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .args(["-T", "-C", "user=root,host=localhost,addr=127.0.0.1"])
        .output()?;
    if !output.status.success() || !output.stderr.is_empty() {
        bail!("effective sshd configuration could not be verified");
    }
    let text = String::from_utf8(output.stdout)?;
    if !text.lines().any(|l| l == "pubkeyauthentication yes")
        || text.lines().any(|l| l == "permitrootlogin no")
    {
        bail!("sshd does not permit a forced root public-key command");
    }
    if !text.lines().any(|l| {
        l.split_whitespace().next() == Some("authorizedkeysfile")
            && l.contains(".ssh/authorized_keys")
    }) {
        bail!("sshd does not use root's standard authorized_keys file");
    }
    Ok(())
}

fn root_shell() -> Result<PathBuf> {
    let output = Command::new("/usr/bin/getent")
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .args(["passwd", "root"])
        .output()?;
    if !output.status.success() || !output.stderr.is_empty() {
        bail!("root account is unavailable");
    }
    let text = String::from_utf8(output.stdout)?;
    let fields: Vec<_> = text.trim_end().split(':').collect();
    if fields.len() != 7 || fields[0] != "root" {
        bail!("root account record is invalid");
    }
    let shell = PathBuf::from(fields[6]);
    if !shell.is_absolute() {
        bail!("root login shell path is unsafe");
    }
    Ok(shell)
}

fn create_root_dir(path: &Path, mode: u32) -> Result<()> {
    if !path.try_exists()? {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    verify_root_directory(path)?;
    let actual = fs::symlink_metadata(path)?.mode() & 0o7777;
    if actual != mode {
        bail!(
            "{} has mode {:o}; expected {:o}",
            path.display(),
            actual,
            mode
        );
    }
    Ok(())
}

fn ensure_root_parent(path: &Path) -> Result<()> {
    if !path.try_exists()? {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    verify_root_directory(path)
}

fn verify_root_directory(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.uid() != 0 || meta.gid() != 0 || meta.mode() & 0o022 != 0 {
        bail!("{} is not a protected root-owned directory", path.display());
    }
    Ok(())
}

fn verify_protected_file(
    path: &Path,
    exact_mode: Option<u32>,
    maximum: u64,
) -> Result<fs::Metadata> {
    for parent in path
        .ancestors()
        .skip(1)
        .take_while(|p| *p != Path::new("/"))
    {
        verify_root_directory(parent)?;
    }
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.gid() != 0
        || meta.mode() & 0o022 != 0
        || meta.len() == 0
        || meta.len() > maximum
    {
        bail!("{} is not a protected root-owned file", path.display());
    }
    if exact_mode.is_some_and(|mode| meta.mode() & 0o7777 != mode) {
        bail!("{} has an unsafe mode", path.display());
    }
    Ok(meta)
}

fn open_user_file(path: &Path, uid: u32, size: u64) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != uid || meta.len() != size || meta.mode() & 0o022 != 0 {
        bail!("incoming helper has unsafe ownership, mode, or size");
    }
    Ok(file)
}

fn copy_and_hash(
    mut source: File,
    destination: &Path,
    size: u64,
    expected_hash: &str,
) -> Result<()> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(destination)?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > size {
            bail!("incoming helper grew while copying");
        }
        hasher.update(&buffer[..count]);
        output.write_all(&buffer[..count])?;
    }
    output.sync_all()?;
    if total != size || hex::encode(hasher.finalize()) != expected_hash {
        bail!("incoming helper does not match trusted hash and size");
    }
    Ok(())
}

fn hash_file(path: &Path, maximum: u64) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > maximum {
            bail!("file is too large");
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let temporary = path.with_extension("syn-new");
    if temporary.try_exists()? {
        bail!("stale maintenance temporary file exists");
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    Ok(())
}

fn account(user: &str) -> Result<(u32, PathBuf)> {
    validate_user(user)?;
    let output = Command::new("/usr/bin/getent")
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .args(["passwd", user])
        .output()?;
    if !output.status.success() || !output.stderr.is_empty() {
        bail!("managed account is unavailable");
    }
    let text = String::from_utf8(output.stdout)?;
    let fields: Vec<_> = text.trim_end().split(':').collect();
    if fields.len() != 7 || fields[0] != user {
        bail!("managed account record is invalid");
    }
    Ok((fields[2].parse()?, PathBuf::from(fields[5])))
}

fn validate_user(value: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with('-')
        || value.len() > 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        bail!("managed user contains unsupported characters");
    }
    Ok(())
}
fn validate_hex(value: &str, length: usize, label: &str) -> Result<()> {
    if value.len() != length
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        bail!("{label} must be {length} lowercase hexadecimal characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const OP: &str = "0123456789abcdef0123456789abcdef";
    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    #[test]
    fn parses_fixed_vocabulary() {
        assert_eq!(
            parse_original("syn-maintenance-v1 probe").unwrap(),
            Request::Probe
        );
        assert!(matches!(
            parse_original(&format!("syn-maintenance-v1 retain {OP} {HASH} 123")).unwrap(),
            Request::Retain { size: 123, .. }
        ));
    }
    #[test]
    fn rejects_shell_syntax_and_extra_args() {
        for value in [
            "syn-maintenance-v1 probe; id",
            "syn-maintenance-v1 probe extra",
            "syn-maintenance-v1 build x",
            "rm -rf /",
            "syn-maintenance-v1  probe",
        ] {
            assert!(parse_original(value).is_err(), "accepted {value}");
        }
    }
    #[test]
    fn rejects_arbitrary_and_bad_tokens() {
        assert!(parse_original(&format!("syn-maintenance-v1 execute {OP}")).is_err());
        assert!(parse_original(&format!("syn-maintenance-v1 retain {OP} {HASH} 0")).is_err());
        assert!(
            parse_original(&format!("syn-maintenance-v1 prepare {OP} {HASH};x {HASH}")).is_err()
        );
    }
    #[test]
    fn validates_ed25519_key_shape() {
        assert!(validate_public_key("ssh-rsa AAAA").is_err());
        assert!(validate_public_key("ssh-ed25519 not-base64").is_err());
        assert!(validate_public_key("ssh-ed25519 AAAA comment").is_err());
        let mut blob = Vec::new();
        blob.extend_from_slice(&11_u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32_u32.to_be_bytes());
        blob.extend_from_slice(&[7; 32]);
        assert!(validate_public_key(&format!("ssh-ed25519 {}", STANDARD.encode(blob))).is_ok());
    }
    #[test]
    fn symlink_is_not_a_protected_file() {
        let root =
            std::env::temp_dir().join(format!("syn-maintenance-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        std::os::unix::fs::symlink("missing", root.join("helper")).unwrap();
        assert!(verify_protected_file(&root.join("helper"), None, 100).is_err());
        let _ = fs::remove_dir_all(root);
    }
}
