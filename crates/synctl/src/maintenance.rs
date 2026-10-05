use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
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
const WIRE_COMMAND: &str = "syn-maintenance";
const VERSION_FLAG: &str = "--protocol-version";
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
    if words.iter().any(|word| word.is_empty()) {
        bail!("unauthorized maintenance command");
    }
    match words.as_slice() {
        [WIRE_COMMAND, VERSION_FLAG, "1", "probe"] => Ok(Request::Probe),
        [WIRE_COMMAND, VERSION_FLAG, "1", "retain", operation, hash, size] => {
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
        [WIRE_COMMAND, VERSION_FLAG, "1", "prepare", operation, request_hash, source_hash] => {
            validate_hex(operation, 32, "operation ID")?;
            validate_hex(request_hash, 64, "request hash")?;
            validate_hex(source_hash, 64, "source hash")?;
            Ok(Request::Prepare {
                operation: (*operation).into(),
                request_hash: (*request_hash).into(),
                source_hash: (*source_hash).into(),
            })
        }
        [WIRE_COMMAND, VERSION_FLAG, "1", name @ ("cleanup" | "build" | "configure" | "activate" | "complete"), operation] =>
        {
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
        [WIRE_COMMAND, VERSION_FLAG, "1", "recover"] => Ok(Request::Recover),
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
        verify_authorized_keys_file(Path::new(AUTHORIZED_KEYS))?;
        let text = fs::read_to_string(AUTHORIZED_KEYS)?;
        let Some(append) = authorized_entry_append(&text, entry)? else {
            return Ok(());
        };
        let mut file = OpenOptions::new()
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(AUTHORIZED_KEYS)?;
        file.write_all(append.as_bytes())?;
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

fn authorized_entry_append(text: &str, entry: &str) -> Result<Option<String>> {
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
        return Ok(None);
    }
    Ok(Some(format!(
        "{}{}\n",
        if !text.is_empty() && !text.ends_with('\n') {
            "\n"
        } else {
            ""
        },
        entry
    )))
}

fn remove_exact_authorized_entry(entry: &str) -> Result<()> {
    verify_protected_file(Path::new(AUTHORIZED_KEYS), Some(0o600), 1024 * 1024)?;
    let text = fs::read_to_string(AUTHORIZED_KEYS)?;
    let updated = without_exact_authorized_entry(&text, entry)?;
    atomic_write(Path::new(AUTHORIZED_KEYS), updated.as_bytes(), 0o600)
}

fn without_exact_authorized_entry(text: &str, entry: &str) -> Result<String> {
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
    Ok(format!(
        "{}{}",
        kept.join("\n"),
        if kept.is_empty() { "" } else { "\n" }
    ))
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
    verify_root_shell_path(&shell)?;
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

fn verify_root_shell_path(shell: &Path) -> Result<()> {
    verify_shell_path_owned_by(shell, Path::new("/"), 0, 0)
}

fn verify_shell_path_owned_by(shell: &Path, boundary: &Path, uid: u32, gid: u32) -> Result<()> {
    if !shell.is_absolute()
        || !boundary.is_absolute()
        || shell
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        bail!("root login shell path is unsafe");
    }
    let boundary_meta = fs::symlink_metadata(boundary)?;
    if !boundary_meta.is_dir()
        || boundary_meta.uid() != uid
        || boundary_meta.gid() != gid
        || boundary_meta.mode() & 0o022 != 0
    {
        bail!("root login shell trust root is not protected");
    }

    let relative = shell
        .strip_prefix(boundary)
        .map_err(|_| anyhow::anyhow!("root login shell path is unsafe"))?;
    let mut components = relative.components();
    let resolved = if components.next() == Some(Component::Normal(std::ffi::OsStr::new("bin"))) {
        let bin = boundary.join("bin");
        let meta = fs::symlink_metadata(&bin)?;
        if meta.file_type().is_symlink() {
            let target = fs::read_link(&bin)?;
            let trusted_absolute = boundary.join("usr/bin");
            if meta.uid() != uid
                || meta.gid() != gid
                || (target != Path::new("usr/bin") && target != trusted_absolute)
            {
                bail!("root login shell uses an untrusted /bin link");
            }
            components.fold(boundary.join("usr/bin"), |path, component| {
                path.join(component.as_os_str())
            })
        } else {
            shell.to_path_buf()
        }
    } else {
        shell.to_path_buf()
    };

    for parent in resolved
        .ancestors()
        .skip(1)
        .take_while(|path| *path != boundary)
    {
        let meta = fs::symlink_metadata(parent)?;
        if !meta.is_dir() || meta.uid() != uid || meta.gid() != gid || meta.mode() & 0o022 != 0 {
            bail!("root login shell parent is not trusted");
        }
    }
    let meta = fs::symlink_metadata(&resolved)?;
    if !meta.is_file()
        || meta.uid() != uid
        || meta.gid() != gid
        || meta.mode() & 0o022 != 0
        || meta.mode() & 0o111 == 0
    {
        bail!("root login shell is not trusted executable state");
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
    verify_protected_file_state(path, exact_mode, maximum, false)
}

fn verify_authorized_keys_file(path: &Path) -> Result<fs::Metadata> {
    verify_protected_file_state(path, Some(0o600), 1024 * 1024, true)
}

fn verify_protected_file_state(
    path: &Path,
    exact_mode: Option<u32>,
    maximum: u64,
    allow_empty: bool,
) -> Result<fs::Metadata> {
    for parent in path
        .ancestors()
        .skip(1)
        .take_while(|p| *p != Path::new("/"))
    {
        verify_root_directory(parent)?;
    }
    let meta = fs::symlink_metadata(path)?;
    if !protected_file_metadata(&meta, maximum, allow_empty, 0, 0) {
        bail!("{} is not a protected root-owned file", path.display());
    }
    if exact_mode.is_some_and(|mode| meta.mode() & 0o7777 != mode) {
        bail!("{} has an unsafe mode", path.display());
    }
    Ok(meta)
}

fn protected_file_metadata(
    meta: &fs::Metadata,
    maximum: u64,
    allow_empty: bool,
    uid: u32,
    gid: u32,
) -> bool {
    meta.is_file()
        && meta.uid() == uid
        && meta.gid() == gid
        && meta.mode() & 0o022 == 0
        && (allow_empty || meta.len() != 0)
        && meta.len() <= maximum
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstalledRelease {
    pub schema_version: u16,
    pub release_id: String,
    pub commit: String,
}
pub(crate) fn installed_metadata() -> Result<Option<InstalledRelease>> {
    let path = Path::new("/usr/share/syn/release.json");
    if !path.try_exists()? {
        return Ok(None);
    }
    verify_protected_file(path, None, 16 * 1024)?;
    let release: InstalledRelease = serde_json::from_slice(&fs::read(path)?)?;
    validate_hex(&release.commit, 40, "installed commit")?;
    if release.schema_version != 1
        || release.release_id.len() != 14
        || !release.release_id.bytes().all(|b| b.is_ascii_digit())
    {
        bail!("invalid installed release metadata");
    }
    Ok(Some(release))
}
// Mobile setup retains its own helper and account binding. It never replaces
// the Mac's maintenance helper, configuration or authorized key.
const MOBILE_ROOT: &str = "/var/lib/syn/maintenance/mobile";
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MobileConfig {
    device_id: String,
    managed_gid: u32,
    allow_development: bool,
    binding: Config,
}
#[derive(Debug, Eq, PartialEq)]
enum MobileRequest {
    Enroll,
    Profile,
    Upload {
        artifact: &'static str,
        hash: String,
        size: u64,
    },
    Maintenance(Request),
}
pub(crate) fn validate_device(device: &str) -> Result<()> {
    if device.len() != 36
        || device.bytes().enumerate().any(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b != b'-'
            } else {
                !b.is_ascii_hexdigit() || b.is_ascii_uppercase()
            }
        })
    {
        bail!("invalid mobile device identifier");
    }
    Ok(())
}
fn mobile_directory(device: &str) -> Result<PathBuf> {
    validate_device(device)?;
    Ok(Path::new(MOBILE_ROOT).join(device))
}
fn mobile_entry(device: &str, key: &str) -> Result<String> {
    let retained = mobile_directory(device)?.join("synctl");
    Ok(format!("restrict,no-user-rc,command=\"{} --json maintenance serve-mobile --device-id {device}\" {key} syn-mobile-maintenance-v1:{device}", retained.display()))
}
fn load_mobile(device: &str) -> Result<MobileConfig> {
    let path = mobile_directory(device)?.join("config.json");
    verify_protected_file(&path, Some(0o600), 64 * 1024)?;
    let config: MobileConfig = serde_json::from_slice(&fs::read(&path)?)?;
    let (uid, _) = account(&config.binding.managed_user)?;
    if config.device_id != device
        || config.binding.protocol != PROTOCOL
        || uid == 0
        || uid != config.binding.managed_uid
        || account_gid(&config.binding.managed_user)? != config.managed_gid
        || config.binding.authorized_keys_entry != mobile_entry(device, &config.binding.public_key)?
    {
        bail!("mobile maintenance account or identity changed");
    }
    validate_public_key(&config.binding.public_key)?;
    Ok(config)
}
fn account_gid(user: &str) -> Result<u32> {
    validate_user(user)?;
    let output = Command::new("/usr/bin/id")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args(["-g", user])
        .output()?;
    if !output.status.success() || !output.stderr.is_empty() {
        bail!("managed group is unavailable");
    }
    Ok(String::from_utf8(output.stdout)?.trim().parse()?)
}
pub fn install_mobile(
    user: &str,
    device: &str,
    key: &str,
    allow_development: bool,
    apply: bool,
) -> Result<Report> {
    validate_device(device)?;
    validate_user(user)?;
    let (uid, _) = account(user)?;
    let gid = account_gid(user)?;
    if uid == 0 || gid == 0 {
        bail!("mobile setup requires a non-root account and group");
    }
    let key = validate_public_key(key)?;
    let entry = mobile_entry(device, &key)?;
    if apply {
        require_root()?;
        verify_sshd_and_root_shell()?;
        verify_current_bootstrap()?;
        ensure_root_parent(Path::new("/var/lib/syn"))?;
        create_root_dir(Path::new(ROOT), 0o700)?;
        create_root_dir(Path::new(MOBILE_ROOT), 0o700)?;
        let dir = mobile_directory(device)?;
        if !dir.try_exists()? && fs::read_dir(MOBILE_ROOT)?.count() >= 8 {
            bail!("too many phone setup identities");
        }
        create_root_dir(&dir, 0o700)?;
        let config = MobileConfig {
            device_id: device.into(),
            managed_gid: gid,
            allow_development,
            binding: Config {
                protocol: PROTOCOL,
                managed_user: user.into(),
                managed_uid: uid,
                public_key: key.clone(),
                authorized_keys_entry: entry.clone(),
            },
        };
        let config_path = dir.join("config.json");
        let bytes = serde_json::to_vec(&config)?;
        if config_path.try_exists()? {
            load_mobile(device)?;
            if fs::read(&config_path)? != bytes {
                bail!("phone setup binding differs; revoke it explicitly first");
            }
        }
        let retained = dir.join("synctl");
        let source = fs::canonicalize(std::env::current_exe()?)?;
        let size = fs::metadata(&source)?.len();
        let hash = hash_file(&source, MAX_HELPER)?;
        if retained.try_exists()? {
            verify_protected_file(&retained, Some(0o500), MAX_HELPER)?;
            if hash_file(&retained, MAX_HELPER)? != hash {
                bail!("phone retained helper differs; refusing replacement");
            }
        } else {
            copy_and_hash(File::open(source)?, &retained, size, &hash)?;
        }
        if !config_path.try_exists()? {
            atomic_write(&config_path, &bytes, 0o600)?;
        }
        create_root_dir(Path::new("/root/.ssh"), 0o700)?;
        let mut text = if Path::new(AUTHORIZED_KEYS).try_exists()? {
            verify_authorized_keys_file(Path::new(AUTHORIZED_KEYS))?;
            fs::read_to_string(AUTHORIZED_KEYS)?
        } else {
            String::new()
        };
        if let Some(append) = mobile_entry_append(&text, &entry, device, &key)? {
            text.push_str(&append);
            atomic_write(Path::new(AUTHORIZED_KEYS), text.as_bytes(), 0o600)?;
        }
    }
    Ok(Report {
        protocol: PROTOCOL,
        managed_user: user.into(),
        action: "install-mobile",
        applied: apply,
    })
}
fn mobile_entry_append(text: &str, entry: &str, device: &str, key: &str) -> Result<Option<String>> {
    let tag = format!("syn-mobile-maintenance-v1:{device}");
    let existing: Vec<_> = text.lines().filter(|line| line.ends_with(&tag)).collect();
    if existing.len() > 1
        || existing.iter().any(|line| *line != entry)
        || text
            .lines()
            .any(|line| line.contains(&format!(" {key} ")) && line != entry)
    {
        bail!("phone maintenance key or tagged entry conflicts with existing SSH authorization");
    }
    if existing.len() == 1 {
        return Ok(None);
    }
    Ok(Some(format!(
        "{}{}\n",
        if text.is_empty() || text.ends_with('\n') {
            ""
        } else {
            "\n"
        },
        entry
    )))
}
fn parse_mobile(value: &str) -> Result<MobileRequest> {
    if value.len() > 512 {
        bail!("mobile command is too large");
    }
    let words: Vec<_> = value.split(' ').collect();
    match words.as_slice() {
        ["syn-mobile", VERSION_FLAG, "1", "enroll"] => Ok(MobileRequest::Enroll),
        ["syn-mobile", VERSION_FLAG, "1", "profile"] => Ok(MobileRequest::Profile),
        ["syn-mobile", VERSION_FLAG, "1", "upload", artifact, hash, size] => {
            let (artifact, maximum) = match *artifact {
                "source" => ("source", 2 * 1024 * 1024 * 1024),
                "helper" => ("helper", MAX_HELPER),
                "request" => ("request", 64 * 1024),
                _ => bail!("unsupported phone setup artifact"),
            };
            validate_hex(hash, 64, "artifact hash")?;
            let size: u64 = size.parse()?;
            if size == 0 || size > maximum {
                bail!("artifact size is outside the supported range");
            }
            Ok(MobileRequest::Upload {
                artifact,
                hash: (*hash).into(),
                size,
            })
        }
        ["syn-mobile", rest @ ..] => Ok(MobileRequest::Maintenance(parse_original(&format!(
            "syn-maintenance {}",
            rest.join(" ")
        ))?)),
        _ => bail!("unauthorized phone maintenance command"),
    }
}
pub(crate) fn validate_mobile_request(
    request: &crate::onboarding::OnboardingRequest,
) -> Result<()> {
    let Some(device) = &request.approver_device_id else {
        return Ok(());
    };
    let config = load_mobile(device)?;
    validate_mobile_binding(request, &config)
}
fn validate_mobile_binding(
    request: &crate::onboarding::OnboardingRequest,
    config: &MobileConfig,
) -> Result<()> {
    if request.approver_device_id.as_deref() != Some(config.device_id.as_str())
        || request.managed_user != config.binding.managed_user
        || (request.development_signer && !config.allow_development)
    {
        bail!("phone operation exceeds its device, account or development-signer authorization");
    }
    Ok(())
}
fn verify_mobile_operation(
    config: &MobileConfig,
    operation: &str,
    incoming: Option<&str>,
) -> Result<()> {
    validate_hex(operation, 32, "operation ID")?;
    let bytes = if let Some(hash) = incoming {
        let (_, home) = account(&config.binding.managed_user)?;
        let path = home
            .join(crate::onboarding::INCOMING_DIRECTORY)
            .join(crate::onboarding::REQUEST_NAME);
        let meta = fs::symlink_metadata(&path)?;
        if meta.len() == 0 || meta.len() > 64 * 1024 {
            bail!("setup request is too large");
        }
        let mut file = open_user_file(&path, config.binding.managed_uid, meta.len())?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        if hex::encode(Sha256::digest(&bytes)) != hash {
            bail!("setup request hash changed");
        }
        bytes
    } else {
        let path = Path::new(crate::onboarding::STAGING_ROOT)
            .join(operation)
            .join("request.json");
        verify_protected_file(&path, Some(0o600), 64 * 1024)?;
        fs::read(path)?
    };
    let request: crate::onboarding::OnboardingRequest = serde_json::from_slice(&bytes)?;
    if request.operation_id != operation {
        bail!("setup operation changed");
    }
    validate_mobile_binding(&request, config)
}
pub fn serve_mobile(device: &str) -> Result<()> {
    require_root()?;
    let config = load_mobile(device)?;
    let retained = mobile_directory(device)?.join("synctl");
    verify_protected_file(&retained, Some(0o500), MAX_HELPER)?;
    let original =
        std::env::var("SSH_ORIGINAL_COMMAND").context("forced phone command required")?;
    match parse_mobile(&original)? {
        MobileRequest::Enroll => crate::approvers::enroll_mobile(device, config.allow_development),
        MobileRequest::Profile => crate::approvers::print_profile(device),
        MobileRequest::Upload {
            artifact,
            hash,
            size,
        } => receive_mobile(&config, artifact, &hash, size),
        MobileRequest::Maintenance(Request::Probe) => {
            let output = Command::new("/usr/sbin/ip")
                .env_clear()
                .env("PATH", "/usr/sbin:/usr/bin:/bin")
                .args(["-j", "address", "show"])
                .output()?;
            if !output.status.success() || !output.stderr.is_empty() {
                bail!("machine addresses are unavailable");
            }
            let addresses: Vec<_> = crate::interface_addresses(&output.stdout)?
                .into_iter()
                .map(|(_, ip)| ip)
                .filter(|ip| !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast())
                .collect();
            let target_id = if Path::new(syn_config::DEFAULT_AGENT_CONFIG).try_exists()? {
                Some(syn_config::AgentConfig::load(syn_config::DEFAULT_AGENT_CONFIG)?.target_id)
            } else {
                None
            };
            let installed = installed_metadata()?;
            println!(
                "{}",
                serde_json::json!({"ok":true,"data":{"protocol_version":1,"managed_user":config.binding.managed_user,
                "device_id":device,"allow_development":config.allow_development,"listen_ips":addresses,"target_id":target_id,"installed_release_id":installed.as_ref().map(|v| &v.release_id),"installed_release_commit":installed.as_ref().map(|v| &v.commit)}})
            );
            Ok(())
        }
        MobileRequest::Maintenance(Request::Retain {
            operation,
            hash,
            size,
        }) => retain_incoming(&config.binding, &operation, &hash, size),
        MobileRequest::Maintenance(Request::Prepare {
            operation,
            request_hash,
            source_hash,
        }) => {
            verify_mobile_operation(&config, &operation, Some(&request_hash))?;
            run_helper(
                &config.binding,
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
            )
        }
        MobileRequest::Maintenance(Request::Phase { name, operation }) => {
            verify_mobile_operation(&config, &operation, None)?;
            run_helper(
                &config.binding,
                &operation,
                &[
                    "--json",
                    "onboard",
                    name,
                    "--operation-id",
                    &operation,
                    "--apply",
                ],
            )
        }
        MobileRequest::Maintenance(Request::Recover) => run_clean(
            &retained,
            &config.binding,
            &["--json", "recover", "--restore-local-sudo", "--apply"],
        ),
    }
}
#[cfg(target_os = "linux")]
fn receive_mobile(config: &MobileConfig, artifact: &str, hash: &str, size: u64) -> Result<()> {
    let (_, home) = account(&config.binding.managed_user)?;
    // No elevated identity may touch the user's upload directory. This is the
    // end of one forced SSH request, so privileges are dropped permanently.
    #[cfg(target_os = "linux")]
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0
            || libc::setgid(config.managed_gid) != 0
            || libc::setuid(config.binding.managed_uid) != 0
        {
            bail!("unable to drop phone upload privileges");
        }
        if libc::getuid() != config.binding.managed_uid
            || libc::geteuid() != config.binding.managed_uid
            || libc::getgid() != config.managed_gid
            || libc::getegid() != config.managed_gid
            || libc::getgroups(0, std::ptr::null_mut()) != 0
        {
            bail!("phone upload retained root identity");
        }
    }
    #[cfg(target_os = "linux")]
    {
        let directory = home.join(crate::onboarding::INCOMING_DIRECTORY);
        for path in [&home, &home.join(".cache"), &directory] {
            if !path.try_exists()? {
                fs::create_dir(path)?;
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            }
            let meta = fs::symlink_metadata(path)?;
            if !meta.is_dir()
                || meta.uid() != config.binding.managed_uid
                || meta.mode() & 0o022 != 0
            {
                bail!("unsafe phone upload directory");
            }
        }
        receive_checked(&directory, artifact, hash, size, std::io::stdin().lock())?;
        println!(
            "{}",
            serde_json::json!({"ok":true,"data":{"artifact":artifact,"size_bytes":size,"sha256":hash}})
        );
        Ok(())
    }
}
#[cfg(not(target_os = "linux"))]
fn receive_mobile(_config: &MobileConfig, _artifact: &str, _hash: &str, _size: u64) -> Result<()> {
    bail!("phone setup uploads require Linux")
}
#[cfg(any(target_os = "linux", test))]
fn receive_checked(
    directory: &Path,
    artifact: &str,
    hash: &str,
    size: u64,
    input: impl Read,
) -> Result<()> {
    let name = match artifact {
        "source" => "source.incoming",
        "helper" => "synctl-bootstrap.incoming",
        "request" => "request.incoming",
        _ => bail!("unsupported upload"),
    };
    let destination = directory.join(name);
    let temporary = directory.join(format!(".{name}.{}", std::process::id()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        let mut input = input.take(size + 1);
        let mut hasher = Sha256::new();
        let mut count = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let n = input.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            count += n as u64;
            if count > size {
                bail!("upload exceeds its exact size");
            }
            hasher.update(&buffer[..n]);
            file.write_all(&buffer[..n])?;
        }
        if count != size || hex::encode(hasher.finalize()) != hash {
            bail!("upload does not match trusted bytes");
        }
        file.sync_all()?;
        if fs::symlink_metadata(&destination).is_ok_and(|m| !m.is_file() || m.nlink() != 1) {
            bail!("unsafe existing upload");
        }
        fs::rename(&temporary, &destination)?;
        File::open(directory)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}
pub fn revoke_mobile(device: &str, apply: bool) -> Result<Report> {
    require_root()?;
    let config = load_mobile(device)?;
    if apply {
        remove_exact_authorized_entry(&config.binding.authorized_keys_entry)?;
        let dir = mobile_directory(device)?;
        fs::remove_file(dir.join("config.json"))?;
        fs::remove_file(dir.join("synctl"))?;
        fs::remove_dir(dir)?;
        File::open(MOBILE_ROOT)?.sync_all()?;
    }
    Ok(Report {
        protocol: PROTOCOL,
        managed_user: config.binding.managed_user,
        action: "revoke-mobile",
        applied: apply,
    })
}
pub(crate) fn revoke_mobile_if_present(device: &str) -> Result<()> {
    if mobile_directory(device)?.join("config.json").try_exists()? {
        revoke_mobile(device, true)?;
    }
    Ok(())
}
pub fn revoke_all_mobile() -> Result<()> {
    if !Path::new(MOBILE_ROOT).try_exists()? {
        return Ok(());
    }
    verify_root_directory(Path::new(MOBILE_ROOT))?;
    for entry in fs::read_dir(MOBILE_ROOT)? {
        let device = entry?
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("invalid phone directory"))?;
        revoke_mobile(&device, true)?;
    }
    Ok(())
}

#[cfg(test)]
mod mobile_tests {
    use super::*;
    const DEVICE: &str = "00000000-0000-4000-8000-000000000001";
    #[test]
    fn mobile_golden_and_account_device_development_binding() {
        let bytes =
            include_str!("../../../macos/Tests/SynTests/Fixtures/mobile-onboarding-v1.json");
        let request: crate::onboarding::OnboardingRequest = serde_json::from_str(bytes).unwrap();
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            serde_json::from_str::<serde_json::Value>(bytes).unwrap()
        );
        let mut config = MobileConfig {
            device_id: DEVICE.into(),
            managed_gid: 1000,
            allow_development: true,
            binding: Config {
                protocol: 1,
                managed_user: "developer".into(),
                managed_uid: 1000,
                public_key: String::new(),
                authorized_keys_entry: String::new(),
            },
        };
        validate_mobile_binding(&request, &config).unwrap();
        config.allow_development = false;
        assert!(validate_mobile_binding(&request, &config).is_err());
        config.allow_development = true;
        config.device_id = "00000000-0000-4000-8000-000000000002".into();
        assert!(validate_mobile_binding(&request, &config).is_err());
        config.device_id = DEVICE.into();
        config.binding.managed_user = "other-user".into();
        assert!(validate_mobile_binding(&request, &config).is_err());
        let mut value: serde_json::Value = serde_json::from_str(bytes).unwrap();
        value["executor"] = serde_json::json!("unauthorized");
        assert!(serde_json::from_value::<crate::onboarding::OnboardingRequest>(value).is_err());
    }
    #[test]
    fn mobile_protocol_rejects_executors_paths_versions_and_bad_sizes() {
        assert_eq!(
            parse_mobile("syn-mobile --protocol-version 1 probe").unwrap(),
            MobileRequest::Maintenance(Request::Probe)
        );
        for invalid in [
            "syn-mobile --protocol-version 2 probe",
            "syn-mobile --protocol-version 1 exec true",
            "syn-mobile --protocol-version 1 recover;id",
            "syn-mobile  --protocol-version 1 profile",
            "syn-mobile --protocol-version 1 upload ../../etc/passwd x 2",
        ] {
            assert!(parse_mobile(invalid).is_err(), "{invalid}");
        }
        let hash = "a".repeat(64);
        assert!(parse_mobile(&format!(
            "syn-mobile --protocol-version 1 upload helper {hash} 0"
        ))
        .is_err());
        assert!(parse_mobile(&format!(
            "syn-mobile --protocol-version 1 upload request {hash} 65537"
        ))
        .is_err());
        assert!(validate_device(DEVICE).is_ok());
        assert!(validate_device("00000000-0000-4000-8000-00000000000/").is_err());
    }
    #[test]
    fn phone_key_append_and_revoke_preserve_other_authorizations() {
        let key = "ssh-ed25519 public-test-only";
        let entry = mobile_entry(DEVICE, key).unwrap();
        let existing = "unrelated administrator key\nMac restricted key syn-maintenance-v1\n";
        let addition = mobile_entry_append(existing, &entry, DEVICE, key)
            .unwrap()
            .unwrap();
        let updated = format!("{existing}{addition}");
        assert!(mobile_entry_append(&updated, &entry, DEVICE, key)
            .unwrap()
            .is_none());
        assert_eq!(
            without_exact_authorized_entry(&updated, &entry).unwrap(),
            existing
        );
        assert!(mobile_entry_append(
            &format!("restrict {key} another-phone\n"),
            &entry,
            DEVICE,
            key
        )
        .is_err());
    }
    #[test]
    fn upload_rejects_partial_grown_changed_and_symlink_bytes_atomically() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!("syn-mobile-upload-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let bytes = b"public test artifact";
        let hash = hex::encode(Sha256::digest(bytes));
        receive_checked(&dir, "source", &hash, bytes.len() as u64, &bytes[..]).unwrap();
        let destination = dir.join("source.incoming");
        for (size, data, digest) in [
            (bytes.len() as u64, &bytes[..3], hash.clone()),
            (3, &bytes[..], hash.clone()),
            (bytes.len() as u64, &bytes[..], "0".repeat(64)),
        ] {
            assert!(receive_checked(&dir, "source", &digest, size, data).is_err());
            assert_eq!(fs::read(&destination).unwrap(), bytes);
        }
        fs::remove_file(&destination).unwrap();
        let outside = dir.join("outside");
        fs::write(&outside, b"retained").unwrap();
        symlink(&outside, &destination).unwrap();
        assert!(receive_checked(&dir, "source", &hash, bytes.len() as u64, &bytes[..]).is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"retained");
        fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    const OP: &str = "0123456789abcdef0123456789abcdef";
    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    fn shell_fixture(absolute_link: bool) -> (PathBuf, u32, u32) {
        let root = std::env::temp_dir().join(format!(
            "syn-shell-test-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("usr")).unwrap();
        fs::create_dir(root.join("usr/bin")).unwrap();
        fs::write(root.join("usr/bin/bash"), b"test shell").unwrap();
        fs::set_permissions(root.join("usr/bin/bash"), fs::Permissions::from_mode(0o755)).unwrap();
        let target = if absolute_link {
            root.join("usr/bin")
        } else {
            PathBuf::from("usr/bin")
        };
        std::os::unix::fs::symlink(target, root.join("bin")).unwrap();
        let meta = fs::symlink_metadata(&root).unwrap();
        (root, meta.uid(), meta.gid())
    }

    #[test]
    fn parses_cross_language_maintenance_vectors() {
        let vectors: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../tests/fixtures/maintenance-requests-v1.json"
        ))
        .unwrap();
        for vector in vectors {
            let kind = vector["kind"].as_str().unwrap();
            let command = vector["command"].as_str().unwrap();
            let expected = match kind {
                "probe" => Request::Probe,
                "retain" => Request::Retain {
                    operation: OP.into(),
                    hash: HASH.into(),
                    size: 123,
                },
                "prepare" => Request::Prepare {
                    operation: OP.into(),
                    request_hash: HASH.into(),
                    source_hash: HASH.into(),
                },
                "cleanup" => Request::Phase {
                    name: "cleanup",
                    operation: OP.into(),
                },
                "build" => Request::Phase {
                    name: "build",
                    operation: OP.into(),
                },
                "configure" => Request::Phase {
                    name: "configure",
                    operation: OP.into(),
                },
                "activate" => Request::Phase {
                    name: "activate",
                    operation: OP.into(),
                },
                "complete" => Request::Phase {
                    name: "complete",
                    operation: OP.into(),
                },
                "recover" => Request::Recover,
                _ => panic!("unknown maintenance request vector: {kind}"),
            };
            assert_eq!(parse_original(command).unwrap(), expected, "vector {kind}");
        }
    }
    #[test]
    fn rejects_shell_syntax_and_extra_args() {
        for value in [
            "syn-maintenance --protocol-version 1 probe; id",
            "syn-maintenance --protocol-version 1 probe extra",
            "syn-maintenance --protocol-version 1 build x",
            "rm -rf /",
            "syn-maintenance --protocol-version 1  probe",
            "syn-maintenance --protocol-version 1 probe\tid",
            "syn-maintenance --protocol-version 1 probe\nid",
        ] {
            assert!(parse_original(value).is_err(), "accepted {value}");
        }
    }
    #[test]
    fn rejects_arbitrary_and_bad_tokens() {
        assert!(parse_original(&format!(
            "syn-maintenance --protocol-version 1 execute {OP}"
        ))
        .is_err());
        assert!(parse_original(&format!(
            "syn-maintenance --protocol-version 1 retain {OP} {HASH} 0"
        ))
        .is_err());
        assert!(parse_original(&format!(
            "syn-maintenance --protocol-version 1 prepare {OP} {HASH};x {HASH}"
        ))
        .is_err());
    }
    #[test]
    fn rejects_old_or_malformed_protocol_prefixes() {
        for value in [
            "syn-maintenance-v1 probe",
            "syn-maintenance probe",
            "syn-maintenance --protocol-version probe",
            "syn-maintenance --protocol-version 2 probe",
            "syn-maintenance --protocol-version 1 --protocol-version 1 probe",
            "syn-maintenance --version 1 probe",
            "syn-maintenance --protocol-version=1 probe",
            "syn-maintenance 1 --protocol-version probe",
        ] {
            assert!(parse_original(value).is_err(), "accepted {value}");
        }
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

    #[test]
    fn bootstrap_copy_rejects_substituted_helper_with_trusted_hash() {
        let root = std::env::temp_dir().join(format!(
            "syn-bootstrap-hash-test-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let source = root.join("synctl-bootstrap.incoming");
        let destination = root.join("synctl-bootstrap");
        let trusted = b"trusted bootstrap helper";
        let substituted = vec![b'x'; trusted.len()];
        fs::write(&source, &substituted).unwrap();

        let error = copy_and_hash(
            File::open(&source).unwrap(),
            &destination,
            trusted.len() as u64,
            &hex::encode(Sha256::digest(trusted)),
        )
        .unwrap_err();
        let message = error.to_string();
        let _ = fs::remove_dir_all(root);
        assert_eq!(
            message,
            "incoming helper does not match trusted hash and size"
        );
    }

    #[test]
    fn empty_authorized_keys_install_revoke_reinstall_lifecycle() {
        let entry = "restrict ssh-ed25519 test syn-maintenance-v1";
        let installed = authorized_entry_append("", entry).unwrap().unwrap();
        assert_eq!(installed, format!("{entry}\n"));
        assert!(authorized_entry_append(&installed, entry)
            .unwrap()
            .is_none());

        let revoked = without_exact_authorized_entry(&installed, entry).unwrap();
        assert!(revoked.is_empty());
        assert_eq!(
            authorized_entry_append(&revoked, entry).unwrap().unwrap(),
            format!("{entry}\n")
        );
    }

    #[test]
    fn only_authorized_keys_may_use_protected_empty_file_state() {
        let root = std::env::temp_dir().join(format!(
            "syn-authorized-keys-test-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("authorized_keys");
        fs::write(&path, []).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let meta = fs::symlink_metadata(&path).unwrap();
        assert!(protected_file_metadata(
            &meta,
            1024 * 1024,
            true,
            meta.uid(),
            meta.gid()
        ));
        assert!(!protected_file_metadata(
            &meta,
            1024 * 1024,
            false,
            meta.uid(),
            meta.gid()
        ));
        assert!(!protected_file_metadata(
            &meta,
            1024 * 1024,
            true,
            meta.uid() + 1,
            meta.gid()
        ));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o622)).unwrap();
        let writable = fs::symlink_metadata(&path).unwrap();
        assert!(!protected_file_metadata(
            &writable,
            1024 * 1024,
            true,
            writable.uid(),
            writable.gid()
        ));
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("missing", &path).unwrap();
        let symlink = fs::symlink_metadata(&path).unwrap();
        assert!(!protected_file_metadata(
            &symlink,
            1024 * 1024,
            true,
            symlink.uid(),
            symlink.gid()
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn accepts_relative_and_absolute_usrmerge_root_shell_links() {
        for absolute_link in [false, true] {
            let (root, uid, gid) = shell_fixture(absolute_link);
            assert!(verify_shell_path_owned_by(&root.join("bin/bash"), &root, uid, gid).is_ok());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn accepts_root_shell_in_real_bin_directory() {
        let (root, uid, gid) = shell_fixture(false);
        fs::remove_file(root.join("bin")).unwrap();
        fs::create_dir(root.join("bin")).unwrap();
        fs::copy(root.join("usr/bin/bash"), root.join("bin/bash")).unwrap();
        assert!(verify_shell_path_owned_by(&root.join("bin/bash"), &root, uid, gid).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_usrmerge_shell_with_writable_resolved_parent() {
        let (root, uid, gid) = shell_fixture(false);
        fs::set_permissions(root.join("usr/bin"), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(verify_shell_path_owned_by(&root.join("bin/bash"), &root, uid, gid).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_usrmerge_shell_with_wrong_bin_target() {
        let (root, uid, gid) = shell_fixture(false);
        fs::remove_file(root.join("bin")).unwrap();
        std::os::unix::fs::symlink("usr/local/bin", root.join("bin")).unwrap();
        assert!(verify_shell_path_owned_by(&root.join("bin/bash"), &root, uid, gid).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_usrmerge_shell_with_chained_bin_target() {
        let (root, uid, gid) = shell_fixture(false);
        fs::remove_file(root.join("bin")).unwrap();
        fs::create_dir(root.join("alias")).unwrap();
        std::os::unix::fs::symlink("../usr/bin", root.join("alias/bin")).unwrap();
        std::os::unix::fs::symlink("alias/bin", root.join("bin")).unwrap();
        assert!(verify_shell_path_owned_by(&root.join("bin/bash"), &root, uid, gid).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_non_executable_usrmerge_shell() {
        let (root, uid, gid) = shell_fixture(false);
        fs::set_permissions(root.join("usr/bin/bash"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(verify_shell_path_owned_by(&root.join("bin/bash"), &root, uid, gid).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
