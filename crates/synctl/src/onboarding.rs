use std::fs;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use syn_config::{
    AgentConfig, PluginConfig, Policy, DEFAULT_AGENT_CONFIG, DEFAULT_INSTALL_STATE,
    DEFAULT_PLUGIN_CONFIG, DEFAULT_POLICY_PATH,
};
use syn_protocol::{
    generate_signing_key, signing_key_to_pem, verifying_key_from_pem, verifying_key_sec1,
    verifying_key_to_pem,
};

use crate::require_root;

pub const INCOMING_DIRECTORY: &str = ".cache/syn-setup";
pub const REQUEST_NAME: &str = "request.incoming";
pub const SOURCE_NAME: &str = "source.incoming";
pub const STAGING_ROOT: &str = "/var/lib/syn/onboarding";
pub const BOOTSTRAP_HELPER_NAME: &str = "synctl-bootstrap";
pub const BOOTSTRAP_ROOT: &str = "/var/lib/syn/onboarding-bootstrap";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_SOURCE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_HELPER_BYTES: u64 = 128 * 1024 * 1024;
const BUILD_ROOT: &str = "/var/lib/syn-build";
const BUILD_HOME: &str = "/var/lib/syn-build/home";
const BUILD_USER: &str = "syn-build";
const FIRST_REGULAR_UID: u32 = 1_000;
const BUILD_GROUP_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
const APPROVAL_PUBLIC: &str = "/etc/syn/keys/approval-public.pem";
const DENIAL_PUBLIC: &str = "/etc/syn/keys/denial-public.pem";
const TARGET_PRIVATE: &str = "/etc/syn/keys/target-private.pem";
const TARGET_PUBLIC: &str = "/etc/syn/keys/target-public.pem";
const TLS_PRIVATE: &str = "/etc/syn/tls/target-key.pem";
const TLS_CERTIFICATE: &str = "/etc/syn/tls/target-cert.pem";
const CLIENT_CA: &str = "/etc/syn/tls/approver-ca.pem";
const BUILD_DEPENDENCIES: &[&str] = &[
    "binutils",
    "build-essential",
    "cargo",
    "dpkg-dev",
    "libpam0g-dev",
    "openssl",
    "python3",
    "rustc",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OnboardingRequest {
    pub schema_version: u16,
    pub operation_id: String,
    pub release_id: String,
    pub release_commit: String,
    pub managed_user: String,
    pub target_id: String,
    pub display_name: String,
    pub hostname: String,
    pub listen_ip: IpAddr,
    pub client_identity_label: String,
    pub approval_public_x963_base64: String,
    pub denial_public_x963_base64: String,
    pub client_certificate_pem_base64: String,
    pub source_sha256: String,
    pub source_size_bytes: u64,
    pub helper_sha256: String,
    pub helper_size_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct OnboardingPlan {
    pub applied: bool,
    pub operation_id: String,
    pub release_id: String,
    pub release_commit: String,
    pub managed_user: String,
    pub target_id: String,
    pub listen: String,
    pub staging_directory: PathBuf,
    pub actions: Vec<&'static str>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OnboardingJournal {
    schema_version: u16,
    operation_id: String,
    release_id: String,
    release_commit: String,
    phase: String,
    managed_user: String,
    managed_uid: u32,
    request_sha256: String,
    source_sha256: String,
    helper_sha256: String,
    helper_size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    package_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_deadline_unix_seconds: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BuildReport {
    pub operation_id: String,
    pub release_id: String,
    pub package_sha256: String,
    pub dependencies_installed: bool,
    pub phase: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct PairingReport {
    pub operation_id: String,
    pub release_id: String,
    pub target: MacTargetProfile,
    pub phase: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct ActivationReport {
    pub operation_id: String,
    pub release_id: String,
    pub approved: bool,
    pub recovery_armed: bool,
    pub phase: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct CompletionReport {
    pub operation_id: String,
    pub release_id: String,
    pub approved: bool,
    pub recovery_armed: bool,
    pub phase: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct CleanupReport {
    pub operation_id: String,
    pub cleaned: bool,
    pub phase: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct MacTargetProfile {
    #[serde(rename = "targetID")]
    target_id: String,
    #[serde(rename = "displayName")]
    display_name: String,
    #[serde(rename = "webSocketURL")]
    web_socket_url: String,
    #[serde(rename = "targetPublicKeyBase64")]
    target_public_key_base64: String,
    #[serde(rename = "serverCertificateSHA256Hex")]
    server_certificate_sha256_hex: String,
    #[serde(rename = "clientIdentityLabel")]
    client_identity_label: String,
}

struct HelperSource {
    path: PathBuf,
    metadata: fs::Metadata,
    source_uid: u32,
    protected_uid: u32,
    bootstrap_operation_id: Option<String>,
}

struct OnboardingLock(fs::File);

impl OnboardingLock {
    fn acquire() -> Result<Self> {
        let path = Path::new(STAGING_ROOT).join(".transition.lock");
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o7777 != 0o600
        {
            bail!("onboarding transition lock has unsafe ownership or mode");
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error()).context("lock onboarding transition");
        }
        Ok(Self(file))
    }
}

impl Drop for OnboardingLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActivationStep {
    Continue,
    AdoptArmedInstall,
    Done,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompletionStep {
    Verify,
    Disarm,
    Done,
}

fn activation_step(
    phase: &str,
    install_state_present: bool,
    managed_rule_present: bool,
) -> Result<ActivationStep> {
    if matches!(
        phase,
        "armed_pending_final_approval" | "completion_verified" | "complete"
    ) {
        return Ok(ActivationStep::Done);
    }
    if install_state_present != managed_rule_present {
        bail!("activation has partial sudo state; recover local sudo before retrying");
    }
    if install_state_present {
        return Ok(ActivationStep::AdoptArmedInstall);
    }
    Ok(ActivationStep::Continue)
}

fn completion_step(phase: &str) -> Result<CompletionStep> {
    match phase {
        "armed_pending_final_approval" => Ok(CompletionStep::Verify),
        "completion_verified" => Ok(CompletionStep::Disarm),
        "complete" => Ok(CompletionStep::Done),
        _ => bail!("onboarding journal is not ready for completion"),
    }
}

pub fn prepare(
    expected_request_sha256: &str,
    expected_source_sha256: &str,
    apply: bool,
) -> Result<OnboardingPlan> {
    require_root()?;
    let helper = current_helper_source()?;
    let sudo_user = std::env::var("SUDO_USER").context("Mac-led setup must be run through sudo")?;
    let (uid, home) = account(&sudo_user)?;
    if uid == 0 {
        bail!("Mac-led setup requires a non-root SSH account");
    }
    let incoming = home.join(INCOMING_DIRECTORY);
    let address_output = fixed_command("/usr/sbin/ip")
        .args(["-j", "address", "show"])
        .stdin(Stdio::null())
        .output()?;
    if !address_output.status.success() || !address_output.stderr.is_empty() {
        bail!("remote network addresses could not be verified");
    }
    let assigned: Vec<_> = crate::interface_addresses(&address_output.stdout)?
        .into_iter()
        .map(|(_, address)| address)
        .collect();
    prepare_from(
        &incoming,
        Path::new(STAGING_ROOT),
        &helper,
        &sudo_user,
        uid,
        expected_request_sha256,
        expected_source_sha256,
        Some(&assigned),
        apply,
    )
}

// Keep each privilege and path boundary explicit at this security-sensitive
// entry point rather than hiding test or production identities in globals.
#[allow(clippy::too_many_arguments)]
fn prepare_from(
    incoming: &Path,
    staging_root: &Path,
    helper: &HelperSource,
    sudo_user: &str,
    sudo_uid: u32,
    expected_request_sha256: &str,
    expected_source_sha256: &str,
    assigned_addresses: Option<&[IpAddr]>,
    apply: bool,
) -> Result<OnboardingPlan> {
    validate_sha256(expected_request_sha256, "request")?;
    validate_sha256(expected_source_sha256, "source")?;
    let request_path = incoming.join(REQUEST_NAME);
    let source_path = incoming.join(SOURCE_NAME);
    let request_bytes = read_verified_user_file(
        &request_path,
        sudo_uid,
        MAX_REQUEST_BYTES,
        expected_request_sha256,
    )?;
    let request: OnboardingRequest =
        serde_json::from_slice(&request_bytes).context("onboarding request is not valid JSON")?;
    validate_request(&request, sudo_user, expected_source_sha256)?;
    if helper.bootstrap_operation_id.as_deref() != Some(request.operation_id.as_str()) {
        bail!("bootstrap helper path does not match the onboarding operation");
    }
    verify_helper_source(helper, request.helper_size_bytes, &request.helper_sha256)?;
    if assigned_addresses.is_some_and(|addresses| !addresses.contains(&request.listen_ip)) {
        bail!("selected listen address is not assigned to this remote machine");
    }

    let source_metadata = verified_user_metadata(
        &source_path,
        sudo_uid,
        MAX_SOURCE_BYTES,
        Some(request.source_size_bytes),
    )?;
    // Preview still hashes the full archive. A stale UI must never claim a
    // candidate is ready merely because its path and stated size exist.
    verify_user_file_hash(&source_path, &source_metadata, expected_source_sha256)?;

    let staging_directory = staging_root.join(&request.operation_id);
    let plan = OnboardingPlan {
        applied: apply,
        operation_id: request.operation_id.clone(),
        release_id: request.release_id.clone(),
        release_commit: request.release_commit.clone(),
        managed_user: request.managed_user.clone(),
        target_id: request.target_id.clone(),
        listen: format!("{}:{}", request.listen_ip, syn_config::DEFAULT_LISTEN_PORT),
        staging_directory: staging_directory.clone(),
        actions: vec![
            "copy the verified request and source into a new root-owned operation directory",
            "build as Syn's locked non-administrator build account",
            "install the exact matching package before changing sudo",
            "pair this Mac and start the direct approval connection",
            "arm recovery immediately before activating Syn's sudo gate",
        ],
    };
    if !apply {
        return Ok(plan);
    }
    if staging_directory.exists() || staging_directory.is_symlink() {
        validate_existing_prepared_operation(
            &staging_directory,
            helper.protected_uid,
            sudo_uid,
            &request,
            expected_request_sha256,
            expected_source_sha256,
        )?;
        return Ok(plan);
    }
    fs::create_dir_all(staging_root)?;
    fs::set_permissions(staging_root, fs::Permissions::from_mode(0o700))?;
    let staging_metadata = fs::symlink_metadata(staging_root)?;
    if !staging_metadata.is_dir()
        || staging_metadata.uid() != helper.protected_uid
        || staging_metadata.mode() & 0o777 != 0o700
    {
        bail!("onboarding staging root has unsafe ownership or mode");
    }
    fs::create_dir(&staging_directory)?;
    fs::set_permissions(&staging_directory, fs::Permissions::from_mode(0o700))?;

    let result = (|| -> Result<()> {
        write_new_root_file(
            &staging_directory.join("request.json"),
            &request_bytes,
            0o600,
        )?;
        copy_verified_user_file(
            &source_path,
            &staging_directory.join("source.tar.gz"),
            &source_metadata,
            expected_source_sha256,
        )?;
        copy_verified_helper(
            helper,
            &staging_directory.join(BOOTSTRAP_HELPER_NAME),
            request.helper_size_bytes,
            &request.helper_sha256,
        )?;
        let journal = OnboardingJournal {
            schema_version: 1,
            operation_id: request.operation_id,
            release_id: request.release_id,
            release_commit: request.release_commit,
            phase: "candidate_staged".into(),
            managed_user: request.managed_user,
            managed_uid: sudo_uid,
            request_sha256: expected_request_sha256.into(),
            source_sha256: expected_source_sha256.into(),
            helper_sha256: request.helper_sha256,
            helper_size_bytes: request.helper_size_bytes,
            package_sha256: None,
            recovery_deadline_unix_seconds: None,
        };
        write_new_root_file(
            &staging_directory.join("journal.json"),
            &serde_json::to_vec_pretty(&journal)?,
            0o600,
        )?;
        fs::File::open(&staging_directory)?.sync_all()?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&staging_directory);
        return Err(error);
    }
    Ok(plan)
}

fn validate_existing_prepared_operation(
    operation: &Path,
    protected_uid: u32,
    managed_uid: u32,
    request: &OnboardingRequest,
    expected_request_sha256: &str,
    expected_source_sha256: &str,
) -> Result<()> {
    let metadata = fs::symlink_metadata(operation)?;
    if !metadata.is_dir() || metadata.uid() != protected_uid || metadata.mode() & 0o077 != 0 {
        bail!("existing onboarding operation directory is unsafe");
    }
    let journal_path = operation.join("journal.json");
    validate_owned_file(&journal_path, protected_uid, 0o600, 64 * 1024)?;
    let journal: OnboardingJournal = serde_json::from_slice(&fs::read(&journal_path)?)?;
    if journal.schema_version != 1
        || journal.operation_id != request.operation_id
        || journal.release_id != request.release_id
        || journal.release_commit != request.release_commit
        || journal.managed_user != request.managed_user
        || journal.managed_uid != managed_uid
        || journal.request_sha256 != expected_request_sha256
        || journal.source_sha256 != expected_source_sha256
        || journal.helper_sha256 != request.helper_sha256
        || journal.helper_size_bytes != request.helper_size_bytes
        || !matches!(
            journal.phase.as_str(),
            "candidate_staged"
                | "package_built"
                | "paired_pending_approval"
                | "activation_recovery_armed"
                | "armed_pending_final_approval"
                | "completion_verified"
                | "complete"
        )
    {
        bail!("existing onboarding operation does not match this exact request");
    }
    let request_path = operation.join("request.json");
    validate_owned_file(&request_path, protected_uid, 0o600, MAX_REQUEST_BYTES)?;
    if hash_regular_file(&request_path, MAX_REQUEST_BYTES, Some(protected_uid))?
        != expected_request_sha256
    {
        bail!("existing protected onboarding request differs from this retry");
    }
    let source_path = operation.join("source.tar.gz");
    validate_owned_file(&source_path, protected_uid, 0o600, MAX_SOURCE_BYTES)?;
    if fs::metadata(&source_path)?.len() != request.source_size_bytes
        || hash_regular_file(&source_path, MAX_SOURCE_BYTES, Some(protected_uid))?
            != expected_source_sha256
    {
        bail!("existing protected onboarding source differs from this retry");
    }
    let helper_path = operation.join(BOOTSTRAP_HELPER_NAME);
    validate_owned_file(&helper_path, protected_uid, 0o700, MAX_HELPER_BYTES)?;
    if fs::metadata(&helper_path)?.len() != request.helper_size_bytes
        || hash_regular_file(&helper_path, MAX_HELPER_BYTES, Some(protected_uid))?
            != request.helper_sha256
    {
        bail!("existing protected onboarding helper differs from this retry");
    }
    Ok(())
}

pub fn build(operation_id: &str, apply: bool) -> Result<BuildReport> {
    require_root()?;
    let _onboarding = OnboardingLock::acquire()?;
    validate_hex(operation_id, 32, "operation ID")?;
    let operation = Path::new(STAGING_ROOT).join(operation_id);
    let mut journal = load_journal(&operation, &["candidate_staged", "package_built"])?;
    let request = load_protected_request(&operation, &journal)?;
    validate_protected_source(&operation, &journal, &request)?;
    if journal.phase == "package_built" {
        let package_sha256 = validate_protected_package(&operation, &journal, &request)?;
        return Ok(BuildReport {
            operation_id: operation_id.into(),
            release_id: journal.release_id,
            package_sha256,
            dependencies_installed: missing_dependencies()?.is_empty(),
            phase: "package_built",
        });
    }
    if Path::new(DEFAULT_INSTALL_STATE).exists() {
        bail!("restore ordinary password sudo before building an update");
    }
    let missing = missing_dependencies()?;
    let report = BuildReport {
        operation_id: operation_id.into(),
        release_id: journal.release_id.clone(),
        package_sha256: String::new(),
        dependencies_installed: missing.is_empty(),
        phase: if apply {
            "package_built"
        } else {
            "build_planned"
        },
    };
    if !apply {
        return Ok(report);
    }
    ensure_build_root()?;
    ensure_build_account()?;
    if !missing.is_empty() {
        run_quiet("/usr/bin/apt-get", &["update"])?;
        let mut arguments = vec!["install", "-y", "--no-install-recommends"];
        arguments.extend(BUILD_DEPENDENCIES.iter().copied());
        run_quiet("/usr/bin/apt-get", &arguments)?;
    }
    let work = Path::new(BUILD_ROOT).join(operation_id);
    if work.exists() || work.is_symlink() {
        bail!("build workspace already exists; recover or use a new operation");
    }
    fs::create_dir(&work)?;
    chown(&work, BUILD_USER, BUILD_USER)?;
    fs::set_permissions(&work, fs::Permissions::from_mode(0o700))?;

    let result = (|| -> Result<String> {
        let build_home = work.join("home");
        fs::create_dir(&build_home)?;
        chown(&build_home, BUILD_USER, BUILD_USER)?;
        fs::set_permissions(&build_home, fs::Permissions::from_mode(0o700))?;
        let input_directory = work.join("input");
        fs::create_dir(&input_directory)?;
        chown(&input_directory, "root", BUILD_USER)?;
        fs::set_permissions(&input_directory, fs::Permissions::from_mode(0o750))?;
        let build_source = input_directory.join("source.tar.gz");
        copy_protected_source_for_build(
            &operation.join("source.tar.gz"),
            &build_source,
            request.source_size_bytes,
            &journal.source_sha256,
        )?;
        chown(&build_source, "root", BUILD_USER)?;
        fs::set_permissions(&build_source, fs::Permissions::from_mode(0o440))?;
        run_clean_quiet(
            "/usr/sbin/runuser",
            &[
                "-u",
                BUILD_USER,
                "--",
                "/usr/bin/tar",
                "--extract",
                "--gzip",
                "--file",
                build_source
                    .to_str()
                    .context("build source path is not UTF-8")?,
                "--directory",
                work.to_str().context("build path is not UTF-8")?,
                "--no-same-owner",
                "--no-same-permissions",
            ],
            Path::new("/"),
            &build_home,
        )?;
        let source_root = work.join(format!("syn-remote-source-{}", request.release_id));
        let source_root_metadata = fs::symlink_metadata(&source_root)?;
        let work_metadata = fs::symlink_metadata(&work)?;
        if !source_root_metadata.is_dir() || source_root_metadata.uid() != work_metadata.uid() {
            bail!("archive release root is not an isolated build-user directory");
        }
        let release_metadata = source_root.join("release/release.json");
        verify_archived_release(&release_metadata, &request)?;
        let output_directory = work.join("dist");
        fs::create_dir(&output_directory)?;
        chown(&output_directory, BUILD_USER, BUILD_USER)?;
        let target_directory = work.join("target");
        let cargo_home = work.join("cargo-home");
        fs::create_dir(&cargo_home)?;
        chown(&cargo_home, BUILD_USER, BUILD_USER)?;
        fs::set_permissions(&cargo_home, fs::Permissions::from_mode(0o700))?;
        let environment = [
            format!("HOME={}", build_home.display()),
            "USER=syn-build".into(),
            "LOGNAME=syn-build".into(),
            "LANG=C".into(),
            "LC_ALL=C".into(),
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin".into(),
            format!("CARGO_HOME={}", cargo_home.display()),
            format!("CARGO_TARGET_DIR={}", target_directory.display()),
            format!("SYN_RELEASE_METADATA={}", release_metadata.display()),
            "SYN_CARGO=/usr/bin/cargo".into(),
        ];
        let mut command = Command::new("/usr/sbin/runuser");
        command
            .env_clear()
            .current_dir(&source_root)
            .process_group(0)
            .args(["-u", BUILD_USER, "--", "/usr/bin/env", "-i"])
            .args(&environment)
            .arg("/bin/sh")
            .arg(source_root.join("scripts/build-deb.sh"))
            .arg(&output_directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let status = run_isolated_build(&mut command)?;
        if !status.success() {
            bail!("isolated remote build failed");
        }
        let package =
            output_directory.join(format!("syn-approvals_{}_arm64.deb", request.release_id));
        let protected_package = operation.join("syn-approvals.deb");
        let snapshot = (|| -> Result<String> {
            copy_new_file_limited(&package, &protected_package, 0o600, MAX_SOURCE_BYTES)?;
            let digest = hash_regular_file(&protected_package, MAX_SOURCE_BYTES, Some(0))?;
            validate_built_package(&protected_package, &request.release_id)?;
            fs::File::open(&operation)?.sync_all()?;
            Ok(digest)
        })();
        if snapshot.is_err() {
            let _ = fs::remove_file(&protected_package);
        }
        snapshot
    })();
    let _ = fs::remove_dir_all(&work);
    let package_sha256 = result?;
    journal.phase = "package_built".into();
    journal.package_sha256 = Some(package_sha256.clone());
    write_journal(&operation, &journal)?;
    Ok(BuildReport {
        package_sha256,
        dependencies_installed: true,
        ..report
    })
}

pub fn configure(operation_id: &str, apply: bool) -> Result<PairingReport> {
    require_root()?;
    let _onboarding = OnboardingLock::acquire()?;
    validate_hex(operation_id, 32, "operation ID")?;
    let operation = Path::new(STAGING_ROOT).join(operation_id);
    let mut journal = load_journal(
        &operation,
        &[
            "package_built",
            "paired_pending_approval",
            "activation_recovery_armed",
            "armed_pending_final_approval",
            "completion_verified",
            "complete",
        ],
    )?;
    let request = load_protected_request(&operation, &journal)?;
    let package = operation.join("syn-approvals.deb");
    validate_protected_package(&operation, &journal, &request)?;
    if journal.phase != "package_built" {
        validate_live_configuration(&request, journal.managed_uid)?;
        return Ok(PairingReport {
            operation_id: operation_id.into(),
            release_id: request.release_id.clone(),
            target: live_profile(&request)?,
            phase: "paired_pending_approval",
        });
    }
    if !apply {
        return Ok(PairingReport {
            operation_id: operation_id.into(),
            release_id: request.release_id.clone(),
            target: planned_profile(&request),
            phase: "configuration_planned",
        });
    }
    if Path::new(DEFAULT_INSTALL_STATE).exists()
        || Path::new("/etc/sudoers.d/90-syn-managed-user").exists()
    {
        bail!("restore ordinary password sudo before installing an update");
    }
    crate::recovery_timer::prepare_helper(&operation.join(BOOTSTRAP_HELPER_NAME))?;
    run_quiet(
        "/usr/bin/dpkg",
        &[
            "--install",
            package.to_str().context("package path is not UTF-8")?,
        ],
    )?;
    configure_identities(&request)?;
    configure_target(&request, journal.managed_uid)?;
    run_quiet(
        "/usr/bin/systemctl",
        &["enable", "--now", "syn-agent.service"],
    )?;
    run_quiet(
        "/usr/bin/systemctl",
        &["is-active", "--quiet", "syn-agent.service"],
    )?;
    let target = live_profile(&request)?;
    journal.phase = "paired_pending_approval".into();
    write_journal(&operation, &journal)?;
    Ok(PairingReport {
        operation_id: operation_id.into(),
        release_id: request.release_id,
        target,
        phase: "paired_pending_approval",
    })
}

pub fn activate(operation_id: &str, apply: bool) -> Result<ActivationReport> {
    require_root()?;
    let _onboarding = OnboardingLock::acquire()?;
    validate_hex(operation_id, 32, "operation ID")?;
    let operation = Path::new(STAGING_ROOT).join(operation_id);
    let mut journal = load_journal(
        &operation,
        &[
            "paired_pending_approval",
            "activation_recovery_armed",
            "armed_pending_final_approval",
            "completion_verified",
            "complete",
        ],
    )?;
    let request = load_protected_request(&operation, &journal)?;
    if !apply {
        return Ok(ActivationReport {
            operation_id: operation_id.into(),
            release_id: request.release_id,
            approved: false,
            recovery_armed: false,
            phase: "activation_planned",
        });
    }
    let install_state_present = Path::new(DEFAULT_INSTALL_STATE).try_exists()?;
    let managed_rule_present = Path::new("/etc/sudoers.d/90-syn-managed-user").try_exists()?;
    match activation_step(&journal.phase, install_state_present, managed_rule_present)? {
        ActivationStep::Done => {
            verify_installed_release(&request)?;
            crate::installer::check_installed_coupling(Path::new(DEFAULT_INSTALL_STATE))?;
            let phase = match journal.phase.as_str() {
                "complete" => "complete",
                "completion_verified" => "completion_verified",
                _ => "armed_pending_final_approval",
            };
            return Ok(ActivationReport {
                operation_id: operation_id.into(),
                release_id: request.release_id,
                approved: true,
                recovery_armed: crate::recovery_timer::status().armed,
                phase,
            });
        }
        ActivationStep::AdoptArmedInstall => {
            verify_installed_release(&request)?;
            crate::installer::check_installed_coupling(Path::new(DEFAULT_INSTALL_STATE))?;
            require_operation_recovery_timer(&journal)?;
            journal.phase = "armed_pending_final_approval".into();
            write_journal(&operation, &journal)?;
            return Ok(ActivationReport {
                operation_id: operation_id.into(),
                release_id: request.release_id,
                approved: true,
                recovery_armed: true,
                phase: "armed_pending_final_approval",
            });
        }
        ActivationStep::Continue => {}
    }

    // Recovery may have fired after the timer was journaled but before the
    // installer completed. Once both privileged artifacts are absent and the
    // timer is fully gone, this operation can safely return to its pre-arm
    // checkpoint. Never rewrite or extend a live or inconsistent timer.
    if journal.phase == "activation_recovery_armed" {
        let current = crate::recovery_timer::status();
        if current.status == "not_armed" {
            journal.phase = "paired_pending_approval".into();
            journal.recovery_deadline_unix_seconds = None;
            write_journal(&operation, &journal)?;
        } else {
            require_operation_recovery_timer(&journal)?;
        }
    }
    crate::preflight::test_approval(Path::new(DEFAULT_PLUGIN_CONFIG), true)?;
    if journal.phase == "paired_pending_approval" {
        let current = crate::recovery_timer::status();
        let deadline = if current.armed {
            current
                .deadline_unix_seconds
                .context("armed recovery timer has no deadline")?
        } else if current.status == "not_armed" {
            crate::recovery_timer::arm(15, true)?
                .deadline_unix_seconds
                .context("new recovery timer has no deadline")?
        } else {
            bail!("recovery state is inconsistent; recover it before activation");
        };
        journal.recovery_deadline_unix_seconds = Some(deadline);
        journal.phase = "activation_recovery_armed".into();
        write_journal(&operation, &journal)?;
    }
    require_operation_recovery_timer(&journal)?;
    let plan = crate::installer::plan(
        &request.managed_user,
        Path::new(DEFAULT_INSTALL_STATE),
        false,
    )?;
    if !plan.blockers.is_empty() {
        let blockers = plan.blockers.join("; ");
        // A concurrent legacy installer could have created privileged state
        // after our first check. In that case the recovery timer is the safety
        // boundary and must remain armed for the operator to recover.
        if Path::new(DEFAULT_INSTALL_STATE).try_exists()?
            || Path::new("/etc/sudoers.d/90-syn-managed-user").try_exists()?
        {
            bail!(
                "activation is blocked after privileged state appeared; recovery remains armed: {blockers}"
            );
        }
        crate::recovery_timer::cancel(true)?;
        journal.phase = "paired_pending_approval".into();
        journal.recovery_deadline_unix_seconds = None;
        write_journal(&operation, &journal)?;
        bail!("activation is blocked: {blockers}");
    }
    crate::installer::apply(plan, Path::new(DEFAULT_INSTALL_STATE))?;
    let _transition = crate::recovery_worker::TransitionLock::acquire()?;
    require_operation_recovery_timer(&journal)?;
    verify_installed_release(&request)?;
    crate::installer::check_installed_coupling(Path::new(DEFAULT_INSTALL_STATE))?;
    journal.phase = "armed_pending_final_approval".into();
    write_journal(&operation, &journal)?;
    Ok(ActivationReport {
        operation_id: operation_id.into(),
        release_id: request.release_id,
        approved: true,
        recovery_armed: crate::recovery_timer::status().armed,
        phase: "armed_pending_final_approval",
    })
}

pub fn complete(operation_id: &str, apply: bool) -> Result<CompletionReport> {
    require_root()?;
    let _onboarding = OnboardingLock::acquire()?;
    validate_hex(operation_id, 32, "operation ID")?;
    let operation = Path::new(STAGING_ROOT).join(operation_id);
    let mut journal = load_journal(
        &operation,
        &[
            "armed_pending_final_approval",
            "completion_verified",
            "complete",
        ],
    )?;
    let request = load_protected_request(&operation, &journal)?;
    verify_installed_release(&request)?;
    validate_live_configuration(&request, journal.managed_uid)?;
    crate::installer::check_installed_coupling(Path::new(DEFAULT_INSTALL_STATE))?;
    if completion_step(&journal.phase)? == CompletionStep::Done {
        return Ok(CompletionReport {
            operation_id: operation_id.into(),
            release_id: request.release_id,
            approved: true,
            recovery_armed: crate::recovery_timer::status().armed,
            phase: "complete",
        });
    }
    if !apply {
        return Ok(CompletionReport {
            operation_id: operation_id.into(),
            release_id: request.release_id,
            approved: false,
            recovery_armed: crate::recovery_timer::status().armed,
            phase: "completion_planned",
        });
    }
    if completion_step(&journal.phase)? == CompletionStep::Verify {
        require_operation_recovery_timer(&journal)?;
        crate::preflight::test_approval(Path::new(DEFAULT_PLUGIN_CONFIG), false)?;
        let _transition = crate::recovery_worker::TransitionLock::acquire()?;
        crate::installer::check_installed_coupling(Path::new(DEFAULT_INSTALL_STATE))?;
        verify_installed_release(&request)?;
        validate_live_configuration(&request, journal.managed_uid)?;
        require_operation_recovery_timer(&journal)?;
        crate::recovery_timer::commit_helper(&operation.join(BOOTSTRAP_HELPER_NAME))?;
        journal.phase = "completion_verified".into();
        write_journal(&operation, &journal)?;
    }
    let _transition = crate::recovery_worker::TransitionLock::acquire()?;
    crate::installer::check_installed_coupling(Path::new(DEFAULT_INSTALL_STATE))?;
    verify_installed_release(&request)?;
    validate_live_configuration(&request, journal.managed_uid)?;
    crate::recovery_timer::cancel(true)?;
    // Recovery may have removed the passwordless rule before waiting for our
    // transition lock. A stopped timer alone cannot prove healthy completion.
    crate::installer::check_installed_coupling(Path::new(DEFAULT_INSTALL_STATE))?;
    verify_installed_release(&request)?;
    validate_live_configuration(&request, journal.managed_uid)?;
    if crate::recovery_timer::status().status != "not_armed" {
        bail!("automatic recovery did not finish disarming");
    }
    journal.phase = "complete".into();
    write_journal(&operation, &journal)?;
    Ok(CompletionReport {
        operation_id: operation_id.into(),
        release_id: request.release_id,
        approved: true,
        recovery_armed: crate::recovery_timer::status().armed,
        phase: "complete",
    })
}

pub fn cleanup(operation_id: &str, apply: bool) -> Result<CleanupReport> {
    require_root()?;
    let _onboarding = OnboardingLock::acquire()?;
    validate_hex(operation_id, 32, "operation ID")?;
    let operation = Path::new(STAGING_ROOT).join(operation_id);
    let journal = load_journal(
        &operation,
        &[
            "candidate_staged",
            "package_built",
            "paired_pending_approval",
        ],
    )?;
    if Path::new(DEFAULT_INSTALL_STATE).try_exists()?
        || Path::new("/etc/sudoers.d/90-syn-managed-user").try_exists()?
    {
        bail!("bootstrap staging cleanup is allowed only before sudo activation");
    }
    if !apply {
        return Ok(CleanupReport {
            operation_id: operation_id.into(),
            cleaned: false,
            phase: "cleanup_planned",
        });
    }

    let bootstrap = Path::new(BOOTSTRAP_ROOT)
        .join(operation_id)
        .join(BOOTSTRAP_HELPER_NAME);
    let bootstrap_operation = Path::new(BOOTSTRAP_ROOT).join(operation_id);
    if bootstrap_operation.try_exists()?
        && validate_bootstrap_helper_path(&bootstrap)? != operation_id
    {
        bail!("bootstrap cleanup path does not match the operation");
    }
    if bootstrap.try_exists()? {
        validate_owned_file(&bootstrap, 0, 0o500, MAX_HELPER_BYTES)?;
        if hash_regular_file(&bootstrap, MAX_HELPER_BYTES, Some(0))? != journal.helper_sha256 {
            bail!("bootstrap helper differs from the protected operation");
        }
        fs::remove_file(&bootstrap)?;
        fs::File::open(
            bootstrap
                .parent()
                .context("bootstrap helper has no parent")?,
        )?
        .sync_all()?;
    }
    if bootstrap_operation.try_exists()? {
        fs::remove_dir(&bootstrap_operation)?;
        fs::File::open(BOOTSTRAP_ROOT)?.sync_all()?;
    }
    Ok(CleanupReport {
        operation_id: operation_id.into(),
        cleaned: true,
        phase: "staging_cleaned",
    })
}

fn load_journal(operation: &Path, expected_phases: &[&str]) -> Result<OnboardingJournal> {
    validate_root_directory(operation)?;
    let path = operation.join("journal.json");
    validate_root_file(&path, 64 * 1024)?;
    let journal: OnboardingJournal = serde_json::from_slice(&fs::read(path)?)?;
    if journal.schema_version != 1
        || !expected_phases.contains(&journal.phase.as_str())
        || journal.release_id != syn_protocol::release_id()
        || journal.release_commit != syn_protocol::release_commit()
        || operation.file_name().and_then(|value| value.to_str()) != Some(&journal.operation_id)
    {
        bail!("onboarding journal is not in the required release-bound phase");
    }
    validate_operation_helper(operation, &journal)?;
    Ok(journal)
}

fn load_protected_request(
    operation: &Path,
    journal: &OnboardingJournal,
) -> Result<OnboardingRequest> {
    let path = operation.join("request.json");
    validate_root_file(&path, MAX_REQUEST_BYTES)?;
    let bytes = fs::read(path)?;
    if hex::encode(Sha256::digest(&bytes)) != journal.request_sha256 {
        bail!("protected onboarding request differs from the journal");
    }
    let request: OnboardingRequest = serde_json::from_slice(&bytes)?;
    validate_request(&request, &journal.managed_user, &journal.source_sha256)?;
    if request.operation_id != journal.operation_id {
        bail!("onboarding request operation differs from the journal");
    }
    Ok(request)
}

fn write_journal(operation: &Path, journal: &OnboardingJournal) -> Result<()> {
    crate::atomic_write(
        &operation.join("journal.json"),
        &serde_json::to_vec_pretty(journal)?,
        0o600,
    )
}

fn require_operation_recovery_timer(journal: &OnboardingJournal) -> Result<()> {
    let expected = journal
        .recovery_deadline_unix_seconds
        .context("onboarding journal has no recovery deadline")?;
    let current = crate::recovery_timer::status();
    if !current.armed || current.deadline_unix_seconds != Some(expected) {
        bail!("the operation-bound recovery deadline is not armed");
    }
    Ok(())
}

fn validate_protected_source(
    operation: &Path,
    journal: &OnboardingJournal,
    request: &OnboardingRequest,
) -> Result<()> {
    let path = operation.join("source.tar.gz");
    validate_root_file(&path, MAX_SOURCE_BYTES)?;
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.mode() & 0o777 != 0o600 || metadata.len() != request.source_size_bytes {
        bail!("protected onboarding source has unsafe permissions or size");
    }
    if hash_regular_file(&path, MAX_SOURCE_BYTES, Some(0))? != journal.source_sha256 {
        bail!("protected onboarding source differs from the journal");
    }
    Ok(())
}

fn validate_protected_package(
    operation: &Path,
    journal: &OnboardingJournal,
    request: &OnboardingRequest,
) -> Result<String> {
    let path = operation.join("syn-approvals.deb");
    let expected = journal
        .package_sha256
        .as_deref()
        .context("journal has no package hash")?;
    let actual = hash_regular_file(&path, MAX_SOURCE_BYTES, Some(0))?;
    if actual != expected {
        bail!("protected package no longer matches the build journal");
    }
    validate_built_package(&path, &request.release_id)?;
    Ok(actual)
}

fn copy_protected_source_for_build(
    source: &Path,
    destination: &Path,
    expected_size: u64,
    expected_hash: &str,
) -> Result<()> {
    copy_protected_source_for_build_owned(source, destination, expected_size, expected_hash, 0)
}

fn copy_protected_source_for_build_owned(
    source: &Path,
    destination: &Path,
    expected_size: u64,
    expected_hash: &str,
    expected_uid: u32,
) -> Result<()> {
    validate_sha256(expected_hash, "source")?;
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() != expected_size
        || metadata.len() == 0
        || metadata.len() > MAX_SOURCE_BYTES
    {
        bail!("protected onboarding source is invalid before build");
    }
    let mut input = open_no_follow(source)?;
    if !same_file_and_state(&input.metadata()?, &metadata) {
        bail!("protected onboarding source changed before build");
    }
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(destination)?;
    let result = (|| -> Result<()> {
        let mut hasher = Sha256::new();
        let mut copied = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = input.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            copied = copied
                .checked_add(count as u64)
                .context("source size overflow")?;
            if copied > MAX_SOURCE_BYTES {
                bail!("protected onboarding source grew during build copy");
            }
            output.write_all(&buffer[..count])?;
            hasher.update(&buffer[..count]);
        }
        output.sync_all()?;
        if copied != expected_size || hex::encode(hasher.finalize()) != expected_hash {
            bail!("protected onboarding source changed during build copy");
        }
        if !same_file_and_state(&input.metadata()?, &metadata) {
            bail!("protected onboarding source changed during build copy");
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(destination);
    }
    result
}

fn validate_live_configuration(request: &OnboardingRequest, managed_uid: u32) -> Result<()> {
    let agent = AgentConfig::load(DEFAULT_AGENT_CONFIG)?;
    agent.validate()?;
    let plugin = PluginConfig::load(DEFAULT_PLUGIN_CONFIG)?;
    plugin.validate()?;
    let expected_listen =
        std::net::SocketAddr::new(request.listen_ip, syn_config::DEFAULT_LISTEN_PORT).to_string();
    if agent.target_id != request.target_id
        || agent.listen != expected_listen
        || plugin.target_id != request.target_id
        || plugin.managed_user != request.managed_user
        || plugin.managed_uid != managed_uid
    {
        bail!("live configuration differs from the onboarding operation");
    }
    run_quiet(
        "/usr/bin/systemctl",
        &["is-active", "--quiet", "syn-agent.service"],
    )
}

fn verify_installed_release(request: &OnboardingRequest) -> Result<()> {
    let package = command_output(
        "/usr/bin/dpkg-query",
        &[
            "--show",
            "--showformat=${db:Status-Abbrev} ${Version}",
            "syn-approvals",
        ],
    )?;
    if package != format!("ii  {}", request.release_id) {
        bail!("installed package does not match the onboarding release");
    }
    let helper = command_output("/usr/bin/synctl", &["--version"])?;
    if helper.trim_end() != format!("synctl {}", request.release_id) {
        bail!("installed helper does not match the onboarding release");
    }
    let metadata = Path::new("/usr/share/syn/release.json");
    validate_root_file(metadata, 16 * 1024)?;
    verify_archived_release(metadata, request)?;
    Ok(())
}

fn missing_dependencies() -> Result<Vec<&'static str>> {
    let mut missing = Vec::new();
    for package in BUILD_DEPENDENCIES {
        let output = fixed_command("/usr/bin/dpkg-query")
            .args(["--show", "--showformat=${db:Status-Abbrev}", package])
            .stdin(Stdio::null())
            .output()?;
        if !output.status.success() || output.stdout != b"ii " || !output.stderr.is_empty() {
            missing.push(*package);
        }
    }
    Ok(missing)
}

fn ensure_build_account() -> Result<()> {
    let existing = fixed_command("/usr/bin/getent")
        .args(["passwd", BUILD_USER])
        .stdin(Stdio::null())
        .output()?;
    if existing.status.success() {
        if !existing.stderr.is_empty() {
            bail!("build account lookup returned unexpected diagnostics");
        }
    } else {
        if !existing.stderr.is_empty() {
            bail!("build account lookup returned unexpected diagnostics");
        }
        run_quiet(
            "/usr/sbin/adduser",
            &[
                "--system",
                "--group",
                "--home",
                BUILD_HOME,
                "--shell",
                "/usr/sbin/nologin",
                BUILD_USER,
            ],
        )?;
    }
    let passwd = strict_command_bytes("/usr/bin/getent", &["passwd", BUILD_USER])?;
    let uid = passwd_uid(&passwd)?;
    let uid_text = uid.to_string();
    let uid_record = strict_command_bytes("/usr/bin/getent", &["passwd", &uid_text])?;
    let group = strict_command_bytes("/usr/bin/getent", &["group", BUILD_USER])?;
    let groups = strict_command_bytes("/usr/bin/id", &["-G", BUILD_USER])?;
    validate_build_account_records(&passwd, &uid_record, &group, &groups)?;
    run_quiet("/usr/bin/passwd", &["--lock", BUILD_USER])?;
    Ok(())
}

fn ensure_build_root() -> Result<()> {
    ensure_build_root_at(Path::new(BUILD_ROOT), 0, 0)
}

fn ensure_build_root_at(path: &Path, uid: u32, gid: u32) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o711))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let mut metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir()
        && metadata.uid() == uid
        && metadata.gid() == gid
        && metadata.mode() & 0o7777 == 0o755
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o711))?;
        metadata = fs::symlink_metadata(path)?;
    }
    if !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o7777 != 0o711
    {
        bail!("build root must be a root-owned directory with mode 0711");
    }
    Ok(())
}

fn passwd_uid(passwd: &[u8]) -> Result<u32> {
    let text = std::str::from_utf8(passwd)?;
    let line = single_line(text, "build account")?;
    let fields: Vec<_> = line.split(':').collect();
    if fields.len() != 7 {
        bail!("existing syn-build account record is invalid");
    }
    Ok(fields[2].parse()?)
}

fn validate_build_account_records(
    passwd: &[u8],
    uid_record: &[u8],
    group: &[u8],
    groups: &[u8],
) -> Result<()> {
    let passwd_text = std::str::from_utf8(passwd)?;
    let passwd_line = single_line(passwd_text, "build account")?;
    let fields: Vec<_> = passwd_line.split(':').collect();
    if fields.len() != 7
        || fields[0] != BUILD_USER
        || fields[5] != BUILD_HOME
        || fields[6] != "/usr/sbin/nologin"
    {
        bail!("existing syn-build account does not match Syn's locked build identity");
    }
    let uid: u32 = fields[2].parse()?;
    let gid: u32 = fields[3].parse()?;
    if uid == 0 || uid >= FIRST_REGULAR_UID || gid == 0 {
        bail!("syn-build must use an unprivileged dedicated system identity");
    }

    let uid_text = std::str::from_utf8(uid_record)?;
    if single_line(uid_text, "build UID")? != passwd_line {
        bail!("syn-build UID is shared with another account");
    }

    let group_text = std::str::from_utf8(group)?;
    let group_fields: Vec<_> = single_line(group_text, "build group")?.split(':').collect();
    if group_fields.len() != 4
        || group_fields[0] != BUILD_USER
        || group_fields[2].parse::<u32>()? != gid
        || !group_fields[3].is_empty()
    {
        bail!("syn-build primary group is not an exact dedicated group");
    }

    let group_ids: Vec<u32> = std::str::from_utf8(groups)?
        .split_ascii_whitespace()
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()?;
    if group_ids != [gid] {
        bail!("syn-build must not belong to supplementary or privileged groups");
    }
    Ok(())
}

fn single_line<'a>(value: &'a str, label: &str) -> Result<&'a str> {
    let value = value.strip_suffix('\n').unwrap_or(value);
    if value.is_empty() || value.contains('\n') || value.contains('\r') {
        bail!("{label} lookup is ambiguous");
    }
    Ok(value)
}

fn verify_archived_release(path: &Path, request: &OnboardingRequest) -> Result<()> {
    validate_regular_file(path, 16 * 1024)?;
    let value: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
    if value.as_object().map(|value| value.len()) != Some(3)
        || value["schema_version"] != 1
        || value["release_id"] != request.release_id
        || value["commit"] != request.release_commit
    {
        bail!("archived source release identity does not match the helper");
    }
    Ok(())
}

fn validate_built_package(path: &Path, release_id: &str) -> Result<()> {
    validate_root_file(path, MAX_SOURCE_BYTES)?;
    let package = command_output(
        "/usr/bin/dpkg-deb",
        &[
            "--field",
            path.to_str().context("package path is not UTF-8")?,
            "Package",
        ],
    )?;
    let version = command_output(
        "/usr/bin/dpkg-deb",
        &[
            "--field",
            path.to_str().context("package path is not UTF-8")?,
            "Version",
        ],
    )?;
    let architecture = command_output(
        "/usr/bin/dpkg-deb",
        &[
            "--field",
            path.to_str().context("package path is not UTF-8")?,
            "Architecture",
        ],
    )?;
    validate_package_identity(
        package.trim_end(),
        version.trim_end(),
        architecture.trim_end(),
        release_id,
    )
}

fn validate_package_identity(
    package: &str,
    version: &str,
    architecture: &str,
    release_id: &str,
) -> Result<()> {
    if package != "syn-approvals" || version != release_id || architecture != "arm64" {
        bail!("built package identity does not match the requested release");
    }
    Ok(())
}

fn run_isolated_build(command: &mut Command) -> Result<ExitStatus> {
    let mut child = command.spawn()?;
    let process_group = i32::try_from(child.id()).context("build process ID is out of range")?;
    #[cfg(target_os = "linux")]
    let watchdog = match BuildWatchdog::start(process_group) {
        Ok(watchdog) => watchdog,
        Err(error) => {
            let _ = terminate_process_group(process_group);
            let _ = child.wait();
            return Err(error);
        }
    };
    let status = child.wait();
    let shutdown = terminate_process_group(process_group);
    #[cfg(target_os = "linux")]
    let watchdog_shutdown = watchdog.disarm();
    #[cfg(not(target_os = "linux"))]
    let watchdog_shutdown: Result<()> = Ok(());
    match (status, shutdown, watchdog_shutdown) {
        (Ok(status), Ok(()), Ok(())) => Ok(status),
        (Err(error), Ok(()), Ok(())) => Err(error.into()),
        (Ok(_), Err(error), _) | (Err(_), Err(error), _) | (_, _, Err(error)) => Err(error),
    }
}

/// A separate, signal-immune process owns the build process-group cleanup if
/// synctl itself is killed. The pipe is close-on-exec, so EOF means the parent
/// disappeared without explicitly disarming the watchdog.
#[cfg(target_os = "linux")]
struct BuildWatchdog {
    write_fd: RawFd,
    pid: libc::pid_t,
}

#[cfg(target_os = "linux")]
impl BuildWatchdog {
    fn start(process_group: i32) -> Result<Self> {
        let mut descriptors = [-1; 2];
        if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(std::io::Error::last_os_error()).context("create build watchdog pipe");
        }
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(descriptors[0]);
                libc::close(descriptors[1]);
            }
            return Err(error).context("start build watchdog");
        }
        if pid == 0 {
            unsafe {
                libc::close(descriptors[1]);
                libc::setpgid(0, 0);
                libc::signal(libc::SIGINT, libc::SIG_IGN);
                libc::signal(libc::SIGHUP, libc::SIG_IGN);
                libc::signal(libc::SIGTERM, libc::SIG_IGN);
                let mut byte = 0_u8;
                let read = libc::read(
                    descriptors[0],
                    (&mut byte as *mut u8).cast::<libc::c_void>(),
                    1,
                );
                libc::close(descriptors[0]);
                if read == 0 {
                    libc::kill(-process_group, libc::SIGTERM);
                    libc::sleep(BUILD_GROUP_SHUTDOWN_GRACE.as_secs() as libc::c_uint);
                    libc::kill(-process_group, libc::SIGKILL);
                }
                libc::_exit(0);
            }
        }
        unsafe {
            libc::close(descriptors[0]);
        }
        Ok(Self {
            write_fd: descriptors[1],
            pid,
        })
    }

    fn disarm(mut self) -> Result<()> {
        let byte = [1_u8];
        let write_result =
            unsafe { libc::write(self.write_fd, byte.as_ptr().cast::<libc::c_void>(), 1) };
        unsafe {
            libc::close(self.write_fd);
        }
        self.write_fd = -1;
        let mut status = 0;
        let waited = unsafe { libc::waitpid(self.pid, &mut status, 0) };
        if write_result != 1 || waited != self.pid {
            bail!("build watchdog did not shut down cleanly");
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for BuildWatchdog {
    fn drop(&mut self) {
        if self.write_fd >= 0 {
            unsafe {
                libc::close(self.write_fd);
            }
        }
    }
}

fn terminate_process_group(process_group: i32) -> Result<()> {
    if !process_group_exists(process_group)? {
        return Ok(());
    }
    signal_process_group(process_group, libc::SIGTERM)?;
    if wait_for_process_group_exit(process_group, BUILD_GROUP_SHUTDOWN_GRACE)? {
        return Ok(());
    }
    signal_process_group(process_group, libc::SIGKILL)?;
    if !wait_for_process_group_exit(process_group, BUILD_GROUP_SHUTDOWN_GRACE)? {
        bail!("isolated build descendants did not terminate");
    }
    Ok(())
}

fn process_group_exists(process_group: i32) -> Result<bool> {
    let result = unsafe { libc::kill(-process_group, 0) };
    if result == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(error.into()),
    }
}

fn signal_process_group(process_group: i32, signal: i32) -> Result<()> {
    let result = unsafe { libc::kill(-process_group, signal) };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(error.into())
}

fn wait_for_process_group_exit(process_group: i32, grace: Duration) -> Result<bool> {
    let deadline = Instant::now() + grace;
    while process_group_exists(process_group)? {
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(25));
    }
    Ok(true)
}

fn configure_identities(request: &OnboardingRequest) -> Result<()> {
    let approval = syn_protocol::verifying_key_from_sec1(
        &STANDARD.decode(&request.approval_public_x963_base64)?,
    )?;
    let denial = syn_protocol::verifying_key_from_sec1(
        &STANDARD.decode(&request.denial_public_x963_base64)?,
    )?;
    let approval_pem = verifying_key_to_pem(&approval)?;
    let denial_pem = verifying_key_to_pem(&denial)?;
    let client_certificate = STANDARD.decode(&request.client_certificate_pem_base64)?;
    ensure_or_write_exact(Path::new(APPROVAL_PUBLIC), approval_pem.as_bytes(), 0o640)?;
    ensure_or_write_exact(Path::new(DENIAL_PUBLIC), denial_pem.as_bytes(), 0o640)?;
    ensure_or_write_exact(Path::new(CLIENT_CA), &client_certificate, 0o640)?;
    if Path::new(TARGET_PRIVATE).exists() || Path::new(TARGET_PUBLIC).exists() {
        validate_root_file(Path::new(TARGET_PRIVATE), 64 * 1024)?;
        validate_root_file(Path::new(TARGET_PUBLIC), 64 * 1024)?;
        let private = syn_protocol::signing_key_from_pem(&fs::read_to_string(TARGET_PRIVATE)?)?;
        let public = verifying_key_from_pem(&fs::read_to_string(TARGET_PUBLIC)?)?;
        if verifying_key_sec1(private.verifying_key()) != verifying_key_sec1(&public) {
            bail!("retained target signing keys do not match");
        }
    } else {
        let key = generate_signing_key();
        write_new_root_file(
            Path::new(TARGET_PRIVATE),
            signing_key_to_pem(&key)?.as_bytes(),
            0o600,
        )?;
        write_new_root_file(
            Path::new(TARGET_PUBLIC),
            verifying_key_to_pem(key.verifying_key())?.as_bytes(),
            0o640,
        )?;
    }
    if Path::new(TLS_PRIVATE).exists() || Path::new(TLS_CERTIFICATE).exists() {
        validate_root_file(Path::new(TLS_PRIVATE), 64 * 1024)?;
        validate_root_file(Path::new(TLS_CERTIFICATE), 64 * 1024)?;
    } else {
        let subject = format!("/CN={}", request.hostname);
        let san = if request.hostname.parse::<IpAddr>().is_ok() {
            format!("subjectAltName=IP:{}", request.hostname)
        } else {
            format!("subjectAltName=DNS:{}", request.hostname)
        };
        run_quiet(
            "/usr/bin/openssl",
            &[
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-pkeyopt",
                "ec_param_enc:named_curve",
                "-sha256",
                "-days",
                "365",
                "-nodes",
                "-subj",
                &subject,
                "-addext",
                &san,
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=critical,digitalSignature",
                "-addext",
                "extendedKeyUsage=serverAuth",
                "-keyout",
                TLS_PRIVATE,
                "-out",
                TLS_CERTIFICATE,
            ],
        )?;
    }
    for path in [
        APPROVAL_PUBLIC,
        DENIAL_PUBLIC,
        TARGET_PUBLIC,
        TLS_PRIVATE,
        TLS_CERTIFICATE,
        CLIENT_CA,
    ] {
        chown(Path::new(path), "root", "syn")?;
    }
    fs::set_permissions(TLS_PRIVATE, fs::Permissions::from_mode(0o640))?;
    Ok(())
}

fn configure_target(request: &OnboardingRequest, managed_uid: u32) -> Result<()> {
    let listen = std::net::SocketAddr::new(request.listen_ip, syn_config::DEFAULT_LISTEN_PORT);
    let agent = AgentConfig {
        schema_version: syn_config::AGENT_CONFIG_SCHEMA_VERSION,
        target_id: request.target_id.clone(),
        listen: listen.to_string(),
        unix_socket: syn_config::DEFAULT_SOCKET_PATH.into(),
        plugin_uid: 0,
        max_pending: 16,
        target_public_key: TARGET_PUBLIC.into(),
        approval_public_key: APPROVAL_PUBLIC.into(),
        denial_public_key: DENIAL_PUBLIC.into(),
        tls_certificate: TLS_CERTIFICATE.into(),
        tls_private_key: TLS_PRIVATE.into(),
        client_ca_certificate: CLIENT_CA.into(),
    };
    agent.validate()?;
    let plugin = PluginConfig {
        schema_version: 1,
        target_id: request.target_id.clone(),
        managed_uid,
        managed_user: request.managed_user.clone(),
        agent_socket: syn_config::DEFAULT_SOCKET_PATH.into(),
        timeout_seconds: syn_config::APPROVAL_TIMEOUT_SECONDS,
        target_private_key: TARGET_PRIVATE.into(),
        approval_public_key: APPROVAL_PUBLIC.into(),
        denial_public_key: DENIAL_PUBLIC.into(),
        policy_path: DEFAULT_POLICY_PATH.into(),
        pam_service: "syn-sudo-fallback".into(),
    };
    plugin.validate()?;
    let policy = Policy {
        managed_uid,
        managed_user: request.managed_user.clone(),
        ..Policy::default()
    };
    policy.validate()?;
    crate::atomic_write(
        Path::new(DEFAULT_AGENT_CONFIG),
        toml::to_string_pretty(&agent)?.as_bytes(),
        0o640,
    )?;
    crate::atomic_write(
        Path::new(DEFAULT_PLUGIN_CONFIG),
        toml::to_string_pretty(&plugin)?.as_bytes(),
        0o640,
    )?;
    crate::atomic_write(
        Path::new(DEFAULT_POLICY_PATH),
        toml::to_string_pretty(&policy)?.as_bytes(),
        0o640,
    )?;
    for path in [
        DEFAULT_AGENT_CONFIG,
        DEFAULT_PLUGIN_CONFIG,
        DEFAULT_POLICY_PATH,
    ] {
        chown(Path::new(path), "root", "syn")?;
    }
    Ok(())
}

fn planned_profile(request: &OnboardingRequest) -> MacTargetProfile {
    MacTargetProfile {
        target_id: request.target_id.clone(),
        display_name: request.display_name.clone(),
        web_socket_url: websocket_url(&request.hostname),
        target_public_key_base64: String::new(),
        server_certificate_sha256_hex: String::new(),
        client_identity_label: request.client_identity_label.clone(),
    }
}

fn live_profile(request: &OnboardingRequest) -> Result<MacTargetProfile> {
    let public = verifying_key_from_pem(&fs::read_to_string(TARGET_PUBLIC)?)?;
    let mut reader = std::io::BufReader::new(fs::File::open(TLS_CERTIFICATE)?);
    let certificate = rustls_pemfile::certs(&mut reader)
        .next()
        .transpose()?
        .context("target TLS certificate is empty")?;
    Ok(MacTargetProfile {
        target_id: request.target_id.clone(),
        display_name: request.display_name.clone(),
        web_socket_url: websocket_url(&request.hostname),
        target_public_key_base64: STANDARD.encode(verifying_key_sec1(&public)),
        server_certificate_sha256_hex: hex::encode(Sha256::digest(certificate.as_ref())),
        client_identity_label: request.client_identity_label.clone(),
    })
}

fn websocket_url(hostname: &str) -> String {
    if hostname.contains(':') && !(hostname.starts_with('[') && hostname.ends_with(']')) {
        format!("wss://[{hostname}]:{}", syn_config::DEFAULT_LISTEN_PORT)
    } else {
        format!("wss://{hostname}:{}", syn_config::DEFAULT_LISTEN_PORT)
    }
}

fn ensure_or_write_exact(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    if path.exists() {
        validate_root_file(path, 64 * 1024)?;
        if fs::read(path)? != bytes {
            bail!("retained pairing identity differs from this Mac");
        }
        return Ok(());
    }
    write_new_root_file(path, bytes, mode)
}

fn current_helper_source() -> Result<HelperSource> {
    let path = fs::canonicalize(std::env::current_exe()?)?;
    let metadata = fs::symlink_metadata(&path)?;
    validate_helper_metadata(&metadata, 0, metadata.len())?;
    if metadata.gid() != 0 || metadata.mode() & 0o7777 != 0o500 {
        bail!("bootstrap helper must be root-owned mode 0500");
    }
    let operation_id = validate_bootstrap_helper_path(&path)?;
    #[cfg(target_os = "linux")]
    {
        let loaded = fs::metadata("/proc/self/exe")?;
        if loaded.dev() != metadata.dev() || loaded.ino() != metadata.ino() {
            bail!("the executing helper changed before onboarding began");
        }
    }
    Ok(HelperSource {
        path,
        metadata,
        source_uid: 0,
        protected_uid: 0,
        bootstrap_operation_id: Some(operation_id),
    })
}

fn validate_bootstrap_helper_path(path: &Path) -> Result<String> {
    if path.file_name().and_then(|value| value.to_str()) != Some(BOOTSTRAP_HELPER_NAME) {
        bail!("bootstrap helper has an unexpected filename");
    }
    let operation = path
        .parent()
        .context("bootstrap helper has no operation directory")?;
    let operation_id = operation
        .file_name()
        .and_then(|value| value.to_str())
        .context("bootstrap operation path is not UTF-8")?;
    validate_hex(operation_id, 32, "bootstrap operation ID")?;
    if operation.parent() != Some(Path::new(BOOTSTRAP_ROOT)) {
        bail!("bootstrap helper is outside the protected bootstrap root");
    }
    for directory in [Path::new(BOOTSTRAP_ROOT), operation] {
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o022 != 0
        {
            bail!("bootstrap helper parent is not a protected root-owned directory");
        }
    }
    Ok(operation_id.into())
}

fn verify_helper_source(
    helper: &HelperSource,
    expected_size: u64,
    expected_hash: &str,
) -> Result<()> {
    validate_sha256(expected_hash, "helper")?;
    let mut input = open_verified_helper(helper, expected_size)?;
    let actual_hash = hash_reader(&mut input, MAX_HELPER_BYTES)?;
    if actual_hash != expected_hash {
        bail!("the executing helper does not match the onboarding request");
    }
    verify_helper_path(helper, expected_size)
}

fn copy_verified_helper(
    helper: &HelperSource,
    destination: &Path,
    expected_size: u64,
    expected_hash: &str,
) -> Result<()> {
    let mut input = open_verified_helper(helper, expected_size)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o700);
    let mut output = options.open(destination)?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .context("helper size overflow")?;
        if total > MAX_HELPER_BYTES {
            let _ = fs::remove_file(destination);
            bail!("helper is too large");
        }
        output.write_all(&buffer[..count])?;
        hasher.update(&buffer[..count]);
    }
    output.sync_all()?;
    if total != expected_size || hex::encode(hasher.finalize()) != expected_hash {
        let _ = fs::remove_file(destination);
        bail!("the executing helper changed while it was being protected");
    }
    verify_helper_path(helper, expected_size)?;
    let protected = fs::symlink_metadata(destination)?;
    if protected.uid() != helper.protected_uid || protected.mode() & 0o777 != 0o700 {
        let _ = fs::remove_file(destination);
        bail!("protected onboarding helper has unsafe ownership or permissions");
    }
    Ok(())
}

fn open_verified_helper(helper: &HelperSource, expected_size: u64) -> Result<fs::File> {
    verify_helper_path(helper, expected_size)?;
    let input = open_no_follow(&helper.path)?;
    let metadata = input.metadata()?;
    validate_helper_metadata(&metadata, helper.source_uid, expected_size)?;
    if !same_file_and_state(&metadata, &helper.metadata) {
        bail!("the executing helper changed during verification");
    }
    Ok(input)
}

fn verify_helper_path(helper: &HelperSource, expected_size: u64) -> Result<()> {
    let metadata = fs::symlink_metadata(&helper.path)?;
    validate_helper_metadata(&metadata, helper.source_uid, expected_size)?;
    if !same_file_and_state(&metadata, &helper.metadata) {
        bail!("the executing helper changed during verification");
    }
    Ok(())
}

fn validate_helper_metadata(
    metadata: &fs::Metadata,
    expected_uid: u32,
    expected_size: u64,
) -> Result<()> {
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
        || expected_size == 0
        || expected_size > MAX_HELPER_BYTES
        || metadata.len() != expected_size
    {
        bail!("onboarding helper is not a protected executable regular file");
    }
    Ok(())
}

fn same_file_and_state(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn validate_operation_helper(operation: &Path, journal: &OnboardingJournal) -> Result<()> {
    validate_sha256(&journal.helper_sha256, "helper")?;
    let path = operation.join(BOOTSTRAP_HELPER_NAME);
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o700
        || metadata.len() != journal.helper_size_bytes
        || metadata.len() == 0
        || metadata.len() > MAX_HELPER_BYTES
    {
        bail!("protected onboarding helper is invalid");
    }
    if hash_regular_file(&path, MAX_HELPER_BYTES, Some(0))? != journal.helper_sha256 {
        bail!("protected onboarding helper differs from the journal");
    }

    let expected_path = fs::canonicalize(&path)?;
    let current_path = fs::canonicalize(std::env::current_exe()?)?;
    if current_path != expected_path {
        bail!("continue onboarding with this operation's protected helper");
    }
    #[cfg(target_os = "linux")]
    {
        let loaded = fs::metadata("/proc/self/exe")?;
        if loaded.dev() != metadata.dev() || loaded.ino() != metadata.ino() {
            bail!("the running process is not the protected onboarding helper");
        }
    }
    Ok(())
}

fn hash_reader(reader: &mut impl Read, maximum: u64) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .context("file size overflow")?;
        if total > maximum {
            bail!("protected artifact is too large");
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn hash_regular_file(path: &Path, maximum: u64, expected_uid: Option<u32>) -> Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > maximum
        || expected_uid.is_some_and(|uid| metadata.uid() != uid)
    {
        bail!("protected artifact is invalid");
    }
    let mut input = open_no_follow(path)?;
    hash_reader(&mut input, maximum)
}

fn validate_root_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        bail!("onboarding operation directory is not root-owned and private");
    }
    Ok(())
}

fn validate_root_file(path: &Path, maximum: u64) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        bail!("protected onboarding file is invalid");
    }
    Ok(())
}

fn validate_owned_file(path: &Path, uid: u32, mode: u32, maximum: u64) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != mode
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        bail!("protected onboarding file has unsafe ownership, mode, or size");
    }
    Ok(())
}

fn validate_regular_file(path: &Path, maximum: u64) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        bail!("release file is invalid");
    }
    Ok(())
}

fn copy_new_file_limited(source: &Path, destination: &Path, mode: u32, maximum: u64) -> Result<()> {
    let mut input = open_no_follow(source)?;
    let metadata = input.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        bail!("build output is not a supported regular file");
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(mode);
    let mut output = options.open(destination)?;
    let copied = std::io::copy(&mut Read::by_ref(&mut input).take(maximum + 1), &mut output)?;
    if copied != metadata.len() || copied > maximum {
        let _ = fs::remove_file(destination);
        bail!("build output changed while it was being protected");
    }
    output.sync_all()?;
    Ok(())
}

fn chown(path: &Path, user: &str, group: &str) -> Result<()> {
    run_quiet(
        "/usr/bin/chown",
        &[
            &format!("{user}:{group}"),
            path.to_str().context("path is not UTF-8")?,
        ],
    )
}

fn fixed_command(program: &str) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .current_dir("/");
    command
}

fn run_quiet(program: &str, arguments: &[&str]) -> Result<()> {
    let status = fixed_command(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        bail!("guided setup operation failed: {program} exited {status}");
    }
    Ok(())
}

fn run_clean_quiet(program: &str, arguments: &[&str], cwd: &Path, home: &Path) -> Result<()> {
    let status = Command::new(program)
        .args(arguments)
        .env_clear()
        .env("HOME", home)
        .env("USER", BUILD_USER)
        .env("LOGNAME", BUILD_USER)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        bail!("guided setup operation failed: {program} exited {status}");
    }
    Ok(())
}

fn command_output(program: &str, arguments: &[&str]) -> Result<String> {
    let output = fixed_command(program)
        .args(arguments)
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() || !output.stderr.is_empty() || output.stdout.len() > 16 * 1024 {
        bail!("guided setup inspection failed");
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn strict_command_bytes(program: &str, arguments: &[&str]) -> Result<Vec<u8>> {
    let output = fixed_command(program)
        .args(arguments)
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() || !output.stderr.is_empty() || output.stdout.len() > 64 * 1024 {
        bail!("guided setup identity inspection failed");
    }
    Ok(output.stdout)
}

fn validate_request(
    request: &OnboardingRequest,
    sudo_user: &str,
    expected_source_sha256: &str,
) -> Result<()> {
    if request.schema_version != 1 {
        bail!("unsupported onboarding request schema");
    }
    if request.release_id != syn_protocol::release_id()
        || request.release_commit != syn_protocol::release_commit()
    {
        bail!("onboarding request does not match this helper's exact release");
    }
    if request.managed_user != sudo_user {
        bail!("onboarding request must manage the authenticated SSH account");
    }
    validate_account_name(&request.managed_user)?;
    validate_hex(&request.operation_id, 32, "operation ID")?;
    validate_identifier(&request.target_id, 128, "target ID")?;
    validate_display_name(&request.display_name)?;
    validate_hostname(&request.hostname)?;
    if request.listen_ip.is_unspecified()
        || request.listen_ip.is_loopback()
        || request.listen_ip.is_multicast()
        || request.listen_ip == IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
    {
        bail!("listen address must be a concrete unicast address");
    }
    if request.client_identity_label != format!("Syn {} transport", request.target_id) {
        bail!("transport identity label does not match the target");
    }
    let approval = syn_protocol::verifying_key_from_sec1(
        &STANDARD.decode(&request.approval_public_x963_base64)?,
    )?;
    let denial = syn_protocol::verifying_key_from_sec1(
        &STANDARD.decode(&request.denial_public_x963_base64)?,
    )?;
    if syn_protocol::key_id(&approval) == syn_protocol::key_id(&denial) {
        bail!("approval and denial keys must be different");
    }
    let certificate = STANDARD.decode(&request.client_certificate_pem_base64)?;
    if certificate.is_empty() || certificate.len() > 16 * 1024 {
        bail!("transport certificate has an invalid size");
    }
    let mut reader = std::io::BufReader::new(certificate.as_slice());
    let certificates: Vec<_> =
        rustls_pemfile::certs(&mut reader).collect::<std::result::Result<_, _>>()?;
    if certificates.len() != 1 || certificates[0].as_ref().is_empty() {
        bail!("transport certificate must contain exactly one certificate");
    }
    validate_sha256(&request.source_sha256, "source")?;
    if request.source_sha256 != expected_source_sha256 {
        bail!("source hash differs between the trusted command and request");
    }
    if request.source_size_bytes == 0 || request.source_size_bytes > MAX_SOURCE_BYTES {
        bail!("source size is outside the supported range");
    }
    Ok(())
}

fn account(user: &str) -> Result<(u32, PathBuf)> {
    validate_account_name(user)?;
    let output = fixed_command("/usr/bin/getent")
        .args(["passwd", user])
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() || !output.stderr.is_empty() {
        bail!("authenticated SSH account is unavailable");
    }
    let text = String::from_utf8(output.stdout)?;
    if text.lines().count() != 1 {
        bail!("authenticated SSH account is ambiguous");
    }
    let fields: Vec<_> = text.trim_end_matches('\n').split(':').collect();
    if fields.len() != 7 || fields[0] != user {
        bail!("authenticated SSH account record is invalid");
    }
    let uid: u32 = fields[2].parse()?;
    let home = PathBuf::from(fields[5]);
    if !home.is_absolute() || home == Path::new("/") {
        bail!("authenticated SSH account has an unsafe home directory");
    }
    Ok((uid, home))
}

fn read_verified_user_file(
    path: &Path,
    uid: u32,
    maximum: u64,
    expected_hash: &str,
) -> Result<Vec<u8>> {
    let metadata = verified_user_metadata(path, uid, maximum, None)?;
    let mut input = open_no_follow(path)?;
    verify_opened_metadata(&input, &metadata, uid, maximum, None)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut input)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || hex::encode(Sha256::digest(&bytes)) != expected_hash
    {
        bail!("staged request changed or did not match its trusted hash");
    }
    verify_opened_metadata(&input, &metadata, uid, maximum, None)?;
    Ok(bytes)
}

fn verify_user_file_hash(
    path: &Path,
    expected_metadata: &fs::Metadata,
    expected_hash: &str,
) -> Result<()> {
    let mut input = open_no_follow(path)?;
    verify_opened_metadata(
        &input,
        expected_metadata,
        expected_metadata.uid(),
        MAX_SOURCE_BYTES,
        Some(expected_metadata.len()),
    )?;
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        copied = copied
            .checked_add(count as u64)
            .context("source size overflow")?;
        if copied > MAX_SOURCE_BYTES {
            bail!("source is too large");
        }
        hasher.update(&buffer[..count]);
    }
    if copied != expected_metadata.len() || hex::encode(hasher.finalize()) != expected_hash {
        bail!("staged source changed or did not match its trusted hash");
    }
    verify_opened_metadata(
        &input,
        expected_metadata,
        expected_metadata.uid(),
        MAX_SOURCE_BYTES,
        Some(expected_metadata.len()),
    )
}

fn copy_verified_user_file(
    path: &Path,
    destination: &Path,
    metadata: &fs::Metadata,
    expected_hash: &str,
) -> Result<()> {
    let mut input = open_no_follow(path)?;
    verify_opened_metadata(
        &input,
        metadata,
        metadata.uid(),
        MAX_SOURCE_BYTES,
        Some(metadata.len()),
    )?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut output = options.open(destination)?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .context("source size overflow")?;
        if total > MAX_SOURCE_BYTES {
            bail!("source is too large");
        }
        output.write_all(&buffer[..count])?;
        hasher.update(&buffer[..count]);
    }
    output.sync_all()?;
    if total != metadata.len() || hex::encode(hasher.finalize()) != expected_hash {
        let _ = fs::remove_file(destination);
        bail!("staged source changed or did not match its trusted hash");
    }
    verify_opened_metadata(
        &input,
        metadata,
        metadata.uid(),
        MAX_SOURCE_BYTES,
        Some(metadata.len()),
    )?;
    Ok(())
}

fn verified_user_metadata(
    path: &Path,
    uid: u32,
    maximum: u64,
    exact_size: Option<u64>,
) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        bail!("staged setup input must be a private regular file owned by the SSH account");
    }
    if metadata.len() == 0
        || metadata.len() > maximum
        || exact_size.is_some_and(|size| size != metadata.len())
    {
        bail!("staged setup input has an invalid size");
    }
    Ok(metadata)
}

fn open_no_follow(path: &Path) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
        .open(path)
        .with_context(|| format!("open staged setup input {}", path.display()))
}

fn verify_opened_metadata(
    file: &fs::File,
    expected: &fs::Metadata,
    uid: u32,
    maximum: u64,
    exact_size: Option<u64>,
) -> Result<()> {
    let current = file.metadata()?;
    if !current.file_type().is_file()
        || current.uid() != uid
        || current.mode() & 0o077 != 0
        || current.len() == 0
        || current.len() > maximum
        || exact_size.is_some_and(|size| size != current.len())
        || current.dev() != expected.dev()
        || current.ino() != expected.ino()
        || current.len() != expected.len()
        || current.mtime() != expected.mtime()
        || current.mtime_nsec() != expected.mtime_nsec()
        || current.ctime() != expected.ctime()
        || current.ctime_nsec() != expected.ctime_nsec()
    {
        bail!("staged setup input changed during verification");
    }
    // Verify the file descriptor, not a path reopened after the checks above.
    if file.as_raw_fd() < 0 {
        bail!("staged setup input is unavailable");
    }
    Ok(())
}

fn write_new_root_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(mode);
    let mut output = options.open(path)?;
    output.write_all(bytes)?;
    output.sync_all()?;
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    validate_hex(value, 64, &format!("{label} SHA-256"))
}

fn validate_hex(value: &str, length: usize, label: &str) -> Result<()> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} is invalid");
    }
    Ok(())
}

fn validate_account_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || value == "root"
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        bail!("managed account is invalid");
    }
    Ok(())
}

fn validate_identifier(value: &str, maximum: usize, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        bail!("{label} is invalid");
    }
    Ok(())
}

fn validate_display_name(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        bail!("display name is invalid");
    }
    Ok(())
}

fn validate_hostname(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 253
        || value.starts_with('-')
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'[' | b']')
        })
    {
        bail!("hostname is invalid");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "syn-onboarding-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture(source: &[u8]) -> (OnboardingRequest, Vec<u8>) {
        let helper = b"trusted helper bytes";
        let approval = syn_protocol::generate_signing_key();
        let denial = syn_protocol::generate_signing_key();
        let request = OnboardingRequest {
            schema_version: 1,
            operation_id: "0123456789abcdef0123456789abcdef".into(),
            release_id: syn_protocol::release_id().into(),
            release_commit: syn_protocol::release_commit().into(),
            managed_user: "developer".into(),
            target_id: "remote_machine".into(),
            display_name: "Remote machine".into(),
            hostname: "remote.local".into(),
            listen_ip: "192.168.2.10".parse().unwrap(),
            client_identity_label: "Syn remote_machine transport".into(),
            approval_public_x963_base64: STANDARD
                .encode(syn_protocol::verifying_key_sec1(approval.verifying_key())),
            denial_public_x963_base64: STANDARD
                .encode(syn_protocol::verifying_key_sec1(denial.verifying_key())),
            client_certificate_pem_base64: STANDARD
                .encode("-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n"),
            source_sha256: hex::encode(Sha256::digest(source)),
            source_size_bytes: source.len() as u64,
            helper_sha256: hex::encode(Sha256::digest(helper)),
            helper_size_bytes: helper.len() as u64,
        };
        let bytes = serde_json::to_vec(&request).unwrap();
        (request, bytes)
    }

    #[test]
    fn request_rejects_release_user_source_and_identity_substitution() {
        let source = b"source";
        let (mut request, _) = fixture(source);
        assert!(validate_request(&request, "developer", &request.source_sha256).is_ok());
        request.release_commit = "1".repeat(40);
        assert!(validate_request(&request, "developer", &request.source_sha256).is_err());
        request.release_commit = syn_protocol::release_commit().into();
        assert!(validate_request(&request, "another", &request.source_sha256).is_err());
        assert!(validate_request(&request, "developer", &"0".repeat(64)).is_err());
        request.client_identity_label = "another".into();
        assert!(validate_request(&request, "developer", &request.source_sha256).is_err());
    }

    #[test]
    fn staged_files_must_be_private_regular_exact_and_stay_inside_new_operation() {
        let directory = Directory::new();
        let incoming = directory.0.join("incoming");
        let staging = directory.0.join("staging");
        fs::create_dir(&incoming).unwrap();
        fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700)).unwrap();
        let source = b"exact source bytes";
        let (_, request) = fixture(source);
        let request_path = incoming.join(REQUEST_NAME);
        let source_path = incoming.join(SOURCE_NAME);
        let helper_path = directory.0.join("synctl-bootstrap-test");
        fs::write(&request_path, &request).unwrap();
        fs::write(&source_path, source).unwrap();
        fs::write(&helper_path, b"trusted helper bytes").unwrap();
        fs::set_permissions(&request_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&helper_path, fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(&source_path).unwrap().uid();
        let helper = HelperSource {
            path: helper_path.clone(),
            metadata: fs::metadata(&helper_path).unwrap(),
            source_uid: uid,
            protected_uid: uid,
            bootstrap_operation_id: Some("0123456789abcdef0123456789abcdef".into()),
        };
        let request_hash = hex::encode(Sha256::digest(&request));
        let source_hash = hex::encode(Sha256::digest(source));

        let plan = prepare_from(
            &incoming,
            &staging,
            &helper,
            "developer",
            uid,
            &request_hash,
            &source_hash,
            None,
            true,
        )
        .unwrap();
        assert!(plan.applied);
        let retry = prepare_from(
            &incoming,
            &staging,
            &helper,
            "developer",
            uid,
            &request_hash,
            &source_hash,
            None,
            true,
        )
        .unwrap();
        assert!(retry.applied);
        let operation = staging.join("0123456789abcdef0123456789abcdef");
        assert_eq!(fs::read(operation.join("source.tar.gz")).unwrap(), source);
        assert_eq!(
            fs::metadata(operation.join("source.tar.gz"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );

        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(verified_user_metadata(
            &source_path,
            uid,
            MAX_SOURCE_BYTES,
            Some(source.len() as u64)
        )
        .is_err());
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(verify_user_file_hash(
            &source_path,
            &fs::metadata(&source_path).unwrap(),
            &"0".repeat(64)
        )
        .is_err());

        fs::write(operation.join("source.tar.gz"), b"corrupt source bytes").unwrap();
        assert!(prepare_from(
            &incoming,
            &staging,
            &helper,
            "developer",
            uid,
            &request_hash,
            &source_hash,
            None,
            true,
        )
        .is_err());
    }

    #[test]
    fn activation_and_completion_crash_boundaries_are_resumable() {
        assert_eq!(
            activation_step("paired_pending_approval", false, false).unwrap(),
            ActivationStep::Continue
        );
        assert_eq!(
            activation_step("activation_recovery_armed", true, true).unwrap(),
            ActivationStep::AdoptArmedInstall
        );
        assert!(activation_step("activation_recovery_armed", true, false).is_err());
        assert_eq!(
            activation_step("armed_pending_final_approval", true, true).unwrap(),
            ActivationStep::Done
        );

        // activation_recovery_armed + live state models a crash after
        // installer::apply but before its journal write. A crash after helper
        // commit but before its journal write safely repeats verification.
        // After the checkpoint journal write, both a crash before cancellation
        // and one after cancellation resume at idempotent disarm.
        assert_eq!(
            completion_step("armed_pending_final_approval").unwrap(),
            CompletionStep::Verify
        );
        assert_eq!(
            completion_step("completion_verified").unwrap(),
            CompletionStep::Disarm
        );
        assert_eq!(completion_step("complete").unwrap(), CompletionStep::Done);
    }

    #[test]
    fn protected_build_source_rejects_corruption_and_symlinks() {
        let directory = Directory::new();
        let source = directory.0.join("protected-source.tar.gz");
        let snapshot = directory.0.join("build-source.tar.gz");
        let bytes = b"exact protected source";
        fs::write(&source, bytes).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = fs::metadata(&source).unwrap().uid();
        let expected_hash = hex::encode(Sha256::digest(bytes));

        copy_protected_source_for_build_owned(
            &source,
            &snapshot,
            bytes.len() as u64,
            &expected_hash,
            uid,
        )
        .unwrap();
        assert_eq!(fs::read(&snapshot).unwrap(), bytes);

        fs::write(&source, vec![b'x'; bytes.len()]).unwrap();
        assert!(copy_protected_source_for_build_owned(
            &source,
            &directory.0.join("corrupt-copy.tar.gz"),
            bytes.len() as u64,
            &expected_hash,
            uid,
        )
        .is_err());

        fs::remove_file(&source).unwrap();
        std::os::unix::fs::symlink(&snapshot, &source).unwrap();
        assert!(copy_protected_source_for_build_owned(
            &source,
            &directory.0.join("symlink-copy.tar.gz"),
            bytes.len() as u64,
            &expected_hash,
            uid,
        )
        .is_err());
    }

    #[test]
    fn package_identity_is_exactly_release_and_arm64_bound() {
        let release = syn_protocol::release_id();
        assert!(validate_package_identity("syn-approvals", release, "arm64", release).is_ok());
        assert!(validate_package_identity("other", release, "arm64", release).is_err());
        assert!(validate_package_identity("syn-approvals", "other", "arm64", release).is_err());
        assert!(validate_package_identity("syn-approvals", release, "amd64", release).is_err());
    }

    #[test]
    fn build_identity_rejects_privileged_shared_or_login_capable_accounts() {
        let valid_passwd = b"syn-build:x:992:992::/var/lib/syn-build/home:/usr/sbin/nologin\n";
        let valid_group = b"syn-build:x:992:\n";
        assert!(
            validate_build_account_records(valid_passwd, valid_passwd, valid_group, b"992\n")
                .is_ok()
        );
        for invalid in [
            b"syn-build:x:1000:992::/var/lib/syn-build/home:/usr/sbin/nologin\n".as_slice(),
            b"syn-build:x:0:992::/var/lib/syn-build/home:/usr/sbin/nologin\n".as_slice(),
            b"syn-build:x:992:0::/var/lib/syn-build/home:/usr/sbin/nologin\n".as_slice(),
            b"syn-build:x:992:992::/tmp:/usr/sbin/nologin\n".as_slice(),
            b"syn-build:x:992:992::/var/lib/syn-build/home:/bin/sh\n".as_slice(),
        ] {
            assert!(
                validate_build_account_records(invalid, invalid, valid_group, b"992\n").is_err()
            );
        }
        assert!(validate_build_account_records(
            valid_passwd,
            b"another:x:992:992::/var/lib/another:/usr/sbin/nologin\n",
            valid_group,
            b"992\n"
        )
        .is_err());
        assert!(validate_build_account_records(
            valid_passwd,
            valid_passwd,
            valid_group,
            b"992 27\n"
        )
        .is_err());
    }

    #[test]
    fn build_root_recovers_exact_trusted_adduser_scaffold() {
        let directory = Directory::new();
        let metadata = fs::symlink_metadata(&directory.0).unwrap();
        let build_root = directory.0.join("syn-build");
        fs::create_dir(&build_root).unwrap();
        fs::set_permissions(&build_root, fs::Permissions::from_mode(0o755)).unwrap();

        ensure_build_root_at(&build_root, metadata.uid(), metadata.gid()).unwrap();
        assert_eq!(
            fs::symlink_metadata(&build_root).unwrap().mode() & 0o7777,
            0o711
        );
        ensure_build_root_at(&build_root, metadata.uid(), metadata.gid()).unwrap();
    }

    #[test]
    fn build_root_is_protected_before_first_account_home_is_created() {
        let directory = Directory::new();
        let metadata = fs::symlink_metadata(&directory.0).unwrap();
        let build_root = directory.0.join("syn-build");

        ensure_build_root_at(&build_root, metadata.uid(), metadata.gid()).unwrap();
        fs::create_dir(build_root.join("home")).unwrap();
        assert_eq!(
            fs::symlink_metadata(&build_root).unwrap().mode() & 0o7777,
            0o711
        );
    }

    #[test]
    fn build_root_rejects_writable_wrong_owner_and_symlink_state() {
        let directory = Directory::new();
        let metadata = fs::symlink_metadata(&directory.0).unwrap();
        for mode in [0o700, 0o733, 0o777] {
            let path = directory.0.join(format!("mode-{mode:o}"));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(ensure_build_root_at(&path, metadata.uid(), metadata.gid()).is_err());
        }
        let wrong_owner = directory.0.join("wrong-owner");
        fs::create_dir(&wrong_owner).unwrap();
        fs::set_permissions(&wrong_owner, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(ensure_build_root_at(&wrong_owner, metadata.uid() + 1, metadata.gid()).is_err());

        let link = directory.0.join("link");
        std::os::unix::fs::symlink(&wrong_owner, &link).unwrap();
        assert!(ensure_build_root_at(&link, metadata.uid(), metadata.gid()).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn build_watchdog_kills_the_group_if_its_parent_disappears() {
        let mut command = Command::new("/bin/sh");
        command
            .process_group(0)
            .args(["-c", "trap '' TERM; sleep 30 & wait"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command.spawn().unwrap();
        let process_group = i32::try_from(child.id()).unwrap();
        let watchdog = BuildWatchdog::start(process_group).unwrap();
        drop(watchdog);
        let deadline = Instant::now() + Duration::from_secs(6);
        let mut child_exited = false;
        while Instant::now() < deadline {
            child_exited |= child.try_wait().unwrap().is_some();
            if child_exited && !process_group_exists(process_group).unwrap() {
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        let group_exited = !process_group_exists(process_group).unwrap();
        if !group_exited {
            let _ = signal_process_group(process_group, libc::SIGKILL);
        }
        let _ = child.wait();
        assert!(child_exited && group_exited);
    }
}
