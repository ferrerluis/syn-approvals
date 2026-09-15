use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{atomic_write, require_root};

pub const RECOVERY_SERVICE: &str = "/usr/lib/systemd/system/syn-auto-recover.service";
pub const RECOVERY_HELPER: &str = "/var/lib/syn/recovery/synctl";
const RECOVERY_HELPER_IDENTITY: &str = "/var/lib/syn/recovery/synctl.identity.json";
pub const RECOVERY_TIMER: &str = "/etc/systemd/system/syn-auto-recover.timer";
pub const RECOVERY_DEADLINE_STATE: &str = "/var/lib/syn/recovery-deadline.json";
const TIMER_NAME: &str = "syn-auto-recover.timer";
const RECOVERY_SERVICE_NAME: &str = "syn-auto-recover.service";
const PROOF_SERVICE: &str = "/run/systemd/system/syn-recovery-proof.service";
const PROOF_TIMER: &str = "/run/systemd/system/syn-recovery-proof.timer";
const PROOF_TIMER_NAME: &str = "syn-recovery-proof.timer";
const PROOF_MARKER: &str = "/run/syn-recovery-proof-fired";
const MANAGED_HEADER: &str = "# Managed by Syn. Do not edit.\n";
const RECOVERY_DIRECTORY: &str = "/var/lib/syn/recovery";
const MAX_HELPER_BYTES: u64 = 128 * 1024 * 1024;
const EXPECTED_RECOVERY_SERVICE: &[u8] =
    include_bytes!("../../../packaging/systemd/syn-auto-recover.service");
pub const MIN_INSTALL_RECOVERY_SECONDS: u64 = 10 * 60;
const ARM_SYSTEMCTL_COMMANDS: &[&[&str]] = &[
    &["daemon-reload"],
    &["enable", TIMER_NAME],
    &["restart", TIMER_NAME],
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeadlineState {
    schema_version: u16,
    armed_at_unix_seconds: u64,
    deadline_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RecoveryHelperIdentity {
    schema_version: u16,
    sha256: String,
    size: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct RecoveryTimerReport {
    pub status: &'static str,
    pub armed: bool,
    pub state_valid: bool,
    pub timer_active: bool,
    pub timer_enabled: bool,
    pub deadline_unix_seconds: Option<u64>,
    pub seconds_remaining: Option<u64>,
    pub state_path: PathBuf,
    pub timer_path: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
pub struct RecoveryActionReport {
    pub applied: bool,
    pub action: &'static str,
    pub deadline_unix_seconds: Option<u64>,
    pub timer_path: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
pub struct RecoveryProofReport {
    pub applied: bool,
    pub fired: bool,
    pub seconds: u64,
}

pub fn status() -> RecoveryTimerReport {
    let state_path = PathBuf::from(RECOVERY_DEADLINE_STATE);
    let timer_path = PathBuf::from(RECOVERY_TIMER);
    let state_present = state_path.exists();
    let state_result = read_deadline_state(&state_path);
    let state_valid = !state_present || state_result.is_ok();
    let state = state_result.ok();
    let timer_active = systemctl_check("is-active", TIMER_NAME);
    let timer_enabled = systemctl_check("is-enabled", TIMER_NAME);
    let now = unix_seconds().ok();
    let seconds_remaining = state
        .as_ref()
        .and_then(|state| now.map(|now| state.deadline_unix_seconds.saturating_sub(now)));
    let (status, armed) = classify_recovery_state(
        state_present,
        state_valid,
        timer_path.exists(),
        timer_active,
        timer_enabled,
        seconds_remaining,
    );
    RecoveryTimerReport {
        status,
        armed,
        state_valid,
        timer_active,
        timer_enabled,
        deadline_unix_seconds: state.as_ref().map(|state| state.deadline_unix_seconds),
        seconds_remaining,
        state_path,
        timer_path,
    }
}

pub fn arm(minutes: u64, apply: bool) -> Result<RecoveryActionReport> {
    if !(1..=60).contains(&minutes) {
        bail!("recovery deadline must be between 1 and 60 minutes");
    }
    let now = unix_seconds()?;
    let deadline = now
        .checked_add(
            minutes
                .checked_mul(60)
                .context("recovery deadline overflow")?,
        )
        .context("recovery deadline overflow")?;
    let report = RecoveryActionReport {
        applied: apply,
        action: "arm",
        deadline_unix_seconds: Some(deadline),
        timer_path: RECOVERY_TIMER.into(),
    };
    if !apply {
        return Ok(report);
    }
    require_root()?;
    validate_recovery_service(Path::new(RECOVERY_SERVICE))?;
    validate_recovery_helper(Path::new(RECOVERY_HELPER))?;
    validate_existing_managed_timer(Path::new(RECOVERY_TIMER))?;
    validate_existing_deadline_state(Path::new(RECOVERY_DEADLINE_STATE))?;

    let timer = render_recovery_timer(deadline);
    let state = DeadlineState {
        schema_version: 1,
        armed_at_unix_seconds: now,
        deadline_unix_seconds: deadline,
    };
    atomic_write(Path::new(RECOVERY_TIMER), timer.as_bytes(), 0o644)?;
    atomic_write(
        Path::new(RECOVERY_DEADLINE_STATE),
        &serde_json::to_vec_pretty(&state)?,
        0o644,
    )?;
    if let Err(error) = (|| -> Result<()> {
        for command in ARM_SYSTEMCTL_COMMANDS {
            run_systemctl(command)?;
        }
        let current = status();
        if !current.armed || current.deadline_unix_seconds != Some(deadline) {
            bail!("systemd did not arm the exact recovery deadline");
        }
        Ok(())
    })() {
        let _ = disarm_files(true, true);
        return Err(error);
    }
    Ok(report)
}

/// Retain a known-good root-owned synctl before package replacement. An
/// existing valid helper is deliberately preserved, even when `source` is a
/// newer candidate; call `commit_helper` only after activation completes.
pub fn prepare_helper(source: &Path) -> Result<()> {
    require_root()?;
    validate_helper_source(source)?;
    ensure_recovery_directory()?;
    match fs::symlink_metadata(RECOVERY_HELPER) {
        Ok(_) => validate_recovery_helper(Path::new(RECOVERY_HELPER)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => install_helper_copy(source),
        Err(error) => Err(error.into()),
    }
}

/// Replace the retained helper with the candidate only after that exact
/// release has completed its privileged activation transaction.
pub fn commit_helper(source: &Path) -> Result<()> {
    require_root()?;
    validate_helper_source(source)?;
    ensure_recovery_directory()?;
    validate_recovery_helper(Path::new(RECOVERY_HELPER))?;
    install_helper_copy(source)
}

pub fn cancel(apply: bool) -> Result<RecoveryActionReport> {
    let current = status();
    let report = RecoveryActionReport {
        applied: apply,
        action: "cancel",
        deadline_unix_seconds: current.deadline_unix_seconds,
        timer_path: RECOVERY_TIMER.into(),
    };
    if !apply {
        return Ok(report);
    }
    require_root()?;
    disarm_files(true, true)?;
    Ok(report)
}

pub fn disarm_after_recovery() -> Result<()> {
    // This path runs inside the recovery service itself.
    disarm_files(true, false)
}

pub fn prove(seconds: u64, apply: bool) -> Result<RecoveryProofReport> {
    if !(1..=10).contains(&seconds) {
        bail!("proof delay must be between 1 and 10 seconds");
    }
    if !apply {
        return Ok(RecoveryProofReport {
            applied: false,
            fired: false,
            seconds,
        });
    }
    require_root()?;
    cleanup_proof();
    atomic_write(
        Path::new(PROOF_SERVICE),
        render_proof_service().as_bytes(),
        0o644,
    )?;
    atomic_write(
        Path::new(PROOF_TIMER),
        render_proof_timer(seconds).as_bytes(),
        0o644,
    )?;
    let result = (|| -> Result<bool> {
        run_systemctl(&["daemon-reload"])?;
        run_systemctl(&["start", PROOF_TIMER_NAME])?;
        let wait = Duration::from_millis(100);
        for _ in 0..((seconds + 5) * 10) {
            if Path::new(PROOF_MARKER).exists() {
                return Ok(true);
            }
            thread::sleep(wait);
        }
        Ok(false)
    })();
    cleanup_proof();
    run_systemctl(&["daemon-reload"])?;
    let fired = result?;
    if !fired {
        bail!("systemd recovery proof timer did not fire");
    }
    Ok(RecoveryProofReport {
        applied: true,
        fired,
        seconds,
    })
}

pub fn has_minimum_remaining(seconds: u64) -> bool {
    let current = status();
    report_has_minimum_remaining(&current, seconds)
}

fn report_has_minimum_remaining(current: &RecoveryTimerReport, seconds: u64) -> bool {
    current.armed
        && current
            .seconds_remaining
            .is_some_and(|value| value >= seconds)
}

fn classify_recovery_state(
    state_present: bool,
    state_valid: bool,
    timer_present: bool,
    timer_active: bool,
    timer_enabled: bool,
    seconds_remaining: Option<u64>,
) -> (&'static str, bool) {
    let complete = state_present
        && state_valid
        && timer_present
        && timer_active
        && timer_enabled
        && seconds_remaining.is_some();
    if complete && seconds_remaining.is_some_and(|seconds| seconds > 0) {
        ("armed", true)
    } else if complete && seconds_remaining == Some(0) {
        ("overdue", false)
    } else if !state_present && !timer_present && !timer_active && !timer_enabled {
        ("not_armed", false)
    } else {
        ("inconsistent", false)
    }
}

fn disarm_files(reload: bool, stop_recovery: bool) -> Result<()> {
    validate_existing_managed_timer(Path::new(RECOVERY_TIMER))?;
    validate_existing_deadline_state(Path::new(RECOVERY_DEADLINE_STATE))?;
    let timer_known = Path::new(RECOVERY_TIMER).try_exists()?
        || systemctl_check("is-active", TIMER_NAME)
        || systemctl_check("is-enabled", TIMER_NAME);
    if timer_known {
        run_systemctl(&["disable", "--now", TIMER_NAME])?;
        if systemctl_check("is-active", TIMER_NAME) || systemctl_check("is-enabled", TIMER_NAME) {
            bail!("automatic recovery timer remained active or enabled after disable");
        }
    }
    if stop_recovery
        && (timer_known
            || Path::new(RECOVERY_SERVICE).try_exists()?
            || systemctl_check("is-active", RECOVERY_SERVICE_NAME))
    {
        // Stopping the timer does not cancel an already queued service job.
        // Quiesce it before discarding deadline evidence; the caller must then
        // recheck sudo coupling in case recovery already removed it.
        run_systemctl(&["stop", RECOVERY_SERVICE_NAME])?;
        if systemctl_check("is-active", RECOVERY_SERVICE_NAME) {
            bail!("automatic recovery service remained active after stop");
        }
    }
    for path in [RECOVERY_TIMER, RECOVERY_DEADLINE_STATE] {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if reload {
        run_systemctl(&["daemon-reload"])?;
    }
    Ok(())
}

fn validate_recovery_service(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect recovery service {}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.permissions().mode() & 0o7777 != 0o644
    {
        bail!("recovery service must be a root-owned regular file with mode 0644");
    }
    if fs::read(path)? != EXPECTED_RECOVERY_SERVICE {
        bail!("recovery service differs from the exact packaged unit");
    }
    Ok(())
}

fn validate_helper_source(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect recovery helper source {}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
        || metadata.len() == 0
        || metadata.len() > MAX_HELPER_BYTES
    {
        bail!("recovery helper source is not a protected root-owned executable");
    }
    Ok(())
}

fn validate_recovery_helper(path: &Path) -> Result<()> {
    validate_recovery_helper_file(path)?;
    let recorded = read_recovery_helper_identity(Path::new(RECOVERY_HELPER_IDENTITY))?;
    let actual = recovery_helper_identity(path)?;
    if !helper_identity_matches(&recorded, &actual) {
        bail!("retained recovery helper differs from its durable identity");
    }
    Ok(())
}

fn validate_recovery_helper_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect retained recovery helper {}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o500
        || metadata.len() == 0
        || metadata.len() > MAX_HELPER_BYTES
    {
        bail!("retained recovery helper must be root-owned mode 0500");
    }
    Ok(())
}

fn recovery_helper_identity(path: &Path) -> Result<RecoveryHelperIdentity> {
    let mut input = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = input.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o500
        || metadata.len() == 0
        || metadata.len() > MAX_HELPER_BYTES
    {
        bail!("opened retained recovery helper is unsafe");
    }
    Ok(RecoveryHelperIdentity {
        schema_version: 1,
        sha256: hex::encode(hash_reader(&mut input)?),
        size: metadata.len(),
    })
}

fn read_recovery_helper_identity(path: &Path) -> Result<RecoveryHelperIdentity> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open retained recovery helper identity {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o600
    {
        bail!("retained recovery helper identity must be root-owned mode 0600");
    }
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    let identity: RecoveryHelperIdentity = serde_json::from_slice(&contents)?;
    if !valid_helper_identity(&identity) {
        bail!("retained recovery helper identity is invalid");
    }
    Ok(identity)
}

fn valid_helper_identity(identity: &RecoveryHelperIdentity) -> bool {
    identity.schema_version == 1
        && identity.size != 0
        && identity.size <= MAX_HELPER_BYTES
        && identity.sha256.len() == 64
        && identity
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn helper_identity_matches(
    recorded: &RecoveryHelperIdentity,
    actual: &RecoveryHelperIdentity,
) -> bool {
    valid_helper_identity(recorded) && valid_helper_identity(actual) && recorded == actual
}

fn ensure_recovery_directory() -> Result<()> {
    let path = Path::new(RECOVERY_DIRECTORY);
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o700
    {
        bail!("recovery directory must be root-owned mode 0700");
    }
    Ok(())
}

fn install_helper_copy(source: &Path) -> Result<()> {
    let mut input = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(source)?;
    let source_metadata = input.metadata()?;
    if !source_metadata.is_file()
        || source_metadata.uid() != 0
        || source_metadata.gid() != 0
        || source_metadata.mode() & 0o022 != 0
        || source_metadata.mode() & 0o111 == 0
        || source_metadata.len() == 0
        || source_metadata.len() > MAX_HELPER_BYTES
    {
        bail!("opened recovery helper source changed or is unsafe");
    }

    let temporary = Path::new(RECOVERY_DIRECTORY).join(format!(
        ".synctl.incomplete.{}.{}",
        std::process::id(),
        unix_seconds()?
    ));
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)?;
    let copy_result = (|| -> Result<[u8; 32]> {
        let mut source_hash = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        let mut copied = 0_u64;
        loop {
            let count = input.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            copied = copied
                .checked_add(count as u64)
                .context("recovery helper size overflow")?;
            if copied > MAX_HELPER_BYTES {
                bail!("recovery helper source grew beyond its size limit");
            }
            source_hash.update(&buffer[..count]);
            output.write_all(&buffer[..count])?;
        }
        if copied != source_metadata.len() || input.metadata()?.len() != source_metadata.len() {
            bail!("recovery helper source changed while it was copied");
        }
        output.sync_all()?;
        Ok(source_hash.finalize().into())
    })();
    drop(output);
    let source_hash = match copy_result {
        Ok(hash) => hash,
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
    };
    if hash_file(&temporary)? != source_hash {
        let _ = fs::remove_file(&temporary);
        bail!("retained recovery helper hash differs from its protected source");
    }
    fs::rename(&temporary, RECOVERY_HELPER)?;
    fs::File::open(RECOVERY_DIRECTORY)?.sync_all()?;
    validate_recovery_helper_file(Path::new(RECOVERY_HELPER))?;
    if hash_file(Path::new(RECOVERY_HELPER))? != source_hash {
        bail!("retained recovery helper changed after installation");
    }
    let identity = recovery_helper_identity(Path::new(RECOVERY_HELPER))?;
    if identity.sha256 != hex::encode(source_hash) {
        bail!("retained recovery helper identity differs from its protected source");
    }
    atomic_write(
        Path::new(RECOVERY_HELPER_IDENTITY),
        &serde_json::to_vec_pretty(&identity)?,
        0o600,
    )?;
    validate_recovery_helper(Path::new(RECOVERY_HELPER))?;
    Ok(())
}

fn hash_file(path: &Path) -> Result<[u8; 32]> {
    let mut input = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    hash_reader(&mut input)
}

fn hash_reader(input: &mut impl Read) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    let copied = std::io::copy(input, &mut HashWriter(&mut hash))?;
    if copied == 0 || copied > MAX_HELPER_BYTES {
        bail!("retained recovery helper has an invalid size");
    }
    Ok(hash.finalize().into())
}

struct HashWriter<'a>(&'a mut Sha256);

impl Write for HashWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0.update(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn validate_existing_managed_timer(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
        || !fs::read_to_string(path)?.starts_with(MANAGED_HEADER)
    {
        bail!("refusing to replace a recovery timer not safely owned by Syn");
    }
    Ok(())
}

fn read_deadline_state(path: &Path) -> Result<DeadlineState> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        bail!("recovery deadline state permissions are unsafe");
    }
    let state: DeadlineState = serde_json::from_slice(&fs::read(path)?)?;
    if state.schema_version != 1 || state.deadline_unix_seconds < state.armed_at_unix_seconds {
        bail!("recovery deadline state is invalid");
    }
    Ok(state)
}

fn validate_existing_deadline_state(path: &Path) -> Result<()> {
    match read_deadline_state(path) {
        Ok(_) => Ok(()),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn render_recovery_timer(deadline: u64) -> String {
    format!(
        "{MANAGED_HEADER}[Unit]\nDescription=Syn automatic sudo recovery deadline\n\n[Timer]\nOnCalendar=@{deadline}\nAccuracySec=1s\nPersistent=true\nUnit={RECOVERY_SERVICE_NAME}\n\n[Install]\nWantedBy=timers.target\n"
    )
}

fn render_proof_service() -> String {
    format!(
        "{MANAGED_HEADER}[Unit]\nDescription=Syn harmless recovery timer proof\n\n[Service]\nType=oneshot\nExecStart=/usr/bin/touch {PROOF_MARKER}\n"
    )
}

fn render_proof_timer(seconds: u64) -> String {
    format!(
        "{MANAGED_HEADER}[Unit]\nDescription=Syn harmless recovery timer proof\n\n[Timer]\nOnActiveSec={seconds}s\nAccuracySec=100ms\nUnit=syn-recovery-proof.service\n"
    )
}

fn cleanup_proof() {
    let _ = Command::new("systemctl")
        .args(["stop", PROOF_TIMER_NAME])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    for path in [PROOF_TIMER, PROOF_SERVICE, PROOF_MARKER] {
        let _ = fs::remove_file(path);
    }
}

fn run_systemctl(arguments: &[&str]) -> Result<()> {
    let status = Command::new("systemctl").args(arguments).status()?;
    if !status.success() {
        bail!("systemctl {} failed with {status}", arguments.join(" "));
    }
    Ok(())
}

fn systemctl_check(command: &str, unit: &str) -> bool {
    Command::new("systemctl")
        .args([command, "--quiet", unit])
        .status()
        .is_ok_and(|status| status.success())
}

fn unix_seconds() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_timer_uses_absolute_persistent_deadline() {
        let rendered = render_recovery_timer(1_700_000_000);
        assert!(rendered.starts_with(MANAGED_HEADER));
        assert!(rendered.contains("OnCalendar=@1700000000\n"));
        assert!(rendered.contains("Persistent=true\n"));
        assert!(!rendered.contains("OnBootSec="));
        assert!(!rendered.contains("OnActiveSec="));
    }

    #[test]
    fn proof_units_execute_only_fixed_touch_command() {
        let service = render_proof_service();
        let timer = render_proof_timer(2);
        assert!(service.contains("ExecStart=/usr/bin/touch /run/syn-recovery-proof-fired"));
        assert!(!service.contains("/bin/sh"));
        assert!(timer.contains("OnActiveSec=2s"));
    }

    #[test]
    fn arm_command_sequence_is_exact() {
        assert_eq!(
            ARM_SYSTEMCTL_COMMANDS,
            &[
                &["daemon-reload"][..],
                &["enable", "syn-auto-recover.timer"][..],
                &["restart", "syn-auto-recover.timer"][..],
            ]
        );
    }

    #[test]
    fn recovery_state_transitions_fail_closed() {
        assert_eq!(
            classify_recovery_state(false, true, false, false, false, None),
            ("not_armed", false)
        );
        assert_eq!(
            classify_recovery_state(true, true, true, true, true, Some(900)),
            ("armed", true)
        );
        assert_eq!(
            classify_recovery_state(true, true, true, true, true, Some(0)),
            ("overdue", false)
        );
        assert_eq!(
            classify_recovery_state(true, false, true, true, true, None),
            ("inconsistent", false)
        );
        assert_eq!(
            classify_recovery_state(true, true, true, false, true, Some(900)),
            ("inconsistent", false)
        );
    }

    #[test]
    fn minimum_window_requires_a_live_armed_deadline() {
        let report = RecoveryTimerReport {
            status: "armed",
            armed: true,
            state_valid: true,
            timer_active: true,
            timer_enabled: true,
            deadline_unix_seconds: Some(1_000),
            seconds_remaining: Some(MIN_INSTALL_RECOVERY_SECONDS),
            state_path: RECOVERY_DEADLINE_STATE.into(),
            timer_path: RECOVERY_TIMER.into(),
        };
        assert!(report_has_minimum_remaining(
            &report,
            MIN_INSTALL_RECOVERY_SECONDS
        ));
        let mut expired = report.clone();
        expired.seconds_remaining = Some(MIN_INSTALL_RECOVERY_SECONDS - 1);
        assert!(!report_has_minimum_remaining(
            &expired,
            MIN_INSTALL_RECOVERY_SECONDS
        ));
        expired.armed = false;
        expired.seconds_remaining = Some(MIN_INSTALL_RECOVERY_SECONDS);
        assert!(!report_has_minimum_remaining(
            &expired,
            MIN_INSTALL_RECOVERY_SECONDS
        ));
    }

    #[test]
    fn recovery_service_retries_boundedly_and_allows_sudo_validation() {
        let service = String::from_utf8(EXPECTED_RECOVERY_SERVICE.to_vec()).unwrap();
        assert!(!service.contains("ConditionPathExists="));
        assert!(service.contains(
            "ExecStart=/var/lib/syn/recovery/synctl recover --restore-local-sudo --apply"
        ));
        assert!(service.contains("Restart=on-failure\n"));
        assert!(service.contains("RestartSec=2s\n"));
        assert!(service.contains("StartLimitIntervalSec=30s\n"));
        assert!(service.contains("StartLimitBurst=5\n"));
        assert!(service.contains("NoNewPrivileges=no\n"));
        assert!(!service.contains("NoNewPrivileges=yes\n"));
    }

    #[test]
    fn retained_helper_identity_rejects_content_or_size_drift() {
        let identity = RecoveryHelperIdentity {
            schema_version: 1,
            sha256: "ab".repeat(32),
            size: 4096,
        };
        assert!(helper_identity_matches(&identity, &identity));
        assert!(!helper_identity_matches(
            &identity,
            &RecoveryHelperIdentity {
                sha256: "cd".repeat(32),
                ..identity.clone()
            }
        ));
        assert!(!helper_identity_matches(
            &identity,
            &RecoveryHelperIdentity {
                size: 4097,
                ..identity.clone()
            }
        ));
        assert!(!valid_helper_identity(&RecoveryHelperIdentity {
            sha256: "AB".repeat(32),
            ..identity
        }));
    }
}
