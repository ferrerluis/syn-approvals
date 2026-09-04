use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::{atomic_write, require_root};

pub const RECOVERY_SERVICE: &str = "/usr/lib/systemd/system/syn-auto-recover.service";
pub const RECOVERY_TIMER: &str = "/etc/systemd/system/syn-auto-recover.timer";
pub const RECOVERY_DEADLINE_STATE: &str = "/var/lib/syn/recovery-deadline.json";
const TIMER_NAME: &str = "syn-auto-recover.timer";
const RECOVERY_SERVICE_NAME: &str = "syn-auto-recover.service";
const PROOF_SERVICE: &str = "/run/systemd/system/syn-recovery-proof.service";
const PROOF_TIMER: &str = "/run/systemd/system/syn-recovery-proof.timer";
const PROOF_TIMER_NAME: &str = "syn-recovery-proof.timer";
const PROOF_MARKER: &str = "/run/syn-recovery-proof-fired";
const MANAGED_HEADER: &str = "# Managed by Syn. Do not edit.\n";
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
        let _ = disarm_files(true);
        return Err(error);
    }
    Ok(report)
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
    if systemctl_check("is-active", RECOVERY_SERVICE_NAME) {
        bail!("recovery is already running; refusing to race it");
    }
    disarm_files(true)?;
    Ok(report)
}

pub fn disarm_after_recovery() -> Result<()> {
    disarm_files(true)
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

fn disarm_files(reload: bool) -> Result<()> {
    validate_existing_managed_timer(Path::new(RECOVERY_TIMER))?;
    validate_existing_deadline_state(Path::new(RECOVERY_DEADLINE_STATE))?;
    let _ = Command::new("systemctl")
        .args(["disable", "--now", TIMER_NAME])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
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
        || metadata.permissions().mode() & 0o022 != 0
    {
        bail!("recovery service must be a root-owned, non-writable regular file");
    }
    let contents = fs::read_to_string(path)?;
    if !contents
        .lines()
        .any(|line| line == "ExecStart=/usr/bin/synctl recover --restore-local-sudo --apply")
    {
        bail!("recovery service has an unexpected command");
    }
    Ok(())
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
}
