use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use syn_config::{InstallState, PluginConfig, Policy, StatOverrideRecord};

use crate::recovery_timer;
use crate::{atomic_write, require_root};

const SUDO_CONF: &str = "/etc/sudo.conf";
const SUDOERS_RULE: &str = "/etc/sudoers.d/90-syn-managed-user";
const PLUGIN_PATH: &str = "/usr/libexec/sudo/syn_approval.so";
const PAIRING_MARKER: &str = "/var/lib/syn/pairing-complete.json";
const PREFLIGHT_MARKER: &str = "/var/lib/syn/preflight-complete.json";
const BACKUP_PATH: &str = "/var/lib/syn/backups/sudo.conf.before-syn";
const PLUGIN_LINE: &str =
    "Plugin syn_approval /usr/libexec/sudo/syn_approval.so config=/etc/syn/plugin.toml";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstallPlan {
    pub supported_target: bool,
    pub managed_user: String,
    pub managed_uid: Option<u32>,
    pub state_path: PathBuf,
    pub actions: Vec<String>,
    pub blockers: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RecoveryResult {
    pub applied: bool,
    pub actions: Vec<String>,
}

pub fn plan(user: &str, state_path: &Path) -> Result<InstallPlan> {
    validate_user(user)?;
    let managed_uid = lookup_uid(user);
    let supported_target = std::env::consts::OS == "linux"
        && std::env::consts::ARCH == "aarch64"
        && os_release_value("ID").as_deref() == Some("ubuntu")
        && os_release_value("VERSION_ID").as_deref() == Some("26.04");
    let required = [
        "/usr/bin/sudo.ws",
        "/usr/sbin/visudo.ws",
        PLUGIN_PATH,
        "/etc/syn/agent.toml",
        "/etc/syn/plugin.toml",
        "/etc/syn/policy.toml",
        "/etc/syn/keys/target-private.pem",
        "/etc/syn/keys/target-public.pem",
        "/etc/syn/keys/approval-public.pem",
        "/etc/syn/keys/denial-public.pem",
        PAIRING_MARKER,
        PREFLIGHT_MARKER,
    ];
    let mut blockers = Vec::new();
    if !supported_target {
        blockers.push("apply is supported only on Ubuntu 26.04 ARM64".into());
    }
    if managed_uid.is_none() {
        blockers.push(format!("managed user {user:?} does not exist"));
    }
    for path in required {
        if !Path::new(path).exists() {
            blockers.push(format!("required staged file is missing: {path}"));
        }
    }
    if state_path.exists() {
        blockers.push(format!(
            "installation state already exists: {}",
            state_path.display()
        ));
    }
    if !recovery_timer::has_minimum_remaining(recovery_timer::MIN_INSTALL_RECOVERY_SECONDS) {
        blockers
            .push("Pi-local automatic sudo recovery needs at least 10 minutes remaining".into());
    }
    match validate_staged_security_state(user, managed_uid) {
        Ok(()) => {}
        Err(error) => blockers.push(format!("staged security state is invalid: {error:#}")),
    }
    Ok(InstallPlan {
        supported_target,
        managed_user: user.into(),
        managed_uid,
        state_path: state_path.into(),
        actions: vec![
            "record current sudo alternative and provider modes".into(),
            "persistently remove setuid from alternate sudo providers".into(),
            "select /usr/bin/sudo.ws".into(),
            "enable the root-owned Syn approval plug-in".into(),
            "validate plug-in loading and sudoers syntax".into(),
            "enable and start the rootless syn-agent service".into(),
            "add the managed one-user NOPASSWD rule last".into(),
        ],
        blockers,
    })
}

fn validate_staged_security_state(user: &str, uid: Option<u32>) -> Result<()> {
    let uid = uid.context("managed user does not exist")?;
    let plugin = PluginConfig::load("/etc/syn/plugin.toml")?;
    plugin.validate()?;
    let policy = Policy::load(&plugin.policy_path)?;
    policy.validate()?;
    if plugin.managed_user != user
        || plugin.managed_uid != uid
        || policy.managed_user != user
        || policy.managed_uid != uid
    {
        bail!("requested, plug-in, and policy managed identities differ");
    }
    let approval =
        syn_protocol::verifying_key_from_pem(&fs::read_to_string(&plugin.approval_public_key)?)?;
    let expected_key_id = syn_protocol::key_id_hex(&approval);
    let preflight: serde_json::Value = serde_json::from_slice(&fs::read(PREFLIGHT_MARKER)?)?;
    let pairing: serde_json::Value = serde_json::from_slice(&fs::read(PAIRING_MARKER)?)?;
    if preflight != pairing
        || preflight["schema_version"] != 1
        || preflight["target_id"] != plugin.target_id
        || preflight["approver_key_id"] != expected_key_id
        || preflight["test_executable"] != "/usr/bin/true"
    {
        bail!("pairing and signed preflight evidence do not match current keys");
    }
    let completed = preflight["completed_at_unix_ms"]
        .as_i64()
        .context("preflight completion time is missing")?;
    let now = syn_protocol::unix_time_ms();
    if completed > now || now - completed > 1_800_000 {
        bail!("signed preflight is older than 30 minutes or from the future");
    }
    for path in [PREFLIGHT_MARKER, PAIRING_MARKER] {
        let metadata = fs::metadata(path)?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            bail!("{path} is not root-owned and protected from writes");
        }
    }
    Ok(())
}

pub fn apply(plan: InstallPlan, state_path: &Path) -> Result<()> {
    require_root()?;
    if !plan.blockers.is_empty() {
        bail!("installation is blocked: {}", plan.blockers.join("; "));
    }
    let managed_uid = plan.managed_uid.context("managed UID disappeared")?;
    if lookup_uid(&plan.managed_user) != Some(managed_uid) {
        bail!("managed user changed between planning and apply");
    }
    if !recovery_timer::has_minimum_remaining(recovery_timer::MIN_INSTALL_RECOVERY_SECONDS) {
        bail!("automatic sudo recovery timer has less than 10 minutes remaining");
    }

    let previous_alternative = fs::read_link("/etc/alternatives/sudo")
        .ok()
        .map(|path| path.display().to_string());
    let backup = PathBuf::from(BACKUP_PATH);
    if backup.exists() {
        bail!("refusing to overwrite sudo.conf recovery backup");
    }
    if let Some(parent) = backup.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(SUDO_CONF, &backup)?;
    fs::set_permissions(&backup, fs::Permissions::from_mode(0o600))?;

    let providers = command_stdout("update-alternatives", &["--list", "sudo"])?;
    let mut stat_overrides = Vec::new();
    for provider in providers
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let canonical = fs::canonicalize(provider).unwrap_or_else(|_| PathBuf::from(provider));
        if canonical == Path::new("/usr/bin/sudo.ws") || provider == "/usr/bin/sudo.ws" {
            continue;
        }
        let metadata = fs::metadata(&canonical)
            .with_context(|| format!("inspect alternate provider {}", canonical.display()))?;
        if metadata.mode() & 0o4000 == 0 {
            continue;
        }
        let existing = Command::new("dpkg-statoverride")
            .args(["--list", canonical.to_string_lossy().as_ref()])
            .output()?;
        if existing.status.success() && !existing.stdout.is_empty() {
            bail!(
                "alternate provider {} already has an administrator stat override",
                canonical.display()
            );
        }
        stat_overrides.push(StatOverrideRecord {
            path: canonical,
            previous_mode: metadata.mode() & 0o7777,
            previous_owner: metadata.uid(),
            previous_group: metadata.gid(),
        });
    }

    let mut state = InstallState {
        schema_version: 1,
        phase: "prepared".into(),
        managed_user: plan.managed_user.clone(),
        managed_uid,
        previous_sudo_alternative: previous_alternative,
        stat_overrides: stat_overrides.clone(),
        created_paths: vec![PathBuf::from(SUDOERS_RULE)],
        sudo_conf_backup: Some(backup),
    };
    write_state(state_path, &state)?;

    let result = (|| -> Result<()> {
        for record in &stat_overrides {
            run(
                "dpkg-statoverride",
                &[
                    "--add",
                    "root",
                    "root",
                    "0755",
                    record.path.to_string_lossy().as_ref(),
                ],
            )?;
            if fs::metadata(&record.path)?.mode() & 0o4000 != 0 {
                bail!(
                    "setuid override did not take effect for {}",
                    record.path.display()
                );
            }
        }
        state.phase = "alternate_providers_disabled".into();
        write_state(state_path, &state)?;

        run(
            "update-alternatives",
            &["--set", "sudo", "/usr/bin/sudo.ws"],
        )?;
        let selected = fs::canonicalize("/etc/alternatives/sudo")?;
        let expected = fs::canonicalize("/usr/bin/sudo.ws")?;
        if selected != expected {
            bail!("sudo alternative did not resolve to sudo.ws");
        }
        state.phase = "sudo_ws_selected".into();
        write_state(state_path, &state)?;

        let mut sudo_conf = fs::read_to_string(SUDO_CONF)?;
        if !sudo_conf.lines().any(|line| line.trim() == PLUGIN_LINE) {
            if !sudo_conf.ends_with('\n') {
                sudo_conf.push('\n');
            }
            sudo_conf.push_str(PLUGIN_LINE);
            sudo_conf.push('\n');
            atomic_write(Path::new(SUDO_CONF), sudo_conf.as_bytes(), 0o644)?;
        }
        run("/usr/bin/sudo.ws", &["-V"])?;
        state.phase = "plugin_enabled".into();
        write_state(state_path, &state)?;

        run("systemctl", &["enable", "--now", "syn-agent.service"])?;
        run("systemctl", &["is-active", "--quiet", "syn-agent.service"])?;
        let rule = format!(
            "# Managed by Syn. Remove this before disabling syn_approval.\n{} ALL=(ALL:ALL) NOPASSWD: ALL\n",
            plan.managed_user
        );
        let temporary_rule = Path::new("/etc/sudoers.d/.90-syn-managed-user.tmp");
        atomic_write(temporary_rule, rule.as_bytes(), 0o440)?;
        run(
            "/usr/sbin/visudo.ws",
            &["-cf", temporary_rule.to_string_lossy().as_ref()],
        )?;
        fs::rename(temporary_rule, SUDOERS_RULE)?;
        run("/usr/sbin/visudo.ws", &["-cf", "/etc/sudoers"])?;
        state.phase = "armed".into();
        write_state(state_path, &state)?;
        Ok(())
    })();

    if let Err(error) = result {
        if let Err(rollback_error) = recover(state_path, true) {
            bail!("install failed: {error:#}; recovery also failed: {rollback_error:#}");
        }
        return Err(error);
    }
    Ok(())
}

pub fn recover(state_path: &Path, apply: bool) -> Result<RecoveryResult> {
    let state: InstallState = serde_json::from_slice(
        &fs::read(state_path).with_context(|| format!("read {}", state_path.display()))?,
    )?;
    let mut actions = vec![
        format!("remove {SUDOERS_RULE}"),
        "restore the pre-Syn sudo.conf backup".into(),
        "restore the previous sudo alternative".into(),
        "remove only stat overrides recorded by Syn".into(),
        "disable syn-agent.service".into(),
    ];
    if !apply {
        return Ok(RecoveryResult {
            applied: false,
            actions,
        });
    }
    require_root()?;

    if Path::new(SUDOERS_RULE).exists() {
        fs::remove_file(SUDOERS_RULE)?;
    }
    recovery_timer::disarm_after_recovery()?;
    if let Some(backup) = &state.sudo_conf_backup {
        if backup.exists() {
            atomic_write(Path::new(SUDO_CONF), &fs::read(backup)?, 0o644)?;
        }
    }
    if let Some(previous) = &state.previous_sudo_alternative {
        run("update-alternatives", &["--set", "sudo", previous])?;
    }
    for record in &state.stat_overrides {
        let path = record.path.to_string_lossy();
        let _ = Command::new("dpkg-statoverride")
            .args(["--remove", path.as_ref()])
            .status();
        fs::set_permissions(
            &record.path,
            fs::Permissions::from_mode(record.previous_mode),
        )?;
        let c_path = std::ffi::CString::new(record.path.as_os_str().as_encoded_bytes())?;
        if unsafe {
            libc::chown(
                c_path.as_ptr(),
                record.previous_owner,
                record.previous_group,
            )
        } != 0
        {
            bail!("unable to restore ownership for {}", record.path.display());
        }
    }
    let _ = Command::new("systemctl")
        .args(["disable", "--now", "syn-agent.service"])
        .status();
    run("/usr/sbin/visudo.ws", &["-cf", "/etc/sudoers"])?;
    actions.push("ordinary password sudo restored; keys retained".into());
    Ok(RecoveryResult {
        applied: true,
        actions,
    })
}

fn write_state(path: &Path, state: &InstallState) -> Result<()> {
    atomic_write(path, &serde_json::to_vec_pretty(state)?, 0o600)
}

fn lookup_uid(user: &str) -> Option<u32> {
    let output = Command::new("id").args(["-u", user]).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).ok()?.trim().parse().ok())
        .flatten()
}

fn validate_user(user: &str) -> Result<()> {
    if user.is_empty()
        || user.len() > 64
        || !user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        bail!("managed user contains unsupported characters");
    }
    Ok(())
}

fn os_release_value(key: &str) -> Option<String> {
    fs::read_to_string("/etc/os-release")
        .ok()?
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once('=')?;
            (name == key).then(|| value.trim_matches('"').to_owned())
        })
}

fn command_stdout(program: &str, arguments: &[&str]) -> Result<String> {
    let output = Command::new(program).args(arguments).output()?;
    if !output.status.success() {
        bail!("{program} failed with {}", output.status);
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn run(program: &str, arguments: &[&str]) -> Result<()> {
    let status = Command::new(program).args(arguments).status()?;
    if !status.success() {
        bail!("{program} failed with {status}");
    }
    Ok(())
}
