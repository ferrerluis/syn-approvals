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
const PLUGIN_LINE: &str =
    "Plugin syn_approval /usr/libexec/sudo/syn_approval.so config=/etc/syn/plugin.toml";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstallPlan {
    pub shadow_mode: bool,
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

pub fn plan(user: &str, state_path: &Path, shadow: bool) -> Result<InstallPlan> {
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
    if state_path != Path::new(syn_config::DEFAULT_INSTALL_STATE) {
        blockers.push("automatic recovery requires the standard install-state path".into());
    }
    if Path::new(SUDOERS_RULE).exists() {
        blockers.push("existing Syn sudoers rule must be recovered before installation".into());
    }
    if let Ok(contents) = fs::read_to_string(SUDO_CONF) {
        if contents.lines().any(|line| {
            let mut words = line.split_whitespace();
            words.next() == Some("Plugin") && words.next() == Some("syn_approval")
        }) {
            blockers.push("Syn approval plug-in is already registered".into());
        }
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
        shadow_mode: shadow,
        supported_target,
        managed_user: user.into(),
        managed_uid,
        state_path: state_path.into(),
        actions: installation_actions(shadow),
        blockers,
    })
}

fn installation_actions(shadow: bool) -> Vec<String> {
    if shadow {
        vec![
            "record a protected sudo.conf backup and shadow recovery state".into(),
            "preserve the current sudo alternative and provider modes".into(),
            "enable the root-owned Syn approval plug-in for direct sudo.ws tests".into(),
            "validate plug-in loading and sudoers syntax".into(),
            "keep ordinary password authentication; do not create a NOPASSWD rule".into(),
        ]
    } else {
        vec![
            "record current sudo alternative and provider modes".into(),
            "persistently remove setuid from alternate sudo providers".into(),
            "select /usr/bin/sudo.ws".into(),
            "enable the root-owned Syn approval plug-in".into(),
            "validate plug-in loading and sudoers syntax".into(),
            "enable and start the rootless syn-agent service".into(),
            "add the managed one-user NOPASSWD rule last".into(),
        ]
    }
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
    // Re-read live prerequisites; never apply a stale preview.
    let plan = self::plan(&plan.managed_user, state_path, plan.shadow_mode)?;
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
    if plan.shadow_mode {
        return apply_shadow(&plan, state_path, managed_uid);
    }

    let previous_alternative = fs::read_link("/etc/alternatives/sudo")
        .ok()
        .map(|path| path.display().to_string());
    validate_root_file(Path::new(SUDO_CONF))?;
    validate_root_file(Path::new(PLUGIN_PATH))?;
    let backup = PathBuf::from(format!(
        "/var/lib/syn/backups/sudo.conf.install.{}.{}",
        syn_protocol::unix_time_ms(),
        std::process::id()
    ));

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

    // Retain each backup independently so recovery does not prevent a later
    // guarded reinstall, and never truncate a previous recovery copy.
    write_new_backup(&backup, &fs::read(SUDO_CONF)?)?;
    let mut state = InstallState {
        schema_version: 1,
        phase: "prepared".into(),
        managed_user: plan.managed_user.clone(),
        managed_uid,
        previous_sudo_alternative: previous_alternative,
        stat_overrides: stat_overrides.clone(),
        created_paths: vec![PathBuf::from(SUDOERS_RULE)],
        sudo_conf_backup: Some(backup),
        shadow_mode: false,
        sudo_conf_original_mode: Some(fs::metadata(SUDO_CONF)?.mode() & 0o7777),
        previous_sudo_alternative_auto: Some(sudo_alternative_auto()?),
    };
    write_state(state_path, &state)?;

    let result = (|| -> Result<()> {
        for record in &stat_overrides {
            let path = record.path.to_string_lossy();
            run("dpkg-statoverride", &disable_provider_arguments(&path))?;
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
        let rule = managed_rule(&plan.managed_user);
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
    validate_root_file(state_path)?;
    let state: InstallState = serde_json::from_slice(
        &fs::read(state_path).with_context(|| format!("read {}", state_path.display()))?,
    )?;
    if state.schema_version != 1 {
        bail!("unsupported installation state schema");
    }
    if state.shadow_mode {
        return recover_shadow(state_path, &state, apply);
    }
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
    if let Some(backup) = &state.sudo_conf_backup {
        validate_root_file(backup)?;
        atomic_write(
            Path::new(SUDO_CONF),
            &fs::read(backup)?,
            state.sudo_conf_original_mode.unwrap_or(0o644),
        )?;
    }
    if let Some(previous) = &state.previous_sudo_alternative {
        if state.previous_sudo_alternative_auto == Some(true) {
            run("update-alternatives", &["--auto", "sudo"])?;
        } else {
            run("update-alternatives", &["--set", "sudo", previous])?;
        }
    }
    for record in &state.stat_overrides {
        let path = record.path.to_string_lossy();
        let existing = Command::new("dpkg-statoverride")
            .args(["--list", path.as_ref()])
            .output()?;
        if existing.status.success() {
            validate_syn_override(&String::from_utf8(existing.stdout)?, &path)?;
            run("dpkg-statoverride", &["--remove", &path])?;
        } else if existing.status.code() != Some(1) || !existing.stdout.is_empty() {
            bail!("unable to inspect stat override for {path}");
        }
        // chown can clear setuid even when the owner is unchanged. Restore
        // ownership first, then mode, through one non-symlink file descriptor.
        restore_provider_metadata(record)?;
    }
    run("systemctl", &["disable", "--now", "syn-agent.service"])?;
    run("/usr/sbin/visudo.ws", &["-cf", "/etc/sudoers"])?;
    archive_recovered_state(
        state_path,
        state
            .sudo_conf_backup
            .as_deref()
            .context("recovery backup is missing")?,
    )?;
    recovery_timer::disarm_after_recovery()?;
    actions.push("ordinary password sudo restored; keys retained".into());
    Ok(RecoveryResult {
        applied: true,
        actions,
    })
}

fn sudo_alternative_auto() -> Result<bool> {
    let query = command_stdout("update-alternatives", &["--query", "sudo"])?;
    parse_alternative_auto(&query)
}

pub fn check_installed_coupling(state_path: &Path) -> Result<String> {
    validate_root_file(state_path)?;
    let state: InstallState = serde_json::from_slice(&fs::read(state_path)?)?;
    if state.schema_version != 1 || state.shadow_mode || state.phase != "armed" {
        bail!("installation is not in the armed phase");
    }
    if lookup_uid(&state.managed_user) != Some(state.managed_uid) {
        bail!("managed account no longer matches the installed UID");
    }
    if fs::canonicalize("/usr/bin/sudo")? != fs::canonicalize("/usr/bin/sudo.ws")? {
        bail!("ordinary sudo does not select sudo.ws");
    }
    for path in [SUDO_CONF, SUDOERS_RULE, PLUGIN_PATH] {
        validate_root_file(Path::new(path))?;
    }
    validate_coupling_contents(
        &fs::read_to_string(SUDO_CONF)?,
        &fs::read_to_string(SUDOERS_RULE)?,
        &state.managed_user,
    )?;
    for record in &state.stat_overrides {
        let path = record.path.to_string_lossy();
        validate_syn_override(
            &command_stdout("dpkg-statoverride", &["--list", &path])?,
            &path,
        )?;
        if fs::metadata(&record.path)?.mode() & 0o4000 != 0 {
            bail!("recorded alternate provider is still setuid");
        }
    }
    run("systemctl", &["is-active", "--quiet", "syn-agent.service"])?;
    Ok(format!("armed for {} ({}); sudo.ws, global plug-in, exact one-user rule, persistent provider overrides, and active relay verified", state.managed_user, state.managed_uid))
}

fn managed_rule(user: &str) -> String {
    format!("# Managed by Syn. Remove this before disabling syn_approval.\n{user} ALL=(ALL:ALL) NOPASSWD: ALL\n")
}

fn validate_coupling_contents(sudo_conf: &str, rule: &str, user: &str) -> Result<()> {
    validate_user(user)?;
    let registrations: Vec<_> = sudo_conf
        .lines()
        .filter(|line| {
            let mut words = line.split_whitespace();
            words.next() == Some("Plugin") && words.next() == Some("syn_approval")
        })
        .collect();
    if registrations.len() != 1 || registrations[0].trim() != PLUGIN_LINE {
        bail!("expected exactly one global Syn plug-in registration");
    }
    if rule != managed_rule(user) {
        bail!("managed sudoers rule differs from the exact one-user rule");
    }
    Ok(())
}

fn parse_alternative_auto(query: &str) -> Result<bool> {
    match query.lines().find_map(|line| line.strip_prefix("Status: ")) {
        Some("auto") => Ok(true),
        Some("manual") => Ok(false),
        _ => bail!("sudo alternative selection mode is missing or unknown"),
    }
}

fn validate_root_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        bail!(
            "{} must be a root-owned regular file protected from writes",
            path.display()
        );
    }
    Ok(())
}

fn disable_provider_arguments(path: &str) -> [&str; 6] {
    ["--update", "--add", "root", "root", "0755", path]
}

fn validate_syn_override(output: &str, path: &str) -> Result<()> {
    let fields: Vec<_> = output.split_whitespace().collect();
    if fields.len() != 4
        || fields[0] != "root"
        || fields[1] != "root"
        || u32::from_str_radix(fields[2], 8).ok() != Some(0o755)
        || fields[3] != path
    {
        bail!("stat override no longer matches Syn's recorded change: {path}");
    }
    Ok(())
}

fn restore_provider_metadata(record: &StatOverrideRecord) -> Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&record.path)?;
    if !file.metadata()?.is_file() {
        bail!("provider is not a regular file: {}", record.path.display());
    }
    if unsafe {
        libc::fchown(
            file.as_raw_fd(),
            record.previous_owner,
            record.previous_group,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("restore provider ownership");
    }
    file.set_permissions(fs::Permissions::from_mode(record.previous_mode))?;
    let metadata = file.metadata()?;
    if metadata.uid() != record.previous_owner
        || metadata.gid() != record.previous_group
        || metadata.mode() & 0o7777 != record.previous_mode
    {
        bail!("provider metadata restoration did not match recorded state");
    }
    Ok(())
}

fn write_new_backup(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    fs::File::open(path.parent().context("backup parent is missing")?)?.sync_all()?;
    Ok(())
}

fn archive_recovered_state(state_path: &Path, backup: &Path) -> Result<()> {
    let archived = PathBuf::from(format!("{}.recovered-state.json", backup.display()));
    if archived.exists() {
        bail!("recovery archive already exists");
    }
    fs::rename(state_path, &archived)?;
    fs::File::open(archived.parent().context("archive parent is missing")?)?.sync_all()?;
    fs::File::open(state_path.parent().context("state parent is missing")?)?.sync_all()?;
    Ok(())
}

fn apply_shadow(plan: &InstallPlan, state_path: &Path, managed_uid: u32) -> Result<()> {
    validate_root_file(Path::new(SUDO_CONF))?;
    validate_root_file(Path::new(PLUGIN_PATH))?;
    let original = fs::read(SUDO_CONF)?;
    let original_mode = fs::metadata(SUDO_CONF)?.mode() & 0o7777;
    let backup = PathBuf::from(format!(
        "/var/lib/syn/backups/sudo.conf.shadow.{}",
        syn_protocol::unix_time_ms()
    ));
    // create_new refuses collisions and symlinks; retain this backup after recovery.
    write_new_backup(&backup, &original)?;
    let mut state = InstallState {
        schema_version: 1,
        phase: "shadow_prepared".into(),
        managed_user: plan.managed_user.clone(),
        managed_uid,
        previous_sudo_alternative: Some(
            fs::read_link("/etc/alternatives/sudo")?
                .display()
                .to_string(),
        ),
        previous_sudo_alternative_auto: Some(sudo_alternative_auto()?),
        stat_overrides: vec![],
        created_paths: vec![],
        sudo_conf_backup: Some(backup),
        sudo_conf_original_mode: Some(original_mode),
        shadow_mode: true,
    };
    // The timer can recover even if the process dies immediately after this write.
    write_state(state_path, &state)?;
    let result = (|| -> Result<()> {
        let mut contents = String::from_utf8(original)?;
        if !contents.ends_with('\n') {
            contents.push('\n');
        }
        contents.push_str(PLUGIN_LINE);
        contents.push('\n');
        atomic_write(Path::new(SUDO_CONF), contents.as_bytes(), original_mode)?;
        run("/usr/bin/sudo.ws", &["-V"])?;
        run("/usr/sbin/visudo.ws", &["-cf", "/etc/sudoers"])?;
        if Path::new(SUDOERS_RULE).exists() {
            bail!("unexpected Syn sudoers rule during shadow setup");
        }
        state.phase = "shadow_enabled".into();
        write_state(state_path, &state)
    })();
    if let Err(error) = result {
        if let Err(rollback) = recover_shadow(state_path, &state, true) {
            bail!("shadow setup failed: {error:#}; recovery also failed: {rollback:#}");
        }
        return Err(error);
    }
    Ok(())
}

fn recover_shadow(state_path: &Path, state: &InstallState, apply: bool) -> Result<RecoveryResult> {
    let actions = vec![
        format!("remove {SUDOERS_RULE} first if present"),
        "restore original sudo.conf contents and mode".into(),
        "preserve providers and agent state, which shadow setup does not change".into(),
        "validate sudoers, archive shadow state, and cancel automatic recovery".into(),
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
    let backup = state
        .sudo_conf_backup
        .as_ref()
        .context("shadow backup is missing from state")?;
    validate_root_file(backup)?;
    let original = fs::read(backup)?;
    atomic_write(
        Path::new(SUDO_CONF),
        &original,
        state
            .sudo_conf_original_mode
            .context("shadow backup mode is missing")?,
    )?;
    if fs::read(SUDO_CONF)? != original {
        bail!("shadow recovery content verification failed");
    }
    run("/usr/sbin/visudo.ws", &["-cf", "/etc/sudoers"])?;
    // Archive rather than overwrite: the next shadow/install run starts clean.
    archive_recovered_state(state_path, backup)?;
    recovery_timer::disarm_after_recovery()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(name: &str) -> Self {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "syn-installer-{name}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn override_updates_live_permissions_and_only_our_override_can_be_removed() {
        let path = "/usr/lib/cargo/bin/sudo";
        assert_eq!(
            disable_provider_arguments(path),
            ["--update", "--add", "root", "root", "0755", path]
        );
        assert!(validate_syn_override(&format!("root root 755 {path}\n"), path).is_ok());
        assert!(validate_syn_override(&format!("root root 0755 {path}\n"), path).is_ok());
        for invalid in [
            format!("root root 4755 {path}"),
            format!("someone root 755 {path}"),
            "root root 755 /another/path".into(),
            format!("root root 755 {path}\nroot root 755 {path}"),
            String::new(),
        ] {
            assert!(validate_syn_override(&invalid, path).is_err());
        }
    }

    #[test]
    fn installed_coupling_rejects_missing_duplicate_or_modified_rules() {
        let user = "managed";
        let rule = managed_rule(user);
        assert!(validate_coupling_contents(PLUGIN_LINE, &rule, user).is_ok());
        for conf in [
            String::new(),
            format!("# {PLUGIN_LINE}"),
            format!("{PLUGIN_LINE}\n{PLUGIN_LINE}"),
            PLUGIN_LINE.replace("config=", "other="),
        ] {
            assert!(validate_coupling_contents(&conf, &rule, user).is_err());
        }
        for invalid in [
            String::new(),
            managed_rule("someone_else"),
            format!("{rule}ALL ALL=(ALL) NOPASSWD: ALL\n"),
        ] {
            assert!(validate_coupling_contents(PLUGIN_LINE, &invalid, user).is_err());
        }
    }

    #[test]
    fn recovery_restores_setuid_after_ownership_and_rejects_symlinks() {
        let directory = TestDirectory::new("metadata");
        let path = directory.0.join("inert-provider-fixture");
        fs::write(&path, b"inert test fixture, never executed").unwrap();
        let metadata = fs::metadata(&path).unwrap();
        let record = StatOverrideRecord {
            path: path.clone(),
            previous_mode: 0o4755,
            previous_owner: metadata.uid(),
            previous_group: metadata.gid(),
        };
        restore_provider_metadata(&record).unwrap();
        let restored = fs::metadata(&path).unwrap();
        assert_eq!(restored.uid(), record.previous_owner);
        assert_eq!(restored.gid(), record.previous_group);
        assert_eq!(restored.mode() & 0o7777, 0o4755);

        let link = directory.0.join("provider-link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(restore_provider_metadata(&StatOverrideRecord {
            path: link,
            ..record
        })
        .is_err());
    }

    #[test]
    fn backups_and_recovery_archives_are_preserved_across_reinstallation() {
        let directory = TestDirectory::new("archive");
        let state = directory.0.join("install-state.json");
        for iteration in 0..2 {
            let backup = directory.0.join(format!("sudo.conf.{iteration}"));
            write_new_backup(&backup, b"original sudo configuration").unwrap();
            assert!(write_new_backup(&backup, b"replacement").is_err());
            assert_eq!(fs::read(&backup).unwrap(), b"original sudo configuration");
            assert_eq!(fs::metadata(&backup).unwrap().mode() & 0o7777, 0o600);
            fs::write(&state, b"recorded recovery state").unwrap();
            archive_recovered_state(&state, &backup).unwrap();
            assert!(!state.exists());
            assert_eq!(
                fs::read(format!("{}.recovered-state.json", backup.display())).unwrap(),
                b"recorded recovery state"
            );
            fs::write(&state, b"new state must survive archive collision").unwrap();
            assert!(archive_recovered_state(&state, &backup).is_err());
            assert!(state.exists());
        }
    }

    #[test]
    fn shadow_plan_never_changes_providers_or_adds_passwordless_access() {
        let actions = installation_actions(true);
        assert_eq!(actions.len(), 5);
        assert!(actions
            .iter()
            .any(|action| action.contains("do not create a NOPASSWD rule")));
        assert!(!actions.iter().any(|action| action.starts_with("select ")
            || action.starts_with("persistently remove")
            || action.starts_with("add ")));
        let armed = installation_actions(false);
        assert_eq!(
            armed.last().unwrap(),
            "add the managed one-user NOPASSWD rule last"
        );
        assert!(armed
            .iter()
            .any(|action| action.contains("persistently remove setuid")));
    }

    #[test]
    fn alternative_selection_mode_is_preserved_and_unknown_modes_rejected() {
        assert!(parse_alternative_auto("Name: sudo\nStatus: auto\n").unwrap());
        assert!(!parse_alternative_auto("Name: sudo\nStatus: manual\n").unwrap());
        assert!(parse_alternative_auto("Name: sudo\n").is_err());
        assert!(parse_alternative_auto("Status: unexpected\n").is_err());
    }
}
