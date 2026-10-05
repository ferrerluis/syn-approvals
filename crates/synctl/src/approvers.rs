//! Root-only additional device enrollment. Public bytes are hash-bound before they confer trust.
use crate::{atomic_write, require_root};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{fs, os::unix::fs::MetadataExt, path::Path, process::Command};
use syn_config::{
    approvers::{ApproverRecord, ApproverRegistry},
    AgentConfig, PluginConfig, DEFAULT_AGENT_CONFIG, DEFAULT_PLUGIN_CONFIG,
};
const REGISTRY: &str = "/etc/syn/approvers.json";

pub fn list() -> Result<serde_json::Value> {
    require_root()?;
    let (agent, _) = configs()?;
    let registry = registry(&agent)?;
    Ok(
        serde_json::json!({"devices": registry.approvers.iter().map(|p| serde_json::json!({
        "device_id":p.device_id, "display_name":p.display_name, "development":p.development
    })).collect::<Vec<_>>()}),
    )
}
pub fn enroll(
    input: &Path,
    expected_hash: &str,
    allow_development: bool,
    apply: bool,
) -> Result<serde_json::Value> {
    require_root()?;
    if expected_hash.len() != 64
        || !expected_hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("invalid enrollment hash");
    }
    let metadata = fs::symlink_metadata(input)?;
    if !metadata.is_file() || metadata.len() > 24 * 1024 {
        bail!("invalid enrollment input");
    }
    let bytes = fs::read(input)?;
    if hex::encode(Sha256::digest(&bytes)) != expected_hash {
        bail!("enrollment bytes changed");
    }
    let record: ApproverRecord =
        serde_json::from_slice(&bytes).context("invalid device enrollment")?;
    record.validate()?;
    validate_primary_collisions(&record)?;
    if record.development && !allow_development {
        bail!("development signer needs explicit --allow-development enrollment");
    }
    // WebPKI must parse the public certificate before it becomes a trust anchor.
    let der = rustls::pki_types::CertificateDer::from(record.certificate_der()?);
    let _ =
        rustls::server::ParsedCertificate::try_from(&der).context("invalid client certificate")?;
    let (mut agent, mut plugin) = configs()?;
    let mut registry = registry(&agent)?;
    if let Some(existing) = registry
        .approvers
        .iter()
        .find(|p| p.device_id == record.device_id)
    {
        if serde_json::to_vec(existing)? != serde_json::to_vec(&record)? {
            bail!("device already enrolled with different identities; revoke first");
        }
    } else {
        registry.approvers.push(record.clone());
    }
    registry.validate()?;
    let path = agent
        .approver_registry
        .clone()
        .unwrap_or_else(|| REGISTRY.into());
    agent.approver_registry = Some(path.clone());
    plugin.approver_registry = Some(path.clone());
    if apply {
        persist(&agent, &plugin, &registry)?;
    }
    Ok(
        serde_json::json!({"device_id":record.device_id,"applied":apply,"development":record.development}),
    )
}
pub fn revoke(device: &str, apply: bool) -> Result<serde_json::Value> {
    require_root()?;
    let (agent, plugin) = configs()?;
    let mut registry = registry(&agent)?;
    let old_count = registry.approvers.len();
    registry.approvers.retain(|p| p.device_id != device);
    let removed = old_count != registry.approvers.len();
    if !removed && !mobile_keys()?.contains_key(device) {
        bail!("device is not enrolled or authorized");
    }
    if apply {
        if removed {
            persist(&agent, &plugin, &registry)?;
        }
        revoke_mobile_key(device)?;
    }
    Ok(serde_json::json!({"device_id":device,"revoked":apply}))
}
fn protected(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        bail!("unsafe protected pairing file");
    }
    Ok(())
}
fn configs() -> Result<(AgentConfig, PluginConfig)> {
    protected(Path::new(DEFAULT_AGENT_CONFIG))?;
    protected(Path::new(DEFAULT_PLUGIN_CONFIG))?;
    let agent = AgentConfig::load(DEFAULT_AGENT_CONFIG)?;
    let plugin = PluginConfig::load(DEFAULT_PLUGIN_CONFIG)?;
    agent.validate()?;
    plugin.validate()?;
    if agent.target_id != plugin.target_id
        || agent.approver_registry != plugin.approver_registry
        || agent.approval_public_key != plugin.approval_public_key
        || agent.denial_public_key != plugin.denial_public_key
    {
        bail!("agent and plugin pairing configurations disagree");
    }
    Ok((agent, plugin))
}
fn registry(agent: &AgentConfig) -> Result<ApproverRegistry> {
    Ok(match &agent.approver_registry {
        Some(path) => ApproverRegistry::load(path)?,
        None => ApproverRegistry::empty(),
    })
}
fn persist(agent: &AgentConfig, plugin: &PluginConfig, registry: &ApproverRegistry) -> Result<()> {
    let path = agent
        .approver_registry
        .as_deref()
        .context("missing approver registry path")?;
    let parent = path.parent().context("missing registry parent")?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        bail!("unsafe registry parent");
    }
    let prior_registry = match fs::symlink_metadata(path) {
        Ok(_) => {
            protected(path)?;
            Some(fs::read(path)?)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let old_agent = fs::read(DEFAULT_AGENT_CONFIG)?;
    let old_plugin = fs::read(DEFAULT_PLUGIN_CONFIG)?;
    let update = (|| -> Result<()> {
        atomic_write(path, &serde_json::to_vec_pretty(registry)?, 0o644)?;
        write_configuration(
            Path::new(DEFAULT_PLUGIN_CONFIG),
            toml::to_string_pretty(plugin)?.as_bytes(),
        )?;
        write_configuration(
            Path::new(DEFAULT_AGENT_CONFIG),
            toml::to_string_pretty(agent)?.as_bytes(),
        )?;
        if !Command::new("/usr/bin/systemctl")
            .args(["try-restart", "syn-agent.service"])
            .status()?
            .success()
        {
            bail!("agent restart failed");
        }
        if !Command::new("/usr/bin/systemctl")
            .args(["is-active", "--quiet", "syn-agent.service"])
            .status()?
            .success()
        {
            bail!("agent is not healthy after pairing update");
        }
        Ok(())
    })();
    if update.is_err() {
        // Restore the smaller prior trust set before attempting service recovery.
        match prior_registry {
            Some(bytes) => atomic_write(path, &bytes, 0o644)?,
            None => {
                let _ = fs::remove_file(path);
            }
        }
        write_configuration(Path::new(DEFAULT_PLUGIN_CONFIG), &old_plugin)?;
        write_configuration(Path::new(DEFAULT_AGENT_CONFIG), &old_agent)?;
        let _ = Command::new("/usr/bin/systemctl")
            .args(["try-restart", "syn-agent.service"])
            .status();
    }
    update
}

fn write_configuration(path: &Path, bytes: &[u8]) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    atomic_write(path, bytes, metadata.mode() & 0o777)?;
    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    // Retain the syn group's read access after atomic root-owned replacement.
    if unsafe { libc::chown(name.as_ptr(), 0, metadata.gid()) } != 0 {
        bail!("unable to preserve configuration group ownership");
    }
    Ok(())
}
fn validate_primary_collisions(record: &ApproverRecord) -> Result<()> {
    let (agent, _) = configs()?;
    let (approval, denial) = record.keys()?;
    for path in [&agent.approval_public_key, &agent.denial_public_key] {
        protected(path)?;
        let key = syn_protocol::verifying_key_from_pem(&fs::read_to_string(path)?)?;
        if key == approval || key == denial {
            bail!("device keys collide with the primary approver");
        }
    }
    let cert = fs::File::open(&agent.client_ca_certificate)?;
    for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(cert)) {
        if <[u8; 32]>::from(Sha256::digest(cert?.as_ref())) == record.certificate_fingerprint()? {
            bail!("device certificate collides with the primary approver");
        }
    }
    Ok(())
}
const MOBILE_ROOT: &str = "/var/lib/syn/mobile-maintenance";
const MOBILE_KEYS: &str = "/var/lib/syn/mobile-maintenance/authorized-keys.json";
const AUTHORIZED_KEYS: &str = "/root/.ssh/authorized_keys";

fn valid_device(device: &str) -> bool {
    device.len() == 36
        && device
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b'-')
}
fn canonical_ssh_key(public_key: &str) -> Result<String> {
    let words: Vec<_> = public_key.split_whitespace().collect();
    if words.len() != 2 || words[0] != "ssh-ed25519" {
        bail!("expected one Ed25519 public key without options");
    }
    let bytes = STANDARD.decode(words[1])?;
    let mut expected = vec![0, 0, 0, 11];
    expected.extend_from_slice(b"ssh-ed25519");
    expected.extend_from_slice(&[0, 0, 0, 32]);
    if bytes.len() != 51 || !bytes.starts_with(&expected) {
        bail!("invalid Ed25519 public key");
    }
    Ok(format!("ssh-ed25519 {}", STANDARD.encode(bytes)))
}
fn mobile_keys() -> Result<std::collections::BTreeMap<String, String>> {
    match fs::symlink_metadata(MOBILE_KEYS) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Default::default()),
        Err(e) => Err(e.into()),
        Ok(metadata) => {
            protected(Path::new(MOBILE_KEYS))?;
            if metadata.len() > 16 * 1024 {
                bail!("mobile maintenance registry is too large");
            }
            Ok(serde_json::from_slice(&fs::read(MOBILE_KEYS)?)?)
        }
    }
}
pub fn authorize(device: &str, public_key: &str, apply: bool) -> Result<serde_json::Value> {
    require_root()?;
    configs()?;
    if !valid_device(device) {
        bail!("invalid mobile device identifier");
    }
    let public_key = canonical_ssh_key(public_key)?;
    let entry = format!("restrict,command=\"/usr/bin/synctl --json approvers serve --device-id {device}\" {public_key} syn-ios-maintenance-v1:{device}");
    let mut keys = mobile_keys()?;
    if let Some(old) = keys.get(device) {
        if old != &entry {
            bail!("device already has a different maintenance key; revoke first");
        }
    } else {
        if keys.len() >= 8 {
            bail!("too many mobile maintenance keys");
        }
        keys.insert(device.into(), entry.clone());
    }
    if apply {
        for directory in ["/var/lib/syn", MOBILE_ROOT, "/root/.ssh"] {
            if !Path::new(directory).exists() {
                fs::create_dir(directory)?;
                fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
            }
            let meta = fs::symlink_metadata(directory)?;
            if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                bail!("unsafe mobile maintenance directory");
            }
        }
        let mut contents = if Path::new(AUTHORIZED_KEYS).exists() {
            protected(Path::new(AUTHORIZED_KEYS))?;
            fs::read_to_string(AUTHORIZED_KEYS)?
        } else {
            String::new()
        };
        if !contents.lines().any(|line| line == entry) {
            if !contents.is_empty() && !contents.ends_with('\n') {
                contents.push('\n');
            }
            contents.push_str(&entry);
            contents.push('\n');
        }
        // Keep a recoverable ownership record before granting the forced-key access.
        atomic_write(Path::new(MOBILE_KEYS), &serde_json::to_vec(&keys)?, 0o600)?;
        atomic_write(Path::new(AUTHORIZED_KEYS), contents.as_bytes(), 0o600)?;
    }
    Ok(
        serde_json::json!({"device_id":device,"authorized":apply,"scope":"enroll this device and read its public profile"}),
    )
}
pub fn serve(device: &str) -> Result<()> {
    require_root()?;
    if !valid_device(device) || !mobile_keys()?.contains_key(device) {
        bail!("mobile maintenance access is revoked");
    }
    let operation = std::env::var("SSH_ORIGINAL_COMMAND")?;
    match operation.as_str() {
        "syn-mobile --protocol-version 1 enroll" => {
            let mut data = Vec::new();
            std::io::stdin()
                .take(24 * 1024 + 1)
                .read_to_end(&mut data)?;
            if data.len() > 24 * 1024 {
                bail!("mobile enrollment is too large");
            }
            let record: ApproverRecord = serde_json::from_slice(&data)?;
            if record.device_id != device {
                bail!("mobile key cannot enroll another device");
            }
            // A development signer must be explicitly authorized in the trusted terminal.
            let config = fs::read_to_string(format!("{MOBILE_ROOT}/{device}.development"));
            let allow_development = config.as_deref().is_ok_and(|value| value == "allowed\n");
            let path = Path::new(MOBILE_ROOT).join(format!("{device}.incoming"));
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(&data)?;
            file.sync_all()?;
            drop(file);
            let result = enroll(
                &path,
                &hex::encode(Sha256::digest(&data)),
                allow_development,
                true,
            );
            let _ = fs::remove_file(&path);
            result?;
            print_profile(device)?;
        }
        "syn-mobile --protocol-version 1 profile" => print_profile(device)?,
        _ => bail!("unauthorized mobile maintenance operation"),
    }
    Ok(())
}
fn print_profile(device: &str) -> Result<()> {
    let (agent, _) = configs()?;
    if !registry(&agent)?
        .approvers
        .iter()
        .any(|p| p.device_id == device)
    {
        bail!("device is not enrolled");
    }
    let cert = rustls_pemfile::certs(&mut std::io::BufReader::new(fs::File::open(
        &agent.tls_certificate,
    )?))
    .next()
    .context("target TLS certificate missing")??;
    let target_key =
        syn_protocol::verifying_key_from_pem(&fs::read_to_string(&agent.target_public_key)?)?;
    let profile = serde_json::json!({"targetID":agent.target_id,"displayName":agent.target_id,
        "webSocketURL":format!("wss://{}",agent.listen),
        "targetPublicKeyBase64":STANDARD.encode(syn_protocol::verifying_key_sec1(&target_key)),
        "serverCertificateSHA256Hex":hex::encode(Sha256::digest(cert.as_ref())),
        "clientIdentityLabel":format!("Syn iOS {device} transport"),
        "installedReleaseID":syn_protocol::release_id(),"installedReleaseCommit":syn_protocol::release_commit()});
    println!("{}", profile);
    Ok(())
}
pub fn revoke_mobile_key(device: &str) -> Result<()> {
    require_root()?;
    let mut keys = mobile_keys()?;
    if let Some(entry) = keys.remove(device) {
        protected(Path::new(AUTHORIZED_KEYS))?;
        let contents = fs::read_to_string(AUTHORIZED_KEYS)?;
        let mut kept = contents
            .lines()
            .filter(|line| *line != entry)
            .collect::<Vec<_>>()
            .join("\n");
        if !kept.is_empty() {
            kept.push('\n');
        }
        atomic_write(Path::new(AUTHORIZED_KEYS), kept.as_bytes(), 0o600)?;
        atomic_write(Path::new(MOBILE_KEYS), &serde_json::to_vec(&keys)?, 0o600)?;
        let _ = fs::remove_file(Path::new(MOBILE_ROOT).join(format!("{device}.development")));
    }
    Ok(())
}
pub fn revoke_all_mobile_keys() -> Result<()> {
    for device in mobile_keys()?.keys() {
        revoke_mobile_key(device)?;
    }
    Ok(())
}
pub fn allow_development(device: &str) -> Result<()> {
    require_root()?;
    if !valid_device(device) || !mobile_keys()?.contains_key(device) {
        bail!("unknown mobile maintenance device");
    }
    atomic_write(
        &Path::new(MOBILE_ROOT).join(format!("{device}.development")),
        b"allowed\n",
        0o600,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_options_and_shell_text_in_mobile_key() {
        assert!(canonical_ssh_key("command=evil ssh-ed25519 AAAA").is_err());
        assert!(canonical_ssh_key("ssh-ed25519 AAAA;evil").is_err());
        assert!(!valid_device("x;id"));
        assert!(valid_device("00000000-0000-4000-8000-000000000001"));
    }
}
