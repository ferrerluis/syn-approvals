use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Serialize;
use syn_config::{PluginConfig, Policy};
use syn_protocol::message_kind;
use syn_protocol::{
    digest_environment, key_id_hex, sign_request, sorted_environment_names, verify_decision,
    verify_request, ApprovalRequestV1, AuthenticationClass, CommandInfoEntry, DecisionAction,
    SudoIntentV1, WireMessageV1, MAX_WIRE_BYTES,
};
use zeroize::Zeroizing;

use crate::{atomic_write, require_root};

const PREFLIGHT_MARKER: &str = "/var/lib/syn/preflight-complete.json";
const PAIRING_MARKER: &str = "/var/lib/syn/pairing-complete.json";

#[derive(Debug, Serialize)]
pub struct ApprovalTestReport {
    approved: bool,
    target_id: String,
    request_id: String,
    request_hash: String,
    approver_key_id: String,
    preflight_recorded: bool,
}

#[derive(Debug, Serialize)]
pub struct FallbackTestReport {
    configuration_valid: bool,
    timeout_seconds: u64,
    pam_service: String,
    pam_file: String,
    pam_file_present: bool,
    live_prompt_performed: bool,
    note: String,
}

#[derive(Serialize)]
struct PreflightEvidence {
    schema_version: u16,
    target_id: String,
    completed_at_unix_ms: i64,
    request_id: String,
    request_hash: String,
    approver_key_id: String,
    test_executable: String,
}

pub fn test_approval(config_path: &Path, record_preflight: bool) -> Result<ApprovalTestReport> {
    require_root()?;
    let config = PluginConfig::load(config_path)?;
    config.validate()?;
    let policy = Policy::load(&config.policy_path)?;
    policy.validate()?;
    if policy.managed_uid != config.managed_uid || policy.managed_user != config.managed_user {
        bail!("plug-in and policy managed identities differ");
    }

    let signing_key_pem = Zeroizing::new(fs::read_to_string(&config.target_private_key)?);
    let signing_key = syn_protocol::signing_key_from_pem(&signing_key_pem)?;
    let approval_key =
        syn_protocol::verifying_key_from_pem(&fs::read_to_string(&config.approval_public_key)?)?;
    let denial_key =
        syn_protocol::verifying_key_from_pem(&fs::read_to_string(&config.denial_public_key)?)?;
    let environment: Vec<Vec<u8>> = std::env::vars_os()
        .map(|(name, value)| {
            let mut entry = name.as_os_str().as_bytes().to_vec();
            entry.push(b'=');
            entry.extend_from_slice(value.as_os_str().as_bytes());
            entry
        })
        .collect();
    let cwd = std::env::current_dir()?.as_os_str().as_bytes().to_vec();
    let command_info = vec![
        entry("command", b"/usr/bin/true"),
        CommandInfoEntry {
            key: "cwd".into(),
            value: cwd.clone().into(),
        },
        entry("runas_gid", b"0"),
        entry("runas_group", b"root"),
        entry("runas_uid", b"0"),
        entry("runas_user", b"root"),
    ];
    let intent = SudoIntentV1 {
        invoking_uid: config.managed_uid,
        invoking_gid: config.managed_uid,
        invoking_user: config.managed_user.clone(),
        pid: std::process::id(),
        parent_pid: 0,
        tty: Some("synctl-preflight".into()),
        non_interactive: false,
        working_directory: cwd.into(),
        run_as_uid: 0,
        run_as_gid: 0,
        run_as_user: "root".into(),
        run_as_group: "root".into(),
        sudo_mode: "run".into(),
        executable: b"/usr/bin/true".to_vec().into(),
        argv: vec![b"true".to_vec().into()],
        command_info,
        environment_digest: digest_environment(&environment).to_vec().into(),
        environment_names: sorted_environment_names(&environment),
        policy_version: 1,
        sudo_provider: "synctl-preflight".into(),
        risk_markers: vec!["harmless_preflight".into()],
    };
    let mut request = ApprovalRequestV1::new(
        config.target_id.clone(),
        signing_key.verifying_key(),
        intent,
    );
    request.ttl_ms = u32::try_from(config.timeout_seconds * 1_000)?;
    let signed_request = sign_request(&request, &signing_key)?;
    let verified_request = verify_request(&signed_request, signing_key.verifying_key())?;
    let wire = WireMessageV1::new(message_kind::REQUEST, signed_request)?.encode()?;

    let mut stream = UnixStream::connect(&config.agent_socket)
        .with_context(|| format!("connect to {}", config.agent_socket.display()))?;
    stream.set_read_timeout(Some(Duration::from_secs(config.timeout_seconds + 2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    write_frame(&mut stream, &wire)?;
    let response = WireMessageV1::decode(&read_frame(&mut stream)?)?;
    if response.kind == message_kind::UNAVAILABLE {
        bail!("preflight expired without a valid Mac decision");
    }
    if response.kind != message_kind::DECISION {
        bail!("agent returned an unexpected preflight message");
    }
    if let Ok(denial) = verify_decision(response.body.as_slice(), &denial_key) {
        if denial.decision.matches(&verified_request)
            && denial.decision.action == DecisionAction::Deny
            && denial.decision.authentication_class == AuthenticationClass::DeviceAuthenticated
        {
            bail!("Mac explicitly denied the preflight request");
        }
    }
    let approval = verify_decision(response.body.as_slice(), &approval_key)?;
    if !approval.decision.matches(&verified_request)
        || approval.decision.action != DecisionAction::ApproveOnce
        || approval.decision.authentication_class != AuthenticationClass::SystemUserPresence
    {
        bail!("preflight approval is not bound to the test request");
    }

    let evidence = PreflightEvidence {
        schema_version: 1,
        target_id: config.target_id.clone(),
        completed_at_unix_ms: syn_protocol::unix_time_ms(),
        request_id: hex::encode(verified_request.request.request_id.as_slice()),
        request_hash: hex::encode(verified_request.payload_hash),
        approver_key_id: hex::encode(approval.signer_key_id),
        test_executable: "/usr/bin/true".into(),
    };
    if record_preflight {
        let encoded = serde_json::to_vec_pretty(&evidence)?;
        atomic_write(Path::new(PREFLIGHT_MARKER), &encoded, 0o600)?;
        atomic_write(Path::new(PAIRING_MARKER), &encoded, 0o600)?;
    }
    Ok(ApprovalTestReport {
        approved: true,
        target_id: config.target_id,
        request_id: evidence.request_id,
        request_hash: evidence.request_hash,
        approver_key_id: key_id_hex(&approval_key),
        preflight_recorded: record_preflight,
    })
}

pub fn test_fallback(config_path: &Path) -> Result<FallbackTestReport> {
    let config = PluginConfig::load(config_path)?;
    config.validate()?;
    let policy = Policy::load(&config.policy_path)?;
    policy.validate()?;
    let pam_file = Path::new("/etc/pam.d").join(&config.pam_service);
    Ok(FallbackTestReport {
        configuration_valid: policy.password_fallback_on_timeout
            && policy.timeout_seconds == config.timeout_seconds,
        timeout_seconds: config.timeout_seconds,
        pam_service: config.pam_service,
        pam_file: pam_file.display().to_string(),
        pam_file_present: pam_file.exists(),
        live_prompt_performed: false,
        note: "Read-only check only. The installer requires a separate live sudo timeout test before arming.".into(),
    })
}

fn entry(key: &str, value: &[u8]) -> CommandInfoEntry {
    CommandInfoEntry {
        key: key.into(),
        value: value.to_vec().into(),
    }
}

fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_WIRE_BYTES {
        bail!("invalid preflight frame size");
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)?;
    Ok(())
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_WIRE_BYTES {
        bail!("invalid preflight response size");
    }
    let mut bytes = vec![0_u8; length];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}
