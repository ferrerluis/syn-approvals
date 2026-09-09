use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::Serialize;
use socket2::{Domain, SockAddr, Socket, Type};
use syn_config::{PluginConfig, Policy};
use syn_protocol::message_kind;
use syn_protocol::{
    digest_environment, key_id_hex, sign_request, sorted_environment_names, verify_decision,
    verify_request, ApprovalRequestV1, AuthenticationClass, CommandInfoEntry, DecisionAction,
    SudoIntentV1, VerifiedDecision, VerifiedRequest, WireMessageV1, MAX_WIRE_BYTES,
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
    // One monotonic budget includes signing, connect, framing, and verification.
    let deadline = Instant::now() + Duration::from_secs(config.timeout_seconds);
    let signed_request = sign_request(&request, &signing_key)?;
    let verified_request = verify_request(&signed_request, signing_key.verifying_key())?;
    let wire = WireMessageV1::new(message_kind::REQUEST, signed_request)?.encode()?;

    let mut stream = connect_until(&config.agent_socket, deadline)
        .with_context(|| format!("connect to {}", config.agent_socket.display()))?;
    write_frame(&mut stream, &wire, deadline)?;
    let response = WireMessageV1::decode(&read_frame(&mut stream, deadline)?)?;
    let approval = validate_response(
        &response,
        &verified_request,
        &approval_key,
        &denial_key,
        deadline,
    )?;

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

fn validate_response(
    response: &WireMessageV1,
    request: &VerifiedRequest,
    approval_key: &p256::ecdsa::VerifyingKey,
    denial_key: &p256::ecdsa::VerifyingKey,
    deadline: Instant,
) -> Result<VerifiedDecision> {
    if response.kind == message_kind::UNAVAILABLE {
        bail!("preflight expired without a valid Mac decision");
    }
    if response.kind != message_kind::DECISION {
        bail!("agent returned an unexpected preflight message");
    }
    if let Ok(denial) = verify_decision(response.body.as_slice(), denial_key) {
        if denial.decision.matches(request)
            && denial.decision.action == DecisionAction::Deny
            && denial.decision.authentication_class == AuthenticationClass::DeviceAuthenticated
        {
            bail!("Mac explicitly denied the preflight request");
        }
    }
    let approval = verify_decision(response.body.as_slice(), approval_key)?;
    if !approval.decision.matches(request)
        || approval.decision.action != DecisionAction::ApproveOnce
        || approval.decision.authentication_class != AuthenticationClass::SystemUserPresence
    {
        bail!("preflight approval is not bound to the test request");
    }

    // Verification must finish before expiry, not merely the last socket read.
    remaining(deadline)?;
    Ok(approval)
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

fn remaining(deadline: Instant) -> std::io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "preflight deadline elapsed")
        })
}

fn connect_until(path: &Path, deadline: Instant) -> std::io::Result<UnixStream> {
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    socket.connect_timeout(&SockAddr::unix(path)?, remaining(deadline)?)?;
    let fd: std::os::fd::OwnedFd = socket.into();
    Ok(fd.into())
}

fn write_until(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(bytes) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_until(stream: &mut UnixStream, bytes: &mut [u8], deadline: Instant) -> std::io::Result<()> {
    let mut received = 0;
    while received < bytes.len() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(&mut bytes[received..]) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => received += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_frame(stream: &mut UnixStream, bytes: &[u8], deadline: Instant) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_WIRE_BYTES {
        bail!("invalid preflight frame size");
    }
    write_until(stream, &(bytes.len() as u32).to_be_bytes(), deadline)?;
    write_until(stream, bytes, deadline)?;
    Ok(())
}

fn read_frame(stream: &mut UnixStream, deadline: Instant) -> Result<Vec<u8>> {
    let mut length = [0_u8; 4];
    read_until(stream, &mut length, deadline)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_WIRE_BYTES {
        bail!("invalid preflight response size");
    }
    let mut bytes = vec![0_u8; length];
    read_until(stream, &mut bytes, deadline)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;

    #[test]
    fn requester_rejects_late_denied_modified_wrong_target_and_replayed_decisions() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/protocol-v2.json")).unwrap();
        let target = SigningKey::from_slice(&[1_u8; 32]).unwrap();
        let approval = SigningKey::from_slice(&[2_u8; 32]).unwrap();
        let denial = SigningKey::from_slice(&[3_u8; 32]).unwrap();
        let request = verify_request(
            &hex::decode(fixture["signed_request_hex"].as_str().unwrap()).unwrap(),
            target.verifying_key(),
        )
        .unwrap();
        let signed = hex::decode(fixture["signed_approval_hex"].as_str().unwrap()).unwrap();
        let evaluate = |bytes: &[u8], request: &VerifiedRequest, deadline| {
            validate_response(
                &WireMessageV1::new(message_kind::DECISION, bytes.to_vec()).unwrap(),
                request,
                approval.verifying_key(),
                denial.verifying_key(),
                deadline,
            )
        };
        let deadline = Instant::now() + Duration::from_secs(syn_config::APPROVAL_TIMEOUT_SECONDS);
        assert!(evaluate(&signed, &request, deadline).is_ok());
        assert!(evaluate(&signed, &request, Instant::now()).is_err());
        assert!(evaluate(
            &hex::decode(fixture["signed_denial_hex"].as_str().unwrap()).unwrap(),
            &request,
            deadline,
        )
        .unwrap_err()
        .to_string()
        .contains("explicitly denied"));
        let mut modified = signed.clone();
        *modified.last_mut().unwrap() ^= 1;
        assert!(evaluate(&modified, &request, deadline).is_err());
        assert!(evaluate(b"malformed", &request, deadline).is_err());
        let mut wrong_target = request.clone();
        wrong_target.request.target_id = "another-target".into();
        assert!(evaluate(&signed, &wrong_target, deadline).is_err());
        let mut next_invocation = request.clone();
        next_invocation.request.request_id = vec![9; 16].into();
        next_invocation.payload_hash[0] ^= 1;
        assert!(evaluate(&signed, &next_invocation, deadline).is_err());
    }

    #[test]
    fn prior_protocol_request_and_decision_are_rejected() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/protocol-v1.json")).unwrap();
        let target = SigningKey::from_slice(&[1_u8; 32]).unwrap();
        let approval = SigningKey::from_slice(&[2_u8; 32]).unwrap();
        let request = hex::decode(fixture["signed_request_hex"].as_str().unwrap()).unwrap();
        let decision = hex::decode(fixture["signed_approval_hex"].as_str().unwrap()).unwrap();
        assert!(verify_request(&request, target.verifying_key()).is_err());
        assert!(verify_decision(&decision, approval.verifying_key()).is_err());
    }

    #[test]
    fn bounded_frames_reject_empty_oversized_and_truncated_inputs() {
        let deadline = Instant::now() + Duration::from_secs(1);
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        write_frame(&mut writer, b"test", deadline).unwrap();
        assert_eq!(read_frame(&mut reader, deadline).unwrap(), b"test");
        assert!(write_frame(&mut writer, b"", deadline).is_err());
        assert!(write_frame(&mut writer, &vec![0; MAX_WIRE_BYTES + 1], deadline).is_err());
        for bytes in [
            &[0, 0, 0, 0][..],
            &[0, 2, 0, 0][..],
            &[0, 0][..],
            &[0, 0, 0, 2, 1][..],
        ] {
            let (mut reader, mut writer) = UnixStream::pair().unwrap();
            writer.write_all(bytes).unwrap();
            drop(writer);
            assert!(read_frame(&mut reader, deadline).is_err());
        }
    }

    #[test]
    fn slow_header_and_body_share_one_deadline() {
        for prewrite_header in [false, true] {
            let (mut reader, mut writer) = UnixStream::pair().unwrap();
            if prewrite_header {
                writer.write_all(&100_u32.to_be_bytes()).unwrap();
            }
            let sender = std::thread::spawn(move || {
                for _ in 0..100 {
                    std::thread::sleep(Duration::from_millis(40));
                    if writer.write_all(&[0]).is_err() {
                        break;
                    }
                }
            });
            let started = Instant::now();
            assert!(read_frame(&mut reader, started + Duration::from_millis(120)).is_err());
            assert!(started.elapsed() < Duration::from_secs(1));
            drop(reader);
            sender.join().unwrap();
        }
    }

    #[test]
    fn blocked_write_and_expired_connect_are_bounded() {
        let (mut writer, _reader) = UnixStream::pair().unwrap();
        socket2::SockRef::from(&writer)
            .set_send_buffer_size(4096)
            .unwrap();
        let started = Instant::now();
        assert!(write_until(
            &mut writer,
            &vec![0; 1024 * 1024],
            started + Duration::from_millis(100),
        )
        .is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            connect_until(Path::new("/run/syn-test-unused.sock"), Instant::now())
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::TimedOut
        );
    }
}
