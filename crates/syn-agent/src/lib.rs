use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use futures_util::{SinkExt, StreamExt};
use p256::ecdsa::VerifyingKey;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use serde::Deserialize;
use syn_config::AgentConfig;
use syn_protocol::message_kind;
use syn_protocol::{
    encode_canonical, verify_decision, verify_request, AuthenticationClass, CancelV1,
    DecisionAction, ErrorV1, HelloV1, VerifiedDecision, VerifiedRequest, WireMessageV1,
    MAX_WIRE_BYTES, PROTOCOL_VERSION,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::sync::{broadcast, oneshot, Mutex, Semaphore};
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::{protocol::WebSocketConfig, Message};
use tracing::{info, warn};

const REQUEST_BROADCAST_CAPACITY: usize = 64;
// Setup can need an initial macOS Keychain permission. This budget does not
// extend the signed command's 90-second TTL or create an approval grant.
const TLS_SETUP_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_APPROVER_CONNECTIONS: usize = 4;

#[cfg(test)]
#[test]
fn approver_connection_slots_are_bounded_and_released() {
    let slots = Arc::new(Semaphore::new(MAX_APPROVER_CONNECTIONS));
    let mut held = Vec::new();
    for _ in 0..MAX_APPROVER_CONNECTIONS {
        held.push(slots.clone().try_acquire_owned().unwrap());
    }
    assert!(slots.clone().try_acquire_owned().is_err());
    drop(held.pop());
    assert!(slots.clone().try_acquire_owned().is_ok());
}

pub struct Agent {
    config: AgentConfig,
    state: Arc<AgentState>,
    tls_acceptor: TlsAcceptor,
}

struct AgentState {
    target_id: String,
    target_key: VerifyingKey,
    approval_key: VerifyingKey,
    denial_key: VerifyingKey,
    max_pending: usize,
    pending: Mutex<HashMap<String, PendingRequest>>,
    event_tx: broadcast::Sender<WireMessageV1>,
}

struct PendingRequest {
    verified: VerifiedRequest,
    signed_request: Vec<u8>,
    deadline: Instant,
    response_tx: oneshot::Sender<LocalResponse>,
}

enum LocalResponse {
    Decision(Vec<u8>),
    IntegrityFailure,
}

impl Agent {
    pub async fn from_config(config: AgentConfig) -> Result<Self> {
        config.validate()?;
        verify_selected_address(&config)?;
        let target_key = read_verifying_key(&config.target_public_key)?;
        let approval_key = read_verifying_key(&config.approval_public_key)?;
        let denial_key = read_verifying_key(&config.denial_public_key)?;
        let tls_acceptor = TlsAcceptor::from(Arc::new(load_tls_config(&config)?));
        let (event_tx, _) = broadcast::channel(REQUEST_BROADCAST_CAPACITY);
        Ok(Self {
            state: Arc::new(AgentState {
                target_id: config.target_id.clone(),
                target_key,
                approval_key,
                denial_key,
                max_pending: config.max_pending,
                pending: Mutex::new(HashMap::new()),
                event_tx,
            }),
            config,
            tls_acceptor,
        })
    }

    pub async fn run(self) -> Result<()> {
        let unix_listener = bind_unix_socket(&self.config.unix_socket).await?;
        let tcp_listener = TcpListener::bind(&self.config.listen)
            .await
            .with_context(|| format!("unable to bind network listener {}", self.config.listen))?;
        info!(listen = %self.config.listen, socket = %self.config.unix_socket.display(), "Syn agent ready");

        let unix_state = self.state.clone();
        let plugin_uid = self.config.plugin_uid;
        let unix_task = tokio::spawn(async move {
            loop {
                let (stream, _) = unix_listener.accept().await?;
                let state = unix_state.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_local(stream, state, plugin_uid).await {
                        warn!(error = %error, "local request rejected");
                    }
                });
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        });

        let network_state = self.state.clone();
        let acceptor = self.tls_acceptor.clone();
        let network_task = tokio::spawn(async move {
            let slots = Arc::new(Semaphore::new(MAX_APPROVER_CONNECTIONS));
            loop {
                let (stream, peer) = tcp_listener.accept().await?;
                // Source addresses may change across private networks. The TLS acceptor below
                // still requires a client certificate issued by the configured paired CA.
                let Ok(slot) = slots.clone().try_acquire_owned() else {
                    warn!(%peer, "approver connection limit reached");
                    continue;
                };
                let state = network_state.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _slot = slot;
                    if let Err(error) = handle_network(stream, state, acceptor).await {
                        warn!(%peer, error = %error, "approver connection closed");
                    }
                });
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        });

        tokio::select! {
            result = unix_task => result.context("local listener task panicked")??,
            result = network_task => result.context("network listener task panicked")??,
            _ = tokio::signal::ctrl_c() => info!("shutdown requested"),
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct InterfaceReport {
    ifname: String,
    #[serde(default)]
    addr_info: Vec<InterfaceAddress>,
}

#[derive(Deserialize)]
struct InterfaceAddress {
    local: String,
}

fn verify_selected_address(config: &AgentConfig) -> Result<()> {
    let output = Command::new("ip")
        .args(["-j", "address", "show"])
        .output()
        .context("unable to inspect local interface addresses")?;
    if !output.status.success() {
        bail!("unable to inspect local interface addresses");
    }
    let addresses = parse_interface_addresses(&output.stdout)?;
    config.validate_selected_address(&addresses)?;
    Ok(())
}

fn parse_interface_addresses(json: &[u8]) -> Result<Vec<(String, std::net::IpAddr)>> {
    let reports: Vec<InterfaceReport> =
        serde_json::from_slice(json).context("invalid ip interface report")?;
    let mut addresses = Vec::new();
    for report in reports {
        for address in report.addr_info {
            if let Ok(address) = address.local.parse() {
                addresses.push((report.ifname.clone(), address));
            }
        }
    }
    Ok(addresses)
}

async fn bind_unix_socket(path: &Path) -> Result<UnixListener> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_socket() => tokio::fs::remove_file(path).await?,
        Ok(_) => bail!("refusing to replace non-socket path {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(path)?;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)).await?;
    Ok(listener)
}

async fn handle_local(
    mut stream: UnixStream,
    state: Arc<AgentState>,
    plugin_uid: u32,
) -> Result<()> {
    let credentials = stream.peer_cred()?;
    if credentials.uid() != plugin_uid {
        bail!("Unix peer UID {} is not permitted", credentials.uid());
    }
    let bytes = read_frame(&mut stream).await?;
    let message = match WireMessageV1::decode(&bytes) {
        Ok(message) => message,
        Err(_) => {
            return write_hard_error(
                &mut stream,
                "malformed_request",
                "local request envelope is malformed",
            )
            .await
        }
    };
    if message.kind != message_kind::REQUEST {
        return write_hard_error(
            &mut stream,
            "invalid_local_message",
            "local client sent a non-request message",
        )
        .await;
    }
    let verified = match verify_request(message.body.as_slice(), &state.target_key) {
        Ok(verified) => verified,
        Err(_) => {
            return write_hard_error(
                &mut stream,
                "invalid_target_signature",
                "request signature or schema is invalid",
            )
            .await
        }
    };
    if verified.request.target_id != state.target_id {
        return write_hard_error(
            &mut stream,
            "wrong_target",
            "request target does not match this agent",
        )
        .await;
    }
    if verified.request.release_id != syn_protocol::release_id()
        || verified.request.release_commit != syn_protocol::release_commit()
    {
        return write_hard_error(
            &mut stream,
            "release_mismatch",
            "request and relay releases do not match",
        )
        .await;
    }
    let request_id_bytes = verified.request.request_id.to_vec();
    let request_id = hex::encode(verified.request.request_id.as_slice());
    let ttl = Duration::from_millis(verified.request.ttl_ms.into());
    let (response_tx, response_rx) = oneshot::channel();
    {
        let mut pending = state.pending.lock().await;
        if pending.len() >= state.max_pending {
            return write_unavailable(&mut stream, "queue_full", "pending request limit reached")
                .await;
        }
        if pending.contains_key(&request_id) {
            drop(pending);
            return write_hard_error(&mut stream, "replay", "duplicate live request ID").await;
        }
        pending.insert(
            request_id.clone(),
            PendingRequest {
                verified,
                signed_request: message.body.to_vec(),
                deadline: Instant::now() + ttl,
                response_tx,
            },
        );
    }
    let request_event = WireMessageV1::new(message_kind::REQUEST, message.body.to_vec())?;
    let _ = state.event_tx.send(request_event);

    enum LocalOutcome {
        Decision(Vec<u8>),
        IntegrityFailure,
        Expired,
        Disconnected,
    }
    let outcome = tokio::select! {
        response = response_rx => match response {
            Ok(LocalResponse::Decision(decision)) => LocalOutcome::Decision(decision),
            Ok(LocalResponse::IntegrityFailure) => LocalOutcome::IntegrityFailure,
            Err(_) => LocalOutcome::Expired,
        },
        _ = tokio::time::sleep(ttl) => LocalOutcome::Expired,
        _ = stream.read_u8() => LocalOutcome::Disconnected,
    };
    match outcome {
        LocalOutcome::Decision(signed_decision) => {
            let response = WireMessageV1::new(message_kind::DECISION, signed_decision)?.encode()?;
            write_frame(&mut stream, &response).await?;
        }
        LocalOutcome::Expired => {
            state.pending.lock().await.remove(&request_id);
            broadcast_cancel(&state, &request_id_bytes).await?;
            write_unavailable(&mut stream, "expired", "no valid decision before deadline").await?;
        }
        LocalOutcome::IntegrityFailure => {
            let error = ErrorV1 {
                code: "integrity_failure".into(),
                message: "authenticated approver sent an invalid decision".into(),
            };
            let response =
                WireMessageV1::new(message_kind::ERROR, encode_canonical(&error)?)?.encode()?;
            write_frame(&mut stream, &response).await?;
        }
        LocalOutcome::Disconnected => {
            state.pending.lock().await.remove(&request_id);
            broadcast_cancel(&state, &request_id_bytes).await?;
        }
    }
    Ok(())
}

async fn broadcast_cancel(state: &AgentState, request_id: &[u8]) -> Result<()> {
    let cancel = CancelV1 {
        request_id: request_id.to_vec().into(),
    };
    let event = WireMessageV1::new(message_kind::CANCEL, encode_canonical(&cancel)?)?;
    let _ = state.event_tx.send(event);
    Ok(())
}

async fn write_unavailable(stream: &mut UnixStream, code: &str, message: &str) -> Result<()> {
    let error = ErrorV1 {
        code: code.into(),
        message: message.into(),
    };
    let wire =
        WireMessageV1::new(message_kind::UNAVAILABLE, encode_canonical(&error)?)?.encode()?;
    write_frame(stream, &wire).await
}

async fn write_hard_error(stream: &mut UnixStream, code: &str, message: &str) -> Result<()> {
    let error = ErrorV1 {
        code: code.into(),
        message: message.into(),
    };
    let wire = WireMessageV1::new(message_kind::ERROR, encode_canonical(&error)?)?.encode()?;
    write_frame(stream, &wire).await
}

fn hello_matches_local(hello: &HelloV1, target_id: &str) -> bool {
    hello.minimum_version <= PROTOCOL_VERSION
        && hello.maximum_version >= PROTOCOL_VERSION
        && hello.target_id == target_id
        && hello.release_id == syn_protocol::release_id()
        && hello.release_commit == syn_protocol::release_commit()
}

async fn handle_network(
    stream: tokio::net::TcpStream,
    state: Arc<AgentState>,
    acceptor: TlsAcceptor,
) -> Result<()> {
    let tls = tokio::time::timeout(TLS_SETUP_TIMEOUT, acceptor.accept(stream))
        .await
        .context("mutual TLS timed out")?
        .context("mutual TLS failed")?;
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_WIRE_BYTES))
        .max_frame_size(Some(MAX_WIRE_BYTES));
    let mut websocket = tokio::time::timeout(
        Duration::from_secs(10),
        tokio_tungstenite::accept_async_with_config(tls, Some(config)),
    )
    .await
    .context("WebSocket upgrade timed out")?
    .context("WebSocket upgrade failed")?;
    let hello = HelloV1 {
        minimum_version: PROTOCOL_VERSION,
        maximum_version: PROTOCOL_VERSION,
        target_id: state.target_id.clone(),
        release_id: syn_protocol::release_id().into(),
        release_commit: syn_protocol::release_commit().into(),
    };
    send_wire(
        &mut websocket,
        WireMessageV1::new(message_kind::HELLO, encode_canonical(&hello)?)?,
    )
    .await?;

    let client_hello = tokio::time::timeout(Duration::from_secs(5), websocket.next())
        .await
        .context("approver did not negotiate a protocol version")?
        .context("approver disconnected before protocol negotiation")??;
    let Message::Binary(client_hello) = client_hello else {
        bail!("approver protocol negotiation must use a binary frame");
    };
    let client_hello = WireMessageV1::decode(&client_hello)?;
    if client_hello.kind != message_kind::HELLO {
        bail!("approver did not begin with a hello message");
    }
    let client_hello: HelloV1 = syn_protocol::decode_canonical(client_hello.body.as_slice())?;
    if !hello_matches_local(&client_hello, &state.target_id) {
        bail!("approver and target protocol, identity, or release do not match");
    }

    let snapshot: Vec<Vec<u8>> = {
        let pending = state.pending.lock().await;
        pending
            .values()
            .filter(|request| request.deadline > Instant::now())
            .map(|request| request.signed_request.clone())
            .collect()
    };
    for request in snapshot {
        send_wire(
            &mut websocket,
            WireMessageV1::new(message_kind::REQUEST, request)?,
        )
        .await?;
    }

    let mut event_rx = state.event_tx.subscribe();
    loop {
        tokio::select! {
            incoming = websocket.next() => {
                let Some(incoming) = incoming else { break };
                let incoming = match incoming {
                    Ok(message) => message,
                    Err(error) => {
                        if websocket_error_is_integrity_failure(&error) {
                            hard_fail_pending(&state).await;
                        }
                        return Err(error.into());
                    }
                };
                match incoming {
                    Message::Binary(bytes) => {
                        let message = match WireMessageV1::decode(&bytes) {
                            Ok(message) => message,
                            Err(error) => {
                                hard_fail_pending(&state).await;
                                return Err(error.into());
                            }
                        };
                        match message.kind {
                            message_kind::DECISION => {
                                if let Err(error) = route_decision(message.body.as_slice(), &state).await {
                                    hard_fail_pending(&state).await;
                                    return Err(error);
                                }
                            },
                            message_kind::PING => send_wire(&mut websocket, WireMessageV1::new(message_kind::PONG, message.body.to_vec())?).await?,
                            _ => {
                                hard_fail_pending(&state).await;
                                bail!("approver sent an unexpected message kind");
                            },
                        }
                    }
                    Message::Ping(bytes) => websocket.send(Message::Pong(bytes)).await?,
                    Message::Close(_) => break,
                    Message::Text(_) => {
                        hard_fail_pending(&state).await;
                        bail!("text WebSocket frames are not supported");
                    },
                    _ => {}
                }
            }
            event = event_rx.recv() => {
                match event {
                    Ok(event) => send_wire(&mut websocket, event).await?,
                    Err(broadcast::error::RecvError::Lagged(_)) => bail!("approver connection lagged behind request queue"),
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
    Ok(())
}

fn websocket_error_is_integrity_failure(error: &tokio_tungstenite::tungstenite::Error) -> bool {
    use tokio_tungstenite::tungstenite::Error;
    !matches!(
        error,
        Error::Io(_) | Error::Tls(_) | Error::ConnectionClosed | Error::AlreadyClosed
    )
}

async fn route_decision(signed: &[u8], state: &AgentState) -> Result<()> {
    let verified = match verify_decision(signed, &state.approval_key) {
        Ok(decision) => decision,
        Err(_) => verify_decision(signed, &state.denial_key)?,
    };
    validate_decision_key_class(&verified, state)?;
    if verified.decision.release_id != syn_protocol::release_id()
        || verified.decision.release_commit != syn_protocol::release_commit()
    {
        bail!("decision and relay releases do not match");
    }
    let request_id = hex::encode(verified.decision.request_id.as_slice());
    let pending = {
        let mut requests = state.pending.lock().await;
        let Some(request) = requests.get(&request_id) else {
            bail!("decision does not match a pending request");
        };
        if !decision_is_timely(request.deadline, Instant::now())
            || !verified.decision.matches(&request.verified)
        {
            bail!("decision is late or request binding does not match");
        }
        requests
            .remove(&request_id)
            .context("pending request disappeared before routing")?
    };
    pending
        .response_tx
        .send(LocalResponse::Decision(signed.to_vec()))
        .map_err(|_| anyhow!("requesting sudo process disconnected"))
}

fn decision_is_timely(deadline: Instant, now: Instant) -> bool {
    now < deadline
}

async fn hard_fail_pending(state: &AgentState) {
    let pending = {
        let mut requests = state.pending.lock().await;
        requests
            .drain()
            .map(|(_, request)| request)
            .collect::<Vec<_>>()
    };
    for request in pending {
        let _ = request.response_tx.send(LocalResponse::IntegrityFailure);
    }
}

fn validate_decision_key_class(decision: &VerifiedDecision, state: &AgentState) -> Result<()> {
    let expected = match (
        decision.decision.action,
        decision.decision.authentication_class,
    ) {
        (DecisionAction::ApproveOnce, AuthenticationClass::SystemUserPresence) => {
            syn_protocol::key_id(&state.approval_key)
        }
        (DecisionAction::Deny, AuthenticationClass::DeviceAuthenticated) => {
            syn_protocol::key_id(&state.denial_key)
        }
        _ => bail!("decision authentication class is invalid"),
    };
    if decision.signer_key_id != expected {
        bail!("decision was signed by the wrong approver key");
    }
    Ok(())
}

async fn send_wire<S>(websocket: &mut S, message: WireMessageV1) -> Result<()>
where
    S: futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    websocket
        .send(Message::Binary(message.encode()?.into()))
        .await?;
    Ok(())
}

async fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let length = stream.read_u32().await? as usize;
    if length == 0 || length > MAX_WIRE_BYTES {
        bail!("invalid local frame length");
    }
    let mut bytes = vec![0_u8; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

async fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_WIRE_BYTES {
        bail!("invalid outbound local frame length");
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}

fn read_verifying_key(path: &Path) -> Result<VerifyingKey> {
    let pem = std::fs::read_to_string(path)
        .with_context(|| format!("unable to read public key {}", path.display()))?;
    syn_protocol::verifying_key_from_pem(&pem).map_err(Into::into)
}

fn load_tls_config(config: &AgentConfig) -> Result<ServerConfig> {
    let certificates = load_certificates(&config.tls_certificate)?;
    let private_key = load_private_key(&config.tls_private_key)?;
    let mut roots = RootCertStore::empty();
    for certificate in load_certificates(&config.client_ca_certificate)? {
        roots.add(certificate)?;
    }
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
    let mut tls = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certificates, private_key)?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tls)
}

fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).with_context(|| format!("unable to read {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let certificates: Vec<_> = rustls_pemfile::certs(&mut reader).collect::<Result<_, _>>()?;
    if certificates.is_empty() {
        bail!("{} contains no certificates", path.display());
    }
    Ok(certificates)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).with_context(|| format!("unable to read {}", path.display()))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow!("{} contains no private key", path.display()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn configuration_and_signed_request_deadlines_agree() {
        assert_eq!(syn_config::APPROVAL_TIMEOUT_SECONDS, 90);
        assert_eq!(
            syn_config::APPROVAL_TIMEOUT_SECONDS * 1_000,
            u64::from(syn_protocol::DEFAULT_TTL_MS)
        );
    }

    #[test]
    fn hello_requires_the_exact_target_and_release() {
        let hello = HelloV1 {
            minimum_version: PROTOCOL_VERSION,
            maximum_version: PROTOCOL_VERSION,
            target_id: "remote-one".into(),
            release_id: syn_protocol::release_id().into(),
            release_commit: syn_protocol::release_commit().into(),
        };
        assert!(hello_matches_local(&hello, "remote-one"));

        let mut wrong_release = hello.clone();
        wrong_release.release_id = "20260908000000".into();
        assert!(!hello_matches_local(&wrong_release, "remote-one"));

        let mut wrong_commit = hello;
        wrong_commit.release_commit = "f".repeat(40);
        assert!(!hello_matches_local(&wrong_commit, "remote-one"));
    }

    use super::*;
    use syn_protocol::{
        digest_environment, generate_signing_key, sign_decision, sign_request, ApprovalRequestV1,
        DecisionV1, SudoIntentV1,
    };

    fn intent() -> SudoIntentV1 {
        SudoIntentV1 {
            invoking_uid: 1000,
            invoking_gid: 1000,
            invoking_user: "luis".into(),
            pid: 1,
            parent_pid: 0,
            tty: Some("/dev/pts/1".into()),
            non_interactive: false,
            working_directory: b"/tmp".to_vec().into(),
            run_as_uid: 0,
            run_as_gid: 0,
            run_as_user: "root".into(),
            run_as_group: "root".into(),
            sudo_mode: "run".into(),
            executable: b"/usr/bin/true".to_vec().into(),
            argv: vec![b"true".to_vec().into()],
            command_info: vec![],
            environment_digest: digest_environment([b"PATH=/usr/bin".as_slice()])
                .to_vec()
                .into(),
            environment_names: vec!["PATH".into()],
            policy_version: 1,
            sudo_provider: "test".into(),
            risk_markers: vec![],
        }
    }

    async fn state_with_pending() -> (
        Arc<AgentState>,
        syn_protocol::VerifiedRequest,
        p256::ecdsa::SigningKey,
        oneshot::Receiver<LocalResponse>,
    ) {
        let target = generate_signing_key();
        let approval = generate_signing_key();
        let denial = generate_signing_key();
        let request = ApprovalRequestV1::new("pi-dev".into(), target.verifying_key(), intent());
        let signed = sign_request(&request, &target).unwrap();
        let verified = verify_request(&signed, target.verifying_key()).unwrap();
        let (response_tx, response_rx) = oneshot::channel();
        let (event_tx, _) = broadcast::channel(4);
        let state = Arc::new(AgentState {
            target_id: "pi-dev".into(),
            target_key: *target.verifying_key(),
            approval_key: *approval.verifying_key(),
            denial_key: *denial.verifying_key(),
            max_pending: 4,
            pending: Mutex::new(HashMap::from([(
                hex::encode(verified.request.request_id.as_slice()),
                PendingRequest {
                    verified: verified.clone(),
                    signed_request: signed,
                    deadline: Instant::now()
                        + Duration::from_millis(syn_protocol::DEFAULT_TTL_MS.into()),
                    response_tx,
                },
            )])),
            event_tx,
        });
        (state, verified, approval, response_rx)
    }

    #[tokio::test]
    async fn valid_bound_approval_routes_once() {
        let (state, request, approval, response_rx) = state_with_pending().await;
        let decision = DecisionV1::for_request(
            &request,
            DecisionAction::ApproveOnce,
            AuthenticationClass::SystemUserPresence,
            approval.verifying_key(),
        );
        let signed = sign_decision(&decision, &approval).unwrap();
        route_decision(&signed, &state).await.unwrap();
        let LocalResponse::Decision(routed) = response_rx.await.unwrap() else {
            panic!("valid approval was hard-failed");
        };
        assert_eq!(routed, signed);
        assert!(state.pending.lock().await.is_empty());
        assert!(route_decision(&signed, &state).await.is_err());
    }

    #[tokio::test]
    async fn local_requester_disconnect_removes_pending_and_broadcasts_cancel() {
        let target = generate_signing_key();
        let request = ApprovalRequestV1::new("pi-dev".into(), target.verifying_key(), intent());
        let request_id = request.request_id.to_vec();
        let signed = sign_request(&request, &target).unwrap();
        let (event_tx, mut event_rx) = broadcast::channel(4);
        let state = Arc::new(AgentState {
            target_id: "pi-dev".into(),
            target_key: *target.verifying_key(),
            approval_key: *generate_signing_key().verifying_key(),
            denial_key: *generate_signing_key().verifying_key(),
            max_pending: 4,
            pending: Mutex::new(HashMap::new()),
            event_tx,
        });
        let (server, mut client) = UnixStream::pair().unwrap();
        let plugin_uid = server.peer_cred().unwrap().uid();
        let task = tokio::spawn(handle_local(server, state.clone(), plugin_uid));
        let wire = WireMessageV1::new(message_kind::REQUEST, signed)
            .unwrap()
            .encode()
            .unwrap();
        write_frame(&mut client, &wire).await.unwrap();

        let request_event = event_rx.recv().await.unwrap();
        assert_eq!(request_event.kind, message_kind::REQUEST);
        assert_eq!(state.pending.lock().await.len(), 1);
        drop(client);
        task.await.unwrap().unwrap();

        let cancel_event = event_rx.recv().await.unwrap();
        assert_eq!(cancel_event.kind, message_kind::CANCEL);
        let cancel: CancelV1 = syn_protocol::decode_canonical(&cancel_event.body).unwrap();
        assert_eq!(cancel.request_id.as_slice(), request_id);
        assert!(state.pending.lock().await.is_empty());
    }

    #[tokio::test]
    async fn local_relay_rejects_other_releases_signed_by_the_same_target() {
        for change_commit in [false, true] {
            let target = generate_signing_key();
            let approver = generate_signing_key();
            let (event_tx, mut event_rx) = broadcast::channel(4);
            let state = Arc::new(AgentState {
                target_id: "pi-dev".into(),
                target_key: *target.verifying_key(),
                approval_key: *approver.verifying_key(),
                denial_key: *generate_signing_key().verifying_key(),
                max_pending: 4,
                pending: Mutex::new(HashMap::new()),
                event_tx,
            });
            let mut request =
                ApprovalRequestV1::new("pi-dev".into(), target.verifying_key(), intent());
            if change_commit {
                request.release_commit = if syn_protocol::release_commit() == "1".repeat(40) {
                    "2".repeat(40)
                } else {
                    "1".repeat(40)
                };
            } else {
                request.release_id = if syn_protocol::release_id() == "20260906000001" {
                    "20260906000002".into()
                } else {
                    "20260906000001".into()
                };
            }
            let signed = sign_request(&request, &target).unwrap();
            // The key is still trusted; this is a build-identity failure, not a
            // forged-signature test. Reject before notifying or adding a waiter.
            assert!(verify_request(&signed, target.verifying_key()).is_ok());
            let (server, mut client) = UnixStream::pair().unwrap();
            let plugin_uid = server.peer_cred().unwrap().uid();
            let task = tokio::spawn(handle_local(server, state.clone(), plugin_uid));
            let wire = WireMessageV1::new(message_kind::REQUEST, signed)
                .unwrap()
                .encode()
                .unwrap();
            write_frame(&mut client, &wire).await.unwrap();
            let reply = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut client))
                .await
                .unwrap()
                .unwrap();
            let reply = WireMessageV1::decode(&reply).unwrap();
            assert_eq!(reply.kind, message_kind::ERROR);
            assert_eq!(
                reply.body.as_slice(),
                encode_canonical(&ErrorV1 {
                    code: "release_mismatch".into(),
                    message: "request and relay releases do not match".into(),
                })
                .unwrap()
            );
            task.await.unwrap().unwrap();
            assert!(state.pending.lock().await.is_empty());
            assert!(matches!(
                event_rx.try_recv(),
                Err(broadcast::error::TryRecvError::Empty)
            ));
        }
    }

    #[test]
    fn interface_report_collects_addresses_without_provider_assumptions() {
        let addresses = parse_interface_addresses(
            br#"[
                {"ifname":"enp1s0","addr_info":[{"local":"192.168.50.12"}]},
                {"ifname":"private0","addr_info":[{"local":"fd00::12"},{"local":"invalid"}]}
            ]"#,
        )
        .unwrap();
        assert_eq!(
            addresses,
            vec![
                ("enp1s0".into(), "192.168.50.12".parse().unwrap()),
                ("private0".into(), "fd00::12".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn decision_deadline_is_strict() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(syn_config::APPROVAL_TIMEOUT_SECONDS);
        assert!(decision_is_timely(
            deadline,
            deadline - Duration::from_nanos(1)
        ));
        assert!(!decision_is_timely(deadline, deadline));
        assert!(!decision_is_timely(
            deadline,
            deadline + Duration::from_nanos(1)
        ));
    }

    #[test]
    fn malformed_websocket_is_not_ordinary_unavailability() {
        use tokio_tungstenite::tungstenite::{error::CapacityError, Error};
        assert!(websocket_error_is_integrity_failure(&Error::Capacity(
            CapacityError::MessageTooLong {
                size: MAX_WIRE_BYTES + 1,
                max_size: MAX_WIRE_BYTES
            }
        )));
        assert!(!websocket_error_is_integrity_failure(
            &Error::ConnectionClosed
        ));
        assert!(!websocket_error_is_integrity_failure(&Error::Io(
            std::io::ErrorKind::ConnectionReset.into()
        )));
    }

    #[tokio::test]
    async fn forged_approval_is_rejected_and_stays_pending() {
        let (state, request, _approval, _response_rx) = state_with_pending().await;
        let attacker = generate_signing_key();
        let decision = DecisionV1::for_request(
            &request,
            DecisionAction::ApproveOnce,
            AuthenticationClass::SystemUserPresence,
            attacker.verifying_key(),
        );
        let signed = sign_decision(&decision, &attacker).unwrap();
        assert!(route_decision(&signed, &state).await.is_err());
        assert_eq!(state.pending.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn late_wrong_target_and_modified_decisions_hard_fail_the_waiter() {
        for case in ["late", "target", "modified"] {
            let (state, request, approval, response_rx) = state_with_pending().await;
            let mut decision = DecisionV1::for_request(
                &request,
                DecisionAction::ApproveOnce,
                AuthenticationClass::SystemUserPresence,
                approval.verifying_key(),
            );
            if case == "target" {
                decision.target_id = "another-target".into();
            }
            if case == "late" {
                state
                    .pending
                    .lock()
                    .await
                    .get_mut(&hex::encode(request.request.request_id.as_slice()))
                    .unwrap()
                    .deadline = Instant::now();
            }
            let mut signed = sign_decision(&decision, &approval).unwrap();
            if case == "modified" {
                *signed.last_mut().unwrap() ^= 1;
            }
            assert!(route_decision(&signed, &state).await.is_err());
            // This is the same failure transition used by the network handler.
            hard_fail_pending(&state).await;
            assert!(matches!(
                response_rx.await.unwrap(),
                LocalResponse::IntegrityFailure
            ));
        }
    }

    #[tokio::test]
    async fn integrity_failure_wakes_waiter_without_a_decision() {
        let (state, _request, _approval, response_rx) = state_with_pending().await;
        hard_fail_pending(&state).await;
        assert!(matches!(
            response_rx.await.unwrap(),
            LocalResponse::IntegrityFailure
        ));
        assert!(state.pending.lock().await.is_empty());
    }
}
