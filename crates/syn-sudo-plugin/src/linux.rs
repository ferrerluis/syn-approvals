use std::collections::BTreeMap;
use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::ptr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use p256::ecdsa::{SigningKey, VerifyingKey};
use socket2::{Domain, SockAddr, Socket, Type};
use syn_config::{PluginConfig, Policy, DEFAULT_PLUGIN_CONFIG};
use syn_protocol::message_kind;
use syn_protocol::{
    digest_environment, sign_request, sorted_environment_names, verify_decision, verify_request,
    ApprovalRequestV1, AuthenticationClass, CommandInfoEntry, DecisionAction, SudoIntentV1,
    VerifiedRequest, WireMessageV1, MAX_WIRE_BYTES,
};
use zeroize::Zeroizing;

use crate::cancellation::{self, SignalGuard, IO_SLICE};

const SUDO_API_VERSION: c_uint = (1 << 16) | 22;
const SUDO_APPROVAL_PLUGIN: c_uint = 4;
const MAX_ENTRY_BYTES: usize = 8192;
const MAX_COMMAND_INFO_ITEMS: usize = 128;
const SUDO_CONV_PROMPT_ECHO_OFF: c_int = 0x0001;
const SUDO_CONV_PROMPT_ECHO_ON: c_int = 0x0002;
const SUDO_CONV_ERROR_MSG: c_int = 0x0003;
const SUDO_CONV_INFO_MSG: c_int = 0x0004;
static GENERIC_ERROR: &[u8] = b"Syn denied due to an internal approval error\0";
const DENIAL_NOTICE: &str = "Syn approval was denied or Mac authentication was canceled. Rerun sudo to create a new request.\n";

type SudoConv = unsafe extern "C" fn(
    num_msgs: c_int,
    msgs: *const SudoConvMessage,
    replies: *mut SudoConvReply,
    callback: *mut SudoConvCallback,
) -> c_int;
type SudoPrintf = unsafe extern "C" fn(msg_type: c_int, format: *const c_char, ...) -> c_int;

#[repr(C)]
struct SudoConvMessage {
    msg_type: c_int,
    timeout: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct SudoConvReply {
    reply: *mut c_char,
}

#[repr(C)]
struct SudoConvCallback {
    version: c_uint,
    closure: *mut c_void,
    on_suspend: Option<unsafe extern "C" fn(c_int, *mut c_void) -> c_int>,
    on_resume: Option<unsafe extern "C" fn(c_int, *mut c_void) -> c_int>,
}

#[repr(C)]
pub struct ApprovalPlugin {
    plugin_type: c_uint,
    version: c_uint,
    open: Option<ApprovalOpen>,
    close: Option<unsafe extern "C" fn()>,
    check: Option<ApprovalCheck>,
    show_version: Option<unsafe extern "C" fn(verbose: c_int) -> c_int>,
}

type ApprovalOpen = unsafe extern "C" fn(
    version: c_uint,
    conversation: Option<SudoConv>,
    sudo_printf: Option<SudoPrintf>,
    settings: *const *mut c_char,
    user_info: *const *mut c_char,
    submit_optind: c_int,
    submit_argv: *const *mut c_char,
    submit_envp: *const *mut c_char,
    plugin_options: *const *mut c_char,
    errstr: *mut *const c_char,
) -> c_int;

type ApprovalCheck = unsafe extern "C" fn(
    command_info: *const *mut c_char,
    run_argv: *const *mut c_char,
    run_envp: *const *mut c_char,
    errstr: *mut *const c_char,
) -> c_int;

#[derive(Clone)]
struct PluginState {
    conversation: SudoConv,
    invoking_uid: u32,
    invoking_gid: u32,
    invoking_user: String,
    pid: u32,
    parent_pid: u32,
    tty: Option<String>,
    working_directory: Vec<u8>,
    non_interactive: bool,
    sudo_mode: String,
    config_path: String,
}

static STATE: Mutex<Option<PluginState>> = Mutex::new(None);

#[no_mangle]
pub static mut syn_approval: ApprovalPlugin = ApprovalPlugin {
    plugin_type: SUDO_APPROVAL_PLUGIN,
    version: SUDO_API_VERSION,
    open: Some(plugin_open),
    close: Some(plugin_close),
    check: Some(plugin_check),
    show_version: Some(plugin_show_version),
};

unsafe extern "C" fn plugin_open(
    version: c_uint,
    conversation: Option<SudoConv>,
    _sudo_printf: Option<SudoPrintf>,
    settings: *const *mut c_char,
    user_info: *const *mut c_char,
    _submit_optind: c_int,
    _submit_argv: *const *mut c_char,
    _submit_envp: *const *mut c_char,
    plugin_options: *const *mut c_char,
    errstr: *mut *const c_char,
) -> c_int {
    ffi_boundary(errstr, || {
        if version >> 16 != SUDO_API_VERSION >> 16 {
            return Err("unsupported sudo plug-in API major version");
        }
        let conversation = conversation.ok_or("sudo did not provide a conversation callback")?;
        // SAFETY: sudo supplies NULL-terminated arrays for the lifetime of open().
        let settings = unsafe { parse_key_values(settings, 256)? };
        // SAFETY: same ABI guarantee as settings.
        let user_info = unsafe { parse_key_values(user_info, 256)? };
        // SAFETY: same ABI guarantee as settings.
        let options = if plugin_options.is_null() {
            BTreeMap::new()
        } else {
            // SAFETY: when non-NULL, sudo supplies a terminated ABI array.
            unsafe { parse_key_values(plugin_options, 64)? }
        };
        let config_path = options
            .get("config")
            .map(|value| String::from_utf8(value.clone()).map_err(|_| "config path is not UTF-8"))
            .transpose()?
            .unwrap_or_else(|| DEFAULT_PLUGIN_CONFIG.to_owned());
        if !Path::new(&config_path).is_absolute() {
            return Err("plug-in config path must be absolute");
        }
        let state = PluginState {
            conversation,
            invoking_uid: parse_u32(required(&user_info, "uid")?, "uid")?,
            invoking_gid: parse_u32(required(&user_info, "gid")?, "gid")?,
            invoking_user: parse_text(required(&user_info, "user")?, "user")?,
            pid: optional_u32(&user_info, "pid")?.unwrap_or_else(std::process::id),
            parent_pid: optional_u32(&user_info, "ppid")?.unwrap_or(0),
            tty: optional_text(&user_info, "tty")?,
            working_directory: required(&user_info, "cwd")?.clone(),
            non_interactive: bool_setting(&settings, "noninteractive")?,
            sudo_mode: detect_mode(&settings)?,
            config_path,
        };
        let mut slot = STATE.lock().map_err(|_| "plug-in state lock is poisoned")?;
        *slot = Some(state);
        Ok(1)
    })
}

unsafe extern "C" fn plugin_close() {
    let _ = std::panic::catch_unwind(|| {
        if let Ok(mut slot) = STATE.lock() {
            *slot = None;
        }
    });
}

unsafe extern "C" fn plugin_show_version(_verbose: c_int) -> c_int {
    let message = b"Syn sudo approval plug-in 0.1.0-alpha.1\n";
    // SAFETY: message is a valid static byte slice and stderr is process-owned.
    let _ = unsafe { libc::write(libc::STDERR_FILENO, message.as_ptr().cast(), message.len()) };
    1
}

unsafe extern "C" fn plugin_check(
    command_info: *const *mut c_char,
    run_argv: *const *mut c_char,
    run_envp: *const *mut c_char,
    errstr: *mut *const c_char,
) -> c_int {
    ffi_boundary(errstr, || {
        let state = STATE
            .lock()
            .map_err(|_| "plug-in state lock is poisoned")?
            .clone()
            .ok_or("plug-in check called before open")?;
        ensure_root_owned_file(Path::new(&state.config_path))?;
        let config = PluginConfig::load(&state.config_path)
            .map_err(|_| "unable to load Syn plug-in configuration")?;
        config
            .validate()
            .map_err(|_| "invalid Syn plug-in configuration")?;
        ensure_root_owned_file(&config.policy_path)?;
        ensure_root_owned_file(&config.approval_public_key)?;
        ensure_root_owned_file(&config.denial_public_key)?;

        if state.invoking_uid != config.managed_uid {
            return Ok(1);
        }
        if state.invoking_user != config.managed_user {
            return Err("managed UID and username do not match configuration");
        }
        let policy = Policy::load(&config.policy_path).map_err(|_| "unable to load Syn policy")?;
        policy.validate().map_err(|_| "invalid Syn policy")?;
        if policy.managed_uid != state.invoking_uid || policy.managed_user != state.invoking_user {
            return Err("managed identity differs between plug-in and policy");
        }
        if policy.timeout_seconds != config.timeout_seconds {
            return Err("timeout differs between plug-in and policy");
        }

        // SAFETY: sudo owns all three NULL-terminated arrays for this callback.
        let command_info_raw = unsafe { parse_array(command_info, MAX_COMMAND_INFO_ITEMS)? };
        // SAFETY: same callback-lifetime guarantee.
        let argv = unsafe { parse_array(run_argv, 256)? };
        // SAFETY: same callback-lifetime guarantee.
        let environment = unsafe { parse_array(run_envp, 4096)? };
        let command_info_map = parse_key_value_bytes(command_info_raw)?;
        let executable = required(&command_info_map, "command")?.clone();
        if argv.is_empty() {
            return Err("sudo supplied an empty final argv");
        }
        if !policy
            .allowed_modes
            .iter()
            .any(|mode| mode == &state.sudo_mode)
        {
            hard_notice("Syn denied this sudo operation mode.\n");
            return Ok(0);
        }
        if policy.blocks_executable(&executable) {
            hard_notice("Syn policy blocks direct root shells and interpreters.\n");
            return Ok(0);
        }

        let intent = build_intent(&state, &command_info_map, argv, environment)?;
        let target_key = read_signing_key(&config.target_private_key)?;
        let request =
            ApprovalRequestV1::new(config.target_id.clone(), target_key.verifying_key(), intent);
        let signed_request =
            sign_request(&request, &target_key).map_err(|_| "unable to sign Syn request")?;
        let verified_request = verify_request(&signed_request, target_key.verifying_key())
            .map_err(|_| "internal request verification failed")?;

        hard_notice("Waiting for Syn approval on your Mac…\n");
        let signals = SignalGuard::install()?;
        let started = Instant::now();
        let timeout = Duration::from_secs(config.timeout_seconds);
        let outcome = (|| match exchange_with_agent(&config, &signed_request, started + timeout) {
            Ok(AgentReply::Decision(signed_decision)) => {
                let approval_key = read_verifying_key(&config.approval_public_key)?;
                let denial_key = read_verifying_key(&config.denial_public_key)?;
                evaluate_decision(
                    &signed_decision,
                    &verified_request,
                    &approval_key,
                    &denial_key,
                    started,
                    timeout,
                )
            }
            Ok(AgentReply::Unavailable) | Err(ExchangeError::Unavailable) => {
                cancellation::wait_until(started + timeout);
                Ok(DecisionOutcome::Expired)
            }
            Err(ExchangeError::Invalid) => Err("Syn received a malformed agent response"),
        })();
        // Restore sudo's signal handlers before any PAM conversation. A
        // canceled wait is final and must never become password fallback.
        if signals.finish() {
            hard_notice("Syn invocation canceled. Nothing was approved.\n");
            return Ok(0);
        }
        match outcome? {
            DecisionOutcome::Approve => Ok(1),
            DecisionOutcome::Expired => fallback_or_deny(&state, &config, &policy),
            DecisionOutcome::Deny => {
                // A signed denial intentionally does not reveal whether the
                // user chose Deny or canceled the system authentication sheet.
                hard_notice(DENIAL_NOTICE);
                Ok(0)
            }
        }
    })
}

fn decision_is_timely(elapsed: Duration, deadline: Duration) -> bool {
    elapsed < deadline
}

#[derive(Debug, PartialEq)]
enum DecisionOutcome {
    Approve,
    Deny,
    Expired,
}

fn evaluate_decision(
    signed: &[u8],
    request: &VerifiedRequest,
    approval_key: &VerifyingKey,
    denial_key: &VerifyingKey,
    started: Instant,
    timeout: Duration,
) -> Result<DecisionOutcome, &'static str> {
    // Verify integrity before considering fallback, including after expiry.
    if let Ok(verified) = verify_decision(signed, approval_key) {
        if verified.decision.action != DecisionAction::ApproveOnce
            || verified.decision.authentication_class != AuthenticationClass::SystemUserPresence
            || !verified.decision.matches(request)
        {
            return Err("approval decision is not bound to this request");
        }
        return Ok(if decision_is_timely(started.elapsed(), timeout) {
            DecisionOutcome::Approve
        } else {
            DecisionOutcome::Expired
        });
    }
    if let Ok(verified) = verify_decision(signed, denial_key) {
        if verified.decision.action != DecisionAction::Deny
            || verified.decision.authentication_class != AuthenticationClass::DeviceAuthenticated
            || !verified.decision.matches(request)
        {
            return Err("denial decision is not bound to this request");
        }
        return Ok(DecisionOutcome::Deny);
    }
    Err("Syn received an invalid decision signature")
}

fn build_intent(
    state: &PluginState,
    command_info: &BTreeMap<String, Vec<u8>>,
    argv: Vec<Vec<u8>>,
    environment: Vec<Vec<u8>>,
) -> Result<SudoIntentV1, &'static str> {
    let executable = required(command_info, "command")?.clone();
    let working_directory = command_info
        .get("cwd")
        .cloned()
        .unwrap_or_else(|| state.working_directory.clone());
    let run_as_uid = parse_u32(required(command_info, "runas_uid")?, "runas_uid")?;
    let run_as_gid = parse_u32(required(command_info, "runas_gid")?, "runas_gid")?;
    let run_as_user =
        optional_text(command_info, "runas_user")?.unwrap_or_else(|| run_as_uid.to_string());
    let run_as_group =
        optional_text(command_info, "runas_group")?.unwrap_or_else(|| run_as_gid.to_string());
    let entries = command_info
        .iter()
        .map(|(key, value)| CommandInfoEntry {
            key: key.clone(),
            value: value.clone().into(),
        })
        .collect();
    let risk_markers = risk_markers(&executable, &argv);
    Ok(SudoIntentV1 {
        invoking_uid: state.invoking_uid,
        invoking_gid: state.invoking_gid,
        invoking_user: state.invoking_user.clone(),
        pid: state.pid,
        parent_pid: state.parent_pid,
        tty: state.tty.clone(),
        non_interactive: state.non_interactive,
        working_directory: working_directory.into(),
        run_as_uid,
        run_as_gid,
        run_as_user,
        run_as_group,
        sudo_mode: state.sudo_mode.clone(),
        executable: executable.into(),
        argv: argv.into_iter().map(Into::into).collect(),
        command_info: entries,
        environment_digest: digest_environment(&environment).to_vec().into(),
        environment_names: sorted_environment_names(&environment),
        policy_version: 1,
        sudo_provider: "sudo.ws".into(),
        risk_markers,
    })
}

fn risk_markers(executable: &[u8], argv: &[Vec<u8>]) -> Vec<String> {
    let base = executable
        .rsplit(|byte| *byte == b'/')
        .next()
        .unwrap_or(executable);
    let mut markers = Vec::new();
    if matches!(base, b"apt" | b"apt-get" | b"dpkg" | b"snap") {
        markers.push("package_manager_root_equivalent".into());
    }
    if matches!(
        base,
        b"chmod" | b"chown" | b"cp" | b"install" | b"mv" | b"tee"
    ) {
        markers.push("filesystem_write_root_equivalent".into());
    }
    if argv
        .iter()
        .any(|argument| argument.windows(2).any(|window| window == b"-c"))
    {
        markers.push("inline_code_argument".into());
    }
    markers
}

enum AgentReply {
    Decision(Vec<u8>),
    Unavailable,
}

enum ExchangeError {
    Unavailable,
    Invalid,
}

fn exchange_with_agent(
    config: &PluginConfig,
    signed_request: &[u8],
    deadline: Instant,
) -> Result<AgentReply, ExchangeError> {
    let mut stream =
        connect_until(&config.agent_socket, deadline).map_err(|_| ExchangeError::Unavailable)?;
    let message = WireMessageV1::new(message_kind::REQUEST, signed_request.to_vec())
        .and_then(|message| message.encode())
        .map_err(|_| ExchangeError::Invalid)?;
    write_frame(&mut stream, &message, deadline).map_err(|_| ExchangeError::Unavailable)?;
    let response = read_frame(&mut stream, deadline).map_err(|error| {
        if matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::WouldBlock
                | std::io::ErrorKind::UnexpectedEof
        ) {
            ExchangeError::Unavailable
        } else {
            ExchangeError::Invalid
        }
    })?;
    let wire = WireMessageV1::decode(&response).map_err(|_| ExchangeError::Invalid)?;
    match wire.kind {
        message_kind::DECISION => Ok(AgentReply::Decision(wire.body.to_vec())),
        message_kind::UNAVAILABLE => Ok(AgentReply::Unavailable),
        _ => Err(ExchangeError::Invalid),
    }
}

fn remaining(deadline: Instant) -> std::io::Result<Duration> {
    cancellation::check()?;
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "Syn deadline elapsed"))
}

fn connect_until(path: &Path, deadline: Instant) -> std::io::Result<UnixStream> {
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    socket.connect_timeout(&SockAddr::unix(path)?, remaining(deadline)?.min(IO_SLICE))?;
    let fd: std::os::fd::OwnedFd = socket.into();
    Ok(fd.into())
}

fn write_until(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?.min(IO_SLICE)))?;
        match stream.write(bytes) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(count) => bytes = &bytes[count..],
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_until(
    stream: &mut UnixStream,
    bytes: &mut [u8],
    deadline: Instant,
    allow_empty_eof: bool,
) -> std::io::Result<()> {
    let mut received = 0;
    while received < bytes.len() {
        stream.set_read_timeout(Some(remaining(deadline)?.min(IO_SLICE)))?;
        match stream.read(&mut bytes[received..]) {
            Ok(0) if allow_empty_eof && received == 0 => {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            Ok(0) => return Err(std::io::ErrorKind::InvalidData.into()),
            Ok(count) => received += count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_frame(stream: &mut UnixStream, bytes: &[u8], deadline: Instant) -> std::io::Result<()> {
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "oversized frame",
        ));
    }
    write_until(stream, &(bytes.len() as u32).to_be_bytes(), deadline)?;
    write_until(stream, bytes, deadline)
}

pub(crate) fn read_frame(stream: &mut UnixStream, deadline: Instant) -> std::io::Result<Vec<u8>> {
    let mut length = [0_u8; 4];
    read_until(stream, &mut length, deadline, true)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_WIRE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid frame size",
        ));
    }
    let mut bytes = vec![0_u8; length];
    read_until(stream, &mut bytes, deadline, false)?;
    Ok(bytes)
}

fn fallback_or_deny(
    state: &PluginState,
    config: &PluginConfig,
    policy: &Policy,
) -> Result<c_int, &'static str> {
    if state.non_interactive || state.tty.is_none() || !policy.password_fallback_on_timeout {
        hard_notice("Syn approval unavailable; non-interactive sudo denied.\n");
        return Ok(0);
    }
    hard_notice("Syn approval timed out. Enter your Ubuntu password to continue.\n");
    pam_authenticate_once(
        &config.pam_service,
        &state.invoking_user,
        state.conversation,
    )
    .map(|authenticated| if authenticated { 1 } else { 0 })
}

fn read_signing_key(path: &Path) -> Result<SigningKey, &'static str> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "unable to inspect target private key")?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("target private key permissions are unsafe");
    }
    let pem =
        Zeroizing::new(fs::read_to_string(path).map_err(|_| "unable to read target private key")?);
    syn_protocol::signing_key_from_pem(&pem).map_err(|_| "invalid target private key")
}

fn ensure_root_owned_file(path: &Path) -> Result<(), &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "unable to inspect root-owned file")?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err("security-sensitive file ownership or permissions are unsafe");
    }
    Ok(())
}

fn read_verifying_key(path: &Path) -> Result<VerifyingKey, &'static str> {
    let pem = fs::read_to_string(path).map_err(|_| "unable to read approver public key")?;
    syn_protocol::verifying_key_from_pem(&pem).map_err(|_| "invalid approver public key")
}

unsafe fn parse_array(
    values: *const *mut c_char,
    maximum: usize,
) -> Result<Vec<Vec<u8>>, &'static str> {
    if values.is_null() {
        return Err("sudo supplied a NULL array");
    }
    let mut output = Vec::new();
    for index in 0..=maximum {
        // SAFETY: caller establishes a NULL-terminated sudo ABI array.
        let pointer = unsafe { *values.add(index) };
        if pointer.is_null() {
            return Ok(output);
        }
        if index == maximum {
            return Err("sudo array exceeds the item limit");
        }
        // SAFETY: each non-NULL entry is a NUL-terminated string per sudo ABI.
        let bytes = unsafe { CStr::from_ptr(pointer) }.to_bytes();
        if bytes.len() > MAX_ENTRY_BYTES {
            return Err("sudo array entry exceeds 8192 bytes");
        }
        output.push(bytes.to_vec());
    }
    Err("sudo array is not terminated")
}

unsafe fn parse_key_values(
    values: *const *mut c_char,
    maximum: usize,
) -> Result<BTreeMap<String, Vec<u8>>, &'static str> {
    // SAFETY: caller forwards sudo-owned ABI arrays.
    parse_key_value_bytes(unsafe { parse_array(values, maximum)? })
}

fn parse_key_value_bytes(values: Vec<Vec<u8>>) -> Result<BTreeMap<String, Vec<u8>>, &'static str> {
    let mut output = BTreeMap::new();
    for value in values {
        let delimiter = value
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or("sudo field has no equals delimiter")?;
        let (key, value_with_delimiter) = value.split_at(delimiter);
        let value = &value_with_delimiter[1..];
        let key = std::str::from_utf8(key).map_err(|_| "sudo field name is not UTF-8")?;
        if key.is_empty()
            || key.len() > 128
            || output.insert(key.to_owned(), value.to_vec()).is_some()
        {
            return Err("sudo field name is invalid or duplicated");
        }
    }
    Ok(output)
}

fn required<'a>(
    map: &'a BTreeMap<String, Vec<u8>>,
    key: &str,
) -> Result<&'a Vec<u8>, &'static str> {
    map.get(key).ok_or("sudo required field is missing")
}

fn parse_u32(value: &[u8], _label: &str) -> Result<u32, &'static str> {
    std::str::from_utf8(value)
        .map_err(|_| "numeric sudo field is not UTF-8")?
        .parse()
        .map_err(|_| "numeric sudo field is invalid")
}

fn parse_text(value: &[u8], _label: &str) -> Result<String, &'static str> {
    let value = std::str::from_utf8(value).map_err(|_| "sudo text field is not UTF-8")?;
    if value.is_empty() || value.contains('\0') {
        return Err("sudo text field is invalid");
    }
    Ok(value.to_owned())
}

fn optional_u32(map: &BTreeMap<String, Vec<u8>>, key: &str) -> Result<Option<u32>, &'static str> {
    map.get(key).map(|value| parse_u32(value, key)).transpose()
}

fn optional_text(
    map: &BTreeMap<String, Vec<u8>>,
    key: &str,
) -> Result<Option<String>, &'static str> {
    map.get(key).map(|value| parse_text(value, key)).transpose()
}

fn bool_setting(map: &BTreeMap<String, Vec<u8>>, key: &str) -> Result<bool, &'static str> {
    match map.get(key).map(Vec::as_slice) {
        None | Some(b"false") => Ok(false),
        Some(b"true") => Ok(true),
        Some(_) => Err("sudo boolean setting is invalid"),
    }
}

fn detect_mode(settings: &BTreeMap<String, Vec<u8>>) -> Result<String, &'static str> {
    for (setting, mode) in [
        ("login_shell", "login_shell"),
        ("run_shell", "shell"),
        ("implied_shell", "shell"),
        ("sudoedit", "edit"),
        ("list_user", "list"),
        ("validate", "validate"),
        ("invalidate", "invalidate"),
    ] {
        if bool_setting(settings, setting)? {
            return Ok(mode.into());
        }
    }
    Ok("run".into())
}

fn ffi_boundary<F>(errstr: *mut *const c_char, operation: F) -> c_int
where
    F: FnOnce() -> Result<c_int, &'static str> + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(operation) {
        Ok(Ok(value)) => value,
        Ok(Err(message)) => {
            set_error(errstr, message);
            -1
        }
        Err(_) => {
            set_error(errstr, "Syn plug-in panicked and denied the invocation");
            -1
        }
    }
}

fn set_error(errstr: *mut *const c_char, message: &'static str) {
    hard_notice(message);
    hard_notice("\n");
    if !errstr.is_null() {
        // SAFETY: sudo provides writable storage for one error-string pointer.
        unsafe { *errstr = GENERIC_ERROR.as_ptr().cast() };
    }
}

fn hard_notice(message: &str) {
    // SAFETY: message points to a live Rust string during this syscall.
    let _ = unsafe { libc::write(libc::STDERR_FILENO, message.as_ptr().cast(), message.len()) };
}

// Minimal libpam ABI. This module exists only on Linux and links no PAM code into
// the network agent. PAM remains the sole owner of password verification.
#[repr(C)]
struct PamHandle {
    _private: [u8; 0],
}

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConv {
    conv: Option<
        unsafe extern "C" fn(
            c_int,
            *const *const PamMessage,
            *mut *mut PamResponse,
            *mut c_void,
        ) -> c_int,
    >,
    appdata_ptr: *mut c_void,
}

#[link(name = "pam")]
extern "C" {
    fn pam_start(
        service: *const c_char,
        user: *const c_char,
        conv: *const PamConv,
        pamh: *mut *mut PamHandle,
    ) -> c_int;
    fn pam_end(pamh: *mut PamHandle, status: c_int) -> c_int;
    fn pam_authenticate(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_acct_mgmt(pamh: *mut PamHandle, flags: c_int) -> c_int;
}

struct PamConversationData {
    sudo_conv: SudoConv,
}

fn pam_authenticate_once(
    service: &str,
    user: &str,
    sudo_conv: SudoConv,
) -> Result<bool, &'static str> {
    let service = CString::new(service).map_err(|_| "PAM service name is invalid")?;
    let user = CString::new(user).map_err(|_| "PAM username is invalid")?;
    let mut data = PamConversationData { sudo_conv };
    let conv = PamConv {
        conv: Some(pam_conversation),
        appdata_ptr: (&mut data as *mut PamConversationData).cast(),
    };
    let mut handle = ptr::null_mut();
    // SAFETY: all pointers remain valid through pam_end and PAM owns no Rust data.
    let mut status = unsafe { pam_start(service.as_ptr(), user.as_ptr(), &conv, &mut handle) };
    if status == 0 {
        // SAFETY: successful pam_start returns a live handle.
        status = unsafe { pam_authenticate(handle, 0) };
    }
    if status == 0 {
        // SAFETY: same live handle.
        status = unsafe { pam_acct_mgmt(handle, 0) };
    }
    let authenticated = status == 0;
    if !handle.is_null() {
        // SAFETY: PAM specifies pam_end as the terminal operation for this handle.
        let _ = unsafe { pam_end(handle, status) };
    }
    Ok(authenticated)
}

unsafe extern "C" fn pam_conversation(
    num_msg: c_int,
    messages: *const *const PamMessage,
    responses: *mut *mut PamResponse,
    appdata: *mut c_void,
) -> c_int {
    const PAM_SUCCESS: c_int = 0;
    const PAM_CONV_ERR: c_int = 19;
    if num_msg <= 0
        || num_msg > 32
        || messages.is_null()
        || responses.is_null()
        || appdata.is_null()
    {
        return PAM_CONV_ERR;
    }
    // SAFETY: appdata was created by pam_authenticate_once and is live during PAM.
    let data = unsafe { &mut *appdata.cast::<PamConversationData>() };
    // SAFETY: calloc returns suitably aligned zeroed storage or NULL.
    let allocated = unsafe { libc::calloc(num_msg as usize, std::mem::size_of::<PamResponse>()) }
        .cast::<PamResponse>();
    if allocated.is_null() {
        return PAM_CONV_ERR;
    }
    for index in 0..num_msg as usize {
        // SAFETY: PAM supplies num_msg pointers and each points to a PamMessage.
        let message_pointer = unsafe { *messages.add(index) };
        if message_pointer.is_null() {
            // SAFETY: allocated belongs to this callback.
            unsafe { free_pam_responses(allocated, index) };
            return PAM_CONV_ERR;
        }
        // SAFETY: checked non-NULL and valid for this callback.
        let message = unsafe { &*message_pointer };
        let sudo_type = match message.msg_style {
            1 => SUDO_CONV_PROMPT_ECHO_OFF,
            2 => SUDO_CONV_PROMPT_ECHO_ON,
            3 => SUDO_CONV_ERROR_MSG,
            4 => SUDO_CONV_INFO_MSG,
            _ => {
                // SAFETY: allocated belongs to this callback.
                unsafe { free_pam_responses(allocated, index) };
                return PAM_CONV_ERR;
            }
        };
        let sudo_message = SudoConvMessage {
            msg_type: sudo_type,
            timeout: 0,
            msg: message.msg,
        };
        let mut sudo_reply = SudoConvReply {
            reply: ptr::null_mut(),
        };
        // SAFETY: sudo callback and C structs follow the sudo plug-in ABI.
        if unsafe { (data.sudo_conv)(1, &sudo_message, &mut sudo_reply, ptr::null_mut()) } != 0 {
            if !sudo_reply.reply.is_null() {
                // SAFETY: sudo allocated this reply with malloc.
                unsafe { wipe_and_free(sudo_reply.reply) };
            }
            // SAFETY: allocated belongs to this callback.
            unsafe { free_pam_responses(allocated, index) };
            return PAM_CONV_ERR;
        }
        if !sudo_reply.reply.is_null() {
            // SAFETY: sudo returns a NUL-terminated reply allocated with malloc.
            let reply = unsafe { CStr::from_ptr(sudo_reply.reply) }.to_bytes();
            // SAFETY: allocate a separate PAM-owned C string.
            let copied = unsafe { libc::malloc(reply.len() + 1) }.cast::<u8>();
            if copied.is_null() {
                // SAFETY: sudo allocated this reply with malloc.
                unsafe { wipe_and_free(sudo_reply.reply) };
                // SAFETY: allocated belongs to this callback.
                unsafe { free_pam_responses(allocated, index) };
                return PAM_CONV_ERR;
            }
            // SAFETY: copied has reply.len()+1 bytes and regions do not overlap.
            unsafe {
                ptr::copy_nonoverlapping(reply.as_ptr(), copied, reply.len());
                *copied.add(reply.len()) = 0;
                (*allocated.add(index)).resp = copied.cast();
            }
            // SAFETY: reply belongs to sudo's conversation allocation contract.
            unsafe { wipe_and_free(sudo_reply.reply) };
        }
    }
    // SAFETY: PAM takes ownership of this response array on success.
    unsafe { *responses = allocated };
    PAM_SUCCESS
}

unsafe fn wipe_and_free(value: *mut c_char) {
    if value.is_null() {
        return;
    }
    // SAFETY: value is a live NUL-terminated allocation from the sudo callback.
    let length = unsafe { CStr::from_ptr(value) }.to_bytes().len();
    for index in 0..length {
        // SAFETY: each index is within the allocation before its trailing NUL.
        unsafe { ptr::write_volatile(value.add(index), 0) };
    }
    // SAFETY: value was allocated by the compatible process allocator.
    unsafe { libc::free(value.cast()) };
}

unsafe fn free_pam_responses(responses: *mut PamResponse, initialized: usize) {
    for index in 0..initialized {
        // SAFETY: index is within the initialized prefix.
        let response = unsafe { (*responses.add(index)).resp };
        if !response.is_null() {
            // SAFETY: response was allocated by this callback.
            unsafe { wipe_and_free(response) };
        }
    }
    // SAFETY: responses was allocated by calloc in this callback.
    unsafe { libc::free(responses.cast()) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_fields_fail() {
        assert!(parse_key_value_bytes(vec![b"uid=1".to_vec(), b"uid=2".to_vec()]).is_err());
    }

    #[test]
    fn direct_shells_are_detectable() {
        assert_eq!(
            risk_markers(b"/usr/bin/apt", &[]),
            vec!["package_manager_root_equivalent"]
        );
    }

    #[test]
    fn decision_deadline_is_strict() {
        let deadline = Duration::from_secs(30);
        assert!(decision_is_timely(
            deadline - Duration::from_nanos(1),
            deadline
        ));
        assert!(!decision_is_timely(deadline, deadline));
        assert!(!decision_is_timely(
            deadline + Duration::from_nanos(1),
            deadline
        ));
    }

    #[test]
    fn integrity_and_denial_are_final_even_after_deadline() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/protocol-v1.json")).unwrap();
        let target = SigningKey::from_slice(&[1_u8; 32]).unwrap();
        let approval = SigningKey::from_slice(&[2_u8; 32]).unwrap();
        let denial = SigningKey::from_slice(&[3_u8; 32]).unwrap();
        let request = verify_request(
            &hex::decode(fixture["signed_request_hex"].as_str().unwrap()).unwrap(),
            target.verifying_key(),
        )
        .unwrap();
        let signed_approval =
            hex::decode(fixture["signed_approval_hex"].as_str().unwrap()).unwrap();
        let signed_denial = hex::decode(fixture["signed_denial_hex"].as_str().unwrap()).unwrap();
        let timeout = Duration::from_secs(30);
        let evaluate = |signed: &[u8], request: &VerifiedRequest, started| {
            evaluate_decision(
                signed,
                request,
                approval.verifying_key(),
                denial.verifying_key(),
                started,
                timeout,
            )
        };
        assert_eq!(
            evaluate(&signed_approval, &request, Instant::now()).unwrap(),
            DecisionOutcome::Approve
        );
        let expired_start = Instant::now() - timeout;
        assert_eq!(
            evaluate(&signed_approval, &request, expired_start).unwrap(),
            DecisionOutcome::Expired
        );
        assert_eq!(
            evaluate(&signed_denial, &request, expired_start).unwrap(),
            DecisionOutcome::Deny
        );
        let mut forged = signed_approval.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(evaluate(&forged, &request, expired_start).is_err());
        let mut different_request = request.clone();
        different_request.payload_hash[0] ^= 1;
        assert!(evaluate(&signed_approval, &different_request, expired_start).is_err());
        assert!(evaluate(&signed_denial, &different_request, expired_start).is_err());
        assert!(evaluate(b"malformed", &request, expired_start).is_err());
    }

    #[test]
    fn signed_approval_cannot_be_replayed_against_changed_execution_intent() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/protocol-v1.json")).unwrap();
        // Offline fixture keys only; never read a deployed signing identity.
        let target = SigningKey::from_slice(&[1_u8; 32]).unwrap();
        let approval = SigningKey::from_slice(&[2_u8; 32]).unwrap();
        let denial = SigningKey::from_slice(&[3_u8; 32]).unwrap();
        let original = verify_request(
            &hex::decode(fixture["signed_request_hex"].as_str().unwrap()).unwrap(),
            target.verifying_key(),
        )
        .unwrap();
        let signed_approval =
            hex::decode(fixture["signed_approval_hex"].as_str().unwrap()).unwrap();
        for case in [
            "target",
            "nonce",
            "request_id",
            "argv",
            "environment",
            "run_as",
        ] {
            let mut changed = original.request.clone();
            match case {
                "target" => changed.target_id = "different-target".into(),
                "nonce" => changed.nonce = vec![9; 32].into(),
                "request_id" => changed.request_id = vec![9; 16].into(),
                "argv" => changed
                    .sudo
                    .argv
                    .push(b"different-argument".to_vec().into()),
                "environment" => changed.sudo.environment_digest = vec![9; 32].into(),
                "run_as" => changed.sudo.run_as_uid = 1234,
                _ => unreachable!(),
            }
            let signed_changed = sign_request(&changed, &target).unwrap();
            let verified_changed = verify_request(&signed_changed, target.verifying_key()).unwrap();
            for started in [Instant::now(), Instant::now() - Duration::from_secs(30)] {
                assert!(
                    evaluate_decision(
                        &signed_approval,
                        &verified_changed,
                        approval.verifying_key(),
                        denial.verifying_key(),
                        started,
                        Duration::from_secs(30)
                    )
                    .is_err(),
                    "{case} must hard-fail, not enter timeout fallback"
                );
            }
        }
    }

    #[test]
    fn denial_notice_explains_cancellation_and_one_use_retry_without_claiming_a_reason() {
        assert!(DENIAL_NOTICE.contains("denied or Mac authentication was canceled"));
        assert!(DENIAL_NOTICE.contains("Rerun sudo to create a new request"));
        assert!(!DENIAL_NOTICE.contains("password"));
    }

    #[test]
    fn frame_round_trip_and_truncation() {
        let deadline = Instant::now() + Duration::from_secs(1);
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        write_frame(&mut writer, b"test", deadline).unwrap();
        assert_eq!(read_frame(&mut reader, deadline).unwrap(), b"test");
        // EOF partway through a frame is malformed, not ordinary unavailability.
        for truncated in [&[0_u8, 0][..], &[0, 0, 0, 2, 1][..]] {
            let (mut reader, mut writer) = UnixStream::pair().unwrap();
            writer.write_all(truncated).unwrap();
            drop(writer);
            assert_eq!(
                read_frame(&mut reader, deadline).unwrap_err().kind(),
                std::io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn slow_header_and_body_cannot_restart_deadline() {
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
            let error = read_frame(&mut reader, started + Duration::from_millis(120)).unwrap_err();
            assert!(matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ));
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
        let error = write_until(
            &mut writer,
            &vec![0; 1024 * 1024],
            started + Duration::from_millis(100),
        )
        .unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            connect_until(Path::new("/run/syn-test-unused.sock"), Instant::now())
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::TimedOut
        );
    }
}
