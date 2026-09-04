//! Signed, deterministic protocol primitives for Syn.
//!
//! This crate deliberately contains no networking and no command execution.

use std::collections::BTreeSet;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use minicbor::bytes::ByteVec;
use minicbor::data::Tag;
use minicbor::{Decode, Decoder, Encode, Encoder};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

pub const PROTOCOL_VERSION: u16 = 1;
pub const SUDO_ADAPTER_KIND: &str = "org.syn-approvals.sudo";
pub const SUDO_SCHEMA_VERSION: u16 = 1;
pub const DEFAULT_TTL_MS: u32 = 90_000;
pub const MAX_WIRE_BYTES: usize = 64 * 1024;
pub const ES256_ALGORITHM: i64 = -7;

pub mod message_kind {
    pub const HELLO: u8 = 1;
    pub const REQUEST: u8 = 2;
    pub const CANCEL: u8 = 3;
    pub const DECISION: u8 = 4;
    pub const RESULT: u8 = 5;
    pub const PING: u8 = 6;
    pub const PONG: u8 = 7;
    pub const ERROR: u8 = 8;
    pub const UNAVAILABLE: u8 = 9;
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("CBOR encoding failed: {0}")]
    Encode(String),
    #[error("CBOR decoding failed: {0}")]
    Decode(String),
    #[error("message is not canonically encoded")]
    NonCanonical,
    #[error("invalid COSE Sign1 envelope: {0}")]
    InvalidCose(&'static str),
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("key material is invalid: {0}")]
    InvalidKey(String),
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("message exceeds the 64 KiB limit")]
    TooLarge,
}

#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
#[cbor(map)]
pub struct CommandInfoEntry {
    #[n(0)]
    pub key: String,
    #[n(1)]
    pub value: ByteVec,
}

#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
#[cbor(map)]
pub struct SudoIntentV1 {
    #[n(0)]
    pub invoking_uid: u32,
    #[n(1)]
    pub invoking_gid: u32,
    #[n(2)]
    pub invoking_user: String,
    #[n(3)]
    pub pid: u32,
    #[n(4)]
    pub parent_pid: u32,
    #[n(5)]
    pub tty: Option<String>,
    #[n(6)]
    pub non_interactive: bool,
    #[n(7)]
    pub working_directory: ByteVec,
    #[n(8)]
    pub run_as_uid: u32,
    #[n(9)]
    pub run_as_gid: u32,
    #[n(10)]
    pub run_as_user: String,
    #[n(11)]
    pub run_as_group: String,
    #[n(12)]
    pub sudo_mode: String,
    #[n(13)]
    pub executable: ByteVec,
    #[n(14)]
    pub argv: Vec<ByteVec>,
    #[n(15)]
    pub command_info: Vec<CommandInfoEntry>,
    #[n(16)]
    pub environment_digest: ByteVec,
    #[n(17)]
    pub environment_names: Vec<String>,
    #[n(18)]
    pub policy_version: u16,
    #[n(19)]
    pub sudo_provider: String,
    #[n(20)]
    pub risk_markers: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
#[cbor(map)]
pub struct ApprovalRequestV1 {
    #[n(0)]
    pub protocol_version: u16,
    #[n(1)]
    pub request_id: ByteVec,
    #[n(2)]
    pub nonce: ByteVec,
    #[n(3)]
    pub target_id: String,
    #[n(4)]
    pub target_key_id: ByteVec,
    #[n(5)]
    pub adapter_kind: String,
    #[n(6)]
    pub adapter_schema_version: u16,
    #[n(7)]
    pub issued_at_unix_ms: i64,
    #[n(8)]
    pub ttl_ms: u32,
    #[n(9)]
    pub sudo: SudoIntentV1,
}

impl ApprovalRequestV1 {
    pub fn new(target_id: String, target_key: &VerifyingKey, sudo: SudoIntentV1) -> Self {
        let mut request_id = vec![0_u8; 16];
        let mut nonce = vec![0_u8; 32];
        OsRng.fill_bytes(&mut request_id);
        OsRng.fill_bytes(&mut nonce);
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id: request_id.into(),
            nonce: nonce.into(),
            target_id,
            target_key_id: key_id(target_key).to_vec().into(),
            adapter_kind: SUDO_ADAPTER_KIND.to_owned(),
            adapter_schema_version: SUDO_SCHEMA_VERSION,
            issued_at_unix_ms: unix_time_ms(),
            ttl_ms: DEFAULT_TTL_MS,
            sudo,
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(validation("unsupported protocol version"));
        }
        if self.request_id.len() != 16 || self.nonce.len() != 32 {
            return Err(validation("invalid request ID or nonce length"));
        }
        if self.target_key_id.len() != 32 {
            return Err(validation("invalid target key ID length"));
        }
        validate_text("target ID", &self.target_id, 128)?;
        if self.adapter_kind != SUDO_ADAPTER_KIND
            || self.adapter_schema_version != SUDO_SCHEMA_VERSION
        {
            return Err(validation("unsupported adapter kind or schema"));
        }
        if self.ttl_ms != DEFAULT_TTL_MS {
            return Err(validation("private alpha TTL must be exactly 90 seconds"));
        }
        self.sudo.validate()
    }
}

impl SudoIntentV1 {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_text("invoking user", &self.invoking_user, 256)?;
        validate_text("run-as user", &self.run_as_user, 256)?;
        validate_text("run-as group", &self.run_as_group, 256)?;
        validate_text("sudo mode", &self.sudo_mode, 64)?;
        validate_text("sudo provider", &self.sudo_provider, 128)?;
        if self.executable.is_empty() || self.executable.len() > 8192 {
            return Err(validation("invalid executable length"));
        }
        if self.argv.is_empty() || self.argv.len() > 256 {
            return Err(validation("invalid argv count"));
        }
        if self.argv.iter().any(|arg| arg.len() > 8192) {
            return Err(validation("argv entry exceeds 8192 bytes"));
        }
        if self.environment_digest.len() != 32 {
            return Err(validation("invalid environment digest length"));
        }
        if self.command_info.len() > 128 || self.environment_names.len() > 1024 {
            return Err(validation("intent collection exceeds its limit"));
        }
        ensure_sorted_unique(
            self.command_info.iter().map(|entry| entry.key.as_str()),
            "command-info keys",
        )?;
        ensure_sorted_unique(
            self.environment_names.iter().map(String::as_str),
            "environment names",
        )?;
        for entry in &self.command_info {
            validate_text("command-info key", &entry.key, 128)?;
            if entry.value.len() > 8192 {
                return Err(validation("command-info value exceeds 8192 bytes"));
            }
        }
        for marker in &self.risk_markers {
            validate_text("risk marker", marker, 128)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Encode, Decode)]
#[cbor(index_only)]
pub enum DecisionAction {
    #[n(1)]
    ApproveOnce,
    #[n(2)]
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Encode, Decode)]
#[cbor(index_only)]
pub enum AuthenticationClass {
    #[n(1)]
    SystemUserPresence,
    #[n(2)]
    DeviceAuthenticated,
}

#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
#[cbor(map)]
pub struct DecisionV1 {
    #[n(0)]
    pub protocol_version: u16,
    #[n(1)]
    pub request_id: ByteVec,
    #[n(2)]
    pub request_payload_hash: ByteVec,
    #[n(3)]
    pub target_id: String,
    #[n(4)]
    pub action: DecisionAction,
    #[n(5)]
    pub decided_at_unix_ms: i64,
    #[n(6)]
    pub approver_key_id: ByteVec,
    #[n(7)]
    pub authentication_class: AuthenticationClass,
}

impl DecisionV1 {
    pub fn for_request(
        request: &VerifiedRequest,
        action: DecisionAction,
        class: AuthenticationClass,
        approver_key: &VerifyingKey,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id: request.request.request_id.clone(),
            request_payload_hash: request.payload_hash.to_vec().into(),
            target_id: request.request.target_id.clone(),
            action,
            decided_at_unix_ms: unix_time_ms(),
            approver_key_id: key_id(approver_key).to_vec().into(),
            authentication_class: class,
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(validation("unsupported decision protocol version"));
        }
        if self.request_id.len() != 16
            || self.request_payload_hash.len() != 32
            || self.approver_key_id.len() != 32
        {
            return Err(validation("invalid decision identifier length"));
        }
        validate_text("target ID", &self.target_id, 128)?;
        match (self.action, self.authentication_class) {
            (DecisionAction::ApproveOnce, AuthenticationClass::SystemUserPresence)
            | (DecisionAction::Deny, AuthenticationClass::DeviceAuthenticated) => Ok(()),
            _ => Err(validation("decision uses the wrong authentication class")),
        }
    }

    pub fn matches(&self, request: &VerifiedRequest) -> bool {
        self.request_id.as_slice() == request.request.request_id.as_slice()
            && self.request_payload_hash.as_slice() == request.payload_hash
            && self.target_id == request.request.target_id
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedRequest {
    pub request: ApprovalRequestV1,
    pub payload_hash: [u8; 32],
    pub signer_key_id: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct VerifiedDecision {
    pub decision: DecisionV1,
    pub signer_key_id: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
#[cbor(map)]
pub struct WireMessageV1 {
    #[n(0)]
    pub protocol_version: u16,
    #[n(1)]
    pub kind: u8,
    #[n(2)]
    pub body: ByteVec,
}

#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
#[cbor(map)]
pub struct HelloV1 {
    #[n(0)]
    pub minimum_version: u16,
    #[n(1)]
    pub maximum_version: u16,
    #[n(2)]
    pub target_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
#[cbor(map)]
pub struct CancelV1 {
    #[n(0)]
    pub request_id: ByteVec,
}

#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
#[cbor(map)]
pub struct ErrorV1 {
    #[n(0)]
    pub code: String,
    #[n(1)]
    pub message: String,
}

impl WireMessageV1 {
    pub fn new(kind: u8, body: Vec<u8>) -> Result<Self, ProtocolError> {
        if !matches!(kind, 1..=9) {
            return Err(validation("unknown wire message kind"));
        }
        let message = Self {
            protocol_version: PROTOCOL_VERSION,
            kind,
            body: body.into(),
        };
        if encode_canonical(&message)?.len() > MAX_WIRE_BYTES {
            return Err(ProtocolError::TooLarge);
        }
        Ok(message)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let bytes = encode_canonical(self)?;
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(ProtocolError::TooLarge);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(ProtocolError::TooLarge);
        }
        let message: Self = decode_canonical(bytes)?;
        if message.protocol_version != PROTOCOL_VERSION || !matches!(message.kind, 1..=9) {
            return Err(validation("unsupported wire message"));
        }
        Ok(message)
    }
}

pub fn generate_signing_key() -> SigningKey {
    SigningKey::random(&mut OsRng)
}

pub fn signing_key_to_pem(key: &SigningKey) -> Result<Zeroizing<String>, ProtocolError> {
    key.to_pkcs8_pem(LineEnding::LF)
        .map_err(|error| ProtocolError::InvalidKey(error.to_string()))
}

pub fn signing_key_from_pem(pem: &str) -> Result<SigningKey, ProtocolError> {
    SigningKey::from_pkcs8_pem(pem).map_err(|error| ProtocolError::InvalidKey(error.to_string()))
}

pub fn verifying_key_to_pem(key: &VerifyingKey) -> Result<String, ProtocolError> {
    key.to_public_key_pem(LineEnding::LF)
        .map_err(|error| ProtocolError::InvalidKey(error.to_string()))
}

pub fn verifying_key_from_pem(pem: &str) -> Result<VerifyingKey, ProtocolError> {
    VerifyingKey::from_public_key_pem(pem)
        .map_err(|error| ProtocolError::InvalidKey(error.to_string()))
}

pub fn verifying_key_from_sec1(bytes: &[u8]) -> Result<VerifyingKey, ProtocolError> {
    VerifyingKey::from_sec1_bytes(bytes)
        .map_err(|error| ProtocolError::InvalidKey(error.to_string()))
}

pub fn verifying_key_sec1(key: &VerifyingKey) -> Vec<u8> {
    key.to_encoded_point(false).as_bytes().to_vec()
}

pub fn key_id(key: &VerifyingKey) -> [u8; 32] {
    sha256(&verifying_key_sec1(key))
}

pub fn key_id_hex(key: &VerifyingKey) -> String {
    hex::encode(key_id(key))
}

pub fn sign_request(
    request: &ApprovalRequestV1,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, ProtocolError> {
    request.validate()?;
    if request.target_key_id.as_slice() != key_id(signing_key.verifying_key()) {
        return Err(validation("target key ID does not match signing key"));
    }
    let payload = encode_canonical(request)?;
    sign_cose(&payload, signing_key)
}

pub fn verify_request(
    signed: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<VerifiedRequest, ProtocolError> {
    let (payload, signer_key_id) = verify_cose(signed, verifying_key)?;
    let request: ApprovalRequestV1 = decode_canonical(&payload)?;
    request.validate()?;
    if request.target_key_id.as_slice() != signer_key_id {
        return Err(validation("request target key ID does not match signer"));
    }
    Ok(VerifiedRequest {
        request,
        payload_hash: sha256(&payload),
        signer_key_id,
    })
}

pub fn sign_decision(
    decision: &DecisionV1,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, ProtocolError> {
    decision.validate()?;
    if decision.approver_key_id.as_slice() != key_id(signing_key.verifying_key()) {
        return Err(validation("approver key ID does not match signing key"));
    }
    sign_cose(&encode_canonical(decision)?, signing_key)
}

pub fn verify_decision(
    signed: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<VerifiedDecision, ProtocolError> {
    let (payload, signer_key_id) = verify_cose(signed, verifying_key)?;
    let decision: DecisionV1 = decode_canonical(&payload)?;
    decision.validate()?;
    if decision.approver_key_id.as_slice() != signer_key_id {
        return Err(validation("decision key ID does not match signer"));
    }
    Ok(VerifiedDecision {
        decision,
        signer_key_id,
    })
}

pub fn request_payload_hash(request: &ApprovalRequestV1) -> Result<[u8; 32], ProtocolError> {
    Ok(sha256(&encode_canonical(request)?))
}

pub fn digest_environment<I, B>(values: I) -> [u8; 32]
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    let collected: Vec<B> = values.into_iter().collect();
    let mut hasher = Sha256::new();
    hasher.update((collected.len() as u32).to_be_bytes());
    for value in collected {
        let bytes = value.as_ref();
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
    }
    hasher.finalize().into()
}

pub fn encode_canonical<T>(value: &T) -> Result<Vec<u8>, ProtocolError>
where
    T: Encode<()>,
{
    minicbor::to_vec(value).map_err(|error| ProtocolError::Encode(error.to_string()))
}

pub fn decode_canonical<'bytes, T>(bytes: &'bytes [u8]) -> Result<T, ProtocolError>
where
    T: Decode<'bytes, ()> + Encode<()>,
{
    let value: T =
        minicbor::decode(bytes).map_err(|error| ProtocolError::Decode(error.to_string()))?;
    let encoded = encode_canonical(&value)?;
    if encoded != bytes {
        return Err(ProtocolError::NonCanonical);
    }
    Ok(value)
}

pub fn sign_cose(payload: &[u8], signing_key: &SigningKey) -> Result<Vec<u8>, ProtocolError> {
    let kid = key_id(signing_key.verifying_key());
    let protected = encode_protected_header(&kid)?;
    let to_sign = encode_signature_structure(&protected, payload)?;
    let signature: Signature = signing_key.sign(&to_sign);

    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);
    encoder
        .tag(Tag::new(18))
        .and_then(|encoder| encoder.array(4))
        .and_then(|encoder| encoder.bytes(&protected))
        .and_then(|encoder| encoder.map(0))
        .and_then(|encoder| encoder.bytes(payload))
        .and_then(|encoder| encoder.bytes(&signature.to_bytes()))
        .map_err(|error| ProtocolError::Encode(error.to_string()))?;
    if output.len() > MAX_WIRE_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    Ok(output)
}

pub fn verify_cose(
    signed: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<(Vec<u8>, [u8; 32]), ProtocolError> {
    if signed.len() > MAX_WIRE_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    let mut decoder = Decoder::new(signed);
    let tag = decoder.tag().map_err(decode_error)?;
    if tag != Tag::new(18) {
        return Err(ProtocolError::InvalidCose("missing COSE Sign1 tag"));
    }
    if decoder.array().map_err(decode_error)? != Some(4) {
        return Err(ProtocolError::InvalidCose("expected four-element array"));
    }
    let protected = decoder.bytes().map_err(decode_error)?.to_vec();
    if decoder.map().map_err(decode_error)? != Some(0) {
        return Err(ProtocolError::InvalidCose(
            "unprotected header must be empty",
        ));
    }
    let payload = decoder.bytes().map_err(decode_error)?.to_vec();
    let signature_bytes = decoder.bytes().map_err(decode_error)?;
    if decoder.position() != signed.len() {
        return Err(ProtocolError::InvalidCose("trailing data"));
    }
    let signer_key_id = decode_protected_header(&protected)?;
    if signer_key_id != key_id(verifying_key) {
        return Err(ProtocolError::InvalidSignature);
    }
    let signature = Signature::from_slice(signature_bytes)
        .map_err(|_| ProtocolError::InvalidCose("invalid ES256 signature length"))?;
    let to_verify = encode_signature_structure(&protected, &payload)?;
    verifying_key
        .verify(&to_verify, &signature)
        .map_err(|_| ProtocolError::InvalidSignature)?;
    Ok((payload, signer_key_id))
}

fn encode_protected_header(kid: &[u8; 32]) -> Result<Vec<u8>, ProtocolError> {
    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);
    encoder
        .map(2)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.i64(ES256_ALGORITHM))
        .and_then(|encoder| encoder.u8(4))
        .and_then(|encoder| encoder.bytes(kid))
        .map_err(|error| ProtocolError::Encode(error.to_string()))?;
    Ok(output)
}

fn decode_protected_header(bytes: &[u8]) -> Result<[u8; 32], ProtocolError> {
    let mut decoder = Decoder::new(bytes);
    if decoder.map().map_err(decode_error)? != Some(2) {
        return Err(ProtocolError::InvalidCose("invalid protected header map"));
    }
    if decoder.u8().map_err(decode_error)? != 1
        || decoder.i64().map_err(decode_error)? != ES256_ALGORITHM
        || decoder.u8().map_err(decode_error)? != 4
    {
        return Err(ProtocolError::InvalidCose(
            "protected header is not canonical ES256",
        ));
    }
    let kid = decoder.bytes().map_err(decode_error)?;
    if kid.len() != 32 || decoder.position() != bytes.len() {
        return Err(ProtocolError::InvalidCose("invalid key ID"));
    }
    let mut output = [0_u8; 32];
    output.copy_from_slice(kid);
    Ok(output)
}

fn encode_signature_structure(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);
    encoder
        .array(4)
        .and_then(|encoder| encoder.str("Signature1"))
        .and_then(|encoder| encoder.bytes(protected))
        .and_then(|encoder| encoder.bytes(&[]))
        .and_then(|encoder| encoder.bytes(payload))
        .map_err(|error| ProtocolError::Encode(error.to_string()))?;
    Ok(output)
}

fn ensure_sorted_unique<'a, I>(values: I, label: &str) -> Result<(), ProtocolError>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut previous: Option<&str> = None;
    for value in values {
        if previous.is_some_and(|last| last >= value) {
            return Err(validation(format!("{label} must be sorted and unique")));
        }
        previous = Some(value);
    }
    Ok(())
}

pub fn sorted_environment_names<I, B>(environment: I) -> Vec<String>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    let mut names = BTreeSet::new();
    for entry in environment {
        let bytes = entry.as_ref();
        let name = bytes.split(|byte| *byte == b'=').next().unwrap_or_default();
        if let Ok(name) = std::str::from_utf8(name) {
            if !name.is_empty() {
                names.insert(name.to_owned());
            }
        }
    }
    names.into_iter().collect()
}

fn validate_text(label: &str, value: &str, maximum: usize) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > maximum || value.contains('\0') {
        return Err(validation(format!("invalid {label}")));
    }
    Ok(())
}

fn validation(message: impl Into<String>) -> ProtocolError {
    ProtocolError::Validation(message.into())
}

fn decode_error(error: minicbor::decode::Error) -> ProtocolError {
    ProtocolError::Decode(error.to_string())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn unix_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

pub fn short_request_id(request_id: &[u8]) -> String {
    let take = request_id.len().min(4);
    hex::encode_upper(&request_id[..take])
}

impl fmt::Display for DecisionAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ApproveOnce => "approve_once",
            Self::Deny => "deny",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_intent() -> SudoIntentV1 {
        let environment = [b"LANG=C.UTF-8".as_slice(), b"PATH=/usr/bin".as_slice()];
        SudoIntentV1 {
            invoking_uid: 1000,
            invoking_gid: 1000,
            invoking_user: "luis".into(),
            pid: 123,
            parent_pid: 100,
            tty: Some("/dev/pts/2".into()),
            non_interactive: false,
            working_directory: ByteVec::from(b"/home/luis/project".to_vec()),
            run_as_uid: 0,
            run_as_gid: 0,
            run_as_user: "root".into(),
            run_as_group: "root".into(),
            sudo_mode: "run".into(),
            executable: ByteVec::from(b"/usr/bin/apt".to_vec()),
            argv: vec![
                ByteVec::from(b"apt".to_vec()),
                ByteVec::from(b"install".to_vec()),
                ByteVec::from(b"gh".to_vec()),
            ],
            command_info: vec![CommandInfoEntry {
                key: "command".into(),
                value: ByteVec::from(b"/usr/bin/apt".to_vec()),
            }],
            environment_digest: ByteVec::from(digest_environment(environment).to_vec()),
            environment_names: vec!["LANG".into(), "PATH".into()],
            policy_version: 1,
            sudo_provider: "sudo.ws-1.9.17p2".into(),
            risk_markers: vec!["package_manager_root_equivalent".into()],
        }
    }

    #[test]
    fn request_and_decision_round_trip() {
        let target_key = generate_signing_key();
        let approval_key = generate_signing_key();
        let request =
            ApprovalRequestV1::new("pi-dev".into(), target_key.verifying_key(), sample_intent());
        let signed = sign_request(&request, &target_key).unwrap();
        let verified = verify_request(&signed, target_key.verifying_key()).unwrap();
        assert_eq!(verified.request, request);

        let decision = DecisionV1::for_request(
            &verified,
            DecisionAction::ApproveOnce,
            AuthenticationClass::SystemUserPresence,
            approval_key.verifying_key(),
        );
        let signed_decision = sign_decision(&decision, &approval_key).unwrap();
        let verified_decision =
            verify_decision(&signed_decision, approval_key.verifying_key()).unwrap();
        assert!(verified_decision.decision.matches(&verified));
    }

    #[test]
    fn tampering_is_rejected() {
        let key = generate_signing_key();
        let request = ApprovalRequestV1::new("pi-dev".into(), key.verifying_key(), sample_intent());
        let mut signed = sign_request(&request, &key).unwrap();
        let last = signed.len() - 1;
        signed[last] ^= 0x01;
        assert!(matches!(
            verify_request(&signed, key.verifying_key()),
            Err(ProtocolError::InvalidSignature)
        ));
    }

    #[test]
    fn wrong_authentication_class_is_rejected() {
        let key = generate_signing_key();
        let request = ApprovalRequestV1::new("pi-dev".into(), key.verifying_key(), sample_intent());
        let verified =
            verify_request(&sign_request(&request, &key).unwrap(), key.verifying_key()).unwrap();
        let decision = DecisionV1::for_request(
            &verified,
            DecisionAction::ApproveOnce,
            AuthenticationClass::DeviceAuthenticated,
            key.verifying_key(),
        );
        assert!(decision.validate().is_err());
    }

    #[test]
    fn request_rejects_non_alpha_ttl() {
        let key = generate_signing_key();
        let mut request =
            ApprovalRequestV1::new("pi-dev".into(), key.verifying_key(), sample_intent());
        assert_eq!(request.ttl_ms, 90_000);
        for ttl in [30_000, DEFAULT_TTL_MS - 1, DEFAULT_TTL_MS + 1] {
            request.ttl_ms = ttl;
            assert!(request.validate().is_err());
        }
    }

    #[test]
    fn published_golden_vectors_verify() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/protocol-v1.json")).unwrap();
        let target = SigningKey::from_slice(&[1; 32]).unwrap();
        let approval = SigningKey::from_slice(&[2; 32]).unwrap();
        let denial = SigningKey::from_slice(&[3; 32]).unwrap();
        for (field, non_interactive) in [
            ("signed_no_tty_request_hex", false),
            ("signed_no_tty_noninteractive_request_hex", true),
        ] {
            let signed = hex::decode(fixture[field].as_str().unwrap()).unwrap();
            let request = verify_request(&signed, target.verifying_key()).unwrap();
            assert_eq!(request.request.sudo.tty, None);
            assert_eq!(request.request.sudo.non_interactive, non_interactive);
        }
        let legacy_request =
            hex::decode(fixture["legacy_30_second_request_hex"].as_str().unwrap()).unwrap();
        assert!(verify_request(&legacy_request, target.verifying_key()).is_err());
        let request_bytes = hex::decode(fixture["signed_request_hex"].as_str().unwrap()).unwrap();
        let request = verify_request(&request_bytes, target.verifying_key()).unwrap();
        assert_eq!(
            hex::encode(request.payload_hash),
            fixture["request_payload_hash_hex"].as_str().unwrap()
        );
        let approval_bytes = hex::decode(fixture["signed_approval_hex"].as_str().unwrap()).unwrap();
        let approval = verify_decision(&approval_bytes, approval.verifying_key()).unwrap();
        assert!(approval.decision.matches(&request));
        assert_eq!(approval.decision.action, DecisionAction::ApproveOnce);
        let denial_bytes = hex::decode(fixture["signed_denial_hex"].as_str().unwrap()).unwrap();
        let denial = verify_decision(&denial_bytes, denial.verifying_key()).unwrap();
        assert!(denial.decision.matches(&request));
        assert_eq!(denial.decision.action, DecisionAction::Deny);
    }

    #[test]
    fn environment_framing_is_unambiguous() {
        let left = digest_environment([b"ab".as_slice(), b"c".as_slice()]);
        let right = digest_environment([b"a".as_slice(), b"bc".as_slice()]);
        assert_ne!(left, right);
    }

    #[test]
    fn wire_message_round_trip() {
        let message = WireMessageV1::new(message_kind::PING, b"nonce".to_vec()).unwrap();
        let encoded = message.encode().unwrap();
        assert_eq!(WireMessageV1::decode(&encoded).unwrap(), message);
    }
}
