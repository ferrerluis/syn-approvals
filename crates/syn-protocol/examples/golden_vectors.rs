use minicbor::bytes::ByteVec;
use p256::ecdsa::SigningKey;
use serde_json::json;
use syn_protocol::{
    digest_environment, key_id, sign_decision, sign_request, verify_request, ApprovalRequestV1,
    AuthenticationClass, CommandInfoEntry, DecisionAction, DecisionV1, SudoIntentV1,
    PROTOCOL_VERSION, SUDO_ADAPTER_KIND, SUDO_SCHEMA_VERSION,
};

fn main() {
    let target = SigningKey::from_slice(&[1; 32]).unwrap();
    let approval = SigningKey::from_slice(&[2; 32]).unwrap();
    let denial = SigningKey::from_slice(&[3; 32]).unwrap();
    let environment = [b"LANG=C.UTF-8".as_slice(), b"PATH=/usr/bin".as_slice()];
    let intent = SudoIntentV1 {
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
        argv: [b"apt".as_slice(), b"install".as_slice(), b"gh".as_slice()]
            .into_iter()
            .map(|value| ByteVec::from(value.to_vec()))
            .collect(),
        command_info: vec![CommandInfoEntry {
            key: "command".into(),
            value: ByteVec::from(b"/usr/bin/apt".to_vec()),
        }],
        environment_digest: ByteVec::from(digest_environment(environment).to_vec()),
        environment_names: vec!["LANG".into(), "PATH".into()],
        policy_version: 1,
        sudo_provider: "sudo.ws-1.9.17p2".into(),
        risk_markers: vec!["package_manager_root_equivalent".into()],
    };
    let request = ApprovalRequestV1 {
        protocol_version: PROTOCOL_VERSION,
        request_id: ByteVec::from((0_u8..16).collect::<Vec<_>>()),
        nonce: ByteVec::from((32_u8..64).collect::<Vec<_>>()),
        target_id: "pi-dev".into(),
        target_key_id: ByteVec::from(key_id(target.verifying_key()).to_vec()),
        adapter_kind: SUDO_ADAPTER_KIND.into(),
        adapter_schema_version: SUDO_SCHEMA_VERSION,
        issued_at_unix_ms: 1_700_000_000_000,
        ttl_ms: 30_000,
        sudo: intent,
    };
    let signed_request = sign_request(&request, &target).unwrap();
    let verified = verify_request(&signed_request, target.verifying_key()).unwrap();
    let mut approval_decision = DecisionV1::for_request(
        &verified,
        DecisionAction::ApproveOnce,
        AuthenticationClass::SystemUserPresence,
        approval.verifying_key(),
    );
    approval_decision.decided_at_unix_ms = 1_700_000_001_000;
    let mut denial_decision = DecisionV1::for_request(
        &verified,
        DecisionAction::Deny,
        AuthenticationClass::DeviceAuthenticated,
        denial.verifying_key(),
    );
    denial_decision.decided_at_unix_ms = 1_700_000_001_001;

    let output = json!({
        "schema_version": 1,
        "target_public_sec1_hex": hex::encode(syn_protocol::verifying_key_sec1(target.verifying_key())),
        "approval_public_sec1_hex": hex::encode(syn_protocol::verifying_key_sec1(approval.verifying_key())),
        "denial_public_sec1_hex": hex::encode(syn_protocol::verifying_key_sec1(denial.verifying_key())),
        "signed_request_hex": hex::encode(signed_request),
        "request_payload_hash_hex": hex::encode(verified.payload_hash),
        "signed_approval_hex": hex::encode(sign_decision(&approval_decision, &approval).unwrap()),
        "signed_denial_hex": hex::encode(sign_decision(&denial_decision, &denial).unwrap()),
    });
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
