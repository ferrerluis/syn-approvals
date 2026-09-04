use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DEFAULT_AGENT_CONFIG: &str = "/etc/syn/agent.toml";
pub const DEFAULT_PLUGIN_CONFIG: &str = "/etc/syn/plugin.toml";
pub const DEFAULT_POLICY_PATH: &str = "/etc/syn/policy.toml";
pub const DEFAULT_INSTALL_STATE: &str = "/var/lib/syn/install-state.json";
pub const DEFAULT_PAIRING_STATE: &str = "/var/lib/syn/pairing.json";
pub const DEFAULT_SOCKET_PATH: &str = "/run/syn/agent.sock";
pub const DEFAULT_LISTEN_PORT: u16 = 41_781;
pub const APPROVAL_TIMEOUT_SECONDS: u64 = 90;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverlayKind {
    Tailscale,
    NordMeshnet,
}

impl OverlayKind {
    pub fn interface_name(self) -> &'static str {
        match self {
            Self::Tailscale => "tailscale0",
            Self::NordMeshnet => "nordlynx",
        }
    }

    pub fn accepts_address(self, address: IpAddr) -> bool {
        match self {
            Self::Tailscale => is_cgnat_ipv4(address) || is_tailscale_ipv6(address),
            Self::NordMeshnet => is_cgnat_ipv4(address),
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("unable to read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("unable to parse {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("configuration is invalid: {0}")]
    Invalid(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub schema_version: u16,
    pub target_id: String,
    pub overlay: OverlayKind,
    pub listen: String,
    pub approver_ip: IpAddr,
    #[serde(default = "default_socket")]
    pub unix_socket: PathBuf,
    #[serde(default = "default_plugin_uid")]
    pub plugin_uid: u32,
    #[serde(default = "default_max_pending")]
    pub max_pending: usize,
    pub target_public_key: PathBuf,
    pub approval_public_key: PathBuf,
    pub denial_public_key: PathBuf,
    pub tls_certificate: PathBuf,
    pub tls_private_key: PathBuf,
    pub client_ca_certificate: PathBuf,
}

impl AgentConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        load_toml(path)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != 1 {
            return Err(ConfigError::Invalid(
                "unsupported agent schema version".into(),
            ));
        }
        if self.target_id.is_empty() || self.target_id.len() > 128 {
            return Err(ConfigError::Invalid("invalid target ID".into()));
        }
        let listen = self.listen_address()?;
        if listen.port() == 0 || !self.overlay.accepts_address(listen.ip()) {
            return Err(ConfigError::Invalid(
                "listen address is not valid for the configured private overlay".into(),
            ));
        }
        if !self.overlay.accepts_address(self.approver_ip)
            || self.approver_ip == listen.ip()
            || self.approver_ip.is_ipv4() != listen.ip().is_ipv4()
        {
            return Err(ConfigError::Invalid(
                "approver IP is not a distinct peer on the configured private overlay".into(),
            ));
        }
        if !(1..=64).contains(&self.max_pending) {
            return Err(ConfigError::Invalid(
                "max_pending must be between 1 and 64".into(),
            ));
        }
        for path in [
            &self.target_public_key,
            &self.approval_public_key,
            &self.denial_public_key,
            &self.tls_certificate,
            &self.tls_private_key,
            &self.client_ca_certificate,
        ] {
            if !path.is_absolute() {
                return Err(ConfigError::Invalid(format!(
                    "security-sensitive path must be absolute: {}",
                    path.display()
                )));
            }
        }
        Ok(())
    }

    pub fn listen_address(&self) -> Result<SocketAddr, ConfigError> {
        self.listen.parse::<SocketAddr>().map_err(|_| {
            ConfigError::Invalid("listen must be a concrete overlay IP and port".into())
        })
    }

    pub fn validate_interface_addresses(
        &self,
        addresses: &[(String, IpAddr)],
    ) -> Result<(), ConfigError> {
        let listen_ip = self.listen_address()?.ip();
        let expected = self.overlay.interface_name();
        if addresses
            .iter()
            .any(|(interface, address)| interface == expected && *address == listen_ip)
        {
            Ok(())
        } else {
            Err(ConfigError::Invalid(format!(
                "listen IP {listen_ip} is not assigned to required interface {expected}"
            )))
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginConfig {
    pub schema_version: u16,
    pub target_id: String,
    pub managed_uid: u32,
    pub managed_user: String,
    #[serde(default = "default_socket")]
    pub agent_socket: PathBuf,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
    pub target_private_key: PathBuf,
    pub approval_public_key: PathBuf,
    pub denial_public_key: PathBuf,
    #[serde(default = "default_policy")]
    pub policy_path: PathBuf,
    #[serde(default = "default_pam_service")]
    pub pam_service: String,
}

impl PluginConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        load_toml(path)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != 1 {
            return Err(ConfigError::Invalid(
                "unsupported plug-in schema version".into(),
            ));
        }
        if self.target_id.is_empty() || self.managed_user.is_empty() {
            return Err(ConfigError::Invalid(
                "target and managed user are required".into(),
            ));
        }
        if self.timeout_seconds != APPROVAL_TIMEOUT_SECONDS {
            return Err(ConfigError::Invalid(
                "private alpha timeout must be exactly 90 seconds".into(),
            ));
        }
        if self.pam_service != "syn-sudo-fallback" {
            return Err(ConfigError::Invalid(
                "private alpha requires the dedicated syn-sudo-fallback PAM service".into(),
            ));
        }
        for path in [
            &self.agent_socket,
            &self.target_private_key,
            &self.approval_public_key,
            &self.denial_public_key,
            &self.policy_path,
        ] {
            if !path.is_absolute() {
                return Err(ConfigError::Invalid(format!(
                    "security-sensitive path must be absolute: {}",
                    path.display()
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema_version: u16,
    pub managed_uid: u32,
    pub managed_user: String,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
    #[serde(default = "default_max_pending")]
    pub max_pending: usize,
    #[serde(default = "default_true")]
    pub password_fallback_on_timeout: bool,
    #[serde(default)]
    pub allow_interactive_root: bool,
    #[serde(default = "default_allowed_modes")]
    pub allowed_modes: Vec<String>,
    #[serde(default = "default_blocked_executables")]
    pub blocked_executables: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            schema_version: 1,
            managed_uid: 1000,
            managed_user: "change-me".into(),
            timeout_seconds: default_timeout_seconds(),
            max_pending: default_max_pending(),
            password_fallback_on_timeout: true,
            allow_interactive_root: false,
            allowed_modes: default_allowed_modes(),
            blocked_executables: default_blocked_executables(),
        }
    }
}

impl Policy {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        load_toml(path)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != 1 {
            return Err(ConfigError::Invalid(
                "unsupported policy schema version".into(),
            ));
        }
        if self.managed_user.is_empty() || self.managed_user.contains(['\n', '\0']) {
            return Err(ConfigError::Invalid("invalid managed user".into()));
        }
        if self.timeout_seconds != APPROVAL_TIMEOUT_SECONDS || !(1..=64).contains(&self.max_pending)
        {
            return Err(ConfigError::Invalid(
                "policy limits are outside the safe range".into(),
            ));
        }
        if self.allowed_modes.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one sudo mode is required".into(),
            ));
        }
        Ok(())
    }

    pub fn blocks_executable(&self, executable: &[u8]) -> bool {
        if self.allow_interactive_root {
            return false;
        }
        let basename = executable
            .rsplit(|byte| *byte == b'/')
            .next()
            .unwrap_or(executable);
        self.blocked_executables
            .iter()
            .any(|blocked| basename == blocked.as_bytes())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstallState {
    pub schema_version: u16,
    pub phase: String,
    pub managed_user: String,
    pub managed_uid: u32,
    pub previous_sudo_alternative: Option<String>,
    #[serde(default)]
    pub stat_overrides: Vec<StatOverrideRecord>,
    #[serde(default)]
    pub created_paths: Vec<PathBuf>,
    pub sudo_conf_backup: Option<PathBuf>,
    /// Shadow testing never changes sudo providers or creates passwordless access.
    #[serde(default)]
    pub shadow_mode: bool,
    #[serde(default)]
    pub sudo_conf_original_mode: Option<u32>,
    #[serde(default)]
    pub previous_sudo_alternative_auto: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatOverrideRecord {
    pub path: PathBuf,
    pub previous_mode: u32,
    pub previous_owner: u32,
    pub previous_group: u32,
}

pub fn load_toml<T>(path: impl AsRef<Path>) -> Result<T, ConfigError>
where
    T: for<'de> Deserialize<'de>,
{
    let path = path.as_ref();
    let contents = fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    toml::from_str(&contents).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

fn default_socket() -> PathBuf {
    DEFAULT_SOCKET_PATH.into()
}

fn is_cgnat_ipv4(address: IpAddr) -> bool {
    let IpAddr::V4(address) = address else {
        return false;
    };
    let octets = address.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn is_tailscale_ipv6(address: IpAddr) -> bool {
    let IpAddr::V6(address) = address else {
        return false;
    };
    let segments = address.segments();
    segments[0] == 0xfd7a && segments[1] == 0x115c && segments[2] == 0xa1e0
}

fn default_plugin_uid() -> u32 {
    0
}

fn default_timeout_seconds() -> u64 {
    APPROVAL_TIMEOUT_SECONDS
}

fn default_max_pending() -> usize {
    16
}

fn default_policy() -> PathBuf {
    DEFAULT_POLICY_PATH.into()
}

fn default_pam_service() -> String {
    "syn-sudo-fallback".into()
}

fn default_true() -> bool {
    true
}

fn default_allowed_modes() -> Vec<String> {
    vec!["run".into()]
}

fn default_blocked_executables() -> Vec<String> {
    [
        "ash", "bash", "csh", "dash", "elvish", "env", "fish", "ion", "ksh", "lua", "node", "perl",
        "python", "python3", "ruby", "sh", "su", "sudo", "sudo-rs", "sudo.ws", "tcsh", "xonsh",
        "zsh",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_blocks_obvious_shells() {
        let policy = Policy::default();
        assert!(policy.blocks_executable(b"/usr/bin/bash"));
        assert!(!policy.blocks_executable(b"/usr/bin/apt"));
    }

    #[test]
    fn policy_rejects_unsafe_timeout() {
        let policy = Policy {
            timeout_seconds: 1,
            ..Policy::default()
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn policy_rejects_non_alpha_timeout() {
        let policy = Policy {
            timeout_seconds: 120,
            ..Policy::default()
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn ninety_second_defaults_and_examples_reject_legacy_timeout() {
        assert_eq!(Policy::default().timeout_seconds, 90);
        let mut policy: Policy =
            toml::from_str(include_str!("../../../packaging/examples/policy.toml")).unwrap();
        let mut plugin: PluginConfig =
            toml::from_str(include_str!("../../../packaging/examples/plugin.toml")).unwrap();
        assert_eq!(policy.timeout_seconds, 90);
        assert_eq!(plugin.timeout_seconds, 90);
        policy.validate().unwrap();
        plugin.validate().unwrap();
        policy.timeout_seconds = 30;
        plugin.timeout_seconds = 30;
        assert!(policy.validate().is_err());
        assert!(plugin.validate().is_err());
    }

    #[test]
    fn overlay_ranges_are_narrow() {
        assert!(OverlayKind::NordMeshnet.accepts_address("100.64.0.1".parse().unwrap()));
        assert!(OverlayKind::NordMeshnet.accepts_address("100.127.255.254".parse().unwrap()));
        assert!(!OverlayKind::NordMeshnet.accepts_address("fd7a:115c:a1e0::1".parse().unwrap()));
        assert!(OverlayKind::Tailscale.accepts_address("fd7a:115c:a1e0::1".parse().unwrap()));
        assert!(!OverlayKind::Tailscale.accepts_address("0.0.0.0".parse().unwrap()));
        assert!(!OverlayKind::NordMeshnet.accepts_address("192.168.1.2".parse().unwrap()));
    }

    fn agent_config(overlay: OverlayKind, listen: &str, approver_ip: &str) -> AgentConfig {
        AgentConfig {
            schema_version: 1,
            target_id: "pi-development".into(),
            overlay,
            listen: listen.into(),
            approver_ip: approver_ip.parse().unwrap(),
            unix_socket: DEFAULT_SOCKET_PATH.into(),
            plugin_uid: 0,
            max_pending: 16,
            target_public_key: "/etc/syn/keys/target-public.pem".into(),
            approval_public_key: "/etc/syn/keys/approval-public.pem".into(),
            denial_public_key: "/etc/syn/keys/denial-public.pem".into(),
            tls_certificate: "/etc/syn/tls/target-cert.pem".into(),
            tls_private_key: "/etc/syn/tls/target-key.pem".into(),
            client_ca_certificate: "/etc/syn/tls/approver-ca.pem".into(),
        }
    }

    #[test]
    fn nord_config_requires_nord_interface_and_distinct_peer() {
        let config = agent_config(
            OverlayKind::NordMeshnet,
            "100.99.102.171:41781",
            "100.70.150.245",
        );
        config.validate().unwrap();
        config
            .validate_interface_addresses(&[("nordlynx".into(), "100.99.102.171".parse().unwrap())])
            .unwrap();
        assert!(config
            .validate_interface_addresses(&[(
                "tailscale0".into(),
                "100.99.102.171".parse().unwrap()
            )])
            .is_err());

        let same_peer = agent_config(
            OverlayKind::NordMeshnet,
            "100.99.102.171:41781",
            "100.99.102.171",
        );
        assert!(same_peer.validate().is_err());
    }

    #[test]
    fn overlay_config_rejects_wildcard_loopback_and_lan() {
        for listen in ["0.0.0.0:41781", "127.0.0.1:41781", "192.168.1.2:41781"] {
            assert!(
                agent_config(OverlayKind::NordMeshnet, listen, "100.70.150.245")
                    .validate()
                    .is_err()
            );
        }
    }
}
