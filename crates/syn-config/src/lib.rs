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
pub const AGENT_CONFIG_SCHEMA_VERSION: u16 = 2;
pub const INSTALL_STATE_SCHEMA_VERSION: u16 = 2;
pub const SUDO_SECURE_PATH: &str =
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin";
// Replace (do not append to) sudo's inherited-variable lists for the managed
// user. The approval plug-in independently validates the resulting values.
pub const SUDO_ENV_KEEP: &str =
    "DISPLAY XAUTHORITY DEBIAN_FRONTEND DEBIAN_PRIORITY NEEDRESTART_MODE";
pub const SUDO_ENV_CHECK: &str = "COLORTERM LANG LANGUAGE TERM LC_ALL LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT LC_IDENTIFICATION";

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
    pub listen: String,
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
        let path = path.as_ref();
        let contents = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        parse_agent_config(path, &contents)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != AGENT_CONFIG_SCHEMA_VERSION {
            return Err(ConfigError::Invalid(format!(
                "unsupported agent schema version {}; expected {AGENT_CONFIG_SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        if self.target_id.is_empty() || self.target_id.len() > 128 {
            return Err(ConfigError::Invalid("invalid target ID".into()));
        }
        let listen = self.listen_address()?;
        if listen.port() == 0 || !is_safe_listen_address(listen.ip()) {
            return Err(ConfigError::Invalid(
                "listen must use a non-wildcard, non-loopback, unicast address and a nonzero port"
                    .into(),
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
            ConfigError::Invalid("listen must be one concrete IP address and port".into())
        })
    }

    pub fn validate_selected_address(
        &self,
        addresses: &[(String, IpAddr)],
    ) -> Result<(), ConfigError> {
        let listen_ip = self.listen_address()?.ip();
        if addresses.iter().any(|(_, address)| *address == listen_ip) {
            Ok(())
        } else {
            Err(ConfigError::Invalid(format!(
                "listen IP {listen_ip} is not assigned to any local interface"
            )))
        }
    }
}

fn parse_agent_config(path: &Path, contents: &str) -> Result<AgentConfig, ConfigError> {
    let value: toml::Value = toml::from_str(contents).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    let table = value.as_table();
    let uses_legacy_network_fields = table
        .is_some_and(|table| table.contains_key("overlay") || table.contains_key("approver_ip"));
    let is_legacy_schema = value
        .get("schema_version")
        .and_then(toml::Value::as_integer)
        == Some(1);
    if is_legacy_schema || uses_legacy_network_fields {
        return Err(ConfigError::Invalid(
            "legacy provider-bound agent configuration is not accepted; guided setup must write schema_version = 2 with one explicit listen address and without overlay or approver_ip"
                .into(),
        ));
    }
    toml::from_str(contents).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })
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
    /// An existing protective administrator override is never owned by Syn.
    /// Absent in legacy v1 state, whose recorded overrides were all Syn-owned.
    #[serde(default)]
    pub preserved_override: Option<String>,
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

fn is_safe_listen_address(address: IpAddr) -> bool {
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && address != IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
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

    fn agent_config(listen: &str) -> AgentConfig {
        AgentConfig {
            schema_version: AGENT_CONFIG_SCHEMA_VERSION,
            target_id: "pi-development".into(),
            listen: listen.into(),
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
    fn selected_address_accepts_lan_and_provider_independent_interfaces() {
        let config = agent_config("192.168.50.12:41781");
        config.validate().unwrap();
        config
            .validate_selected_address(&[("enp1s0".into(), "192.168.50.12".parse().unwrap())])
            .unwrap();
        config
            .validate_selected_address(&[(
                "future-private-network0".into(),
                "192.168.50.12".parse().unwrap(),
            )])
            .unwrap();
        assert!(config
            .validate_selected_address(&[("enp1s0".into(), "192.168.50.13".parse().unwrap())])
            .is_err());
    }

    #[test]
    fn selected_address_rejects_unsafe_listener_classes() {
        for listen in [
            "0.0.0.0:41781",
            "[::]:41781",
            "127.0.0.1:41781",
            "224.0.0.1:41781",
            "[ff02::1]:41781",
            "255.255.255.255:41781",
            "192.168.1.2:0",
        ] {
            assert!(
                agent_config(listen).validate().is_err(),
                "accepted {listen}"
            );
        }
    }

    #[test]
    fn legacy_provider_bound_agent_config_is_rejected_explicitly() {
        let error = parse_agent_config(
            Path::new("agent.toml"),
            r#"
schema_version = 1
target_id = "pi-development"
overlay = "nord_meshnet"
listen = "100.64.0.10:41781"
approver_ip = "100.64.0.11"
"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("legacy provider-bound"));
        assert!(error.to_string().contains("schema_version = 2"));
    }

    #[test]
    fn packaged_agent_example_uses_current_schema() {
        let config = parse_agent_config(
            Path::new("agent.toml"),
            include_str!("../../../packaging/examples/agent.toml"),
        )
        .unwrap();
        config.validate().unwrap();
    }
}
