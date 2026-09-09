mod installer;
mod maintenance;
mod onboarding;
mod preflight;
mod providers;
mod recovery_timer;
mod recovery_worker;

use std::fs;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use sha2::{Digest, Sha256};
use syn_config::{
    AgentConfig, PluginConfig, Policy, DEFAULT_AGENT_CONFIG, DEFAULT_INSTALL_STATE,
    DEFAULT_PLUGIN_CONFIG, DEFAULT_POLICY_PATH,
};
use syn_protocol::{
    generate_signing_key, key_id_hex, signing_key_to_pem, verify_request, verifying_key_from_pem,
    verifying_key_sec1, verifying_key_to_pem,
};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(name = "synctl", version = syn_protocol::release_id(), about = "Manage and diagnose a Syn target")]
struct Cli {
    /// Emit one stable JSON value on stdout.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: TopLevel,
}

#[derive(Debug, Subcommand)]
enum TopLevel {
    /// Check platform, configuration, provider, service, and recovery state.
    Doctor(ConfigPaths),
    /// Show the configured target without exposing secrets.
    Status(ConfigPaths),
    /// Generate target key material.
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
    /// Stage approver identities and produce a certificate-pinned Mac profile.
    Pair {
        #[command(subcommand)]
        command: PairCommand,
    },
    /// Show, initialize, or update the root-owned local policy.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Verify a request without approving or executing it.
    Request {
        #[command(subcommand)]
        command: RequestCommand,
    },
    /// Exercise the signed target-to-Mac round trip without executing a command.
    Test {
        #[command(subcommand)]
        command: TestCommand,
    },
    /// Show or apply the guarded Ubuntu installation transaction.
    Install(InstallArguments),
    /// Restore ordinary password sudo using recorded state.
    Recover(RecoverArguments),
    /// Recover ordinary sudo and remove Syn; protected keys and backups remain.
    Uninstall(RecoverArguments),
    /// Restore local sudo and remove the current Mac's public pairing material.
    Unpair(UnpairArguments),
    /// Prove, arm, inspect, or cancel the machine-local automatic recovery timer.
    Recovery {
        #[command(subcommand)]
        command: RecoveryCommand,
    },
    /// Stage the exact Mac-selected release for guided installation or update.
    Onboard {
        #[command(subcommand)]
        command: OnboardCommand,
    },
    /// Install, serve, or revoke Syn's restricted root maintenance key.
    Maintenance {
        #[command(subcommand)]
        command: MaintenanceCommand,
    },
}

#[derive(Debug, Subcommand)]
enum MaintenanceCommand {
    /// Retain this helper and add one restricted root SSH key.
    Install {
        #[arg(long)]
        user: String,
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        apply: bool,
    },
    /// Serve the forced-command maintenance protocol.
    Serve,
    /// Remove only the exact maintenance key entry installed by Syn.
    Revoke {
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Clone, Debug, Args)]
struct ConfigPaths {
    #[arg(long, default_value = DEFAULT_AGENT_CONFIG)]
    agent_config: PathBuf,
    #[arg(long, default_value = DEFAULT_PLUGIN_CONFIG)]
    plugin_config: PathBuf,
    #[arg(long, default_value = DEFAULT_POLICY_PATH)]
    policy: PathBuf,
}

#[derive(Debug, Subcommand)]
enum KeysCommand {
    /// Create an ES256 target keypair without overwriting files.
    GenerateTarget {
        #[arg(long, default_value = "/etc/syn/keys/target-private.pem")]
        private: PathBuf,
        #[arg(long, default_value = "/etc/syn/keys/target-public.pem")]
        public: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum PairCommand {
    /// Validate and stage the Mac's public approval and denial keys.
    AcceptApprover {
        #[arg(long)]
        approval_x963_base64: String,
        #[arg(long)]
        denial_x963_base64: String,
        #[arg(long, default_value = "/etc/syn/keys/approval-public.pem")]
        approval_public: PathBuf,
        #[arg(long, default_value = "/etc/syn/keys/denial-public.pem")]
        denial_public: PathBuf,
        #[arg(long)]
        apply: bool,
    },
    /// Produce the certificate-pinned JSON profile imported by the Mac app.
    Profile {
        #[arg(long)]
        target_id: String,
        #[arg(long)]
        display_name: String,
        #[arg(long)]
        web_socket_url: String,
        #[arg(long, default_value = "/etc/syn/keys/target-public.pem")]
        target_public: PathBuf,
        #[arg(long, default_value = "/etc/syn/tls/target-cert.pem")]
        tls_certificate: PathBuf,
        #[arg(long)]
        client_identity_label: String,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Read and validate a policy.
    Show {
        #[arg(long, default_value = DEFAULT_POLICY_PATH)]
        path: PathBuf,
    },
    /// Create a one-user policy. Requires --apply and refuses overwrite.
    Init {
        #[arg(long)]
        user: String,
        #[arg(long)]
        uid: u32,
        #[arg(long, default_value = DEFAULT_POLICY_PATH)]
        path: PathBuf,
        #[arg(long)]
        apply: bool,
    },
    /// Change the two alpha policy switches while preserving all other fields.
    Set {
        #[arg(long, default_value = DEFAULT_POLICY_PATH)]
        path: PathBuf,
        #[arg(long)]
        password_fallback_on_timeout: Option<bool>,
        #[arg(long)]
        allow_interactive_root: Option<bool>,
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Debug, Subcommand)]
enum RequestCommand {
    /// Verify and summarize a target-signed COSE request.
    Inspect {
        #[arg(long)]
        file: PathBuf,
        #[arg(long, default_value = "/etc/syn/keys/target-public.pem")]
        target_public: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum TestCommand {
    /// Request approval for a synthetic /usr/bin/true intent.
    Approval {
        #[arg(long, default_value = DEFAULT_PLUGIN_CONFIG)]
        plugin_config: PathBuf,
        /// Record the successful signed round trip as install preflight evidence.
        #[arg(long)]
        record_preflight: bool,
    },
    /// Validate the configured timeout/PAM fallback surface without prompting.
    Fallback {
        #[arg(long, default_value = DEFAULT_PLUGIN_CONFIG)]
        plugin_config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum RecoveryCommand {
    /// Show the local automatic-recovery deadline without changing it.
    Status,
    /// Schedule ordinary password sudo restoration at an absolute deadline.
    Arm {
        #[arg(long, default_value_t = 15)]
        minutes: u64,
        /// Perform changes. Without this flag the command is read-only.
        #[arg(long)]
        apply: bool,
    },
    /// Cancel recovery after this invocation itself passes through healthy Syn sudo.
    Cancel {
        /// Perform changes. Without this flag the command is read-only.
        #[arg(long)]
        apply: bool,
    },
    /// Prove systemd timer execution with a harmless temporary marker.
    Prove {
        #[arg(long, default_value_t = 2)]
        seconds: u64,
        /// Perform changes. Without this flag the command is read-only.
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Debug, Subcommand)]
enum OnboardCommand {
    /// Verify and optionally copy ordinary-user inputs into protected staging.
    Prepare {
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        source_sha256: String,
        #[arg(long)]
        apply: bool,
    },
    /// Remove the root-only bootstrap copy after protected staging succeeds.
    Cleanup {
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        apply: bool,
    },
    /// Build the staged release under Syn's locked non-administrator account.
    Build {
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        apply: bool,
    },
    /// Install the package, preserve or create identities, and start pairing.
    Configure {
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        apply: bool,
    },
    /// Run a signed preflight, arm recovery, and activate the sudo gate.
    Activate {
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        apply: bool,
    },
    /// Verify the installed release through a fresh approval, then disarm recovery.
    Complete {
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Debug, Args)]
struct InstallArguments {
    #[arg(long)]
    user: String,
    /// Test sudo.ws directly without changing providers or adding NOPASSWD.
    #[arg(long)]
    shadow: bool,
    /// Perform changes. Without this flag the command is read-only.
    #[arg(long)]
    apply: bool,
    /// Required with --apply; confirms console or recovery access.
    #[arg(long)]
    acknowledge_console_recovery: bool,
    #[arg(long, default_value = DEFAULT_INSTALL_STATE)]
    state: PathBuf,
}

#[derive(Debug, Args)]
struct RecoverArguments {
    #[arg(long)]
    restore_local_sudo: bool,
    #[arg(long)]
    apply: bool,
    #[arg(long, default_value = DEFAULT_INSTALL_STATE)]
    state: PathBuf,
}

#[derive(Debug, Args)]
struct UnpairArguments {
    #[arg(long)]
    restore_local_sudo: bool,
    #[arg(long)]
    apply: bool,
    #[arg(long, default_value = DEFAULT_INSTALL_STATE)]
    state: PathBuf,
    #[arg(long, default_value = "/etc/syn/keys/approval-public.pem")]
    approval_public: PathBuf,
    #[arg(long, default_value = "/etc/syn/keys/denial-public.pem")]
    denial_public: PathBuf,
    #[arg(long, default_value = "/etc/syn/tls/approver-ca.pem")]
    client_ca: PathBuf,
}

#[derive(Serialize)]
struct Envelope<T: Serialize> {
    ok: bool,
    data: T,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    platform: String,
    architecture: String,
    ubuntu_release: Option<String>,
    target_supported: bool,
    agent_config: Check,
    plugin_config: Check,
    policy: Check,
    identity_coupling: Check,
    agent_socket: Check,
    network: Check,
    sudo_ws: Check,
    sudo_rs_provider: Check,
    sudo_coupling: Check,
    install_state: Check,
    recovery_timer: Check,
    healthy: bool,
}

#[derive(Debug, Serialize)]
struct Check {
    status: &'static str,
    detail: String,
}

#[derive(Debug, Serialize)]
struct StatusReport {
    schema_version: u16,
    configured: Option<bool>,
    configuration_state: &'static str,
    release_id: &'static str,
    release_commit: &'static str,
    target_id: Option<String>,
    managed_user: Option<String>,
    managed_uid: Option<u32>,
    listen: Option<String>,
    timeout_seconds: Option<u64>,
    agent_socket: Option<String>,
    target_key_id: Option<String>,
}

fn main() {
    let cli = Cli::parse();
    if let Err(error) = run(&cli) {
        if cli.json {
            let output = serde_json::json!({
                "ok": false,
                "error": { "code": "synctl_error", "message": error.to_string() }
            });
            match serde_json::to_string(&output) {
                Ok(encoded) => println!("{encoded}"),
                Err(serialization_error) => {
                    eprintln!("synctl: unable to encode JSON error: {serialization_error}")
                }
            }
        } else {
            eprintln!("synctl: {error:#}");
        }
        std::process::exit(1);
    }
}

fn run(cli: &Cli) -> Result<()> {
    match &cli.command {
        TopLevel::Doctor(paths) => output(cli.json, doctor(paths)?),
        TopLevel::Status(paths) => output(cli.json, status(paths)?),
        TopLevel::Keys { command } => match command {
            KeysCommand::GenerateTarget { private, public } => {
                require_root_if_system_path(private)?;
                generate_target_keys(private, public)?;
                output(
                    cli.json,
                    serde_json::json!({"private": private, "public": public}),
                )
            }
        },
        TopLevel::Pair { command } => match command {
            PairCommand::AcceptApprover {
                approval_x963_base64,
                denial_x963_base64,
                approval_public,
                denial_public,
                apply,
            } => output(
                cli.json,
                accept_approver(
                    approval_x963_base64,
                    denial_x963_base64,
                    approval_public,
                    denial_public,
                    *apply,
                )?,
            ),
            PairCommand::Profile {
                target_id,
                display_name,
                web_socket_url,
                target_public,
                tls_certificate,
                client_identity_label,
            } => output(
                cli.json,
                pairing_profile(
                    target_id,
                    display_name,
                    web_socket_url,
                    target_public,
                    tls_certificate,
                    client_identity_label,
                )?,
            ),
        },
        TopLevel::Policy { command } => match command {
            PolicyCommand::Show { path } => output(cli.json, show_policy(path)?),
            PolicyCommand::Init {
                user,
                uid,
                path,
                apply,
            } => {
                let policy = initialized_policy(user, *uid)?;
                if *apply {
                    require_root_if_system_path(path)?;
                    write_toml_private(path, &policy, 0o640)?;
                }
                output(
                    cli.json,
                    serde_json::json!({"apply": apply, "path": path, "policy": policy}),
                )
            }
            PolicyCommand::Set {
                path,
                password_fallback_on_timeout,
                allow_interactive_root,
                apply,
            } => {
                let mut policy = show_policy(path)?;
                if password_fallback_on_timeout.is_none() && allow_interactive_root.is_none() {
                    bail!("policy set requires at least one setting");
                }
                if let Some(value) = password_fallback_on_timeout {
                    policy.password_fallback_on_timeout = *value;
                }
                if let Some(value) = allow_interactive_root {
                    policy.allow_interactive_root = *value;
                }
                policy.validate()?;
                if *apply {
                    require_root_if_system_path(path)?;
                    write_toml_private(path, &policy, 0o640)?;
                }
                output(
                    cli.json,
                    serde_json::json!({"apply": apply, "path": path, "policy": policy}),
                )
            }
        },
        TopLevel::Request { command } => match command {
            RequestCommand::Inspect {
                file,
                target_public,
            } => output(cli.json, inspect_request(file, target_public)?),
        },
        TopLevel::Test { command } => match command {
            TestCommand::Approval {
                plugin_config,
                record_preflight,
            } => output(
                cli.json,
                preflight::test_approval(plugin_config, *record_preflight)?,
            ),
            TestCommand::Fallback { plugin_config } => {
                output(cli.json, preflight::test_fallback(plugin_config)?)
            }
        },
        TopLevel::Install(arguments) => {
            let plan = installer::plan(&arguments.user, &arguments.state, arguments.shadow)?;
            if arguments.apply {
                if !arguments.acknowledge_console_recovery {
                    bail!("--apply requires --acknowledge-console-recovery");
                }
                installer::apply(plan.clone(), &arguments.state)?;
            }
            output(cli.json, plan)
        }
        TopLevel::Recover(arguments) => {
            if !arguments.restore_local_sudo {
                bail!("recovery requires --restore-local-sudo");
            }
            output(
                cli.json,
                installer::recover(&arguments.state, arguments.apply)?,
            )
        }
        TopLevel::Uninstall(arguments) => {
            if !arguments.restore_local_sudo {
                bail!("uninstall requires --restore-local-sudo");
            }
            let actions = vec![
                "remove Syn's NOPASSWD rule before any other teardown",
                "restore ordinary password sudo and provider state",
                "disable the Syn agent and automatic recovery timer",
                "revoke Syn's restricted maintenance SSH key while preserving unrelated keys",
                "remove the syn-approvals package while retaining protected keys and backups",
            ];
            if arguments.apply {
                require_root()?;
                let installed = package_is_installed("syn-approvals")?;
                if arguments.state.exists() {
                    installer::recover(&arguments.state, true)?;
                } else if Path::new("/etc/sudoers.d/90-syn-managed-user").exists() {
                    bail!("Syn appears armed but install state is missing; use console recovery");
                } else {
                    recovery_timer::cancel(true)?;
                }
                verify_local_sudo_recovered(&arguments.state)?;
                if Path::new("/var/lib/syn/maintenance/config.json").try_exists()? {
                    maintenance::revoke(true)?;
                }
                if installed {
                    run_fixed(
                        "/usr/bin/systemctl",
                        &["disable", "--now", "syn-agent.service"],
                    )?;
                    run_fixed("/usr/bin/dpkg", &["--remove", "syn-approvals"])?;
                    run_fixed("/usr/bin/systemctl", &["daemon-reload"])?;
                }
            }
            output(
                cli.json,
                serde_json::json!({
                    "applied": arguments.apply,
                    "actions": actions,
                    "retained": ["Syn pairing keys", "recovery helper", "sudo backups"],
                }),
            )
        }
        TopLevel::Unpair(arguments) => {
            if !arguments.restore_local_sudo {
                bail!("unpair requires --restore-local-sudo");
            }
            let paths = [
                arguments.approval_public.clone(),
                arguments.denial_public.clone(),
                arguments.client_ca.clone(),
                PathBuf::from("/var/lib/syn/pairing-complete.json"),
                PathBuf::from("/var/lib/syn/preflight-complete.json"),
            ];
            if arguments.apply {
                require_root()?;
                if arguments.state.exists() {
                    installer::recover(&arguments.state, true)?;
                } else if Path::new("/etc/sudoers.d/90-syn-managed-user").exists() {
                    bail!("Syn appears armed but install state is missing; use console recovery");
                }
                for path in &paths {
                    if path.exists() {
                        fs::remove_file(path)?;
                    }
                }
            }
            output(
                cli.json,
                serde_json::json!({"apply": arguments.apply, "remove": paths}),
            )
        }
        TopLevel::Recovery { command } => match command {
            RecoveryCommand::Status => output(cli.json, recovery_timer::status()),
            RecoveryCommand::Arm { minutes, apply } => {
                if *apply {
                    recovery_timer::prepare_helper(&std::env::current_exe()?)?;
                }
                output(cli.json, recovery_timer::arm(*minutes, *apply)?)
            }
            RecoveryCommand::Cancel { apply } => {
                if *apply {
                    require_healthy_syn_sudo_invocation()?;
                }
                output(cli.json, recovery_timer::cancel(*apply)?)
            }
            RecoveryCommand::Prove { seconds, apply } => {
                output(cli.json, recovery_timer::prove(*seconds, *apply)?)
            }
        },
        TopLevel::Onboard { command } => match command {
            OnboardCommand::Prepare {
                request_sha256,
                source_sha256,
                apply,
            } => output(
                cli.json,
                onboarding::prepare(request_sha256, source_sha256, *apply)?,
            ),
            OnboardCommand::Build {
                operation_id,
                apply,
            } => output(cli.json, onboarding::build(operation_id, *apply)?),
            OnboardCommand::Cleanup {
                operation_id,
                apply,
            } => output(cli.json, onboarding::cleanup(operation_id, *apply)?),
            OnboardCommand::Configure {
                operation_id,
                apply,
            } => output(cli.json, onboarding::configure(operation_id, *apply)?),
            OnboardCommand::Activate {
                operation_id,
                apply,
            } => output(cli.json, onboarding::activate(operation_id, *apply)?),
            OnboardCommand::Complete {
                operation_id,
                apply,
            } => output(cli.json, onboarding::complete(operation_id, *apply)?),
        },
        TopLevel::Maintenance { command } => match command {
            MaintenanceCommand::Install {
                user,
                public_key,
                apply,
            } => output(cli.json, maintenance::install(user, public_key, *apply)?),
            MaintenanceCommand::Serve => maintenance::serve(),
            MaintenanceCommand::Revoke { apply } => output(cli.json, maintenance::revoke(*apply)?),
        },
    }
}

fn output<T>(json: bool, data: T) -> Result<()>
where
    T: Serialize + std::fmt::Debug,
{
    if json {
        println!("{}", serde_json::to_string(&Envelope { ok: true, data })?);
    } else {
        println!("{data:#?}");
    }
    Ok(())
}

fn package_is_installed(package: &str) -> Result<bool> {
    let output = Command::new("/usr/bin/dpkg-query")
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .current_dir("/")
        .args(["--show", "--showformat=${db:Status-Abbrev}", package])
        .stdin(std::process::Stdio::null())
        .output()?;
    if output.status.success() {
        return Ok(output.stderr.is_empty() && output.stdout == b"ii ");
    }
    if output.status.code() == Some(1) {
        return Ok(false);
    }
    bail!("unable to inspect package {package}")
}

fn verify_local_sudo_recovered(state: &Path) -> Result<()> {
    if state.try_exists()? || Path::new("/etc/sudoers.d/90-syn-managed-user").try_exists()? {
        bail!("ordinary password sudo recovery is incomplete");
    }
    let selected = fs::canonicalize("/usr/bin/sudo")?;
    if let Ok(sudo_ws) = fs::canonicalize("/usr/bin/sudo.ws") {
        if selected == sudo_ws {
            bail!("ordinary sudo still selects the Syn-gated provider");
        }
    }
    run_fixed("/usr/bin/sudo", &["-V"])?;
    run_fixed("/usr/sbin/visudo", &["-cf", "/etc/sudoers"])
}

fn run_fixed(program: &str, arguments: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .current_dir("/")
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .status()?;
    if !status.success() {
        bail!("{program} failed with {status}");
    }
    Ok(())
}

fn doctor(paths: &ConfigPaths) -> Result<DoctorReport> {
    let platform = std::env::consts::OS.to_owned();
    let architecture = std::env::consts::ARCH.to_owned();
    let ubuntu_release = os_release_value("VERSION_ID");
    let target_supported = platform == "linux"
        && architecture == "aarch64"
        && ubuntu_release.as_deref() == Some("26.04");

    let agent =
        AgentConfig::load(&paths.agent_config).and_then(|value| value.validate().map(|_| value));
    let plugin =
        PluginConfig::load(&paths.plugin_config).and_then(|value| value.validate().map(|_| value));
    let policy = Policy::load(&paths.policy).and_then(|value| value.validate().map(|_| value));
    let agent_socket_path = agent
        .as_ref()
        .map(|config| config.unix_socket.clone())
        .unwrap_or_else(|_| syn_config::DEFAULT_SOCKET_PATH.into());
    let identity_coupling = coupling_check(&agent, &plugin, &policy);
    let agent_config = result_check(agent.as_ref().map(|_| "valid"));
    let plugin_config = result_check(plugin.as_ref().map(|_| "valid"));
    let policy_check = result_check(policy.as_ref().map(|_| "valid"));
    let agent_socket = path_check(&agent_socket_path);
    let network = network_check(&agent);
    let sudo_ws = command_check("sudo.ws", &["-V"]);
    let sudo_rs_provider = sudo_rs_check();
    let sudo_coupling = match installer::check_installed_coupling(Path::new(DEFAULT_INSTALL_STATE))
    {
        Ok(detail) => Check {
            status: "ok",
            detail,
        },
        Err(error) => Check {
            status: "not_armed_or_invalid",
            detail: error.to_string(),
        },
    };
    let install_state = path_check(Path::new(DEFAULT_INSTALL_STATE));
    let recovery = recovery_timer::status();
    let recovery_timer = Check {
        status: recovery.status,
        detail: match recovery.deadline_unix_seconds {
            Some(deadline) => format!(
                "deadline={deadline} remaining={}s active={} enabled={} state_valid={}",
                recovery.seconds_remaining.unwrap_or(0),
                recovery.timer_active,
                recovery.timer_enabled,
                recovery.state_valid
            ),
            None if recovery.state_valid => "no automatic recovery deadline is armed".into(),
            None => "automatic recovery deadline state exists but is invalid".into(),
        },
    };
    let healthy = target_supported
        && agent_config.status == "ok"
        && plugin_config.status == "ok"
        && policy_check.status == "ok"
        && identity_coupling.status == "ok"
        && agent_socket.status == "ok"
        && network.status == "ok"
        && sudo_ws.status == "ok"
        && sudo_rs_provider.status == "ok"
        && sudo_coupling.status == "ok"
        && install_state.status == "ok";

    Ok(DoctorReport {
        platform,
        architecture,
        ubuntu_release,
        target_supported,
        agent_config,
        plugin_config,
        policy: policy_check,
        identity_coupling,
        agent_socket,
        network,
        sudo_ws,
        sudo_rs_provider,
        sudo_coupling,
        install_state,
        recovery_timer,
        healthy,
    })
}

fn require_healthy_syn_sudo_invocation() -> Result<()> {
    require_root()?;
    let install_state_path = Path::new(DEFAULT_INSTALL_STATE);
    let managed_sudoers_path = Path::new("/etc/sudoers.d/90-syn-managed-user");
    if !install_state_path.exists() {
        if managed_sudoers_path.exists() {
            bail!(
                "Syn's managed sudoers rule exists without install state; recover local sudo instead of canceling automatic recovery"
            );
        }
        return Ok(());
    }
    let state: syn_config::InstallState = serde_json::from_slice(
        &fs::read(install_state_path)
            .context("read install state before canceling automatic recovery")?,
    )?;
    let sudo_user = std::env::var("SUDO_USER").unwrap_or_default();
    let sudo_uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok());
    if sudo_user != state.managed_user || sudo_uid != Some(state.managed_uid) {
        bail!(
            "recovery cancel must itself be run by the managed user through an approved sudo invocation"
        );
    }
    let report = doctor(&ConfigPaths {
        agent_config: DEFAULT_AGENT_CONFIG.into(),
        plugin_config: DEFAULT_PLUGIN_CONFIG.into(),
        policy: DEFAULT_POLICY_PATH.into(),
    })?;
    if !report.healthy || !recovery_timer::status().armed {
        bail!("Syn and its automatic recovery timer must be healthy before cancellation");
    }
    Ok(())
}

fn coupling_check(
    agent: &std::result::Result<AgentConfig, syn_config::ConfigError>,
    plugin: &std::result::Result<PluginConfig, syn_config::ConfigError>,
    policy: &std::result::Result<Policy, syn_config::ConfigError>,
) -> Check {
    let (Ok(agent), Ok(plugin), Ok(policy)) = (agent, plugin, policy) else {
        return Check {
            status: "missing_or_invalid",
            detail: "configuration must be valid before coupling can be checked".into(),
        };
    };
    let mut fingerprints = None;
    let keys_match = (|| -> Option<bool> {
        let target_public =
            verifying_key_from_pem(&fs::read_to_string(&agent.target_public_key).ok()?).ok()?;
        let target_private_pem =
            Zeroizing::new(fs::read_to_string(&plugin.target_private_key).ok()?);
        let target_private = syn_protocol::signing_key_from_pem(&target_private_pem).ok()?;
        let agent_approval =
            verifying_key_from_pem(&fs::read_to_string(&agent.approval_public_key).ok()?).ok()?;
        let plugin_approval =
            verifying_key_from_pem(&fs::read_to_string(&plugin.approval_public_key).ok()?).ok()?;
        let agent_denial =
            verifying_key_from_pem(&fs::read_to_string(&agent.denial_public_key).ok()?).ok()?;
        let plugin_denial =
            verifying_key_from_pem(&fs::read_to_string(&plugin.denial_public_key).ok()?).ok()?;
        fingerprints = Some(format!(
            "target={} approval={} denial={}",
            key_id_hex(&target_public),
            key_id_hex(&agent_approval),
            key_id_hex(&agent_denial)
        ));
        Some(
            syn_protocol::key_id(&target_public)
                == syn_protocol::key_id(target_private.verifying_key())
                && syn_protocol::key_id(&agent_approval) == syn_protocol::key_id(&plugin_approval)
                && syn_protocol::key_id(&agent_denial) == syn_protocol::key_id(&plugin_denial),
        )
    })();
    let matches = agent.target_id == plugin.target_id
        && plugin.managed_uid == policy.managed_uid
        && plugin.managed_user == policy.managed_user
        && plugin.timeout_seconds == policy.timeout_seconds
        && keys_match == Some(true);
    Check {
        status: if matches { "ok" } else { "invalid" },
        detail: if matches {
            format!(
                "target, managed identity, timeout, and authorization keys match; {}",
                fingerprints.unwrap_or_default()
            )
        } else {
            "agent, plug-in, policy, or key material differs or is unreadable".into()
        },
    }
}

fn status(paths: &ConfigPaths) -> Result<StatusReport> {
    let agent =
        AgentConfig::load(&paths.agent_config).and_then(|config| config.validate().map(|_| config));
    let plugin = PluginConfig::load(&paths.plugin_config)
        .and_then(|config| config.validate().map(|_| config));
    let configuration_state = configuration_state(agent.as_ref().err(), plugin.as_ref().err());
    let configured = match configuration_state {
        "unreadable" => None,
        "configured" => Some(true),
        _ => Some(false),
    };
    let agent = agent.ok();
    let plugin = plugin.ok();
    let target_key_id = agent
        .as_ref()
        .and_then(|config| fs::read_to_string(&config.target_public_key).ok())
        .and_then(|pem| verifying_key_from_pem(&pem).ok())
        .map(|key| key_id_hex(&key));
    Ok(StatusReport {
        schema_version: 1,
        configured,
        configuration_state,
        release_id: syn_protocol::release_id(),
        release_commit: syn_protocol::release_commit(),
        target_id: agent.as_ref().map(|value| value.target_id.clone()),
        managed_user: plugin.as_ref().map(|value| value.managed_user.clone()),
        managed_uid: plugin.as_ref().map(|value| value.managed_uid),
        listen: agent.as_ref().map(|value| value.listen.clone()),
        timeout_seconds: plugin.as_ref().map(|value| value.timeout_seconds),
        agent_socket: agent
            .as_ref()
            .map(|value| value.unix_socket.display().to_string()),
        target_key_id,
    })
}

fn configuration_state(
    agent: Option<&syn_config::ConfigError>,
    plugin: Option<&syn_config::ConfigError>,
) -> &'static str {
    use syn_config::ConfigError;
    let errors = [agent, plugin];
    if errors.iter().flatten().any(|error| {
        matches!(error, ConfigError::Read { source, .. }
        if source.kind() != std::io::ErrorKind::NotFound)
    }) {
        return "unreadable";
    }
    if errors
        .iter()
        .flatten()
        .any(|error| !matches!(error, ConfigError::Read { .. }))
    {
        return "invalid";
    }
    match (agent, plugin) {
        (None, None) => "configured",
        (Some(_), Some(_)) => "absent",
        _ => "incomplete",
    }
}

fn network_check(agent: &std::result::Result<AgentConfig, syn_config::ConfigError>) -> Check {
    let Ok(agent) = agent else {
        return Check {
            status: "missing_or_invalid",
            detail: "valid agent configuration is required for network checks".into(),
        };
    };
    let interface_output = match Command::new("ip").args(["-j", "address", "show"]).output() {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            return Check {
                status: "error",
                detail: format!("local interface inspection exit={}", output.status),
            }
        }
        Err(error) => {
            return Check {
                status: "missing",
                detail: format!("unable to inspect local interfaces: {error}"),
            }
        }
    };
    let addresses = match interface_addresses(&interface_output.stdout) {
        Ok(addresses) => addresses,
        Err(error) => {
            return Check {
                status: "error",
                detail: error.to_string(),
            }
        }
    };
    if let Err(error) = agent.validate_selected_address(&addresses) {
        return Check {
            status: "invalid",
            detail: error.to_string(),
        };
    }
    let listen_ip = match agent.listen_address() {
        Ok(address) => address.ip(),
        Err(error) => {
            return Check {
                status: "invalid",
                detail: error.to_string(),
            }
        }
    };
    let interface = addresses
        .iter()
        .find_map(|(interface, address)| (*address == listen_ip).then_some(interface.as_str()))
        .unwrap_or("unknown");
    Check {
        status: "ok",
        detail: format!(
            "{} is assigned to {}; remote peers still require the paired mTLS client certificate",
            agent.listen, interface
        ),
    }
}

pub(crate) fn interface_addresses(json: &[u8]) -> Result<Vec<(String, std::net::IpAddr)>> {
    let reports: serde_json::Value = serde_json::from_slice(json)?;
    let reports = reports
        .as_array()
        .context("ip interface report is not an array")?;
    let mut addresses = Vec::new();
    for report in reports {
        let Some(interface) = report.get("ifname").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(items) = report
            .get("addr_info")
            .and_then(serde_json::Value::as_array)
        else {
            continue;
        };
        for item in items {
            let Some(local) = item.get("local").and_then(serde_json::Value::as_str) else {
                continue;
            };
            if let Ok(address) = local.parse() {
                addresses.push((interface.to_owned(), address));
            }
        }
    }
    Ok(addresses)
}

fn generate_target_keys(private: &Path, public: &Path) -> Result<()> {
    if private.exists() || public.exists() {
        bail!("refusing to overwrite an existing key file");
    }
    let key = generate_signing_key();
    write_file_new(private, signing_key_to_pem(&key)?.as_bytes(), 0o600)?;
    write_file_new(
        public,
        verifying_key_to_pem(key.verifying_key())?.as_bytes(),
        0o644,
    )
}

fn accept_approver(
    approval_base64: &str,
    denial_base64: &str,
    approval_path: &Path,
    denial_path: &Path,
    apply: bool,
) -> Result<serde_json::Value> {
    let approval = syn_protocol::verifying_key_from_sec1(&STANDARD.decode(approval_base64)?)?;
    let denial = syn_protocol::verifying_key_from_sec1(&STANDARD.decode(denial_base64)?)?;
    if syn_protocol::key_id(&approval) == syn_protocol::key_id(&denial) {
        bail!("approval and denial keys must be different");
    }
    if apply {
        require_root_if_system_path(approval_path)?;
        if approval_path.exists() || denial_path.exists() {
            bail!("refusing to overwrite an existing approver public key");
        }
        write_file_new(
            approval_path,
            verifying_key_to_pem(&approval)?.as_bytes(),
            0o644,
        )?;
        if let Err(error) = write_file_new(
            denial_path,
            verifying_key_to_pem(&denial)?.as_bytes(),
            0o644,
        ) {
            let _ = fs::remove_file(approval_path);
            return Err(error);
        }
    }
    Ok(serde_json::json!({
        "apply": apply,
        "approval_public": approval_path,
        "approval_key_id": key_id_hex(&approval),
        "denial_public": denial_path,
        "denial_key_id": key_id_hex(&denial),
    }))
}

#[derive(Debug, Serialize)]
struct MacTargetProfile {
    #[serde(rename = "targetID")]
    target_id: String,
    #[serde(rename = "displayName")]
    display_name: String,
    #[serde(rename = "webSocketURL")]
    web_socket_url: String,
    #[serde(rename = "targetPublicKeyBase64")]
    target_public_key_base64: String,
    #[serde(rename = "serverCertificateSHA256Hex")]
    server_certificate_sha256_hex: String,
    #[serde(rename = "clientIdentityLabel")]
    client_identity_label: String,
}

fn pairing_profile(
    target_id: &str,
    display_name: &str,
    web_socket_url: &str,
    target_public: &Path,
    tls_certificate: &Path,
    client_identity_label: &str,
) -> Result<MacTargetProfile> {
    if target_id.is_empty() || target_id.len() > 128 || display_name.is_empty() {
        bail!("target ID or display name is invalid");
    }
    let url = web_socket_url
        .parse::<http::Uri>()
        .context("invalid WebSocket URL")?;
    if url.scheme_str() != Some("wss") || url.authority().is_none() {
        bail!("Mac target profile requires a wss:// URL");
    }
    if client_identity_label.is_empty() {
        bail!("client identity label is required");
    }
    let public = verifying_key_from_pem(&fs::read_to_string(target_public)?)?;
    let mut reader = std::io::BufReader::new(fs::File::open(tls_certificate)?);
    let certificate = rustls_pemfile::certs(&mut reader)
        .next()
        .transpose()?
        .context("TLS certificate PEM is empty")?;
    Ok(MacTargetProfile {
        target_id: target_id.into(),
        display_name: display_name.into(),
        web_socket_url: web_socket_url.into(),
        target_public_key_base64: STANDARD.encode(verifying_key_sec1(&public)),
        server_certificate_sha256_hex: hex::encode(Sha256::digest(certificate.as_ref())),
        client_identity_label: client_identity_label.into(),
    })
}

fn show_policy(path: &Path) -> Result<Policy> {
    let policy = Policy::load(path)?;
    policy.validate()?;
    Ok(policy)
}

fn initialized_policy(user: &str, uid: u32) -> Result<Policy> {
    validate_user_name(user)?;
    let policy = Policy {
        managed_user: user.into(),
        managed_uid: uid,
        ..Policy::default()
    };
    policy.validate()?;
    Ok(policy)
}

fn inspect_request(file: &Path, target_public: &Path) -> Result<serde_json::Value> {
    let public = verifying_key_from_pem(&fs::read_to_string(target_public)?)?;
    let verified = verify_request(&fs::read(file)?, &public)?;
    let sudo = &verified.request.sudo;
    Ok(serde_json::json!({
        "target_id": verified.request.target_id,
        "request_id": hex::encode(verified.request.request_id.as_slice()),
        "request_hash": hex::encode(verified.payload_hash),
        "adapter": verified.request.adapter_kind,
        "schema": verified.request.adapter_schema_version,
        "ttl_ms": verified.request.ttl_ms,
        "invoking_uid": sudo.invoking_uid,
        "invoking_user": sudo.invoking_user,
        "run_as_uid": sudo.run_as_uid,
        "run_as_user": sudo.run_as_user,
        "executable_hex": hex::encode(sudo.executable.as_slice()),
        "argv_hex": sudo.argv.iter().map(|v| hex::encode(v.as_slice())).collect::<Vec<_>>(),
        "environment_digest": hex::encode(sudo.environment_digest.as_slice()),
        "risk_markers": sudo.risk_markers,
    }))
}

fn result_check<T, E: std::fmt::Display>(result: std::result::Result<T, E>) -> Check
where
    T: ToString,
{
    match result {
        Ok(detail) => Check {
            status: "ok",
            detail: detail.to_string(),
        },
        Err(error) => Check {
            status: "missing_or_invalid",
            detail: error.to_string(),
        },
    }
}

fn path_check(path: &Path) -> Check {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        Check {
            status: "ok",
            detail: format!(
                "{} mode={:04o} uid={} gid={}",
                path.display(),
                metadata.mode() & 0o7777,
                metadata.uid(),
                metadata.gid()
            ),
        }
    } else {
        Check {
            status: "missing",
            detail: path.display().to_string(),
        }
    }
}

fn command_check(program: &str, arguments: &[&str]) -> Check {
    match Command::new(program).args(arguments).output() {
        Ok(output) if output.status.success() => Check {
            status: "ok",
            detail: format!("{program} exited successfully"),
        },
        Ok(output) => Check {
            status: "error",
            detail: format!("{program} exit={}", output.status),
        },
        Err(error) => Check {
            status: "missing",
            detail: format!("{program}: {error}"),
        },
    }
}

fn sudo_rs_check() -> Check {
    let mut candidates = vec![
        PathBuf::from("/usr/bin/sudo-rs"),
        PathBuf::from("/usr/lib/cargo/bin/sudo"),
    ];
    if let Ok(output) = Command::new("update-alternatives")
        .args(["--list", "sudo"])
        .output()
    {
        for path in String::from_utf8_lossy(&output.stdout).lines() {
            if path.contains("sudo-rs") {
                candidates.push(PathBuf::from(path));
            }
        }
    }
    candidates.sort();
    candidates.dedup();
    let installed: Vec<_> = candidates
        .into_iter()
        .filter_map(|path| fs::metadata(&path).ok().map(|metadata| (path, metadata)))
        .collect();
    if installed.is_empty() {
        return Check {
            status: "not_installed",
            detail: "no known sudo-rs executable found".into(),
        };
    }
    let unsafe_provider = installed
        .iter()
        .any(|(_, metadata)| metadata.mode() & 0o4000 != 0);
    Check {
        status: if unsafe_provider {
            "unsafe_setuid"
        } else {
            "ok"
        },
        detail: installed
            .iter()
            .map(|(path, metadata)| {
                format!("{} mode={:04o}", path.display(), metadata.mode() & 0o7777)
            })
            .collect::<Vec<_>>()
            .join(", "),
    }
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

fn validate_user_name(user: &str) -> Result<()> {
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

fn require_root_if_system_path(path: &Path) -> Result<()> {
    if path.starts_with("/etc") || path.starts_with("/var") || path.starts_with("/usr") {
        require_root()?;
    }
    Ok(())
}

pub(crate) fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("this mutation requires root");
    }
    Ok(())
}

fn write_file_new(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(mode);
    let mut file = options.open(path)?;
    std::io::Write::write_all(&mut file, contents)?;
    file.sync_all()?;
    Ok(())
}

fn write_toml_private<T: Serialize>(path: &Path, value: &T, mode: u32) -> Result<()> {
    atomic_write(path, toml::to_string_pretty(value)?.as_bytes(), mode)
}

pub(crate) fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().context("output path has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".syn-{}.tmp", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(mode);
    let mut file = options.open(&temporary)?;
    std::io::Write::write_all(&mut file, contents)?;
    file.sync_all()?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
    fs::rename(&temporary, path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod status_tests {
    use super::*;
    use std::io::ErrorKind;
    use syn_config::ConfigError;

    fn read_error(kind: ErrorKind) -> ConfigError {
        ConfigError::Read {
            path: PathBuf::from("/synthetic/config.toml"),
            source: std::io::Error::from(kind),
        }
    }

    #[test]
    fn status_distinguishes_missing_partial_invalid_and_unreadable_configuration() {
        let missing = read_error(ErrorKind::NotFound);
        let denied = read_error(ErrorKind::PermissionDenied);
        let invalid = ConfigError::Invalid("synthetic invalid configuration".into());
        assert_eq!(configuration_state(None, None), "configured");
        assert_eq!(
            configuration_state(Some(&missing), Some(&missing)),
            "absent"
        );
        assert_eq!(configuration_state(Some(&missing), None), "incomplete");
        assert_eq!(configuration_state(None, Some(&missing)), "incomplete");
        assert_eq!(configuration_state(Some(&invalid), None), "invalid");
        assert_eq!(
            configuration_state(Some(&missing), Some(&denied)),
            "unreadable"
        );
        assert_eq!(
            configuration_state(Some(&denied), Some(&invalid)),
            "unreadable"
        );
    }

    #[test]
    fn absent_status_still_identifies_the_binary_release_without_claiming_configuration() {
        let directory = std::env::temp_dir().join(format!(
            "syn-absent-status-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        assert!(!directory.exists());
        let report = status(&ConfigPaths {
            agent_config: directory.join("agent.toml"),
            plugin_config: directory.join("plugin.toml"),
            policy: directory.join("policy.toml"),
        })
        .unwrap();
        assert_eq!(report.schema_version, 1);
        assert_eq!(report.configured, Some(false));
        assert_eq!(report.configuration_state, "absent");
        assert_eq!(report.release_id, syn_protocol::release_id());
        assert_eq!(report.release_commit, syn_protocol::release_commit());
        assert!(report.target_id.is_none());
        assert!(report.managed_uid.is_none());
        assert!(!directory.exists());
    }
}
