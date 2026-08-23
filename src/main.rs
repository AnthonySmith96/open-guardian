mod audit;
mod banner;
mod bench;
mod broker;
mod config;
mod context;
mod logger;
mod pipeline;
mod proxy;
mod router;
mod security;
mod server;

use crate::server::ServerConfig;
use clap::{Parser, Subcommand};
use service_manager::*;
#[cfg(windows)]
use std::io::IsTerminal;
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

#[cfg(feature = "native-keyring")]
use open_guardian::secrets::{KeychainAdmin, SecretRef, SecretValue};

#[cfg(windows)]
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

#[derive(Parser)]
#[command(name = "open-guardian")]
#[command(about = "Local egress data protection for AI agents", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the egress protection proxy
    Start {
        /// IP address to listen on (defaults to loopback only)
        #[arg(long)]
        bind: Option<String>,

        /// Port to listen on
        #[arg(short, long)]
        port: Option<u16>,

        /// Upstream URL
        #[arg(short, long)]
        upstream: Option<String>,

        /// Use local Ollama (Overrides upstream)
        #[arg(short, long)]
        local: bool,

        /// Enable detailed request logging
        #[arg(short, long)]
        verbose: bool,
    },
    /// Scan for insecure configurations (The Inspector)
    Audit {
        /// Path to scan
        #[arg(default_value = ".")]
        path: String,
    },
    /// Generate integrity manifest for rules (Requires GUARDIAN_HMAC_KEY)
    Sign {
        /// Directory containing rules
        #[arg(default_value = "rules")]
        rules_dir: String,
    },
    /// Run the leak-detection benchmark against the corpus
    Bench {
        /// Directory with the corpus case files
        #[arg(long, default_value = "benchmarks/corpus")]
        corpus: PathBuf,

        /// Override the rules file (e.g. an upstream gitleaks.toml)
        #[arg(long)]
        rules: Option<PathBuf>,

        /// Exit non-zero on any leak or missed detection (CI gate)
        #[arg(long)]
        gate: bool,

        /// Write the deterministic benchmark document here
        #[arg(long)]
        docs: Option<PathBuf>,

        /// Write detailed JSON results here
        #[arg(long)]
        json: Option<PathBuf>,
    },
    /// Service management (Install, Uninstall, Start, Stop)
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Provision credentials in Open-Guardian's native keychain namespace
    #[cfg(feature = "native-keyring")]
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },
    /// Action Broker daemon and manual requests (v0.5)
    Broker {
        #[command(subcommand)]
        action: BrokerAction,
    },
    /// Serve guardian tools over MCP stdio for AI agent harnesses
    #[cfg(feature = "mcp")]
    Mcp,
    /// Manage the signed action policy (keygen, sign, verify, sudoers)
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// Approve a pending broker action request (operator channel)
    Approve {
        /// Request id shown by `open-guardian requests`
        id: String,

        /// Approval code (prompted if omitted)
        #[arg(long)]
        code: Option<String>,

        /// Skip the approval-code check (explicit operator override)
        #[arg(long)]
        yes: bool,
    },
    /// Deny a pending broker action request
    Deny {
        /// Request id shown by `open-guardian requests`
        id: String,
    },
    /// List broker action requests (shows approval codes while pending)
    Requests,
    /// Verify the hash chain of an audit log
    Verify {
        /// Audit log file (proxy or broker)
        #[arg(default_value = "guardian_audit.jsonl")]
        log: String,
    },
    /// Wrap an MCP stdio server and sanitize its tool outputs (Context DLP)
    McpGateway {
        /// DLP rules file override (before --)
        #[arg(long)]
        rules: Option<PathBuf>,

        /// Downstream MCP server after --, e.g. -- npx -y @modelcontextprotocol/server-github
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Sanitize text through the DLP engine: stdin → stdout (hooks, pipelines)
    Sanitize {
        /// Read from this file instead of stdin
        #[arg(long)]
        file: Option<PathBuf>,

        /// DLP rules file override
        #[arg(long)]
        rules: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum BrokerAction {
    /// Start the broker daemon (loads the signed policy; loopback IPC only)
    Start,
    /// Submit an action request from the terminal (for testing without MCP)
    Request {
        /// Action id from the signed policy
        action: String,

        /// Justification shown to the operator
        #[arg(default_value = "manual test")]
        reason: String,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum PolicyAction {
    /// Generate an ed25519 keypair: <key> (secret, 0600) and <key>.pub
    Keygen {
        #[arg(long, default_value = "broker/policy.key")]
        key: PathBuf,
    },
    /// Sign a policy file (writes <policy>.sig)
    Sign {
        #[arg(long, default_value = "broker/policy.toml")]
        policy: PathBuf,

        #[arg(long, default_value = "broker/policy.key")]
        key: PathBuf,
    },
    /// Verify a policy signature and summarize its actions
    Verify {
        #[arg(long, default_value = "broker/policy.toml")]
        policy: PathBuf,

        #[arg(long, default_value = "broker/policy.pub")]
        public_key: PathBuf,
    },
    /// Print the exact sudoers lines for the policy's elevated actions
    Sudoers {
        #[arg(long, default_value = "broker/policy.toml")]
        policy: PathBuf,

        #[arg(long, default_value = "broker/policy.pub")]
        public_key: PathBuf,

        /// OS user the broker daemon runs as
        #[arg(long)]
        user: Option<String>,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum ServiceAction {
    /// Install as a system service
    Install,
    /// Uninstall the system service
    Uninstall,
    /// Start the installed service
    Start,
    /// Stop the running service
    Stop,
}

#[cfg(feature = "native-keyring")]
#[derive(Subcommand, Debug, Clone)]
enum SecretAction {
    /// Store a value entered through a hidden terminal prompt
    Set {
        /// Canonical keychain reference, for example {{secret:keychain://providers/openai#api_key}}
        reference: SecretRef,
    },
    /// Delete an exact keychain entry
    Delete {
        /// Canonical keychain reference to delete
        reference: SecretRef,
    },
}

#[cfg(feature = "native-keyring")]
async fn handle_secret_command(action: SecretAction) -> anyhow::Result<()> {
    let admin = KeychainAdmin;

    match action {
        SecretAction::Set { reference } => {
            KeychainAdmin::validate_reference(&reference)?;
            let value = rpassword::prompt_password("Secret value: ")?;
            let value = SecretValue::new(value)?;
            admin.set(&reference, value).await?;
            banner::print_success(&format!(
                "Stored {reference} in the native credential store."
            ));
        }
        SecretAction::Delete { reference } => {
            KeychainAdmin::validate_reference(&reference)?;
            admin.delete(&reference).await?;
            banner::print_success(&format!(
                "Deleted {reference} from the native credential store."
            ));
        }
    }

    Ok(())
}

fn get_env_path() -> PathBuf {
    // Determine the base directory: the directory containing the executable.
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            return exe_dir.join(".env");
        }
    }
    std::env::current_dir().unwrap_or_default().join(".env")
}

fn handle_service_command(action: ServiceAction) -> anyhow::Result<()> {
    let label: ServiceLabel = "com.openguardian.shield"
        .parse()
        .map_err(|error| anyhow::anyhow!("invalid native service label: {error}"))?;
    let manager = <dyn ServiceManager>::native()
        .map_err(|e| anyhow::anyhow!("Failed to detect service manager: {e}"))?;

    match action {
        ServiceAction::Install => {
            let exe_path = std::env::current_exe()?;
            banner::print_step(&format!("Installing service {label}..."));

            manager
                .install(ServiceInstallCtx {
                    label: label.clone(),
                    program: exe_path,
                    args: vec!["start".into()],
                    contents: None,
                    username: None,
                    working_directory: None,
                    environment: None,
                    autostart: true,
                    restart_policy: if cfg!(windows) {
                        RestartPolicy::OnFailure {
                            delay_secs: Some(60),
                        }
                    } else {
                        RestartPolicy::Always {
                            delay_secs: Some(5),
                        }
                    },
                })
                .map_err(|e| anyhow::anyhow!("Installation failed: {e}"))?;

            #[cfg(windows)]
            {
                // service-manager doesn't support sc failure, so we run it manually
                let status = std::process::Command::new("sc.exe")
                    .args([
                        "failure",
                        "com.openguardian.shield",
                        "actions=restart/60000/restart/60000/restart/60000",
                        "reset=86400",
                    ])
                    .status();

                match status {
                    Ok(s) if s.success() => banner::print_success("Windows: Auto-recovery policy (60s) applied via sc failure."),
                    _ => banner::print_warning("Windows: Failed to apply sc failure policy. You may need to run it manually as Administrator."),
                }
            }

            banner::print_success("Service installed successfully.");
        }
        ServiceAction::Uninstall => {
            banner::print_step(&format!("Uninstalling service {label}..."));
            manager
                .uninstall(ServiceUninstallCtx {
                    label: label.clone(),
                })
                .map_err(|e| anyhow::anyhow!("Uninstallation failed: {e}"))?;
            banner::print_success("Service uninstalled successfully.");
        }
        ServiceAction::Start => {
            banner::print_step(&format!("Starting service {label}..."));
            manager
                .start(ServiceStartCtx {
                    label: label.clone(),
                })
                .map_err(|e| anyhow::anyhow!("Failed to start service: {e}"))?;
            banner::print_success("Service started.");
        }
        ServiceAction::Stop => {
            banner::print_step(&format!("Stopping service {label}..."));
            manager
                .stop(ServiceStopCtx {
                    label: label.clone(),
                })
                .map_err(|e| anyhow::anyhow!("Failed to stop service: {e}"))?;
            banner::print_success("Service stopped.");
        }
    }
    Ok(())
}

#[cfg(windows)]
define_windows_service!(ffi_service_main, windows_service_main);

#[cfg(windows)]
fn windows_service_main(_arguments: Vec<std::ffi::OsString>) {
    let shutdown_token = tokio_util::sync::CancellationToken::new();
    let shutdown_token_clone = shutdown_token.clone();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                shutdown_token_clone.cancel();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle =
        service_control_handler::register("com.openguardian.shield", event_handler).unwrap();

    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .unwrap();

    // Start the actual logic
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        if let Err(e) = run_app(
            Commands::Start {
                bind: None,
                port: None,
                upstream: None,
                local: false,
                verbose: true,
            },
            shutdown_token,
        )
        .await
        {
            tracing::error!("Service failure: {}", e);
        }
    });

    // Tell SCM we are stopping
    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::StopPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 1,
            wait_hint: Duration::from_secs(5),
            process_id: None,
        })
        .unwrap();

    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .unwrap();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Enable ANSI support on Windows
    #[cfg(windows)]
    let _ = colored::control::set_virtual_terminal(true);

    logger::init_logger();

    let env_path = get_env_path();
    if env_path.exists() {
        match dotenvy::from_path(&env_path) {
            Ok(_) => tracing::info!("Loaded .env from: {}", env_path.display()),
            Err(e) => tracing::error!("Failed to load .env from {}: {}", env_path.display(), e),
        }
    } else {
        tracing::info!("No .env found at: {}", env_path.display());
    }

    // Check if we are being run as a Windows service
    #[cfg(windows)]
    {
        if std::env::args().any(|arg| arg == "start") && !std::io::stdout().is_terminal() {
            tracing::info!("Starting as Windows Service...");
            return service_dispatcher::start("com.openguardian.shield", ffi_service_main)
                .map_err(|e| anyhow::anyhow!("Service dispatcher failed: {}", e));
        }
    }

    let cli = Cli::parse();

    // Stdio-protocol subcommands own stdout (MCP JSON-RPC frames, sanitize
    // pipes): nothing but their payload may be printed there.
    let owns_stdout = {
        #[cfg(feature = "mcp")]
        {
            matches!(
                cli.command,
                Commands::Mcp | Commands::McpGateway { .. } | Commands::Sanitize { .. }
            )
        }
        #[cfg(not(feature = "mcp"))]
        {
            matches!(
                cli.command,
                Commands::McpGateway { .. } | Commands::Sanitize { .. }
            )
        }
    };
    if !owns_stdout {
        banner::print_banner();
    }

    // Create a cancellation token for local runs (e.g. Ctrl+C)
    let shutdown_token = tokio_util::sync::CancellationToken::new();
    let t = shutdown_token.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            t.cancel();
        }
    });

    run_app(cli.command, shutdown_token).await
}

async fn run_app(
    command: Commands,
    shutdown_token: tokio_util::sync::CancellationToken,
) -> anyhow::Result<()> {
    match command {
        Commands::Start {
            bind,
            port,
            upstream,
            local,
            verbose,
        } => {
            let file_config = config::load_config()?;

            let upstream_url = if local {
                let ollama_url = "http://127.0.0.1:11434/v1";
                banner::print_step("Checking local Ollama status...");
                if TcpStream::connect_timeout(
                    &std::net::SocketAddr::from(([127, 0, 0, 1], 11434)),
                    Duration::from_secs(1),
                )
                .is_err()
                {
                    banner::print_warning("Local AI (Ollama) not detected on port 11434.");
                } else {
                    banner::print_success("Ollama detected.");
                }
                ollama_url.to_string()
            } else {
                upstream
                    .or(file_config
                        .server
                        .as_ref()
                        .and_then(|s| s.default_upstream.clone()))
                    .unwrap_or_else(|| "http://127.0.0.1:11434/v1".to_string())
            };

            let port = port
                .or(file_config.server.as_ref().and_then(|s| s.port))
                .unwrap_or(8080);

            let bind_address = bind
                .or(file_config
                    .server
                    .as_ref()
                    .and_then(|s| s.bind_address.clone()))
                .unwrap_or_else(|| "127.0.0.1".to_string());

            let timeout_seconds = 300;

            let routes = file_config.routes.clone().unwrap_or_default();

            let audit_log_path = file_config
                .security
                .as_ref()
                .and_then(|s| s.audit_log_path.clone());
            let requests_per_minute = file_config
                .server
                .as_ref()
                .and_then(|s| s.requests_per_minute);
            let dlp_config = file_config
                .security
                .as_ref()
                .and_then(|s| s.dlp.clone())
                .unwrap_or_default();

            let config = ServerConfig {
                bind_address,
                port,
                default_upstream: upstream_url,
                routes,
                audit_log_path,
                requests_per_minute,
                timeout_seconds,
                verbose,
                dlp_config,
                load_balancer: file_config.load_balancer,
                security: file_config.security.clone(),
                vault: file_config.vault,
            };

            tracing::info!("Server starting on {}:{}", config.bind_address, port);
            server::start_server(config, shutdown_token).await?;
        }
        Commands::Audit { path } => {
            audit::run_audit(&path)?;
        }
        Commands::Bench {
            corpus,
            rules,
            gate,
            docs,
            json,
        } => {
            bench::run(&bench::BenchOptions {
                corpus_dir: corpus,
                rules_file: rules,
                gate,
                docs_path: docs,
                json_path: json,
            })
            .await?;
        }
        Commands::Sign { rules_dir } => {
            let rules_dir = config::resolve_resource_path(rules_dir);
            let key = std::env::var("GUARDIAN_HMAC_KEY")
                .map_err(|_| anyhow::anyhow!("GUARDIAN_HMAC_KEY must be set to sign rules"))?;
            if key.is_empty() {
                return Err(anyhow::anyhow!(
                    "GUARDIAN_HMAC_KEY cannot be empty when signing rules"
                ));
            }

            banner::print_step(&format!("Signing rules in {}/...", rules_dir.display()));

            let checker =
                crate::security::integrity::RuleIntegrityChecker::new(&rules_dir, &key)
                    .map_err(|e| anyhow::anyhow!("Failed to initialize integrity checker: {e}"))?;

            checker
                .save_manifest()
                .map_err(|e| anyhow::anyhow!("Failed to save manifest: {e}"))?;

            banner::print_success(
                "Rules signed successfully. Manifest generated (.manifest.json).",
            );
        }
        Commands::Service { action } => {
            handle_service_command(action)?;
        }
        #[cfg(feature = "native-keyring")]
        Commands::Secret { action } => {
            handle_secret_command(action).await?;
        }
        Commands::Broker { action } => match action {
            BrokerAction::Start => {
                broker::run_daemon(shutdown_token).await?;
            }
            BrokerAction::Request { action, reason } => {
                let client = broker::client::BrokerClient::admin()?;
                let created = client.request_action(&action, &reason).await?;
                banner::print_success(&format!(
                    "Request {} created ({}) — awaiting operator approval.",
                    created.request_id, created.status
                ));
                println!(
                    "  The operator sees: open-guardian approve {} --code <code>",
                    created.request_id
                );
            }
        },
        #[cfg(feature = "mcp")]
        Commands::Mcp => {
            // MCP stdio carries the protocol on stdout: status to stderr only.
            eprintln!("➜ Serving guardian MCP tools over stdio...");
            broker::mcp::run_stdio().await?;
        }
        Commands::Policy { action } => handle_policy_command(action)?,
        Commands::Approve { id, code, yes } => {
            handle_approve(id, code, yes).await?;
        }
        Commands::Deny { id } => {
            let client = broker::client::BrokerClient::admin()?;
            client.deny(&id).await?;
            banner::print_success(&format!("Request {id} denied."));
        }
        Commands::Requests => {
            let client = broker::client::BrokerClient::admin()?;
            let requests = client.list_requests().await?;
            if requests.is_empty() {
                banner::print_step("No broker requests.");
                return Ok(());
            }
            for entry in requests {
                let code = entry
                    .code
                    .as_deref()
                    .map(|code| format!("  code: {code}"))
                    .unwrap_or_default();
                println!(
                    "{}  {:<10}  {:<18}  {}{}",
                    entry.id, entry.status, entry.action_id, entry.reason, code
                );
            }
        }
        Commands::Verify { log } => match crate::security::verify_audit_chain(&log) {
            Ok(report) => {
                banner::print_success(&format!(
                    "Audit chain OK: {} events, tip {}",
                    report.lines,
                    &report.last_hash[..16.min(report.last_hash.len())]
                ));
            }
            Err(broken) => {
                return Err(anyhow::anyhow!(
                    "AUDIT CHAIN BROKEN at line {}: {}",
                    broken.line,
                    broken.reason
                ));
            }
        },
        Commands::McpGateway { rules, command } => {
            // MCP stdio carries the protocol on stdout: status goes to
            // stderr only, or the harness connection breaks.
            eprintln!("➜ MCP gateway up: {}", command.join(" "));
            let engine = context::build_engine(rules)?;
            let code = context::run_gateway(std::sync::Arc::new(engine), &command)?;
            std::process::exit(code);
        }
        Commands::Sanitize { file, rules } => {
            let engine = context::build_engine(rules)?;
            let bytes = match file {
                Some(path) => std::fs::read(path)?,
                None => {
                    let mut buffer = Vec::new();
                    std::io::Read::read_to_end(&mut std::io::stdin(), &mut buffer)?;
                    buffer
                }
            };
            let input = String::from_utf8_lossy(&bytes);
            let output = context::sanitize_text(&input, &engine);
            if output.contains(context::SUPPRESSED_BY_DLP) {
                // stdout stays pipe-clean; hooks consume it verbatim.
                eprintln!("⚠ output suppressed: potential obfuscated sensitive data detected");
            }
            print!("{output}");
        }
    }

    Ok(())
}

fn handle_policy_command(action: PolicyAction) -> anyhow::Result<()> {
    use broker::policy;

    match action {
        PolicyAction::Keygen { key } => {
            let key = config::resolve_resource_path(key);
            let verifying_key = policy::keygen(&key)?;
            banner::print_success(&format!(
                "Keypair generated for key id {}:\n  secret: {} (0600)\n  public: {}",
                policy::key_id(&verifying_key),
                key.display(),
                key.with_extension("pub").display()
            ));
            banner::print_warning(
                "Keep the secret key offline; pin the .pub in guardian.toml [broker].",
            );
        }
        PolicyAction::Sign {
            policy: policy_path,
            key,
        } => {
            let policy_path = config::resolve_resource_path(policy_path);
            let key = config::resolve_resource_path(key);
            let key_id = policy::sign_policy(&policy_path, &key)?;
            banner::print_success(&format!(
                "Signed {} (key id {}) → {}.sig",
                policy_path.display(),
                key_id,
                policy_path.display()
            ));
        }
        PolicyAction::Verify {
            policy: policy_path,
            public_key,
        } => {
            let policy_path = config::resolve_resource_path(policy_path);
            let public_key = config::resolve_resource_path(public_key);
            let loaded = policy::load_signed_policy(&policy_path, &public_key)?;
            banner::print_success(&format!(
                "Policy signature valid (fingerprint {}). {} action(s):",
                &loaded.fingerprint[..16.min(loaded.fingerprint.len())],
                loaded.actions.len()
            ));
            for action in &loaded.actions {
                let elevation = action
                    .user
                    .as_deref()
                    .map(|user| format!("  (as {user})"))
                    .unwrap_or_default();
                println!("  {:<24} {}{}", action.id, action.description, elevation);
            }
        }
        PolicyAction::Sudoers {
            policy: policy_path,
            public_key,
            user,
        } => {
            let policy_path = config::resolve_resource_path(policy_path);
            let public_key = config::resolve_resource_path(public_key);
            let loaded = policy::load_signed_policy(&policy_path, &public_key)?;
            let invoking_user = user
                .or_else(|| {
                    std::env::var("USER")
                        .ok()
                        .or_else(|| std::env::var("USERNAME").ok())
                })
                .unwrap_or_else(|| "guardian-broker".to_string());
            let lines = policy::sudoers_lines(&loaded, &invoking_user);
            if lines.is_empty() {
                banner::print_step("No elevated actions in this policy; no sudoers rules needed.");
                return Ok(());
            }
            println!("# /etc/sudoers.d/guardian-broker — install with: visudo -f /etc/sudoers.d/guardian-broker");
            for line in lines {
                println!("{line}");
            }
        }
    }
    Ok(())
}

async fn handle_approve(id: String, code: Option<String>, yes: bool) -> anyhow::Result<()> {
    use std::io::BufRead;

    let client = broker::client::BrokerClient::admin()?;
    let code = if yes {
        None
    } else {
        match code {
            Some(code) => Some(code),
            None => {
                print!("Approval code (see `open-guardian requests`): ");
                use std::io::Write;
                std::io::stdout().flush().ok();
                let mut line = String::new();
                std::io::stdin()
                    .lock()
                    .read_line(&mut line)
                    .map_err(|error| anyhow::anyhow!("cannot read approval code: {error}"))?;
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    return Err(anyhow::anyhow!("no code given; aborted"));
                }
                Some(trimmed.to_string())
            }
        }
    };

    client.approve(&id, code.as_deref(), yes).await?;
    banner::print_success(&format!("Request {id} approved; executing."));

    // Poll briefly so the operator sees the outcome inline.
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let status = match client.status(&id).await {
            Ok(status) => status,
            Err(_) => continue,
        };
        match status.status.as_str() {
            "executing" | "pending" => continue,
            "completed" => {
                if let Some(result) = status.result {
                    println!(
                        "  exit_code: {}",
                        result
                            .get("exit_code")
                            .map(|v| v.to_string())
                            .unwrap_or_default()
                    );
                    if let Some(error) = result.get("error").and_then(|v| v.as_str()) {
                        println!("  error:     {error}");
                    }
                    if let Some(stdout) = result.get("stdout").and_then(|v| v.as_str()) {
                        if !stdout.is_empty() {
                            println!("  stdout:    {stdout}");
                        }
                    }
                    if let Some(stderr) = result.get("stderr").and_then(|v| v.as_str()) {
                        if !stderr.is_empty() {
                            println!("  stderr:    {stderr}");
                        }
                    }
                    return Ok(());
                }
                // Result already consumed elsewhere (e.g. the agent polled it).
                println!("  completed (result was already delivered once).");
                return Ok(());
            }
            other => {
                banner::print_warning(&format!("Request {id} ended in state: {other}"));
                return Ok(());
            }
        }
    }
    banner::print_step("Still executing; check `open-guardian requests` later.");
    Ok(())
}
