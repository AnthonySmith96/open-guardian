mod audit;
mod banner;
mod config;
mod logger;
mod pipeline;
mod proxy;
mod router;
mod security;
mod server;

use crate::server::ServerConfig;
use clap::{Parser, Subcommand};
use service_manager::*;
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

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
#[command(about = "The Shield for the Age of AI Agents", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Open-GuardIAn Proxy (The Shield)
    Start {
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
    /// Service management (Install, Uninstall, Start, Stop)
    Service {
        #[command(subcommand)]
        action: ServiceAction,
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
    let label: ServiceLabel = "com.openguardian.shield".parse().unwrap();
    let manager = <dyn ServiceManager>::native()
        .map_err(|e| anyhow::anyhow!("Failed to detect service manager: {}", e))?;

    match action {
        ServiceAction::Install => {
            let exe_path = std::env::current_exe()?;
            banner::print_step(&format!("Installing service {}...", label));

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
                .map_err(|e| anyhow::anyhow!("Installation failed: {}", e))?;

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
            banner::print_step(&format!("Uninstalling service {}...", label));
            manager
                .uninstall(ServiceUninstallCtx {
                    label: label.clone(),
                })
                .map_err(|e| anyhow::anyhow!("Uninstallation failed: {}", e))?;
            banner::print_success("Service uninstalled successfully.");
        }
        ServiceAction::Start => {
            banner::print_step(&format!("Starting service {}...", label));
            manager
                .start(ServiceStartCtx {
                    label: label.clone(),
                })
                .map_err(|e| anyhow::anyhow!("Failed to start service: {}", e))?;
            banner::print_success("Service started.");
        }
        ServiceAction::Stop => {
            banner::print_step(&format!("Stopping service {}...", label));
            manager
                .stop(ServiceStopCtx {
                    label: label.clone(),
                })
                .map_err(|e| anyhow::anyhow!("Failed to stop service: {}", e))?;
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
        if std::env::args().any(|arg| arg == "start") && !atty::is(atty::Stream::Stdout) {
            tracing::info!("Starting as Windows Service...");
            return service_dispatcher::start("com.openguardian.shield", ffi_service_main)
                .map_err(|e| anyhow::anyhow!("Service dispatcher failed: {}", e));
        }
    }

    let cli = Cli::parse();
    banner::print_banner();

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
            port,
            upstream,
            local,
            verbose,
        } => {
            let file_config = config::load_config();

            let upstream_url = if local {
                let ollama_url = "http://127.0.0.1:11434/v1";
                banner::print_step("Checking local Ollama status...");
                if TcpStream::connect_timeout(
                    &"127.0.0.1:11434".parse().unwrap(),
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
                    .unwrap_or_else(|| "https://api.openai.com/v1".to_string())
            };

            let port = port
                .or(file_config.server.as_ref().and_then(|s| s.port))
                .unwrap_or(8080);

            let timeout_seconds = 300;

            let routes = file_config.routes.clone().unwrap_or_default();

            let judge_config = file_config.judge.clone().unwrap_or_default();
            let audit_log_path = file_config
                .security
                .as_ref()
                .and_then(|s| s.audit_log_path.clone());
            let block_threshold = file_config
                .security
                .as_ref()
                .and_then(|s| s.block_threshold);
            let requests_per_minute = file_config
                .server
                .as_ref()
                .and_then(|s| s.requests_per_minute);
            let policies = file_config
                .security
                .as_ref()
                .and_then(|s| s.policies.clone())
                .unwrap_or_default();

            let dlp_config = file_config
                .security
                .as_ref()
                .and_then(|s| s.dlp.clone())
                .unwrap_or_default();

            let config = ServerConfig {
                port,
                default_upstream: upstream_url,
                routes,
                judge_config,
                audit_log_path,
                block_threshold,
                requests_per_minute,
                timeout_seconds,
                verbose,
                policies,
                dlp_config,
                load_balancer: file_config.load_balancer,
                security: file_config.security.clone(),
            };

            tracing::info!("Server starting on port {}", port);
            server::start_server(config, shutdown_token).await?;
        }
        Commands::Audit { path } => {
            audit::run_audit(&path)?;
        }
        Commands::Sign { rules_dir } => {
            let key = std::env::var("GUARDIAN_HMAC_KEY")
                .expect("FATAL: GUARDIAN_HMAC_KEY must be set in environment to sign rules");

            banner::print_step(&format!("Signing rules in {}/...", rules_dir));

            let checker =
                crate::security::integrity::RuleIntegrityChecker::new(&rules_dir, &key, false)
                    .map_err(|e| {
                        anyhow::anyhow!("Failed to initialize integrity checker: {}", e)
                    })?;

            checker
                .save_manifest()
                .map_err(|e| anyhow::anyhow!("Failed to save manifest: {}", e))?;

            banner::print_success(
                "Rules signed successfully. Manifest generated (.manifest.json).",
            );
        }
        Commands::Service { action } => {
            handle_service_command(action)?;
        }
    }

    Ok(())
}
