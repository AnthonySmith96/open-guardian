//! Action Broker (v0.5): privileged actions for AI agents behind signed
//! policies, out-of-band human approval, hash-chained audit, and output DLP.
//!
//! The daemon (`open-guardian broker start`) is the single authority: it loads
//! the signed policy, owns the request state machine, executes commands
//! without a shell, resolves secrets only inside the child's environment, and
//! scans captured output with the same DLP engine the egress proxy uses.
//!
//! Two frontends talk to it over loopback HTTP with separate bearer tokens:
//! the MCP stdio server (agent channel: request + status only) and the
//! operator CLI (approve/deny/list — the only channel that sees approval
//! codes).

pub mod client;
pub mod execute;
pub mod ipc;
pub mod policy;
pub mod state;

#[cfg(feature = "mcp")]
pub mod mcp;

use crate::config;
use crate::security::{AuditChain, DlpEngine};
use std::sync::Arc;
use std::time::Duration;

/// Loads config, verifies the signed policy, wires DLP + secrets + audit,
/// and serves the daemon until shutdown. Every failure is fatal by design.
pub async fn run_daemon(shutdown_token: tokio_util::sync::CancellationToken) -> anyhow::Result<()> {
    let file_config = config::load_config()?;
    let broker_cfg = file_config.broker.clone().unwrap_or_default();

    let policy_path =
        config::resolve_resource_path(broker_cfg.policy.as_deref().ok_or_else(|| {
            anyhow::anyhow!("[broker] policy = \"broker/policy.toml\" is required in guardian.toml")
        })?);
    let public_key_path =
        config::resolve_resource_path(broker_cfg.public_key.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "[broker] public_key = \"broker/policy.pub\" is required in guardian.toml"
            )
        })?);
    let policy = policy::load_signed_policy(&policy_path, &public_key_path)?;

    // The broker runs privileged commands; unlike the proxy it refuses to
    // start if the DLP rules are missing rather than continuing with the
    // built-in PII detectors alone.
    let dlp_config = file_config
        .security
        .as_ref()
        .and_then(|security| security.dlp.clone())
        .unwrap_or_default();
    if let Some(first) = dlp_config.rules_files.first() {
        let rules_path = config::resolve_resource_path(first);
        if !rules_path.exists() {
            anyhow::bail!(
                "broker refuses to start: DLP rules file {} not found",
                rules_path.display()
            );
        }
    }
    let dlp_engine =
        DlpEngine::build(&dlp_config).map_err(|error| anyhow::anyhow!("DLP engine: {error}"))?;

    let secret_broker =
        Arc::new(crate::server::assemble_secret_broker(file_config.vault.as_ref()).await?);

    let audit_path = broker_cfg
        .audit_log_path
        .clone()
        .unwrap_or_else(|| "guardian_broker_audit.jsonl".to_string());
    let (audit, _writer) = AuditChain::open(config::resolve_resource_path(&audit_path))?;

    let options = ipc::DaemonOptions::new(
        policy,
        secret_broker,
        Arc::new(dlp_engine),
        audit,
        Duration::from_secs(broker_cfg.pending_ttl_secs.unwrap_or(120)),
        Duration::from_secs(broker_cfg.result_ttl_secs.unwrap_or(300)),
    );

    ipc::start(options, shutdown_token).await?;
    Ok(())
}
