//! Loopback IPC client shared by the operator CLI and the MCP server.

use super::ipc;
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;

#[derive(Clone)]
pub struct BrokerClient {
    base: String,
    token: String,
    http: reqwest::Client,
}

/// Only consumed by the MCP server (`open-guardian mcp`).
#[cfg_attr(not(feature = "mcp"), allow(dead_code))]
#[derive(Debug, Deserialize)]
pub struct ActionSummary {
    pub id: String,
    pub description: String,
    pub requires_elevation: bool,
}

#[cfg_attr(not(feature = "mcp"), allow(dead_code))]
#[derive(Debug, Deserialize)]
pub struct RequestCreated {
    pub request_id: String,
    pub status: String,
    #[serde(default)]
    pub expires_in_secs: Option<u64>,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RequestEntry {
    pub id: String,
    pub action_id: String,
    #[serde(default)]
    pub reason: String,
    pub status: String,
    #[serde(default)]
    pub code: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // reason/message/error exist for API completeness and CLI/MCP evolution
pub struct StatusReport {
    pub request_id: String,
    pub action_id: String,
    #[serde(default)]
    pub reason: String,
    pub status: String,
    #[serde(default)]
    pub result: Option<Value>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

impl BrokerClient {
    pub fn new(addr: &str, token: &str) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .context("cannot build broker client")?;
        Ok(Self {
            base: format!("http://{addr}"),
            token: token.to_string(),
            http,
        })
    }

    /// Operator channel: full power (approve/deny/list).
    pub fn admin() -> Result<Self> {
        if let (Ok(addr), Ok(token)) = (
            std::env::var("GUARDIAN_BROKER_URL"),
            std::env::var("GUARDIAN_BROKER_TOKEN"),
        ) {
            return Self::new(&addr, &token);
        }
        let (addr, token) = ipc::read_discovery(ipc::ADMIN_DISCOVERY_FILE)?;
        Self::new(&addr, &token)
    }

    /// Agent channel: request + status only.
    #[cfg_attr(not(feature = "mcp"), allow(dead_code))]
    pub fn agent() -> Result<Self> {
        if let (Ok(addr), Ok(token)) = (
            std::env::var("GUARDIAN_BROKER_URL"),
            std::env::var("GUARDIAN_BROKER_AGENT_TOKEN"),
        ) {
            return Self::new(&addr, &token);
        }
        let (addr, token) = ipc::read_discovery(ipc::AGENT_DISCOVERY_FILE)?;
        Self::new(&addr, &token)
    }

    async fn post<T: for<'de> Deserialize<'de>>(&self, path: &str, body: Value) -> Result<T> {
        let response = self
            .http
            .post(format!("{}{path}", self.base))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("broker request {path} failed"))?;
        let status = response.status();
        let payload: Value = response
            .json()
            .await
            .context("broker returned a malformed response")?;
        if !status.is_success() {
            let detail = payload
                .get("message")
                .or_else(|| payload.get("error"))
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            anyhow::bail!("broker: {detail} (HTTP {})", status.as_u16());
        }
        serde_json::from_value(payload)
            .with_context(|| format!("broker response for {path} did not match the expected shape"))
    }

    #[cfg_attr(not(feature = "mcp"), allow(dead_code))]
    pub async fn list_actions(&self) -> Result<Vec<ActionSummary>> {
        #[derive(Deserialize)]
        struct ActionsResponse {
            actions: Vec<ActionSummary>,
        }
        let response: ActionsResponse = self.post("/v1/actions", Value::Null).await?;
        Ok(response.actions)
    }

    pub async fn request_action(&self, action_id: &str, reason: &str) -> Result<RequestCreated> {
        self.post(
            "/v1/request",
            serde_json::json!({ "action_id": action_id, "reason": reason }),
        )
        .await
    }

    pub async fn approve(&self, request_id: &str, code: Option<&str>, yes: bool) -> Result<Value> {
        self.post(
            "/v1/approve",
            serde_json::json!({ "request_id": request_id, "code": code, "yes": yes }),
        )
        .await
    }

    pub async fn deny(&self, request_id: &str) -> Result<Value> {
        self.post("/v1/deny", serde_json::json!({ "request_id": request_id }))
            .await
    }

    pub async fn status(&self, request_id: &str) -> Result<StatusReport> {
        self.post(
            "/v1/status",
            serde_json::json!({ "request_id": request_id }),
        )
        .await
    }

    pub async fn list_requests(&self) -> Result<Vec<RequestEntry>> {
        #[derive(Deserialize)]
        struct RequestsResponse {
            requests: Vec<RequestEntry>,
        }
        let response: RequestsResponse = self.post("/v1/requests", Value::Null).await?;
        Ok(response.requests)
    }
}
