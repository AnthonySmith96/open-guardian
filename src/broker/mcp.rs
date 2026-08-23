//! MCP stdio surface for AI agent harnesses (Claude Code, Cursor, Goose, …).
//!
//! Three tools, all agent-channel only: the MCP client can list actions,
//! request one, and poll its status. Approval codes and admin operations
//! never cross this boundary by construction.

use super::client::{BrokerClient, StatusReport};
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::ErrorCode;
use rmcp::tool;
use rmcp::tool_handler;
use rmcp::tool_router;
use rmcp::transport::stdio;
use rmcp::ServerHandler;
use rmcp::ServiceExt;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone)]
pub struct GuardianTools {
    client: BrokerClient,
}

#[derive(Deserialize, JsonSchema)]
struct RequestActionParams {
    /// Action id as returned by guardian_list_actions.
    action_id: String,
    /// Short human-readable justification for the operator.
    #[serde(default)]
    reason: String,
}

#[derive(Serialize, JsonSchema)]
struct RequestCreatedOut {
    request_id: String,
    status: String,
    expires_in_secs: Option<u64>,
    message: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct StatusParams {
    request_id: String,
}

#[derive(Serialize, JsonSchema)]
struct StatusOut {
    request_id: String,
    action_id: String,
    status: String,
    /// Present exactly once, on the first successful poll after completion.
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[derive(Serialize, JsonSchema)]
struct ActionsOut {
    actions: Vec<ActionSummaryOut>,
}

#[derive(Serialize, JsonSchema)]
struct ActionSummaryOut {
    id: String,
    description: String,
    requires_elevation: bool,
}

fn internal(message: impl Into<String>) -> rmcp::ErrorData {
    rmcp::ErrorData::new(
        ErrorCode::INTERNAL_ERROR,
        format!("guardian broker: {}", message.into()),
        None,
    )
}

fn invalid(message: impl Into<String>) -> rmcp::ErrorData {
    rmcp::ErrorData::new(
        ErrorCode::INVALID_PARAMS,
        format!("guardian broker: {}", message.into()),
        None,
    )
}

#[tool_router]
impl GuardianTools {
    pub fn new(client: BrokerClient) -> Self {
        Self { client }
    }

    #[tool(
        name = "guardian_list_actions",
        description = "List the privileged actions the operator's signed policy allows this agent to request."
    )]
    async fn list_actions(&self) -> Result<Json<ActionsOut>, rmcp::ErrorData> {
        let actions = self
            .client
            .list_actions()
            .await
            .map_err(|error| internal(error.to_string()))?;
        Ok(Json(ActionsOut {
            actions: actions
                .into_iter()
                .map(|action| ActionSummaryOut {
                    id: action.id,
                    description: action.description,
                    requires_elevation: action.requires_elevation,
                })
                .collect(),
        }))
    }

    #[tool(
        name = "guardian_request_action",
        description = "Request a privileged action. A human operator must approve it out-of-band before it executes. Poll guardian_request_status afterwards."
    )]
    async fn request_action(
        &self,
        Parameters(params): Parameters<RequestActionParams>,
    ) -> Result<Json<RequestCreatedOut>, rmcp::ErrorData> {
        let created = self
            .client
            .request_action(&params.action_id, &params.reason)
            .await
            .map_err(|error| {
                // Unknown actions are client mistakes, not broker failures.
                if error.to_string().contains("unknown_action") {
                    invalid(error.to_string())
                } else {
                    internal(error.to_string())
                }
            })?;
        Ok(Json(RequestCreatedOut {
            request_id: created.request_id,
            status: created.status,
            expires_in_secs: created.expires_in_secs,
            message: created.message,
        }))
    }

    #[tool(
        name = "guardian_request_status",
        description = "Poll an action request. On the first poll after execution finishes, includes the (DLP-sanitized) result; it is delivered exactly once."
    )]
    async fn request_status(
        &self,
        Parameters(params): Parameters<StatusParams>,
    ) -> Result<Json<StatusOut>, rmcp::ErrorData> {
        let status: StatusReport =
            self.client
                .status(&params.request_id)
                .await
                .map_err(|error| {
                    if error.to_string().contains("unknown_request") {
                        invalid(error.to_string())
                    } else {
                        internal(error.to_string())
                    }
                })?;
        Ok(Json(StatusOut {
            request_id: status.request_id,
            action_id: status.action_id,
            status: status.status,
            result: status.result,
            note: status.note,
        }))
    }
}

#[tool_handler(
    name = "open-guardian",
    version = "0.5.0",
    instructions = "Request privileged actions behind the operator's signed policy. Approval is always out-of-band; poll guardian_request_status for results."
)]
impl ServerHandler for GuardianTools {}

/// Serves the MCP tools over stdio until the client disconnects.
pub async fn run_stdio() -> anyhow::Result<()> {
    let client = BrokerClient::agent().map_err(|error| {
        anyhow::anyhow!(
            "cannot reach the broker daemon: {error} (start it with `open-guardian broker start`)"
        )
    })?;
    let service = GuardianTools::new(client)
        .serve(stdio())
        .await
        .map_err(|error| anyhow::anyhow!("MCP stdio transport failed: {error}"))?;
    service
        .waiting()
        .await
        .map_err(|error| anyhow::anyhow!("MCP service terminated: {error}"))?;
    Ok(())
}
