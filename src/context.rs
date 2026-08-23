//! Context DLP (v0.6): the same DLP engine that guards egress, applied to
//! tool output *before* it enters the model's context.
//!
//! Two surfaces:
//! - `open-guardian mcp-gateway -- <command>`: wraps any MCP stdio server and
//!   rewrites every tool result (the JSON-RPC `CallToolResult` shape) on its
//!   way up to the harness. Requests, notifications, and every other result
//!   shape pass through untouched.
//! - `open-guardian sanitize`: stdin → stdout through the engine, for harness
//!   hooks and shell pipelines.
//!
//! Sanitization is the broker's output rule, shared verbatim: irreversible
//! redaction of secrets/PII, then an obfuscation probe — text that still
//! trips detection after normalization suppresses entirely.

use crate::security::{normalize_for_matching, DlpEngine};
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;

pub const SUPPRESSED_BY_DLP: &str =
    "[output suppressed: potential obfuscated sensitive data detected]";

/// Redacts secrets/PII irreversibly; text that still trips detection once
/// normalized (obfuscation) suppresses entirely instead of leaking.
pub fn sanitize_text(text: &str, engine: &DlpEngine) -> String {
    let redacted = engine.redact_permanent(text);
    if engine
        .check_violations(&normalize_for_matching(&redacted))
        .is_some()
    {
        return SUPPRESSED_BY_DLP.to_string();
    }
    redacted
}

/// Builds the DLP engine for the context surface. Rule files load or the
/// command fails — same fail-closed contract as the proxy and the broker.
/// `--rules` swaps in a single file (gitleaks format), like `bench`.
pub fn build_engine(rules: Option<PathBuf>) -> anyhow::Result<DlpEngine> {
    let file_config = crate::config::load_config()?;
    let mut config = file_config
        .security
        .and_then(|security| security.dlp)
        .unwrap_or_default();
    if let Some(rules) = rules {
        config.rules_files = vec![rules.display().to_string()];
    }
    DlpEngine::build(&config).map_err(|error| anyhow::anyhow!("DLP engine: {error}"))
}

/// A JSON-RPC message is a tool result iff it is a response whose `result`
/// carries a `content` array — the CallToolResult shape. The other result
/// shapes (`tools`, `contents`, `messages`) never carry tool output.
fn is_tool_result(message: &Value) -> bool {
    message
        .get("result")
        .and_then(|result| result.get("content"))
        .is_some_and(|content| content.is_array())
}

/// Redacts every string in the tree in place. Numbers are probed too (a
/// bare-digit Luhn card serializes as a JSON number) and replaced with their
/// redacted form when redaction changes them.
fn redact_tree(value: &mut Value, engine: &DlpEngine) {
    match value {
        Value::String(text) => *text = engine.redact_permanent(text),
        Value::Number(number) => {
            let raw = number.to_string();
            let redacted = engine.redact_permanent(&raw);
            if redacted != raw {
                *value = Value::String(redacted);
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_tree(item, engine);
            }
        }
        Value::Object(fields) => {
            for (_, item) in fields {
                redact_tree(item, engine);
            }
        }
        _ => {}
    }
}

/// Sanitizes one newline-delimited JSON-RPC message. Lines that are not a
/// tool result (requests, notifications, other responses, non-JSON) come
/// back verbatim; modified messages come back re-serialized.
pub fn sanitize_rpc_line(line: &str, engine: &DlpEngine) -> String {
    let Ok(mut message) = serde_json::from_str::<Value>(line) else {
        return line.to_string();
    };
    if !is_tool_result(&message) {
        return line.to_string();
    }
    let Some(result) = message.get_mut("result") else {
        return line.to_string();
    };

    redact_tree(result, engine);

    let probe = serde_json::to_string(result).unwrap_or_default();
    if engine
        .check_violations(&normalize_for_matching(&probe))
        .is_some()
    {
        // Obfuscated data survived redaction (encodings, homoglyphs); the
        // value cannot be rewritten in place, so the result is replaced.
        *result = json!({
            "content": [{ "type": "text", "text": SUPPRESSED_BY_DLP }]
        });
    }

    serde_json::to_string(&message).unwrap_or_else(|_| line.to_string())
}

/// Downstream → harness pump: sanitize every line of the wrapped server's
/// stdout. Ends at EOF, forwarding everything it saw.
pub(crate) fn pump_downstream<R: BufRead, W: Write>(
    mut reader: R,
    mut out: W,
    engine: &DlpEngine,
) -> std::io::Result<()> {
    let mut raw = Vec::new();
    loop {
        raw.clear();
        match reader.read_until(b'\n', &mut raw) {
            Ok(0) => break,
            Ok(_) => {
                let line = String::from_utf8_lossy(&raw);
                let trimmed = line.trim_end_matches(['\r', '\n']);
                if trimmed.is_empty() {
                    writeln!(out)?;
                } else {
                    writeln!(out, "{}", sanitize_rpc_line(trimmed, engine))?;
                }
                out.flush()?;
            }
            Err(_) => break,
        }
    }
    out.flush()
}

/// Harness → downstream pump: verbatim bytes, no parsing. EOF on the harness
/// side closes the downstream's stdin, ending the session.
pub(crate) fn pump_upstream<R: BufRead, W: Write>(
    mut reader: R,
    mut writer: W,
) -> std::io::Result<()> {
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        match reader.read_until(b'\n', &mut buffer) {
            Ok(0) => break,
            Ok(_) => {
                writer.write_all(&buffer)?;
                writer.flush()?;
            }
            Err(_) => break,
        }
    }
    writer.flush()
}

/// Runs `command` as a downstream MCP stdio server and pipes the harness
/// through it: harness → downstream verbatim, downstream → harness with every
/// tool result sanitized. Returns the downstream's exit code.
pub fn run_gateway(engine: Arc<DlpEngine>, command: &[String]) -> anyhow::Result<i32> {
    let mut child = std::process::Command::new(&command[0])
        .args(&command[1..])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| anyhow::anyhow!("failed to start {}: {error}", command[0]))?;

    let child_stdin = child.stdin.take().expect("piped stdin");
    let child_stdout = child.stdout.take().expect("piped stdout");

    let downstream = {
        let engine = Arc::clone(&engine);
        std::thread::spawn(move || {
            let reader = std::io::BufReader::new(child_stdout);
            let _ = pump_downstream(reader, std::io::stdout().lock(), &engine);
        })
    };

    // Deliberately not joined: this thread blocks on the harness's stdin
    // until the harness closes the session, which outlives the gateway.
    std::thread::spawn(move || {
        let reader = std::io::BufReader::new(std::io::stdin());
        let _ = pump_upstream(reader, child_stdin);
    });

    let status = child.wait()?;
    let _ = downstream.join();
    Ok(status.code().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DlpConfig;
    use std::io::Cursor;

    fn engine() -> DlpEngine {
        // The repo's shipped rules give the engine real secret patterns
        // (sk_live_*, gsk_*, etc.) alongside the built-in PII detectors.
        DlpEngine::build(&DlpConfig::default()).expect("engine with shipped rules")
    }

    #[test]
    fn plain_text_passes_unchanged() {
        let output = sanitize_text("deployment finished in 12s", &engine());
        assert_eq!(output, "deployment finished in 12s");
    }

    #[test]
    fn secrets_are_redacted_from_text() {
        let secret = "sk_live_Qw3Er5Ty7Ui9Op1As3DfGh";
        let output = sanitize_text(&format!("token={secret} ok"), &engine());
        assert!(!output.contains(secret), "leaked: {output}");
        assert!(output.contains("token="));
    }

    #[test]
    fn obfuscated_secret_suppresses_whole_text() {
        // Percent-encoded Groq key from the benchmark corpus: invisible to
        // plain redaction, caught by the normalization probe.
        let output = sanitize_text("use gsk_Qw3%45r5Ty7Ui9Op1As3DfGh please", &engine());
        assert_eq!(output, SUPPRESSED_BY_DLP);
    }

    fn tool_result_line(text: &str) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","id":7,"result":{{"content":[{{"type":"text","text":{}}}]}}}}"#,
            serde_json::json!(text)
        )
    }

    #[test]
    fn tool_result_text_is_sanitized() {
        let secret = "sk_live_Qw3Er5Ty7Ui9Op1As3DfGh";
        let line = tool_result_line(&format!("here is the key {secret} for deploy"));
        let output = sanitize_rpc_line(&line, &engine());
        assert!(!output.contains(secret), "leaked: {output}");
        let parsed: Value = serde_json::from_str(&output).expect("still valid JSON-RPC");
        let texts: Vec<&str> = parsed["result"]["content"]
            .as_array()
            .expect("content array kept")
            .iter()
            .filter_map(|item| item["text"].as_str())
            .collect();
        assert_eq!(texts.len(), 1);
        assert!(texts[0].contains("here is the key"));
    }

    #[test]
    fn nested_structured_content_is_sanitized() {
        let secret = "sk_live_Qw3Er5Ty7Ui9Op1As3DfGh";
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":3,"result":{{"content":[{{"type":"text","text":"done"}}],"structuredContent":{{"note":"env {secret}","nested":{{"deep":"mail a@b.com"}}}}}}}}"#
        );
        let output = sanitize_rpc_line(&line, &engine());
        assert!(!output.contains(secret), "leaked: {output}");
        assert!(!output.contains("a@b.com"), "PII leaked: {output}");
        assert!(output.contains("done"));
    }

    #[test]
    fn bare_number_secret_is_redacted() {
        let line = r#"{"jsonrpc":"2.0","id":4,"result":{"content":[{"type":"text","text":"card"}],"structuredContent":{"card":4111111111111111}}}"#;
        let output = sanitize_rpc_line(line, &engine());
        assert!(!output.contains("4111111111111111"), "leaked: {output}");
        let parsed: Value = serde_json::from_str(&output).expect("valid JSON");
        assert!(parsed["result"]["structuredContent"]["card"].is_string());
    }

    #[test]
    fn obfuscated_tool_result_is_replaced_with_notice() {
        let line = tool_result_line("run with gsk_Qw3%45r5Ty7Ui9Op1As3DfGh now");
        let output = sanitize_rpc_line(&line, &engine());
        let parsed: Value = serde_json::from_str(&output).expect("valid JSON");
        assert_eq!(parsed["result"]["content"][0]["text"], SUPPRESSED_BY_DLP);
    }

    #[test]
    fn non_tool_messages_pass_verbatim() {
        let engine = engine();
        let verbatim = [
            r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo","description":"echo text"}]}}"#,
            r#"{"jsonrpc":"2.0","id":2,"result":{"contents":[{"uri":"file:///a"}]}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"echo"}}"#,
            "not json at all",
        ];
        for line in verbatim {
            assert_eq!(sanitize_rpc_line(line, &engine), line);
        }
    }

    #[test]
    fn downstream_pump_sanitizes_only_tool_results() {
        let secret = "sk_live_Qw3Er5Ty7Ui9Op1As3DfGh";
        let input = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"protocolVersion\":\"2025-06-18\"}}}}\n\
             {tool}\n\
             not json\n",
            tool = tool_result_line(&format!("leak {secret}"))
        );
        let mut output = Vec::new();
        pump_downstream(Cursor::new(input.into_bytes()), &mut output, &engine()).expect("pump");
        let output = String::from_utf8(output).expect("utf8");
        let mut lines = output.lines();
        let init = lines.next().expect("line 1");
        assert!(init.contains("protocolVersion"));
        let tool = lines.next().expect("line 2");
        assert!(!tool.contains(secret), "leaked: {tool}");
        assert!(tool.contains("leak"), "kept the surrounding text");
        assert_eq!(lines.next(), Some("not json"));
        assert_eq!(lines.next(), None);
    }

    #[test]
    fn upstream_pump_forwards_bytes_verbatim() {
        let input = b"{\"id\":1}\n{\"id\":2}\ntrailing without newline";
        let mut output = Vec::new();
        pump_upstream(Cursor::new(input.to_vec()), &mut output).expect("pump");
        assert_eq!(output, input.to_vec());
    }
}
