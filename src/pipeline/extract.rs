//! JSON String Extraction for Security Scanning
//!
//! SECURITY FIX C2: Extract ALL user-controlled strings from request bodies,
//! not just `messages[*].content` for user/system roles.
//!
//! Scans:
//! - `/messages/*/content` (ALL roles: user, system, assistant, tool, function)
//! - `/prompt` (for /v1/completions)
//! - `/input` (for /v1/embeddings)
//! - `/tool_calls/*/function/arguments` (JSON strings in tool call args)
//! - `/instructions` (some API variants)
//!
//! This prevents attackers from hiding malicious content in assistant messages,
//! tool results, or other fields that were previously unscanned.

use serde_json::Value;
use std::collections::VecDeque;

/// Represents a string extracted from JSON with its location and context.
#[derive(Debug, Clone)]
pub struct ScanTarget {
    /// JSON pointer path (e.g., "/messages/3/content")
    pub json_pointer: String,
    /// The role of the message if applicable (user, system, assistant, tool, function)
    pub role: Option<String>,
    /// The kind of field this string came from
    pub kind: TargetKind,
    /// The exact string from JSON
    pub raw: String,
}

/// Categories of extracted strings for context-aware scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    /// Content field in messages array
    MessageContent,
    /// Prompt field (completions endpoint)
    Prompt,
    /// Input field (embeddings endpoint)
    Input,
    /// Tool call function arguments
    ToolArguments,
    /// Instructions field
    Instructions,
    /// Other string field
    UnknownString,
}

/// Extracts all scannable strings from a JSON request body.
///
/// # Security
/// This function MUST extract strings from ALL user-controlled fields.
/// Missing a field means a potential bypass vector.
pub fn extract_scan_targets(body: &Value) -> Vec<ScanTarget> {
    let mut targets = Vec::new();
    let mut queue: VecDeque<(String, &Value)> = VecDeque::new();
    queue.push_back(("".to_string(), body));

    while let Some((pointer, value)) = queue.pop_front() {
        match value {
            Value::Object(map) => {
                // Check for known high-value fields
                if let Some(content) = map.get("content") {
                    extract_content_strings(&pointer, content, map.get("role"), &mut targets);
                }

                // Check for prompt field (completions endpoint)
                if let Some(prompt) = map.get("prompt") {
                    extract_string_or_array(
                        &format!("{}/prompt", pointer),
                        prompt,
                        TargetKind::Prompt,
                        &mut targets,
                    );
                }

                // Check for input field (embeddings endpoint)
                if let Some(input) = map.get("input") {
                    extract_string_or_array(
                        &format!("{}/input", pointer),
                        input,
                        TargetKind::Input,
                        &mut targets,
                    );
                }

                // Check for instructions field
                if let Some(instructions) = map.get("instructions") {
                    extract_string_value(
                        &format!("{}/instructions", pointer),
                        instructions,
                        TargetKind::Instructions,
                        &mut targets,
                    );
                }

                // Check for tool_calls array
                if let Some(tool_calls) = map.get("tool_calls") {
                    extract_tool_calls(&pointer, tool_calls, &mut targets);
                }

                // Recurse into all object fields
                for (key, val) in map {
                    let child_pointer = format!("{}/{}", pointer, escape_json_pointer(key));
                    queue.push_back((child_pointer, val));
                }
            }
            Value::Array(arr) => {
                for (idx, val) in arr.iter().enumerate() {
                    let child_pointer = format!("{}/{}", pointer, idx);
                    queue.push_back((child_pointer, val));
                }
            }
            _ => {}
        }
    }

    targets
}

/// Extracts strings from a content field (may be string or array of content parts).
fn extract_content_strings(
    pointer: &str,
    content: &Value,
    role: Option<&Value>,
    targets: &mut Vec<ScanTarget>,
) {
    let role_str = role.and_then(|r| r.as_str()).map(String::from);

    match content {
        Value::String(s) => {
            targets.push(ScanTarget {
                json_pointer: format!("{}/content", pointer),
                role: role_str,
                kind: TargetKind::MessageContent,
                raw: s.clone(),
            });
        }
        Value::Array(parts) => {
            // Content parts: [{"type": "text", "text": "..."}, ...]
            for (idx, part) in parts.iter().enumerate() {
                if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                    targets.push(ScanTarget {
                        json_pointer: format!("{}/content/{}/text", pointer, idx),
                        role: role_str.clone(),
                        kind: TargetKind::MessageContent,
                        raw: text.to_string(),
                    });
                }
            }
        }
        _ => {}
    }
}

/// Extracts strings from a field that may be a string or array of strings.
fn extract_string_or_array(
    pointer: &str,
    value: &Value,
    kind: TargetKind,
    targets: &mut Vec<ScanTarget>,
) {
    match value {
        Value::String(s) => {
            targets.push(ScanTarget {
                json_pointer: pointer.to_string(),
                role: None,
                kind,
                raw: s.clone(),
            });
        }
        Value::Array(arr) => {
            for (idx, val) in arr.iter().enumerate() {
                if let Some(s) = val.as_str() {
                    targets.push(ScanTarget {
                        json_pointer: format!("{}/{}", pointer, idx),
                        role: None,
                        kind,
                        raw: s.to_string(),
                    });
                }
            }
        }
        _ => {}
    }
}

/// Extracts a single string value.
fn extract_string_value(
    pointer: &str,
    value: &Value,
    kind: TargetKind,
    targets: &mut Vec<ScanTarget>,
) {
    if let Some(s) = value.as_str() {
        targets.push(ScanTarget {
            json_pointer: pointer.to_string(),
            role: None,
            kind,
            raw: s.to_string(),
        });
    }
}

/// Extracts strings from tool_calls array.
fn extract_tool_calls(pointer: &str, tool_calls: &Value, targets: &mut Vec<ScanTarget>) {
    if let Value::Array(calls) = tool_calls {
        for (idx, call) in calls.iter().enumerate() {
            // Extract function.arguments which is typically a JSON string
            if let Some(args) = call.get("function").and_then(|f| f.get("arguments")) {
                if let Some(args_str) = args.as_str() {
                    targets.push(ScanTarget {
                        json_pointer: format!("{}/tool_calls/{}/function/arguments", pointer, idx),
                        role: Some("tool".to_string()),
                        kind: TargetKind::ToolArguments,
                        raw: args_str.to_string(),
                    });
                }
            }
        }
    }
}

/// Escapes special characters in JSON pointer paths.
fn escape_json_pointer(s: &str) -> String {
    s.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extract_messages_all_roles() {
        let body = json!({
            "messages": [
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi there!"},
                {"role": "tool", "content": "Tool result with secret"},
            ]
        });

        let targets = extract_scan_targets(&body);

        // Should extract ALL message contents, not just user
        assert!(targets
            .iter()
            .any(|t| t.raw == "Hello" && t.role == Some("user".into())));
        assert!(targets
            .iter()
            .any(|t| t.raw == "Hi there!" && t.role == Some("assistant".into())));
        assert!(targets
            .iter()
            .any(|t| t.raw == "Tool result with secret" && t.role == Some("tool".into())));

        // Should have at least 3 targets
        assert!(targets.len() >= 3);
    }

    #[test]
    fn test_extract_prompt_field() {
        let body = json!({
            "prompt": "Complete this sentence"
        });

        let targets = extract_scan_targets(&body);
        assert!(targets
            .iter()
            .any(|t| t.kind == TargetKind::Prompt && t.raw == "Complete this sentence"));
    }

    #[test]
    fn test_extract_input_field() {
        let body = json!({
            "input": "Embed this text"
        });

        let targets = extract_scan_targets(&body);
        assert!(targets
            .iter()
            .any(|t| t.kind == TargetKind::Input && t.raw == "Embed this text"));
    }

    #[test]
    fn test_extract_tool_calls() {
        let body = json!({
            "messages": [
                {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [
                        {
                            "function": {
                                "name": "get_weather",
                                "arguments": "{\"location\": \"secret base\"}"
                            }
                        }
                    ]
                }
            ]
        });

        let targets = extract_scan_targets(&body);
        assert!(targets
            .iter()
            .any(|t| t.kind == TargetKind::ToolArguments && t.raw.contains("secret base")));
    }

    #[test]
    fn test_content_parts() {
        let body = json!({
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Hello"},
                        {"type": "image_url", "image_url": {"url": "http://example.com/image.png"}}
                    ]
                }
            ]
        });

        let targets = extract_scan_targets(&body);
        assert!(targets.iter().any(|t| t.raw == "Hello"));
    }
}
