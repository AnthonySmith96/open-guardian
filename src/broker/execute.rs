//! Command execution: argv exact, no shell, secrets only in the child's
//! environment, output DLP-sanitized before anyone reads it.

use super::policy::{ActionDef, OutputPolicy};
use super::state::ActionResult;
use crate::security::{normalize_for_matching, DlpEngine};
use open_guardian::secrets::SecretBroker;
use std::time::Instant;

/// Captured stdout/stderr are capped here before sanitization.
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

const SUPPRESSED_BY_POLICY: &str = "[output suppressed by policy]";
const SUPPRESSED_BY_DLP: &str = "[output suppressed: potential obfuscated sensitive data detected]";

/// Runs one allowlisted action and returns a fully sanitized result. This
/// function never returns Err: execution problems (missing binary, timeout,
/// unresolvable secret) become an `ActionResult` with `error` set, which is
/// safe to expose.
pub async fn execute_action(
    action: &ActionDef,
    secret_broker: &SecretBroker,
    dlp: &DlpEngine,
) -> ActionResult {
    let started = Instant::now();

    #[cfg(windows)]
    if action.user.is_some() {
        // A signed policy with a `user` target cannot be honored on Windows;
        // refuse rather than silently dropping the elevation boundary.
        return ActionResult {
            exit_code: None,
            duration_ms: 0,
            stdout: String::new(),
            stderr: String::new(),
            truncated: false,
            suppressed: false,
            error: Some(
                "action requires elevation via sudo, which is not available on Windows; nothing executed"
                    .into(),
            ),
        };
    }

    // Secrets resolve here and nowhere else — straight into the child's env.
    let mut command = build_command(action);
    for binding in &action.env {
        match secret_broker.resolve(&binding.reference).await {
            Ok(value) => {
                command.env(&binding.name, value.expose_secret());
            }
            Err(error) => {
                return ActionResult {
                    exit_code: None,
                    duration_ms: started.elapsed().as_millis() as u64,
                    stdout: String::new(),
                    stderr: String::new(),
                    truncated: false,
                    suppressed: false,
                    error: Some(format!(
                        "secret {} could not be resolved: {} (action refused, nothing executed)",
                        binding.name, error
                    )),
                };
            }
        }
    }

    let output = match tokio::time::timeout(
        std::time::Duration::from_secs(action.timeout_secs),
        command.output(),
    )
    .await
    {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            return ActionResult {
                exit_code: None,
                duration_ms: started.elapsed().as_millis() as u64,
                stdout: String::new(),
                stderr: String::new(),
                truncated: false,
                suppressed: false,
                error: Some(format!("failed to start {}: {error}", action.exec[0])),
            };
        }
        Err(_) => {
            return ActionResult {
                exit_code: None,
                duration_ms: started.elapsed().as_millis() as u64,
                stdout: String::new(),
                stderr: String::new(),
                truncated: false,
                suppressed: false,
                error: Some(format!(
                    "timed out after {}s (process killed)",
                    action.timeout_secs
                )),
            };
        }
    };

    let (stdout, stdout_truncated) = truncate(&String::from_utf8_lossy(&output.stdout));
    let (stderr, stderr_truncated) = truncate(&String::from_utf8_lossy(&output.stderr));

    ActionResult {
        exit_code: output.status.code(),
        duration_ms: started.elapsed().as_millis() as u64,
        stdout: sanitize(action.output, dlp, &stdout),
        stderr: sanitize(action.output, dlp, &stderr),
        truncated: stdout_truncated || stderr_truncated,
        suppressed: action.output == OutputPolicy::Suppress,
        error: None,
    }
}

fn build_command(action: &ActionDef) -> tokio::process::Command {
    #[cfg(unix)]
    if let Some(user) = &action.user {
        // Exact-argv sudoers rule: NOPASSWD, non-interactive, no shell.
        let mut sudo = tokio::process::Command::new("sudo");
        sudo.arg("-n").arg("-u").arg(user).arg("--");
        sudo.arg(&action.exec[0]).args(&action.exec[1..]);
        return sudo;
    }

    let mut command = tokio::process::Command::new(&action.exec[0]);
    command.args(&action.exec[1..]);
    command
}

/// Caps a captured stream, cutting on a char boundary.
fn truncate(text: &str) -> (String, bool) {
    if text.len() <= MAX_OUTPUT_BYTES {
        return (text.to_string(), false);
    }
    let mut cut = MAX_OUTPUT_BYTES;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    (text[..cut].to_string(), true)
}

/// Applies the policy's output rule plus the DLP pipeline: one-way redaction
/// of plain secrets/PII, then an obfuscation probe on the redacted text —
/// anything suspicious left after redaction suppresses the whole stream.
fn sanitize(policy: OutputPolicy, dlp: &DlpEngine, text: &str) -> String {
    if policy == OutputPolicy::Suppress {
        return SUPPRESSED_BY_POLICY.to_string();
    }
    let redacted = dlp.redact_permanent(text);
    if dlp
        .check_violations(&normalize_for_matching(&redacted))
        .is_some()
    {
        return SUPPRESSED_BY_DLP.to_string();
    }
    redacted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DlpConfig;
    use crate::security::DlpEngine;

    fn engine() -> DlpEngine {
        // The repo's shipped rules give the engine real secret patterns
        // (sk_live_*, etc.) alongside the built-in PII detectors.
        DlpEngine::build(&DlpConfig::default()).expect("engine with shipped rules")
    }

    fn action(exec: &[&str]) -> ActionDef {
        ActionDef {
            id: "test-action".into(),
            description: "test".into(),
            exec: exec.iter().map(|part| part.to_string()).collect(),
            user: None,
            timeout_secs: 10,
            output: OutputPolicy::Redact,
            env: vec![],
        }
    }

    fn secret_broker(value: &'static str) -> SecretBroker {
        struct Fixed(&'static str);
        use async_trait::async_trait;
        use open_guardian::secrets::{SecretBackend, SecretValue};
        #[async_trait]
        impl SecretBackend for Fixed {
            fn scheme(&self) -> &'static str {
                "test"
            }
            async fn resolve(
                &self,
                _reference: &open_guardian::secrets::SecretRef,
            ) -> Result<SecretValue, open_guardian::secrets::SecretError> {
                SecretValue::new(self.0.to_string())
            }
        }
        let mut broker = SecretBroker::new();
        broker.register(Fixed(value)).expect("register");
        broker
    }

    fn env_binding(name: &str, reference: &str) -> super::super::policy::EnvBinding {
        super::super::policy::EnvBinding {
            name: name.into(),
            reference: reference.parse().expect("ref"),
        }
    }

    #[tokio::test]
    async fn plain_output_is_returned_verbatim() {
        let result = execute_action(
            &action(&["/bin/echo", "hello world"]),
            &SecretBroker::new(),
            &engine(),
        )
        .await;
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.stdout.trim(), "hello world");
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn secret_printed_by_the_command_is_redacted() {
        // The secret comes from the env var the broker injected; the command
        // echoes it back. The agent-visible stdout must not contain it.
        let mut def = action(&["/bin/sh", "-c", "printf 'token=%s\\n' \"$DEPLOY_TOKEN\""]);
        def.env = vec![env_binding(
            "DEPLOY_TOKEN",
            "{{secret:test://prod/deploy#token}}",
        )];
        let secret = "sk_live_Qw3Er5Ty7Ui9Op1As3DfGh";

        let result = execute_action(&def, &secret_broker(secret), &engine()).await;
        assert_eq!(result.exit_code, Some(0));
        assert!(
            !result.stdout.contains(secret),
            "stdout leaked the secret: {}",
            result.stdout
        );
        assert!(result.stdout.contains("token="));
    }

    #[tokio::test]
    async fn pii_in_output_is_redacted() {
        let mut def = action(&["/bin/sh", "-c", "echo mail user@example.com done"]);
        def.env = vec![];
        let result = execute_action(&def, &SecretBroker::new(), &engine()).await;
        assert!(!result.stdout.contains("user@example.com"));
        assert!(result.stdout.contains("<EMAIL>") || result.stdout.contains("EMAIL"));
    }

    #[tokio::test]
    async fn obfuscated_secret_suppresses_the_whole_output() {
        // Percent-encoded secret: plain redaction cannot rewrite it in place,
        // so the probe must fail closed by suppressing everything.
        let mut def = action(&[
            "/bin/sh",
            "-c",
            "printf 'x %s y\\n' \"$(printf '%s' \"$DEPLOY_TOKEN\" | sed 's/Q/%51/g')\"",
        ]);
        def.env = vec![env_binding(
            "DEPLOY_TOKEN",
            "{{secret:test://prod/deploy#token}}",
        )];
        let secret = "sk_live_Qw3Er5Ty7Ui9Op1As3DfGh";

        let result = execute_action(&def, &secret_broker(secret), &engine()).await;
        assert_eq!(result.stdout, SUPPRESSED_BY_DLP);
    }

    #[tokio::test]
    async fn suppress_policy_never_returns_output() {
        let mut def = action(&["/bin/echo", "innocuous"]);
        def.output = OutputPolicy::Suppress;
        let result = execute_action(&def, &SecretBroker::new(), &engine()).await;
        assert_eq!(result.stdout, SUPPRESSED_BY_POLICY);
        assert!(result.suppressed);
    }

    #[tokio::test]
    async fn unresolvable_secret_refuses_to_execute() {
        use open_guardian::secrets::EnvironmentBackend;
        let mut def = action(&["/bin/echo", "should-not-run"]);
        def.env = vec![env_binding(
            "DEPLOY_TOKEN",
            "{{secret:env://DEFINITELY_MISSING_VAR_42}}",
        )];

        let mut broker = SecretBroker::new();
        broker
            .register(EnvironmentBackend)
            .expect("register env backend");
        let result = execute_action(&def, &broker, &engine()).await;
        assert!(result.error.is_some());
        assert!(result
            .error
            .as_deref()
            .unwrap()
            .contains("DEFINITELY_MISSING_VAR_42"));
        assert_eq!(
            result.exit_code, None,
            "nothing may execute when env resolution fails"
        );
    }

    #[tokio::test]
    async fn timeout_kills_the_process() {
        let mut def = action(&["/bin/sleep", "30"]);
        def.timeout_secs = 1;
        let started = Instant::now();
        let result = execute_action(&def, &SecretBroker::new(), &engine()).await;
        assert!(result.error.as_deref().unwrap().contains("timed out"));
        assert!(started.elapsed().as_secs() < 10);
    }

    #[tokio::test]
    async fn missing_binary_reports_error_without_panicking() {
        let result = execute_action(
            &action(&["/nonexistent/definitely-not-here"]),
            &SecretBroker::new(),
            &engine(),
        )
        .await;
        assert!(result.error.is_some());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn elevated_action_invokes_sudo_non_interactively() {
        // No sudoers rule exists for the test user, so sudo must fail fast
        // (-n forbids the password prompt) — proving the argv shape.
        let mut def = action(&["/bin/echo", "hi"]);
        def.user = Some("root".into());
        let result = execute_action(&def, &SecretBroker::new(), &engine()).await;
        assert_ne!(result.exit_code, Some(0));
    }

    #[tokio::test]
    async fn oversized_output_is_truncated() {
        let mut def = action(&["/bin/sh", "-c", "yes 0123456789abcdef | head -c 200000"]);
        def.timeout_secs = 10;
        let result = execute_action(&def, &SecretBroker::new(), &engine()).await;
        assert!(result.truncated);
        assert!(result.stdout.len() <= MAX_OUTPUT_BYTES + 16);
    }
}
