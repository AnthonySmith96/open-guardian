//! Hash-chained security audit log.
//!
//! Every line is a JSON object whose `hash` field commits to the previous
//! line's hash, so any edit, deletion, or reordering of history is detectable
//! with [`verify`]. A single writer task owns the file: producers hand events
//! to [`AuditChain::log`] and never block, which preserves the previous
//! fire-and-forget ergonomics while keeping the chain consistent under
//! concurrency.
//!
//! One chain file per process: two processes appending to the same file would
//! interleave their chains. The proxy and the broker daemon therefore keep
//! separate audit paths.

use anyhow::Context;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Handle used by producers. Cheap to clone via `Arc`.
#[derive(Clone)]
pub struct AuditChain {
    tx: mpsc::UnboundedSender<Value>,
}

impl AuditChain {
    /// Opens (or creates) the chain file and spawns the single writer task.
    ///
    /// If the file already exists, the chain resumes from the last line so
    /// history stays continuous across restarts.
    pub fn open(
        path: impl AsRef<Path>,
    ) -> anyhow::Result<(Arc<Self>, tokio::task::JoinHandle<()>)> {
        let path = path.as_ref().to_path_buf();
        let (seq, prev_hash) = recover_tip(&path).context("failed to read existing audit chain")?;

        let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
        let writer = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let mut state = WriterState { seq, prev_hash };
            let mut file = match tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .await
            {
                Ok(file) => file,
                Err(error) => {
                    tracing::error!("audit chain: cannot open {}: {error}", path.display());
                    return;
                }
            };
            while let Some(mut event) = rx.recv().await {
                let line = state.append_line(&mut event);
                if let Some(line) = line {
                    if let Err(error) = file.write_all(line.as_bytes()).await {
                        tracing::error!("audit chain: append failed: {error}");
                    }
                }
            }
            let _ = file.flush().await;
        });

        Ok((Arc::new(Self { tx }), writer))
    }

    /// Queues an event. Events are redaction-safe by contract: callers must
    /// never place secret material in them.
    pub fn log(&self, event: Value) {
        if self.tx.send(event).is_err() {
            tracing::error!("audit chain: writer task is gone; event dropped");
        }
    }
}

struct WriterState {
    seq: u64,
    prev_hash: String,
}

impl WriterState {
    fn append_line(&mut self, event: &mut Value) -> Option<String> {
        let object = match event.as_object_mut() {
            Some(object) => object,
            None => {
                tracing::error!("audit chain: events must be JSON objects; dropped");
                return None;
            }
        };
        self.seq += 1;
        object.insert("seq".into(), Value::from(self.seq));
        object.insert("prev".into(), Value::from(self.prev_hash.clone()));

        // serde_json's default map is key-sorted, so writer and verifier
        // serialize the hash-less payload to identical bytes.
        let payload = serde_json::to_string(&object_as_value(object)).ok()?;
        let mut hasher = Sha256::new();
        hasher.update(self.prev_hash.as_bytes());
        hasher.update(payload.as_bytes());
        let hash = hex::encode(hasher.finalize());
        object.insert("hash".into(), Value::from(hash.clone()));

        self.prev_hash = hash;
        Some(serde_json::to_string(object).ok()? + "\n")
    }
}

fn object_as_value(object: &serde_json::Map<String, Value>) -> Value {
    Value::Object(object.clone())
}

/// Reads an existing chain file and returns (last_seq, last_hash) to resume
/// from. An empty or missing file yields the genesis state.
fn recover_tip(path: &Path) -> anyhow::Result<(u64, String)> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((0, GENESIS_HASH.to_string()))
        }
        Err(error) => return Err(anyhow::anyhow!("{error}")),
    };

    let mut seq = 0;
    let mut prev_hash = GENESIS_HASH.to_string();
    for (index, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line)
            .with_context(|| format!("line {} is not valid JSON", index + 1))?;
        seq = value.get("seq").and_then(Value::as_u64).unwrap_or(0);
        prev_hash = value
            .get("hash")
            .and_then(Value::as_str)
            .unwrap_or(GENESIS_HASH)
            .to_string();
    }
    Ok((seq, prev_hash))
}

#[derive(Debug)]
pub struct ChainReport {
    pub lines: u64,
    pub last_hash: String,
}

#[derive(Debug)]
pub struct ChainBroken {
    pub line: u64,
    pub reason: String,
}

/// Validates the full chain of an audit log: sequence numbers increment,
/// every `hash` recomputes, and every `prev` links to the previous line.
pub fn verify(path: impl AsRef<Path>) -> Result<ChainReport, ChainBroken> {
    let content = std::fs::read_to_string(path.as_ref()).map_err(|error| ChainBroken {
        line: 0,
        reason: format!("cannot read log: {error}"),
    })?;

    let mut expected_seq = 1_u64;
    let mut prev_hash = GENESIS_HASH.to_string();
    let mut lines = 0_u64;

    for raw_line in content.lines() {
        if raw_line.trim().is_empty() {
            continue;
        }
        let line_number = lines + 1;
        let value: Value = serde_json::from_str(raw_line).map_err(|error| ChainBroken {
            line: line_number,
            reason: format!("not valid JSON: {error}"),
        })?;
        let object = value.as_object().ok_or_else(|| ChainBroken {
            line: line_number,
            reason: "line is not a JSON object".into(),
        })?;

        let seq = object
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| ChainBroken {
                line: line_number,
                reason: "missing seq".into(),
            })?;
        if seq != expected_seq {
            return Err(ChainBroken {
                line: line_number,
                reason: format!("expected seq {expected_seq}, found {seq}"),
            });
        }

        let stored_hash =
            object
                .get("hash")
                .and_then(Value::as_str)
                .ok_or_else(|| ChainBroken {
                    line: line_number,
                    reason: "missing hash".into(),
                })?;
        let stored_prev = object.get("prev").and_then(Value::as_str).unwrap_or("");
        if stored_prev != prev_hash {
            return Err(ChainBroken {
                line: line_number,
                reason: "prev does not link to the previous line's hash".into(),
            });
        }

        let mut payload_object = object.clone();
        payload_object.remove("hash");
        let payload =
            serde_json::to_string(&Value::Object(payload_object)).map_err(|error| ChainBroken {
                line: line_number,
                reason: format!("cannot re-serialize payload: {error}"),
            })?;
        let mut hasher = Sha256::new();
        hasher.update(prev_hash.as_bytes());
        hasher.update(payload.as_bytes());
        let computed = hex::encode(hasher.finalize());
        if computed != stored_hash {
            return Err(ChainBroken {
                line: line_number,
                reason: "hash mismatch: line was modified after it was written".into(),
            });
        }

        prev_hash = stored_hash.to_string();
        expected_seq += 1;
        lines += 1;
    }

    Ok(ChainReport {
        lines,
        last_hash: prev_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn temp_chain_path(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "guardian-audit-chain-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[tokio::test]
    async fn chain_verifies_and_resumes_across_restarts() {
        let path = temp_chain_path("restart");

        let (chain, writer) = AuditChain::open(&path).expect("open");
        chain.log(json!({"event": "one"}));
        chain.log(json!({"event": "two"}));
        chain.log(json!({"event": "three"}));
        // Dropping the handle closes the channel; the writer then flushes
        // and exits, so awaiting it is a deterministic barrier.
        drop(chain);
        writer.await.expect("writer exits cleanly");

        let report = verify(&path).expect("chain verifies");
        assert_eq!(report.lines, 3);

        // Reopen: the chain must resume at seq 4 and stay valid.
        let (chain, writer) = AuditChain::open(&path).expect("reopen");
        chain.log(json!({"event": "four"}));
        drop(chain);
        writer.await.expect("writer exits cleanly");

        let report = verify(&path).expect("resumed chain verifies");
        assert_eq!(report.lines, 4);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_events_keep_the_chain_consistent() {
        let path = temp_chain_path("concurrent");

        let (chain, writer) = AuditChain::open(&path).expect("open");
        let mut handles = Vec::new();
        for worker in 0..8_u64 {
            let chain = chain.clone();
            handles.push(tokio::spawn(async move {
                for i in 0..25_u64 {
                    chain.log(json!({"event": "parallel", "worker": worker, "i": i}));
                }
            }));
        }
        for handle in handles {
            handle.await.expect("worker");
        }
        drop(chain);
        writer.await.expect("writer exits cleanly");

        let report = verify(&path).expect("chain verifies under concurrency");
        assert_eq!(report.lines, 8 * 25);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampered_line_breaks_the_chain() {
        let path = temp_chain_path("tamper");
        std::fs::write(
            &path,
            concat!(
                r#"{"event":"alpha","prev":"0000000000000000000000000000000000000000000000000000000000000000","seq":1,"hash":"aaaa"}"#,
                "\n",
                r#"{"event":"beta","prev":"aaaa","seq":2,"hash":"bbbb"}"#,
                "\n",
            ),
        )
        .expect("write chain");

        let broken = verify(&path).expect_err("must detect tampering");
        assert_eq!(broken.line, 1);
        assert!(broken.reason.contains("hash mismatch"));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn reordering_is_detected_through_prev_links() {
        let path = temp_chain_path("reorder");
        let (chain, writer) = AuditChain::open(&path).expect("open");
        chain.log(json!({"event": "one"}));
        chain.log(json!({"event": "two"}));
        drop(chain);
        writer.await.expect("writer exits cleanly");

        // Swap the two lines: seq and prev links can no longer both hold.
        let content = std::fs::read_to_string(&path).expect("read");
        let mut lines: Vec<&str> = content.lines().collect();
        lines.reverse();
        std::fs::write(&path, lines.join("\n") + "\n").expect("rewrite");

        assert!(verify(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn deleting_history_is_detected() {
        let path = temp_chain_path("delete");
        let (chain, writer) = AuditChain::open(&path).expect("open");
        chain.log(json!({"event": "one"}));
        chain.log(json!({"event": "two"}));
        chain.log(json!({"event": "three"}));
        drop(chain);
        writer.await.expect("writer exits cleanly");

        let content = std::fs::read_to_string(&path).expect("read");
        let kept: Vec<&str> = content.lines().skip(1).collect();
        std::fs::write(&path, kept.join("\n") + "\n").expect("truncate history");

        let broken = verify(&path).expect_err("deletion must be detected");
        assert!(broken.reason.contains("prev") || broken.reason.contains("seq"));
        let _ = std::fs::remove_file(&path);
    }
}
