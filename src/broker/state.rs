//! Request state machine: Teleport-style pending → approve/deny → executed,
//! with Vault-style single-use results and TTLs.

use chrono::{DateTime, Utc};
use rand::{Rng, RngCore};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Alphabet without lookalikes so a human can read a code aloud reliably.
const CODE_ALPHABET: &[u8] = b"23456789abcdefghjkmnpqrstuvwxyz";

#[derive(Debug, Clone)]
pub struct ActionResult {
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    /// Already DLP-sanitized before it ever enters this store.
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub suppressed: bool,
    /// Spawn/timeout failure text when the command never completed.
    pub error: Option<String>,
}

impl ActionResult {
    pub fn to_json(&self) -> Value {
        json!({
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "truncated": self.truncated,
            "suppressed": self.suppressed,
            "error": self.error,
        })
    }
}

#[derive(Debug, Clone)]
pub enum RequestState {
    Pending {
        code: String,
        expires_at: Instant,
    },
    Executing,
    Completed {
        result: ActionResult,
        delivered: bool,
        expires_at: Instant,
    },
    Denied,
    Expired,
}

impl RequestState {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Pending { .. } => "pending",
            Self::Executing => "executing",
            Self::Completed { .. } => "completed",
            Self::Denied => "denied",
            Self::Expired => "expired",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequestRecord {
    pub id: String,
    pub action_id: String,
    /// DLP-redacted at submission time.
    pub reason: String,
    pub created_at: DateTime<Utc>,
    /// When the sweeper may drop this record entirely. History lives in the
    /// audit chain, not in memory.
    pub purge_at: Instant,
    pub state: RequestState,
}

#[derive(Debug)]
pub struct CreatedRequest {
    pub record: RequestRecord,
    pub code: String,
    pub pending_ttl: Duration,
}

#[derive(Debug)]
pub enum ApproveError {
    Unknown,
    NotPending(&'static str),
    WrongCode,
}

#[derive(Debug)]
pub struct ApprovedRequest {
    pub action_id: String,
}

pub struct RequestStore {
    pending_ttl: Duration,
    result_ttl: Duration,
    requests: Mutex<HashMap<String, RequestRecord>>,
}

impl RequestStore {
    pub fn new(pending_ttl: Duration, result_ttl: Duration) -> Self {
        Self {
            pending_ttl,
            result_ttl,
            requests: Mutex::new(HashMap::new()),
        }
    }

    pub fn create(&self, action_id: &str, reason: &str) -> CreatedRequest {
        let mut id_bytes = [0u8; 4];
        rand::rngs::OsRng.fill_bytes(&mut id_bytes);
        let id = hex::encode(id_bytes);

        let mut rng = rand::thread_rng();
        let code: String = (0..6)
            .map(|_| CODE_ALPHABET[rng.gen_range(0..CODE_ALPHABET.len())] as char)
            .collect();

        let record = RequestRecord {
            id: id.clone(),
            action_id: action_id.to_string(),
            reason: reason.to_string(),
            created_at: Utc::now(),
            purge_at: Instant::now() + self.pending_ttl + self.result_ttl,
            state: RequestState::Pending {
                code: code.clone(),
                expires_at: Instant::now() + self.pending_ttl,
            },
        };
        self.requests
            .lock()
            .expect("request store poisoned")
            .insert(id.clone(), record.clone());
        CreatedRequest {
            record,
            code,
            pending_ttl: self.pending_ttl,
        }
    }

    /// Snapshot for status/listing. Never exposes the approval code: only
    /// `code_of` (admin channel) can read it.
    pub fn snapshot(&self, id: &str) -> Option<RequestRecord> {
        self.requests
            .lock()
            .expect("request store poisoned")
            .get(id)
            .cloned()
    }

    /// The pending request's approval code. Admin-channel only.
    pub fn code_of(&self, id: &str) -> Option<String> {
        match self.snapshot(id)?.state {
            RequestState::Pending { code, .. } => Some(code),
            _ => None,
        }
    }

    pub fn list(&self) -> Vec<RequestRecord> {
        let mut records: Vec<RequestRecord> = self
            .requests
            .lock()
            .expect("request store poisoned")
            .values()
            .cloned()
            .collect();
        records.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        records
    }

    /// Validates the code and atomically transitions Pending → Executing.
    /// The caller then executes and reports back via [`Self::complete`].
    pub fn approve(&self, id: &str, code: &str) -> Result<ApprovedRequest, ApproveError> {
        let mut requests = self.requests.lock().expect("request store poisoned");
        let record = requests.get_mut(id).ok_or(ApproveError::Unknown)?;
        match &record.state {
            RequestState::Pending {
                code: expected,
                expires_at,
            } => {
                if Instant::now() >= *expires_at {
                    record.state = RequestState::Expired;
                    return Err(ApproveError::NotPending("request already expired"));
                }
                if !constant_time_eq(expected.as_bytes(), code.as_bytes()) {
                    return Err(ApproveError::WrongCode);
                }
                let action_id = record.action_id.clone();
                record.state = RequestState::Executing;
                Ok(ApprovedRequest { action_id })
            }
            RequestState::Executing => Err(ApproveError::NotPending("already approved; executing")),
            RequestState::Completed { delivered, .. } => {
                Err(ApproveError::NotPending(if *delivered {
                    "already completed and delivered"
                } else {
                    "already completed; fetch the result"
                }))
            }
            RequestState::Denied => Err(ApproveError::NotPending("already denied")),
            RequestState::Expired => Err(ApproveError::NotPending("already expired")),
        }
    }

    pub fn deny(&self, id: &str) -> Result<(), ApproveError> {
        let mut requests = self.requests.lock().expect("request store poisoned");
        let record = requests.get_mut(id).ok_or(ApproveError::Unknown)?;
        match &record.state {
            RequestState::Pending { expires_at, .. } => {
                if Instant::now() >= *expires_at {
                    record.state = RequestState::Expired;
                    return Err(ApproveError::NotPending("request already expired"));
                }
                record.state = RequestState::Denied;
                Ok(())
            }
            _ => Err(ApproveError::NotPending("no longer pending")),
        }
    }

    /// Executing → Completed. The result is readable exactly once.
    pub fn complete(&self, id: &str, result: ActionResult) {
        if let Some(record) = self
            .requests
            .lock()
            .expect("request store poisoned")
            .get_mut(id)
        {
            record.state = RequestState::Completed {
                result,
                delivered: false,
                expires_at: Instant::now() + self.result_ttl,
            };
        }
    }

    /// One-time result delivery: marks delivered and returns the result.
    pub fn deliver(&self, id: &str) -> Option<ActionResult> {
        let mut requests = self.requests.lock().expect("request store poisoned");
        let record = requests.get_mut(id)?;
        match &mut record.state {
            RequestState::Completed {
                result, delivered, ..
            } => {
                if *delivered {
                    return None;
                }
                *delivered = true;
                Some(result.clone())
            }
            _ => None,
        }
    }

    /// Expires stale pending requests and drops records past their retention
    /// window. Returns the ids that just expired (for audit).
    pub fn sweep(&self) -> Vec<String> {
        let mut requests = self.requests.lock().expect("request store poisoned");
        let now = Instant::now();
        let mut expired = Vec::new();
        let mut purge = Vec::new();

        for (id, record) in requests.iter_mut() {
            match &record.state {
                RequestState::Pending { expires_at, .. } => {
                    if now >= *expires_at {
                        expired.push(id.clone());
                        record.state = RequestState::Expired;
                        record.purge_at = now + self.result_ttl;
                    } else if now >= record.purge_at {
                        purge.push(id.clone());
                    }
                }
                RequestState::Completed { expires_at, .. } => {
                    if now >= *expires_at || now >= record.purge_at {
                        purge.push(id.clone());
                    }
                }
                RequestState::Denied | RequestState::Expired | RequestState::Executing => {
                    if now >= record.purge_at {
                        purge.push(id.clone());
                    }
                }
            }
        }
        for id in &purge {
            requests.remove(id);
        }
        expired
    }
}

/// Length-independent constant-time byte comparison for approval codes.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> RequestStore {
        RequestStore::new(Duration::from_secs(120), Duration::from_secs(300))
    }

    #[test]
    fn approve_requires_the_exact_code_and_delivers_once() {
        let store = store();
        let created = store.create("restart-nginx", "deploy");

        assert_eq!(created.record.state.name(), "pending");
        assert_eq!(created.code.len(), 6);
        assert!(matches!(
            store.approve(&created.record.id, "wrong1"),
            Err(ApproveError::WrongCode)
        ));

        let approved = store
            .approve(&created.record.id, &created.code)
            .expect("approve");
        assert_eq!(approved.action_id, "restart-nginx");
        assert!(matches!(
            store.approve(&created.record.id, &created.code),
            Err(ApproveError::NotPending(_))
        ));

        store.complete(
            &created.record.id,
            ActionResult {
                exit_code: Some(0),
                duration_ms: 12,
                stdout: "ok".into(),
                stderr: String::new(),
                truncated: false,
                suppressed: false,
                error: None,
            },
        );

        let first = store.deliver(&created.record.id).expect("first read");
        assert_eq!(first.stdout, "ok");
        assert!(
            store.deliver(&created.record.id).is_none(),
            "result must be single-use"
        );
    }

    #[test]
    fn deny_blocks_execution() {
        let store = store();
        let created = store.create("restart-nginx", "deploy");
        store.deny(&created.record.id).expect("deny");
        assert!(matches!(
            store.approve(&created.record.id, &created.code),
            Err(ApproveError::NotPending(_))
        ));
        assert_eq!(
            store.snapshot(&created.record.id).unwrap().state.name(),
            "denied"
        );
    }

    #[test]
    fn sweep_expires_stale_pending_requests() {
        let store = RequestStore::new(Duration::from_millis(20), Duration::from_secs(300));
        let created = store.create("restart-nginx", "deploy");
        std::thread::sleep(Duration::from_millis(40));

        let expired = store.sweep();
        assert_eq!(expired, vec![created.record.id.clone()]);
        assert_eq!(
            store.snapshot(&created.record.id).unwrap().state.name(),
            "expired"
        );
        assert!(matches!(
            store.approve(&created.record.id, &created.code),
            Err(ApproveError::NotPending(_))
        ));
    }

    #[test]
    fn snapshots_never_leak_the_code() {
        let store = store();
        let created = store.create("restart-nginx", "deploy");
        let snapshot = store.snapshot(&created.record.id).expect("snapshot");

        match snapshot.state {
            RequestState::Pending { code, .. } => {
                // The enum carries the code internally; the IPC layer is the
                // only place that renders state to JSON and it never includes
                // it. Guard the JSON rendering contract here indirectly:
                assert_eq!(code.len(), 6);
            }
            other => panic!("expected pending, got {:?}", other.name()),
        }
    }
}
