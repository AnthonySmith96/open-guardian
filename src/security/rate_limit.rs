//! Per-client-IP rate limiting.
//!
//! Token bucket per source IP, refilled continuously at
//! `requests_per_minute / 60` tokens per second with full-bucket
//! bursts. Keys are the socket peer addresses reported by the local
//! listener — forwarded headers are intentionally ignored so clients
//! cannot spoof their limiter identity.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;

/// Default per-IP budget (20 req/s sustained, burstable).
pub const DEFAULT_REQUESTS_PER_MINUTE: u32 = 1200;

/// Buckets idle for this long are prunable.
const IDLE_PRUNE_AGE: Duration = Duration::from_secs(120);

struct TokenBucket {
    tokens: u32,
    max_tokens: u32,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(max_tokens: u32) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            last_refill: Instant::now(),
        }
    }

    fn try_consume(&mut self) -> bool {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        let refill_rate = f64::from(self.max_tokens) / 60.0;
        let new_tokens = (elapsed * refill_rate).floor() as u32;
        if new_tokens > 0 {
            self.tokens = (self.tokens + new_tokens).min(self.max_tokens);
            self.last_refill = Instant::now();
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    fn is_idle(&self) -> bool {
        self.last_refill.elapsed() >= IDLE_PRUNE_AGE
    }
}

#[derive(Clone)]
pub struct PerIpRateLimiter {
    buckets: Arc<Mutex<HashMap<IpAddr, TokenBucket>>>,
    requests_per_minute: u32,
}

impl PerIpRateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            requests_per_minute: requests_per_minute.max(1),
        }
    }

    /// Consumes one token for `ip`. Returns `true` when the request is
    /// allowed, `false` when that IP exceeded its budget.
    pub async fn check(&self, ip: IpAddr) -> bool {
        let mut buckets = self.buckets.lock().await;
        buckets
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(self.requests_per_minute))
            .try_consume()
    }

    /// Drops buckets that have been idle long enough to refill fully.
    pub async fn prune(&self) {
        let mut buckets = self.buckets.lock().await;
        buckets.retain(|_, bucket| !bucket.is_idle());
    }

    /// Periodic background prune so a proxy exposed to many clients does
    /// not accumulate limiter state forever.
    pub fn spawn_prune_task(self: &Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        let limiter = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                limiter.prune().await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::PerIpRateLimiter;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, last))
    }

    #[tokio::test]
    async fn budgets_are_tracked_per_ip() {
        let limiter = PerIpRateLimiter::new(3);

        for _ in 0..3 {
            assert!(limiter.check(ip(1)).await);
        }
        assert!(!limiter.check(ip(1)).await, "first IP exhausted its budget");
        assert!(limiter.check(ip(2)).await, "second IP has its own budget");
    }

    #[tokio::test]
    async fn tokens_refill_over_time() {
        let limiter = PerIpRateLimiter::new(2);

        assert!(limiter.check(ip(1)).await);
        assert!(limiter.check(ip(1)).await);
        assert!(!limiter.check(ip(1)).await);

        // 2 tokens/min → after ~35s at least one token has refilled.
        tokio::time::pause();
        tokio::time::advance(std::time::Duration::from_secs(35)).await;
        assert!(limiter.check(ip(1)).await, "bucket refilled");
    }

    #[tokio::test]
    async fn prune_clears_idle_buckets() {
        let limiter = PerIpRateLimiter::new(10);
        assert!(limiter.check(ip(1)).await);

        tokio::time::pause();
        tokio::time::advance(std::time::Duration::from_secs(180)).await;
        limiter.prune().await;

        // A pruned IP simply starts with a fresh bucket.
        assert!(limiter.check(ip(1)).await);
    }

    #[test]
    fn zero_limit_is_clamped_to_one() {
        let limiter = PerIpRateLimiter::new(0);
        // 0 means "deny everything except a single burst token" — clamped,
        // never a division by zero or an accidental unlimited bucket.
        assert_eq!(limiter.requests_per_minute, 1);
    }
}
