//! Per-IP Rate Limiting Module
//!
//! This module implements per-source IP rate limiting using a simple token bucket.
//! Note: Uses basic implementation compatible with governor 0.5 API.

use http::{HeaderMap, HeaderValue, StatusCode};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Default TTL for idle rate limiter entries (seconds).
const DEFAULT_ENTRY_TTL_SECS: u64 = 600;

pub const DEFAULT_NORMAL_LIMIT: u32 = 60;
pub const DEFAULT_FLAGGED_LIMIT: u32 = 30;
pub const DEFAULT_BLOCKED_LIMIT: u32 = 5;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_normal_limit")]
    pub normal_limit: u32,
    #[serde(default = "default_flagged_limit")]
    pub flagged_limit: u32,
    #[serde(default = "default_blocked_limit")]
    pub blocked_limit: u32,
    #[serde(default = "default_true")]
    pub enable_headers: bool,
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval_secs: u64,
}

fn default_normal_limit() -> u32 {
    DEFAULT_NORMAL_LIMIT
}
fn default_flagged_limit() -> u32 {
    DEFAULT_FLAGGED_LIMIT
}
fn default_blocked_limit() -> u32 {
    DEFAULT_BLOCKED_LIMIT
}
fn default_true() -> bool {
    true
}
fn default_cleanup_interval() -> u64 {
    300
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            normal_limit: DEFAULT_NORMAL_LIMIT,
            flagged_limit: DEFAULT_FLAGGED_LIMIT,
            blocked_limit: DEFAULT_BLOCKED_LIMIT,
            enable_headers: true,
            cleanup_interval_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrafficClass {
    Normal,
    Flagged,
    Blocked,
}

impl Default for TrafficClass {
    fn default() -> Self {
        Self::Normal
    }
}

#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: u32,
    max_tokens: u32,
    last_refill: Instant,
    last_access: Instant,
    refill_rate: f64, // tokens per second
}

impl TokenBucket {
    fn new(max_tokens: u32) -> Self {
        let now = Instant::now();
        Self {
            tokens: max_tokens,
            max_tokens,
            last_refill: now,
            last_access: now,
            refill_rate: max_tokens as f64 / 60.0,
        }
    }

    fn try_consume(&mut self) -> bool {
        self.refill();
        self.last_access = Instant::now();
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        let new_tokens = (elapsed * self.refill_rate).floor() as u32;
        if new_tokens > 0 {
            self.tokens = (self.tokens + new_tokens).min(self.max_tokens);
            self.last_refill = Instant::now();
        }
    }
}

#[derive(Debug, Clone)]
pub struct IpRateLimiter {
    normal_bucket: TokenBucket,
    flagged_bucket: TokenBucket,
    blocked_bucket: TokenBucket,
    traffic_class: TrafficClass,
}

impl IpRateLimiter {
    pub fn new(config: &RateLimitConfig) -> Self {
        Self {
            normal_bucket: TokenBucket::new(config.normal_limit),
            flagged_bucket: TokenBucket::new(config.flagged_limit),
            blocked_bucket: TokenBucket::new(config.blocked_limit),
            traffic_class: TrafficClass::Normal,
        }
    }

    pub fn check(&mut self) -> RateLimitCheck {
        let bucket = match self.traffic_class {
            TrafficClass::Normal => &mut self.normal_bucket,
            TrafficClass::Flagged => &mut self.flagged_bucket,
            TrafficClass::Blocked => &mut self.blocked_bucket,
        };

        if bucket.try_consume() {
            RateLimitCheck::Allowed {
                remaining: bucket.tokens,
                class: self.traffic_class,
            }
        } else {
            RateLimitCheck::Denied {
                wait_time_secs: 1, // Approximate
                class: self.traffic_class,
            }
        }
    }

    pub fn set_traffic_class(&mut self, class: TrafficClass) {
        self.traffic_class = class;
    }

    pub fn get_traffic_class(&self) -> TrafficClass {
        self.traffic_class
    }
}

#[derive(Debug, Clone)]
pub enum RateLimitCheck {
    Allowed {
        remaining: u32,
        class: TrafficClass,
    },
    Denied {
        wait_time_secs: u64,
        class: TrafficClass,
    },
}

pub struct PerIpRateLimiter {
    limiters: Arc<RwLock<std::collections::HashMap<IpAddr, IpRateLimiter>>>,
    config: RateLimitConfig,
}

impl PerIpRateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            limiters: Arc::new(RwLock::new(std::collections::HashMap::new())),
            config,
        }
    }

    pub async fn check(&self, ip: IpAddr) -> RateLimitCheck {
        let mut limiters = self.limiters.write().await;

        let limiter = limiters
            .entry(ip)
            .or_insert_with(|| IpRateLimiter::new(&self.config));

        limiter.check()
    }

    pub async fn check_with_headers(
        &self,
        ip: IpAddr,
        mut headers: HeaderMap,
    ) -> (RateLimitCheck, HeaderMap) {
        let check = self.check(ip).await;

        if self.config.enable_headers {
            let (limit, remaining, reset_in) = match &check {
                RateLimitCheck::Allowed { remaining, .. } => {
                    (self.config.normal_limit, *remaining, 60)
                }
                RateLimitCheck::Denied { wait_time_secs, .. } => {
                    (self.config.normal_limit, 0, *wait_time_secs)
                }
            };

            if let Ok(limit_val) = HeaderValue::from_str(&limit.to_string()) {
                headers.insert("X-RateLimit-Limit", limit_val);
            }
            if let Ok(rem_val) = HeaderValue::from_str(&remaining.to_string()) {
                headers.insert("X-RateLimit-Remaining", rem_val);
            }
            if let Ok(reset_val) = HeaderValue::from_str(&reset_in.to_string()) {
                headers.insert("X-RateLimit-Reset", reset_val);
            }
        }

        (check, headers)
    }

    pub async fn set_traffic_class(&self, ip: IpAddr, class: TrafficClass) {
        let mut limiters = self.limiters.write().await;

        if let Some(limiter) = limiters.get_mut(&ip) {
            limiter.set_traffic_class(class);
            info!("IP {} traffic class set to {:?}", ip, class);
        } else {
            let mut limiter = IpRateLimiter::new(&self.config);
            limiter.set_traffic_class(class);
            limiters.insert(ip, limiter);
            info!("IP {} created with traffic class {:?}", ip, class);
        }
    }

    pub async fn get_traffic_class(&self, ip: IpAddr) -> TrafficClass {
        let limiters = self.limiters.read().await;

        limiters
            .get(&ip)
            .map(|l| l.get_traffic_class())
            .unwrap_or(TrafficClass::Normal)
    }

    pub async fn remove_ip(&self, ip: IpAddr) {
        let mut limiters = self.limiters.write().await;
        limiters.remove(&ip);
        info!("IP {} removed from rate limiter", ip);
    }

    /// Remove entries that haven't been accessed within `ttl`.
    pub async fn cleanup_expired(&self, ttl: Duration) -> usize {
        let mut limiters = self.limiters.write().await;
        let before = limiters.len();
        limiters.retain(|_ip, limiter| {
            // Check the normal bucket's last_access as a proxy for activity
            let dominated_bucket = match limiter.traffic_class {
                TrafficClass::Normal => &limiter.normal_bucket,
                TrafficClass::Flagged => &limiter.flagged_bucket,
                TrafficClass::Blocked => &limiter.blocked_bucket,
            };
            dominated_bucket.last_access.elapsed() < ttl
        });
        let removed = before - limiters.len();
        if removed > 0 {
            info!(
                "Rate limiter cleanup: removed {} expired entries ({} remaining)",
                removed,
                limiters.len()
            );
        }
        removed
    }

    /// Returns the current number of tracked IPs.
    pub async fn len(&self) -> usize {
        self.limiters.read().await.len()
    }

    /// Spawn a background task that periodically cleans up expired entries.
    /// Returns a `JoinHandle` for the cleanup task.
    pub fn spawn_cleanup_task(
        self: &Arc<Self>,
        interval: Duration,
        ttl: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let limiter = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                limiter.cleanup_expired(ttl).await;
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitStats {
    pub total_ips: u32,
    pub normal_ips: u32,
    pub flagged_ips: u32,
    pub blocked_ips: u32,
}

pub async fn apply_rate_limit(limiter: &PerIpRateLimiter, ip: IpAddr) -> Result<(), StatusCode> {
    match limiter.check(ip).await {
        RateLimitCheck::Allowed { .. } => Ok(()),
        RateLimitCheck::Denied { wait_time_secs, .. } => {
            warn!(
                "Rate limit exceeded for IP {} - retry after {}s",
                ip, wait_time_secs
            );
            Err(StatusCode::TOO_MANY_REQUESTS)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_hashmap_stays_bounded() {
        let config = RateLimitConfig::default();
        let limiter = PerIpRateLimiter::new(config);

        // Insert 100 IPs
        for i in 0..100u8 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
            limiter.check(ip).await;
        }
        assert_eq!(limiter.len().await, 100);

        // Cleanup with a zero TTL should remove all entries
        let removed = limiter.cleanup_expired(Duration::from_secs(0)).await;
        assert_eq!(removed, 100);
        assert_eq!(limiter.len().await, 0);
    }

    #[tokio::test]
    async fn test_cleanup_preserves_recent() {
        let config = RateLimitConfig::default();
        let limiter = PerIpRateLimiter::new(config);

        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        limiter.check(ip).await;

        // Cleanup with a generous TTL should keep the entry
        let removed = limiter.cleanup_expired(Duration::from_secs(3600)).await;
        assert_eq!(removed, 0);
        assert_eq!(limiter.len().await, 1);
    }

    #[tokio::test]
    async fn test_rate_limit_allows_and_denies() {
        let config = RateLimitConfig {
            normal_limit: 2,
            ..Default::default()
        };
        let limiter = PerIpRateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // First two should be allowed
        assert!(matches!(
            limiter.check(ip).await,
            RateLimitCheck::Allowed { .. }
        ));
        assert!(matches!(
            limiter.check(ip).await,
            RateLimitCheck::Allowed { .. }
        ));
        // Third should be denied
        assert!(matches!(
            limiter.check(ip).await,
            RateLimitCheck::Denied { .. }
        ));
    }
}

pub fn extract_client_ip(headers: &HeaderMap, direct_ip: IpAddr) -> IpAddr {
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(ip_str) = forwarded_str.split(',').next() {
                if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }

    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                return ip;
            }
        }
    }

    direct_ip
}
