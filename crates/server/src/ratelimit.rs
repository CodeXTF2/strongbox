//! Minimal per-IP token bucket for unauthenticated endpoints. Single-instance only; a
//! multi-instance deployment should rate-limit at the proxy or in a shared store.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

pub struct RateLimiter {
    per_minute: f64,
    buckets: Mutex<HashMap<IpAddr, (f64, Instant)>>,
}

impl RateLimiter {
    pub fn new(per_minute: u32) -> Self {
        RateLimiter {
            per_minute: per_minute as f64,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap();
        let (tokens, last) = buckets.entry(ip).or_insert((self.per_minute, now));
        *tokens = (*tokens + now.duration_since(*last).as_secs_f64() * self.per_minute / 60.0)
            .min(self.per_minute);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn purge(&self) {
        let now = Instant::now();
        self.buckets
            .lock()
            .unwrap()
            .retain(|_, (_, last)| now.duration_since(*last).as_secs() < 600);
    }
}
