//! Minimal in-memory rate limiter for authentication endpoints.
//!
//! Fixed-window attempt counter with lockout, keyed by an identifier (e.g. the
//! login email). Intended as a first line of defence against online password
//! guessing; for multi-instance deployments put a shared rate limiter (or a
//! WAF / reverse proxy) in front as well.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Failed attempts allowed within `WINDOW` before a lockout kicks in.
const MAX_ATTEMPTS: u32 = 5;
/// Rolling window in which attempts are counted.
const WINDOW: Duration = Duration::from_secs(60);
/// How long a key is locked out once it exceeds `MAX_ATTEMPTS`.
const LOCKOUT: Duration = Duration::from_secs(300);
/// Hard cap on tracked keys, so attacker-supplied identifiers can't grow the
/// map without bound. When exceeded we drop entries that are no longer relevant.
const MAX_KEYS: usize = 10_000;

struct Bucket {
    count: u32,
    window_start: Instant,
    locked_until: Option<Instant>,
}

fn store() -> &'static Mutex<HashMap<String, Bucket>> {
    static S: OnceLock<Mutex<HashMap<String, Bucket>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Record an attempt for `key`. Returns `Err(retry_after_secs)` when the key is
/// currently rate-limited and the attempt should be rejected.
pub fn check_and_record(key: &str) -> Result<(), u64> {
    let now = Instant::now();
    let mut map = store().lock().unwrap_or_else(|e| e.into_inner());

    if map.len() > MAX_KEYS {
        map.retain(|_, b| {
            b.locked_until.map(|u| u > now).unwrap_or(false)
                || now.duration_since(b.window_start) <= WINDOW
        });
    }

    let b = map.entry(key.to_string()).or_insert(Bucket {
        count: 0,
        window_start: now,
        locked_until: None,
    });

    if let Some(until) = b.locked_until {
        if now < until {
            return Err((until - now).as_secs() + 1);
        }
        // Lockout expired — start fresh.
        b.count = 0;
        b.window_start = now;
        b.locked_until = None;
    }

    if now.duration_since(b.window_start) > WINDOW {
        b.count = 0;
        b.window_start = now;
    }

    b.count += 1;
    if b.count > MAX_ATTEMPTS {
        b.locked_until = Some(now + LOCKOUT);
        return Err(LOCKOUT.as_secs());
    }
    Ok(())
}

/// Clear a key's counter after a successful authentication.
pub fn reset(key: &str) {
    store()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(key);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_out_after_max_attempts() {
        let key = "lockout@example.com";
        for _ in 0..MAX_ATTEMPTS {
            assert!(check_and_record(key).is_ok());
        }
        // The next attempt crosses the threshold and is rejected.
        assert!(check_and_record(key).is_err());
        reset(key);
    }

    #[test]
    fn reset_clears_counter() {
        let key = "reset@example.com";
        for _ in 0..MAX_ATTEMPTS {
            let _ = check_and_record(key);
        }
        reset(key);
        assert!(check_and_record(key).is_ok());
        reset(key);
    }
}
