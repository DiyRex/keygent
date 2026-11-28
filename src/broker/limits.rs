//! Broker limits (SPEC §4.1): connection/run slots, the `Redact` byte budget and the auth-failure window. Owned by
//! `Shared` (not process globals) so they are per-broker and unit-testable.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A bounded counter; `take` hands out a slot that gives itself back on drop.
#[derive(Default)]
pub struct Counter(Arc<AtomicUsize>);

/// One taken unit of a `Counter`.
pub struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

impl Counter {
    /// A slot if fewer than `cap` are taken. Never overshoots (no add-then-undo), so a concurrent taker is never
    /// refused spuriously.
    pub fn take(&self, cap: usize) -> Option<Slot> {
        let mut n = self.0.load(Ordering::Acquire);
        loop {
            if n >= cap {
                return None;
            }
            match self.0.compare_exchange_weak(
                n,
                n.saturating_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Slot(self.0.clone())),
                Err(cur) => n = cur,
            }
        }
    }
}

/// Token bucket in whole bytes (no floats): `rate` bytes per second, burst `rate`.
pub struct ByteBucket {
    rate: u64,
    state: Mutex<Option<(Instant, u64)>>,
}

impl ByteBucket {
    pub const fn new(rate_per_sec: u64) -> Self {
        ByteBucket {
            rate: rate_per_sec,
            state: Mutex::new(None),
        }
    }

    /// Spend `n` bytes now if the budget allows.
    pub fn spend(&self, n: usize) -> bool {
        self.spend_at(n, Instant::now())
    }

    fn spend_at(&self, n: usize, now: Instant) -> bool {
        let mut g = super::lock(&self.state);
        let (last, tokens) = g.unwrap_or((now, self.rate));
        let elapsed = now.saturating_duration_since(last).as_nanos();
        let refill = elapsed
            .saturating_mul(u128::from(self.rate))
            .checked_div(1_000_000_000)
            .unwrap_or(0);
        let avail = u128::from(tokens)
            .saturating_add(refill)
            .min(u128::from(self.rate));
        let avail = u64::try_from(avail).unwrap_or(self.rate);
        let need = u64::try_from(n).unwrap_or(u64::MAX);
        let left = avail.checked_sub(need);
        *g = Some((now, left.unwrap_or(avail)));
        left.is_some()
    }
}

/// Events per fixed window (auth failures: 30 per minute).
pub struct Window {
    cap: u32,
    len: Duration,
    state: Mutex<Option<(Instant, u32)>>,
}

impl Window {
    pub const fn new(cap: u32, len: Duration) -> Self {
        Window {
            cap,
            len,
            state: Mutex::new(None),
        }
    }

    /// Count one event; `false` once the window's cap is exceeded.
    pub fn hit(&self) -> bool {
        self.hit_at(Instant::now())
    }

    fn hit_at(&self, now: Instant) -> bool {
        let mut g = super::lock(&self.state);
        let (start, n) = match *g {
            Some((t, n)) if now.saturating_duration_since(t) < self.len => (t, n),
            _ => (now, 0),
        };
        *g = Some((start, n.saturating_add(1)));
        n < self.cap
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests: a panic is the failure report")]
    use super::*;

    #[test]
    fn counter_caps_and_releases() {
        let c = Counter::default();
        let a = c.take(2).unwrap();
        let _b = c.take(2).unwrap();
        assert!(c.take(2).is_none());
        drop(a);
        assert!(c.take(2).is_some());
    }

    #[test]
    fn bucket_spends_and_refills() {
        let b = ByteBucket::new(1000);
        let t0 = Instant::now();
        assert!(b.spend_at(600, t0));
        assert!(!b.spend_at(600, t0), "only 400 left");
        assert!(b.spend_at(400, t0));
        assert!(
            b.spend_at(500, t0 + Duration::from_millis(500)),
            "refilled 500 in 0.5 s"
        );
        assert!(
            !b.spend_at(2000, t0 + Duration::from_secs(10)),
            "never above the burst"
        );
    }

    #[test]
    fn window_resets() {
        let w = Window::new(2, Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(w.hit_at(t0) && w.hit_at(t0));
        assert!(!w.hit_at(t0));
        assert!(w.hit_at(t0 + Duration::from_secs(61)));
    }
}
