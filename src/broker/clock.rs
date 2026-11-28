//! Dual-clock deadlines (SPEC §4.1): every deadline has a monotonic **and** a wall-clock expiry; either one passing
//! means expired, so a wall clock stepped backwards never extends it. A wall-vs-monotonic gap larger than the idle
//! timeout means the machine was suspended → seal on wake.

use std::time::{Duration, Instant, SystemTime};

#[derive(Clone, Copy, Debug)]
pub struct Deadline {
    mono: Instant,
    wall: SystemTime,
}

impl Deadline {
    pub fn after(d: Duration) -> Deadline {
        let now_m = Instant::now();
        let now_w = SystemTime::now();
        Deadline {
            mono: now_m.checked_add(d).unwrap_or(now_m),
            wall: now_w.checked_add(d).unwrap_or(now_w),
        }
    }

    pub fn expired(&self) -> bool {
        Instant::now() >= self.mono || SystemTime::now() >= self.wall
    }

    /// Time left by the stricter of the two clocks.
    pub fn remaining(&self) -> Duration {
        let m = self.mono.saturating_duration_since(Instant::now());
        let w = self
            .wall
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO);
        m.min(w)
    }
}

/// Detects suspend: monotonic clocks (CLOCK_MONOTONIC / mach uptime) stop during sleep, the wall clock doesn't.
pub struct SuspendWatch {
    last_m: Instant,
    last_w: SystemTime,
}

impl SuspendWatch {
    pub fn new() -> Self {
        SuspendWatch {
            last_m: Instant::now(),
            last_w: SystemTime::now(),
        }
    }

    /// True if, since the previous call, the wall clock advanced more than the monotonic clock by over `limit`.
    pub fn suspended_longer_than(&mut self, limit: Duration) -> bool {
        let (m, w) = (Instant::now(), SystemTime::now());
        let dm = m.saturating_duration_since(self.last_m);
        let dw = w.duration_since(self.last_w).unwrap_or(Duration::ZERO);
        self.last_m = m;
        self.last_w = w;
        dw.saturating_sub(dm) > limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadlines() {
        let d = Deadline::after(Duration::from_millis(30));
        assert!(!d.expired());
        assert!(d.remaining() <= Duration::from_millis(30));
        std::thread::sleep(Duration::from_millis(40));
        assert!(d.expired());
        assert_eq!(d.remaining(), Duration::ZERO);
    }

    #[test]
    fn wall_clock_alone_expires_it() {
        // simulate a wall clock that has already passed (e.g. set forward): either clock expiring is enough
        let d = Deadline {
            mono: Instant::now() + Duration::from_secs(3600),
            wall: SystemTime::now() - Duration::from_secs(1),
        };
        assert!(d.expired());
        let d = Deadline {
            mono: Instant::now() - Duration::from_secs(1),
            wall: SystemTime::now() + Duration::from_secs(3600),
        };
        assert!(
            d.expired(),
            "a wall clock set back never extends the deadline"
        );
    }

    #[test]
    fn suspend_gap() {
        let mut s = SuspendWatch::new();
        assert!(!s.suspended_longer_than(Duration::from_secs(1)));
        s.last_w = SystemTime::now() - Duration::from_secs(120); // as if 2 min passed while asleep
        assert!(s.suspended_longer_than(Duration::from_secs(60)));
    }
}
