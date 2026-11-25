// Prospective r.bing-only controller retry. No wire/transport policy is here.
use std::time::Duration;

pub(super) const CELL_BYTES: u64 = 600;
pub(super) const WINDOW: Duration = Duration::from_micros(5_000);
const RETRY_QUANTUM: Duration = Duration::from_micros(250);
const DIAGNOSTIC_RETRY_QUANTUM: Duration = Duration::from_millis(5);

pub(super) fn window() -> Duration {
    if std::env::var_os("QCSD_RBING_INCOMING_WINDOW_1S").is_some() {
        Duration::from_secs(1)
    } else {
        WINDOW
    }
}

/// A future allocation wake, capped at the ORIGINAL exclusive deadline.
/// The deadline wake expires the cell; it never authorizes an allocation.
pub(super) fn next_wake(release: Duration, now: Duration) -> Option<Duration> {
    let deadline = release.checked_add(window())?;
    if now < release || now >= deadline {
        return None;
    }
    let quantum = if std::env::var_os("QCSD_RBING_INCOMING_WINDOW_1S").is_some() {
        DIAGNOSTIC_RETRY_QUANTUM
    } else {
        RETRY_QUANTUM
    };
    Some(now.checked_add(quantum)?.min(deadline))
}

/// All uncommitted allocation bytes must be accounted for before reuse.
pub(super) fn complete_rollback(remaining: u64, credit: Option<u64>, claims: Option<u64>) -> bool {
    remaining > 0
        && remaining <= CELL_BYTES
        && credit
            .and_then(|credit| claims.and_then(|claims| credit.checked_add(claims)))
            .and_then(|staged| remaining.checked_add(staged))
            == Some(CELL_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_are_strictly_future_and_never_extend_the_original_window() {
        let release = Duration::from_micros(1_000);
        let mut now = release;
        let deadline = release + WINDOW;
        let mut wakes = 0;
        while let Some(next) = next_wake(release, now) {
            assert!(next > now && next <= deadline);
            now = next;
            wakes += 1;
        }
        assert_eq!(wakes, 20);
        assert_eq!(now, deadline);
    }

    #[test]
    fn deadline_and_late_callbacks_cannot_allocate_or_restart_window() {
        let release = Duration::from_micros(100);
        for now in [release + WINDOW, release + WINDOW + Duration::from_nanos(1)] {
            assert_eq!(next_wake(release, now), None);
        }
        assert_eq!(next_wake(release, release - Duration::from_nanos(1)), None);
    }

    #[test]
    fn sub_quantum_tail_wakes_at_original_deadline_only() {
        let release = Duration::from_micros(100);
        assert_eq!(
            next_wake(release, release + WINDOW - Duration::from_nanos(1)),
            Some(release + WINDOW)
        );
    }

    #[test]
    fn duration_overflow_is_a_refusal() {
        assert_eq!(next_wake(Duration::MAX, Duration::MAX), None);
    }

    #[test]
    fn rollback_requires_the_entire_original_six_hundred_bytes() {
        for (remaining, credit, claims) in
            [(600, 0, 0), (500, 100, 0), (100, 200, 300), (1, 299, 300)]
        {
            assert!(complete_rollback(remaining, Some(credit), Some(claims)));
        }
        for (remaining, credit, claims) in [
            (0, 600, 0),
            (601, 0, 0),
            (500, 99, 0),
            (500, 101, 0),
            (100, u64::MAX, 1),
        ] {
            assert!(!complete_rollback(remaining, Some(credit), Some(claims)));
        }
        assert!(!complete_rollback(600, None, Some(0)));
        assert!(!complete_rollback(600, Some(0), None));
    }
}
