use std::time::Duration;

/// Retry delays for waiting on the database: 1s, 2s, 4s, then 5s forever.
pub struct Backoff {
    next: Duration,
}

impl Backoff {
    const MAX: Duration = Duration::from_secs(5);

    pub fn new() -> Self {
        Self {
            next: Duration::from_secs(1),
        }
    }

    pub fn next_delay(&mut self) -> Duration {
        let delay = self.next;
        self.next = (self.next * 2).min(Self::MAX);
        delay
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delays_double_then_cap_at_five_seconds() {
        let mut b = Backoff::new();
        let got: Vec<u64> = (0..6).map(|_| b.next_delay().as_secs()).collect();
        assert_eq!(got, vec![1, 2, 4, 5, 5, 5]);
    }
}
