use std::ops::ControlFlow;

use chrono::{DateTime, Duration, Utc};

use crate::Error;

/// /// A policy for retrying API requests
///
/// Refresh the order state repeatedly, waiting `delay` before the first attempt and increasing
/// the delay by a factor of `backoff` after each attempt, until the `timeout` is reached.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    delay: Duration,
    backoff: f32,
    timeout: Duration,
}

impl RetryPolicy {
    /// A constructor for the default `RetryPolicy`
    ///
    /// Will retry for ``timeout`` with an initial delay of ``delay`` and a backoff factor of ``backoff``.
    #[must_use]
    pub const fn new(delay: Duration, backoff: f32, timeout: Duration) -> Self {
        Self {
            delay,
            backoff,
            timeout,
        }
    }

    /// Set the initial delay
    ///
    /// This is the delay before the first retry attempt. The delay will be multiplied by the
    /// backoff factor after each attempt.
    #[must_use]
    pub const fn initial_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    /// Set the backoff factor
    ///
    /// The delay will be multiplied by this factor after each retry attempt.
    #[must_use]
    pub const fn backoff(mut self, backoff: f32) -> Self {
        self.backoff = backoff;
        self
    }

    /// Set the timeout for retries
    ///
    /// After this duration has passed, no more retries will be attempted.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub(crate) fn state(&self) -> RetryState {
        RetryState {
            delay: self.delay,
            backoff: self.backoff,
            deadline: Utc::now() + self.timeout,
        }
    }
}

impl Default for RetryPolicy {
    /// A constructor for the default `RetryPolicy`
    ///
    /// Will retry for 30s with an initial delay of 250ms and a backoff factor of 2.0.
    fn default() -> Self {
        Self {
            delay: Duration::milliseconds(250),
            backoff: 2.0,
            timeout: Duration::seconds(30),
        }
    }
}

pub struct RetryState {
    delay: Duration,
    backoff: f32,
    deadline: DateTime<Utc>,
}

impl RetryState {
    pub async fn wait(&mut self, after: Option<DateTime<Utc>>) -> ControlFlow<Error, ()> {
        let now = Utc::now();

        if let Some(after) = after {
            let delay = after.signed_duration_since(now);
            let next = now + delay;

            if next > self.deadline {
                return ControlFlow::<Error, ()>::Break(Error::Timeout(next));
            }

            let Ok(delay) = delay.to_std() else {
                return ControlFlow::<Error, ()>::Break(Error::Timeout(next));
            };

            tokio::time::sleep(delay).await;
            return ControlFlow::Continue(());
        }

        if let Some(ns) = self.delay.num_nanoseconds() {
            #[allow(clippy::cast_precision_loss)]
            let scaled = (ns as f64 * f64::from(self.backoff)).round();

            // clamp to valid range
            #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
            let scaled = scaled.max(i64::MIN as f64).min(i64::MAX as f64) as i64;

            self.delay = chrono::Duration::nanoseconds(scaled);
        }

        let next = now + self.delay;

        if next > self.deadline {
            ControlFlow::Break(Error::Timeout(next))
        } else {
            ControlFlow::Continue(())
        }
    }
}
