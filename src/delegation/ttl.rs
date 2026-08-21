//! Delegation TTL management.
//!
//! Delegations have a 4-hour TTL with refresh triggered at 75% elapsed (3 hours).
//! While the control plane is reachable, agents continuously refresh their
//! delegations so they always have a fresh key.
//!
//! During a control-plane outage, the agent uses its most recent delegation
//! to renew workload SVIDs locally (degraded mode).

use time::{Duration, OffsetDateTime};

/// Delegation TTL configuration.
///
/// These values are owned by `fleetos-control` (in `control.example.toml`),
/// not `fleetos-core`.
#[derive(Debug, Clone, Copy)]
pub struct DelegationTtlConfig {
    /// Total TTL for a delegation (4 hours).
    pub ttl: Duration,

    /// Fraction of TTL at which refresh is triggered (0.75 = 75%).
    pub refresh_fraction: f64,
}

impl Default for DelegationTtlConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::hours(4),
            refresh_fraction: 0.75,
        }
    }
}

impl DelegationTtlConfig {
    /// Compute the refresh time (when the delegation should be renewed).
    pub fn refresh_at(&self, issued_at: OffsetDateTime) -> OffsetDateTime {
        let refresh_duration = self.ttl * self.refresh_fraction;
        issued_at + refresh_duration
    }

    /// Compute the expiry time.
    pub fn expires_at(&self, issued_at: OffsetDateTime) -> OffsetDateTime {
        issued_at + self.ttl
    }

    /// Check if a delegation issued at `issued_at` should be refreshed now.
    pub fn should_refresh(&self, issued_at: OffsetDateTime) -> bool {
        let now = OffsetDateTime::now_utc();
        let refresh_time = self.refresh_at(issued_at);
        now >= refresh_time
    }

    /// Check if a delegation issued at `issued_at` has expired.
    pub fn is_expired(&self, issued_at: OffsetDateTime) -> bool {
        let now = OffsetDateTime::now_utc();
        let expiry_time = self.expires_at(issued_at);
        now >= expiry_time
    }

    /// Remaining time until refresh is needed.
    pub fn time_until_refresh(&self, issued_at: OffsetDateTime) -> Duration {
        let now = OffsetDateTime::now_utc();
        let refresh_time = self.refresh_at(issued_at);
        (refresh_time - now).max(Duration::ZERO)
    }

    /// Remaining time until expiry.
    pub fn time_until_expiry(&self, issued_at: OffsetDateTime) -> Duration {
        let now = OffsetDateTime::now_utc();
        let expiry_time = self.expires_at(issued_at);
        (expiry_time - now).max(Duration::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values() {
        let config = DelegationTtlConfig::default();
        assert_eq!(config.ttl, Duration::hours(4));
        assert_eq!(config.refresh_fraction, 0.75);
    }

    #[test]
    fn refresh_at_is_75_percent() {
        let config = DelegationTtlConfig::default();
        let issued_at = OffsetDateTime::now_utc();
        let refresh_at = config.refresh_at(issued_at);

        let expected = issued_at + Duration::hours(3);
        assert_eq!(refresh_at, expected);
    }

    #[test]
    fn expires_at_is_full_ttl() {
        let config = DelegationTtlConfig::default();
        let issued_at = OffsetDateTime::now_utc();
        let expires_at = config.expires_at(issued_at);

        let expected = issued_at + Duration::hours(4);
        assert_eq!(expires_at, expected);
    }

    #[test]
    fn should_refresh_after_75_percent() {
        let config = DelegationTtlConfig::default();
        let issued_at = OffsetDateTime::now_utc() - Duration::hours(3) - Duration::minutes(1);

        assert!(config.should_refresh(issued_at));
    }

    #[test]
    fn should_not_refresh_before_75_percent() {
        let config = DelegationTtlConfig::default();
        let issued_at = OffsetDateTime::now_utc() - Duration::hours(2);

        assert!(!config.should_refresh(issued_at));
    }

    #[test]
    fn is_expired_after_full_ttl() {
        let config = DelegationTtlConfig::default();
        let issued_at = OffsetDateTime::now_utc() - Duration::hours(4) - Duration::minutes(1);

        assert!(config.is_expired(issued_at));
    }

    #[test]
    fn is_not_expired_before_ttl() {
        let config = DelegationTtlConfig::default();
        let issued_at = OffsetDateTime::now_utc() - Duration::hours(3);

        assert!(!config.is_expired(issued_at));
    }
}
