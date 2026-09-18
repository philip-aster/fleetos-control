//! CR-CTRL-6: Disruption budget guard.
//!
//! Structural seam consulted by every disruptive mutation (HPA scale-down,
//! node eviction/drain, workload delete). The guard evaluates against
//! committed state at proposal time; because all disruptions are proposed
//! through the leader and serialized by the Raft log, budget checks are
//! linearizable for free — no separate in-memory lock.
//!
//! Semantics (per the CR-CTRL-6 directive):
//! - A budget declares `min_available` OR `max_unavailable` (mutually
//!   exclusive; setting both is rejected at admission). Either may be an
//!   absolute count or a percentage of the role's desired replica count.
//! - `max_unavailable` is normalized to `min_available = desired - max_unavailable`
//!   so the guard has one code path. Percentages round UP for `min_available`
//!   and DOWN for `max_unavailable` (fail-closed on ambiguity).
//! - No budget declared for a role ⇒ unbounded disruption allowed.

use crate::storage::StorageEngine;
use fleetos_core::proto::workload::DisruptionBudget;
use fleetos_core::spiffe::WorkloadRole;
use fleetos_core::tenant::TenantId;
use std::sync::Arc;
use thiserror::Error;

/// The kind of disruptive mutation being requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisruptionTarget {
    /// Node eviction / drain (removes all placements on the node).
    Eviction,
    /// HPA or manual scale-down (reduces a role's replica count).
    ScaleDown,
    /// Workload deletion (scale-to-zero).
    Delete,
    /// VPA vertical resize (replaces pods at a new footprint).
    VerticalResize,
}

/// Why a disruption was denied. Carries enough state for the caller to
/// compute a partial allowance (`current_healthy - min_available`).
#[derive(Debug, Clone, Error)]
#[error(
    "disruption denied: min_available={min_available}, current_healthy={current_healthy}, requested={requested}, forced={forced}"
)]
pub struct DisruptionDenied {
    pub min_available: u32,
    pub current_healthy: u32,
    pub requested: u32,
    pub forced: bool,
}

/// The disruption guard seam. Both eviction and HPA hold an
/// `Arc<dyn DisruptionGuard>` and never call budget logic inline.
pub trait DisruptionGuard: Send + Sync {
    /// May the caller disrupt `count` pods of `(tenant, workload, role)`?
    fn allow_disruption(
        &self,
        tenant: &TenantId,
        workload: &str,
        role: &WorkloadRole,
        count: u32,
        target: DisruptionTarget,
    ) -> Result<(), DisruptionDenied>;
}

/// No-op guard: always allows. Wired in by default until a budget-backed
/// guard is configured; swaps in under the same trait.
pub struct NoopDisruptionGuard;

impl DisruptionGuard for NoopDisruptionGuard {
    fn allow_disruption(
        &self,
        _tenant: &TenantId,
        _workload: &str,
        _role: &WorkloadRole,
        _count: u32,
        _target: DisruptionTarget,
    ) -> Result<(), DisruptionDenied> {
        Ok(())
    }
}

/// Budget-backed guard: evaluates the workload's `DisruptionBudget` for the
/// target role against committed placement state.
pub struct BudgetBackedDisruptionGuard {
    storage: Arc<StorageEngine>,
}

impl BudgetBackedDisruptionGuard {
    pub fn new(storage: Arc<StorageEngine>) -> Self {
        Self { storage }
    }

    /// Count currently-placed pods for `(tenant, workload, role)`.
    // NOTE: counts placements as the healthy proxy. Refine to intersect with
    // reported-ready status once that signal is wired through here.
    fn count_placed(
        &self,
        tenant: &TenantId,
        workload: &str,
        role: &WorkloadRole,
    ) -> Result<u32, DisruptionDenied> {
        let placements = self
            .storage
            .list_placements()
            .map_err(|_| DisruptionDenied {
                min_available: 0,
                current_healthy: 0,
                requested: 0,
                forced: false,
            })?;
        let n = placements
            .iter()
            .filter(|p| {
                p.tenant_id == tenant.as_str() && p.service == workload && p.role == role.as_str()
            })
            .count();
        Ok(n as u32)
    }
}

impl DisruptionGuard for BudgetBackedDisruptionGuard {
    fn allow_disruption(
        &self,
        tenant: &TenantId,
        workload: &str,
        role: &WorkloadRole,
        count: u32,
        _target: DisruptionTarget,
    ) -> Result<(), DisruptionDenied> {
        // Load + decode the workload spec.
        let raw = self
            .storage
            .get_workload_spec(tenant.as_str(), workload)
            .map_err(|_| deny(0, 0, count))?;
        let raw = match raw {
            Some(r) => r,
            None => return Ok(()), // Unknown workload ⇒ nothing to protect.
        };
        let spec: fleetos_core::proto::workload::WorkloadSpec =
            prost::Message::decode(raw.as_slice()).map_err(|_| deny(0, 0, count))?;

        let role_str = role.as_str();

        // No budget declared for this role ⇒ unbounded disruption allowed.
        let budget = match spec.budgets.get(role_str) {
            Some(b) => b,
            None => return Ok(()),
        };
        // Budget present but empty (no policy set) ⇒ treat as unbounded.
        if budget.policy.is_none() {
            return Ok(());
        }

        let desired = spec.replicas.get(role_str).copied().unwrap_or(0);

        // Resolve to a single min_available; fail-closed if unresolvable.
        let min_available =
            resolve_min_available(budget, desired).ok_or_else(|| deny(0, 0, count))?;

        let current_healthy = self.count_placed(tenant, workload, role)?;

        if current_healthy.saturating_sub(count) < min_available {
            return Err(DisruptionDenied {
                min_available,
                current_healthy,
                requested: count,
                forced: false,
            });
        }
        Ok(())
    }
}

fn deny(min_available: u32, current_healthy: u32, requested: u32) -> DisruptionDenied {
    DisruptionDenied {
        min_available,
        current_healthy,
        requested,
        forced: false,
    }
}

/// Resolve a budget to an absolute `min_available`.
/// Returns `None` when the budget is unresolvable (fail-closed at the caller).
fn resolve_min_available(budget: &DisruptionBudget, desired: u32) -> Option<u32> {
    use fleetos_core::proto::fleetos::disruption_budget::Policy;
    use fleetos_core::proto::fleetos::disruption_budget_value::Value;

    match budget.policy.as_ref()? {
        Policy::MinAvailable(v) => match v.value.as_ref()? {
            Value::Count(c) => Some(*c),
            Value::Percent(p) => {
                if *p > 100 {
                    return None;
                }
                // Round UP.
                Some(((desired as u64 * *p as u64 + 99) / 100) as u32)
            }
        },
        Policy::MaxUnavailable(v) => {
            let max_unavailable = match v.value.as_ref()? {
                Value::Count(c) => *c,
                Value::Percent(p) => {
                    if *p > 100 {
                        return None;
                    }
                    // Round DOWN.
                    ((desired as u64 * *p as u64) / 100) as u32
                }
            };
            // Normalize to min_available.
            Some(desired.saturating_sub(max_unavailable))
        }
    }
}
