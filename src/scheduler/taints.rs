//! Taint/toleration scheduling (CR-CTRL-9).
//!
//! Node taints are operator-managed, replicated via `SetNodeTaints` /
//! `RemoveNodeTaint`, and stored in the `node_taints` keyspace. Toleration
//! semantics follow K8s:
//! - `NoSchedule` / `NoExecute`: hard filter — a pod must tolerate every
//!   such taint on a node to be schedulable there.
//! - `PreferNoSchedule`: scoring penalty only, never a filter.
//! - `toleration_seconds` on a NoExecute toleration is enforced at runtime
//!   by the node controller (`plan_no_execute_evictions` below).
//!   `toleration_seconds == 0` means "tolerate indefinitely": proto3 cannot
//!   distinguish an absent int64 from zero, and the fail-safe direction is
//!   pods staying rather than churning.
use crate::raft::records::NodeTaint;
use crate::scheduler::Placement;
use fleetos_core::proto::fleetos::Toleration;

pub const EFFECT_NO_SCHEDULE: &str = "NoSchedule";
pub const EFFECT_PREFER_NO_SCHEDULE: &str = "PreferNoSchedule";
pub const EFFECT_NO_EXECUTE: &str = "NoExecute";

/// Score penalty per untolerated `PreferNoSchedule` taint (scales with the
/// topology score in the engine's ranking).
pub const PREFER_NO_SCHEDULE_PENALTY: f64 = 0.25;

/// K8s-style match of one toleration against one taint.
pub fn tolerates(tol: &Toleration, taint: &NodeTaint) -> bool {
    // An empty toleration effect matches any taint effect.
    if !tol.effect.is_empty() && tol.effect != taint.effect {
        return false;
    }
    // Empty key + Exists is the wildcard toleration (matches any key/value).
    if tol.key.is_empty() {
        return tol.operator == "Exists";
    }
    if tol.key != taint.key {
        return false;
    }
    match tol.operator.as_str() {
        "Exists" => true,
        // An empty operator defaults to Equal (K8s).
        "" | "Equal" => tol.value == taint.value,
        _ => false,
    }
}

/// True if any toleration covers the taint.
pub fn is_tolerated(tolerations: &[Toleration], taint: &NodeTaint) -> bool {
    tolerations.iter().any(|t| tolerates(t, taint))
}

/// Hard filter: pod passes iff it tolerates every NoSchedule/NoExecute taint.
pub fn passes_taint_filter(tolerations: &[Toleration], node_taints: &[NodeTaint]) -> bool {
    node_taints
        .iter()
        .filter(|t| t.effect == EFFECT_NO_SCHEDULE || t.effect == EFFECT_NO_EXECUTE)
        .all(|t| is_tolerated(tolerations, t))
}

/// Scoring input: number of untolerated PreferNoSchedule taints.
pub fn prefer_no_schedule_penalties(tolerations: &[Toleration], node_taints: &[NodeTaint]) -> u32 {
    node_taints
        .iter()
        .filter(|t| t.effect == EFFECT_PREFER_NO_SCHEDULE && !is_tolerated(tolerations, t))
        .count() as u32
}

/// Runtime NoExecute planning — the pure core of the node controller's
/// enforcement pass. For a node's NoExecute taints, returns the pod_ids that
/// must be evicted: untolerating pods immediately; tolerating pods once their
/// `toleration_seconds` grace has elapsed since `taint.time_added_unix`.
///
/// Deterministic: output sorted by pod_id.
pub fn plan_no_execute_evictions(
    now_unix: i64,
    node_taints: &[NodeTaint],
    node_placements: &[Placement],
    tolerations_for: &dyn Fn(&Placement) -> Vec<Toleration>,
) -> Vec<String> {
    let no_execute: Vec<&NodeTaint> = node_taints
        .iter()
        .filter(|t| t.effect == EFFECT_NO_EXECUTE)
        .collect();
    if no_execute.is_empty() {
        return Vec::new();
    }
    let mut evict = Vec::new();
    for placement in node_placements {
        let tolerations = tolerations_for(placement);
        for taint in &no_execute {
            let matching: Vec<&Toleration> =
                tolerations.iter().filter(|t| tolerates(t, taint)).collect();
            if matching.is_empty() {
                evict.push(placement.pod_id.clone());
                break;
            }
            // Most permissive matching toleration wins: any zero grace means
            // tolerate indefinitely; otherwise the largest grace applies.
            let mut indefinite = false;
            let mut max_grace: i64 = 0;
            for tol in &matching {
                if tol.toleration_seconds <= 0 {
                    indefinite = true;
                    break;
                }
                max_grace = max_grace.max(tol.toleration_seconds);
            }
            if !indefinite && now_unix - taint.time_added_unix > max_grace {
                evict.push(placement.pod_id.clone());
                break;
            }
        }
    }
    evict.sort();
    evict.dedup();
    evict
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::ResourceSpec;
    use fleetos_core::spiffe::SpiffeId;

    fn taint(key: &str, value: &str, effect: &str, added: i64) -> NodeTaint {
        NodeTaint {
            key: key.to_owned(),
            value: value.to_owned(),
            effect: effect.to_owned(),
            time_added_unix: added,
        }
    }

    fn tol(key: &str, op: &str, value: &str, effect: &str, seconds: i64) -> Toleration {
        Toleration {
            key: key.to_owned(),
            operator: op.to_owned(),
            value: value.to_owned(),
            effect: effect.to_owned(),
            toleration_seconds: seconds,
        }
    }

    fn placement(pod: &str) -> Placement {
        Placement {
            pod_id: pod.to_owned(),
            tenant_id: "t".to_owned(),
            service: "s".to_owned(),
            role: "r".to_owned(),
            ordinal: 0,
            node_id: "spiffe://t.internal/ns/system/node/n1"
                .parse::<SpiffeId>()
                .unwrap(),
            resources: ResourceSpec::zero(),
        }
    }

    #[test]
    fn toleration_matching_truth_table() {
        let t = taint("gpu", "a100", EFFECT_NO_SCHEDULE, 0);
        assert!(tolerates(
            &tol("gpu", "Equal", "a100", EFFECT_NO_SCHEDULE, 0),
            &t
        ));
        assert!(tolerates(
            &tol("gpu", "Exists", "", EFFECT_NO_SCHEDULE, 0),
            &t
        ));
        assert!(tolerates(&tol("gpu", "Equal", "a100", "", 0), &t)); // empty effect = any
        assert!(!tolerates(
            &tol("gpu", "Equal", "h100", EFFECT_NO_SCHEDULE, 0),
            &t
        ));
        assert!(!tolerates(
            &tol("gpu", "Equal", "a100", EFFECT_NO_EXECUTE, 0),
            &t
        ));
        assert!(!tolerates(&tol("other", "Exists", "", "", 0), &t));
        assert!(tolerates(&tol("", "Exists", "", "", 0), &t)); // wildcard
        assert!(!tolerates(&tol("", "Equal", "", "", 0), &t)); // wildcard needs Exists
        // Empty operator defaults to Equal.
        assert!(tolerates(&tol("gpu", "", "a100", "", 0), &t));
    }

    #[test]
    fn filter_requires_all_hard_taints_tolerated() {
        let taints = vec![
            taint("gpu", "a100", EFFECT_NO_SCHEDULE, 0),
            taint("maint", "", EFFECT_NO_EXECUTE, 0),
            taint("soft", "", EFFECT_PREFER_NO_SCHEDULE, 0),
        ];
        let both = vec![
            tol("gpu", "Exists", "", EFFECT_NO_SCHEDULE, 0),
            tol("maint", "Exists", "", EFFECT_NO_EXECUTE, 0),
        ];
        assert!(passes_taint_filter(&both, &taints));
        let only_gpu = vec![tol("gpu", "Exists", "", EFFECT_NO_SCHEDULE, 0)];
        assert!(!passes_taint_filter(&only_gpu, &taints));
        // PreferNoSchedule alone never blocks.
        assert!(passes_taint_filter(&[], &[taints[2].clone()]));
    }

    #[test]
    fn prefer_penalties_count_untolerated_only() {
        let taints = vec![
            taint("a", "", EFFECT_PREFER_NO_SCHEDULE, 0),
            taint("b", "", EFFECT_PREFER_NO_SCHEDULE, 0),
        ];
        let one = vec![tol("a", "Exists", "", EFFECT_PREFER_NO_SCHEDULE, 0)];
        assert_eq!(prefer_no_schedule_penalties(&one, &taints), 1);
        assert_eq!(prefer_no_schedule_penalties(&[], &taints), 2);
    }

    #[test]
    fn no_execute_eviction_matrix() {
        let taints = vec![taint("maint", "", EFFECT_NO_EXECUTE, 1_000)];
        let pods = vec![placement("pod-a"), placement("pod-b"), placement("pod-c")];
        // pod-a: no toleration -> immediate. pod-b: grace 500, expired at now=1600.
        // pod-c: zero grace -> indefinite.
        let lookup = |p: &Placement| -> Vec<Toleration> {
            match p.pod_id.as_str() {
                "pod-b" => vec![tol("maint", "Exists", "", EFFECT_NO_EXECUTE, 500)],
                "pod-c" => vec![tol("maint", "Exists", "", EFFECT_NO_EXECUTE, 0)],
                _ => vec![],
            }
        };
        let at_1400 = plan_no_execute_evictions(1_400, &taints, &pods, &lookup);
        assert_eq!(at_1400, vec!["pod-a".to_owned()]); // grace not yet elapsed
        let at_1600 = plan_no_execute_evictions(1_600, &taints, &pods, &lookup);
        assert_eq!(at_1600, vec!["pod-a".to_owned(), "pod-b".to_owned()]);
    }

    #[test]
    fn no_eviction_without_no_execute() {
        let taints = vec![taint("x", "", EFFECT_NO_SCHEDULE, 0)];
        let pods = vec![placement("pod-a")];
        let lookup = |_p: &Placement| vec![];
        assert!(plan_no_execute_evictions(9_999, &taints, &pods, &lookup).is_empty());
    }
}
