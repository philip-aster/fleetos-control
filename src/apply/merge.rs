use fleetos_core::proto::apply::{
    FieldConflict, ManifestNodePoolSpec, ManifestSagRuleSpec, ManifestSecretSpec,
    ManifestTenantSpec, ManifestWorkloadSpec,
};
use fleetos_core::proto::workload::WorkloadSpec;
use prost::Message;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeOutcome {
    Updated(Vec<u8>),
    Unchanged,
    Conflicted(Vec<FieldConflict>),
}

fn conflict(path: &str, live: &str, manifest: &str, last: &str) -> FieldConflict {
    FieldConflict {
        field_path: path.to_string(),
        live_value: live.to_string(),
        manifest_value: manifest.to_string(),
        last_applied_value: last.to_string(),
    }
}

// src/apply/merge.rs

pub fn merge_workload(
    manifest: &ManifestWorkloadSpec,
    live_bytes: &[u8],
    last_applied_bytes: &[u8],
) -> MergeOutcome {
    let mut live: WorkloadSpec = if live_bytes.is_empty() {
        WorkloadSpec::default()
    } else {
        WorkloadSpec::decode(live_bytes).unwrap_or_default()
    };

    // FIX: Decode as ManifestWorkloadSpec, not WorkloadSpec
    let last: ManifestWorkloadSpec = if last_applied_bytes.is_empty() {
        ManifestWorkloadSpec::default()
    } else {
        ManifestWorkloadSpec::decode(last_applied_bytes).unwrap_or_default()
    };

    let mut conflicts = Vec::new();
    let mut changed = false;

    // 1. Image
    if let Some(ref img) = manifest.image {
        let last_img = last.image.clone().unwrap_or_default();
        if live.image != last_img && live.image != *img {
            conflicts.push(conflict("image", &live.image, img, &last_img));
        } else if live.image != *img {
            live.image = img.clone();
            changed = true;
        }
    }

    // 2. Replicas
    if !manifest.replicas.is_empty() {
        let last_replicas = last.replicas.clone();
        if live.replicas != last_replicas && live.replicas != manifest.replicas {
            conflicts.push(conflict(
                "replicas",
                &format!("{:?}", live.replicas),
                &format!("{:?}", manifest.replicas),
                &format!("{:?}", last_replicas),
            ));
        } else if live.replicas != manifest.replicas {
            live.replicas = manifest.replicas.clone();
            changed = true;
        }
    }

    // 3. PodSpec (Invariant: explicitly strip/ignore trusted fields)
    if let Some(ref manifest_pod) = manifest.pod_spec {
        let mut live_pod = live.pod_spec.unwrap_or_default();
        let last_pod = last.pod_spec.clone().unwrap_or_default();

        // Resources
        if manifest_pod.resources.is_some() {
            let last_resources = last_pod.resources.clone();
            if live_pod.resources != last_resources && live_pod.resources != manifest_pod.resources
            {
                conflicts.push(conflict(
                    "pod_spec.resources",
                    &format!("{:?}", live_pod.resources),
                    &format!("{:?}", manifest_pod.resources),
                    &format!("{:?}", last_resources),
                ));
            } else if live_pod.resources != manifest_pod.resources {
                live_pod.resources = manifest_pod.resources.clone();
                changed = true;
            }
        }

        // Env
        if !manifest_pod.env.is_empty() {
            let last_env = last_pod.env.clone();
            if live_pod.env != last_env && live_pod.env != manifest_pod.env {
                conflicts.push(conflict(
                    "pod_spec.env",
                    &format!("{:?}", live_pod.env),
                    &format!("{:?}", manifest_pod.env),
                    &format!("{:?}", last_env),
                ));
            } else if live_pod.env != manifest_pod.env {
                live_pod.env = manifest_pod.env.clone();
                changed = true;
            }
        }

        // Labels
        if !manifest_pod.labels.is_empty() {
            let last_labels = last_pod.labels.clone();
            if live_pod.labels != last_labels && live_pod.labels != manifest_pod.labels {
                conflicts.push(conflict(
                    "pod_spec.labels",
                    &format!("{:?}", live_pod.labels),
                    &format!("{:?}", manifest_pod.labels),
                    &format!("{:?}", last_labels),
                ));
            } else if live_pod.labels != manifest_pod.labels {
                live_pod.labels = manifest_pod.labels.clone();
                changed = true;
            }
        }

        live.pod_spec = Some(live_pod);
    }

    // 4. Placement
    if let Some(p) = manifest.placement {
        let last_placement = last.placement.unwrap_or_default();
        if live.placement != last_placement && live.placement != p {
            conflicts.push(conflict(
                "placement",
                &live.placement.to_string(),
                &p.to_string(),
                &last_placement.to_string(),
            ));
        } else if live.placement != p {
            live.placement = p;
            changed = true;
        }
    }

    // 5. Autoscaling
    if manifest.autoscaling.is_some() {
        let last_autoscaling = last.autoscaling.clone();
        if live.autoscaling != last_autoscaling && live.autoscaling != manifest.autoscaling {
            conflicts.push(conflict(
                "autoscaling",
                &format!("{:?}", live.autoscaling),
                &format!("{:?}", manifest.autoscaling),
                &format!("{:?}", last_autoscaling),
            ));
        } else if live.autoscaling != manifest.autoscaling {
            live.autoscaling = manifest.autoscaling.clone();
            changed = true;
        }
    }

    if !conflicts.is_empty() {
        return MergeOutcome::Conflicted(conflicts);
    }
    if changed {
        MergeOutcome::Updated(live.encode_to_vec())
    } else {
        MergeOutcome::Unchanged
    }
}

pub fn merge_tenant(
    _manifest: &ManifestTenantSpec,
    _live_bytes: &[u8],
    _last_applied_bytes: &[u8],
) -> MergeOutcome {
    // Tenant creation currently only requires tenant_id (in Manifest.name).
    // No mutable fields in ManifestTenantSpec yet.
    MergeOutcome::Unchanged
}

pub fn merge_sag_rule(
    manifest: &ManifestSagRuleSpec,
    live_bytes: &[u8],
    last_applied_bytes: &[u8],
) -> MergeOutcome {
    use fleetos_core::proto::state::SagRule;
    let mut live: SagRule = if live_bytes.is_empty() {
        SagRule::default()
    } else {
        SagRule::decode(live_bytes).unwrap_or_default()
    };
    let last: SagRule = if last_applied_bytes.is_empty() {
        SagRule::default()
    } else {
        SagRule::decode(last_applied_bytes).unwrap_or_default()
    };

    let mut conflicts = Vec::new();
    let mut changed = false;

    if let Some(ref from) = manifest.from {
        if live.from != last.from && live.from != Some(from.clone()) {
            conflicts.push(conflict(
                "from",
                &format!("{:?}", live.from),
                &format!("{:?}", from),
                &format!("{:?}", last.from),
            ));
        } else if live.from != Some(from.clone()) {
            live.from = Some(from.clone());
            changed = true;
        }
    }

    if let Some(ref to) = manifest.to {
        if live.to != last.to && live.to != Some(to.clone()) {
            conflicts.push(conflict(
                "to",
                &format!("{:?}", live.to),
                &format!("{:?}", to),
                &format!("{:?}", last.to),
            ));
        } else if live.to != Some(to.clone()) {
            live.to = Some(to.clone());
            changed = true;
        }
    }

    if let Some(action) = manifest.action {
        let live_action = live.action;
        let last_action = last.action;
        if live_action != last_action && live_action != action {
            conflicts.push(conflict(
                "action",
                &live_action.to_string(),
                &action.to_string(),
                &last_action.to_string(),
            ));
        } else if live_action != action {
            live.action = action;
            changed = true;
        }
    }

    if !conflicts.is_empty() {
        return MergeOutcome::Conflicted(conflicts);
    }

    if changed {
        MergeOutcome::Updated(live.encode_to_vec())
    } else {
        MergeOutcome::Unchanged
    }
}

pub fn merge_secret(
    manifest: &ManifestSecretSpec,
    live_bytes: &[u8],
    _last_applied_bytes: &[u8],
) -> MergeOutcome {
    // Secrets are encrypted at rest. We treat authorized_spiffe_ids as the mergeable state.
    // A full implementation would decode the ACL, check conflicts, and re-encrypt.
    // For now, if the manifest specifies new IDs or a value, we flag it as updated.
    if manifest.value.is_some() || !manifest.authorized_spiffe_ids.is_empty() {
        return MergeOutcome::Updated(live_bytes.to_vec());
    }
    MergeOutcome::Unchanged
}

pub fn merge_node_pool(
    manifest: &ManifestNodePoolSpec,
    live_bytes: &[u8],
    last_applied_bytes: &[u8],
) -> MergeOutcome {
    use crate::provisioning::NodePoolRecord;

    let mut live: NodePoolRecord = if live_bytes.is_empty() {
        return MergeOutcome::Unchanged;
    } else {
        postcard::from_bytes(live_bytes).unwrap_or_else(|_| NodePoolRecord {
            pool_id: String::new(),
            node_kind: crate::attestation::join_token::NodeKind::Agent,
            desired_count: 0,
            vcpus: 0,
            memory_mb: 0,
            disk_gb: 0,
            region_hint: String::new(),
            last_applied_bytes: vec![],
        })
    };

    let last: NodePoolRecord = if last_applied_bytes.is_empty() {
        live.clone()
    } else {
        postcard::from_bytes(last_applied_bytes).unwrap_or_else(|_| live.clone())
    };

    let mut conflicts = Vec::new();
    let mut changed = false;

    if let Some(count) = manifest.desired_count {
        if live.desired_count != last.desired_count && live.desired_count != count {
            conflicts.push(conflict(
                "desired_count",
                &live.desired_count.to_string(),
                &count.to_string(),
                &last.desired_count.to_string(),
            ));
        } else if live.desired_count != count {
            live.desired_count = count;
            changed = true;
        }
    }

    if let Some(vcpus) = manifest.vcpus {
        if live.vcpus != last.vcpus && live.vcpus != vcpus {
            conflicts.push(conflict(
                "vcpus",
                &live.vcpus.to_string(),
                &vcpus.to_string(),
                &last.vcpus.to_string(),
            ));
        } else if live.vcpus != vcpus {
            live.vcpus = vcpus;
            changed = true;
        }
    }

    if let Some(mem) = manifest.memory_mb {
        if live.memory_mb != last.memory_mb && live.memory_mb != mem {
            conflicts.push(conflict(
                "memory_mb",
                &live.memory_mb.to_string(),
                &mem.to_string(),
                &last.memory_mb.to_string(),
            ));
        } else if live.memory_mb != mem {
            live.memory_mb = mem;
            changed = true;
        }
    }

    if let Some(disk) = manifest.disk_gb {
        if live.disk_gb != last.disk_gb && live.disk_gb != disk {
            conflicts.push(conflict(
                "disk_gb",
                &live.disk_gb.to_string(),
                &disk.to_string(),
                &last.disk_gb.to_string(),
            ));
        } else if live.disk_gb != disk {
            live.disk_gb = disk;
            changed = true;
        }
    }

    if let Some(ref region) = manifest.region_hint {
        if live.region_hint != last.region_hint && live.region_hint != *region {
            conflicts.push(conflict(
                "region_hint",
                &live.region_hint,
                region,
                &last.region_hint,
            ));
        } else if live.region_hint != *region {
            live.region_hint = region.clone();
            changed = true;
        }
    }

    if !conflicts.is_empty() {
        return MergeOutcome::Conflicted(conflicts);
    }

    if changed {
        MergeOutcome::Updated(postcard::to_allocvec(&live).unwrap_or_default())
    } else {
        MergeOutcome::Unchanged
    }
}
