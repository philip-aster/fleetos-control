/// Helper utility functions for centralizing Redb/OpenRaft storage key formatting
pub struct KeyBuilder;

impl KeyBuilder {
    // --- Pod Keys ---

    /// Key for a pending/unscheduled Pod Spec: `/pods/pending/{pod_id}`
    pub fn pod_pending(pod_id: &str) -> String {
        format!("/pods/pending/{}", pod_id)
    }

    /// Prefix for scanning all pending Pod Specs: `/pods/pending/`
    pub fn pod_pending_prefix() -> &'static str {
        "/pods/pending/"
    }

    /// Key for a scheduled Pod Spec bound to a node: `/pods/assigned/{node_id}/{pod_id}`
    pub fn pod_assigned(node_id: &str, pod_id: &str) -> String {
        format!("/pods/assigned/{}/{}", node_id, pod_id)
    }

    /// Prefix for scanning all Pod Specs assigned to a specific node: `/pods/assigned/{node_id}/`
    pub fn pod_assigned_node_prefix(node_id: &str) -> String {
        format!("/pods/assigned/{}/", node_id)
    }

    // --- Node Keys ---

    /// Prefix for scanning all node state entries: `/nodes/`
    pub fn node_prefix() -> &'static str {
        "/nodes/"
    }

    /// Key for node registration/capacity profile info: `/nodes/{node_id}/info`
    pub fn node_info(node_id: &str) -> String {
        format!("/nodes/{}/info", node_id)
    }

    /// Key for node heartbeat epoch timestamp: `/nodes/{node_id}/heartbeat`
    pub fn node_heartbeat(node_id: &str) -> String {
        format!("/nodes/{}/heartbeat", node_id)
    }

    /// Key for node health status (HEALTHY, UNHEALTHY, DEGRADED): `/nodes/{node_id}/status`
    pub fn node_status(node_id: &str) -> String {
        format!("/nodes/{}/status", node_id)
    }

    // --- Policy & Secret Keys ---

    /// Key for policy definitions: `/policies/{key}`
    pub fn policy(key: &str) -> String {
        format!("/policies/{}", key)
    }

    /// Prefix for policy definitions: `/policies/`
    pub fn policy_prefix() -> &'static str {
        "/policies/"
    }

    /// Key for secret rotation schedules: `/secrets/rotation/{secret_id}`
    pub fn secret_rotation(secret_id: &str) -> String {
        format!("/secrets/rotation/{}", secret_id)
    }

    /// Prefix for secret rotation schedules: `/secrets/rotation/`
    pub fn secret_rotation_prefix() -> &'static str {
        "/secrets/rotation/"
    }

    /// Key for secret rotation signal events: `/secrets/signals/{secret_id}/rotate`
    pub fn secret_signal_rotate(secret_id: &str) -> String {
        format!("/secrets/signals/{}/rotate", secret_id)
    }
}
