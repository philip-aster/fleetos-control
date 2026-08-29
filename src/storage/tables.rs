//! fjall keyspace name constants.
//!
//! All keyspaces live in a single fjall database directory.

// Version tracking
pub const VERSION_KEYSPACE: &str = "app_version";

// Raft log storage
pub const RAFT_LOG_KEYSPACE: &str = "raft_log";
pub const RAFT_LOG_META_KEYSPACE: &str = "raft_log_meta";

// Raft state machine
pub const RAFT_STATE_KEYSPACE: &str = "raft_state";
pub const RAFT_SNAPSHOT_KEYSPACE: &str = "raft_snapshot";

// Application state
pub const NODE_KEYSPACE: &str = "app_nodes";
pub const SVID_KEYSPACE: &str = "app_svids";
pub const SAG_RULE_KEYSPACE: &str = "app_sag_rules";
pub const JOIN_TOKEN_KEYSPACE: &str = "app_join_tokens";
pub const REVOKED_DELEGATION_KEYSPACE: &str = "app_revoked_delegations";
pub const ACTIVE_DELEGATION_KEYSPACE: &str = "app_active_delegations";
pub const ORDINAL_KEYSPACE: &str = "app_ordinals";
pub const PLACEMENT_KEYSPACE: &str = "app_placements";
pub const TENANT_KEYSPACE: &str = "app_tenants";
pub const WORKLOAD_KEYSPACE: &str = "app_workloads";
pub const SECRET_KEYSPACE: &str = "app_secrets";
pub const DUMMY_IP_KEYSPACE: &str = "app_dummy_ips";
pub const PCR_POLICY_KEYSPACE: &str = "app_pcr_policies";
pub const ROUTER_ASSIGNMENT_KEYSPACE: &str = "app_router_assignments";
pub const NODE_POOL_KEYSPACE: &str = "node_pools";
pub const TRUST_BUNDLE_KEYSPACE: &str = "app_trust_bundles";
pub const NONCE_KEYSPACE: &str = "app_nonces";
pub const NONCE_CLAIM_KEYSPACE: &str = "app_nonce_claims";
pub const SVID_GRANT_KEYSPACE: &str = "app_svid_grants";
pub const REVOKED_SVID_KEYSPACE: &str = "app_revoked_svids";
pub const AUDIT_LOG_KEYSPACE: &str = "app_audit_log";
pub const CRON_CHECKPOINT_KEYSPACE: &str = "app_cron_checkpoints";
pub const OPERATOR_GRANT_KEYSPACE: &str = "app_operator_grants";
pub const WORKLOAD_STATUS_KEYSPACE: &str = "app_workload_status";
