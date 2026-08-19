//! redb table definitions.
//!
//! All tables live in a single redb database file. Table namespaces:
//!   - `raft_log_*`       — openraft log storage
//!   - `raft_state_*`     — openraft state machine
//!   - `app_*`            — application state (nodes, SVIDs, SAG, tokens, etc.)

use redb::TableDefinition;

// ---------------------------------------------------------------------------
// Version tracking
// ---------------------------------------------------------------------------

/// Stores the current MonotonicVersion as a single u64 LE-encoded value.
pub const VERSION_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("app_version");

// ---------------------------------------------------------------------------
// Raft log storage (openraft)
// ---------------------------------------------------------------------------

/// Raft log entries. Key: log index (u64). Value: serialized entry (postcard).
pub const RAFT_LOG_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("raft_log");

/// Raft log metadata (last flushed, purged prefix, etc.).
pub const RAFT_LOG_META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("raft_log_meta");

// ---------------------------------------------------------------------------
// Raft state machine (openraft)
// ---------------------------------------------------------------------------

/// State machine key-value pairs. Key: arbitrary bytes. Value: serialized value.
pub const RAFT_STATE_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("raft_state");

/// Raft snapshots. Key: snapshot index. Value: serialized snapshot (postcard).
pub const RAFT_SNAPSHOT_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("raft_snapshot");

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

/// Node registry. Key: node SpiffeId (UTF-8). Value: serialized NodeRecord.
pub const NODE_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("app_nodes");

/// SVID registry. Key: SVID SpiffeId (UTF-8). Value: serialized SvidRecord.
pub const SVID_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("app_svids");

/// SAG policies. Key: SagRuleId (UTF-8). Value: serialized SagRule.
pub const SAG_RULE_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("app_sag_rules");

/// Join tokens. Key: token hash (UTF-8). Value: serialized JoinTokenRecord.
pub const JOIN_TOKEN_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("app_join_tokens");

/// Delegation revocations.
/// Key: composite `node_id || delegation_id` (see schema.rs).
/// Value: revocation timestamp (u64 LE).
pub const REVOKED_DELEGATION_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("app_revoked_delegations");

/// Active delegations (issued but not yet revoked/expired).
/// Key: composite `node_id || delegation_id`.
/// Value: serialized DelegatedSigningKey metadata.
pub const ACTIVE_DELEGATION_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("app_active_delegations");

/// Scheduler state: ordinal assignments.
/// Key: `(tenant, service, role, ordinal)` serialized. Value: PodId.
pub const ORDINAL_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("app_ordinals");

/// Workload placements. Key: PodId (UTF-8). Value: serialized placement.
pub const PLACEMENT_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("app_placements");

/// Tenant registry. Key: TenantId (UTF-8). Value: serialized TenantRecord.
pub const TENANT_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("app_tenants");

/// WorkloadSpec registry. Key: WorkloadId (UTF-8). Value: serialized WorkloadSpec.
pub const WORKLOAD_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("app_workloads");

/// Secrets at-rest. Key: secret key (UTF-8). Value: envelope-encrypted blob.
pub const SECRET_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("app_secrets");

/// Dummy-IP allocations. Key: tenant + service. Value: allocated IP (u32 LE).
pub const DUMMY_IP_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("app_dummy_ips");

/// PCR policies per node. Key: node SpiffeId. Value: expected PCR values.
pub const PCR_POLICY_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("app_pcr_policies");

/// Router assignments. Key: agent node SpiffeId. Value: serialized router assignment.
pub const ROUTER_ASSIGNMENT_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("app_router_assignments");
