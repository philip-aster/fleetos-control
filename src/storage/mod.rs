pub mod keys;

pub use keys::KeyBuilder;
use redb::TableDefinition;

/// Redb Table Definitions shared across OpenRaft state machine and control plane storage
pub const RAFT_LOG_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("raft_log");
pub const STATE_MACHINE_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("state_machine");
pub const HARD_STATE_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("hard_state");
