//! Serialization helpers for Raft log entries.

use openraft::Entry;
use postcard::{from_bytes, to_allocvec};

use super::FleetosRaftConfig;
use crate::raft::error::RaftError;

pub fn serialize_entry(entry: &Entry<FleetosRaftConfig>) -> Result<Vec<u8>, RaftError> {
    to_allocvec(entry).map_err(RaftError::Serialization)
}

pub fn deserialize_entry(bytes: &[u8]) -> Result<Entry<FleetosRaftConfig>, RaftError> {
    from_bytes(bytes).map_err(RaftError::Serialization)
}
