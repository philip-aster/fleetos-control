pub mod dispatcher;

use crate::grpc::state_service::FleetStateService;
pub use dispatcher::PodDispatcher;
use fleetos_core::{PodSpec, RuntimeEngine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

// Node capacity and capability profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub spiffe_id: String,
    pub total_vcpus: u32,
    pub available_vcpus: u32,
    pub total_memory_mb: u64,
    pub available_memory_mb: u64,
    pub supports_hypervisor: bool,
    pub supports_containerd: bool,
}

pub struct FleetScheduler {
    dispatcher: PodDispatcher,
}

impl FleetScheduler {
    pub fn new(state_service: Arc<FleetStateService>) -> Self {
        Self {
            dispatcher: PodDispatcher::new(state_service),
        }
    }

    /// Evaluates node resource constraints and runtime capability compatibility
    pub fn select_node<'a>(
        &self,
        pod: &PodSpec,
        nodes: &'a HashMap<String, NodeInfo>,
    ) -> Result<&'a NodeInfo, String> {
        let required_vcpus = match &pod.runtime {
            RuntimeEngine::CloudHypervisor(cfg) => cfg.vcpus,
            RuntimeEngine::Containerd(_) => 1,
        };

        let required_memory_mb = match &pod.runtime {
            RuntimeEngine::CloudHypervisor(cfg) => cfg.memory_mb,
            RuntimeEngine::Containerd(_) => 512,
        };

        let mut eligible_nodes: Vec<(&String, &NodeInfo)> = nodes
            .iter()
            .filter(|(_, node)| {
                let runtime_supported = match &pod.runtime {
                    RuntimeEngine::CloudHypervisor(_) => node.supports_hypervisor,
                    RuntimeEngine::Containerd(_) => node.supports_containerd,
                };

                runtime_supported
                    && node.available_vcpus >= required_vcpus
                    && node.available_memory_mb >= required_memory_mb
            })
            .collect();

        if eligible_nodes.is_empty() {
            return Err(format!(
                "No eligible nodes found matching constraints for Pod '{}' (Runtime: {:?})",
                pod.id, pod.runtime
            ));
        }

        // Least-Allocated placement strategy:
        // Primary sort: Available RAM (descending)
        // Secondary sort: Available vCPUs (descending)
        eligible_nodes.sort_by(|a, b| {
            b.1.available_memory_mb
                .cmp(&a.1.available_memory_mb)
                .then_with(|| b.1.available_vcpus.cmp(&a.1.available_vcpus))
        });

        Ok(eligible_nodes.first().unwrap().1)
    }

    /// Schedules a PodSpec by selecting a node and handing off to PodDispatcher
    pub async fn schedule_pod(
        &self,
        pod: PodSpec,
        nodes: &HashMap<String, NodeInfo>,
    ) -> Result<(String, u64), String> {
        let target_node = self.select_node(&pod, nodes)?;
        let target_node_id = target_node.node_id.clone();

        let revision = self.dispatcher.dispatch_pod(&target_node_id, pod).await?;

        Ok((target_node_id, revision))
    }
}
