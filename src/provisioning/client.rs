//! Outbound-only gRPC client to the cloud provider's ProvisioningService.
//!
//! We dial the provider's shim over gRPC. The shim is outside the dark overlay,
//! in standard network space. This is the one and only exception to FleetOS's
//! no-open-ports rule, and it is outbound-only from our perspective.

use fleetos_core::proto::provisioning::{
    NodePoolId, NodePoolSpec, NodePoolStatus, ProvisioningServiceClient, ResourceSpec,
};
use tonic::transport::Channel;

use super::{NodePoolRecord, ProvisioningError, node_kind_to_proto};

/// Outbound-only gRPC client to the provider's ProvisioningService.
pub struct ProvisioningClient {
    client: ProvisioningServiceClient<Channel>,
}

impl ProvisioningClient {
    /// Create a new client connected to the provider endpoint.
    ///
    /// The endpoint is a standard gRPC address (e.g., "http://provider:50051").
    /// The provider shim is outside the dark overlay, so this uses standard
    /// gRPC transport (not mTLS with SPIFFE SVIDs).
    pub async fn connect(endpoint: &str) -> Result<Self, ProvisioningError> {
        let channel = Channel::from_shared(endpoint.to_owned())
            .map_err(|e| ProvisioningError::InvalidEndpoint(e.to_string()))?
            .connect()
            .await?;

        Ok(Self {
            client: ProvisioningServiceClient::new(channel),
        })
    }

    /// Push desired state to the provider.
    ///
    /// The provider creates/destroys nodes to match `desired_count`.
    /// The `bootstrap_payload` is passed through to provisioned nodes untouched.
    pub async fn reconcile_node_pool(
        &mut self,
        record: &NodePoolRecord,
        bootstrap_payload: Vec<u8>,
    ) -> Result<NodePoolStatus, ProvisioningError> {
        let spec = NodePoolSpec {
            pool_id: record.pool_id.clone(),
            node_kind: node_kind_to_proto(&record.node_kind),
            desired_count: record.desired_count,
            resources: Some(ResourceSpec {
                vcpus: record.vcpus,
                memory_mb: record.memory_mb,
                disk_gb: record.disk_gb,
            }),
            region_hint: record.region_hint.clone(),
            bootstrap_payload,
        };

        let response = self.client.reconcile_node_pool(spec).await?;

        Ok(response.into_inner())
    }

    /// Pull actual state from the provider.
    ///
    /// Returns the list of provisioned nodes and their lifecycle states.
    pub async fn get_node_pool_status(
        &mut self,
        pool_id: &str,
    ) -> Result<NodePoolStatus, ProvisioningError> {
        let request = NodePoolId {
            pool_id: pool_id.to_owned(),
        };

        let response = self.client.get_node_pool_status(request).await?;

        Ok(response.into_inner())
    }

    /// Tear down a node pool.
    pub async fn delete_node_pool(&mut self, pool_id: &str) -> Result<(), ProvisioningError> {
        let request = NodePoolId {
            pool_id: pool_id.to_owned(),
        };

        self.client.delete_node_pool(request).await?;
        Ok(())
    }
}
