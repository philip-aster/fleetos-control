use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// High-level Pod specification representing a workload unit on FleetOS
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PodSpec {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub role: PodRole,
    pub runtime: RuntimeEngine,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
    pub containers: Vec<ContainerSpec>,
    pub volumes: Vec<VolumeSpec>,
    pub restart_policy: RestartPolicy,
}

/// Execution role and security boundaries assigned to a Pod
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PodRole {
    /// Role identifier (e.g. "worker-node", "ingress-router", "database-agent")
    pub role_name: String,
    /// Attested SPIFFE ID constraint for identity verification
    pub spiffe_id: Option<String>,
    /// Allowed capability set
    pub capabilities: Vec<String>,
    /// System User / Group under which the workload executes
    pub run_as_user: Option<u32>,
    pub run_as_group: Option<u32>,
}

impl Default for PodRole {
    fn default() -> Self {
        Self {
            role_name: "default".to_string(),
            spiffe_id: None,
            capabilities: Vec::new(),
            run_as_user: Some(1000),
            run_as_group: Some(1000),
        }
    }
}

/// Workload Runtime Engine backing FleetOS execution
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuntimeEngine {
    /// MicroVM isolation backed by CloudHypervisor
    CloudHypervisor(CloudHypervisorConfig),
    /// OCI container isolation backed by Containerd
    Containerd(ContainerdConfig),
}

/// CloudHypervisor MicroVM configuration parameters
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CloudHypervisorConfig {
    pub vcpus: u32,
    pub memory_mb: u64,
    pub kernel_path: String,
    pub initrd_path: Option<String>,
    pub cmdline: String,
    pub enable_sev: bool,
    pub enable_sgx: bool,
    pub vsock_cid: Option<u32>,
}

impl Default for CloudHypervisorConfig {
    fn default() -> Self {
        Self {
            vcpus: 2,
            memory_mb: 2048,
            kernel_path: "/var/lib/fleetos/kernels/vmlinux".to_string(),
            initrd_path: None,
            cmdline: "console=ttyS0 console=hvc0 root=/dev/vda rw quiet".to_string(),
            enable_sev: false,
            enable_sgx: false,
            vsock_cid: None,
        }
    }
}

/// Containerd OCI runtime configuration parameters
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContainerdConfig {
    pub snapshotter: String,
    pub runtime_type: String,
    pub cgroup_parent: Option<String>,
    pub privileged: bool,
}

impl Default for ContainerdConfig {
    fn default() -> Self {
        Self {
            snapshotter: "overlayfs".to_string(),
            runtime_type: "io.containerd.runc.v2".to_string(),
            cgroup_parent: None,
            privileged: false,
        }
    }
}

/// Container specification running inside a pod
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContainerSpec {
    pub name: String,
    pub image: String,
    pub command: Vec<String>,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub volume_mounts: Vec<VolumeMount>,
    pub resources: ResourceRequirements,
}

/// Resource constraints for container workloads
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceRequirements {
    pub cpu_shares: Option<u32>,
    pub memory_limit_mb: Option<u64>,
}

/// Storage volume specification attached to a workload
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VolumeSpec {
    pub name: String,
    pub volume_type: VolumeType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VolumeType {
    /// Virtiofs shared directory backing (MicroVM)
    VirtioFs { host_path: String, tag: String },
    /// Virtio block storage backing
    BlockDevice { path: String, read_only: bool },
    /// Standard host path bind mount (Containerd)
    HostPath { host_path: String },
    /// Ephemeral memory-backed temp volume
    TmpFs { size_mb: u64 },
}

/// Mounting volume mapping into a container
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VolumeMount {
    pub name: String,
    pub mount_path: String,
    pub read_only: bool,
}

/// Pod lifecycle restart behavior
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RestartPolicy {
    Always,
    OnFailure,
    Never,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self::Always
    }
}
