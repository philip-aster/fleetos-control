# fleetos-control

https://img.shields.io/badge/license-Apache--2.0-blue.svg

`fleetos-control` is the control-plane brain of FleetOS, a Rust-based
container and MicroVM orchestrator designed to replace Kubernetes. A single
binary consolidates what Kubernetes splits across `kube-apiserver`, `etcd`,
`scheduler`, and `controller-manager`, replicated by Raft across a small
(3–5 node) control cluster.

FleetOS is a **dark overlay**: control nodes never expose inbound scrape or
management endpoints. Every listener is mTLS-only with SPIFFE identity,
telemetry is pushed outbound over OTLP, and the single outbound exception is
a gRPC dial to the cloud provider's provisioning shim.

## Position in FleetOS

| Crate | Role |
|---|---|
| `fleetos-core` | Frozen primitives: SPIFFE identity, BLAKE3 fingerprints, SAG policy schema, proto definitions, attestation contracts. This crate builds against it and never redefines its types. |
| `fleetos-ebpf` / `fleetos-ebpf-common` | Frozen kernel enforcement plane and shared eBPF ABI layouts (`EbpfPolicyKey`, `DummyIpRouteValue`, …). |
| **`fleetos-control`** | **This crate** — the replicated control plane. |
| `fleetos-agent` | Per-node executor: runs workloads, enforces eBPF policy, attests, fetches secrets, acquires delegated keys. |
| `fleetos-router` / `fleetos-gateway` | Identity-aware routing and egress. |
| `fleetctl-proxy` | The only Admin-API client (operator-facing). |

`fleetos-control` owns: consensus and replicated state, scheduling,
certificate issuance (dual CAs), node attestation, SAG policy compilation,
secrets, node lifecycle, delegation (degraded mode), and provisioning.

## Core design principles

- **All writes go through Raft.** Application keyspaces are mutated only by
  the state machine applying `FleetosCommand` entries. Services and
  controllers propose; they never write storage directly. This invariant is
  audited and test-enforced.
- **Atomic-apply.** Each applied entry commits mutation + `MonotonicVersion`
  increment + audit record in one `fjall` write batch. Watch streams are
  notified only after commit, so subscribers never observe non-durable state.
- **Fail-closed everywhere.** Missing identity, unavailable CA, storage
  error, unknown EK, missing PCR policy, unmatched grant — all rejected.
- **Structural guarantees over documented conventions.** Security properties
  are enforced by types, feature gates, and tests — not by comments.
  (Example: the insecure join path is compiled out of production builds, not
  merely discouraged.)
- **Leader-gated controllers.** Reconciliation loops run only on the Raft
  leader and are cancelled on leadership loss.

## Architecture

### Consensus

`openraft` over `fjall` log storage. The internal Raft transport
(`src/raft/raft.proto`) ships postcard-serialized openraft types inside a
generic `RaftRpc` envelope over mTLS gRPC: `AppendEntries`, `Vote`,
`InstallSnapshot`, and `RequestJoin`.

New control nodes join self-service via `RequestJoin`: added as a learner
(blocking until caught up — including snapshot transfer), then promoted to
voter, with leader redirects handled automatically. Snapshots are triggered
every 10,000 applied entries (`snapshot_logs_since_last`) with 1024-entry
purge batches; snapshot install restores every application keyspace in one
atomic batch.

### State machine

`FjallStateMachine` applies ~30 command variants (tenants, workloads, cron,
SAG rules, secrets + ACLs, nodes, evictions, delegations, dummy-IP
allocations, ordinals, placements, SVID versions, EK registry, PCR policies,
operator grants, quotas, workload status, audit-bearing proposals). After
each commit it publishes `SagUpdateEvent`, `ScheduleUpdateEvent`,
`RouteUpdateEvent`, and `WatchEvent`s into the `BroadcastHub`, which feeds
the gRPC watch streams.

Every command can carry an `AuditContext` (G-2/G-3): the audit record is
written in the **same batch** as the mutation it describes, keyed by the
allocated `MonotonicVersion`.

### Module map

| Module | Contents |
|---|---|
| `raft/` | openraft config, fjall log storage, state machine, snapshot builder, TLS transport, `RaftTransport` server |
| `storage/` | fjall database + keyspace initialization, composite key schemas, `VersionedState` (MonotonicVersion) |
| `ca/` | Dual root CAs, SVID signing (`rcgen`), URI NameConstraints, delegated key issuance, SVID renewal (G-5), `CaService` gRPC |
| `attestation/` | Nonce manager (rate-capped), join-token store, PCR policies, EK certificate chain validation (SHA-256-pinned manufacturer roots), `AttestationService` gRPC |
| `admin/` | `AdminService` gRPC — the only surface for `fleetctl-proxy` and operators |
| `controllers/` | Leader-gated workload / pod / node / cron reconcilers |
| `scheduler/` | Filter+score engine (capacity, anti-affinity, topology spread, bin-packing), read-only ordinal tracker |
| `policy/` | SAG → eBPF entry compilation, precedence, port validation, fingerprint wrapper, staleness |
| `watch/` | `BroadcastHub` + gRPC streams: PolicyService, WatchService, SchedulerService, RouterAssignmentService, SecretService, WorkloadStatusService, DelegationService |
| `secrets/` | Envelope encryption at rest (DEK per secret), SPIFFE-ID ACL matrix |
| `delegation/` | Delegation records, IDs, revocation store |
| `dummy_ip/` | `240.0.0.0/4` allocation math (tenant blocks, service addresses) |
| `provisioning/` | Outbound-only cloud provider client; CONTROL-pool membership management |
| `tls/` | rustls config builders, dual trust-domain validation, dynamic cert resolvers |
| `join.rs` | Secure (TPM credential activation) and fenced-insecure join client + membership request |
| `telemetry.rs` | OTLP push providers + control-plane metric registration |
| `revocation.rs` | Revoked-SVID check used by the mTLS listeners |

## Identity and security model

- **Two trust domains, two independent root CAs** — blast-radius isolation:
  Data/Control (`fleet.example.internal`: nodes, workloads, routers,
  gateways, control peers) and Admin (`fleet-admin.example.internal`:
  `fleetctl-proxy`, operators). Trust-domain routing is structural: which
  listener a connection arrived on decides which bundle validates it.
- **Join flow (secure mode, production):** TPM 2.0 credential activation —
  EK registered out-of-band, `RequestActivation` issues a
  `TPM2_MakeCredential` challenge, the node proves EK possession, submits an
  HMAC activation proof + signed quote bound to the server nonce + CSR, and
  control verifies the quote signature and PCR policy before signing the
  node SVID. EK manufacturer roots are pinned by SHA-256 fingerprint; a
  swapped `.der` fails `cargo test`.
- **Insecure mode is fenced (R-1):** the join-token-only path fabricates no
  quote in production builds — it is compiled out under
  `--features production`, and a production binary refuses to boot with
  `mode = "insecure"` unless `allow_insecure_attestation = true` is set
  (loudly warned, testing-only).
- **SVID lifecycle:** short TTLs (default 1 h), versioned per SPIFFE ID
  through Raft (`UpsertSvidVersion`). Control renews its own SVIDs at 50 %
  of TTL by hot-swapping dynamic TLS resolvers without dropping connections.
- **Revocation (G-4 / CR-5):** evicting a node atomically marks it evicted,
  revokes **all** its delegations, removes its placements, and records its
  SVID in the revoked set — one Raft entry. The revoked set is broadcast via
  `WatchSag`, and every mTLS listener rejects revoked peers fail-closed.

### Degraded mode: delegated signing (CR-16)

When the control plane is unreachable, a hosting node can renew workload
SVIDs locally with a delegated signing key:

- `DelegationService` (Data/Control listener) is the node-callable path.
  Fail-closed authz chain: unauthenticated → `UNAUTHENTICATED`; non-node
  kind → `PERMISSION_DENIED`; caller ≠ requested `node_svid` →
  `PERMISSION_DENIED`. The authenticated identity is always the principal —
  the claimed field is never trusted.
- `AdminService.RequestDelegatedKey` is the cluster-admin/operator override.
- Both entry points issue through one code path
  (`ca::key_issuance::issue_delegated_key` + `StoragePlacementVerifier`):
  placement-verified, `pathLenConstraint = 0`, URI NameConstraints bound to
  the trust domain, TTL-capped, refresh at 75 % of TTL.
- Issuance replicates as `IssueDelegation` with an audit context naming the
  node actor; leader redirects return `leader-dc-address` metadata.

### Secrets

Two layers, both owned here: envelope encryption at rest (per-secret DEK
wrapped by a master key — survives recipient SVID rotation) and a SPIFFE-ID
ACL matrix checked **before** any decryption happens. Delivery is sealed
point-to-point (`fleetos_core::crypto::seal`, X25519 + ChaCha20-Poly1305)
against the requester's current SVID version with a monotonic sequence for
replay protection.

## gRPC surface

| Listener | Auth | Services |
|---|---|---|
| Data/Control (`listeners.data_control`) | mTLS with **optional** client auth (pre-SVID join flow); unauthenticated reachability rejected fail-closed per service | `PolicyService` (WatchSag), `WatchService` (WatchEvents), `SchedulerService` (WatchSchedule), `RouterAssignmentService` (WatchRoutes), `SecretService` (FetchSecret), `WorkloadStatusService`, `AttestationService`, `CaService`, `DelegationService` |
| Admin (`listeners.admin`) | Strict mTLS, Admin trust domain, `ctrl`/`operator` kinds only | `AdminService` — tenants, workloads, cron, SAG rules, secrets + ACLs, delegated-key override, node cordon/evict, quotas, node pools, EK register/revoke, PCR policies, operator JIT grants, audit log, join tokens, cluster status |
| Raft (`listeners.raft`) | Strict mTLS, `control` kind only | `RaftTransport` — AppendEntries, Vote, InstallSnapshot, RequestJoin |

## Controllers

| Controller | Responsibility |
|---|---|
| Workload | Expands `WorkloadSpec` → `PodSpec`s, schedules them, records ordinal assignments and placements via Raft. Unconditionally overwrites the six trusted fields (`tenant_id`, `workload_id`, `role`, `image`, `ordinal`, `pod_id`) — caller-submitted values are a tenant-isolation bypass. |
| Pod | Detects dead pods (missing placement, `live=false`, or stale status report) and replaces them **in place** via `ReassignPodId`; frees ordinal slots on scale-down. |
| Node | Heartbeat-lease death detection → eviction cascade (delegations + placements + SVID revocation, atomic). |
| Cron | Evaluates cron schedules against replicated checkpoints (G-11); triggers runs atomically with checkpoint advance — no double-trigger or lost runs across failover. |

## Scheduling

Deterministic filter → score pipeline (Raft-consistent across control
nodes): schedulable + capacity + anti-affinity filters, then topology-spread
and most-allocated bin-packing scores. **Ordinal stability invariant:**
`(service, role, ordinal)` is a stable slot replaced in place on failure —
never a fungible pool where a dead replica is replaced at the next free
ordinal.

## Dummy-IP addressing

Workloads dial reserved-space addresses (`240.0.0.0/4`) that map to SPIFFE
identities; eBPF on the agents performs the rewrite. Control allocates a
`/16` block per tenant (up to 4,096 tenants — never default to `/8`) and one
address per `(service, role)` pair, both Raft-replicated atomically with the
tenant/placement state they belong to.

## Provisioning

Outbound-only, poll-based client to an externally implemented
`ProvisioningService` shim. Node pools are Raft-replicated records; join
tokens are minted fresh per reconcile cycle. CONTROL pools drive openraft
membership changes directly, with a quorum guard (G-15) that refuses voter
removals that would break the cluster.

## Telemetry

Push-only OTLP (metrics, traces, logs) — consistent with the no-open-ports
rule. Registered metrics: Raft node ID / term / leadership / last-applied
index, current `MonotonicVersion`, per-stream watch subscriber counts,
uptime.

## Feature flags

| Feature | Description |
|---|---|
| (default) | Base build — insecure attestation available for development. |
| `ca` | CA implementation (rcgen/rustls). |
| `tpm` | TPM 2.0 quote verification and credential activation (requires system `tpm2-tss` libraries). |
| `apple-se` | Apple Secure Enclave attestation (macOS only). |
| `production` | `ca` + `tpm` + `apple-se`. Compiles the insecure join path **out** of the binary and refuses to boot with insecure attestation unless explicitly opted in. |

## Configuration

See `control.example.toml`. Key sections: `cluster` (`bootstrap` vs `join`
mode), `trust_domains`, `svid` TTL policy (owned here, not in
`fleetos-core`), `dummy_ip`, `secrets` (master key path), `attestation`
(mode + join-token TTL + the production opt-in), `tpm` backend, `listeners`,
`health` lease timings, `raft` tuning, `operators` (CR-8 JIT bootstrap
admins), `provisioning`, `telemetry`, `graceful_shutdown`.

## Build, run, test

```bash
cargo build --features production
cargo test  --features production
fleetos-control --config control.example.toml
```

- **Bootstrap** (`cluster.mode = "bootstrap"`): one-time first control node.
  Generates both CA roots, forms a single-node Raft cluster. Never run twice.
- **Join** (`cluster.mode = "join"`): attest to an existing control node
  (secure TPM credential activation), receive an SVID and the trust bundle,
  request membership, catch up via snapshot/log replication, promote to voter.

## Hard-invariant test suite

Invariants are locked by dedicated tests in `tests/`:

| Test | Invariant |
|---|---|
| `eviction_cascade.rs` | Eviction revokes all delegations + placements + the node SVID atomically |
| `join_token_single_use.rs`, `join_token_cluster_single_use.rs` | Join tokens are strictly single-use, cluster-wide (V-2) |
| `placement_verification.rs` | Delegated keys only for nodes that host the target workload |
| `ordinal_stability.rs` | Kill pod at ordinal N → replacement is N, driven through the Raft state machine |
| `snapshot_round_trip.rs` | Snapshot → install reproduces all application state |
| `multi_node_replication.rs` | 3-node cluster replicates commands to every node |
| `join_flow_real_transport.rs` | E14/R-3: snapshot transfer and secure join (attestation → membership) over real rustls mTLS + tonic |
| `tls_join_wiring.rs` | Join legs are TLS (`https`), configs build, control SVIDs carry the DNS SAN |
| `template_overwrite.rs` | The six trusted fields are unconditionally overwritten |
| `fingerprint_of_only.rs` | `of_with_ordinal` never appears in this crate |
| `port_range_rejection.rs` | `uint32` ports > 65535 are rejected, not truncated |
| `delegation_revocation.rs`, `atomic_broadcast.rs`, `secret_rotation_event.rs`, `svid_rotation_events.rs` | Revocation one-to-many; broadcast atomicity; rotation events carry the target identity |
| `ebpf_abi_layouts.rs` | eBPF ABI layouts match `fleetos-ebpf-common` exactly |

## License

Licensed under the Apache License, Version 2.0. See the `LICENSE` file.
