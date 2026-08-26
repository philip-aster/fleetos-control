//! Hard invariant: eBPF ABI layouts must match fleetos-ebpf-common exactly.
//!
//! Alignment of `EbpfPolicyKey` is 2 (not 1) because `HostOrderPort` is
//! `#[repr(transparent)]` over `u16`. Do not attempt to force alignment 1
//! by replacing the newtype with `[u8; 2]` — that amputates the byte-order
//! safety invariant.

#[test]
fn abi_layouts_match() {
    // Compile-time assertions inside fleetos-ebpf-common
    fleetos_ebpf_common::assert_layouts();

    // Runtime verification of sizes and alignments
    assert_eq!(
        core::mem::size_of::<fleetos_ebpf_common::EbpfPolicyKey>(),
        40,
        "EbpfPolicyKey must be exactly 40 bytes"
    );
    assert_eq!(
        core::mem::align_of::<fleetos_ebpf_common::EbpfPolicyKey>(),
        2,
        "EbpfPolicyKey alignment must be 2 (HostOrderPort is u16)"
    );

    assert_eq!(
        core::mem::size_of::<fleetos_ebpf_common::EbpfPolicyWildcardKey>(),
        32,
        "EbpfPolicyWildcardKey must be exactly 32 bytes"
    );
    assert_eq!(
        core::mem::align_of::<fleetos_ebpf_common::EbpfPolicyWildcardKey>(),
        1,
        "EbpfPolicyWildcardKey alignment must be 1 (no u16 fields)"
    );

    assert_eq!(
        core::mem::size_of::<fleetos_ebpf_common::EbpfPolicyValue>(),
        16,
        "EbpfPolicyValue must be exactly 16 bytes"
    );

    assert_eq!(
        core::mem::size_of::<fleetos_ebpf_common::DummyIpRouteValue>(),
        40,
        "DummyIpRouteValue must be exactly 40 bytes"
    );
    assert_eq!(
        core::mem::align_of::<fleetos_ebpf_common::DummyIpRouteValue>(),
        8,
        "DummyIpRouteValue alignment must be 8 (contains u64)"
    );

    assert_eq!(
        core::mem::size_of::<fleetos_ebpf_common::SockStateValue>(),
        32,
        "SockStateValue must be exactly 32 bytes"
    );
}
