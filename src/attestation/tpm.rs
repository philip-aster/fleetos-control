//! TPM attestation types — owned by `fleetos-core` (CR-14).
//!
//! `TpmQuote` and `PcrValue` are re-exported from core so the join and
//! insecure-attestation paths keep compiling against a single canonical
//! definition. The TPM I/O (`make_credential`) and signature verification
//! (`verify_quote_signature`) implementations live in core; control only
//! orchestrates them.

pub use fleetos_core::attestation::PcrValue;
pub use fleetos_core::attestation::quote::TpmQuote;

/// Control-side glue: map `[tpm]` config to core's backend descriptor.
/// Kept here (not in core) so core never imports control types.
impl From<&crate::config::TpmConfig> for fleetos_core::attestation::tpm::TpmEndpoint {
    fn from(config: &crate::config::TpmConfig) -> Self {
        use crate::config::TpmBackend;
        match config.backend {
            TpmBackend::Device => fleetos_core::attestation::tpm::TpmEndpoint::Device {
                path: config.device_path.clone(),
            },
            TpmBackend::Swtpm => fleetos_core::attestation::tpm::TpmEndpoint::Swtpm {
                host: config.host.clone(),
                port: config.port,
            },
            TpmBackend::Mssim => fleetos_core::attestation::tpm::TpmEndpoint::Mssim {
                host: config.host.clone(),
                port: config.port,
            },
        }
    }
}
