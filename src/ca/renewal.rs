//! Control-plane SVID renewal (G-5).
//!
//! Runs a background loop that regenerates the node's keypair, signs a new
//! SVID via the local CA, and hot-swaps the certificate in the dynamic TLS
//! resolvers — without dropping existing connections.

use parking_lot::RwLock;
use std::sync::Arc;
use tokio::sync::watch;

use crate::ca::rcgen_impl::{self, SvidKind, SvidParams};
use crate::ca::trust_bundle::TrustBundle;
use crate::tls::mtls::{self, DynamicCertResolver};

/// Holds everything the renewal loop needs.
pub struct ControlSvidRenewer {
    node_name: String,
    dc_trust_domain: String,
    admin_trust_domain: String,
    node_ttl_secs: u64,
    admin_ttl_secs: u64,

    ca_data_control: Arc<RwLock<TrustBundle>>,
    ca_admin: Option<Arc<RwLock<TrustBundle>>>,

    dc_resolver: Arc<DynamicCertResolver>,
    raft_resolver: Arc<DynamicCertResolver>,
    admin_resolver: Option<Arc<DynamicCertResolver>>,
}

impl ControlSvidRenewer {
    pub fn new(
        node_name: String,
        dc_trust_domain: String,
        admin_trust_domain: String,
        node_ttl_secs: u64,
        admin_ttl_secs: u64,
        ca_data_control: Arc<RwLock<TrustBundle>>,
        ca_admin: Option<Arc<RwLock<TrustBundle>>>,
        dc_resolver: Arc<DynamicCertResolver>,
        raft_resolver: Arc<DynamicCertResolver>,
        admin_resolver: Option<Arc<DynamicCertResolver>>,
    ) -> Self {
        Self {
            node_name,
            dc_trust_domain,
            admin_trust_domain,
            node_ttl_secs,
            admin_ttl_secs,
            ca_data_control,
            ca_admin,
            dc_resolver,
            raft_resolver,
            admin_resolver,
        }
    }

    /// Run the renewal loop. Wakes at 50% of TTL to renew with margin.
    pub async fn run_loop(&self, mut shutdown: watch::Receiver<bool>) {
        let refresh_secs = self.node_ttl_secs / 2;
        let refresh_duration = std::time::Duration::from_secs(refresh_secs);

        loop {
            tracing::info!(
                refresh_in_secs = refresh_secs,
                "control SVID renewal scheduled"
            );

            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("control SVID renewer shutting down");
                        return;
                    }
                }
                _ = tokio::time::sleep(refresh_duration) => {
                    if let Err(e) = self.renew_all() {
                        tracing::error!(error = %e, "control SVID renewal failed");
                    }
                }
            }
        }
    }

    fn renew_all(&self) -> Result<(), Box<dyn std::error::Error>> {
        // 1. Renew Data/Control SVID
        let dc_spiffe = format!(
            "spiffe://{}/ns/system/control/{}",
            self.dc_trust_domain, self.node_name
        );
        let dc_params = SvidParams {
            spiffe_id: dc_spiffe.clone(),
            kind: SvidKind::Control,
            role: None,
            ordinal: None,
            degraded: false,
            ttl_secs: self.node_ttl_secs,
        };

        let dc_bundle = self.ca_data_control.read();
        let dc_svid = rcgen_impl::sign_svid(
            &dc_params,
            &dc_bundle.current_key,
            &dc_bundle.current_cert_der,
        )?;
        drop(dc_bundle); // release read lock

        let dc_key = mtls::certified_key_from_der(&dc_svid.cert_der, &dc_svid.private_key_der)?;
        self.dc_resolver.update(dc_key.clone());
        self.raft_resolver.update(dc_key);
        tracing::info!(spiffe_id = %dc_spiffe, "Data/Control SVID renewed");

        // 2. Renew Admin SVID (if CA available)
        if let (Some(ca_admin), Some(admin_resolver)) = (&self.ca_admin, &self.admin_resolver) {
            let admin_spiffe = format!(
                "spiffe://{}/ns/system/control/{}",
                self.admin_trust_domain, self.node_name
            );
            let admin_params = SvidParams {
                spiffe_id: admin_spiffe.clone(),
                kind: SvidKind::Control,
                role: None,
                ordinal: None,
                degraded: false,
                ttl_secs: self.admin_ttl_secs,
            };

            let admin_bundle = ca_admin.read();
            let admin_svid = rcgen_impl::sign_svid(
                &admin_params,
                &admin_bundle.current_key,
                &admin_bundle.current_cert_der,
            )?;
            drop(admin_bundle);

            let admin_key =
                mtls::certified_key_from_der(&admin_svid.cert_der, &admin_svid.private_key_der)?;
            admin_resolver.update(admin_key);
            tracing::info!(spiffe_id = %admin_spiffe, "Admin SVID renewed");
        }

        Ok(())
    }
}
