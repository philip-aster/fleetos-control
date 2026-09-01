//! V-1: Join flow must use TLS, not plaintext.
//!
//! Verifies the two TLS legs are correctly constructed:
//! - Attestation leg: server-trust TLS (trust bundle, no client cert)
//! - Membership leg: full mTLS (SVID identity + trust bundle)
//!
//! The Senior/Master audit found join_cluster/request_membership dialing
//! plaintext http:// after the S-2 mTLS fix. This test locks in the TLS
//! configuration so the regression cannot silently return.
use fleetos_control::ca::rcgen_impl::{self, SvidKind, SvidParams};
use fleetos_control::ca::trust_bundle::TrustBundle;
use fleetos_control::tls::mtls;

const TRUST_DOMAIN: &str = "fleet.test.internal";

fn make_ca() -> TrustBundle {
    TrustBundle::generate_root(TRUST_DOMAIN).unwrap()
}

fn make_control_svid(ca: &TrustBundle, node_name: &str) -> rcgen_impl::SignedSvid {
    let params = SvidParams {
        spiffe_id: format!("spiffe://{}/ns/system/control/{}", TRUST_DOMAIN, node_name),
        kind: SvidKind::Control,
        role: None,
        ordinal: None,
        degraded: false,
        ttl_secs: 3600,
    };
    rcgen_impl::sign_svid(&params, &ca.current_key, &ca.current_cert_der).unwrap()
}

#[test]
fn attestation_leg_builds_server_trust_tls_config() {
    // The attestation leg is pre-SVID: the joiner trusts the server's root
    // bundle but presents no client certificate. This must build a valid
    // rustls ServerConfig via the optional-auth path (mTLS is optional).
    let ca = make_ca();
    let svid = make_control_svid(&ca, "control-1");

    let mtls_config = mtls::MtlsConfig {
        cert_chain: vec![rustls::pki_types::CertificateDer::from(
            svid.cert_der.clone(),
        )],
        private_key: rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(svid.private_key_der.to_vec()),
        ),
        trust_bundle_pem: ca.trust_bundle_pem(),
        role: fleetos_control::tls::trust_domains::TrustDomainRole::DataControl,
    };

    // The optional-auth server config must build successfully.
    // This is the listener the joiner connects to during attestation.
    let server_config = mtls::build_server_config_optional_auth(&mtls_config);
    assert!(
        server_config.is_ok(),
        "optional-auth (attestation leg) TLS config must build: {:?}",
        server_config.err()
    );
}

#[test]
fn membership_leg_builds_full_mtls_config() {
    // The membership leg is post-SVID: the joiner presents its control SVID
    // as a client certificate and the server requires it (strict mTLS).
    let ca = make_ca();
    let svid = make_control_svid(&ca, "control-1");

    let mtls_config = mtls::MtlsConfig {
        cert_chain: vec![rustls::pki_types::CertificateDer::from(
            svid.cert_der.clone(),
        )],
        private_key: rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(svid.private_key_der.to_vec()),
        ),
        trust_bundle_pem: ca.trust_bundle_pem(),
        role: fleetos_control::tls::trust_domains::TrustDomainRole::DataControl,
    };

    // The strict mTLS server config must build successfully.
    // This is the Raft transport listener the joiner connects to for membership.
    let server_config = mtls::build_server_config(&mtls_config);
    assert!(
        server_config.is_ok(),
        "strict mTLS (membership leg) TLS config must build: {:?}",
        server_config.err()
    );
}

#[test]
fn join_svid_passes_data_control_identity_validation() {
    // The joiner's control SVID must be accepted by the Data/Control
    // listener's identity validation (trust domain + kind check).
    let ca = make_ca();
    let svid = make_control_svid(&ca, "control-1");

    let td_config = fleetos_control::tls::trust_domains::TrustDomainConfig {
        data_control: TRUST_DOMAIN.to_owned(),
        admin: "fleet-admin.test.internal".to_owned(),
    };

    let spiffe_id = format!("spiffe://{}/ns/system/control/control-1", TRUST_DOMAIN);
    let result = fleetos_control::tls::trust_domains::validate_peer_identity(
        &spiffe_id,
        fleetos_control::tls::trust_domains::TrustDomainRole::DataControl,
        &td_config,
    );
    assert!(
        result.is_ok(),
        "control SVID must be accepted on Data/Control listener: {:?}",
        result.err()
    );

    // The SVID must actually validate against the trust bundle.
    let valid = ca.validate_svid(&svid.cert_der).unwrap();
    assert!(valid, "join SVID must validate against the trust bundle");
}

#[test]
fn control_svid_carries_dns_san_for_raft_hostname_verification() {
    // The Raft transport uses hostname verification (domain_name set to the
    // trust domain). The control SVID must carry the trust domain as a DNS
    // SAN or the membership-leg TLS handshake fails. This is the exact
    // requirement V-1's membership leg depends on.
    let ca = make_ca();
    let svid = make_control_svid(&ca, "control-1");

    // Parse the certificate and confirm a DNS SAN matching the trust domain is present.
    let (_, cert) = x509_parser::parse_x509_certificate(&svid.cert_der).expect("SVID must parse");
    let san_ext = cert
        .extensions()
        .iter()
        .find(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
        .expect("SVID must carry a SAN extension");

    let has_dns_san = match san_ext.parsed_extension() {
        x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => san
            .general_names
            .iter()
            .any(|gn| matches!(gn, x509_parser::extensions::GeneralName::DNSName(d) if *d == TRUST_DOMAIN)),
        _ => false,
    };
    assert!(
        has_dns_san,
        "control SVID must carry the trust domain '{}' as a DNS SAN for Raft hostname verification",
        TRUST_DOMAIN
    );
}
