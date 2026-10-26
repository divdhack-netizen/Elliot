//! elliot-tls — the single place that builds TLS client configuration.
//!
//! The repeater and the proxy both need a `rustls::ClientConfig`, and both need
//! the same deliberate, caller-controlled "accept invalid certificates" escape
//! hatch. Keeping it here means the verification policy is decided once, and the
//! permissive verifier exists in exactly one place instead of being copied (or
//! half-implemented) per consumer.
//!
//! The provider is always `aws-lc-rs` and the trust anchors are the bundled
//! webpki roots — no OpenSSL anywhere on the network path.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::aws_lc_rs;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::TlsConnector;

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("building the TLS client config: {0}")]
    Config(#[from] rustls::Error),
}

/// A client config that verifies the server against the bundled webpki roots.
/// The default for every caller.
pub fn verified_client_config() -> Result<ClientConfig, TlsError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Ok(awslc_builder()?.with_root_certificates(roots).with_no_client_auth())
}

/// A client config that accepts **any** certificate.
///
/// A deliberate opt-out for probing broken or self-signed targets. It is never a
/// default: every caller propagates an explicit user decision
/// (`accept_invalid_certs`, `verify_upstream`).
pub fn insecure_client_config() -> Result<ClientConfig, TlsError> {
    Ok(awslc_builder()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerification))
        .with_no_client_auth())
}

/// The client config for `accept_invalid_certs`.
pub fn client_config(accept_invalid_certs: bool) -> Result<ClientConfig, TlsError> {
    if accept_invalid_certs {
        insecure_client_config()
    } else {
        verified_client_config()
    }
}

/// A `tokio-rustls` connector for the plain TCP + TLS path (the repeater).
pub fn connector(accept_invalid_certs: bool) -> Result<TlsConnector, TlsError> {
    Ok(TlsConnector::from(Arc::new(client_config(
        accept_invalid_certs,
    )?)))
}

/// Shared builder prologue: the aws-lc-rs provider (never a process-global
/// default) and the safe default protocol versions.
fn awslc_builder() -> Result<ConfigBuilder, TlsError> {
    Ok(
        ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()?,
    )
}

/// The builder state after the provider and protocol versions are fixed, but
/// before a certificate verifier is chosen.
type ConfigBuilder = rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier>;

/// Accepts any certificate. Only ever installed by [`insecure_client_config`],
/// which requires an explicit caller opt-in.
#[derive(Debug)]
struct NoVerification;

impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::SocketAddr;

    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsAcceptor;

    #[test]
    fn both_configs_build() {
        assert!(verified_client_config().is_ok());
        assert!(insecure_client_config().is_ok());
        assert!(client_config(false).is_ok());
        assert!(client_config(true).is_ok());
    }

    /// Spin a TLS server, then check that the same client accepts it only when
    /// the caller explicitly opted out of verification.
    #[tokio::test]
    async fn a_self_signed_server_is_accepted_only_when_opted_out() {
        let addr = spawn_self_signed_server().await;

        // Default (verification on): the self-signed certificate is rejected.
        let verified = connect_once(addr, "localhost", false).await;
        assert!(
            verified.is_err(),
            "a self-signed certificate must fail verification, got {verified:?}"
        );

        // Explicit opt-out: it connects.
        let insecure = connect_once(addr, "localhost", true).await;
        assert!(
            insecure.is_ok(),
            "accept_invalid_certs must connect, got {insecure:?}"
        );
    }

    /// Try one TLS connection and report success or the failure reason.
    async fn connect_once(addr: SocketAddr, host: &str, accept_invalid: bool) -> Result<(), String> {
        let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
        let name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
        let connector = connector(accept_invalid).map_err(|e| e.to_string())?;
        let mut tls = connector
            .connect(name, tcp)
            .await
            .map_err(|e| e.to_string())?;
        tls.shutdown().await.map_err(|e| e.to_string())?;
        Ok(())
    }

    /// A one-certificate TLS server on a loopback port, accepting connections
    /// until the test ends. Handshake failures are expected (the verifying
    /// client must fail) and therefore ignored.
    async fn spawn_self_signed_server() -> SocketAddr {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen should issue a self-signed certificate");
        let cert_der = cert.cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            cert.signing_key.serialize_der(),
        ));

        let server_config =
            rustls::ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("the aws-lc-rs provider supports the default versions")
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .expect("the generated certificate is usable");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    // A handshake failure is expected here (the verifying client
                    // aborts), so only the success path does anything.
                    if let Ok(mut tls) = acceptor.accept(sock).await {
                        let _ = tls.shutdown().await;
                    }
                });
            }
        });
        addr
    }
}
