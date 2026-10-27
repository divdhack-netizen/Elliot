//! Root CA: generate once, persist, load thereafter.
//!
//! The CA private key is the capability to intercept TLS, so it is treated as a
//! secret: generated locally, written with owner-only permissions, and never
//! exported. Only the public certificate ([`Ca::cert_pem`]) leaves this module,
//! for the user-driven trust-store install.
//!
//! The CA lives here, in the shared TLS crate, because two consumers need the
//! same key: the HTTP proxy (via hudsucker's authority) and the generic SOCKS
//! listener ([`Ca::leaf_for_host`]). A per-host leaf minted here is
//! indistinguishable from one minted by the proxy, so the user installs one
//! certificate either way.
//!
//! TODO(hardening, separate task): encrypt the CA key at rest / store it in the
//! OS keychain once the project has key management. For now it is a `0600` file
//! in the app's CA directory.

use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::TlsError;
const CERT_FILE: &str = "ca.crt";
const KEY_FILE: &str = "ca.key";

/// A leaf certificate + its private key, ready for a server config.
pub struct Leaf {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
}

/// A loaded root CA: the signing issuer for per-host leaves, plus the public
/// certificate PEM for export.
pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    cert_pem: String,
}

impl Ca {
    /// Load the CA from `dir`, generating and persisting a new one on first run.
    pub fn load_or_create(dir: &Path) -> Result<Self, TlsError> {
        std::fs::create_dir_all(dir).map_err(|e| io_error(dir, e))?;
        let cert_path = dir.join(CERT_FILE);
        let key_path = dir.join(KEY_FILE);

        if cert_path.exists() && key_path.exists() {
            Self::load(&cert_path, &key_path)
        } else {
            Self::create(&cert_path, &key_path)
        }
    }

    fn load(cert_path: &Path, key_path: &Path) -> Result<Self, TlsError> {
        let cert_pem = std::fs::read_to_string(cert_path).map_err(|e| io_error(cert_path, e))?;
        let key_pem = std::fs::read_to_string(key_path).map_err(|e| io_error(key_path, e))?;
        let key_pair = KeyPair::from_pem(&key_pem)?;
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair)?;
        Ok(Self { issuer, cert_pem })
    }

    fn create(cert_path: &Path, key_path: &Path) -> Result<Self, TlsError> {
        let key_pair = KeyPair::generate()?;

        let mut params = CertificateParams::new(Vec::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Elliot Local CA");
        dn.push(DnType::OrganizationName, "Elliot");
        params.distinguished_name = dn;

        let cert = params.self_signed(&key_pair)?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        write_secret(key_path, key_pem.as_bytes()).map_err(|e| io_error(key_path, e))?;
        std::fs::write(cert_path, cert_pem.as_bytes()).map_err(|e| io_error(cert_path, e))?;

        // Re-build the issuer from the persisted PEM so the load and create
        // paths produce identical issuers.
        let issuer = Issuer::from_ca_cert_pem(&cert_pem, key_pair)?;
        Ok(Self { issuer, cert_pem })
    }

    /// Public certificate PEM (safe to export / install).
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Consume into the signing issuer for hudsucker's authority.
    pub fn into_issuer(self) -> Issuer<'static, KeyPair> {
        self.issuer
    }

    /// Mint a fresh leaf certificate + key for `host`, signed by this CA.
    ///
    /// `host` may be a DNS name or an IP literal; rcgen turns it into the right
    /// subject alternative name (DNS SAN vs IP SAN), so both `example.com` and
    /// `127.0.0.1` produce a certificate the client will accept once the CA is
    /// trusted. A new key pair is generated per call: leaves are cheap, and
    /// reusing one key pair across hosts would couple them for no benefit.
    pub fn leaf_for_host(&self, host: &str) -> Result<Leaf, TlsError> {
        let key_pair = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![host.to_string()])?;

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        dn.push(DnType::OrganizationName, "Elliot");
        params.distinguished_name = dn;

        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;

        let cert = params.signed_by(&key_pair, &self.issuer)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        Ok(Leaf {
            cert: cert.der().clone(),
            key,
        })
    }
}

/// An IO failure carrying the path it happened on (a bare `io::Error` would
/// drop the only context that makes the message actionable).
fn io_error(path: &Path, source: std::io::Error) -> TlsError {
    TlsError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Write `contents` to `path` with owner-only permissions where the platform
/// supports it (`0600` on unix).
fn write_secret(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_config_with_leaf;
    use rustls::crypto::aws_lc_rs;
    use rustls::{ClientConfig, RootCertStore};
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::ServerName;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    #[test]
    fn generates_once_and_reloads_the_same_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let first = Ca::load_or_create(dir.path()).unwrap();
        let pem = first.cert_pem().to_string();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        drop(first);

        // Second call loads the persisted pair instead of minting a new CA:
        // a re-generated CA would silently invalidate every installed cert.
        let second = Ca::load_or_create(dir.path()).unwrap();
        assert_eq!(second.cert_pem(), pem);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("ca.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the CA key must stay owner-only");
        }
    }

    /// The leaf is only useful if a client that trusts the CA actually accepts
    /// it, so the test runs a real handshake rather than inspecting the DER.
    #[tokio::test]
    async fn a_minted_leaf_completes_a_handshake_against_the_ca() {
        let dir = tempfile::tempdir().unwrap();
        let ca = Ca::load_or_create(dir.path()).unwrap();
        let leaf = ca.leaf_for_host("localhost").unwrap();
        let server_config = server_config_with_leaf(leaf.cert, leaf.key).unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(sock).await.unwrap();
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).await.unwrap();
            tls.write_all(b"pong!").await.unwrap();
            tls.flush().await.unwrap();
            buf
        });

        // The client trusts exactly one root: our CA.
        let ca_der = CertificateDer::from_pem_slice(ca.cert_pem().as_bytes()).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(ca_der).unwrap();
        let client_config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));

        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        let mut tls = connector.connect(name, tcp).await.unwrap();
        tls.write_all(b"hello").await.unwrap();
        tls.flush().await.unwrap();
        let mut buf = [0u8; 5];
        tls.read_exact(&mut buf).await.unwrap();

        assert_eq!(&buf, b"pong!");
        assert_eq!(&server.await.unwrap(), b"hello");
    }
}
