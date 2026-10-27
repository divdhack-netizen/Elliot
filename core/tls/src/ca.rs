//! Root CA: generate once, persist, load thereafter.
//!
//! The CA private key is the capability to intercept TLS, so it is treated as a
//! secret: generated locally, never exported and never stored in the clear.
//! [`KeyStore`] decides where it lives — the OS keychain, or an encrypted file
//! when no keychain is usable — and only the public certificate
//! ([`Ca::cert_pem`]) leaves this module, for the user-driven trust-store
//! install.
//!
//! The CA lives here, in the shared TLS crate, because two consumers need the
//! same key: the HTTP proxy (via hudsucker's authority) and the generic SOCKS
//! listener ([`Ca::leaf_for_host`]). A per-host leaf minted here is
//! indistinguishable from one minted by the proxy, so the user installs one
//! certificate either way.

use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::keystore::{self, Secrets};
use crate::TlsError;

pub use crate::keystore::KeyStore;

const CERT_FILE: &str = "ca.crt";

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
    ///
    /// Uses the default [`KeyStore::EncryptedFile`]; desktop callers that have a
    /// session keychain opt into it with [`Ca::load_or_create_with`].
    pub fn load_or_create(dir: &Path) -> Result<Self, TlsError> {
        Self::load_or_create_in(dir, KeyStore::default(), false)
    }

    /// Load or create the CA with an explicit key store.
    pub fn load_or_create_with(dir: &Path, keys: KeyStore) -> Result<Self, TlsError> {
        Self::load_or_create_in(dir, keys, false)
    }

    fn load_or_create_in(
        dir: &Path,
        keys: KeyStore,
        keychain_fails: bool,
    ) -> Result<Self, TlsError> {
        std::fs::create_dir_all(dir).map_err(|e| keystore::io_error(dir, e))?;
        let cert_path = dir.join(CERT_FILE);
        let secrets = Secrets::new(dir, keys, keychain_fails);

        if cert_path.exists() {
            let cert_pem =
                std::fs::read_to_string(&cert_path).map_err(|e| keystore::io_error(&cert_path, e))?;
            let Some(key_pem) = secrets.load()? else {
                // A certificate without its key cannot sign anything, and
                // regenerating one would silently invalidate every installed
                // trust anchor: fail loudly instead.
                return Err(TlsError::KeyStore(format!(
                    "{} exists but its private key is missing (keychain or {})",
                    cert_path.display(),
                    keystore::ENCRYPTED_KEY_FILE
                )));
            };
            let ca = Self::from_pem(cert_pem, key_pem)?;
            // An upgrade may leave a plaintext key behind: it is now redundant.
            secrets.remove_legacy()?;
            Ok(ca)
        } else {
            let (cert_pem, key_pem) = generate_ca_pem()?;
            secrets.store(&key_pem)?;
            std::fs::write(&cert_path, cert_pem.as_bytes())
                .map_err(|e| keystore::io_error(&cert_path, e))?;
            secrets.remove_legacy()?;
            Self::from_pem(cert_pem, key_pem)
        }
    }

    fn from_pem(cert_pem: String, key_pem: String) -> Result<Self, TlsError> {
        let key_pair = KeyPair::from_pem(&key_pem)?;
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

/// Mint the root certificate and its private key, both as PEM.
///
/// Split out from the creation path so the tests can build a *legacy* clear-text
/// CA to migrate without duplicating the certificate parameters.
fn generate_ca_pem() -> Result<(String, String), TlsError> {
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
    Ok((cert.pem(), key_pair.serialize_pem()))
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

        // The private key never lands on disk in the clear.
        assert!(
            !dir.path().join("ca.key").exists(),
            "the CA key must not be a plaintext file"
        );
        assert!(dir.path().join("ca.key.enc").exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for name in ["ca.key.enc", "ca.seed"] {
                let mode = std::fs::metadata(dir.path().join(name))
                    .unwrap()
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o777, 0o600, "{name} must stay owner-only");
            }
        }
    }

    /// An install that predates hardening has a clear-text `ca.key`. It must be
    /// imported into the configured store and removed, keeping the certificate
    /// (and therefore every trust-store install) valid.
    #[test]
    fn a_legacy_clear_key_is_imported_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, key_pem) = generate_ca_pem().unwrap();
        std::fs::write(dir.path().join("ca.crt"), cert_pem.as_bytes()).unwrap();
        std::fs::write(dir.path().join("ca.key"), key_pem.as_bytes()).unwrap();

        let ca = Ca::load_or_create(dir.path()).unwrap();
        assert_eq!(ca.cert_pem(), cert_pem);
        assert!(
            !dir.path().join("ca.key").exists(),
            "the plaintext key must be removed after migration"
        );
        assert!(dir.path().join("ca.key.enc").exists());

        // The migrated key reloads from the encrypted file (the plaintext one
        // is gone), same certificate and same signing power.
        drop(ca);
        let reloaded = Ca::load_or_create(dir.path()).unwrap();
        assert_eq!(reloaded.cert_pem(), cert_pem);
        assert!(reloaded.leaf_for_host("localhost").is_ok());
    }

    /// When the keychain cannot be used (headless machine, CI, denied access),
    /// the key is still persisted — encrypted, never plaintext.
    #[test]
    fn the_keychain_branch_falls_back_to_an_encrypted_file() {
        let dir = tempfile::tempdir().unwrap();
        let first =
            Ca::load_or_create_in(dir.path(), KeyStore::Keychain, true).unwrap();
        let pem = first.cert_pem().to_string();
        drop(first);

        assert!(!dir.path().join("ca.key").exists());
        assert!(dir.path().join("ca.key.enc").exists());

        // Reload with the keychain broken again: the file is found and used.
        let second = Ca::load_or_create_in(dir.path(), KeyStore::Keychain, true).unwrap();
        assert_eq!(second.cert_pem(), pem);
    }

    /// A certificate whose key is gone must not be silently re-minted: that
    /// would invalidate every install of the old one.
    #[test]
    fn a_certificate_without_its_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_pem, _key_pem) = generate_ca_pem().unwrap();
        std::fs::write(dir.path().join("ca.crt"), cert_pem.as_bytes()).unwrap();

        let err = match Ca::load_or_create(dir.path()) {
            Ok(_) => panic!("a CA without its key must not be usable"),
            Err(e) => e,
        };
        assert!(
            matches!(err, TlsError::KeyStore(ref m) if m.contains("private key is missing")),
            "got {err:?}"
        );
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
