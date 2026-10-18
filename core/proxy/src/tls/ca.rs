//! Root CA: generate once, persist, load thereafter.
//!
//! The CA private key is the capability to intercept TLS, so it is treated as a
//! secret: generated locally, written with owner-only permissions, and never
//! exported. Only the public certificate ([`Ca::cert_pem`]) leaves this module,
//! for the user-driven trust-store install.
//!
//! TODO(hardening, separate task): encrypt the CA key at rest / store it in the
//! OS keychain once the project has key management. For now it is a `0600` file
//! in the app's CA directory.

use std::path::Path;

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};

const CERT_FILE: &str = "ca.crt";
const KEY_FILE: &str = "ca.key";

/// A loaded root CA: the signing issuer for per-host leaves, plus the public
/// certificate PEM for export.
pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    cert_pem: String,
}

impl Ca {
    /// Load the CA from `dir`, generating and persisting a new one on first run.
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating CA directory {}", dir.display()))?;
        let cert_path = dir.join(CERT_FILE);
        let key_path = dir.join(KEY_FILE);

        if cert_path.exists() && key_path.exists() {
            Self::load(&cert_path, &key_path)
        } else {
            Self::create(&cert_path, &key_path)
        }
    }

    fn load(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let cert_pem = std::fs::read_to_string(cert_path)
            .with_context(|| format!("reading {}", cert_path.display()))?;
        let key_pem = std::fs::read_to_string(key_path)
            .with_context(|| format!("reading {}", key_path.display()))?;
        let key_pair = KeyPair::from_pem(&key_pem).context("parsing CA private key")?;
        let issuer =
            Issuer::from_ca_cert_pem(&cert_pem, key_pair).context("parsing CA certificate")?;
        Ok(Self { issuer, cert_pem })
    }

    fn create(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let key_pair = KeyPair::generate().context("generating CA key pair")?;

        let mut params = CertificateParams::new(Vec::new()).context("building CA params")?;
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

        let cert = params
            .self_signed(&key_pair)
            .context("self-signing CA certificate")?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        write_secret(key_path, key_pem.as_bytes())
            .with_context(|| format!("writing {}", key_path.display()))?;
        std::fs::write(cert_path, cert_pem.as_bytes())
            .with_context(|| format!("writing {}", cert_path.display()))?;

        // Re-build the issuer from the persisted PEM so the load and create
        // paths produce identical issuers.
        let issuer =
            Issuer::from_ca_cert_pem(&cert_pem, key_pair).context("building CA issuer")?;
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
