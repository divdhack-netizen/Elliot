//! Persistence of the CA private key.
//!
//! The private key is the capability to intercept TLS, so it is never written
//! to disk in the clear. Two backends sit behind one small seam:
//!
//! - [`KeyStore::Keychain`] — the OS keychain (macOS Keychain, Secret Service on
//!   Linux, Credential Manager on Windows), entry `service = "elliot"`,
//!   `account = "ca-key"`. The **public** certificate stays a file (`ca.crt`):
//!   the user installs it, so it is not a secret.
//! - [`KeyStore::EncryptedFile`] — `ca.key.enc`, XChaCha20-Poly1305 with a key
//!   from `ca.seed` (both `0600`). This is the fallback when no keychain is
//!   usable (headless machines, CI), and the library default: a library caller
//!   should not touch the user's keychain unless the desktop app asked for it.
//!
//! Honest limit of the fallback: the wrapping key sits on the same disk, so it
//! defends against a copied/backed-up key file and against accidental exposure,
//! not against an attacker who can already read the user's files. The keychain
//! path is the one that adds an OS-level secret; the file path is the portable
//! floor, never a plaintext key.
//!
//! A legacy plaintext `ca.key` is imported into the configured store and
//! **removed** the first time it is seen ([`Ca::load_or_create`]).

use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};

use crate::TlsError;

/// Where the CA private key is persisted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyStore {
    /// The OS keychain, with the encrypted file as a fallback when the keychain
    /// is unavailable or a keychain operation fails.
    Keychain,
    /// XChaCha20-Poly1305 `ca.key.enc` next to the certificate.
    ///
    /// The default: callers that do not own a desktop session (tests, headless
    /// tools) must not depend on a keychain being present.
    #[default]
    EncryptedFile,
}

/// Encrypted key file, next to `ca.crt`.
pub(crate) const ENCRYPTED_KEY_FILE: &str = "ca.key.enc";
/// Wrapping seed for the encrypted key file.
pub(crate) const SEED_FILE: &str = "ca.seed";
/// Pre-hardening key file, in clear. Migrated and removed.
pub(crate) const LEGACY_KEY_FILE: &str = "ca.key";
const KEYRING_SERVICE: &str = "elliot";
const KEYRING_ACCOUNT: &str = "ca-key";
/// File header, so a versioned format can be introduced without guessing.
const MAGIC: &[u8; 8] = b"ELLIOTK1";
/// Bound into the AEAD so a blob cannot be replayed as another kind of secret.
const AAD: &[u8] = b"elliot-ca-key-v1";
const SEED_LEN: usize = 32;
const NONCE_LEN: usize = 24;

/// The key store for one CA directory.
pub(crate) struct Secrets {
    dir: PathBuf,
    /// Use the OS keychain first, falling back to the encrypted file.
    keychain: bool,
    /// Test hook: make every keychain operation fail, so the fallback branch is
    /// exercised without a real (and possibly prompting) keychain.
    keychain_fails: bool,
}

impl Secrets {
    pub(crate) fn new(dir: &Path, store: KeyStore, keychain_fails: bool) -> Self {
        Self {
            dir: dir.to_path_buf(),
            keychain: store == KeyStore::Keychain,
            keychain_fails,
        }
    }

    /// Read the key: keychain first, then the encrypted file, then a legacy
    /// plaintext key — which is migrated into the configured store and removed.
    pub(crate) fn load(&self) -> Result<Option<String>, TlsError> {
        let mut keychain_error = None;
        if self.keychain {
            match self.keychain_get() {
                Ok(Some(pem)) => return Ok(Some(pem)),
                Ok(None) => {}
                // A broken keychain is a reason to fall back, not to fail: the
                // encrypted file is still a valid store for this CA. The error
                // is kept so a CA with *only* a keychain key reports why it
                // cannot start instead of "key missing".
                Err(e) => {
                    tracing::warn!(
                        "CA key: keychain unavailable ({e}), falling back to {}",
                        ENCRYPTED_KEY_FILE
                    );
                    keychain_error = Some(e);
                }
            }
        }

        let encrypted = self.dir.join(ENCRYPTED_KEY_FILE);
        if encrypted.exists() {
            let seed = self.read_seed()?;
            return self.decrypt_file(&encrypted, &seed).map(Some);
        }

        let legacy = self.dir.join(LEGACY_KEY_FILE);
        if legacy.exists() {
            let pem = std::fs::read_to_string(&legacy).map_err(|e| io_error(&legacy, e))?;
            self.store(&pem)?;
            self.remove_legacy()?;
            return Ok(Some(pem));
        }

        match keychain_error {
            // The key may well exist in the keychain; saying "missing" would
            // send the user hunting for the wrong thing.
            Some(e) => Err(TlsError::KeyStore(format!(
                "the OS keychain is unavailable ({e}) and no {} exists; unlock it and retry",
                ENCRYPTED_KEY_FILE
            ))),
            None => Ok(None),
        }
    }

    /// Persist the key: keychain when configured and working, otherwise the
    /// encrypted file. Never plaintext.
    pub(crate) fn store(&self, key_pem: &str) -> Result<(), TlsError> {
        if self.keychain {
            match self.keychain_set(key_pem) {
                Ok(()) => return Ok(()),
                Err(e) => tracing::warn!(
                    "CA key: keychain store failed ({e}), falling back to {}",
                    ENCRYPTED_KEY_FILE
                ),
            }
        }
        let seed = self.seed_or_create()?;
        let blob = encrypt(&seed, key_pem.as_bytes())?;
        write_secret(&self.dir.join(ENCRYPTED_KEY_FILE), &blob)
    }

    /// Delete a legacy plaintext key, if any. Called after a successful load so
    /// an old clear-text copy never survives an upgrade.
    pub(crate) fn remove_legacy(&self) -> Result<(), TlsError> {
        let legacy = self.dir.join(LEGACY_KEY_FILE);
        if !legacy.exists() {
            return Ok(());
        }
        std::fs::remove_file(&legacy).map_err(|e| io_error(&legacy, e))
    }

    fn keychain_get(&self) -> Result<Option<String>, String> {
        if self.keychain_fails {
            return Err("keychain disabled for this run".into());
        }
        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT).map_err(|e| e.to_string())?;
        match entry.get_password() {
            Ok(pem) => Ok(Some(pem)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    fn keychain_set(&self, key_pem: &str) -> Result<(), String> {
        if self.keychain_fails {
            return Err("keychain disabled for this run".into());
        }
        let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT).map_err(|e| e.to_string())?;
        entry.set_password(key_pem).map_err(|e| e.to_string())
    }

    /// The wrapping seed, created on first use with owner-only permissions.
    fn seed_or_create(&self) -> Result<[u8; SEED_LEN], TlsError> {
        let path = self.dir.join(SEED_FILE);
        if path.exists() {
            return self.read_seed();
        }
        let seed = random_bytes::<SEED_LEN>()?;
        write_secret(&path, &seed)?;
        Ok(seed)
    }

    fn read_seed(&self) -> Result<[u8; SEED_LEN], TlsError> {
        let path = self.dir.join(SEED_FILE);
        let bytes = std::fs::read(&path).map_err(|e| io_error(&path, e))?;
        bytes.try_into().map_err(|_| {
            TlsError::KeyStore(format!(
                "{} is not a {SEED_LEN}-byte key seed",
                path.display()
            ))
        })
    }

    fn decrypt_file(&self, path: &Path, seed: &[u8; SEED_LEN]) -> Result<String, TlsError> {
        let blob = std::fs::read(path).map_err(|e| io_error(path, e))?;
        let plain = decrypt(seed, &blob)?;
        String::from_utf8(plain)
            .map_err(|_| TlsError::KeyStore(format!("{} is not valid UTF-8", path.display())))
    }
}

fn encrypt(seed: &[u8; SEED_LEN], plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
    let nonce_bytes = random_bytes::<NONCE_LEN>()?;
    let cipher = XChaCha20Poly1305::new(&Key::from(*seed));
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce_bytes),
            Payload {
                msg: plaintext,
                aad: AAD,
            },
        )
        .map_err(|_| TlsError::KeyStore("encrypting the CA key failed".into()))?;

    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt(seed: &[u8; SEED_LEN], blob: &[u8]) -> Result<Vec<u8>, TlsError> {
    let header = MAGIC.len() + NONCE_LEN;
    if blob.len() < header || &blob[..MAGIC.len()] != MAGIC {
        return Err(TlsError::KeyStore(
            "encrypted CA key is truncated or not in the expected format".into(),
        ));
    }
    let nonce = XNonce::try_from(&blob[MAGIC.len()..header])
        .map_err(|_| TlsError::KeyStore("encrypted CA key has an invalid nonce".into()))?;
    let cipher = XChaCha20Poly1305::new(&Key::from(*seed));
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &blob[header..],
                aad: AAD,
            },
        )
        .map_err(|_| {
            TlsError::KeyStore("decrypting the CA key failed (wrong seed or corrupted file)".into())
        })
}

fn random_bytes<const N: usize>() -> Result<[u8; N], TlsError> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf)
        .map_err(|e| TlsError::KeyStore(format!("no system randomness: {e}")))?;
    Ok(buf)
}

/// Write `contents` to `path` with owner-only permissions where the platform
/// supports it (`0600` on unix).
pub(crate) fn write_secret(path: &Path, contents: &[u8]) -> Result<(), TlsError> {
    std::fs::write(path, contents).map_err(|e| io_error(path, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| io_error(path, e))?;
    }
    Ok(())
}

/// An IO failure carrying the path it happened on (a bare `io::Error` would
/// drop the only context that makes the message actionable).
pub(crate) fn io_error(path: &Path, source: std::io::Error) -> TlsError {
    TlsError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_encrypted_blob_round_trips_and_is_not_plaintext() {
        let seed = [7u8; SEED_LEN];
        let secret = b"-----BEGIN PRIVATE KEY-----\nsecret\n";
        let blob = encrypt(&seed, secret).unwrap();
        assert!(blob.starts_with(MAGIC));
        assert!(
            !blob.windows(secret.len()).any(|w| w == secret),
            "the key must not appear in the clear"
        );
        assert_eq!(decrypt(&seed, &blob).unwrap(), secret);
    }

    #[test]
    fn a_tampered_blob_is_rejected() {
        let seed = [1u8; SEED_LEN];
        let mut blob = encrypt(&seed, b"secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(decrypt(&seed, &blob).is_err());
    }

    #[test]
    fn a_wrong_seed_cannot_decrypt() {
        let blob = encrypt(&[2u8; SEED_LEN], b"secret").unwrap();
        assert!(decrypt(&[3u8; SEED_LEN], &blob).is_err());
    }
}
