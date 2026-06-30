//! Per-datagram seal/open for the VPN, wrapping the [`ts_tunnel`] shadowsocks
//! AEAD primitives plus carrier obfuscation.
//!
//! Server and client share one pre-shared password, from which the same master
//! key is derived on both ends. Each datagram is independent
//! (`obfs(salt ++ AEAD(plaintext))`), so this type holds no per-peer state and
//! is cheap to share behind an `Arc`.

use ts_tunnel::{
    Cipher, CryptoError, Obfuscator, decrypt_packet, encrypt_packet, evp_bytes_to_key,
};

/// Errors constructing a [`Crypto`].
#[derive(Debug, thiserror::Error)]
pub enum CryptoSetupError {
    /// The cipher name was not one of the supported ciphers.
    #[error(transparent)]
    Cipher(#[from] CryptoError),
}

/// Stateless per-datagram sealer/opener for one pre-shared password.
pub struct Crypto {
    cipher: Cipher,
    master_key: Vec<u8>,
    obfs: Obfuscator,
}

impl Crypto {
    /// Build a [`Crypto`] from a password, cipher name, and obfuscation name.
    ///
    /// The master key is derived from the password with shadowsocks'
    /// `EVP_BytesToKey` to the cipher's key length. `obfs` is one of `none`,
    /// `quic`, or `base64`; both ends must agree.
    pub fn new(password: &str, cipher: &str, obfs: &str) -> Result<Self, CryptoSetupError> {
        let cipher = Cipher::from_name(cipher)?;
        let master_key = evp_bytes_to_key(password.as_bytes(), cipher.key_len());
        Ok(Self {
            cipher,
            master_key,
            obfs: Obfuscator::from_name(obfs),
        })
    }

    /// The AEAD cipher in use.
    pub fn cipher(&self) -> Cipher {
        self.cipher
    }

    /// Encrypt one plaintext packet into a wire datagram
    /// (`obfs(salt ++ AEAD(plaintext))`).
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let datagram = encrypt_packet(self.cipher, &self.master_key, plaintext)?;
        Ok(self.obfs.wrap(&datagram))
    }

    /// Decrypt a received wire datagram back to its plaintext, or `None` if it
    /// fails to de-obfuscate or authenticate (the caller drops it).
    pub fn open(&self, wire: &[u8]) -> Option<Vec<u8>> {
        let datagram = self.obfs.unwrap(wire)?;
        decrypt_packet(self.cipher, &self.master_key, &datagram).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trips_for_each_cipher_and_obfs() {
        for cipher in ["aes-128-gcm", "aes-256-gcm", "chacha20-poly1305"] {
            for obfs in ["none", "quic", "base64"] {
                let c = Crypto::new("hunter2", cipher, obfs).unwrap();
                let pkt = b"the inner IP packet";
                let wire = c.seal(pkt).unwrap();
                assert_eq!(c.open(&wire).as_deref(), Some(&pkt[..]), "{cipher}/{obfs}");
            }
        }
    }

    #[test]
    fn wrong_password_fails_to_open() {
        let a = Crypto::new("right", "chacha20-poly1305", "none").unwrap();
        let b = Crypto::new("wrong", "chacha20-poly1305", "none").unwrap();
        let wire = a.seal(b"secret").unwrap();
        assert!(b.open(&wire).is_none());
    }

    #[test]
    fn unknown_cipher_is_rejected() {
        assert!(Crypto::new("pw", "rc4-md5", "none").is_err());
    }
}
