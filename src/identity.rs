use blake3::Hasher;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use base64::prelude::*;

/// Device identity containing cryptographic keys and fingerprint
#[derive(Clone, Debug)]
pub struct DeviceIdentity {
    /// Ed25519 signing key for device identity
    pub signing_key: SigningKey,
    /// Ed25519 public key derived from signing key
    pub public_key: VerifyingKey,
    /// Short device fingerprint (8 hex chars) derived from public key
    pub fingerprint: String,
}

/// Account master key for multi-device sync
#[derive(Clone, Debug)]
pub struct AccountMasterKey([u8; 32]);

impl DeviceIdentity {
    /// Generate a new device identity with random keys
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key();
        let fingerprint = Self::compute_fingerprint(&public_key);
        
        Self {
            signing_key,
            public_key,
            fingerprint,
        }
    }

    /// Create device identity from existing signing key
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let public_key = signing_key.verifying_key();
        let fingerprint = Self::compute_fingerprint(&public_key);
        
        Self {
            signing_key,
            public_key,
            fingerprint,
        }
    }

    /// Compute 8-character hex fingerprint from public key
    fn compute_fingerprint(public_key: &VerifyingKey) -> String {
        let mut hasher = Hasher::new();
        hasher.update(public_key.as_bytes());
        let hash = hasher.finalize();
        hex::encode(&hash.as_bytes()[..4]).to_uppercase()
    }

    /// Get device fingerprint for server communication
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Export public key for sharing
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }
}

impl AccountMasterKey {
    /// Generate a new account master key
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    /// Create from existing key bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get key bytes for sharing/storage
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compute account hash for server grouping
    pub fn account_hash(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(&self.0);
        let hash = hasher.finalize();
        hex::encode(&hash.as_bytes()[..8]).to_uppercase()
    }

    /// Derive device-specific signing key from master key and device index
    pub fn derive_device_key(&self, device_index: u32) -> SigningKey {
        let mut hasher = Hasher::new();
        hasher.update(b"device_key_derivation");
        hasher.update(&self.0);
        hasher.update(&device_index.to_le_bytes());
        let derived_bytes = hasher.finalize();
        
        // Use first 32 bytes as seed for signing key
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&derived_bytes.as_bytes()[..32]);
        SigningKey::from_bytes(&seed)
    }

    /// Generate device linking URL for QR codes
    pub fn device_linking_url(&self, base_url: &str) -> String {
        let key_b64 = base64::prelude::BASE64_STANDARD.encode(self.0);
        format!("{base_url}#link={key_b64}")
    }

    /// Parse device linking URL to extract master key
    pub fn from_linking_url(url: &str) -> Option<Self> {
        let fragment = url.split('#').nth(1)?;
        let key_param = fragment.strip_prefix("link=")?;
        let key_bytes = base64::prelude::BASE64_STANDARD.decode(key_param).ok()?;
        if key_bytes.len() == 32 {
            let mut array = [0u8; 32];
            array.copy_from_slice(&key_bytes);
            Some(Self(array))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_identity_generation() {
        let identity = DeviceIdentity::generate();
        assert_eq!(identity.fingerprint.len(), 8);
        assert!(identity.fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_account_master_key() {
        let master_key = AccountMasterKey::generate();
        let account_hash = master_key.account_hash();
        assert_eq!(account_hash.len(), 16); // 8 bytes = 16 hex chars
        
        // Test device key derivation
        let device_key1 = master_key.derive_device_key(0);
        let device_key2 = master_key.derive_device_key(1);
        assert_ne!(device_key1.to_bytes(), device_key2.to_bytes());
    }

    #[test]
    fn test_device_linking_url() {
        let master_key = AccountMasterKey::generate();
        let url = master_key.device_linking_url("https://bin.gy");
        let parsed_key = AccountMasterKey::from_linking_url(&url);
        assert!(parsed_key.is_some());
        assert_eq!(master_key.as_bytes(), parsed_key.unwrap().as_bytes());
    }
}