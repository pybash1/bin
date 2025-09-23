use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
use rand_core::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, ReusableSecret, StaticSecret};
use serde::{Serialize, Deserialize};
use base64::prelude::*;
use zeroize::Zeroize;

#[derive(Debug)]
pub enum EncryptionError {
    ChaCha20Poly1305(chacha20poly1305::Error),
    Ed25519(ed25519_dalek::SignatureError),
    InvalidKeySize,
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            EncryptionError::ChaCha20Poly1305(e) => write!(f, "ChaCha20Poly1305 error: {e:?}"),
            EncryptionError::Ed25519(e) => write!(f, "Ed25519 error: {e}"),
            EncryptionError::InvalidKeySize => write!(f, "Invalid key size"),
        }
    }
}

impl std::error::Error for EncryptionError {}

impl From<chacha20poly1305::Error> for EncryptionError {
    fn from(err: chacha20poly1305::Error) -> Self {
        EncryptionError::ChaCha20Poly1305(err)
    }
}

impl From<ed25519_dalek::SignatureError> for EncryptionError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        EncryptionError::Ed25519(err)
    }
}

#[derive(Clone, Debug)]
pub struct X3DHKeyBundle {
    pub identity_key_ed25519: [u8; 32],  // Ed25519 public key for signatures
    pub identity_key_x25519: [u8; 32],   // X25519 public key for DH
    pub signed_prekey: [u8; 32],         // X25519 public key
    pub prekey_signature: [u8; 64],      // Ed25519 signature of signed_prekey
    pub one_time_prekeys: Vec<[u8; 32]>, // X25519 public keys
}

// Custom serialization for X3DHKeyBundle
impl Serialize for X3DHKeyBundle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("X3DHKeyBundle", 5)?;
        state.serialize_field("identity_key_ed25519", &base64::prelude::BASE64_STANDARD.encode(self.identity_key_ed25519))?;
        state.serialize_field("identity_key_x25519", &base64::prelude::BASE64_STANDARD.encode(self.identity_key_x25519))?;
        state.serialize_field("signed_prekey", &base64::prelude::BASE64_STANDARD.encode(self.signed_prekey))?;
        state.serialize_field("prekey_signature", &base64::prelude::BASE64_STANDARD.encode(self.prekey_signature))?;
        state.serialize_field("one_time_prekeys", &self.one_time_prekeys.iter()
            .map(|k| base64::prelude::BASE64_STANDARD.encode(k))
            .collect::<Vec<_>>())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for X3DHKeyBundle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, Visitor, MapAccess};
        use std::fmt;

        struct X3DHKeyBundleVisitor;

        impl<'de> Visitor<'de> for X3DHKeyBundleVisitor {
            type Value = X3DHKeyBundle;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid X3DHKeyBundle")
            }

            fn visit_map<V>(self, mut map: V) -> Result<X3DHKeyBundle, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut identity_key_ed25519 = None;
                let mut identity_key_x25519 = None;
                let mut signed_prekey = None;
                let mut prekey_signature = None;
                let mut one_time_prekeys = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        "identity_key_ed25519" => {
                            let value: String = map.next_value()?;
                            let bytes = base64::prelude::BASE64_STANDARD.decode(value)
                                .map_err(de::Error::custom)?;
                            if bytes.len() != 32 {
                                return Err(de::Error::custom("identity_key_ed25519 must be 32 bytes"));
                            }
                            let mut array = [0u8; 32];
                            array.copy_from_slice(&bytes);
                            identity_key_ed25519 = Some(array);
                        }
                        "identity_key_x25519" => {
                            let value: String = map.next_value()?;
                            let bytes = base64::prelude::BASE64_STANDARD.decode(value)
                                .map_err(de::Error::custom)?;
                            if bytes.len() != 32 {
                                return Err(de::Error::custom("identity_key_x25519 must be 32 bytes"));
                            }
                            let mut array = [0u8; 32];
                            array.copy_from_slice(&bytes);
                            identity_key_x25519 = Some(array);
                        }
                        "signed_prekey" => {
                            let value: String = map.next_value()?;
                            let bytes = base64::prelude::BASE64_STANDARD.decode(value)
                                .map_err(de::Error::custom)?;
                            if bytes.len() != 32 {
                                return Err(de::Error::custom("signed_prekey must be 32 bytes"));
                            }
                            let mut array = [0u8; 32];
                            array.copy_from_slice(&bytes);
                            signed_prekey = Some(array);
                        }
                        "prekey_signature" => {
                            let value: String = map.next_value()?;
                            let bytes = base64::prelude::BASE64_STANDARD.decode(value)
                                .map_err(de::Error::custom)?;
                            if bytes.len() != 64 {
                                return Err(de::Error::custom("prekey_signature must be 64 bytes"));
                            }
                            let mut array = [0u8; 64];
                            array.copy_from_slice(&bytes);
                            prekey_signature = Some(array);
                        }
                        "one_time_prekeys" => {
                            let value: Vec<String> = map.next_value()?;
                            let mut keys = Vec::new();
                            for key_str in value {
                                let bytes = base64::prelude::BASE64_STANDARD.decode(key_str)
                                    .map_err(de::Error::custom)?;
                                if bytes.len() != 32 {
                                    return Err(de::Error::custom("one_time_prekey must be 32 bytes"));
                                }
                                let mut array = [0u8; 32];
                                array.copy_from_slice(&bytes);
                                keys.push(array);
                            }
                            one_time_prekeys = Some(keys);
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }

                Ok(X3DHKeyBundle {
                    identity_key_ed25519: identity_key_ed25519.ok_or_else(|| de::Error::missing_field("identity_key_ed25519"))?,
                    identity_key_x25519: identity_key_x25519.ok_or_else(|| de::Error::missing_field("identity_key_x25519"))?,
                    signed_prekey: signed_prekey.ok_or_else(|| de::Error::missing_field("signed_prekey"))?,
                    prekey_signature: prekey_signature.ok_or_else(|| de::Error::missing_field("prekey_signature"))?,
                    one_time_prekeys: one_time_prekeys.ok_or_else(|| de::Error::missing_field("one_time_prekeys"))?,
                })
            }
        }

        deserializer.deserialize_struct("X3DHKeyBundle", &["identity_key_ed25519", "identity_key_x25519", "signed_prekey", "prekey_signature", "one_time_prekeys"], X3DHKeyBundleVisitor)
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct X3DHInitialMessage {
    pub sender_identity_key_x25519: [u8; 32], // Sender's X25519 identity key
    pub ephemeral_key: [u8; 32],     // X25519 public key
    pub used_one_time_prekey: Option<[u8; 32]>, // Which one-time prekey was used
    pub ciphertext: Vec<u8>,         // Encrypted initial message
    pub nonce: [u8; 12],             // ChaCha20Poly1305 nonce
}

#[derive(Clone)]
pub struct X3DHSession {
    shared_secret: [u8; 32],
    cipher: ChaCha20Poly1305,
}

/// Device private keys for X3DH - stored securely per device
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct DevicePrivateKeys {
    pub identity_ed25519_secret: [u8; 32],       // Ed25519 SigningKey bytes
    pub identity_x25519_secret: [u8; 32],        // StaticSecret bytes
    pub signed_prekey_secret: [u8; 32],          // StaticSecret bytes (using StaticSecret instead of ReusableSecret for persistence)
    pub one_time_prekey_secrets: Vec<[u8; 32]>,  // StaticSecret bytes for each OTK
}

impl DevicePrivateKeys {
    /// Generate new private keys that correspond to a public bundle
    pub fn generate() -> (Self, X3DHKeyBundle, ed25519_dalek::SigningKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        
        // Generate identity keys
        let identity_x25519_secret = StaticSecret::random_from_rng(&mut OsRng);
        let identity_x25519_public = X25519PublicKey::from(&identity_x25519_secret);
        
        // Generate signed prekey as StaticSecret for persistence
        let signed_prekey_secret = StaticSecret::random_from_rng(&mut OsRng);
        let signed_prekey = X25519PublicKey::from(&signed_prekey_secret);
        
        // Sign the prekey with Ed25519 identity key
        let prekey_signature = signing_key.sign(signed_prekey.as_bytes());
        
        // Generate one-time prekeys as StaticSecret for persistence
        let mut one_time_prekeys = Vec::new();
        let mut one_time_prekey_secrets = Vec::new();
        for _ in 0..10 {
            let secret = StaticSecret::random_from_rng(&mut OsRng);
            let public = X25519PublicKey::from(&secret);
            one_time_prekeys.push(*public.as_bytes());
            one_time_prekey_secrets.push(secret.to_bytes());
        }
        
        let bundle = X3DHKeyBundle {
            identity_key_ed25519: *signing_key.verifying_key().as_bytes(),
            identity_key_x25519: *identity_x25519_public.as_bytes(),
            signed_prekey: *signed_prekey.as_bytes(),
            prekey_signature: prekey_signature.to_bytes(),
            one_time_prekeys,
        };
        
        let private_keys = DevicePrivateKeys {
            identity_ed25519_secret: signing_key.to_bytes(),
            identity_x25519_secret: identity_x25519_secret.to_bytes(),
            signed_prekey_secret: signed_prekey_secret.to_bytes(),
            one_time_prekey_secrets: one_time_prekey_secrets,
        };
        
        (private_keys, bundle, signing_key)
    }
    
    /// Convert stored bytes back to cryptographic types for X3DH operations
    pub fn to_crypto_types(&self) -> (SigningKey, StaticSecret, StaticSecret, Vec<StaticSecret>) {
        let identity_ed25519 = SigningKey::from_bytes(&self.identity_ed25519_secret);
        let identity_secret = StaticSecret::from(self.identity_x25519_secret);
        let signed_prekey_secret = StaticSecret::from(self.signed_prekey_secret);
        let otk_secrets = self.one_time_prekey_secrets
            .iter()
            .map(|bytes| StaticSecret::from(*bytes))
            .collect();
        
        (identity_ed25519, identity_secret, signed_prekey_secret, otk_secrets)
    }
}

impl X3DHKeyBundle {
    /// Generate a new key bundle for a device
    pub fn generate(identity_signing_key: &SigningKey) -> (Self, StaticSecret, StaticSecret, Vec<StaticSecret>) {
        // Generate X25519 identity key for DH operations
        let identity_x25519_secret = StaticSecret::random_from_rng(OsRng);
        let identity_x25519_public = X25519PublicKey::from(&identity_x25519_secret);
        
        let signed_prekey_secret = StaticSecret::random_from_rng(OsRng);
        let signed_prekey = X25519PublicKey::from(&signed_prekey_secret);
        
        // Sign the prekey with Ed25519 identity key
        let prekey_signature = identity_signing_key.sign(signed_prekey.as_bytes());
        
        // Generate one-time prekeys
        let mut one_time_prekeys = Vec::new();
        let mut one_time_prekey_secrets = Vec::new();
        for _ in 0..10 {
            let secret = StaticSecret::random_from_rng(OsRng);
            let public = X25519PublicKey::from(&secret);
            one_time_prekeys.push(*public.as_bytes());
            one_time_prekey_secrets.push(secret);
        }
        
        let bundle = X3DHKeyBundle {
            identity_key_ed25519: *identity_signing_key.verifying_key().as_bytes(),
            identity_key_x25519: *identity_x25519_public.as_bytes(),
            signed_prekey: *signed_prekey.as_bytes(),
            prekey_signature: prekey_signature.to_bytes(),
            one_time_prekeys,
        };
        
        (bundle, identity_x25519_secret, signed_prekey_secret, one_time_prekey_secrets)
    }
    
    /// Verify the signature on the signed prekey
    pub fn verify_signature(&self) -> Result<(), ed25519_dalek::SignatureError> {
        let identity_key = VerifyingKey::from_bytes(&self.identity_key_ed25519)?;
        let signature = ed25519_dalek::Signature::from_bytes(&self.prekey_signature);
        identity_key.verify_strict(&self.signed_prekey, &signature)
    }
}

impl X3DHSession {
    /// Initiate X3DH key exchange (sender side)
    pub fn initiate(
        recipient_bundle: &X3DHKeyBundle,
        _sender_identity_ed25519: &SigningKey,
        sender_identity_x25519: &StaticSecret,
    ) -> Result<(Self, X3DHInitialMessage), EncryptionError> {
        // Verify recipient's bundle signature
        recipient_bundle.verify_signature()?;
        
        // Generate ephemeral key pair
        let ephemeral_secret = ReusableSecret::random_from_rng(OsRng);
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
        
        // Select a one-time prekey (if available)
        let (used_one_time_prekey, one_time_prekey_public) = if let Some(otk) = recipient_bundle.one_time_prekeys.first() {
            (Some(*otk), Some(X25519PublicKey::from(*otk)))
        } else {
            (None, None)
        };
        
        // Perform X3DH calculation
        let recipient_identity_key = X25519PublicKey::from(recipient_bundle.identity_key_x25519);
        let recipient_signed_prekey = X25519PublicKey::from(recipient_bundle.signed_prekey);
        
        // DH1 = DH(IK_A, SPK_B)
        let dh1 = sender_identity_x25519.diffie_hellman(&recipient_signed_prekey);
        
        // DH2 = DH(EK_A, IK_B)  
        let dh2 = ephemeral_secret.diffie_hellman(&recipient_identity_key);
        
        // DH3 = DH(EK_A, SPK_B)
        let dh3 = ephemeral_secret.diffie_hellman(&recipient_signed_prekey);
        
        // DH4 = DH(EK_A, OPK_B) (if one-time prekey exists)
        let dh4 = one_time_prekey_public.map(|otk_pub| ephemeral_secret.diffie_hellman(&otk_pub));
        
        // Derive shared secret: KDF(DH1 || DH2 || DH3 || DH4)
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(dh1.as_bytes());
        kdf_input.extend_from_slice(dh2.as_bytes());
        kdf_input.extend_from_slice(dh3.as_bytes());
        if let Some(ref dh4) = dh4 {
            kdf_input.extend_from_slice(dh4.as_bytes());
        }
        
        let shared_secret = blake3::hash(&kdf_input);
        let shared_secret_bytes = *shared_secret.as_bytes();
        
        // Create cipher
        let cipher = ChaCha20Poly1305::new_from_slice(&shared_secret_bytes)
            .map_err(|_| EncryptionError::InvalidKeySize)?;
        
        // Encrypt initial message (empty for now, could be first paste)
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, b"initial_message".as_ref())?;
        
        let initial_message = X3DHInitialMessage {
            sender_identity_key_x25519: *X25519PublicKey::from(sender_identity_x25519).as_bytes(),
            ephemeral_key: *ephemeral_public.as_bytes(),
            used_one_time_prekey,
            ciphertext,
            nonce: *nonce.as_ref(),
        };
        
        let session = X3DHSession {
            shared_secret: shared_secret_bytes,
            cipher,
        };
        
        Ok((session, initial_message))
    }
    
    /// Accept X3DH key exchange (receiver side)
    pub fn accept(
        initial_message: &X3DHInitialMessage,
        _recipient_identity_ed25519: &SigningKey,
        recipient_identity_x25519: &StaticSecret,
        signed_prekey_secret: &StaticSecret,
        one_time_prekey_secret: Option<&StaticSecret>,
    ) -> Result<Self, EncryptionError> {
        let ephemeral_public = X25519PublicKey::from(initial_message.ephemeral_key);
        let sender_identity_key = X25519PublicKey::from(initial_message.sender_identity_key_x25519);
        
        // Perform the same DH calculations
        // DH1 = DH(SPK_B, IK_A)
        let dh1 = signed_prekey_secret.diffie_hellman(&sender_identity_key);
        
        // DH2 = DH(IK_B, EK_A)
        let dh2 = recipient_identity_x25519.diffie_hellman(&ephemeral_public);
        
        // DH3 = DH(SPK_B, EK_A)
        let dh3 = signed_prekey_secret.diffie_hellman(&ephemeral_public);
        
        // DH4 = DH(OPK_B, EK_A) (if one-time prekey was used)
        let dh4 = if let (Some(otk_secret), Some(_)) = (one_time_prekey_secret, initial_message.used_one_time_prekey) {
            Some(otk_secret.diffie_hellman(&ephemeral_public))
        } else {
            None
        };
        
        // Derive the same shared secret
        let mut kdf_input = Vec::new();
        kdf_input.extend_from_slice(dh1.as_bytes());
        kdf_input.extend_from_slice(dh2.as_bytes());
        kdf_input.extend_from_slice(dh3.as_bytes());
        if let Some(ref dh4) = dh4 {
            kdf_input.extend_from_slice(dh4.as_bytes());
        }
        
        let shared_secret = blake3::hash(&kdf_input);
        let shared_secret_bytes = *shared_secret.as_bytes();
        
        // Create cipher
        let cipher = ChaCha20Poly1305::new_from_slice(&shared_secret_bytes)
            .map_err(|_| EncryptionError::InvalidKeySize)?;
        
        // Verify we can decrypt the initial message
        let nonce = Nonce::from_slice(&initial_message.nonce);
        let _decrypted = cipher.decrypt(nonce, initial_message.ciphertext.as_ref())?;
        
        Ok(X3DHSession {
            shared_secret: shared_secret_bytes,
            cipher,
        })
    }
    
    /// Encrypt data using the established session
    pub fn encrypt(&self, data: &[u8]) -> Result<(Vec<u8>, [u8; 12]), EncryptionError> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = self.cipher.encrypt(&nonce, data)?;
        Ok((ciphertext, *nonce.as_ref()))
    }
    
    /// Decrypt data using the established session
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>, EncryptionError> {
        let nonce = Nonce::from_slice(nonce);
        let plaintext = self.cipher.decrypt(nonce, ciphertext)?;
        Ok(plaintext)
    }
}

/// Encrypt paste content for storage (simple approach for account sharing)
pub fn encrypt_paste_content(content: &[u8]) -> Result<(Vec<u8>, [u8; 12], [u8; 32]), EncryptionError> {
    // Generate a random key for this paste
    let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = ChaCha20Poly1305::new(&key);
    
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, content)?;
    
    Ok((ciphertext, *nonce.as_ref(), *key.as_ref()))
}

/// Decrypt paste content from storage
pub fn decrypt_paste_content(
    ciphertext: &[u8], 
    nonce: &[u8; 12], 
    key: &[u8; 32]
) -> Result<Vec<u8>, EncryptionError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| EncryptionError::InvalidKeySize)?;
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher.decrypt(nonce, ciphertext)?;
    Ok(plaintext)
}

/// Encrypt paste content using X3DH protocol for all devices in an account
pub fn encrypt_paste_content_x3dh(
    content: &[u8],
    sender_identity_ed25519: &SigningKey,
    sender_identity_x25519: &StaticSecret,
    recipient_bundles: &[(String, X3DHKeyBundle)], // (device_fingerprint, bundle)
) -> Result<(Vec<u8>, Vec<(String, X3DHInitialMessage)>), EncryptionError> {
    if recipient_bundles.is_empty() {
        return Err(EncryptionError::InvalidKeySize);
    }

    // Generate a random content encryption key
    let content_key = ChaCha20Poly1305::generate_key(&mut OsRng);
    let content_cipher = ChaCha20Poly1305::new(&content_key);
    
    // Encrypt the actual content with the random key
    let content_nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let encrypted_content = content_cipher.encrypt(&content_nonce, content)?;
    
    // Prepare the final content: content_nonce + content_key_size + encrypted_content_keys + encrypted_content
    let mut x3dh_messages = Vec::new();
    let mut encrypted_keys = Vec::new();
    
    // For each device, encrypt the content key using X3DH
    for (device_fingerprint, bundle) in recipient_bundles {
        let (session, initial_message) = X3DHSession::initiate(
            bundle,
            sender_identity_ed25519,
            sender_identity_x25519,
        )?;

        // Encrypt the content key for this device
        let (encrypted_key, key_nonce) = session.encrypt(content_key.as_slice())?;
        
        // Store: key_nonce (12 bytes) + encrypted_key
        let mut device_key_data = Vec::with_capacity(12 + encrypted_key.len());
        device_key_data.extend_from_slice(&key_nonce);
        device_key_data.extend_from_slice(&encrypted_key);
        
        encrypted_keys.push(device_key_data);
        x3dh_messages.push((device_fingerprint.clone(), initial_message));
    }
    
    // Build final encrypted data structure:
    // content_nonce (12) + num_devices (4) + [key_data_size (4) + key_data]* + encrypted_content
    let mut final_content = Vec::new();
    
    // Content nonce (12 bytes)
    final_content.extend_from_slice(content_nonce.as_ref());
    
    // Number of devices (4 bytes)
    final_content.extend_from_slice(&(encrypted_keys.len() as u32).to_le_bytes());
    
    // Each device's encrypted key data
    for key_data in &encrypted_keys {
        // Key data size (4 bytes) + key data
        final_content.extend_from_slice(&(key_data.len() as u32).to_le_bytes());
        final_content.extend_from_slice(key_data);
    }
    
    // Encrypted content
    final_content.extend_from_slice(&encrypted_content);

    Ok((final_content, x3dh_messages))
}

/// Decrypt paste content using X3DH protocol
pub fn decrypt_paste_content_x3dh(
    encrypted_data: &[u8],
    initial_message: &X3DHInitialMessage,
    recipient_identity_ed25519: &SigningKey,
    recipient_identity_x25519: &StaticSecret,
    recipient_signed_prekey: &StaticSecret,
    recipient_one_time_prekey: Option<&StaticSecret>,
    device_index: usize, // Which device's key to use for decryption
) -> Result<Vec<u8>, EncryptionError> {
    
    // Parse the encrypted data structure:
    // content_nonce (12) + num_devices (4) + [key_data_size (4) + key_data]* + encrypted_content
    
    if encrypted_data.len() < 16 {
        return Err(EncryptionError::InvalidKeySize);
    }
    
    let mut offset = 0;
    
    // Extract content nonce (12 bytes)
    let content_nonce: [u8; 12] = encrypted_data[offset..offset + 12]
        .try_into()
        .map_err(|_| EncryptionError::InvalidKeySize)?;
    offset += 12;
    
    // Extract number of devices (4 bytes)
    let num_devices = u32::from_le_bytes(
        encrypted_data[offset..offset + 4]
            .try_into()
            .map_err(|_| EncryptionError::InvalidKeySize)?
    ) as usize;
    offset += 4;
    
    if device_index >= num_devices {
        return Err(EncryptionError::InvalidKeySize);
    }
    
    // Skip to the correct device's key data
    for _i in 0..device_index {
        let key_data_size = u32::from_le_bytes(
            encrypted_data[offset..offset + 4]
                .try_into()
                .map_err(|_| EncryptionError::InvalidKeySize)?
        ) as usize;
        offset += 4 + key_data_size;
    }
    
    // Extract this device's key data
    let key_data_size = u32::from_le_bytes(
        encrypted_data[offset..offset + 4]
            .try_into()
            .map_err(|_| EncryptionError::InvalidKeySize)?
    ) as usize;
    offset += 4;
    
    if offset + key_data_size > encrypted_data.len() {
        return Err(EncryptionError::InvalidKeySize);
    }
    
    let key_data = &encrypted_data[offset..offset + key_data_size];
    offset += key_data_size;
    
    // Skip remaining devices' key data
    for _i in (device_index + 1)..num_devices {
        let key_data_size = u32::from_le_bytes(
            encrypted_data[offset..offset + 4]
                .try_into()
                .map_err(|_| EncryptionError::InvalidKeySize)?
        ) as usize;
        offset += 4 + key_data_size;
    }
    
    // The rest is encrypted content
    let encrypted_content = &encrypted_data[offset..];

    // Recreate the X3DH session
    let session = X3DHSession::accept(
        initial_message,
        recipient_identity_ed25519,
        recipient_identity_x25519,
        recipient_signed_prekey,
        recipient_one_time_prekey,
    )?;

    // Decrypt the content key using X3DH session
    // key_data format: key_nonce (12) + encrypted_key
    if key_data.len() < 12 {
        return Err(EncryptionError::InvalidKeySize);
    }
    
    let key_nonce: [u8; 12] = key_data[0..12]
        .try_into()
        .map_err(|_| EncryptionError::InvalidKeySize)?;
    let encrypted_key = &key_data[12..];
    
    let content_key_bytes = session.decrypt(encrypted_key, &key_nonce)?;
    if content_key_bytes.len() != 32 {
        return Err(EncryptionError::InvalidKeySize);
    }
    
    // Create content cipher and decrypt the actual content
    let content_key: [u8; 32] = content_key_bytes.try_into()
        .map_err(|_| EncryptionError::InvalidKeySize)?;
    let content_cipher = ChaCha20Poly1305::new_from_slice(&content_key)
        .map_err(|_| EncryptionError::InvalidKeySize)?;
    
    let content_nonce_obj = Nonce::from_slice(&content_nonce);
    let plaintext = content_cipher.decrypt(content_nonce_obj, encrypted_content)?;
    
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    #[test]
    fn test_x3dh_without_one_time_prekey() {
        // Generate identity keys for Alice and Bob
        let alice_identity_ed25519 = SigningKey::generate(&mut OsRng);
        let alice_identity_x25519 = StaticSecret::random_from_rng(&mut OsRng);
        let bob_identity = SigningKey::generate(&mut OsRng);
        
        // Bob generates a key bundle without one-time prekeys
        let bob_identity_x25519 = StaticSecret::random_from_rng(&mut OsRng);
        let bob_identity_x25519_public = X25519PublicKey::from(&bob_identity_x25519);
        let signed_prekey_secret = StaticSecret::random_from_rng(&mut OsRng);
        let signed_prekey = X25519PublicKey::from(&signed_prekey_secret);
        let prekey_signature = bob_identity.sign(signed_prekey.as_bytes());
        
        let bob_bundle = X3DHKeyBundle {
            identity_key_ed25519: *bob_identity.verifying_key().as_bytes(),
            identity_key_x25519: *bob_identity_x25519_public.as_bytes(),
            signed_prekey: *signed_prekey.as_bytes(),
            prekey_signature: prekey_signature.to_bytes(),
            one_time_prekeys: Vec::new(), // No one-time prekeys
        };
        
        // Alice initiates key exchange
        let (alice_session, initial_message) = X3DHSession::initiate(&bob_bundle, &alice_identity_ed25519, &alice_identity_x25519).unwrap();
        
        // Bob accepts the key exchange
        let bob_session = X3DHSession::accept(
            &initial_message,
            &bob_identity,
            &bob_identity_x25519,
            &signed_prekey_secret,
            None, // No one-time prekey secret
        ).unwrap();
        
        // Test encryption/decryption
        let test_data = b"Hello, secure world!";
        let (ciphertext, nonce) = alice_session.encrypt(test_data).unwrap();
        let decrypted = bob_session.decrypt(&ciphertext, &nonce).unwrap();
        
        assert_eq!(test_data, decrypted.as_slice());
    }

    #[test]
    fn test_x3dh_key_exchange() {
        // Generate identity keys for Alice and Bob
        let alice_identity_ed25519 = SigningKey::generate(&mut OsRng);
        let alice_identity_x25519 = StaticSecret::random_from_rng(&mut OsRng);
        let bob_identity_ed25519 = SigningKey::generate(&mut OsRng);
        
        // Bob generates a key bundle
        let (bob_bundle, bob_identity_x25519, bob_signed_prekey_secret, bob_one_time_prekey_secrets) = X3DHKeyBundle::generate(&bob_identity_ed25519);
        
        // Alice initiates key exchange
        let (alice_session, initial_message) = X3DHSession::initiate(&bob_bundle, &alice_identity_ed25519, &alice_identity_x25519).unwrap();
        
        // Bob accepts the key exchange
        let bob_session = X3DHSession::accept(
            &initial_message,
            &bob_identity_ed25519,
            &bob_identity_x25519,
            &bob_signed_prekey_secret,
            bob_one_time_prekey_secrets.first(), // Use the first one-time prekey secret
        ).unwrap();
        
        // Test encryption/decryption
        let test_data = b"Hello, secure world!";
        let (ciphertext, nonce) = alice_session.encrypt(test_data).unwrap();
        let decrypted = bob_session.decrypt(&ciphertext, &nonce).unwrap();
        
        assert_eq!(test_data, decrypted.as_slice());
    }
    
    #[test]
    fn test_paste_encryption() {
        let content = b"This is a test paste";
        let (ciphertext, nonce, key) = encrypt_paste_content(content).unwrap();
        let decrypted = decrypt_paste_content(&ciphertext, &nonce, &key).unwrap();
        
        assert_eq!(content, decrypted.as_slice());
    }
    
    #[test]
    fn test_x3dh_paste_sharing_end_to_end() {
        use crate::io::{X3DHBundleStore, DevicePrivateKeyStore, KeyStore, PublicKeyInfo};
        
        // Initialize stores using correct data structures
        let x3dh_store = X3DHBundleStore::default();
        let private_key_store = DevicePrivateKeyStore::default();
        let key_store = KeyStore::default();
        
        // Test scenario: Alice (Device A) and Bob (Device B) in the same account
        let account_hash = "test_account_123";
        let alice_fingerprint = "ALICE001";
        let bob_fingerprint = "BOBDEV01";
        
        // Alice generates her key bundle and stores it
        let (alice_private_keys, alice_bundle, alice_identity_ed25519) = DevicePrivateKeys::generate();
        
        // Store Alice's keys and associate with account
        crate::io::store_x3dh_bundle(&x3dh_store, alice_fingerprint.to_string(), alice_bundle.clone());
        crate::io::store_device_private_keys(&private_key_store, alice_fingerprint.to_string(), alice_private_keys);
        
        // Create and store Alice's public key info with account association
        let alice_public_key_info = PublicKeyInfo {
            fingerprint: alice_fingerprint.to_string(),
            public_key: alice_bundle.identity_key_ed25519,
            account_hash: Some(account_hash.to_string()),
            created_at: 0, // timestamp not important for test
        };
        crate::io::store_public_key(&key_store, alice_public_key_info);
        
        // Bob generates his key bundle and stores it
        let (bob_private_keys, bob_bundle, bob_identity_ed25519) = DevicePrivateKeys::generate();
        
        // Store Bob's keys and associate with account
        crate::io::store_x3dh_bundle(&x3dh_store, bob_fingerprint.to_string(), bob_bundle.clone());
        crate::io::store_device_private_keys(&private_key_store, bob_fingerprint.to_string(), bob_private_keys);
        
        // Create and store Bob's public key info with account association
        let bob_public_key_info = PublicKeyInfo {
            fingerprint: bob_fingerprint.to_string(),
            public_key: bob_bundle.identity_key_ed25519,
            account_hash: Some(account_hash.to_string()),
            created_at: 0, // timestamp not important for test
        };
        crate::io::store_public_key(&key_store, bob_public_key_info);
        
        // Test data to share
        let test_paste_content = b"This is a secret message shared via X3DH!";
        
        // For this test, we'll use Alice as the sender and derive sender keys properly
        let alice_private_keys = crate::io::get_device_private_keys(&private_key_store, alice_fingerprint).unwrap();
        let (_, sender_identity_x25519, _sender_signed_prekey, _sender_one_time_prekeys) = alice_private_keys.to_crypto_types();
        
        // Alice encrypts the paste using X3DH directly (bypassing try_encrypt_paste_with_x3dh for testing)
        let account_bundles = crate::io::list_x3dh_bundles_by_account(&x3dh_store, &key_store, account_hash);
        assert!(!account_bundles.is_empty(), "Should find account bundles");
        
        let encryption_result = encrypt_paste_content_x3dh(
            test_paste_content,
            &alice_identity_ed25519,
            &sender_identity_x25519,
            &account_bundles,
        );
        
        assert!(encryption_result.is_ok(), "X3DH encryption should succeed");
        let (encrypted_content, x3dh_initial_messages) = encryption_result.unwrap();
        
        // Verify encryption worked
        assert_ne!(encrypted_content, test_paste_content, "Content should be encrypted");
        
        // Verify that both Alice and Bob have initial messages
        assert!(x3dh_initial_messages.iter().any(|(fp, _)| fp == alice_fingerprint), "Alice should have an initial message");
        assert!(x3dh_initial_messages.iter().any(|(fp, _)| fp == bob_fingerprint), "Bob should have an initial message");
        
        // Test decryption from Alice's perspective (simulating show_paste endpoint)
        let alice_private_keys = crate::io::get_device_private_keys(&private_key_store, alice_fingerprint).unwrap();
        let alice_initial_message = x3dh_initial_messages.iter().find(|(fp, _)| fp == alice_fingerprint).unwrap().1.clone();
        let (_, alice_identity_x25519, alice_signed_prekey, alice_one_time_prekeys) = alice_private_keys.to_crypto_types();
        let alice_one_time_prekey = alice_one_time_prekeys.first();
        
        let alice_decrypted = decrypt_paste_content_x3dh(
            &encrypted_content,
            &alice_initial_message,
            &alice_identity_ed25519,
            &alice_identity_x25519,
            &alice_signed_prekey,
            alice_one_time_prekey,
            0, // Alice is the first device (index 0)
        );
        
        match alice_decrypted {
            Ok(decrypted) => {
                assert_eq!(decrypted, test_paste_content, "Alice should get back the original content");
            }
            Err(e) => {
                panic!("Alice decryption failed with error: {:?}", e);
            }
        }
        
        // Test decryption from Bob's perspective
        let bob_private_keys = crate::io::get_device_private_keys(&private_key_store, bob_fingerprint).unwrap();
        let bob_initial_message = x3dh_initial_messages.iter().find(|(fp, _)| fp == bob_fingerprint).unwrap().1.clone();
        let (_, bob_identity_x25519, bob_signed_prekey, bob_one_time_prekeys) = bob_private_keys.to_crypto_types();
        let bob_one_time_prekey = bob_one_time_prekeys.first();
        
        let bob_decrypted = decrypt_paste_content_x3dh(
            &encrypted_content,
            &bob_initial_message,
            &bob_identity_ed25519,
            &bob_identity_x25519,
            &bob_signed_prekey,
            bob_one_time_prekey,
            1, // Bob is the second device (index 1)
        );
        
        assert!(bob_decrypted.is_ok(), "Bob should be able to decrypt the paste");
        assert_eq!(bob_decrypted.unwrap(), test_paste_content, "Bob should get back the original content");
        
        println!("✅ X3DH end-to-end paste sharing test passed!");
        println!("   - Generated key bundles for 2 devices");
        println!("   - Encrypted paste content using X3DH for account sharing");
        println!("   - Successfully decrypted from both devices");
        println!("   - Verified content integrity across all operations");
    }
}