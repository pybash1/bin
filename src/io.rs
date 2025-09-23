use actix_web::web::Bytes;
use linked_hash_map::LinkedHashMap;
use parking_lot::RwLock;
use rand::{Rng, distr::Alphanumeric, rng};
use std::{cell::RefCell, collections::HashSet};
use crate::encryption::{X3DHKeyBundle, X3DHInitialMessage, DevicePrivateKeys};

#[derive(Clone)]
pub struct Paste {
    pub content: Bytes,               // Encrypted content (ciphertext)
    pub device_fingerprint: String,
    pub account_hash: Option<String>,
    pub created_at: u64,
    // X3DH-based encryption fields
    pub x3dh_initial_messages: Option<Vec<(String, X3DHInitialMessage)>>, // (device_fingerprint, initial_message) pairs
    pub encryption_nonce: Option<[u8; 12]>, // ChaCha20Poly1305 nonce
    // Legacy encryption fields (for backwards compatibility)
    pub encryption_key: Option<[u8; 32]>,   // Encryption key (for per-paste encryption)
    pub is_encrypted: bool,           // Whether this paste is encrypted
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PublicKeyInfo {
    pub fingerprint: String,
    pub public_key: [u8; 32],
    pub account_hash: Option<String>,
    pub created_at: u64, // Unix timestamp
}

pub type PasteStore = RwLock<LinkedHashMap<String, Paste>>;
pub type KeyStore = RwLock<LinkedHashMap<String, PublicKeyInfo>>;
pub type X3DHBundleStore = RwLock<LinkedHashMap<String, X3DHKeyBundle>>;
pub type DevicePrivateKeyStore = RwLock<LinkedHashMap<String, DevicePrivateKeys>>;

const ACCOUNT_PASTE_LIMIT: usize = 10; // Allow more pastes per account
const DEVICE_PASTE_LIMIT: usize = 2; // Legacy limit for device-only storage

fn purge_old_pastes(entries: &mut LinkedHashMap<String, Paste>, account_hash: Option<&str>, device_fingerprint: &str) {
    if let Some(account_hash) = account_hash {
        // Account-based storage: limit pastes per account
        let account_paste_ids: Vec<String> = entries
            .iter()
            .filter(|(_, paste)| paste.account_hash.as_deref() == Some(account_hash))
            .map(|(id, _)| id.clone())
            .collect();
        
        let to_remove = account_paste_ids.len().saturating_sub(ACCOUNT_PASTE_LIMIT - 1);
        for id in account_paste_ids.into_iter().take(to_remove) {
            entries.remove(&id);
        }
    } else {
        // Legacy device-based storage
        let device_paste_ids: Vec<String> = entries
            .iter()
            .filter(|(_, paste)| paste.device_fingerprint == device_fingerprint && paste.account_hash.is_none())
            .map(|(id, _)| id.clone())
            .collect();

        let to_remove = device_paste_ids.len().saturating_sub(DEVICE_PASTE_LIMIT - 1);
        for id in device_paste_ids.into_iter().take(to_remove) {
            entries.remove(&id);
        }
    }
}

pub fn generate_id() -> String {
    thread_local!(static KEYGEN: RefCell<gpw::PasswordGenerator> = RefCell::new(gpw::PasswordGenerator::default()));

    KEYGEN.with(|k| k.borrow_mut().next()).unwrap_or_else(|| {
        rng()
            .sample_iter(&Alphanumeric)
            .take(6)
            .map(char::from)
            .collect()
    })
}

pub fn store_paste(
    store: &PasteStore, 
    id: String, 
    content: Bytes, 
    device_fingerprint: String, 
    account_hash: Option<String>,
    x3dh_initial_messages: Option<Vec<(String, X3DHInitialMessage)>>,
    encryption_nonce: Option<[u8; 12]>,
    encryption_key: Option<[u8; 32]>,
    is_encrypted: bool,
) {
    let mut entries = store.write();
    purge_old_pastes(&mut entries, account_hash.as_deref(), &device_fingerprint);
    
    let paste = Paste { 
        content, 
        device_fingerprint, 
        account_hash,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        x3dh_initial_messages,
        encryption_nonce,
        encryption_key,
        is_encrypted,
    };
    entries.insert(id, paste);
}

pub fn get_paste(store: &PasteStore, id: &str, device_fingerprint: &str, account_hash: Option<&str>) -> Option<(Bytes, bool, Option<Vec<(String, X3DHInitialMessage)>>, Option<[u8; 12]>, Option<[u8; 32]>)> {
    store.read().get(id).and_then(|paste| {
        // Allow access if:
        // 1. Device fingerprint matches (original owner)
        // 2. Account hash matches (same account)
        let device_matches = paste.device_fingerprint == device_fingerprint;
        let account_matches = account_hash.is_some() && 
                             paste.account_hash.as_deref() == account_hash;
        
        if device_matches || account_matches {
            Some((
                paste.content.clone(),
                paste.is_encrypted,
                paste.x3dh_initial_messages.clone(),
                paste.encryption_nonce,
                paste.encryption_key,
            ))
        } else {
            None
        }
    })
}

pub fn get_all_paste_ids(store: &PasteStore, device_fingerprint: &str, account_hash: Option<&str>) -> Vec<String> {
    let mut ids: Vec<String> = store
        .read()
        .iter()
        .filter(|(_, paste)| {
            // Return pastes that:
            // 1. Were created by this device, OR
            // 2. Belong to the same account (if account_hash is provided)
            let device_matches = paste.device_fingerprint == device_fingerprint;
            let account_matches = account_hash.is_some() && 
                                 paste.account_hash.as_deref() == account_hash;
            
            device_matches || account_matches
        })
        .map(|(id, _)| id.clone())
        .collect();
    ids.reverse();
    ids
}

pub fn generate_unique_device_fingerprint(store: &PasteStore) -> String {
    use crate::identity::DeviceIdentity;
    
    let existing_fingerprints: HashSet<String> = store
        .read()
        .values()
        .map(|paste| paste.device_fingerprint.clone())
        .collect();

    loop {
        let identity = DeviceIdentity::generate();
        if !existing_fingerprints.contains(&identity.fingerprint) {
            return identity.fingerprint;
        }
    }
}

// Key storage functions
pub fn store_public_key(store: &KeyStore, key_info: PublicKeyInfo) {
    let mut entries = store.write();
    entries.insert(key_info.fingerprint.clone(), key_info);
}

pub fn get_public_key(store: &KeyStore, fingerprint: &str) -> Option<PublicKeyInfo> {
    store.read().get(fingerprint).cloned()
}

pub fn list_public_keys_by_account(store: &KeyStore, account_hash: &str) -> Vec<PublicKeyInfo> {
    store
        .read()
        .values()
        .filter(|key_info| key_info.account_hash.as_deref() == Some(account_hash))
        .cloned()
        .collect()
}

// X3DH key bundle storage functions
pub fn store_x3dh_bundle(store: &X3DHBundleStore, fingerprint: String, bundle: X3DHKeyBundle) {
    let mut entries = store.write();
    entries.insert(fingerprint, bundle);
}

pub fn get_x3dh_bundle(store: &X3DHBundleStore, fingerprint: &str) -> Option<X3DHKeyBundle> {
    store.read().get(fingerprint).cloned()
}

pub fn list_x3dh_bundles_by_account(store: &X3DHBundleStore, key_store: &KeyStore, account_hash: &str) -> Vec<(String, X3DHKeyBundle)> {
    // Get all devices in the account
    let account_devices: HashSet<String> = key_store
        .read()
        .values()
        .filter(|key_info| key_info.account_hash.as_deref() == Some(account_hash))
        .map(|key_info| key_info.fingerprint.clone())
        .collect();
    
    // Get X3DH bundles for those devices
    store
        .read()
        .iter()
        .filter(|(fingerprint, _)| account_devices.contains(*fingerprint))
        .map(|(fingerprint, bundle)| (fingerprint.clone(), bundle.clone()))
        .collect()
}

// Device private key storage functions
pub fn store_device_private_keys(store: &DevicePrivateKeyStore, fingerprint: String, private_keys: DevicePrivateKeys) {
    let mut entries = store.write();
    entries.insert(fingerprint, private_keys);
}

pub fn get_device_private_keys(store: &DevicePrivateKeyStore, fingerprint: &str) -> Option<DevicePrivateKeys> {
    store.read().get(fingerprint).cloned()
}

pub fn remove_device_private_keys(store: &DevicePrivateKeyStore, fingerprint: &str) -> Option<DevicePrivateKeys> {
    let mut entries = store.write();
    entries.remove(fingerprint)
}
