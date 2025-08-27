use actix_web::web::Bytes;
use linked_hash_map::LinkedHashMap;
use parking_lot::RwLock;
use rand::{Rng, distr::Alphanumeric, rng};
use std::{cell::RefCell, collections::HashSet};

#[derive(Clone)]
pub struct Paste {
    pub content: Bytes,
    pub device_code: String,
}

pub type PasteStore = RwLock<LinkedHashMap<String, Paste>>;

const DEVICE_PASTE_LIMIT: usize = 2; 

/// Ensures device doesn't exceed paste limit. If it does, removes oldest pastes for that device.
fn purge_device_old(entries: &mut LinkedHashMap<String, Paste>, device_code: &str) {
    let device_pastes: Vec<_> = entries
        .iter()
        .filter(|(_, paste)| paste.device_code == device_code)
        .map(|(id, _)| id.clone())
        .collect();

    if device_pastes.len() >= DEVICE_PASTE_LIMIT {
        let to_remove = device_pastes.len() - DEVICE_PASTE_LIMIT + 1;
        for i in 0..to_remove {
            if let Some(id) = device_pastes.get(i) {
                entries.remove(id);
            }
        }
    }
}

/// Generates a 'pronounceable' random ID using gpw
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

/// Stores a paste under the given id for a specific device
pub fn store_paste(entries: &PasteStore, id: String, content: Bytes, device_code: String) {
    let mut entries = entries.write();

    purge_device_old(&mut entries, &device_code);

    entries.insert(id, Paste { content, device_code });
}

/// Get a paste by id if the requesting device owns it.
///
/// Returns `None` if the paste doesn't exist or device doesn't own it.
pub fn get_paste(entries: &PasteStore, id: &str, device_code: &str) -> Option<Bytes> {
    entries.read().get(id).and_then(|paste| {
        if paste.device_code == device_code {
            Some(paste.content.clone())
        } else {
            None
        }
    })
}

/// Get all paste IDs for a specific device.
pub fn get_all_paste_ids(entries: &PasteStore, device_code: &str) -> Vec<String> {
    let mut ids: Vec<String> = entries
        .read()
        .iter()
        .filter(|(_, paste)| paste.device_code == device_code)
        .map(|(id, _)| id.clone())
        .collect();
    ids.reverse();
    ids
}

/// Generate a unique 8-character device code that doesn't already exist
pub fn generate_unique_device_code(entries: &PasteStore) -> String {
    let existing_devices: HashSet<String> = entries
        .read()
        .values()
        .map(|paste| paste.device_code.clone())
        .collect();

    loop {
        let device_code: String = rng()
            .sample_iter(&Alphanumeric)
            .filter(|c| c.is_ascii_alphanumeric() && (c.is_ascii_uppercase() || c.is_ascii_digit()))
            .take(8)
            .map(char::from)
            .collect();

        if !existing_devices.contains(&device_code) {
            return device_code;
        }
    }
}
