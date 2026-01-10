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

fn purge_old_device_pastes(entries: &mut LinkedHashMap<String, Paste>, device_code: &str) {
    let device_paste_ids: Vec<String> = entries
        .iter()
        .filter(|(_, paste)| paste.device_code == device_code)
        .map(|(id, _)| id.clone())
        .collect();

    let to_remove = device_paste_ids
        .len()
        .saturating_sub(DEVICE_PASTE_LIMIT - 1);
    for id in device_paste_ids.into_iter().take(to_remove) {
        entries.remove(&id);
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

pub fn store_paste(store: &PasteStore, id: String, content: Bytes, device_code: String) {
    let mut entries = store.write();
    purge_old_device_pastes(&mut entries, &device_code);
    entries.insert(
        id,
        Paste {
            content,
            device_code,
        },
    );
}

pub fn get_paste(store: &PasteStore, id: &str, device_code: &str) -> Option<Bytes> {
    store
        .read()
        .get(id)
        .and_then(|paste| (paste.device_code == device_code).then(|| paste.content.clone()))
}

pub fn get_all_paste_ids(store: &PasteStore, device_code: &str) -> Vec<String> {
    let mut ids: Vec<String> = store
        .read()
        .iter()
        .filter(|(_, paste)| paste.device_code == device_code)
        .map(|(id, _)| id.clone())
        .collect();
    ids.reverse();
    ids
}

pub fn generate_unique_device_code(store: &PasteStore) -> String {
    let existing_devices: HashSet<String> = store
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
