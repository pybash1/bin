#![deny(clippy::pedantic)]
#![allow(clippy::unused_async)]

mod errors;
mod encryption;
mod identity;
mod io;
mod params;

use crate::{
    errors::{BadRequest, NotFound, Unauthorized},
    encryption::{X3DHKeyBundle, X3DHInitialMessage, encrypt_paste_content, decrypt_paste_content, encrypt_paste_content_x3dh, decrypt_paste_content_x3dh, DevicePrivateKeys},
    identity::{DeviceIdentity, AccountMasterKey},
    io::{PasteStore, KeyStore, X3DHBundleStore, DevicePrivateKeyStore, PublicKeyInfo, generate_id, generate_unique_device_fingerprint, get_all_paste_ids, store_paste, get_paste, store_public_key, get_public_key, list_public_keys_by_account, store_x3dh_bundle, get_x3dh_bundle, list_x3dh_bundles_by_account, store_device_private_keys, get_device_private_keys},
    params::{DeviceFingerprint, HostHeader, AccountHash},
};
use actix_web::{
    App, Error, HttpRequest, HttpResponse, HttpServer, http::header,
    web::{self, Bytes, Data, FormConfig, PayloadConfig},
};
use base64::prelude::*;
use log::{error, info};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(argh::FromArgs, Clone)]
/// arguments
pub struct BinArgs {
    #[argh(positional, default = "SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8820)")]
    bind_addr: SocketAddr,
    #[argh(option, default = "32 * 1024")]
    /// max paste size (32kb)
    max_paste_size: usize,
}

fn check_auth(req: &HttpRequest, password: Option<&str>) -> Result<(), Unauthorized> {
    password.map_or(Ok(()), |pwd| {
        req.headers()
            .get("App-Password")
            .and_then(|h| h.to_str().ok())
            .filter(|provided| *provided == pwd)
            .map_or(Err(Unauthorized), |_| Ok(()))
    })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> { 
    dotenv::dotenv().ok();
    pretty_env_logger::formatted_builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let args: BinArgs = argh::from_env();
    let password = std::env::var("APP_PASSWORD").ok();
    let store = Data::new(PasteStore::default());
    let key_store = Data::new(KeyStore::default());
    let x3dh_store = Data::new(X3DHBundleStore::default());
    let private_key_store = Data::new(DevicePrivateKeyStore::default());
    let auth_config = Data::new(password);

    let server = HttpServer::new({
        let args = args.clone();
        move || {
            App::new()
                .app_data(store.clone())
                .app_data(key_store.clone())
                .app_data(x3dh_store.clone())
                .app_data(private_key_store.clone())
                .app_data(auth_config.clone())
                .app_data(PayloadConfig::default().limit(args.max_paste_size))
                .app_data(FormConfig::default().limit(args.max_paste_size))
                .wrap(actix_web::middleware::Compress::default())
                .route("/", web::get().to(index))
                .route("/device", web::post().to(generate_device_fingerprint))
                .route("/account", web::post().to(create_account))
                .route("/account/link", web::post().to(link_device_to_account))
                .route("/keys/{fingerprint}", web::put().to(store_device_key))
                .route("/keys/{fingerprint}", web::get().to(get_device_key))
                .route("/keys/account/{account_hash}", web::get().to(list_account_keys))
                .route("/x3dh/bundle/{fingerprint}", web::put().to(store_x3dh_key_bundle))
                .route("/x3dh/bundle/{fingerprint}", web::get().to(get_x3dh_key_bundle))
                .route("/x3dh/bundles/account/{account_hash}", web::get().to(list_account_x3dh_bundles))
                .route("/all", web::get().to(list_all_pastes))
                .route("/", web::post().to(submit))
                .route("/", web::put().to(submit_raw))
                .route("/{paste}", web::get().to(show_paste))
                .default_service(web::to(|req: HttpRequest| async move {
                    error!("Resource not found: {}", req.uri());
                    HttpResponse::from_error(NotFound)
                }))
        }
    });

    info!("Listening on http://{}", args.bind_addr);
    server.bind(args.bind_addr)?.run().await
}

#[derive(serde::Serialize)]
struct ApiInfo {
    message: &'static str,
    endpoints: &'static [ApiEndpoint],
}

#[derive(serde::Serialize)]
struct ApiEndpoint {
    method: &'static str,
    path: &'static str,
    description: &'static str,
}

static API_INFO: ApiInfo = ApiInfo {
    message: "Bin API - A pastebin service with E2E encryption",
    endpoints: &[
        ApiEndpoint { method: "GET", path: "/", description: "Get API information" },
        ApiEndpoint { method: "POST", path: "/", description: "Create a new paste (form data)" },
        ApiEndpoint { method: "PUT", path: "/", description: "Create a new paste (raw data)" },
        ApiEndpoint { method: "POST", path: "/device", description: "Generate a unique device fingerprint" },
        ApiEndpoint { method: "POST", path: "/account", description: "Create new account master key" },
        ApiEndpoint { method: "POST", path: "/account/link", description: "Link device to existing account" },
        ApiEndpoint { method: "PUT", path: "/keys/{fingerprint}", description: "Store public key for device" },
        ApiEndpoint { method: "GET", path: "/keys/{fingerprint}", description: "Get public key for device" },
        ApiEndpoint { method: "GET", path: "/keys/account/{account_hash}", description: "List all devices in account" },
        ApiEndpoint { method: "PUT", path: "/x3dh/bundle/{fingerprint}", description: "Store X3DH key bundle for device" },
        ApiEndpoint { method: "GET", path: "/x3dh/bundle/{fingerprint}", description: "Get X3DH key bundle for device" },
        ApiEndpoint { method: "GET", path: "/x3dh/bundles/account/{account_hash}", description: "List X3DH bundles for account" },
        ApiEndpoint { method: "GET", path: "/all", description: "Get all paste IDs for your device" },
        ApiEndpoint { method: "GET", path: "/{paste}", description: "Get paste content by ID" },
    ],
};

async fn index() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(&API_INFO))
}

async fn generate_device_fingerprint(
    req: HttpRequest,
    store: Data<PasteStore>,
    auth_config: Data<Option<String>>,
) -> Result<String, Error> {
    check_auth(&req, auth_config.as_deref())?;
    Ok(generate_unique_device_fingerprint(&store))
}

async fn list_all_pastes(
    req: HttpRequest,
    device_fingerprint: DeviceFingerprint,
    account_hash: AccountHash,
    store: Data<PasteStore>,
    auth_config: Data<Option<String>>,
) -> Result<HttpResponse, Error> {
    check_auth(&req, auth_config.as_deref())?;
    let device_fingerprint = device_fingerprint.0.ok_or(BadRequest)?;
    let account_hash = account_hash.0.as_deref();
    let paste_ids = get_all_paste_ids(&store, &device_fingerprint, account_hash);
    Ok(HttpResponse::Ok().json(paste_ids))
}

#[derive(serde::Deserialize)]
struct PasteForm {
    val: Bytes,
}

/// Try to encrypt paste content using X3DH, fall back to symmetric encryption
pub fn try_encrypt_paste_with_x3dh(
    content: &[u8],
    device_fingerprint: &str,
    account_hash: &str,
    x3dh_store: &X3DHBundleStore,
    private_key_store: &DevicePrivateKeyStore,
    key_store: &KeyStore,
) -> Result<(Bytes, Option<Vec<(String, X3DHInitialMessage)>>, Option<[u8; 12]>, Option<[u8; 32]>, bool), Box<dyn std::error::Error>> {
    // Try to get our device's private keys
    let sender_private_keys = match get_device_private_keys(private_key_store, device_fingerprint) {
        Some(keys) => keys,
        None => {
            // Fall back to symmetric encryption
            let (encrypted_content, nonce, key) = encrypt_paste_content(content)?;
            return Ok((Bytes::from(encrypted_content), None, Some(nonce), Some(key), true));
        }
    };

    // Try to get all X3DH bundles for this account
    let account_bundles = crate::io::list_x3dh_bundles_by_account(x3dh_store, key_store, account_hash);
    if account_bundles.is_empty() {
        // Fall back to symmetric encryption
        let (encrypted_content, nonce, key) = encrypt_paste_content(content)?;
        return Ok((Bytes::from(encrypted_content), None, Some(nonce), Some(key), true));
    }

    // Convert private keys to crypto types
    let (sender_identity_ed25519, sender_identity_x25519, _signed_prekey, _one_time_prekeys) = sender_private_keys.to_crypto_types();

    // Attempt X3DH encryption
    match encrypt_paste_content_x3dh(
        content,
        &sender_identity_ed25519,
        &sender_identity_x25519,
        &account_bundles,
    ) {
        Ok((encrypted_content, x3dh_messages)) => {
            Ok((Bytes::from(encrypted_content), Some(x3dh_messages), None, None, true))
        }
        Err(_) => {
            // Fall back to symmetric encryption
            let (encrypted_content, nonce, key) = encrypt_paste_content(content)?;
            Ok((Bytes::from(encrypted_content), None, Some(nonce), Some(key), true))
        }
    }
}

async fn submit(
    req: HttpRequest,
    input: web::Form<PasteForm>,
    device_fingerprint: DeviceFingerprint,
    account_hash: AccountHash,
    store: Data<PasteStore>,
    x3dh_store: Data<X3DHBundleStore>,
    key_store: Data<KeyStore>,
    private_key_store: Data<DevicePrivateKeyStore>,
    auth_config: Data<Option<String>>,
) -> Result<HttpResponse, Error> {
    check_auth(&req, auth_config.as_deref())?;
    let device_fingerprint = device_fingerprint.0.ok_or(BadRequest)?;
    let account_hash = account_hash.0;
    let id = generate_id();
    
    let paste_data = input.into_inner().val;
    let (content, x3dh_initial_messages, encryption_nonce, encryption_key, is_encrypted) = if let Some(ref account_hash_str) = account_hash {
        // Try X3DH encryption for account-based sharing
        match try_encrypt_paste_with_x3dh(&paste_data, &device_fingerprint, account_hash_str, &x3dh_store, &private_key_store, &key_store) {
            Ok(result) => result,
            Err(_) => {
                // Fall back to symmetric encryption
                let (encrypted_content, nonce, key) = encrypt_paste_content(&paste_data)
                    .map_err(|_| BadRequest)?;
                (actix_web::web::Bytes::from(encrypted_content), None, Some(nonce), Some(key), true)
            }
        }
    } else {
        // Store unencrypted for device-only access
        (paste_data, None, None, None, false)
    };
    
    store_paste(&store, id.clone(), content, device_fingerprint, account_hash, x3dh_initial_messages, encryption_nonce, encryption_key, is_encrypted);
    Ok(HttpResponse::Found()
        .append_header((header::LOCATION, format!("/{id}")))
        .finish())
}

async fn submit_raw(
    req: HttpRequest,
    data: Bytes,
    host: HostHeader,
    device_fingerprint: DeviceFingerprint,
    account_hash: AccountHash,
    store: Data<PasteStore>,
    x3dh_store: Data<X3DHBundleStore>,
    key_store: Data<KeyStore>,
    private_key_store: Data<DevicePrivateKeyStore>,
    auth_config: Data<Option<String>>,
) -> Result<String, Error> {
    check_auth(&req, auth_config.as_deref())?;
    let device_fingerprint = device_fingerprint.0.ok_or(BadRequest)?;
    let account_hash = account_hash.0;
    let id = generate_id();
    
    let uri = match &host.0 {
        Some(host_header) => {
            if let Ok(host_str) = std::str::from_utf8(host_header.as_bytes()) {
                format!("https://{host_str}/{id}\n")
            } else {
                format!("/{id}\n")
            }
        }
        None => format!("/{id}\n"),
    };

    let (content, x3dh_initial_messages, encryption_nonce, encryption_key, is_encrypted) = if let Some(ref account_hash_str) = account_hash {
        // Try X3DH encryption for account-based sharing
        match try_encrypt_paste_with_x3dh(&data, &device_fingerprint, account_hash_str, &x3dh_store, &private_key_store, &key_store) {
            Ok(result) => result,
            Err(_) => {
                // Fall back to symmetric encryption
                let (encrypted_content, nonce, key) = encrypt_paste_content(&data)
                    .map_err(|_| BadRequest)?;
                (actix_web::web::Bytes::from(encrypted_content), None, Some(nonce), Some(key), true)
            }
        }
    } else {
        // Store unencrypted for device-only access
        (data, None, None, None, false)
    };

    store_paste(&store, id, content, device_fingerprint, account_hash, x3dh_initial_messages, encryption_nonce, encryption_key, is_encrypted);
    Ok(uri)
}


async fn show_paste(
    req: HttpRequest,
    key: actix_web::web::Path<String>,
    device_fingerprint: DeviceFingerprint,
    account_hash: AccountHash,
    store: Data<PasteStore>,
    _x3dh_store: Data<X3DHBundleStore>,
    private_key_store: Data<DevicePrivateKeyStore>,
    auth_config: Data<Option<String>>,
) -> Result<HttpResponse, Error> {
    check_auth(&req, auth_config.as_deref())?;
    let device_fingerprint = device_fingerprint.0.ok_or(BadRequest)?;
    let account_hash = account_hash.0.as_deref();
    let paste_id = key.split('.').next().unwrap();
    
    // Get the paste data
    let paste_data = get_paste(&store, paste_id, &device_fingerprint, account_hash)
        .ok_or(NotFound)?;
    
    let (paste_content, is_encrypted, x3dh_initial_messages, encryption_nonce, encryption_key) = paste_data;
    
    // Decrypt content if encrypted
    let content = if is_encrypted {
        if let Some(x3dh_messages) = x3dh_initial_messages {
            // Try X3DH decryption
            if let Some(private_keys) = get_device_private_keys(&private_key_store, &device_fingerprint) {
                // Find our device's initial message
                if let Some((_, initial_message)) = x3dh_messages.iter().find(|(fp, _)| fp == &device_fingerprint) {
                    let (identity_ed25519, identity_x25519, signed_prekey, one_time_prekeys) = private_keys.to_crypto_types();
                    
                    // Get the first one-time prekey if available
                    let one_time_prekey = one_time_prekeys.first();
                    
                    // We need the sender's identity X25519 key - this should be stored/retrieved properly
                    // For now, we'll extract it from the initial message
                    
                    match decrypt_paste_content_x3dh(
                        &paste_content,
                        initial_message,
                        &identity_ed25519,
                        &identity_x25519,
                        &signed_prekey,
                        one_time_prekey,
                        0, // Try device index 0 first, should be improved to lookup correct index
                    ) {
                        Ok(decrypted) => actix_web::web::Bytes::from(decrypted),
                        Err(_) => {
                            // Fall back to legacy decryption if available
                            if let (Some(nonce), Some(key)) = (encryption_nonce, encryption_key) {
                                actix_web::web::Bytes::from(decrypt_paste_content(&paste_content, &nonce, &key)
                                    .map_err(|_| BadRequest)?)
                            } else {
                                return Err(BadRequest.into());
                            }
                        }
                    }
                } else {
                    // Fall back to legacy decryption
                    if let (Some(nonce), Some(key)) = (encryption_nonce, encryption_key) {
                        actix_web::web::Bytes::from(decrypt_paste_content(&paste_content, &nonce, &key)
                            .map_err(|_| BadRequest)?)
                    } else {
                        return Err(BadRequest.into());
                    }
                }
            } else {
                // Fall back to legacy decryption
                if let (Some(nonce), Some(key)) = (encryption_nonce, encryption_key) {
                    actix_web::web::Bytes::from(decrypt_paste_content(&paste_content, &nonce, &key)
                        .map_err(|_| BadRequest)?)
                } else {
                    return Err(BadRequest.into());
                }
            }
        } else if let (Some(nonce), Some(key)) = (encryption_nonce, encryption_key) {
            // Legacy encryption
            actix_web::web::Bytes::from(decrypt_paste_content(&paste_content, &nonce, &key)
                .map_err(|_| BadRequest)?)
        } else {
            return Err(BadRequest.into());
        }
    } else {
        paste_content
    };
    
    Ok(HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(content))
}

#[derive(serde::Deserialize)]
struct StoreKeyRequest {
    public_key: String, // base64 encoded
    account_hash: Option<String>,
}

#[derive(serde::Serialize)]
struct KeyResponse {
    public_key: String,
    account_hash: Option<String>,
    created_at: u64,
}

#[derive(serde::Serialize)]
struct DeviceInfo {
    fingerprint: String,
    public_key: String,
    created_at: u64,
}

#[derive(serde::Serialize)]
struct AccountResponse {
    account_hash: String,
    device_fingerprint: String,
    public_key: String,
    linking_url: String,
    master_key: String, // base64 encoded for client storage
}

#[derive(serde::Serialize)]
struct LinkResponse {
    account_hash: String,
    device_fingerprint: String,
    public_key: String,
    master_key: String, // base64 encoded for client storage
}

#[derive(serde::Serialize)]
struct BundleInfo {
    fingerprint: String,
    bundle: X3DHKeyBundle,
}

async fn store_device_key(
    req: HttpRequest,
    fingerprint: actix_web::web::Path<String>,
    device_fingerprint: DeviceFingerprint,
    key_request: web::Json<StoreKeyRequest>,
    key_store: Data<KeyStore>,
    auth_config: Data<Option<String>>,
) -> Result<HttpResponse, Error> {
    check_auth(&req, auth_config.as_deref())?;
    let device_fingerprint = device_fingerprint.0.ok_or(BadRequest)?;
    
    // Verify the fingerprint matches the requesting device
    if fingerprint.as_str() != device_fingerprint {
        return Ok(HttpResponse::Forbidden().json("Fingerprint mismatch"));
    }
    
    // Decode the public key
    let public_key_bytes = base64::prelude::BASE64_STANDARD
        .decode(&key_request.public_key)
        .map_err(|_| BadRequest)?;
    
    if public_key_bytes.len() != 32 {
        return Err(BadRequest.into());
    }
    
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&public_key_bytes);
    
    let key_info = PublicKeyInfo {
        fingerprint: device_fingerprint,
        public_key,
        account_hash: key_request.account_hash.clone(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    
    store_public_key(&key_store, key_info);
    Ok(HttpResponse::Ok().json("Key stored successfully"))
}

async fn get_device_key(
    req: HttpRequest,
    fingerprint: actix_web::web::Path<String>,
    device_fingerprint: DeviceFingerprint,
    key_store: Data<KeyStore>,
    auth_config: Data<Option<String>>,
) -> Result<HttpResponse, Error> {
    check_auth(&req, auth_config.as_deref())?;
    let _device_fingerprint = device_fingerprint.0.ok_or(BadRequest)?;
    
    let key_info = get_public_key(&key_store, &fingerprint).ok_or(NotFound)?;
    
    let response = KeyResponse {
        public_key: base64::prelude::BASE64_STANDARD.encode(key_info.public_key),
        account_hash: key_info.account_hash,
        created_at: key_info.created_at,
    };
    
    Ok(HttpResponse::Ok().json(response))
}

async fn list_account_keys(
    req: HttpRequest,
    account_hash: actix_web::web::Path<String>,
    device_fingerprint: DeviceFingerprint,
    key_store: Data<KeyStore>,
    auth_config: Data<Option<String>>,
) -> Result<HttpResponse, Error> {
    check_auth(&req, auth_config.as_deref())?;
    let _device_fingerprint = device_fingerprint.0.ok_or(BadRequest)?;
    
    let keys = list_public_keys_by_account(&key_store, &account_hash);
    
    let devices: Vec<DeviceInfo> = keys.into_iter().map(|key_info| DeviceInfo {
        fingerprint: key_info.fingerprint,
        public_key: base64::prelude::BASE64_STANDARD.encode(key_info.public_key),
        created_at: key_info.created_at,
    }).collect();
    
    Ok(HttpResponse::Ok().json(devices))
}

#[derive(serde::Deserialize)]
struct CreateAccountRequest {
    device_index: Option<u32>,
}

async fn create_account(
    req: HttpRequest,
    device_fingerprint: DeviceFingerprint,
    request: web::Json<CreateAccountRequest>,
    host: HostHeader,
    auth_config: Data<Option<String>>,
) -> Result<HttpResponse, Error> {
    check_auth(&req, auth_config.as_deref())?;
    let _device_fingerprint = device_fingerprint.0.ok_or(BadRequest)?;
    
    let master_key = AccountMasterKey::generate();
    let account_hash = master_key.account_hash();
    
    // Generate device key for this device
    let device_index = request.device_index.unwrap_or(0);
    let device_key = master_key.derive_device_key(device_index);
    let device_identity = DeviceIdentity::from_signing_key(device_key);
    
    // Create linking URL
    let base_url = match &host.0 {
        Some(host_header) => {
            if let Ok(host_str) = std::str::from_utf8(host_header.as_bytes()) {
                format!("https://{host_str}")
            } else {
                "https://bin.gy".to_string()
            }
        }
        None => "https://bin.gy".to_string(),
    };
    
    let linking_url = master_key.device_linking_url(&base_url);
    
    let response = AccountResponse {
        account_hash,
        device_fingerprint: device_identity.fingerprint().to_string(),
        public_key: base64::prelude::BASE64_STANDARD.encode(device_identity.public_key_bytes()),
        linking_url,
        master_key: base64::prelude::BASE64_STANDARD.encode(master_key.as_bytes()),
    };
    
    Ok(HttpResponse::Ok().json(response))
}

#[derive(serde::Deserialize)]
struct LinkDeviceRequest {
    linking_url: String,
    device_index: u32,
}

async fn link_device_to_account(
    req: HttpRequest,
    device_fingerprint: DeviceFingerprint,
    request: web::Json<LinkDeviceRequest>,
    auth_config: Data<Option<String>>,
) -> Result<HttpResponse, Error> {
    check_auth(&req, auth_config.as_deref())?;
    let _device_fingerprint = device_fingerprint.0.ok_or(BadRequest)?;
    
    // Parse the linking URL to extract master key
    let master_key = AccountMasterKey::from_linking_url(&request.linking_url)
        .ok_or(BadRequest)?;
    
    let account_hash = master_key.account_hash();
    
    // Generate device key for this device
    let device_key = master_key.derive_device_key(request.device_index);
    let device_identity = DeviceIdentity::from_signing_key(device_key);
    
    let response = LinkResponse {
        account_hash,
        device_fingerprint: device_identity.fingerprint().to_string(),
        public_key: base64::prelude::BASE64_STANDARD.encode(device_identity.public_key_bytes()),
        master_key: base64::prelude::BASE64_STANDARD.encode(master_key.as_bytes()),
    };
    
    Ok(HttpResponse::Ok().json(response))
}

#[derive(serde::Deserialize)]
struct StoreX3DHBundleRequest {
    bundle: X3DHKeyBundle,
}

async fn store_x3dh_key_bundle(
    req: HttpRequest,
    fingerprint: actix_web::web::Path<String>,
    device_fingerprint: DeviceFingerprint,
    bundle_request: web::Json<StoreX3DHBundleRequest>,
    x3dh_store: Data<X3DHBundleStore>,
    auth_config: Data<Option<String>>,
) -> Result<HttpResponse, Error> {
    check_auth(&req, auth_config.as_deref())?;
    let device_fingerprint = device_fingerprint.0.ok_or(BadRequest)?;
    
    // Verify the fingerprint matches the requesting device
    if fingerprint.as_str() != device_fingerprint {
        return Ok(HttpResponse::Forbidden().json("Fingerprint mismatch"));
    }
    
    store_x3dh_bundle(&x3dh_store, device_fingerprint, bundle_request.into_inner().bundle);
    Ok(HttpResponse::Ok().json("X3DH bundle stored successfully"))
}

async fn get_x3dh_key_bundle(
    req: HttpRequest,
    fingerprint: actix_web::web::Path<String>,
    device_fingerprint: DeviceFingerprint,
    x3dh_store: Data<X3DHBundleStore>,
    auth_config: Data<Option<String>>,
) -> Result<HttpResponse, Error> {
    check_auth(&req, auth_config.as_deref())?;
    let _device_fingerprint = device_fingerprint.0.ok_or(BadRequest)?;
    
    let bundle = get_x3dh_bundle(&x3dh_store, &fingerprint).ok_or(NotFound)?;
    Ok(HttpResponse::Ok().json(bundle))
}

async fn list_account_x3dh_bundles(
    req: HttpRequest,
    account_hash: actix_web::web::Path<String>,
    device_fingerprint: DeviceFingerprint,
    x3dh_store: Data<X3DHBundleStore>,
    key_store: Data<KeyStore>,
    auth_config: Data<Option<String>>,
) -> Result<HttpResponse, Error> {
    check_auth(&req, auth_config.as_deref())?;
    let _device_fingerprint = device_fingerprint.0.ok_or(BadRequest)?;
    
    let bundles = list_x3dh_bundles_by_account(&x3dh_store, &key_store, &account_hash);
    
    let bundle_list: Vec<BundleInfo> = bundles.into_iter().map(|(fingerprint, bundle)| BundleInfo {
        fingerprint,
        bundle,
    }).collect();
    
    Ok(HttpResponse::Ok().json(bundle_list))
}


