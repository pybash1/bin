#![deny(clippy::pedantic)]
#![allow(clippy::unused_async)]

mod errors;
mod io;
mod params;

use crate::{
    errors::{BadRequest, NotFound, Unauthorized},
    io::{PasteStore, generate_id, generate_unique_device_code, get_all_paste_ids, get_paste, store_paste},
    params::{DeviceCode, HostHeader},
};

use actix_web::{
    App, Error, HttpRequest, HttpResponse, HttpServer,
    http::header,
    web::{self, Bytes, Data, FormConfig, PayloadConfig},
};
use log::{error, info};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(argh::FromArgs, Clone)]
/// a pastebin.
pub struct BinArgs {
    /// socket address to bind to (default: 127.0.0.1:8820)
    #[argh(
        positional,
        default = "SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8820)"
    )]
    bind_addr: SocketAddr,
    /// maximum paste size in bytes (default. 32kB)
    #[argh(option, default = "32 * 1024")]
    max_paste_size: usize,
}

fn check_auth(req: &HttpRequest, required_password: Option<&str>) -> Result<(), Unauthorized> {
    if let Some(password) = required_password {
        if let Some(header_value) = req.headers().get("App-Password") {
            if let Ok(provided_password) = header_value.to_str() {
                if provided_password == password {
                    return Ok(());
                }
            }
        }
        Err(Unauthorized)
    } else {
        Ok(())
    }
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
    let auth_config = Data::new(password);

    let server = HttpServer::new({
        let args = args.clone();

        move || {
            App::new()
                .app_data(store.clone())
                .app_data(auth_config.clone())
                .app_data(PayloadConfig::default().limit(args.max_paste_size))
                .app_data(FormConfig::default().limit(args.max_paste_size))
                .wrap(actix_web::middleware::Compress::default())
                .route("/", web::get().to(index))
                .route("/device", web::post().to(generate_device_code))
                .route("/all", web::get().to(list_all_pastes))
                .route("/", web::post().to(submit))
                .route("/", web::put().to(submit_raw))
                .route("/", web::head().to(HttpResponse::MethodNotAllowed))
                .route("/{paste}", web::get().to(show_paste))
                .route("/{paste}", web::head().to(HttpResponse::MethodNotAllowed))
                .default_service(web::to(|req: HttpRequest| async move {
                    error!("Couldn't find resource {}", req.uri());
                    HttpResponse::from_error(NotFound)
                }))
        }
    });

    info!("Listening on http://{}", args.bind_addr);

    server.bind(args.bind_addr)?.run().await
}

#[derive(serde::Serialize)]
struct IndexResponse {
    message: String,
    endpoints: Vec<ApiEndpoint>,
}

#[derive(serde::Serialize)]
struct ApiEndpoint {
    method: String,
    path: String,
    description: String,
}

async fn index() -> Result<HttpResponse, Error> {
    let response = IndexResponse {
        message: "Bin API - A pastebin service".to_string(),
        endpoints: vec![
            ApiEndpoint {
                method: "GET".to_string(),
                path: "/".to_string(),
                description: "Get API information".to_string(),
            },
            ApiEndpoint {
                method: "POST".to_string(),
                path: "/".to_string(),
                description: "Create a new paste (form data)".to_string(),
            },
            ApiEndpoint {
                method: "PUT".to_string(),
                path: "/".to_string(),
                description: "Create a new paste (raw data)".to_string(),
            },
            ApiEndpoint {
                method: "POST".to_string(),
                path: "/device".to_string(),
                description: "Generate a unique device code".to_string(),
            },
            ApiEndpoint {
                method: "GET".to_string(),
                path: "/all".to_string(),
                description: "Get all paste IDs for your device".to_string(),
            },
            ApiEndpoint {
                method: "GET".to_string(),
                path: "/{paste}".to_string(),
                description: "Get paste content by ID".to_string(),
            },
        ],
    };
    Ok(HttpResponse::Ok().json(response))
}

async fn generate_device_code(
    req: HttpRequest,
    store: Data<PasteStore>,
    auth_config: Data<Option<String>>,
) -> Result<String, Error> {
    check_auth(&req, auth_config.as_deref())?;
    
    let device_code = generate_unique_device_code(&store);
    
    Ok(device_code)
}

async fn list_all_pastes(
    req: HttpRequest,
    device_code: DeviceCode,
    store: Data<PasteStore>,
    auth_config: Data<Option<String>>,
) -> Result<HttpResponse, Error> {
    check_auth(&req, auth_config.as_deref())?;
    
    let device_code = device_code.0.ok_or(BadRequest)?;
    let paste_ids = get_all_paste_ids(&store, &device_code);
    Ok(HttpResponse::Ok().json(paste_ids))
}

#[derive(serde::Deserialize)]
struct IndexForm {
    val: Bytes,
}

async fn submit(
    req: HttpRequest,
    input: web::Form<IndexForm>,
    device_code: DeviceCode,
    store: Data<PasteStore>,
    auth_config: Data<Option<String>>,
) -> Result<HttpResponse, Error> {
    check_auth(&req, auth_config.as_deref())?;
    
    let device_code = device_code.0.ok_or(BadRequest)?;
    let id = generate_id();
    let uri = format!("/{id}");
    store_paste(&store, id, input.into_inner().val, device_code);
    Ok(HttpResponse::Found()
        .append_header((header::LOCATION, uri))
        .finish())
}

async fn submit_raw(
    req: HttpRequest,
    data: Bytes,
    host: HostHeader,
    device_code: DeviceCode,
    store: Data<PasteStore>,
    auth_config: Data<Option<String>>,
) -> Result<String, Error> {
    check_auth(&req, auth_config.as_deref())?;
    
    let device_code = device_code.0.ok_or(BadRequest)?;
    let id = generate_id();
    let uri = if let Some(Ok(host)) = host.0.as_ref().map(|v| std::str::from_utf8(v.as_bytes())) {
        format!("https://{host}/{id}\n")
    } else {
        format!("/{id}\n")
    };

    store_paste(&store, id, data, device_code);

    Ok(uri)
}


async fn show_paste(
    req: HttpRequest,
    key: actix_web::web::Path<String>,
    device_code: DeviceCode,
    store: Data<PasteStore>,
    auth_config: Data<Option<String>>,
) -> Result<HttpResponse, Error> {
    check_auth(&req, auth_config.as_deref())?;
    
    let device_code = device_code.0.ok_or(BadRequest)?;
    let mut splitter = key.splitn(2, '.');
    let key = splitter.next().unwrap();
    let _ext = splitter.next();

    let entry = get_paste(&store, key, &device_code).ok_or(Unauthorized)?;

    Ok(HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(entry))
}


