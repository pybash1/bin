#![deny(clippy::pedantic)]
#![allow(clippy::unused_async)]

mod errors;
mod io;
mod params;

use crate::{
    errors::{BadRequest, NotFound, Unauthorized},
    io::{
        PasteStore, generate_id, generate_unique_device_code, get_all_paste_ids, get_paste,
        store_paste,
    },
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
/// arguments
pub struct BinArgs {
    #[argh(
        positional,
        default = "SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8820)"
    )]
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
    message: "Bin(modified for Board)",
    endpoints: &[
        ApiEndpoint {
            method: "GET",
            path: "/",
            description: "Get API information",
        },
        ApiEndpoint {
            method: "POST",
            path: "/",
            description: "Create a new paste (form data)",
        },
        ApiEndpoint {
            method: "PUT",
            path: "/",
            description: "Create a new paste (raw data)",
        },
        ApiEndpoint {
            method: "POST",
            path: "/device",
            description: "Generate a unique device code",
        },
        ApiEndpoint {
            method: "GET",
            path: "/all",
            description: "Get all paste IDs for your device",
        },
        ApiEndpoint {
            method: "GET",
            path: "/{paste}",
            description: "Get paste content by ID",
        },
    ],
};

async fn index() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(&API_INFO))
}

async fn generate_device_code(
    req: HttpRequest,
    store: Data<PasteStore>,
    auth_config: Data<Option<String>>,
) -> Result<String, Error> {
    check_auth(&req, auth_config.as_deref())?;
    Ok(generate_unique_device_code(&store))
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
struct PasteForm {
    val: Bytes,
}

async fn submit(
    req: HttpRequest,
    input: web::Form<PasteForm>,
    device_code: DeviceCode,
    store: Data<PasteStore>,
    auth_config: Data<Option<String>>,
) -> Result<HttpResponse, Error> {
    check_auth(&req, auth_config.as_deref())?;
    let device_code = device_code.0.ok_or(BadRequest)?;
    let id = generate_id();
    store_paste(&store, id.clone(), input.into_inner().val, device_code);
    Ok(HttpResponse::Found()
        .append_header((header::LOCATION, format!("/{id}")))
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
    let paste_id = key.split('.').next().unwrap();
    let content = get_paste(&store, paste_id, &device_code).ok_or(Unauthorized)?;

    Ok(HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(content))
}
