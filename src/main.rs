#![deny(clippy::pedantic)]
#![allow(clippy::unused_async)]
#![allow(clippy::needless_for_each)] // Required for utoipa::OpenApi derive macro

mod errors;
mod io;
mod params;

use crate::{
    errors::{BadRequest, ErrorResponse, NotFound, Unauthorized},
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
use utoipa::{
    Modify, OpenApi,
    openapi::security::{ApiKey, ApiKeyValue, SecurityScheme},
};

/// `OpenAPI` documentation
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Bin (Board Modified)",
        version = "2.0.2",
        description = "A minimalist pastebin API modified for Board. Device-based storage with authentication."
    ),
    paths(index, openapi_spec, generate_device_code, list_all_pastes, submit, submit_raw, show_paste),
    components(schemas(ApiInfo, ApiEndpoint, ErrorResponse)),
    modifiers(&SecurityAddon),
    tags(
        (name = "info", description = "API information endpoints"),
        (name = "device", description = "Device management endpoints"),
        (name = "paste", description = "Paste management endpoints")
    )
)]
struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "app_password",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("App-Password"))),
            );
        }
    }
}

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
                .route("/openapi.json", web::get().to(openapi_spec))
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

#[derive(serde::Serialize, utoipa::ToSchema)]
struct ApiInfo {
    /// Welcome message
    message: &'static str,
    /// List of available API endpoints
    endpoints: &'static [ApiEndpoint],
}

#[derive(serde::Serialize, utoipa::ToSchema)]
struct ApiEndpoint {
    /// HTTP method
    method: &'static str,
    /// URL path
    path: &'static str,
    /// Endpoint description
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

/// Get API information
#[utoipa::path(
    get,
    path = "/",
    tag = "info",
    responses(
        (status = 200, description = "API information", body = ApiInfo)
    )
)]
async fn index() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(&API_INFO))
}

/// Get `OpenAPI` specification
#[utoipa::path(
    get,
    path = "/openapi.json",
    tag = "info",
    responses(
        (status = 200, description = "OpenAPI specification", content_type = "application/json")
    )
)]
async fn openapi_spec() -> HttpResponse {
    HttpResponse::Ok().json(ApiDoc::openapi())
}

/// Generate a unique device code
#[utoipa::path(
    post,
    path = "/device",
    tag = "device",
    responses(
        (status = 200, description = "Generated device code (8 alphanumeric uppercase characters)", body = String),
        (status = 401, description = "Unauthorized - invalid or missing App-Password", body = ErrorResponse)
    ),
    security(
        ("app_password" = [])
    )
)]
async fn generate_device_code(
    req: HttpRequest,
    store: Data<PasteStore>,
    auth_config: Data<Option<String>>,
) -> Result<String, Error> {
    check_auth(&req, auth_config.as_deref())?;
    Ok(generate_unique_device_code(&store))
}

/// List all paste IDs for the authenticated device
#[utoipa::path(
    get,
    path = "/all",
    tag = "paste",
    responses(
        (status = 200, description = "List of paste IDs owned by the device", body = Vec<String>),
        (status = 400, description = "Bad request - missing Device-Code header", body = ErrorResponse),
        (status = 401, description = "Unauthorized - invalid or missing App-Password", body = ErrorResponse)
    ),
    params(
        ("Device-Code" = String, Header, description = "8-character alphanumeric device identifier")
    ),
    security(
        ("app_password" = [])
    )
)]
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

#[derive(serde::Deserialize, utoipa::ToSchema)]
struct PasteForm {
    /// Paste content
    #[schema(value_type = String)]
    val: Bytes,
}

/// Create a new paste from form data
#[utoipa::path(
    post,
    path = "/",
    tag = "paste",
    request_body(content = PasteForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 302, description = "Redirect to the created paste URL"),
        (status = 400, description = "Bad request - missing Device-Code header", body = ErrorResponse),
        (status = 401, description = "Unauthorized - invalid or missing App-Password", body = ErrorResponse)
    ),
    params(
        ("Device-Code" = String, Header, description = "8-character alphanumeric device identifier")
    ),
    security(
        ("app_password" = [])
    )
)]
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

/// Create a new paste from raw data
#[utoipa::path(
    put,
    path = "/",
    tag = "paste",
    request_body(content = String, content_type = "text/plain", description = "Raw paste content"),
    responses(
        (status = 200, description = "URL of the created paste", body = String),
        (status = 400, description = "Bad request - missing Device-Code header", body = ErrorResponse),
        (status = 401, description = "Unauthorized - invalid or missing App-Password", body = ErrorResponse)
    ),
    params(
        ("Device-Code" = String, Header, description = "8-character alphanumeric device identifier")
    ),
    security(
        ("app_password" = [])
    )
)]
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

/// Get paste content by ID
#[utoipa::path(
    get,
    path = "/{paste}",
    tag = "paste",
    responses(
        (status = 200, description = "Paste content", content_type = "text/plain"),
        (status = 400, description = "Bad request - missing Device-Code header", body = ErrorResponse),
        (status = 401, description = "Unauthorized - paste not owned by this device or invalid App-Password", body = ErrorResponse)
    ),
    params(
        ("paste" = String, Path, description = "Paste ID (optionally with file extension for syntax highlighting)"),
        ("Device-Code" = String, Header, description = "8-character alphanumeric device identifier")
    ),
    security(
        ("app_password" = [])
    )
)]
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
