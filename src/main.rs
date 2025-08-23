#![deny(clippy::pedantic)]
#![allow(clippy::unused_async)]

mod errors;
mod highlight;
mod io;
mod params;

use crate::{
    errors::NotFound,
    io::{PasteStore, generate_id, get_all_paste_ids, get_paste, store_paste},
    params::HostHeader,
};

use actix_web::{
    App, Error, HttpRequest, HttpResponse, HttpServer, Responder,
    http::header,
    web::{self, Bytes, Data, FormConfig, PayloadConfig},
};
use log::{error, info};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::LazyLock,
};
use syntect::html::{ClassStyle, css_for_theme_with_class_style};

#[derive(argh::FromArgs, Clone)]
/// a pastebin.
pub struct BinArgs {
    /// socket address to bind to (default: 127.0.0.1:8820)
    #[argh(
        positional,
        default = "SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8820)"
    )]
    bind_addr: SocketAddr,
    /// maximum amount of pastes to store before rotating (default: 1000)
    #[argh(option, default = "1000")]
    buffer_size: usize,
    /// maximum paste size in bytes (default. 32kB)
    #[argh(option, default = "32 * 1024")]
    max_paste_size: usize,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    pretty_env_logger::formatted_builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let args: BinArgs = argh::from_env();

    let store = Data::new(PasteStore::default());

    let server = HttpServer::new({
        let args = args.clone();

        move || {
            App::new()
                .app_data(store.clone())
                .app_data(PayloadConfig::default().limit(args.max_paste_size))
                .app_data(FormConfig::default().limit(args.max_paste_size))
                .wrap(actix_web::middleware::Compress::default())
                .route("/", web::get().to(index))
                .route("/all", web::get().to(list_all_pastes))
                .route("/", web::post().to(submit))
                .route("/", web::put().to(submit_raw))
                .route("/", web::head().to(HttpResponse::MethodNotAllowed))
                .route("/highlight.css", web::get().to(highlight_css))
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
                method: "GET".to_string(),
                path: "/all".to_string(),
                description: "Get all paste IDs".to_string(),
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

async fn list_all_pastes(store: Data<PasteStore>) -> Result<HttpResponse, Error> {
    let paste_ids = get_all_paste_ids(&store);
    Ok(HttpResponse::Ok().json(paste_ids))
}

#[derive(serde::Deserialize)]
struct IndexForm {
    val: Bytes,
}

async fn submit(input: web::Form<IndexForm>, store: Data<PasteStore>) -> impl Responder {
    let id = generate_id();
    let uri = format!("/{id}");
    store_paste(&store, id, input.into_inner().val);
    HttpResponse::Found()
        .append_header((header::LOCATION, uri))
        .finish()
}

async fn submit_raw(
    data: Bytes,
    host: HostHeader,
    store: Data<PasteStore>,
) -> Result<String, Error> {
    let id = generate_id();
    let uri = if let Some(Ok(host)) = host.0.as_ref().map(|v| std::str::from_utf8(v.as_bytes())) {
        format!("https://{host}/{id}\n")
    } else {
        format!("/{id}\n")
    };

    store_paste(&store, id, data);

    Ok(uri)
}


async fn show_paste(
    key: actix_web::web::Path<String>,
    store: Data<PasteStore>,
) -> Result<HttpResponse, Error> {
    let mut splitter = key.splitn(2, '.');
    let key = splitter.next().unwrap();
    let _ext = splitter.next();

    let entry = get_paste(&store, key).ok_or(NotFound)?;

    Ok(HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(entry))
}

async fn highlight_css() -> HttpResponse {
    static CSS: LazyLock<Bytes> = LazyLock::new(|| {
        highlight::BAT_ASSETS.with(|s| {
            Bytes::from(
                css_for_theme_with_class_style(s.get_theme("OneHalfDark"), ClassStyle::Spaced)
                    .unwrap(),
            )
        })
    });

    HttpResponse::Ok()
        .content_type("text/css")
        .body(CSS.clone())
}

