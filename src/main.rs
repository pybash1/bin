#![deny(clippy::pedantic)]
#![allow(clippy::unused_async)]

mod errors;
mod highlight;
mod io;
mod params;

use crate::{
    errors::{InternalServerError, NotFound},
    highlight::highlight,
    io::{PasteStore, generate_id, get_all_paste_ids, get_paste, store_paste},
    params::{HostHeader, IsPlaintextRequest},
};

use actix_web::{
    App, Error, HttpRequest, HttpResponse, HttpServer, Responder,
    http::header,
    web::{self, Bytes, Data, FormConfig, PayloadConfig},
};
use askama::Template;
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

#[derive(Template)]
#[template(path = "index.html")]
struct Index;

async fn index(req: HttpRequest) -> Result<HttpResponse, Error> {
    render_template(&req, &Index)
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

#[derive(Template)]
#[template(path = "paste.html")]
struct ShowPaste {
    content: String,
}

async fn show_paste(
    req: HttpRequest,
    key: actix_web::web::Path<String>,
    plaintext: IsPlaintextRequest,
    store: Data<PasteStore>,
) -> Result<HttpResponse, Error> {
    let mut splitter = key.splitn(2, '.');
    let key = splitter.next().unwrap();
    let ext = splitter.next();

    let entry = get_paste(&store, key).ok_or(NotFound)?;

    if *plaintext {
        Ok(HttpResponse::Ok()
            .content_type("text/plain; charset=utf-8")
            .body(entry))
    } else {
        let data = std::str::from_utf8(entry.as_ref())?;

        let code_highlighted = match ext {
            Some(extension) => match highlight(data, extension) {
                Some(html) => html,
                None => return Err(NotFound.into()),
            },
            None => htmlescape::encode_minimal(data),
        };

        // Add <code> tags to enable line numbering with CSS
        let content = format!(
            "<code>{}</code>",
            code_highlighted.replace('\n', "</code><code>")
        );

        render_template(&req, &ShowPaste { content })
    }
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

fn render_template<T: Template>(req: &HttpRequest, template: &T) -> Result<HttpResponse, Error> {
    match template.render() {
        Ok(html) => Ok(HttpResponse::Ok().content_type("text/html").body(html)),
        Err(e) => {
            error!("Error while rendering template for {}: {e}", req.uri());
            Err(InternalServerError(Box::new(e)).into())
        }
    }
}
