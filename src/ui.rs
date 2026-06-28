use axum::http::StatusCode;

#[cfg(feature = "embed-ui")]
use axum::{
    http::{header, Uri},
    response::{Html, IntoResponse, Response},
};

#[cfg(feature = "embed-ui")]
static WEB_DIR: include_dir::Dir<'static> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/web/dist");

pub fn serve_ui() -> axum::Router {
    #[cfg(feature = "embed-ui")]
    {
        axum::Router::new().fallback(ui_handler)
    }
    #[cfg(not(feature = "embed-ui"))]
    {
        axum::Router::new().fallback(|| async {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Build with --features embed-ui to serve the UI",
            )
        })
    }
}

#[cfg(feature = "embed-ui")]
async fn ui_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    match WEB_DIR.get_file(path) {
        Some(file) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            (
                [(header::CONTENT_TYPE, mime.as_ref().to_owned())],
                file.contents().to_vec(),
            )
                .into_response()
        }
        None => {
            // SPA fallback — serve index.html for all unknown paths
            match WEB_DIR.get_file("index.html") {
                Some(f) => Html(f.contents_utf8().unwrap_or("")).into_response(),
                None => (StatusCode::NOT_FOUND, "UI not built").into_response(),
            }
        }
    }
}
