use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Multipart, Path, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use chrono::Utc;
use clap::Parser;
use image::ImageFormat;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
};
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

/// Convey Image Paste Board - Web-hosted image hosting for Convey chat
#[derive(Parser, Debug)]
#[command(name = "convey-images", version, about)]
struct Args {
    /// Path to config file
    #[arg(short, long, default_value = "/etc/convey-images/config.toml")]
    config: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Config {
    /// Address to bind the HTTP server to
    #[serde(default = "default_bind")]
    bind_address: String,

    /// Base URL for generating links (e.g., "https://convey.pugbot.net")
    #[serde(default = "default_base_url")]
    base_url: String,

    /// Directory to store uploaded images
    #[serde(default = "default_storage_dir")]
    storage_dir: String,

    /// Maximum upload size in bytes (default: 20MB)
    #[serde(default = "default_max_upload_size")]
    max_upload_size: usize,

    /// Maximum number of stored images (oldest removed when exceeded)
    #[serde(default = "default_max_images")]
    max_images: usize,

    /// Image retention period in days (0 = forever)
    #[serde(default = "default_retention_days")]
    retention_days: u64,

    /// Maximum image dimension (width or height) - images larger are resized
    #[serde(default = "default_max_dimension")]
    max_dimension: u32,
}

fn default_bind() -> String { "0.0.0.0:8844".to_string() }
fn default_base_url() -> String { "https://convey.pugbot.net".to_string() }
fn default_storage_dir() -> String { "/var/lib/convey-images".to_string() }
fn default_max_upload_size() -> usize { 20 * 1024 * 1024 } // 20MB
fn default_max_images() -> usize { 10000 }
fn default_retention_days() -> u64 { 90 }
fn default_max_dimension() -> u32 { 4096 }

/// Metadata for a stored image
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ImageMeta {
    /// Unique token ID
    token: String,
    /// Original file extension
    extension: String,
    /// Storage filename (token.ext)
    filename: String,
    /// MIME type
    content_type: String,
    /// File size in bytes (after processing)
    size: u64,
    /// Image width
    width: u32,
    /// Image height
    height: u32,
    /// Upload timestamp (ISO 8601)
    uploaded_at: String,
    /// SHA-256 hash of the processed image
    content_hash: String,
}

/// Upload response returned to client
#[derive(Serialize)]
struct UploadResponse {
    success: bool,
    url: String,
    direct_url: String,
    token: String,
    delete_url: String,
    size: u64,
    width: u32,
    height: u32,
}

#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    error: String,
}

/// Shared application state
struct AppState {
    config: Config,
    /// In-memory index of all images (token -> metadata)
    images: RwLock<HashMap<String, ImageMeta>>,
    /// Delete tokens (delete_token -> image_token)
    delete_tokens: RwLock<HashMap<String, String>>,
}

impl AppState {
    fn storage_path(&self) -> PathBuf {
        PathBuf::from(&self.config.storage_dir)
    }

    fn images_path(&self) -> PathBuf {
        self.storage_path().join("images")
    }

    fn meta_path(&self) -> PathBuf {
        self.storage_path().join("meta")
    }
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    let args = Args::parse();

    // Load config
    let config = load_config(&args.config);
    info!("Convey Image Paste Board starting");
    info!("Bind: {}", config.bind_address);
    info!("Base URL: {}", config.base_url);
    info!("Storage: {}", config.storage_dir);
    info!("Max upload: {} bytes", config.max_upload_size);

    // Ensure storage directories exist
    let storage = PathBuf::from(&config.storage_dir);
    let images_dir = storage.join("images");
    let meta_dir = storage.join("meta");
    tokio::fs::create_dir_all(&images_dir).await.expect("Failed to create images directory");
    tokio::fs::create_dir_all(&meta_dir).await.expect("Failed to create meta directory");

    // Load existing image metadata
    let (images, delete_tokens) = load_all_metadata(&meta_dir).await;
    info!("Loaded {} existing images", images.len());

    let max_upload = config.max_upload_size;

    let state = Arc::new(AppState {
        config,
        images: RwLock::new(images),
        delete_tokens: RwLock::new(delete_tokens),
    });

    // Spawn cleanup task
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        cleanup_loop(cleanup_state).await;
    });

    // Build router
    let app = Router::new()
        .route("/", get(index_page))
        .route("/upload", post(upload_image))
        .route("/i/{token_ext}", get(serve_image))
        .route("/v/{token_ext}", get(view_page))
        .route("/delete/{delete_token}", post(delete_image))
        .route("/api/info/{token}", get(image_info))
        .route("/gallery", get(gallery_page))
        .layer(DefaultBodyLimit::max(max_upload))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state);

    let addr: SocketAddr = app_bind_address(&args).parse().expect("Invalid bind address");
    info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.expect("Failed to bind");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("Server error");
}

fn app_bind_address(args: &Args) -> String {
    let config = load_config(&args.config);
    config.bind_address
}

fn load_config(path: &str) -> Config {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            toml::from_str(&contents).unwrap_or_else(|e| {
                warn!("Failed to parse config {}: {}, using defaults", path, e);
                default_config()
            })
        }
        Err(_) => {
            warn!("Config file {} not found, using defaults", path);
            default_config()
        }
    }
}

fn default_config() -> Config {
    Config {
        bind_address: default_bind(),
        base_url: default_base_url(),
        storage_dir: default_storage_dir(),
        max_upload_size: default_max_upload_size(),
        max_images: default_max_images(),
        retention_days: default_retention_days(),
        max_dimension: default_max_dimension(),
    }
}

async fn load_all_metadata(meta_dir: &std::path::Path) -> (HashMap<String, ImageMeta>, HashMap<String, String>) {
    let mut images = HashMap::new();
    let mut delete_tokens = HashMap::new();

    let mut entries = match tokio::fs::read_dir(meta_dir).await {
        Ok(e) => e,
        Err(_) => return (images, delete_tokens),
    };

    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            if let Ok(data) = tokio::fs::read_to_string(&path).await {
                if let Ok(meta) = serde_json::from_str::<ImageMeta>(&data) {
                    // Generate a deterministic delete token from the image token
                    let delete_token = generate_delete_token(&meta.token);
                    delete_tokens.insert(delete_token, meta.token.clone());
                    images.insert(meta.token.clone(), meta);
                }
            }
        }
    }

    (images, delete_tokens)
}

/// Strip EXIF data from image bytes by re-encoding through the image crate.
/// This effectively removes all metadata including EXIF, ICC profiles, etc.
fn strip_exif_and_process(data: &[u8], max_dimension: u32) -> Result<(Vec<u8>, String, u32, u32), String> {
    // Detect the original format
    let format = image::guess_format(data)
        .map_err(|e| format!("Cannot detect image format: {}", e))?;

    // Decode the image - this strips all metadata
    let img = image::load_from_memory(data)
        .map_err(|e| format!("Failed to decode image: {}", e))?;

    // Resize if necessary (preserving aspect ratio)
    let img = if img.width() > max_dimension || img.height() > max_dimension {
        img.resize(max_dimension, max_dimension, image::imageops::FilterType::Lanczos3)
    } else {
        img
    };

    let width = img.width();
    let height = img.height();

    // Re-encode to a clean format (strips all EXIF/metadata)
    let (output, ext, _content_type) = match format {
        ImageFormat::Jpeg => {
            let mut buf = Vec::new();
            let mut cursor = std::io::Cursor::new(&mut buf);
            img.write_to(&mut cursor, ImageFormat::Jpeg)
                .map_err(|e| format!("Failed to encode JPEG: {}", e))?;
            (buf, "jpg".to_string(), "image/jpeg".to_string())
        }
        ImageFormat::Gif => {
            // For GIF, encode as PNG to strip metadata (loses animation)
            let mut buf = Vec::new();
            let mut cursor = std::io::Cursor::new(&mut buf);
            img.write_to(&mut cursor, ImageFormat::Png)
                .map_err(|e| format!("Failed to encode PNG: {}", e))?;
            (buf, "png".to_string(), "image/png".to_string())
        }
        ImageFormat::WebP => {
            // Re-encode as PNG for reliable metadata stripping
            let mut buf = Vec::new();
            let mut cursor = std::io::Cursor::new(&mut buf);
            img.write_to(&mut cursor, ImageFormat::Png)
                .map_err(|e| format!("Failed to encode PNG: {}", e))?;
            (buf, "png".to_string(), "image/png".to_string())
        }
        _ => {
            // Default: encode as PNG
            let mut buf = Vec::new();
            let mut cursor = std::io::Cursor::new(&mut buf);
            img.write_to(&mut cursor, ImageFormat::Png)
                .map_err(|e| format!("Failed to encode PNG: {}", e))?;
            (buf, "png".to_string(), "image/png".to_string())
        }
    };

    Ok((output, ext, width, height))
}

/// Generate a unique token for the image filename
fn generate_token() -> String {
    // Use UUID v4 truncated to 12 chars for short but unique URLs
    let uuid = Uuid::new_v4();
    let hash = format!("{:x}", Sha256::digest(uuid.as_bytes()));
    hash[..12].to_string()
}

/// Generate a delete token from an image token
fn generate_delete_token(image_token: &str) -> String {
    let hash = format!("{:x}", Sha256::digest(format!("delete-{}", image_token).as_bytes()));
    hash[..16].to_string()
}

// ──────────────────────── HTTP Handlers ────────────────────────

async fn index_page(State(state): State<Arc<AppState>>) -> Html<String> {
    let count = state.images.read().await.len();
    Html(render_index_page(&state.config.base_url, count, state.config.max_upload_size))
}

async fn upload_image(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Response {
    // Extract the file from multipart
    let (filename, data) = match extract_upload(&mut multipart).await {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(ErrorResponse {
                success: false,
                error: e,
            })).into_response();
        }
    };

    if data.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(ErrorResponse {
            success: false,
            error: "Empty file".to_string(),
        })).into_response();
    }

    info!("Upload received: {} ({} bytes)", filename, data.len());

    // Strip EXIF and process image
    let (processed, ext, width, height) = match strip_exif_and_process(&data, state.config.max_dimension) {
        Ok(v) => v,
        Err(e) => {
            error!("Image processing failed: {}", e);
            return (StatusCode::BAD_REQUEST, Json(ErrorResponse {
                success: false,
                error: format!("Image processing failed: {}", e),
            })).into_response();
        }
    };

    // Generate token and content hash
    let token = generate_token();
    let content_hash = format!("{:x}", Sha256::digest(&processed));
    let stored_filename = format!("{}.{}", token, ext);
    let content_type = match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        _ => "image/png",
    }.to_string();

    // Check for duplicate by content hash
    {
        let images = state.images.read().await;
        for (existing_token, meta) in images.iter() {
            if meta.content_hash == content_hash {
                info!("Duplicate image detected, returning existing: {}", existing_token);
                let delete_token = generate_delete_token(existing_token);
                let resp = UploadResponse {
                    success: true,
                    url: format!("{}/v/{}.{}", state.config.base_url, existing_token, meta.extension),
                    direct_url: format!("{}/i/{}.{}", state.config.base_url, existing_token, meta.extension),
                    token: existing_token.clone(),
                    delete_url: format!("{}/delete/{}", state.config.base_url, delete_token),
                    size: meta.size,
                    width: meta.width,
                    height: meta.height,
                };
                return (StatusCode::OK, Json(resp)).into_response();
            }
        }
    }

    // Enforce max images limit
    enforce_image_limit(&state).await;

    // Save the processed image
    let image_path = state.images_path().join(&stored_filename);
    if let Err(e) = tokio::fs::write(&image_path, &processed).await {
        error!("Failed to write image file: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            success: false,
            error: "Storage error".to_string(),
        })).into_response();
    }

    // Create metadata
    let meta = ImageMeta {
        token: token.clone(),
        extension: ext.clone(),
        filename: stored_filename,
        content_type,
        size: processed.len() as u64,
        width,
        height,
        uploaded_at: Utc::now().to_rfc3339(),
        content_hash,
    };

    // Save metadata
    let meta_path = state.meta_path().join(format!("{}.json", token));
    if let Err(e) = tokio::fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap()).await {
        error!("Failed to write metadata: {}", e);
        // Clean up the image file
        let _ = tokio::fs::remove_file(&image_path).await;
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
            success: false,
            error: "Storage error".to_string(),
        })).into_response();
    }

    // Update in-memory index
    let delete_token = generate_delete_token(&token);
    {
        let mut images = state.images.write().await;
        images.insert(token.clone(), meta.clone());
    }
    {
        let mut dt = state.delete_tokens.write().await;
        dt.insert(delete_token.clone(), token.clone());
    }

    info!("Stored image: {} ({}x{}, {} bytes)", token, width, height, meta.size);

    let resp = UploadResponse {
        success: true,
        url: format!("{}/v/{}.{}", state.config.base_url, token, ext),
        direct_url: format!("{}/i/{}.{}", state.config.base_url, token, ext),
        token: token.clone(),
        delete_url: format!("{}/delete/{}", state.config.base_url, delete_token),
        size: meta.size,
        width,
        height,
    };

    (StatusCode::OK, Json(resp)).into_response()
}

async fn serve_image(
    State(state): State<Arc<AppState>>,
    Path(token_ext): Path<String>,
) -> Response {
    let token = token_ext.split('.').next().unwrap_or("");

    let images = state.images.read().await;
    let meta = match images.get(token) {
        Some(m) => m.clone(),
        None => {
            return (StatusCode::NOT_FOUND, "Image not found").into_response();
        }
    };
    drop(images);

    let image_path = state.images_path().join(&meta.filename);
    match tokio::fs::read(&image_path).await {
        Ok(data) => {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, &meta.content_type)
                .header(header::CACHE_CONTROL, "public, max-age=86400, immutable")
                .header(header::CONTENT_LENGTH, data.len())
                .header("X-Content-Type-Options", "nosniff")
                .body(Body::from(data))
                .unwrap()
        }
        Err(_) => (StatusCode::NOT_FOUND, "Image file missing").into_response(),
    }
}

async fn view_page(
    State(state): State<Arc<AppState>>,
    Path(token_ext): Path<String>,
) -> Response {
    let token = token_ext.split('.').next().unwrap_or("");

    let images = state.images.read().await;
    let meta = match images.get(token) {
        Some(m) => m.clone(),
        None => {
            return (StatusCode::NOT_FOUND, Html("Image not found".to_string())).into_response();
        }
    };
    drop(images);

    let direct_url = format!("{}/i/{}.{}", state.config.base_url, meta.token, meta.extension);
    let page = render_view_page(&state.config.base_url, &meta, &direct_url);
    Html(page).into_response()
}

async fn delete_image(
    State(state): State<Arc<AppState>>,
    Path(delete_token): Path<String>,
) -> Response {
    let image_token = {
        let dt = state.delete_tokens.read().await;
        match dt.get(&delete_token) {
            Some(t) => t.clone(),
            None => {
                return (StatusCode::NOT_FOUND, Json(ErrorResponse {
                    success: false,
                    error: "Invalid delete token".to_string(),
                })).into_response();
            }
        }
    };

    // Remove from storage
    let meta = {
        let mut images = state.images.write().await;
        images.remove(&image_token)
    };

    if let Some(meta) = meta {
        let image_path = state.images_path().join(&meta.filename);
        let meta_path = state.meta_path().join(format!("{}.json", meta.token));
        let _ = tokio::fs::remove_file(&image_path).await;
        let _ = tokio::fs::remove_file(&meta_path).await;

        let mut dt = state.delete_tokens.write().await;
        dt.remove(&delete_token);

        info!("Deleted image: {}", image_token);
    }

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "message": "Image deleted"
    }))).into_response()
}

async fn image_info(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> Response {
    let images = state.images.read().await;
    match images.get(&token) {
        Some(meta) => (StatusCode::OK, Json(meta.clone())).into_response(),
        None => (StatusCode::NOT_FOUND, Json(ErrorResponse {
            success: false,
            error: "Image not found".to_string(),
        })).into_response(),
    }
}

async fn gallery_page(State(state): State<Arc<AppState>>) -> Html<String> {
    let images = state.images.read().await;
    let mut sorted: Vec<&ImageMeta> = images.values().collect();
    sorted.sort_by(|a, b| b.uploaded_at.cmp(&a.uploaded_at));
    // Show last 50 images
    let recent: Vec<&ImageMeta> = sorted.into_iter().take(50).collect();
    Html(render_gallery_page(&state.config.base_url, &recent))
}

// ──────────────────────── Helpers ────────────────────────

async fn extract_upload(multipart: &mut Multipart) -> Result<(String, Vec<u8>), String> {
    while let Some(field) = multipart.next_field().await.map_err(|e| format!("Multipart error: {}", e))? {
        let name = field.name().unwrap_or("").to_string();
        if name == "file" || name == "image" {
            let filename = field.file_name().unwrap_or("image.png").to_string();
            let data = field.bytes().await.map_err(|e| format!("Failed to read upload: {}", e))?;
            return Ok((filename, data.to_vec()));
        }
    }
    Err("No file field found in upload".to_string())
}

async fn enforce_image_limit(state: &Arc<AppState>) {
    let mut images = state.images.write().await;
    if images.len() < state.config.max_images {
        return;
    }

    // Find the oldest image
    let oldest = images.values()
        .min_by(|a, b| a.uploaded_at.cmp(&b.uploaded_at))
        .map(|m| m.token.clone());

    if let Some(token) = oldest {
        if let Some(meta) = images.remove(&token) {
            let image_path = state.images_path().join(&meta.filename);
            let meta_path = state.meta_path().join(format!("{}.json", meta.token));
            let _ = tokio::fs::remove_file(&image_path).await;
            let _ = tokio::fs::remove_file(&meta_path).await;

            let delete_token = generate_delete_token(&token);
            let mut dt = state.delete_tokens.write().await;
            dt.remove(&delete_token);

            info!("Removed oldest image {} to stay within limit", token);
        }
    }
}

async fn cleanup_loop(state: Arc<AppState>) {
    let retention = state.config.retention_days;
    if retention == 0 {
        return; // No expiration
    }

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await; // Check hourly

        let now = Utc::now();
        let mut to_remove = Vec::new();

        {
            let images = state.images.read().await;
            for (token, meta) in images.iter() {
                if let Ok(uploaded) = chrono::DateTime::parse_from_rfc3339(&meta.uploaded_at) {
                    let age = now.signed_duration_since(uploaded);
                    if age.num_days() as u64 > retention {
                        to_remove.push(token.clone());
                    }
                }
            }
        }

        for token in to_remove {
            let meta = {
                let mut images = state.images.write().await;
                images.remove(&token)
            };
            if let Some(meta) = meta {
                let image_path = state.images_path().join(&meta.filename);
                let meta_path = state.meta_path().join(format!("{}.json", meta.token));
                let _ = tokio::fs::remove_file(&image_path).await;
                let _ = tokio::fs::remove_file(&meta_path).await;

                let delete_token = generate_delete_token(&token);
                let mut dt = state.delete_tokens.write().await;
                dt.remove(&delete_token);

                info!("Expired image: {} (uploaded {})", token, meta.uploaded_at);
            }
        }
    }
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c().await.expect("Failed to install Ctrl+C handler");
    info!("Shutdown signal received");
}

// ──────────────────────── HTML Templates ────────────────────────

fn render_index_page(_base_url: &str, image_count: usize, max_size: usize) -> String {
    let max_mb = max_size / (1024 * 1024);
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Convey Images</title>
    <meta name="description" content="Convey Image Paste Board - Privacy-respecting image hosting for Convey chat">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            color: #e0e0e0;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
        }}
        .container {{
            max-width: 700px;
            width: 100%;
            padding: 40px 20px;
            text-align: center;
        }}
        h1 {{
            font-size: 2.2em;
            margin-bottom: 8px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        .subtitle {{
            color: #888;
            margin-bottom: 40px;
            font-size: 0.95em;
        }}
        .upload-zone {{
            border: 2px dashed #444;
            border-radius: 16px;
            padding: 60px 30px;
            margin-bottom: 30px;
            cursor: pointer;
            transition: all 0.2s;
            background: #16213e;
        }}
        .upload-zone:hover, .upload-zone.dragging {{
            border-color: #667eea;
            background: #1a2744;
        }}
        .upload-zone p {{
            font-size: 1.1em;
            color: #aaa;
        }}
        .upload-zone .icon {{
            font-size: 3em;
            margin-bottom: 10px;
        }}
        .upload-zone input[type="file"] {{
            display: none;
        }}
        .result {{
            display: none;
            background: #16213e;
            border-radius: 12px;
            padding: 20px;
            margin-top: 20px;
            text-align: left;
        }}
        .result.visible {{ display: block; }}
        .result img {{
            max-width: 100%;
            border-radius: 8px;
            margin-bottom: 15px;
        }}
        .result-url {{
            background: #0f3460;
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .result-url input {{
            flex: 1;
            background: transparent;
            border: none;
            color: #667eea;
            font-size: 0.95em;
            outline: none;
            font-family: monospace;
        }}
        .result-url button {{
            background: #667eea;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.85em;
            white-space: nowrap;
        }}
        .result-url button:hover {{ background: #5a6fd6; }}
        .stats {{
            color: #666;
            font-size: 0.85em;
            margin-top: 40px;
        }}
        .progress {{
            display: none;
            margin-top: 20px;
        }}
        .progress.visible {{ display: block; }}
        .progress-bar {{
            background: #0f3460;
            border-radius: 8px;
            height: 6px;
            overflow: hidden;
        }}
        .progress-bar-inner {{
            background: linear-gradient(90deg, #667eea, #764ba2);
            height: 100%;
            width: 0%;
            transition: width 0.3s;
        }}
        .error {{
            color: #e74c3c;
            margin-top: 10px;
            display: none;
        }}
        .error.visible {{ display: block; }}
        .features {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin: 30px 0;
            text-align: center;
        }}
        .feature {{
            background: #16213e;
            border-radius: 10px;
            padding: 15px;
        }}
        .feature .icon {{ font-size: 1.5em; }}
        .feature .label {{
            font-size: 0.8em;
            color: #888;
            margin-top: 5px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Convey Images</h1>
        <p class="subtitle">Privacy-respecting image hosting &middot; EXIF data stripped &middot; Tokenized URLs</p>
        
        <div class="features">
            <div class="feature">
                <div class="icon">🔒</div>
                <div class="label">EXIF Stripped</div>
            </div>
            <div class="feature">
                <div class="icon">🔗</div>
                <div class="label">Tokenized Names</div>
            </div>
            <div class="feature">
                <div class="icon">📋</div>
                <div class="label">Paste to Upload</div>
            </div>
        </div>

        <div class="upload-zone" id="upload-zone" onclick="document.getElementById('file-input').click()">
            <div class="icon">📸</div>
            <p>Drop an image here, click to select, or paste from clipboard</p>
            <p style="font-size: 0.8em; color: #666; margin-top: 8px;">Max {max_mb}MB &middot; PNG, JPEG, GIF, WebP</p>
            <input type="file" id="file-input" accept="image/*">
        </div>

        <div class="progress" id="progress">
            <div class="progress-bar"><div class="progress-bar-inner" id="progress-inner"></div></div>
            <p style="margin-top: 8px; color: #888; font-size: 0.85em;">Uploading...</p>
        </div>

        <div class="error" id="error"></div>

        <div class="result" id="result">
            <img id="result-img" src="" alt="Uploaded image">
            <div class="result-url">
                <input id="result-url" readonly>
                <button onclick="copyUrl()">Copy</button>
            </div>
            <div class="result-url">
                <input id="result-direct" readonly>
                <button onclick="copyDirect()">Direct</button>
            </div>
        </div>

        <p class="stats">{image_count} images hosted &middot; <a href="/gallery" style="color: #667eea;">Gallery</a></p>
    </div>

    <script>
        const zone = document.getElementById('upload-zone');
        const fileInput = document.getElementById('file-input');
        const progressEl = document.getElementById('progress');
        const progressInner = document.getElementById('progress-inner');
        const errorEl = document.getElementById('error');
        const resultEl = document.getElementById('result');

        // Drag and drop
        zone.addEventListener('dragover', (e) => {{
            e.preventDefault();
            zone.classList.add('dragging');
        }});
        zone.addEventListener('dragleave', () => zone.classList.remove('dragging'));
        zone.addEventListener('drop', (e) => {{
            e.preventDefault();
            zone.classList.remove('dragging');
            if (e.dataTransfer.files.length > 0) {{
                uploadFile(e.dataTransfer.files[0]);
            }}
        }});

        // File input
        fileInput.addEventListener('change', (e) => {{
            if (e.target.files.length > 0) {{
                uploadFile(e.target.files[0]);
            }}
        }});

        // Paste from clipboard
        document.addEventListener('paste', (e) => {{
            const items = e.clipboardData.items;
            for (let i = 0; i < items.length; i++) {{
                if (items[i].type.startsWith('image/')) {{
                    const file = items[i].getAsFile();
                    if (file) uploadFile(file);
                    return;
                }}
            }}
        }});

        function uploadFile(file) {{
            if (!file.type.startsWith('image/')) {{
                showError('Please upload an image file');
                return;
            }}

            const formData = new FormData();
            formData.append('file', file);

            progressEl.classList.add('visible');
            errorEl.classList.remove('visible');
            resultEl.classList.remove('visible');
            progressInner.style.width = '30%';

            fetch('/upload', {{
                method: 'POST',
                body: formData,
            }})
            .then(r => r.json())
            .then(data => {{
                progressInner.style.width = '100%';
                setTimeout(() => progressEl.classList.remove('visible'), 500);

                if (data.success) {{
                    document.getElementById('result-img').src = data.direct_url;
                    document.getElementById('result-url').value = data.direct_url;
                    document.getElementById('result-direct').value = data.direct_url;
                    resultEl.classList.add('visible');
                }} else {{
                    showError(data.error || 'Upload failed');
                }}
            }})
            .catch(err => {{
                progressEl.classList.remove('visible');
                showError('Upload failed: ' + err.message);
            }});
        }}

        function showError(msg) {{
            errorEl.textContent = msg;
            errorEl.classList.add('visible');
        }}

        function copyUrl() {{
            const input = document.getElementById('result-url');
            input.select();
            navigator.clipboard.writeText(input.value);
        }}

        function copyDirect() {{
            const input = document.getElementById('result-direct');
            input.select();
            navigator.clipboard.writeText(input.value);
        }}
    </script>
</body>
</html>"#)
}

fn render_view_page(base_url: &str, meta: &ImageMeta, direct_url: &str) -> String {
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Convey Images - {token}</title>
    <meta property="og:title" content="Convey Image">
    <meta property="og:image" content="{direct_url}">
    <meta property="og:image:width" content="{width}">
    <meta property="og:image:height" content="{height}">
    <meta property="og:type" content="website">
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:image" content="{direct_url}">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            color: #e0e0e0;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 20px;
        }}
        .header {{
            margin-bottom: 20px;
        }}
        .header a {{
            color: #667eea;
            text-decoration: none;
            font-size: 1.2em;
        }}
        img {{
            max-width: 100%;
            max-height: 80vh;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }}
        .info {{
            margin-top: 15px;
            color: #888;
            font-size: 0.85em;
        }}
        .copy-btn {{
            background: #667eea;
            color: white;
            border: none;
            padding: 8px 20px;
            border-radius: 6px;
            cursor: pointer;
            margin-top: 10px;
            font-size: 0.9em;
        }}
        .copy-btn:hover {{ background: #5a6fd6; }}
    </style>
</head>
<body>
    <div class="header"><a href="{base_url}">Convey Images</a></div>
    <img src="{direct_url}" alt="Image {token}">
    <div class="info">{width}x{height} &middot; {size} &middot; {content_type}</div>
    <button class="copy-btn" onclick="navigator.clipboard.writeText('{direct_url}')">Copy Direct URL</button>
</body>
</html>"#,
        token = meta.token,
        direct_url = direct_url,
        width = meta.width,
        height = meta.height,
        size = format_size(meta.size),
        content_type = meta.content_type,
        base_url = base_url,
    )
}

fn render_gallery_page(base_url: &str, images: &[&ImageMeta]) -> String {
    let mut image_html = String::new();
    for meta in images {
        let thumb = format!("{}/i/{}.{}", base_url, meta.token, meta.extension);
        let view = format!("{}/v/{}.{}", base_url, meta.token, meta.extension);
        image_html.push_str(&format!(
            r#"<a href="{view}" class="thumb"><img src="{thumb}" alt="{token}" loading="lazy"><div class="meta">{dims} &middot; {size}</div></a>"#,
            view = view,
            thumb = thumb,
            token = meta.token,
            dims = format!("{}x{}", meta.width, meta.height),
            size = format_size(meta.size),
        ));
    }

    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Convey Images - Gallery</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            color: #e0e0e0;
            min-height: 100vh;
            padding: 30px;
        }}
        h1 {{
            text-align: center;
            margin-bottom: 30px;
        }}
        h1 a {{
            color: #667eea;
            text-decoration: none;
        }}
        .gallery {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 15px;
            max-width: 1200px;
            margin: 0 auto;
        }}
        .thumb {{
            display: block;
            background: #16213e;
            border-radius: 10px;
            overflow: hidden;
            text-decoration: none;
            transition: transform 0.2s;
        }}
        .thumb:hover {{ transform: scale(1.02); }}
        .thumb img {{
            width: 100%;
            height: 180px;
            object-fit: cover;
        }}
        .thumb .meta {{
            padding: 8px 12px;
            font-size: 0.75em;
            color: #888;
        }}
        .empty {{
            text-align: center;
            color: #666;
            padding: 60px;
        }}
    </style>
</head>
<body>
    <h1><a href="{base_url}">Convey Images</a> &middot; Gallery</h1>
    <div class="gallery">
        {images}
    </div>
    {empty}
</body>
</html>"#,
        base_url = base_url,
        images = image_html,
        empty = if images.is_empty() { r#"<p class="empty">No images yet</p>"# } else { "" },
    )
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}
