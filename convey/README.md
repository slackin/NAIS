# Convey Image Paste Board

A self-hosted, privacy-respecting image hosting service for the Convey chat client. Hosted at `convey.pugbot.net`.

## Features

- **EXIF Stripping** – All uploaded images are re-encoded to remove EXIF metadata (GPS, camera info, timestamps, etc.)
- **Tokenized URLs** – Original filenames are never exposed; images get random 12-character token names
- **Duplicate Detection** – Content-hash based dedup returns existing URL for identical images
- **Web Upload** – Drag & drop, file picker, or clipboard paste directly on the web interface
- **API Upload** – Simple `POST /upload` multipart endpoint for client integration
- **Gallery** – Browse recent uploads at `/gallery`
- **Auto Cleanup** – Configurable retention period and max image count
- **Image Resizing** – Large images are downscaled to a configurable max dimension

## API

### Upload

```
POST /upload
Content-Type: multipart/form-data

Field: file (or image) - the image data
```

Response:
```json
{
  "success": true,
  "url": "https://convey.pugbot.net/v/a1b2c3d4e5f6.png",
  "direct_url": "https://convey.pugbot.net/i/a1b2c3d4e5f6.png",
  "token": "a1b2c3d4e5f6",
  "delete_url": "https://convey.pugbot.net/delete/...",
  "size": 123456,
  "width": 1920,
  "height": 1080
}
```

### Direct Image
```
GET /i/{token}.{ext}
```
Returns the image with appropriate Content-Type and caching headers.

### View Page
```
GET /v/{token}.{ext}
```
Returns an HTML page with OG meta tags (for link previews) displaying the image.

### Image Info
```
GET /api/info/{token}
```
Returns JSON metadata about the image.

### Delete
```
POST /delete/{delete_token}
```

## Deployment

1. Build: `cargo build --release --target x86_64-unknown-linux-musl -p convey-images`
2. Deploy: `./deploy.sh`
3. Configure Nginx with `deploy/nginx-convey.conf`
4. Set up TLS: `sudo certbot --nginx -d convey.pugbot.net`

## Configuration

See `convey.toml.example` for all options. Default config location: `/etc/convey-images/config.toml`

| Setting | Default | Description |
|---------|---------|-------------|
| `bind_address` | `0.0.0.0:8844` | HTTP server bind address |
| `base_url` | `https://convey.pugbot.net` | Public URL for link generation |
| `storage_dir` | `/var/lib/convey-images` | Image storage path |
| `max_upload_size` | 20MB | Maximum upload file size |
| `max_images` | 50000 | Maximum stored images |
| `retention_days` | 0 (forever) | Auto-delete after N days |
| `max_dimension` | 4096 | Max width/height (resized if larger) |
