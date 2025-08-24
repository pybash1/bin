# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is "bin", a minimalist pastebin service written in Rust (~300 lines of code). It's an in-memory paste storage system with no database requirement, using Actix Web for the HTTP server and an LRU cache for paste management.

## Build and Development Commands

```bash
# Build the project
cargo build --release

# Run the development version
cargo run

# Run the release version
./target/release/bin

# Run with custom parameters
./bin [bind_addr] [--buffer-size N] [--max-paste-size N]
```

Default configuration:
- Bind address: `127.0.0.1:8820`
- Buffer size: 1000 pastes (before rotation)
- Max paste size: 32kB

## Architecture

The application is structured as a simple REST API with the following key components:

- **main.rs**: HTTP server setup and route handlers using Actix Web
- **io.rs**: Paste storage logic using `LinkedHashMap` with LRU eviction
- **params.rs**: Request parameter extraction (Host header, plaintext detection)
- **errors.rs**: Custom error types with JSON responses

### Core Data Flow

1. Paste storage uses an in-memory `LinkedHashMap<String, Bytes>` wrapped in `RwLock`
2. Paste IDs are generated using the `gpw` crate for pronounceable passwords
3. When buffer limit is reached, old entries are purged from the front of the map
4. All pastes are served as `text/plain` with UTF-8 encoding

### API Endpoints

- `GET /` - API information (JSON)
- `GET /all` - List all paste IDs (JSON)
- `POST /` - Create paste from form data (redirects to paste URL)
- `PUT /` - Create paste from raw data (returns paste URL)
- `GET /{paste_id}[.ext]` - Retrieve paste content (optional extension for syntax highlighting)

### Key Implementation Details

- Uses `parking_lot::RwLock` for thread-safe paste storage
- Supports both form-based and raw data paste creation
- File extensions in URLs are parsed but only used for client-side highlighting
- Host header detection for generating full URLs in PUT responses
- User-Agent detection for plaintext vs. JSON responses