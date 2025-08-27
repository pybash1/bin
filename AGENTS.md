# AGENTS.md - Development Guidelines for Bin

## Build/Test/Lint Commands
- `cargo build` / `cargo build --release` - Build project (release optimized with LTO)
- `cargo run` - Run development server on 127.0.0.1:8820
- `cargo test` - Run all tests (currently no tests in project)
- `cargo check` - Fast compilation check without building
- `cargo clippy` - Run linter (pedantic mode enabled in code)
- `cargo fmt` - Format code with rustfmt

## Code Style & Conventions
- **Clippy**: Pedantic mode enabled (`#![deny(clippy::pedantic)]`)
- **Imports**: Group standard library, external crates, then local modules
- **Naming**: snake_case for functions/variables, PascalCase for types/structs
- **Error Handling**: Custom error types with JSON responses using macro pattern
- **Threading**: Use `parking_lot::RwLock` for concurrent access
- **Async**: Actix-web handlers are async, use `tokio` runtime
- **Memory**: LRU cache pattern with `LinkedHashMap` for paste storage
- **Dependencies**: Minimal external deps, prefer std library when possible

## Architecture Notes
- **Device-based storage**: Each device (identified by 8-char Device-Code header) can store up to 2 pastes
- **Access control**: Pastes can only be viewed by the device that created them
- **Thread-safe storage**: `RwLock<LinkedHashMap<String, Paste>>` with device ownership tracking
- **Device validation**: Device-Code header must be 8 alphanumeric chars (A-Z, 0-9)
- **Auto-purging**: When device exceeds 2 pastes, oldest are automatically removed
- **No global limits**: Removed buffer_size parameter, each device limited independently
- **Required headers**: All endpoints (except GET /) require valid Device-Code header