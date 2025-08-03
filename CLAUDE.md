# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CRWAF (云锁Web应用防火墙) is a high-performance Web Application Firewall implemented in Rust. It provides comprehensive web security protection with rule-based attack detection, multiple defense mechanisms, and real-time monitoring.

## Development Commands

### Build Commands
```bash
# Development build
cargo build

# Release build  
cargo build --release

# Clean build artifacts
cargo clean
```

### Running the Application
```bash
# Run in development mode
cargo run

# Run in release mode
cargo run --release
```

### Testing
```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test module
cargo test rules::tests
```

### Additional Commands
```bash
# Check code formatting
cargo fmt --check

# Format code
cargo fmt

# Run clippy lints
cargo clippy

# Generate documentation
cargo doc --open
```

## Architecture Overview

### Core Modules Structure

The application follows a modular architecture with three main components:

1. **Core Module** (`src/core/`):
   - `config.rs`: Configuration management using TOML files
   - `cache.rs`: File-based caching system with TTL support
   - `cache_manager.rs`: Global cache management
   - `logger.rs`: Custom logging with rotation and compression
   - `grpc.rs`: gRPC server implementation
   - `error.rs`: Error handling types

2. **HTTP Module** (`src/http/`):
   - `server.rs`: Axum-based HTTP server
   - `handler.rs`: Request handlers
   - `middleware/`: HTTP middleware components
     - `attack_detection.rs`: Request analysis and threat detection
     - `logging.rs`: Request/response logging
     - `error.rs`: Error handling middleware

3. **Rules Module** (`src/rules/`):
   - `engine.rs`: Rule evaluation engine
   - `model.rs`: Rule data structures
   - `parser.rs`: JSON rule file parsing
   - `detector.rs`: Attack detection logic with configurable levels
   - `detector_manager.rs`: Global detector management
   - `tests.rs`: Rule engine test suite

### Key Patterns

- **Async/Await**: Uses Tokio runtime throughout
- **Arc/Mutex**: Shared state management for thread safety
- **Configuration-Driven**: TOML-based configuration in `config/config.toml`
- **Rule-Based Detection**: JSON rule files in `rules/` directory
- **Caching Strategy**: Two-tier caching (memory + file-based)
- **gRPC Communication`: Protocol buffers defined in `proto/waf.proto`

### Configuration

The main configuration is in `config/config.toml` with sections for:
- Server settings (HTTP/gRPC ports)
- Cache configuration (memory and file-based)
- Logging settings with rotation policies
- Rule file management

### Rule System

Rules are stored as JSON files in the `rules/` directory:
- `default.json`: Default WAF rules
- `custom.json`: Custom security rules
- `custom_regex.json`: Regular expression based rules
- Rule files are loaded by priority order defined in config

### Build System

- Uses `build.rs` to compile Protocol Buffer definitions
- gRPC services are generated from `proto/waf.proto` at build time
- No custom build scripts or Makefiles - standard Cargo workflow

### Testing Strategy

Tests are primarily located in `src/rules/tests.rs` focusing on rule engine functionality. Run individual test modules using `cargo test <module_name>`.