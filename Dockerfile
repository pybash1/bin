# Build stage
FROM rust:1.75-alpine AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock* ./
COPY src ./src

RUN apk add --no-cache musl-dev
RUN cargo build --release

# Runtime stage
FROM alpine:3.18

RUN apk add --no-cache ca-certificates

COPY --from=builder /build/target/release/bin-mod-board /usr/local/bin/pastebin
RUN chmod +x /usr/local/bin/pastebin

EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/pastebin", "0.0.0.0:8000"]
