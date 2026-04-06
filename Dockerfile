# Multi-stage build for minimal container
FROM rust:1.83-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/agora /usr/local/bin/agora
EXPOSE 8080
CMD ["agora", "serve", "--port", "8080"]
