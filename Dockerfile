# Multi-stage build for minimal container
FROM rust:1.86-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/agora /usr/local/bin/agora
COPY entrypoint-plaza.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENV AGORA_AGENT_ID=plaza-viewer
ENV AGORA_RELAY_URL=https://ntfy.theagora.dev
ENV AGORA_BOOTSTRAP_PUBLIC_PLAZA=1
ENV AGORA_SERVE_READONLY=1
EXPOSE 8080
CMD ["/entrypoint.sh"]
