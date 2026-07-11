# Production gateway image. Build context is the workspace root:
#   docker build -f crates/clave-gateway/Dockerfile -t clave-gateway .
# (the docker-compose `gateway` service does this for you).
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
# `server` = postgres + workos + a tokio runtime. reqwest/rustls use the `ring` provider, so no
# OpenSSL/cmake toolchain is needed in the image.
RUN cargo build -p clave-gateway --features server --release

FROM debian:bookworm-slim
# CA roots so the WorkOS HTTPS calls verify.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/clave-gateway /usr/local/bin/clave-gateway
EXPOSE 8080
USER nobody
ENTRYPOINT ["clave-gateway"]
