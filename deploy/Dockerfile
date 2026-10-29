# Build:  docker build -f deploy/Dockerfile -t strongbox-server .
FROM rust:1.82-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p strongbox-server

FROM debian:bookworm-slim
RUN useradd --system --home /data strongbox && mkdir /data && chown strongbox /data
COPY --from=build /src/target/release/strongbox-server /usr/local/bin/
USER strongbox
# The server speaks plain HTTP. Only publish this port to a TLS-terminating proxy on the same
# host or private network (e.g. `-p 127.0.0.1:8080:8080` with Caddy in front), never directly.
ENV STRONGBOX_DATA_DIR=/data STRONGBOX_LISTEN=0.0.0.0:8080
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["strongbox-server"]
