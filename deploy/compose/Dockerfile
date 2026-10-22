FROM rust:1.99.0-bookworm AS server-build

WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential cmake perl pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src/modules/server
COPY Cargo.toml Cargo.lock ./
COPY --from=hs-core Cargo.toml ../core/Cargo.toml
COPY --from=hs-core src/ ../core/src/
COPY src ./src
RUN cargo build --locked --release --bin hs-server

FROM golang:1.27.1-bookworm AS tui-build

WORKDIR /src/modules/server/tui
COPY tui/go.mod tui/go.sum ./
RUN go mod download
COPY tui/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/helicoid-server .

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libgcc-s1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 helicoid \
    && useradd --uid 10001 --gid 10001 --home-dir /var/lib/helicoid \
        --no-create-home --shell /usr/sbin/nologin helicoid \
    && install -d --owner 10001 --group 10001 --mode 0700 \
        /var/lib/helicoid /var/lib/helicoid/data /var/lib/helicoid/.config \
        /run/helicoid/tls /run/helicoid/backup-control

COPY --from=server-build /src/target/release/hs-server /usr/local/bin/hs-server
COPY --from=tui-build /out/helicoid-server /usr/local/bin/helicoid-server

ENV HOME=/var/lib/helicoid
VOLUME ["/var/lib/helicoid"]
EXPOSE 8920
USER 10001:10001
ENTRYPOINT ["hs-server"]
