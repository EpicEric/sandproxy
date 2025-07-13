FROM --platform=$BUILDPLATFORM rust:1.88.0-alpine3.22 AS builder
ENV PKGCONFIG_SYSROOTDIR=/
RUN apk add --no-cache musl-dev libressl-dev perl build-base zig
RUN cargo install --locked cargo-zigbuild
RUN rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo "fn main() {}" > src/main.rs \
    && cargo zigbuild --release --locked --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl \
    && rm src/main.rs
COPY src ./src
COPY README.md .
RUN cargo zigbuild --release --locked --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl

FROM --platform=$BUILDPLATFORM scratch AS binary
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/sandproxy /sandproxy-linux-amd64
COPY --from=builder /app/target/aarch64-unknown-linux-musl/release/sandproxy /sandproxy-linux-arm64

FROM scratch AS runner
ARG TARGETOS
ARG TARGETARCH
COPY --from=binary /sandproxy-${TARGETOS}-${TARGETARCH} /sandproxy
ENTRYPOINT [ "/sandproxy" ]
