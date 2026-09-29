FROM rust:1.98-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /app/target/x86_64-unknown-linux-musl/release/conxian-nitro-attestation-probe /usr/local/bin/
CMD ["/usr/local/bin/conxian-nitro-attestation-probe"]
