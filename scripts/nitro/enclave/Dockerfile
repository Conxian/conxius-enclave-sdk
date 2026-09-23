# Nitro enclave image for the attestation probe (#242).
#
# A Nitro EIF must be built from an image whose final CMD launches the enclave
# application. This two-stage build produces a small static-ish binary and sets
# it as the enclave entrypoint.
#
# DRAFT: validated against AWS Nitro enclave image requirements; adjust base
# image / musl toolchain to match the enclave OS before first production build.

FROM rust:1.98-slim AS build
WORKDIR /app
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /app/target/release/conxian-nitro-attestation-probe /usr/local/bin/
CMD ["/usr/local/bin/conxian-nitro-attestation-probe"]
