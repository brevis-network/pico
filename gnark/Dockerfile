# syntax=docker/dockerfile:1
#
# The gnark half of the EVM path: `pico-gnark` (setup, prove, verify, solve, exportSolidity; the
# entrypoint) and `pico-gnark-server`, with the KoalaBear field library their hints call into.
# Built from the repository root, since field-ffi is a member of the Rust workspace:
#
#   docker build -f gnark/Dockerfile -t pico-gnark .
#
# The paths a run names are the container's, so mount what it reads and writes:
#
#   docker run --rm -v "$PWD/pico_out:/out" pico-gnark -cmd prove \
#     -constraints /out/wrap_constraints.json -witness /out/wrap_groth16_witness.json \
#     -pk /out/groth16/pk -vk /out/groth16/vk -ccs /out/groth16/ccs \
#     -manifest /out/groth16/manifest.json -proof /out/proof.data
#
# `cargo pico prove --evm` runs the image itself (its own mounts) when PICO_GNARK_IMAGE names it.

FROM rust:1-bookworm AS ffi
# The workspace's nightly, without the development components rust-toolchain adds to it.
ENV RUSTUP_TOOLCHAIN=nightly-2026-09-27
RUN rustup toolchain install nightly-2026-09-27 --profile minimal
WORKDIR /src
COPY . .
RUN cargo build --release --locked --package field-ffi

FROM golang:1.24-bookworm AS go
WORKDIR /src/gnark
COPY gnark/go.mod gnark/go.sum ./
RUN go mod download
COPY gnark/ ./
COPY --from=ffi /src/target/release/libfield_ffi.so /usr/local/lib/
ENV CGO_LDFLAGS="-L/usr/local/lib"
RUN go build -trimpath -o /out/pico-gnark ./sdk/main \
 && go build -trimpath -o /out/pico-gnark-server ./server/main

FROM debian:bookworm-slim
COPY --from=ffi /src/target/release/libfield_ffi.so /usr/local/lib/
RUN ldconfig
COPY --from=go /out/pico-gnark /out/pico-gnark-server /usr/local/bin/
# The binaries' default paths are ./data/...: keys mounted at /data are used as they are.
WORKDIR /
ENTRYPOINT ["pico-gnark"]
