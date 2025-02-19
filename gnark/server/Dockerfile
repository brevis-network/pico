FROM golang:1.22 AS go-builder

FROM rustlang/rust:nightly-bullseye-slim AS rust-builder

# Dependencies
RUN apt update && apt install -y clang && apt install -y git

# Install Go 1.22
COPY --from=go-builder /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:$PATH"

WORKDIR /pico

RUN echo '[credential]' >> /root/.gitconfig
RUN echo 'helper = store' >> /root/.gitconfig

RUN --mount=type=secret,id=gitcre,target=/root/.git-credentials git clone https://github.com/brevis-network/brevis-vm.git

WORKDIR /pico/brevis-vm

RUN --mount=type=secret,id=gitcre,target=/root/.git-credentials cargo build --release --package field-ffi
RUN cp target/release/libfield_ffi.so /usr/lib/

WORKDIR /pico/brevis-vm/gnark/server/main/
RUN go build && cp main /pico_gnark_server

FROM rustlang/rust:nightly-bullseye-slim
COPY --from=rust-builder /pico_gnark_server /pico_gnark_server
COPY --from=rust-builder /pico/brevis-vm/target/release/libfield_ffi.so /usr/lib/

ENTRYPOINT ["/pico_gnark_server"]
CMD ["-field", "kb"]