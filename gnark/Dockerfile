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

RUN --mount=type=secret,id=gitcre,target=/root/.git-credentials cargo build --release
RUN cp target/release/field_ffi.so /usr/lib/

WORKDIR /pico/brevis-vm/gnark/sdk/main/
RUN go build && cp main /pico_gnark_cli

FROM rustlang/rust:nightly-bullseye-slim
COPY --from=rust-builder /pico_gnark_cli /pico_gnark_cli
COPY --from=rust-builder /pico/brevis-vm/target/release/field_ffi.so /usr/lib/

#CMD ["/pico_vm_gnark_cli"]