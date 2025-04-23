# Build
FROM ubuntu:24.04 AS builder

RUN apt-get update -y && apt-get upgrade -y
RUN apt-get isntall -y curl build-essential pkg-config libssl-dev cmake git protobuf-compiler

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
ENV CARGO_HOME=/root/.cargo

WORKDIR /app
COPY . .

RUN cargo build --release --bin coordinator

# Release
FROM ubuntu:24.04
COPY --from=builder /app/target/release/coordinator /usr/local/bin/coordinator

#ENTRYPOINT ["/usr/local/bin/coordinator"]
