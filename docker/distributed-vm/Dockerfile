# syntax=docker/dockerfile:1.4

# Stage 1: Base image with Rust, cargo-chef, and other dependencies installed
FROM rust:1.86-slim AS base

RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    cmake \
    git \
    openssh-client

COPY rust-toolchain .
RUN cargo install --locked cargo-chef && rustup show

WORKDIR /app

# Stage 2: Planner - analyze project and generate recipe.json
FROM base AS planner
WORKDIR /app

# Copy Cargo.toml and Cargo.lock of the workspace
COPY Cargo.toml Cargo.lock ./
# For each workspace member
# (If bins and libs are declared in Cargo.toml already, copying lib.rs and main.rs is not necessary)
COPY derive/Cargo.toml ./derive/
COPY derive/src/lib.rs ./derive/src/

COPY vm/Cargo.toml ./vm/
COPY vm/src/lib.rs ./vm/src/

COPY sdk/cli/Cargo.toml ./sdk/cli/
COPY sdk/cli/src/lib.rs ./sdk/cli/src/

COPY sdk/patch-libs/Cargo.toml ./sdk/patch-libs/
COPY sdk/patch-libs/src/lib.rs ./sdk/patch-libs/src/

COPY sdk/sdk/Cargo.toml ./sdk/sdk/
COPY sdk/sdk/src/lib.rs ./sdk/sdk/src/

COPY scripts/Cargo.toml ./scripts/

COPY gnark/field-ffi/Cargo.toml ./gnark/field-ffi/
COPY gnark/field-ffi/src/lib.rs ./gnark/field-ffi/src/

COPY perf/Cargo.toml ./perf/

COPY distributed-vm/Cargo.toml ./distributed-vm/

ARG RUSTFLAGS
ARG JEMALLOC_SYS_WITH_MALLOC_CONF

ENV RUSTFLAGS=${RUSTFLAGS}
ENV JEMALLOC_SYS_WITH_MALLOC_CONF=${JEMALLOC_SYS_WITH_MALLOC_CONF}

RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Builder - build dependencies and the application
FROM base AS builder
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json

# Use SSH mount for GitHub deploy key access, and cache for cargo registry and git
RUN --mount=type=ssh \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    mkdir -p ~/.ssh && \
    ssh-keyscan github.com >> ~/.ssh/known_hosts && \
    git config --global url."ssh://git@github.com/".insteadOf "https://github.com/" && \
    cargo chef cook --release --recipe-path recipe.json

COPY . .

RUN --mount=type=ssh \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    mkdir -p ~/.ssh && \
    ssh-keyscan github.com >> ~/.ssh/known_hosts && \
    git config --global url."ssh://git@github.com/".insteadOf "https://github.com/" && \
    cargo build --release --bin coordinator --bin worker --target-dir=/app/target