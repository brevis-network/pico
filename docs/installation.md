# Install 

## Option 1:  Cargo install

Install pico-cli from the GitHub repository

`cargo +nightly install --git https://github.com/brevis-network/pico pico-cli`

Check the version

`cargo pico --version`

## Option 2: Local install

Git clone Pico-VM repository

`git clone https://github.com/brevis-network/pico`

cargo install from the local path

`cd sdk/cli
cargo install --locked --force --path .`

## Rust toolchain

Pico uses the rust-specific rust toolchain version (nightly-2024-11-27) to build the program. 

`rustup install nightly-2024-11-27 `
`rustup component add rust-src --toolchain nightly-2024-11-27`
