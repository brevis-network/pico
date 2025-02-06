.PHONY: fmt lint

fmt:
	cargo fmt

lint:
	cargo clippy --workspace --lib --examples --tests --benches --all-features --locked -- -D warnings
