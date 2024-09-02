.PHONY: fmt lint

fmt:
	cargo fmt

lint:
	cargo check --all-features
	cargo clippy --all-features --all-targets -- -D -warnings
