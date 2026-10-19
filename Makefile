.PHONY: fmt lint

# Every workspace root in the repo: `cargo fmt --all` only sees the one it runs from.
fmt:
	cargo fmt --all
	for w in examples perf/aot perf/bench_apps vm/examples/patch-testing; do (cd $$w && cargo fmt --all) || exit 1; done

# The three clippy runs of CI's lint job, in the same order and with the same flags.
lint:
	cargo clippy --workspace --lib --bins --examples --tests --benches --all-features --locked -- -D warnings
	cargo clippy -p pico-prover -p pico-cli --no-default-features --lib --bins --tests --locked -- -D warnings
	cargo clippy -p pico-sdk --features prover,libm --locked -- -D warnings
