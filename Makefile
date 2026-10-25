.PHONY: fmt lint

# Every workspace root CI formats: `cargo fmt --all` only sees the one it runs from.
fmt:
	cargo fmt --all
	for w in examples perf/aot perf/bench_apps vm/examples/patch-testing; do (cd $$w && cargo fmt --all) || exit 1; done

# The clippy runs of CI's lint job, in the same order and with the same lint flags. The first three
# are capped at warn, as in CI, so they fail only on errors. Needs the CUDA toolchain; cuda-mle is
# left out because its build.rs needs nvidia-smi. CI regenerates `aot-generated/` first, so on a
# fresh tree this lints the bootstrap stub instead.
lint:
	cargo clippy --workspace --lib --exclude pico-sdk --exclude cuda-mle -- --cap-lints=warn
	cargo clippy -p pico-aot-codegen --bins -- --cap-lints=warn
	cargo clippy -p pico-vm --bins -- --cap-lints=warn
	cargo clippy -p pico-sdk --features prover,libm --locked -- -D warnings
	cargo clippy -p pico-prover -p pico-cli --lib --bins --tests --locked -- -D warnings
	cargo clippy -p pico-prover -p pico-cli --no-default-features --lib --bins --tests --locked -- -D warnings
