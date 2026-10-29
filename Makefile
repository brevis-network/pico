.PHONY: build fmt lint

SHELL := bash

# Release build of the workspace: GPU (`cuda`) when detect_cuda.sh finds a CUDA toolkit and a GPU,
# CPU otherwise. PICO_CUDA=1 / PICO_CUDA=0 forces one or the other.
build:
	. ./detect_cuda.sh && pico_cuda_detect && \
	if [ "$$PICO_BACKEND" = cuda ]; then \
		cargo build --release --features pico-vm/cuda,distributed-vm/cuda; \
	else \
		cargo build --release; \
	fi

# Every workspace root CI formats: `cargo fmt --all` only sees the one it runs from.
fmt:
	cargo fmt --all
	for w in examples perf/aot perf/bench_apps vm/examples/patch-testing; do (cd $$w && cargo fmt --all) || exit 1; done

# The clippy runs of CI's lint job, in the same order and with the same lint flags. The first three
# are capped at warn, as in CI, so they fail only on errors. CPU build: the CUDA crates `cuda-mle`
# and `gpu-api` are left out. CI regenerates `aot-generated/` first, so on a fresh tree this lints
# the bootstrap stub instead.
lint:
	cargo clippy --workspace --lib --exclude pico-sdk --exclude cuda-mle --exclude pico-gpu-api -- --cap-lints=warn
	cargo clippy -p pico-aot-codegen --bins -- --cap-lints=warn
	cargo clippy -p pico-vm --bins -- --cap-lints=warn
	cargo clippy -p pico-sdk --features prover,libm --locked -- -D warnings
	cargo clippy -p pico-prover -p pico-cli --lib --bins --tests --locked -- -D warnings
	cargo clippy -p pico-prover -p pico-cli --no-default-features --lib --bins --tests --locked -- -D warnings
