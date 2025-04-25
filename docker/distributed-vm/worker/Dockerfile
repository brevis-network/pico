# syntax=docker/dockerfile:1.4

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl3 && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=brevis-multi-machine-builder /app/perf/bench_data/ /usr/local/bin/perf/bench_data/
COPY --from=brevis-multi-machine-builder /app/target/release/worker /usr/local/bin/worker

WORKDIR /usr/local/bin

ENTRYPOINT ["/usr/local/bin/worker"]