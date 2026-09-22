FROM rust:1.98-bookworm AS builder

RUN apt-get update && apt-get install -y nodejs npm && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
ENV DATABASE_URL=sqlite:///app/db_v2.sqlite3
ARG COVERAGE=false
RUN if [ "$COVERAGE" = "true" ]; then \
      export RUSTFLAGS="-C instrument-coverage --remap-path-prefix=/app=sctgdesk-api-server"; \
      cargo build --features coverage --release; \
    else \
      cargo build --release; \
    fi

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/sctgdesk-api-server .

ARG COVERAGE=false
RUN if [ "$COVERAGE" = "true" ]; then mkdir -p /data/coverage; fi
ENV LLVM_PROFILE_FILE=/data/coverage/%p-%m.profraw

EXPOSE 21114

CMD ["./sctgdesk-api-server", "--address", "0.0.0.0", "--port", "21114"]
