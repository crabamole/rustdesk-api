FROM rust:1.98-bookworm AS builder

RUN apt-get update && apt-get install -y nodejs npm && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
ENV DATABASE_URL=sqlite:///app/db_v2.sqlite3
ENV RUSTFLAGS="-C instrument-coverage --remap-path-prefix=/app=sctgdesk-api-server"
RUN cargo build --features coverage --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/sctgdesk-api-server .

ENV LLVM_PROFILE_FILE=/data/coverage/%p-%m.profraw
RUN mkdir -p /data/coverage

EXPOSE 21114

CMD ["./sctgdesk-api-server", "--address", "0.0.0.0", "--port", "21114"]
