# syntax=docker/dockerfile:1
FROM rust:1.98-bookworm AS builder

RUN apt-get update && apt-get install -y nodejs npm && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
ARG COVERAGE=false
# Cache mounts keep crate and npm downloads and compiled dependencies between builds of this builder.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/root/.npm \
    --mount=type=cache,target=/app/target \
    # build.rs skips the console when its build is cached, but include_dir! needs webconsole/dist.
    (cd webconsole && npm install --force && npm run build) \
    && export CARGO_TARGET_DIR=/app/target/coverage-$COVERAGE \
    && if [ "$COVERAGE" = "true" ]; then \
      export RUSTFLAGS="-C instrument-coverage --remap-path-prefix=/app=rustdesk-api"; \
      cargo build --features coverage --release; \
    else \
      cargo build --release; \
    fi \
    && cp $CARGO_TARGET_DIR/release/rustdesk-api /app/rustdesk-api

FROM debian:bookworm-slim

RUN apt-get update && apt-get upgrade -y && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/rustdesk-api .

ARG COVERAGE=false
RUN if [ "$COVERAGE" = "true" ]; then mkdir -p /data/coverage; fi
ENV LLVM_PROFILE_FILE=/data/coverage/%p-%m.profraw

EXPOSE 21114

CMD ["./rustdesk-api", "serve", "--address", "0.0.0.0", "--port", "21114"]
