FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    curl \
    git \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Install Zig 0.16
RUN curl -L https://ziglang.org/download/0.16.0/zig-linux-x86_64-0.16.0.tar.xz | tar xJ -C /opt
ENV PATH="/opt/zig-linux-x86_64-0.16.0:${PATH}"

# Build quicz interop binaries
WORKDIR /quicz
COPY . .
RUN zig build -Doptimize=ReleaseFast

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /quicz/zig-out/bin/quicz-interop-server /usr/local/bin/
COPY --from=builder /quicz/zig-out/bin/quicz-interop-client /usr/local/bin/
COPY interop/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

ENTRYPOINT ["/run_endpoint.sh"]
