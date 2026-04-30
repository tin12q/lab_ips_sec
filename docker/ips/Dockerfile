FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build pkg-config \
    libpcap-dev libnetfilter-queue-dev libnfnetlink-dev \
    libpcre2-dev iptables tcpdump ca-certificates git \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Copy source and build minisnort at image build time
COPY . /workspace/
RUN cmake -S /workspace -B /tmp/minisnort-build -G Ninja \
  && ninja -C /tmp/minisnort-build \
  && mkdir -p /opt/minisnort \
  && cp /tmp/minisnort-build/src/minisnort /opt/minisnort/minisnort \
  && chmod +x /opt/minisnort/minisnort \
  && rm -rf /tmp/minisnort-build
