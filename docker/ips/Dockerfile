FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build pkg-config \
    libpcap-dev libnetfilter-queue-dev libnfnetlink-dev \
    libpcre2-dev iptables tcpdump ca-certificates git \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
