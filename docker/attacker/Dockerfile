FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap hydra curl wget iputils-ping sqlmap iproute2 net-tools \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /scripts
