FROM mcr.microsoft.com/devcontainers/javascript-node:20

# Abilita systemd
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    xl2tpd \
    strongswan \
    ppp \
    curl \
    systemd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Abilita systemd per il container
STOPSIGNAL SIGRTMIN+3

