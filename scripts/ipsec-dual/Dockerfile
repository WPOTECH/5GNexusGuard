# Record the built image ID and dpkg inventory with each run; tag/security updates vary.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan-charon strongswan-swanctl libstrongswan-standard-plugins \
    libcharon-extra-plugins openssl iproute2 nftables wireguard-tools tcpdump \
    python3 python3-cryptography procps util-linux ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY scripts/ipsec-dual /opt/ipsec-dual
WORKDIR /opt/ipsec-dual
ENV DL_IPSEC_ISOLATED=1
CMD ["python3", "integration.py"]
VOLUME ["/evidence"]
