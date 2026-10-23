FROM dl-ipsec-bpf-java25:probe
RUN apt-get update && apt-get install -y --no-install-recommends python3-cryptography iputils-ping && rm -rf /var/lib/apt/lists/*
