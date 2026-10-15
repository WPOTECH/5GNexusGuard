#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
mvn -B "$@" clean package
python3 -m unittest discover -s scripts/ipsec-dual -p 'test_*.py' -v
python3 -m py_compile scripts/ipsec-dual/*.py
bash -n scripts/ipsec-dual/run.sh
