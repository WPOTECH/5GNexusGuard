#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
# Pass -o to use cached Maven dependencies. Privileged gates are a separate command.
mvn -B "$@" package
python3 -m unittest discover -s scripts/native-dual -p 'test_*.py' -v
python3 -m py_compile scripts/native-dual/native.py scripts/native-dual/integration.py
