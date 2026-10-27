#!/usr/bin/env bash
# Explicit local deployment. No hard-coded host, SSH, branch changes or service start.
set -euo pipefail
repo=$(cd "$(dirname "$0")" && pwd)
exec bash "$repo/install.sh" "$@"
