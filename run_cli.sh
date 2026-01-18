#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH=src
python3 cli.py "$@"
