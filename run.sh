#!/usr/bin/env bash

if [ ! -d ".venv" ]; then
    echo "[!] .venv not found. Run: python3 bootstrap.py"
    exit 1
fi

source .venv/bin/activate
python analyzer.py "$@"