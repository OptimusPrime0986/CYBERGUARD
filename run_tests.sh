#!/usr/bin/env bash
# Phase 1 integration tests (needs Docker). Unit tests for Phase 2: `pytest tests/unit` (no Docker).
set -euo pipefail
cd "$(dirname "$0")"
[ -f .env ] || cp .env.example .env
set -a; . ./.env; set +a
docker compose up -d --build
python3 -m venv .venv 2>/dev/null || true
. .venv/bin/activate
pip install -q -r tests/requirements.txt
mkdir -p results
pytest tests/test_phase1.py -v --junitxml=results/phase1-junit.xml | tee results/phase1-output.txt
