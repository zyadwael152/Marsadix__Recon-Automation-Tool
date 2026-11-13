#!/usr/bin/env bash
# Run from the repo root on branch kerolos. Moves the flat Person-4 files into the packages that
# their relative imports expect (marsadix/matching, marsadix/alerts, marsadix/monitor, ...).
set -euo pipefail
mkdir -p marsadix/matching marsadix/alerts marsadix/monitor marsadix/reports tests/p4
# --- M7-M9: matching engine  ->  marsadix/matching/
for f in cpe version models matcher confidence priority adapter; do git mv "$f.py" marsadix/matching/; done
# --- M11-M14, M18: alert delivery  ->  marsadix/alerts/   (root __init__.py is the alerts package docstring)
for f in base dedup discord telegram email webhook dispatch settings http; do git mv "$f.py" marsadix/alerts/; done
git mv __init__.py marsadix/alerts/__init__.py
touch marsadix/matching/__init__.py
# --- shared Person-4 modules imported as marsadix.<name>
for f in dbutil db_v4 p4data risk attack_surface patterns remediation_db p4_cli; do git mv "$f.py" marsadix/; done
git mv matching_run.py marsadix/monitor/
git mv p4_sections.py marsadix/reports/
# --- tests: own folder so the scaffold conftest does not collide with tests/conftest.py
git mv conftest.py tests/p4/conftest.py
git mv fakes.py tests/p4/fakes.py
for f in test_*.py; do git mv "$f" tests/p4/; done
touch tests/p4/__init__.py
git add -A
echo "done. now: git apply <patch files>"
