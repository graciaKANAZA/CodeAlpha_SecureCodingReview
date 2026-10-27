#!/usr/bin/env bash
# Reproduit l'analyse statique de la revue de code (cible : Vulpy, dossier bad/)
set -e
[ -d vulpy ] || git clone --depth 1 https://github.com/fportantier/vulpy.git
python3 -m venv .venv && . .venv/bin/activate
pip install -q bandit semgrep
mkdir -p reports
bandit -r vulpy/bad -x vulpy/bad/payloads,vulpy/bad/static -f txt  -o reports/bandit_vulpy_bad.txt  || true
bandit -r vulpy/bad -x vulpy/bad/payloads,vulpy/bad/static -f html -o reports/bandit_vulpy_bad.html || true
semgrep --config auto vulpy/bad --text -o reports/semgrep_vulpy_bad.txt || true
echo "Rapports écrits dans reports/"
