#!/bin/bash -eu
# Compile each fuzz/fuzz_*.py harness into a ClusterFuzzLite fuzzer. The parsers
# import aiohttp etc., so install the app's runtime deps first.
pip3 install --no-cache-dir -r "$SRC/ai-monitoring/requirements.txt"

# The harnesses import repo-root packages (e.g. `from collectors import ...`). PyInstaller
# (run by compile_python_fuzzer) only searches the harness's own dir by default, so those
# packages are never bundled and the frozen fuzzer dies at startup with
# `ModuleNotFoundError: No module named 'collectors'` (→ 100% broken targets). Put the repo
# root on PyInstaller's module search path (via PYTHONPATH) so they get bundled.
export PYTHONPATH="$SRC/ai-monitoring${PYTHONPATH:+:$PYTHONPATH}"

for harness in "$SRC"/ai-monitoring/fuzz/fuzz_*.py; do
  compile_python_fuzzer "$harness"
done
