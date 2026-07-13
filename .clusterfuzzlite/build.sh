#!/bin/bash -eu
# Compile each fuzz/fuzz_*.py harness into a ClusterFuzzLite fuzzer. The parsers
# import aiohttp etc., so install the app's runtime deps first.
pip3 install --no-cache-dir -r "$SRC/ai-monitoring/requirements.txt"

for harness in "$SRC"/ai-monitoring/fuzz/fuzz_*.py; do
  compile_python_fuzzer "$harness"
done
