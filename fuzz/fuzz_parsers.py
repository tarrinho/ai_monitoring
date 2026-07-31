#!/usr/bin/env python3
"""Atheris fuzz harness for AI-Monitoring's untrusted-input parsers.

These collector parsers turn backend output (nvidia-smi CSV, LiteLLM /spend/logs
bytes, timestamps, numeric fields) into structured data and are contractually
*total* — they must never raise on malformed input, only degrade to defaults. Any
uncaught exception the fuzzer reaches is therefore a real defect, not expected.

Run locally:  pip install atheris && python fuzz/fuzz_parsers.py -runs=100000
Built for ClusterFuzzLite via .clusterfuzzlite/ (compile_python_fuzzer).
"""
import os
import sys

# Put the repo root on sys.path so `from collectors import ...` resolves whether this harness
# is run directly (`python fuzz/fuzz_parsers.py` — the script's own dir, not the repo root, is
# sys.path[0]) or built by ClusterFuzzLite's compile_python_fuzzer. Belt-and-suspenders with the
# PYTHONPATH export in .clusterfuzzlite/build.sh (which is what lets PyInstaller BUNDLE them).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import atheris

with atheris.instrument_imports():
    from collectors import containers, gpu, litellm


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(256)

    gpu._parse_nvidia_csv(text)      # nvidia-smi CSV → per-GPU rows
    gpu._fnum(text)                  # numeric coercion (never raises)
    litellm._fnum(text)
    litellm._parse_ts(text)          # timestamp coercion
    containers._parse_started(text)  # container start-time string

    # the /spend/logs byte parser — the historical CPU-freeze path
    litellm._parse_spend_bytes(fdp.ConsumeBytes(512), 0.0, 256)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
