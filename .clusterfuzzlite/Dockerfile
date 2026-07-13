# ClusterFuzzLite / OSS-Fuzz build environment (Python base image ships Atheris +
# compile_python_fuzzer). Builds the fuzz harnesses in fuzz/ against the app's
# real parser code. See .github/workflows/cflite-pr.yml.
FROM gcr.io/oss-fuzz-base/base-builder-python

COPY . $SRC/ai-monitoring
WORKDIR $SRC/ai-monitoring
COPY .clusterfuzzlite/build.sh $SRC/build.sh
