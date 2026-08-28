# AI-Monitoring — multi-stage, multi-arch build (amd64 / arm64 / arm/v7).
#
# Base is python:3.14-alpine — Debian slim carried ~11 HIGH/CRITICAL OS CVEs
# (perl/ncurses/libacl, many Debian "fix_deferred"); Alpine ships 0.
#
# The `test` stage runs the FULL QA suite; the runtime stage depends on its
# marker, so a regression fails `docker build`. For emulated cross-arch builds
# (armv7 under QEMU) pass --build-arg RUN_TESTS=0 to skip the slow emulated
# suite — the tests already ran on the native arch.
# Base image pinned by multi-arch manifest digest (OpenSSF Scorecard
# Pinned-Dependencies). The tag is kept in the comment for readability; Dependabot
# (docker ecosystem) bumps the digest. Re-pin with:
#   docker buildx imagetools inspect python:3.14-alpine   # top-level Digest
FROM python:3.14-alpine@sha256:26730869004e2b9c4b9ad09cab8625e81d256d1ce97e72df5520e806b1709f92 AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MONITOR_DB_PATH=/data/ai-monitoring.db

WORKDIR /app

# Patch openssl to the fixed build without unpinning the base digest (§9a keeps the
# base pinned by @sha256; the pinned base lags fresh Alpine security bumps). Pulls the
# CVE-2026-14456 fix (libcrypto3/libssl3 >= 3.5.8-r0) so the Trivy §10 gate stays green
# between Dependabot base-digest bumps.
RUN apk upgrade --no-cache libcrypto3 libssl3

# openssh-client: agentless remote-GPU mode runs nvidia-smi over SSH.
RUN apk add --no-cache openssh-client

# upgrade pip first — clears the pip CVEs Trivy flags in the shipped image.
RUN pip install --no-cache-dir --upgrade pip

# build deps are installed only to compile any wheels (aiohttp on musl/armv7),
# then removed so they never reach the final image.
COPY requirements.txt .
RUN apk add --no-cache --virtual .build-deps gcc musl-dev libffi-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-deps


# --- test stage: run the QA suite; build aborts here on any failure ----------
FROM base AS test
ARG RUN_TESTS=1
# BuildKit injects these automatically. When they differ the build is EMULATED (QEMU),
# where launching chromium is slow/fragile — so chromium is installed (and the headless
# smoke runs) ONLY on a native build; emulated builds leave it absent and the smoke
# self-skips (`skipif(not CHROME)`). The native arch already gates the browser coverage.
ARG BUILDPLATFORM
ARG TARGETPLATFORM
COPY requirements-dev.txt .
COPY . .
# Dev deps are installed AND the suite runs only when RUN_TESTS=1 (native builds).
# RUN_TESTS=0 (emulated cross-arch: armv7/amd64 under QEMU) skips both — the suite
# already gated on the native arch, and some dev deps have no musl wheel for
# arm/v7, so a source build would need a Rust toolchain that isn't there. The
# /qa-passed marker is still produced so the runtime stage can depend on it.
#
# chromium (+ swiftshader software-GL + fonts) is installed ONLY in this test stage,
# ONLY on RUN_TESTS=1, and ONLY on a NATIVE build (BUILDPLATFORM==TARGETPLATFORM), so
# tests/test_headless_smoke.py loads each real dashboard in a real browser (catching
# runtime JS bugs the static gate can't — e.g. the Chart.js legend-hang). It never reaches
# the lean runtime stage. On an emulated build chromium is left absent and the smoke
# self-skips — running it under QEMU is slow/fragile and the native arch already covered it.
RUN if [ "$RUN_TESTS" = "1" ]; then \
        if [ "$BUILDPLATFORM" = "$TARGETPLATFORM" ]; then \
            apk add --no-cache chromium chromium-swiftshader nss freetype harfbuzz ttf-freefont; \
        fi \
        && pip install --no-cache-dir -r requirements-dev.txt \
        && MONITOR_DB_PATH=/tmp/build-test.db python -m pytest tests/ -q; \
    fi && touch /qa-passed


# --- runtime stage: lean image, gated on the test stage passing --------------
FROM base AS runtime

# Build provenance (T-19): stamp the source commit into the image so the running container is
# verifiable. Passed by deploy/build-multiarch.sh as `--build-arg GIT_SHA=$(git rev-parse --short)`.
ARG GIT_SHA=unknown
LABEL org.opencontainers.image.revision=$GIT_SHA \
      org.opencontainers.image.version=$GIT_SHA
ENV BUILD_SHA=$GIT_SHA

# app files only (no tests, no dev deps)
COPY config.py db.py dbutil.py auth.py app.py alerts.py anomaly.py metrics_prom.py obslog.py ./
COPY collectors/ ./collectors/
COPY web/ ./web/

# Forces BuildKit to build the `test` stage — if pytest failed, /qa-passed does
# not exist and the whole build fails here.
COPY --from=test /qa-passed /qa-passed

# Strip pip from the RUNTIME image: the app runs `python app.py` and NEVER installs packages, so
# pip — and its VENDORED deps that image scanners flag but which are only reachable when pip
# itself runs (pip 26.2's _vendor pins setuptools 70.3.0 → CVE-2025-47273 and msgpack 1.1.2 →
# GHSA-6v7p-g79w-8964) — has no runtime purpose. Removing it clears those non-exploitable findings
# and shrinks the attack surface. The base + test stages keep pip (they need it to install deps).
RUN rm -rf /usr/local/lib/python*/site-packages/pip \
           /usr/local/lib/python*/site-packages/pip-*.dist-info \
           /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.* 2>/dev/null || true

# non-root (BusyBox adduser: -D no password, -H no home — /app already exists)
RUN adduser -D -H -u 10001 monitor \
    && mkdir -p /data && chown -R monitor:monitor /app /data
USER monitor

VOLUME ["/data"]
EXPOSE 9925

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request,os,sys; \
    p=os.environ.get('MONITOR_PORT','9925'); \
    sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{p}/healthz',timeout=4).status==200 else 1)"

CMD ["python", "app.py"]
