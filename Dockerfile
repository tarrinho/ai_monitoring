# AI-Monitoring — multi-stage, multi-arch build (amd64 / arm64 / arm/v7).
#
# Base is python:3.12-alpine — Debian slim carried ~11 HIGH/CRITICAL OS CVEs
# (perl/ncurses/libacl, many Debian "fix_deferred"); Alpine ships 0.
#
# The `test` stage runs the FULL QA suite; the runtime stage depends on its
# marker, so a regression fails `docker build`. For emulated cross-arch builds
# (armv7 under QEMU) pass --build-arg RUN_TESTS=0 to skip the slow emulated
# suite — the tests already ran on the native arch.
FROM python:3.14-alpine AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MONITOR_DB_PATH=/data/ai-monitoring.db

WORKDIR /app

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
# pytest + pytest-asyncio are pure-python wheels — no build deps needed here.
COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt
COPY . .
# On success drop a marker the runtime stage depends on. RUN_TESTS=0 skips the
# (emulated) suite for cross-arch builds but still produces the marker.
RUN if [ "$RUN_TESTS" = "1" ]; then \
        MONITOR_DB_PATH=/tmp/build-test.db python -m pytest tests/ -q; \
    fi && touch /qa-passed


# --- runtime stage: lean image, gated on the test stage passing --------------
FROM base AS runtime

# app files only (no tests, no dev deps)
COPY config.py db.py auth.py app.py alerts.py anomaly.py metrics_prom.py ./
COPY collectors/ ./collectors/
COPY web/ ./web/

# Forces BuildKit to build the `test` stage — if pytest failed, /qa-passed does
# not exist and the whole build fails here.
COPY --from=test /qa-passed /qa-passed

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
