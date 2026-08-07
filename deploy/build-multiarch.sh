#!/usr/bin/env bash
# build-multiarch.sh — build AI-Monitoring for amd64 / arm64 / arm/v7 and scan
# each with Trivy. The image is pure-python, so ONE Dockerfile (Alpine base)
# serves all arches.
#
#   arm64/amd64 : native/fast, run the full pytest gate (RUN_TESTS=1, default).
#   arm/v7      : emulated (QEMU) — skip the slow emulated suite (RUN_TESTS=0);
#                 the tests already ran on the native arch.
#
# One-time: register QEMU emulation for armv7:
#   docker run --privileged --rm tonistiigi/binfmt --install arm
#
# Behind a proxy, export http_proxy/https_proxy and they are forwarded as
# build-args (the default builder uses the host daemon, which can pull/pull).
set -euo pipefail

# Single source of truth for the version = the string baked into the code (config.VERSION). The
# old hardcoded default (1.0.6) let the tag drift from the code; and reusing one VERSION across
# code states is exactly how a stale image shipped to prod (T-19). A caller may still override
# VERSION, but if it disagrees with config.py we FAIL rather than mislabel the image.
_CODE_VER="$(python3 -c 'import config; print(config.VERSION.split("_")[-1])')"
VERSION="${VERSION:-$_CODE_VER}"
if [ "$VERSION" != "$_CODE_VER" ]; then
  echo "ERROR: VERSION=$VERSION disagrees with config.VERSION=$_CODE_VER — refusing to mislabel" >&2
  exit 1
fi
# Stamp the source commit into every image so the running container is verifiable (see /healthz).
GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
IMAGE="${IMAGE:-ai-monitoring}"
# Trivy's DB download defaults to staging in $TMPDIR (/tmp), which on this host is a
# small tmpfs (~4G) that's often already near-full — the download then dies with a
# misleading "no space left on device" that looks like a scan failure, not a disk
# issue. Redirect both the temp staging area and the on-disk vuln-db cache to the
# project filesystem instead, which has real headroom. Override with TRIVY_TMPDIR=
# if this host's /tmp is fine.
TRIVY_TMPDIR="${TRIVY_TMPDIR:-$(pwd)/.trivy-tmp}"
TRIVY_CACHE="${TRIVY_CACHE:-$(pwd)/.trivy-cache}"
mkdir -p "$TRIVY_TMPDIR" "$TRIVY_CACHE"
PROXY_ARGS=()
[ -n "${http_proxy:-}" ] && PROXY_ARGS+=(--build-arg "http_proxy=$http_proxy"
  --build-arg "https_proxy=${https_proxy:-$http_proxy}"
  --build-arg "HTTP_PROXY=$http_proxy" --build-arg "HTTPS_PROXY=${https_proxy:-$http_proxy}")

build() {   # <platform> <tag-suffix> <run_tests>
  echo "── build $1 (RUN_TESTS=$3) ──"
  DOCKER_BUILDKIT=1 docker build --platform "$1" --target runtime \
    --build-arg "RUN_TESTS=$3" --build-arg "GIT_SHA=$GIT_SHA" "${PROXY_ARGS[@]}" \
    -t "${IMAGE}:${VERSION}-$2" .
}

scan() {    # <tag-suffix>
  echo "── trivy ${IMAGE}:${VERSION}-$1 ──"
  TMPDIR="$TRIVY_TMPDIR" trivy image --scanners vuln --severity HIGH,CRITICAL --no-progress \
    --cache-dir "$TRIVY_CACHE" "${IMAGE}:${VERSION}-$1"
}

# rules.md §14: an offline-loadable image.tar.gz per arch is a MANDATORY build
# artifact (the monitor often runs where the registry isn't reachable). Set
# SAVE_TARBALLS=0 to skip; DIST overrides the output dir (default: dist/).
DIST="${DIST:-dist}"
save() {    # <tag-suffix>  → $DIST/aimon-<arch>.tar.gz
  echo "── save ${IMAGE}:${VERSION}-$1 → ${DIST}/aimon-$1.tar.gz ──"
  docker save "${IMAGE}:${VERSION}-$1" | gzip > "${DIST}/aimon-$1.tar.gz"
}

# Ensure QEMU binfmt is registered for the emulated arches. On an arm64 host, amd64 + arm/v7
# are emulated; the binfmt handlers RESET ON REBOOT, and a missing arm handler makes the armv7
# build die with a bare `exit code: 255` on the first RUN (QEMU can't exec /bin/sh). Register
# idempotently so the build self-heals instead of failing cryptically. Skippable with BINFMT=0.
if [ "${BINFMT:-1}" = "1" ] && ! ls /proc/sys/fs/binfmt_misc/ 2>/dev/null | grep -q qemu-arm; then
  echo "── registering QEMU binfmt (qemu-arm missing) ──"
  docker run --privileged --rm tonistiigi/binfmt --install arm,amd64 >/dev/null 2>&1 \
    || echo "  ! binfmt register failed — emulated (armv7/amd64) builds may fail with exit 255"
fi

build linux/arm64   arm64 1     # native gate
build linux/amd64   amd64 1     # emulated but fast enough; keep gate
build linux/arm/v7  armv7 0     # emulated — skip slow suite

for a in arm64 amd64 armv7; do scan "$a"; done

if [ "${SAVE_TARBALLS:-1}" = "1" ]; then
  mkdir -p "${DIST}"
  for a in arm64 amd64 armv7; do save "$a"; done
fi

echo
echo "Built: ${IMAGE}:${VERSION}-{arm64,amd64,armv7}"
if [ "${SAVE_TARBALLS:-1}" = "1" ]; then
  echo "Tarballs (§14 — offline install with 'docker load < <file>'):"
  ls -lh "${DIST}"/aimon-*.tar.gz | awk '{print "  "$5"  "$NF}'
fi
echo "To publish a multi-arch manifest to a registry, use:"
echo "  docker buildx imagetools create -t <registry>/${IMAGE}:${VERSION} \\"
echo "    <registry>/${IMAGE}:${VERSION}-arm64 ... -amd64 ... -armv7"
