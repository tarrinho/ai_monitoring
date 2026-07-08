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

VERSION="${VERSION:-1.0.6}"
IMAGE="${IMAGE:-ai-monitoring}"
PROXY_ARGS=()
[ -n "${http_proxy:-}" ] && PROXY_ARGS+=(--build-arg "http_proxy=$http_proxy"
  --build-arg "https_proxy=${https_proxy:-$http_proxy}"
  --build-arg "HTTP_PROXY=$http_proxy" --build-arg "HTTPS_PROXY=${https_proxy:-$http_proxy}")

build() {   # <platform> <tag-suffix> <run_tests>
  echo "── build $1 (RUN_TESTS=$3) ──"
  DOCKER_BUILDKIT=1 docker build --platform "$1" --target runtime \
    --build-arg "RUN_TESTS=$3" "${PROXY_ARGS[@]}" \
    -t "${IMAGE}:${VERSION}-$2" .
}

scan() {    # <tag-suffix>
  echo "── trivy ${IMAGE}:${VERSION}-$1 ──"
  trivy image --scanners vuln --severity HIGH,CRITICAL --no-progress \
    "${IMAGE}:${VERSION}-$1"
}

# rules.md §14: an offline-loadable image.tar.gz per arch is a MANDATORY build
# artifact (the monitor often runs where the registry isn't reachable). Set
# SAVE_TARBALLS=0 to skip; DIST overrides the output dir (default: dist/).
DIST="${DIST:-dist}"
save() {    # <tag-suffix>  → $DIST/aimon-<arch>.tar.gz
  echo "── save ${IMAGE}:${VERSION}-$1 → ${DIST}/aimon-$1.tar.gz ──"
  docker save "${IMAGE}:${VERSION}-$1" | gzip > "${DIST}/aimon-$1.tar.gz"
}

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
