#!/usr/bin/env bash
# docker_build.sh — build (and optionally push) the Hiemdall Docker image.
#
# Single-project repo, so no project selector — this always targets hiemdall.
#
# Usage:
#   ./docker_build.sh                    # build locally (arm64 only, --load into docker)
#   ./docker_build.sh --push             # multi-arch build + push to registry
#   ./docker_build.sh --skip-bootjar     # reuse existing build/libs/*.jar
#   ./docker_build.sh --push --skip-bootjar
#
# Image: ${REGISTRY}/hiemdall:${VERSION}  (also tagged :latest)

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
REGISTRY="obake"
IMAGE_NAME="hiemdall"
PLATFORM_PUSH="linux/amd64,linux/arm64"   # multi-platform for registry (--push)
PLATFORM_LOCAL="linux/arm64"              # native platform for local --load

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { echo "[docker_build] $*"; }
err() { echo "[docker_build] ERROR: $*" >&2; }
die() { err "$*"; exit 1; }

# Read version from build.gradle:  version = '0.1.0-SNAPSHOT'
# Anchored at start-of-line so a `version` reference inside a closure can't shadow.
get_version() {
    grep -m1 -E "^[[:space:]]*version[[:space:]]*=" build.gradle \
        | sed -E "s/.*version[[:space:]]*=[[:space:]]*['\"]([^'\"]+)['\"].*/\1/"
}

run_bootjar() {
    log "Running ./gradlew bootJar"
    ./gradlew --no-daemon bootJar
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
PUSH="false"
SKIP_BOOTJAR="false"

for arg in "$@"; do
    case "$arg" in
        --push)         PUSH="true" ;;
        --skip-bootjar) SKIP_BOOTJAR="true" ;;
        -h|--help)
            sed -n '2,13p' "$0"
            exit 0
            ;;
        *)              die "Unknown argument: $arg" ;;
    esac
done

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

[[ -f Dockerfile ]]    || die "No Dockerfile at $SCRIPT_DIR/Dockerfile"
[[ -f build.gradle ]]  || die "No build.gradle at $SCRIPT_DIR (expected a Gradle project root)"

VERSION=$(get_version)
[[ -n "$VERSION" ]] || die "Could not read version from build.gradle"

if [[ "$SKIP_BOOTJAR" != "true" ]]; then
    run_bootjar
else
    log "Skipping bootJar (--skip-bootjar)"
fi

JAR="build/libs/${IMAGE_NAME}-${VERSION}.jar"
[[ -f "$JAR" ]] || die "Expected fat JAR not found at $JAR"

FULL_TAG="${REGISTRY}/${IMAGE_NAME}:${VERSION}"
LATEST_TAG="${REGISTRY}/${IMAGE_NAME}:latest"

if [[ "$PUSH" == "true" ]]; then
    log "Building and pushing  →  $FULL_TAG  ($PLATFORM_PUSH)"
    docker buildx build \
        --platform "$PLATFORM_PUSH" \
        -f Dockerfile \
        -t "$FULL_TAG" \
        -t "$LATEST_TAG" \
        --push \
        .
    log "Pushed    $FULL_TAG  and  $LATEST_TAG"
else
    log "Building  →  $FULL_TAG  ($PLATFORM_LOCAL, local only)"
    docker buildx build \
        --platform "$PLATFORM_LOCAL" \
        -f Dockerfile \
        -t "$FULL_TAG" \
        -t "$LATEST_TAG" \
        --load \
        .
    log "Built     $FULL_TAG  (not pushed)"
fi

log "Done"
