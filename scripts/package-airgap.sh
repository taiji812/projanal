#!/usr/bin/env bash
# ── Air-gap packaging script ────────────────────────────────────────────────
# Builds the base Docker image, exports it as a tar, and bundles all project
# files into a single archive ready for transfer to an air-gapped environment.
#
# Usage:
#   bash scripts/package-airgap.sh           # build image + create bundle
#   bash scripts/package-airgap.sh --no-build  # skip docker build (image must exist)
#
# Output:
#   dist/projanal-airgap-YYYYMMDD-GITHASH.tar.gz
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ── Derive version / tag ──────────────────────────────────────────────────────
APP_VERSION="$(grep '^version' "${PROJECT_ROOT}/pyproject.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')"
GIT_HASH="$(git -C "${PROJECT_ROOT}" rev-parse --short HEAD 2>/dev/null || echo "nogit")"
DATESTAMP="$(date +%Y%m%d)"

BUNDLE_NAME="projanal-airgap-${DATESTAMP}-${GIT_HASH}"
IMAGE_NAME="analysis-agent-base"
IMAGE_TAG="${APP_VERSION}-${GIT_HASH}"
IMAGE_FULL="${IMAGE_NAME}:${IMAGE_TAG}"

DIST_DIR="${PROJECT_ROOT}/dist"
WORK_DIR="${DIST_DIR}/${BUNDLE_NAME}"
IMAGES_DIR="${WORK_DIR}/images"
IMAGE_TAR="${IMAGES_DIR}/${IMAGE_NAME}-${IMAGE_TAG}.tar"
BUNDLE_ARCHIVE="${DIST_DIR}/${BUNDLE_NAME}.tar.gz"

# ── Parse args ────────────────────────────────────────────────────────────────
SKIP_BUILD=false
for arg in "$@"; do
  case "${arg}" in
    --no-build) SKIP_BUILD=true ;;
    *) echo "Unknown argument: ${arg}"; exit 1 ;;
  esac
done

echo "============================================================"
echo "  projanal air-gap packager"
echo "  App version : ${APP_VERSION}"
echo "  Git hash    : ${GIT_HASH}"
echo "  Image       : ${IMAGE_FULL}"
echo "  Output      : ${BUNDLE_ARCHIVE}"
echo "============================================================"

# ── Build base image ──────────────────────────────────────────────────────────
if [[ "${SKIP_BUILD}" == false ]]; then
  echo ""
  echo "==> Building base image: ${IMAGE_FULL}"
  docker build \
    -f "${PROJECT_ROOT}/docker/Dockerfile.base" \
    -t "${IMAGE_FULL}" \
    -t "${IMAGE_NAME}:latest" \
    "${PROJECT_ROOT}"
else
  echo ""
  echo "==> Skipping docker build (--no-build)"
fi

# Verify image exists before continuing
if ! docker image inspect "${IMAGE_FULL}" > /dev/null 2>&1; then
  echo "ERROR: Image '${IMAGE_FULL}' not found. Run without --no-build first."
  exit 1
fi

# ── Assemble bundle directory ─────────────────────────────────────────────────
echo ""
echo "==> Assembling bundle directory: ${WORK_DIR}"
rm -rf "${WORK_DIR}"
mkdir -p "${IMAGES_DIR}"

# Save Docker image
echo "    Exporting Docker image (may take a while)..."
docker save "${IMAGE_FULL}" -o "${IMAGE_TAR}"
echo "    Saved: $(du -sh "${IMAGE_TAR}" | cut -f1)  ${IMAGE_TAR##*/}"

# Project source, config, manifests
echo "    Copying project files..."
cp -r "${PROJECT_ROOT}/src"          "${WORK_DIR}/src"
cp -r "${PROJECT_ROOT}/config"       "${WORK_DIR}/config"
cp -r "${PROJECT_ROOT}/docker"       "${WORK_DIR}/docker"
cp    "${PROJECT_ROOT}/pyproject.toml" "${WORK_DIR}/"
cp    "${PROJECT_ROOT}/.env.example"   "${WORK_DIR}/"

# ── Generate README ───────────────────────────────────────────────────────────
cat > "${WORK_DIR}/README-airgap.md" << EOF
# projanal — Air-gap Deployment Package

| | |
|---|---|
| App version | ${APP_VERSION} |
| Git hash    | ${GIT_HASH} |
| Packaged    | ${DATESTAMP} |
| Base image  | \`${IMAGE_FULL}\` |

---

## 1. Load base image

\`\`\`bash
docker load -i images/${IMAGE_NAME}-${IMAGE_TAG}.tar

# Verify
docker image ls ${IMAGE_NAME}
\`\`\`

## 2. Configure environment

\`\`\`bash
cp .env.example .env
# Required settings:
#   OLLAMA_BASE_URL       — Ollama server (e.g. http://ollama-service:11434)
#   OLLAMA_MODEL          — model name pulled in Ollama
#   ANALYSIS_EMBED_MODEL  — Ollama embedding model (REQUIRED in air-gap;
#                           leaving it unset causes chromadb to attempt an
#                           internet download of all-MiniLM-L6-v2)
\`\`\`

## 3a. Dev / local test — volume mount (no image rebuild on code change)

\`\`\`bash
docker compose -f docker/docker-compose.dev.yml up api

# CLI single analysis:
docker compose -f docker/docker-compose.dev.yml run --rm cli \\
  /workspace --id my-project --output /out/my-project.json
\`\`\`

## 3b. Production — embed source into final image

\`\`\`bash
docker build \\
  -f docker/Dockerfile.prod \\
  --build-arg BASE_IMAGE=${IMAGE_FULL} \\
  -t analysis-agent:${APP_VERSION} \\
  .

# Then run with the standard compose file (edit image: line to match):
docker compose up
\`\`\`

## Notes

- UV venv inside the base image: \`/opt/venv\`
- The editable install in the base image registers \`/app/src\` as the package
  source. Volume-mounting \`./src:/app/src\` (dev) or COPYing src (prod) both
  work without reinstalling packages.
- Ollama LLM and embedding models must be pre-pulled on the Ollama server
  before running analysis.
EOF

# ── Create final archive ──────────────────────────────────────────────────────
echo ""
echo "==> Creating archive: ${BUNDLE_ARCHIVE}"
tar -czf "${BUNDLE_ARCHIVE}" -C "${DIST_DIR}" "${BUNDLE_NAME}"
rm -rf "${WORK_DIR}"

ARCHIVE_SIZE="$(du -sh "${BUNDLE_ARCHIVE}" | cut -f1)"
echo ""
echo "============================================================"
echo "  Done."
echo "  Archive : ${BUNDLE_ARCHIVE}"
echo "  Size    : ${ARCHIVE_SIZE}"
echo ""
echo "  Transfer this file to the air-gapped environment and"
echo "  follow the instructions in README-airgap.md."
echo "============================================================"
