#!/usr/bin/env bash
set -euo pipefail

# Build script for deltator-netcore.aar (Android AAR with Go userspace netcore)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
NETCORE_DIR="${ROOT_DIR}/Android/netcore"
OUTPUT_DIR="${ROOT_DIR}/Android/app/libs"
OUTPUT_AAR="${OUTPUT_DIR}/deltator-netcore.aar"

echo "=== Building deltator-netcore ==="
echo "Netcore dir: ${NETCORE_DIR}"
echo "Output:      ${OUTPUT_AAR}"

mkdir -p "${OUTPUT_DIR}"

# Run unit tests first (fail-closed)
echo "Running Go netcore tests..."
(cd "${NETCORE_DIR}" && go test -v -timeout 60s ./...)

# Ensure gomobile is installed if available
if command -v gomobile &> /dev/null; then
    echo "Using gomobile to build ${OUTPUT_AAR}..."
    (cd "${NETCORE_DIR}" && gomobile bind -target=android/arm,android/arm64,android/amd64 -o "${OUTPUT_AAR}" .)
    echo "Successfully built ${OUTPUT_AAR}"
else
    echo "gomobile not found in PATH; compiling netcore Go package validation..."
    (cd "${NETCORE_DIR}" && go build -v ./...)
    echo "Netcore Go package validated successfully."
fi

echo "=== Build Complete ==="
