#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NYLON_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$NYLON_DIR/../NylonApp"

echo "Building NylonMobile.xcframework for iOS..."
cd "$NYLON_DIR"

# Ensure gomobile is installed
if ! command -v gomobile &>/dev/null; then
    echo "Installing gomobile..."
    go install golang.org/x/mobile/cmd/gomobile@latest
    go install golang.org/x/mobile/cmd/gobind@latest
    gomobile init
fi

# Build XCFramework
gomobile bind -v -target=ios \
    -o "$OUTPUT_DIR/NylonMobile.xcframework" \
    ./mobile

echo "Done: $OUTPUT_DIR/NylonMobile.xcframework"
