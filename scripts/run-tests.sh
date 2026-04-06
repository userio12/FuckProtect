#!/bin/bash
# FuckProtect Test Runner
#
# Runs all unit tests and instrumented tests.
# Usage: ./run-tests.sh [unit|android|all]

set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== FuckProtect Test Runner ==="
echo ""

run_unit_tests() {
    echo "── Unit Tests ──────────────────────────────────────────"
    echo ""

    echo "Running common module tests..."
    ./gradlew :common:test --info

    echo ""
    echo "Running protector module tests..."
    ./gradlew :protector:test --info

    echo ""
    echo "── Unit Tests Complete ─────────────────────────────────"
}

run_android_tests() {
    echo "── Android Instrumented Tests ─────────────────────────"
    echo ""
    echo "Note: Requires connected Android device or emulator."
    echo ""

    ./gradlew :shell:connectedAndroidTest --info

    echo ""
    echo "── Android Instrumented Tests Complete ────────────────"
}

case "${1:-all}" in
    unit)
        run_unit_tests
        ;;
    android)
        run_android_tests
        ;;
    all)
        run_unit_tests
        run_android_tests
        ;;
    *)
        echo "Usage: $0 [unit|android|all]"
        exit 1
        ;;
esac

echo ""
echo "=== All Tests Complete ==="
