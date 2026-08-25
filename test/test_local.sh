#!/usr/bin/env bash
set -euo pipefail

echo "=== packetkit test suite ==="

cd "$(dirname "$0")/.."

echo ""
echo "--- Building ---"
make clean 2>/dev/null || true
make all 2>&1

echo ""
echo "--- Checking binaries exist ---"
for bin in syn-scanner connect-scanner sniffer arp-spoof; do
    if [ -x "$bin" ]; then
        echo "  OK: $bin found"
    else
        echo "  FAIL: $bin missing"
        exit 1
    fi
done

echo ""
echo "--- Connect scan localhost ports 1-100 (no root) ---"
./connect-scanner connect-scan 127.0.0.1 1-100 2>&1 || true

echo ""
echo "--- Help output ---"
echo "  Testing syn-scanner help..."
./syn-scanner 2>&1 && true
echo "  Testing connect-scanner help..."
./connect-scanner 2>&1 && true
echo "  Testing sniffer help..."
./sniffer 2>&1 && true
echo "  Testing arp-spoof help..."
./arp-spoof 2>&1 && true

echo ""
echo "=== All tests completed ==="
