#!/bin/bash
set -e

echo "Building Backend..."
cd "$(dirname "$0")"

# Create entry point shim
echo "from pcap_analyzer.cli import main; import sys; sys.exit(main())" > entry.py

# Build using PyInstaller
export PYTHONPATH=$PYTHONPATH:$(pwd)/src
uv run pyinstaller --noconfirm --onefile --name pcap-server --clean --paths src entry.py

# Cleanup
rm entry.py
echo "Backend build complete: dist/pcap-server"
