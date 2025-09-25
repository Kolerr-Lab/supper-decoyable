#!/bin/bash
# DECOYABLE One-Command Installer
# Run this to get DECOYABLE up and running instantly!

set -e

echo "🚀 DECOYABLE One-Command Installer"
echo "=================================="

# Check if Python 3.11+ is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required. Please install Python 3.11 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
REQUIRED_VERSION="3.11"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "❌ Python $PYTHON_VERSION detected. DECOYABLE requires Python $REQUIRED_VERSION or higher."
    exit 1
fi

echo "✅ Python $PYTHON_VERSION detected"

# Install DECOYABLE
echo "📦 Installing DECOYABLE..."
pip3 install --user decoyable

if [ $? -eq 0 ]; then
    echo "✅ DECOYABLE installed successfully!"
    echo ""
    echo "🎯 Quick Test:"
    echo "  decoyable scan ."
    echo ""
    echo "📖 Demo:"
    echo "  python3 demo.py"
    echo ""
    echo "🔗 Documentation: https://github.com/Kolerr-Lab/supper-decoyable"
else
    echo "❌ Installation failed. Please check your Python/pip setup."
    exit 1
fi