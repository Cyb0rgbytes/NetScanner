#!/bin/bash
# NetScanner 2.0 Quick Setup Script
# Author: Cyb0rgBytes

echo "🔧 Setting up NetScanner 2.0..."

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed!"
    echo "📥 Download from: https://python.org"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "✅ Python $PYTHON_VERSION detected"

# Create virtual environment (optional but recommended)
echo "📁 Creating virtual environment..."
python3 -m venv venv 2>/dev/null || echo "⚠ Virtual environment creation skipped"

# Activate virtual environment
if [ -d "venv" ]; then
    echo "🚀 Activating virtual environment..."
    source venv/bin/activate
fi

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "📦 Installing dependencies..."
pip install scapy rich colorama pyfiglet

# Optional: Install additional features
read -p "🤔 Install optional features? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "📊 Installing additional packages..."
    pip install pandas openpyxl tabulate psutil netifaces
fi

# Verify installation
echo "✅ Verifying installation..."
python3 -c "import scapy, rich, colorama, pyfiglet; print('🎉 All packages installed successfully!')"

echo ""
echo "🚀 NetScanner 2.0 is ready!"
echo "💻 Run with: sudo python3 NetScannerV2.py --target 192.168.1.0/24"
echo "📖 See README.md for more usage examples"
