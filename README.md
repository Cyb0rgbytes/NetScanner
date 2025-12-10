🔬 NetScanner 2.0 - The Ultimate Network Discovery Tool
<p align="center"> <img src="https://img.shields.io/badge/Version-2.0-brightgreen" alt="Version"> <img src="https://img.shields.io/badge/Python-3.7+-blue" alt="Python"> <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License"> <img src="https://img.shields.io/badge/Author-Cyb0rgBytes-purple" alt="Author"> </p><p align="center"> ⚡ <strong>Revolutionizing network discovery with style, speed, and precision!</strong> ⚡ </p>
🎬 What's New in V2.0?
🌟 Visual & UI Enhancements
python

# V1.0: Basic text output
print("IP\t\tMAC Address")
# -------------------------------------------------
# V2.0: Rich, animated interface
🎨 Animated ASCII Banner
📊 Live Progress Bars
🎯 Interactive Tables
🌐 Network Topology Visualization

Feature	V1.0	V2.0
Interface	Plain text	🎭 Rich Terminal UI
Progress	None	🌀 Animated progress bars
Display	Simple table	📋 Interactive tables with colors
Visualization	None	🗺️ Network topology maps
🔧 Technical Improvements
<table> <tr> <td width="50%">
🚀 Performance

    Optimized scanning algorithms

    Configurable timeouts (1-10s)

    Retry mechanisms (1-5 attempts)

    Multi-threaded operations

🎯 Accuracy

    Enhanced ARP packet crafting

    MAC vendor database (1000+ vendors)

    Multiple discovery methods (ARP/ICMP)

    Better error handling

</td> <td width="50%">
📦 Features

    Multiple export formats (JSON, CSV, XML, TXT)

    Port scanning capabilities

    Interface selection

    Verbose debugging mode

    Cross-platform compatibility

🛡️ Reliability

    Permission validation

    Network interface detection

    Graceful error recovery

    Comprehensive logging

</td> </tr> </table>
✨ New Capabilities
yaml

📊 Analytics:
  - Device statistics
  - Vendor distribution
  - Scan timing metrics
  - Network health insights

💾 Export Options:
  - JSON (for APIs/automation)
  - CSV (for spreadsheets)
  - XML (for enterprise tools)
  - TXT (for reports)

🔍 Discovery Methods:
  - ARP scanning (primary)
  - ICMP ping sweep
  - Hybrid approach
  - Custom port scanning

🚀 How to Get Started
🎯 Prerequisites
bash

# Check if you have Python 3.7+
🐍 python3 --version

# Check for pip
📦 pip --version

⚡ One-Line Installation
bash

# Clone & install everything automatically!
✨ curl -sSL https://raw.githubusercontent.com/Cyb0rgBytes/NetScanner/master/install.sh | bash

🔧 Manual Setup (Step-by-Step)
Step 1: Get the Code
bash

# Option A: Clone the repository
📁 git clone https://github.com/Cyb0rgBytes/NetScanner.git
📂 cd NetScanner

# Option B: Download directly
⬇️ wget https://github.com/Cyb0rgBytes/NetScanner/raw/main/NetScannerV2.py

Step 2: Install Dependencies
bash

# Install with pip (recommended)
💻 pip install -r requirements.txt

# Or install individually:
🌟 pip install rich          # Beautiful terminal UI
🎨 pip install pyfiglet      # ASCII art banners
🌈 pip install colorama      # Cross-platform colors
📡 pip install scapy         # Network packet manipulation

Step 3: Make it Executable
bash

# On Linux/Mac
🔧 chmod +x NetScannerV2.py

# On Windows (PowerShell as Admin)
⚙️ Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

Step 4: Verify Installation
bash

# Run a quick test
✅ python3 NetScannerV2.py --help

# You should see the glorious banner!
✨  ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
     ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
     ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
     ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
     ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
     ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝

🎮 Usage Examples
Basic Scan
bash

# Scan your local network
🖥️  sudo python3 NetScannerV2.py --target 192.168.1.0/24

# Output:
🎯 Found 12 devices
📊 Displaying interactive table...
🌐 Generating network map...

Advanced Scans
bash

# With vendor lookup and export
📋 sudo python3 NetScannerV2.py --target 192.168.1.0/24 --vendor --export json

# With custom ports
🔌 sudo python3 NetScannerV2.py --target 192.168.1.0/24 --ports 22,80,443,8080

# Verbose mode for debugging
🐛 sudo python3 NetScannerV2.py --target 10.0.0.0/24 --verbose

# Quick scan with timeout
⏱️  sudo python3 NetScannerV2.py --target 192.168.1.1-50 --timeout 2 --retry 3

Full Command Reference
bash

📖 NetScannerV2.py --help

Usage: NetScannerV2.py [OPTIONS]

🎯 Essential:
  -t, --target    Target IP range (e.g., 192.168.1.0/24) [REQUIRED]

⚙️  Options:
  -i, --interface    Network interface (auto-detected)
  -p, --ports        Ports to scan (22,80,443 or 1-1000)
  -to, --timeout     Timeout in seconds (default: 1)
  -r, --retry        Number of retries (default: 1)
  -v, --verbose      Enable verbose output

💾 Export:
  -e, --export    Format: json, csv, xml, txt
  -o, --output    Output filename

🔍 Discovery:
  --discovery     Method: arp, icmp, both
  --vendor        Enable MAC vendor lookup

📊 Sample Output
Interactive Table View
text

╔══════════════════════════════════════════════════════════╗
║            Network Discovery Results (8 devices)         ║
╠══════════════════════════════════════════════════════════╣
║ #  IP Address       MAC Address       Vendor        Status║
╠══════════════════════════════════════════════════════════╣
║ 1  192.168.1.1      00:1A:2B:3C:4D:5E  Cisco         🟢   ║
║ 2  192.168.1.10     08:00:27:AB:CD:EF  VirtualBox    🟢   ║
║ 3  192.168.1.15     B8:27:EB:12:34:56  Raspberry Pi  🟢   ║
║ 4  192.168.1.20     F4:F5:D8:78:9A:BC  Google        🟢   ║
╚══════════════════════════════════════════════════════════╝

Network Topology Map
text

🌐 Network Topology:
┌─────────────────────────────────────────────┐
│            Local Network Map                │
├─────────────────────────────────────────────┤
│ 📱 192.168.1.15 → Raspberry Pi              │
│ 💻 192.168.1.20 → Google                    │
│ 🖥️  192.168.1.1  → Cisco                    │
│ 🔗 192.168.1.10 → VirtualBox                │
└─────────────────────────────────────────────┘

🏗️ Architecture

<img width="6475" height="917" alt="deepseek_mermaid_20251210_47c84f" src="https://github.com/user-attachments/assets/5f742905-34f8-411b-91b4-538b7ee54350" />

🛠️ Troubleshooting
Common Issues & Solutions
Symptom	🩹 Solution
"Permission denied"	Run with sudo or administrator privileges
"Module not found"	Install missing packages: pip install -r requirements.txt
"No devices found"	Check network interface: --interface eth0
"Scan too slow"	Adjust timeout: --timeout 2
"Incomplete results"	Increase retries: --retry 3
Debug Mode
bash

# Enable verbose logging
🐛 sudo python3 NetScannerV2.py --target 192.168.1.0/24 --verbose

# Check network interfaces
📡 ip a  # Linux
🔧 ifconfig  # macOS
🖥️  ipconfig  # Windows

🤝 Contributing

We 💖 contributions! Here's how you can help:
bash

# 1. Fork the repository
🍴 Click "Fork" on GitHub

# 2. Create a feature branch
🌿 git checkout -b feature/AmazingFeature

# 3. Commit your changes
💾 git commit -m "Add AmazingFeature"

# 4. Push to the branch
🚀 git push origin feature/AmazingFeature

# 5. Open a Pull Request
🎉 Create PR on GitHub

Areas for Contribution

    🔍 Add more MAC vendor entries

    🌐 Support for IPv6

    📊 Additional export formats

    🎨 More visualization options

    🔧 Performance optimizations

📜 License
text

MIT License

Copyright (c) 2024 Cyb0rgBytes

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

✨ Pro Tips
bash

# Quick aliases for your shell
🚀 echo "alias netscan='sudo python3 /path/to/NetScannerV2.py'" >> ~/.bashrc

# Schedule regular network audits
⏰ crontab -e
# Add: 0 2 * * * /usr/bin/python3 /path/to/NetScannerV2.py --target 192.168.1.0/24 --export csv

# Combine with other tools
🔗 netscan --target 192.168.1.0/24 --export json | jq '.[].ip'

<p align="center"> <strong>Made with ❤️ by Cyb0rgBytes</strong><br> <sub>⚡ Happy Scanning! ⚡</sub> </p><p align="center"> <a href="https://github.com/Cyb0rgBytes">GitHub</a> • <a href="https://twitter.com/Cyb0rgBytes">Twitter</a> • <a href="https://cyb0rgbytes.tech">Website</a> </p>

🎯 Remember: Always scan networks you own or have permission to scan. With great power comes great responsibility! 🕵️‍♂️
