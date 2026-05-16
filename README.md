# Network Intrusion Detection System (NIDS)
![Python](https://img.shields.io/badge/Python-3.13-blue)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-red)
![Status](https://img.shields.io/badge/Status-Active-green)

A Python-based real-time Network Intrusion Detection System
that monitors network traffic and detects common cyber attacks.

## What It Does
This tool sits on your network and watches all traffic passing
through. When it detects suspicious activity it raises an alert
and saves it to a log file. At the end it generates a
professional HTML report.

## Attack Types Detected
| Attack | Description | Severity |
|--------|-------------|----------|
| Port Scan | Someone scanning for open ports | HIGH |
| Ping Flood | Overwhelming a device with pings | HIGH |
| SYN Flood | TCP connection flood attack | CRITICAL |
| ARP Spoofing | Fake MAC address attack | CRITICAL |
| Brute Force | Repeated login attempts | HIGH |

## Project Structurenetwork-intrusion-detection-system/
├── src/
│   ├── main.py          ← Run this to start NIDS
│   ├── sniffer.py       ← Captures network packets
│   ├── rules.py         ← Detection rules engine
│   ├── alerts.py        ← Alert display and logging
│   └── dashboard.py     ← Live terminal display
├── logs/
│   └── alerts.log       ← Saved alert history
├── reports/
│   └── nids_report.html ← HTML scan report
├── docs/
│   └── user_manual.md   ← Full user guide
└── tests/
└── test_log.md      ← Testing evidence
## Setup
```bash
# Clone the repo
git clone https://github.com/unchartedcupid/network-intrusion-detection-system.git
cd network-intrusion-detection-system

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## How to Run
```bash
# Always needs sudo for packet capture
sudo /path/to/venv/bin/python3 src/main.py
```

## Requirements
- Kali Linux (or any Linux distro)
- Python 3.x
- Root/sudo privileges
- Libraries: scapy, psutil, colorama

## Tech Stack
- **Python 3.13** — Core language
- **Scapy** — Packet capture and analysis
- **JSON** — Alert storage format
- **HTML/CSS** — Report generation

## Ethical Notice
> This tool is for **authorized use only**.
> Only monitor networks you own or have
> explicit permission to monitor.
> Unauthorized network monitoring is illegal.

## Author
**Victor** — Academic Cybersecurity Project
