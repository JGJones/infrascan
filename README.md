# Infrastructure Scanner (infra-scan)

A simple python script that does network infrastructure scanning - this is for network discovery and port scanning using nmap. It's aimed for authorized security assessments, vulnerability testing, and network infrastructure auditing.

## Overview

This tool provides automated network scanning capabilities with session management, resumable scans, and network splitting for processing. It performs three-phase scanning: host discovery, TCP port scanning, and UDP port scanning.

The reason for network splitting is that I've had to stop nmap scans previously on various jobs and if it was doing a large subnet at the time (such as a /16 for example) - I usually end up having to restart because it can't resume for any reason etc. So I normally overcome that by splitting it into smaller blocks such as /27 (32 hosts) so that if I cancel, it's less painful stopping that.


This script basically automates that for me - give it large subnets or a file with the scope. It'll output to CSV (it can also export to Excel if you have the openpyxl module)


## Scanning steps:

### Root check

It'll check if you ran this as root or not. If not, you can continue, but will be limited to TCP connect scans, no UDP.

### 🔍 Scanning steps

- **Host Discovery**: Fast ping sweeps to identify live hosts (`-sn`)
- **TCP Port Scanning**: Full port range or top-N ports with SYN stealth scans (`-sS`) when run as root
- **UDP Port Scanning**: Top UDP ports (requires root privileges)
- **Service Detection**: Optional service version detection (`-sV`) for discovered open ports

### Features

- **Automatic Network Splitting**: Large networks (/24 or bigger) are split into /27 blocks
- **Flexible Input**: Supports CIDR notation, IP ranges, single IPs, and mixed input from files
- **Progress Tracking**: Real-time progress updates and completion status
- **Resumable Scans**: Create named sessions that can be interrupted and resumed later
- **Progress Preservation**: Automatically saves scan progress and completion state
- **Session Listing**: View and manage existing scan sessions

## Requirements

- Python 3.6+
- nmap binary installed on system
- Root privileges recommended for full functionality

### Python Dependencies
- `python-nmap`: Core nmap integration
- `openpyxl`: Optional, for Excel file generation


## Usage

### Basic Examples

```bash
# Scan specific IP ranges
python3 infra-scan.py -t 192.168.1.0/24 10.0.0.0/24

# Scan from file (one target per line)
python3 infra-scan.py -f targets.txt

# Run with root for full functionality
sudo python3 infra-scan.py -t 192.168.1.0/24
```

### Advanced Usage

```bash
# Create named session for resumable scanning
sudo python3 infra-scan.py --session-id my-audit -t 192.168.0.0/16

# Resume a previous session
python3 infra-scan.py --resume my-audit

# Service detection with custom output directory
python3 infra-scan.py --version -t 192.168.1.0/24 -o scan-results

# Generate Excel reports
python3 infra-scan.py --excel -t 192.168.1.0/24

# Scan top TCP ports only
python3 infra-scan.py --tcp-top-ports 1000 -t 192.168.1.0/24

# List available sessions
python3 infra-scan.py --list-sessions
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-t, --targets` | IP ranges/networks to scan |
| `-f, --file` | File containing IP ranges (one per line) |
| `--session-id` | Custom session ID for resumable scanning |
| `--resume` | Resume a previous scanning session |
| `--list-sessions` | List available session directories |
| `--version` | Perform service detection scan (-sV) |
| `--tcp-top-ports` | Scan top N TCP ports (default: all ports) |
| `--udp-top-ports` | Scan top N UDP ports (default: 400) |
| `-o, --output-dir` | Output directory for results (default: results) |
| `--excel` | Generate Excel files from CSV results |

## Input Formats


```bash
# CIDR notation
192.168.1.0/24

# IP ranges  
192.168.1.1-50

# Single IPs
192.168.1.1

# Mixed in files (supports # comments)
192.168.1.0/24
10.0.0.1-100
# This is a comment
172.16.0.0/16
```

## Output Structure

### Session Directory Structure
```
sessions/
└── session_20240910-143025/
    ├── session_data.json          # Session metadata
    └── net001/
        ├── nets.txt               # IP ranges for this network group
        ├── live_hosts_1.txt       # Discovered live hosts
        ├── tcp_scan_1.csv         # TCP scan results (CSV)
        ├── tcp_scan_1.nmap        # TCP scan results (human-readable)
        ├── udp_scan_1.csv         # UDP scan results (CSV)
        └── udp_scan_1.nmap        # UDP scan results (human-readable)
```

### Final Results Directory
```
results/
├── 192.168.1.0_24_live_hosts_consolidated.txt
├── 192.168.1.0_24_tcp_scan_consolidated.csv
├── 192.168.1.0_24_tcp_scan_consolidated.nmap
├── 192.168.1.0_24_udp_scan_consolidated.csv
├── 192.168.1.0_24_udp_scan_consolidated.nmap
└── scan_summary.txt                           # Comprehensive scan summary
```

⚠️ **IMPORTANT NOTICE** ⚠️

- **Authorization Required**: Only use this tool on networks you own or have explicit permission to scan
- **Legal Compliance**: Ensure compliance with local laws and regulations
- **Responsible Use**: This tool is intended for defensive security, vulnerability assessment, and authorized penetration testing
- **Network Impact**: Large scans can impact network performance; use appropriate timing and concurrency settings

This project is intended for authorized security testing and infrastructure assessment.