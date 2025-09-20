# 🔧 Nmap - Network Mapper Complete Guide

Nmap (Network Mapper) is the most essential network discovery and security auditing tool in penetration testing. It's capable of discovering hosts, services, operating systems, and vulnerabilities across networks using raw IP packets in novel ways.

**Location:** `02-information-gathering/active-reconnaissance/port-scanning/nmap-complete-guide.md`

## 🎯 What is Nmap?

Nmap (Network Mapper) is a free and open-source network discovery and security auditing tool that has become the de facto standard for network reconnaissance in penetration testing. Key capabilities include:

- **Host Discovery**: Identifying live hosts on networks using various techniques
- **Port Scanning**: Determining open, closed, and filtered ports on target systems  
- **Service Detection**: Identifying services and their versions running on open ports
- **OS Detection**: Fingerprinting operating systems and hardware characteristics
- **Vulnerability Scanning**: Using NSE scripts to detect security vulnerabilities
- **Network Mapping**: Creating comprehensive network topology maps

## 📦 Installation and Setup

### Prerequisites:
- Linux/Unix system (Kali Linux recommended)
- Root/sudo privileges for advanced scanning techniques
- Basic understanding of TCP/IP networking
- Network connectivity to target systems

### Installation:
```bash
# On Kali Linux (pre-installed)
nmap --version

# On Ubuntu/Debian
sudo apt update && sudo apt install nmap

# On CentOS/RHEL
sudo yum install nmap

# Verification
nmap --version
# Expected output: Nmap version 7.94SVN ( https://nmap.org )
```

### Initial Configuration:
```bash
# Update Nmap databases
sudo nmap --script-updatedb

# Check NSE script locations
locate *.nse | head -10

# Verify NSE functionality
nmap --script-help http-enum
```

## 🔧 Basic Usage and Syntax

### Basic Workflow:
1. **Host Discovery**: Identify live targets in the network
2. **Port Scanning**: Determine open services on discovered hosts
3. **Service Detection**: Identify specific services and versions
4. **Vulnerability Assessment**: Run NSE scripts for security testing
5. **Report Generation**: Document findings for analysis

### Command Structure:
```bash
# Basic syntax
nmap [Scan Type] [Options] [NSE Scripts] [Targets]

# Example workflow progression
nmap -sn 192.168.1.0/24                    # Host discovery
nmap -sS -F 192.168.1.10                   # Fast TCP scan
nmap -sV -p- 192.168.1.10                  # Service detection
nmap -sC -sV 192.168.1.10                  # Default scripts + versions
```

## ⚙️ Command Line Options

### Host Discovery Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-sn` | Ping scan only (no port scan) | `nmap -sn 192.168.1.0/24` |
| `-Pn` | Skip host discovery (assume up) | `nmap -Pn target.com` |
| `-PS` | TCP SYN ping | `nmap -PS22,80,443 target` |
| `-PA` | TCP ACK ping | `nmap -PA80 target` |
| `-PU` | UDP ping | `nmap -PU53 target` |

### Port Scanning Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-sS` | TCP SYN scan (stealth) | `nmap -sS target` |
| `-sT` | TCP connect scan | `nmap -sT target` |
| `-sU` | UDP scan | `nmap -sU target` |
| `-sA` | TCP ACK scan | `nmap -sA target` |
| `-sF` | FIN scan | `nmap -sF target` |

### Port Specification:
| Option | Purpose | Example |
|--------|---------|---------|
| `-p 80` | Scan specific port | `nmap -p 80 target` |
| `-p 1-100` | Port range | `nmap -p 1-100 target` |
| `-p-` | All ports (1-65535) | `nmap -p- target` |
| `-F` | Fast scan (top 100 ports) | `nmap -F target` |
| `--top-ports 1000` | Scan top N ports | `nmap --top-ports 1000 target` |

### Service Detection:
| Option | Purpose | Example |
|--------|---------|---------|
| `-sV` | Service version detection | `nmap -sV target` |
| `-O` | OS detection | `nmap -O target` |
| `-A` | Aggressive scan (OS, version, scripts) | `nmap -A target` |
| `-sC` | Default NSE scripts | `nmap -sC target` |

### Timing and Performance:
| Option | Purpose | Example |
|--------|---------|---------|
| `-T0` to `-T5` | Timing templates | `nmap -T4 target` |
| `--min-rate 1000` | Minimum packet rate | `nmap --min-rate 1000 target` |
| `--max-retries 2` | Maximum retransmissions | `nmap --max-retries 2 target` |

## 🧪 Real Lab Examples

### Example 1: INE Lab - Complete Network Reconnaissance
```bash
# Phase 1: Target reachability check
ping -c 4 demo.ine.local
# Output: PING demo.ine.local (192.65.236.3) 56(84) bytes of data
# 64 bytes from demo.ine.local (192.65.236.3): icmp_seq=1 ttl=64 time=0.123 ms
# 4 packets transmitted, 4 received, 0% packet loss

# Phase 2: TCP port scan (all 65535 ports)
nmap demo.ine.local -T4 -p-
# Output: Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-11 11:55 IST
# Host is up (0.000020s latency).
# All 65535 scanned ports on demo.ine.local (192.65.236.3) are in ignored states.
# Not shown: 65535 closed tcp ports (reset)

# Phase 3: UDP port scan discovery
nmap demo.ine.local -T4 -sU
# Output: Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-11 11:55 IST
# Nmap scan report for demo.ine.local (192.65.236.3)
# Host is up (0.000089s latency).
# Not shown: 998 closed udp ports (port-unreach), 41 open|filtered udp ports
# PORT    STATE SERVICE
# 161/udp open  snmp

# Phase 4: Service detection on discovered UDP port
nmap demo.ine.local -T4 -sU -p 161 -A
# Output: Comprehensive SNMP service information including:
# - SNMPv1 server; net-snmp SNMPv3 server (public)
# - System information and installed packages
# - Network interface details
# - Running processes and services
```

### Example 2: Comprehensive Service Enumeration
```bash
# Service version detection with NSE scripts
nmap -sV -sC -p 161 demo.ine.local

# Advanced SNMP enumeration
nmap --script snmp-* -p 161 demo.ine.local

# Results analysis from lab output:
# Discovered Ubuntu system with extensive package information
# SNMP community string: public
# Multiple network interfaces including loopback and eth0
# Running processes: supervisord, snmpd, sshd services
```

### Example 3: Script-based Vulnerability Assessment
```bash
# Run vulnerability detection scripts
nmap --script vuln -p 161 demo.ine.local

# SNMP information gathering
nmap --script snmp-info,snmp-sysdescr -p 161 demo.ine.local

# Process enumeration via SNMP
nmap --script snmp-processes -p 161 demo.ine.local
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **Host Discovery (25%)**: Identifying live systems in network ranges
- **Port Scanning (30%)**: TCP/UDP port identification and analysis  
- **Service Enumeration (25%)**: Version detection and service fingerprinting
- **Script Usage (20%)**: Basic NSE script execution for information gathering

### Critical Commands to Master:
```bash
# Host discovery for network ranges
nmap -sn 192.168.1.0/24          # Essential for network mapping

# Fast service discovery
nmap -sV -F target               # Quick service identification

# Comprehensive scanning
nmap -sC -sV target              # Default scripts + version detection

# UDP service discovery  
nmap -sU --top-ports 1000 target # UDP services often overlooked

# Stealth scanning
nmap -sS target                  # Avoid detection/logging

# All ports scanning
nmap -p- target                  # Comprehensive port coverage
```

### eJPT Exam Scenarios:

1. **Network Discovery Scenario:**
   - Required skills: Host discovery, network mapping
   - Expected commands: `nmap -sn`, ping sweeps
   - Success criteria: Identify all live hosts in given subnet

2. **Service Identification Scenario:**
   - Required skills: Port scanning, service detection
   - Expected commands: `nmap -sV`, `nmap -sC`
   - Success criteria: Enumerate services and versions accurately

3. **Vulnerability Assessment Scenario:**
   - Required skills: NSE script usage, vulnerability identification
   - Expected commands: `nmap --script vuln`, specific service scripts
   - Success criteria: Identify exploitable services and vulnerabilities

### Exam Tips and Tricks:
- **Time Management**: Use `-F` for initial scans, then focus on interesting ports
- **UDP Scanning**: Don't forget UDP services (SNMP, DNS, DHCP) - often overlooked
- **Documentation**: Always save scan results with `-oA filename` for reporting
- **Stealth Considerations**: Use `-sS` instead of `-sT` to avoid connection logs
- **Script Selection**: Learn key scripts: `http-enum`, `smb-enum-*`, `ftp-anon`

### Common eJPT Questions:
- Identifying web applications on non-standard ports
- Discovering SNMP community strings and system information
- Finding SMB shares and anonymous access
- Locating SSH services with weak configurations

## ⚠️ Common Issues & Troubleshooting

### Issue 1: "Permission Denied" for SYN Scans
**Problem:** Cannot run SYN scan without root privileges
**Cause:** Raw socket operations require elevated privileges
**Solution:**
```bash
# Use sudo for privileged scans
sudo nmap -sS target

# Alternative: Use connect scan (no privileges needed)
nmap -sT target

# Verify current user permissions
id
```

### Issue 2: Slow UDP Scanning Performance
**Problem:** UDP scans taking extremely long time
**Cause:** UDP is inherently slower due to lack of acknowledgments
**Solution:**
```bash
# Increase timing template
nmap -sU -T4 target

# Limit to top ports only
nmap -sU --top-ports 100 target

# Use version detection to confirm open ports
nmap -sU -sV -p 53,161,123 target
```

### Issue 3: Firewall Blocking Scans
**Problem:** All ports showing as filtered
**Cause:** Target firewall dropping packets
**Solution:**
```bash
# Try different scan techniques
nmap -sA target          # ACK scan for firewall mapping
nmap -f target           # Fragment packets
nmap --source-port 53 target  # Source port manipulation

# Use decoy scanning
nmap -D RND:10 target
```

### Issue 4: NSE Scripts Not Working
**Problem:** Scripts failing or not providing expected output
**Cause:** Outdated script database or missing dependencies
**Solution:**
```bash
# Update script database
sudo nmap --script-updatedb

# Verify script syntax
nmap --script-help script-name

# Test individual scripts
nmap --script http-title -p 80 target
```

## 🔗 Integration with Other Tools

### Primary Integration: Nmap → Service-specific Tools
```bash
# Nmap discovery feeds into specialized enumeration
nmap -sV target | grep "open"

# HTTP services → dirb/gobuster
nmap -p 80,443,8080 target --open

# SMB services → enum4linux
nmap -p 139,445 target --script smb-os-discovery

# FTP services → specific FTP enumeration
nmap -p 21 target --script ftp-anon,ftp-bounce
```

### Secondary Integration: Mass Scanning Workflows
```bash
# Masscan for fast discovery → Nmap for detailed analysis
masscan -p80,443 192.168.1.0/24 --rate=1000 > masscan_results.txt
nmap -sV -iL masscan_results.txt

# Combine with vulnerability scanners
nmap --script vuln target > nmap_vulns.txt
```

### Advanced Workflows:
```bash
# Complete network assessment pipeline
nmap -sn 192.168.1.0/24 | grep "up" | awk '{print $5}' > live_hosts.txt
nmap -sV -iL live_hosts.txt -oA network_scan
nmap --script vuln -iL live_hosts.txt -oA vuln_scan
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** Command execution and key results
2. **Command Outputs:** Full scan results with timestamps
3. **Log Files:** Nmap output files (-oA option)
4. **Service Details:** Version information and banner grabs

### Report Template Structure:
```markdown
## Nmap Network Reconnaissance Results

### Target Information
- Target: demo.ine.local (192.65.236.3)
- Date/Time: 2024-07-11 11:55 IST
- Nmap Version: 7.94SVN

### Commands Executed
```bash
# Host discovery
ping -c 4 demo.ine.local

# TCP port scan
nmap demo.ine.local -T4 -p-

# UDP port scan  
nmap demo.ine.local -T4 -sU

# Service detection
nmap demo.ine.local -T4 -sU -p 161 -A
```

### Key Findings
- **Open UDP Port**: 161/udp (SNMP service)
- **Service Version**: SNMPv1 server; net-snmp SNMPv3 server
- **System Information**: Ubuntu system with extensive package details
- **Security Concern**: SNMP community string "public" accessible

### Recommendations
- Restrict SNMP access to authorized management networks
- Consider disabling SNMP if not required for operations
- Implement SNMP v3 with proper authentication if service needed
```

### Automation Scripts:
```bash
#!/bin/bash
# Automated Nmap documentation script
TARGET=$1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="nmap_results_${TIMESTAMP}"

mkdir -p $OUTPUT_DIR
nmap -sn $TARGET -oA $OUTPUT_DIR/host_discovery
nmap -sV -sC $TARGET -oA $OUTPUT_DIR/service_scan
nmap --script vuln $TARGET -oA $OUTPUT_DIR/vulnerability_scan

echo "Scan completed. Results saved to $OUTPUT_DIR/"
```

## 📚 Additional Resources

### Official Documentation:
- Official Nmap website: https://nmap.org
- Nmap Reference Guide: https://nmap.org/book/
- NSE Script Documentation: https://nmap.org/nsedoc/

### Learning Resources:
- "Nmap Network Scanning" by Gordon Lyon (Fyodor): Comprehensive official guide
- Nmap Scripting Engine Tutorial: https://nmap.org/book/nse.html
- eJPT-focused Nmap labs: Practice with INE platform exercises

### Community Resources:
- Nmap development mailing list: https://nmap.org/mailman/listinfo/dev
- /r/netsec community discussions on Reddit
- SANS penetration testing resources

### Related Tools:
- **Masscan**: High-speed port scanner for large networks
- **Zmap**: Internet-wide network scanner
- **Unicornscan**: Alternative port scanner with unique features
- **NSE Scripts**: Extensive script collection for specialized enumeration
