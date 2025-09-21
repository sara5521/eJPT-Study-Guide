# 🔧 Nmap Basic Scans - Essential Port Scanning Techniques

Network Mapper (Nmap) is the most fundamental and powerful network discovery and security auditing tool in penetration testing. It provides comprehensive capabilities for host discovery, port scanning, service detection, and vulnerability assessment across network infrastructures.

**Location:** `04-port-scanning/nmap-fundamentals/basic-scans.md`

## 🎯 What is Nmap?

Nmap (Network Mapper) is a free and open-source network discovery and security auditing utility designed for network exploration, management, and security testing. Key capabilities include:

- **Host Discovery:** Identifying live hosts on network segments
- **Port Scanning:** Detecting open, closed, and filtered ports across TCP/UDP protocols  
- **Service Detection:** Fingerprinting services and applications running on discovered ports
- **Operating System Detection:** Identifying target operating systems and device types
- **Scriptable Interaction:** Automated vulnerability detection through NSE (Nmap Scripting Engine)
- **Network Mapping:** Creating comprehensive network topology maps

## 📦 Installation and Setup

### Prerequisites:
- Linux/Unix environment (Kali Linux recommended for eJPT)
- Root/sudo privileges for advanced scanning techniques
- Basic understanding of TCP/IP networking concepts
- Knowledge of common network ports and services

### Installation:
```bash
# Installation on Debian/Ubuntu systems
sudo apt update
sudo apt install nmap

# Installation on RHEL/CentOS systems
sudo yum install nmap

# Verification of installation
nmap --version
# Expected output: Nmap version 7.94SVN (https://nmap.org)
```

### Initial Configuration:
```bash
# Update Nmap database
sudo nmap --script-updatedb

# Verify NSE scripts installation
ls /usr/share/nmap/scripts/ | wc -l
# Expected output: 600+ scripts available
```

## 🔧 Basic Usage and Syntax

### Basic Workflow:
1. **Target Selection:** Define IP addresses, ranges, or hostnames to scan
2. **Scan Type Selection:** Choose appropriate scanning technique (TCP/UDP/Stealth)
3. **Port Range Definition:** Specify ports to scan (default, top ports, or custom ranges)
4. **Service Detection:** Enable version detection and OS fingerprinting
5. **Output Analysis:** Interpret results and document findings

### Command Structure:
```bash
# Basic syntax
nmap [scan_type] [options] target_specification

# Essential workflow examples
nmap target_ip                          # Basic TCP SYN scan
nmap -sV target_ip                      # Service version detection
nmap -sS -sV -O target_ip              # Stealth scan with OS detection
```

## ⚙️ Command Line Options

### Basic Scan Types:
| Option | Purpose | Example |
|--------|---------|---------|
| `-sS` | TCP SYN stealth scan (default) | `nmap -sS 192.168.1.1` |
| `-sT` | TCP connect scan | `nmap -sT 192.168.1.1` |
| `-sU` | UDP scan | `nmap -sU 192.168.1.1` |
| `-sA` | TCP ACK scan | `nmap -sA 192.168.1.1` |

### Port Specification Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-p 80` | Scan specific port | `nmap -p 80 target_ip` |
| `-p 1-1000` | Scan port range | `nmap -p 1-1000 target_ip` |
| `-p-` | Scan all 65535 ports | `nmap -p- target_ip` |
| `--top-ports 1000` | Scan most common ports | `nmap --top-ports 1000 target_ip` |

### Detection and Enumeration:
| Option | Purpose | Example |
|--------|---------|---------|
| `-sV` | Service version detection | `nmap -sV target_ip` |
| `-O` | Operating system detection | `nmap -O target_ip` |
| `-A` | Aggressive scan (OS, version, scripts) | `nmap -A target_ip` |
| `--script` | Run NSE scripts | `nmap --script discovery target_ip` |

### Output and Performance:
| Option | Purpose | Example |
|--------|---------|---------|
| `-v` | Verbose output | `nmap -v target_ip` |
| `-oN` | Normal output to file | `nmap -oN scan.txt target_ip` |
| `-T4` | Timing template (faster) | `nmap -T4 target_ip` |
| `--min-rate` | Minimum packet rate | `nmap --min-rate 1000 target_ip` |

## 🧪 Real Lab Examples

### Example 1: Basic Host and Port Discovery
```bash
# Phase 1: Verify target reachability
ping -c 4 demo.ine.local
# Output: PING demo.ine.local (192.197.148.3) 56(84) bytes of data.
# 64 bytes from demo.ine.local (192.197.148.3): icmp_seq=1 ttl=64 time=0.099 ms
# 64 bytes from demo.ine.local (192.197.148.3): icmp_seq=2 ttl=64 time=0.069 ms
# 64 bytes from demo.ine.local (192.197.148.3): icmp_seq=3 ttl=64 time=0.053 ms
# 64 bytes from demo.ine.local (192.197.148.3): icmp_seq=4 ttl=64 time=0.052 ms

# Phase 2: Initial port discovery - DNS service check
nmap demo.ine.local -p 177 -A
# Output: Shows BIND DNS service running on port 177

# Phase 3: UDP port range scanning
nmap demo.ine.local -p 1-250 -sU
# Output: Starting Nmap 7.94SVN at 2024-07-10 14:28 IST
# Stats: 0:01:57 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
# UDP Scan Timing: About 92.72% done; ETC: 14:32 (0:00:11 remaining)
# Nmap scan report for demo.ine.local (192.197.148.3)
# Host is up (0.000071s latency).
# Not shown: 247 closed udp ports (port-unreach)
# PORT     STATE         SERVICE
# 134/udp  open|filtered ingres-net
# 177/udp  open|filtered xdmcp
# 234/udp  open|filtered unknown
```

### Example 2: Service Detection and Enumeration
```bash
# Service detection on discovered UDP ports
nmap demo.ine.local -p 134,177,234 -sUV
# Output: Starting Nmap 7.94SVN at 2024-07-10 14:33 IST
# Nmap scan report for demo.ine.local (192.197.148.3)
# Host is up (0.000026s latency).
# 
# PORT     STATE SERVICE VERSION
# 134/udp  open|filtered ingres-net
# 177/udp  open   domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
# 234/udp  open   snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
# MAC Address: 02:42:c0:c5:94:03 (Unknown)
# Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

# Script enumeration for additional information
nmap demo.ine.local -p 134 -sUV --script=discovery
# Output: No additional useful information revealed for port 134
```

### Example 3: TFTP Service Confirmation
```bash
# Confirming TFTP service on port 134
tftp demo.ine.local 134
# Output: Successful authentication with TFTP server
# tftp> [Interactive TFTP console established]

# Additional verification with specific TFTP probes
nmap demo.ine.local -p 134 -sU --script tftp-enum
# Output: Confirms TFTP service running on UDP port 134
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **Host Discovery Techniques (25%):** Identifying live hosts using ping sweeps and ARP scans
- **TCP Port Scanning (30%):** SYN scans, connect scans, and stealth techniques
- **UDP Port Scanning (20%):** UDP service discovery and enumeration techniques  
- **Service Enumeration (25%):** Version detection and banner grabbing skills

### Critical Commands to Master:
```bash
# Basic TCP scan - most common exam scenario
nmap target_ip

# Service version detection - essential for enumeration phase
nmap -sV target_ip

# UDP scanning - often overlooked but critical for complete assessment
nmap -sU target_ip

# Comprehensive scanning with OS detection
nmap -sS -sV -O target_ip

# Script-based enumeration for specific services
nmap --script discovery target_ip
```

### eJPT Exam Scenarios:
1. **Network Reconnaissance Scenario:** Given a target IP range, identify live hosts and running services
   - Required skills: Host discovery, port scanning, service enumeration
   - Expected commands: `nmap -sn`, `nmap -sS -sV`, `nmap -sU`
   - Success criteria: Complete service inventory with versions identified

2. **Service Enumeration Scenario:** Deep dive into specific services discovered on target systems
   - Required skills: Version detection, script usage, manual verification
   - Expected commands: `nmap -sV -p port`, `nmap --script service-name`
   - Success criteria: Detailed service information for exploitation planning

### Exam Tips and Tricks:
- **Time Management:** Use `-T4` timing for faster scans during time-constrained scenarios
- **Port Priority:** Focus on common ports first, then expand to full range if time permits
- **UDP Scanning:** Don't neglect UDP - critical services like SNMP, DNS, TFTP often run on UDP
- **Documentation:** Always save scan results with `-oN` for reference during exploitation phases

### Common eJPT Questions:
- How to identify services running on non-standard ports?
- What is the difference between TCP SYN and TCP connect scans?
- How to detect UDP services that don't respond to standard probes?

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Slow Scanning Performance
**Problem:** Nmap scans taking excessive time to complete, especially UDP scans
**Cause:** Default timing policies are conservative to avoid network disruption
**Solution:**
```bash
# Increase timing aggressiveness
nmap -T4 target_ip

# Set minimum packet rate for faster scanning
nmap --min-rate 1000 target_ip

# Reduce host timeout for faster host discovery
nmap --host-timeout 10s target_ip
```

### Issue 2: Firewall Blocking Scans
**Problem:** No ports showing as open despite knowing services are running
**Solution:**
```bash
# Use different scan techniques to bypass filtering
nmap -sA target_ip    # ACK scan to detect filtered ports
nmap -f target_ip     # Fragment packets to evade simple firewalls
nmap --source-port 53 target_ip  # Use DNS source port
```

### Issue 3: UDP Scan Accuracy Issues
**Problem:** UDP scans showing ports as "open|filtered" without definitive results
**Prevention:**
```bash
# Increase UDP scan accuracy with version detection
nmap -sUV target_ip

# Use specific scripts for UDP service detection
nmap -sU --script discovery target_ip

# Manual verification of suspected UDP services
nc -u target_ip port
```

### Issue 4: Incomplete Service Detection
**Problem:** Services detected but version information missing
**Optimization:**
```bash
# Force aggressive service detection
nmap -sV --version-intensity 9 target_ip

# Combine with script scanning for additional details
nmap -sV --script banner target_ip
```

## 🔗 Integration with Other Tools

### Primary Integration: Nmap → Service Enumeration → Exploitation
```bash
# Phase 1: Initial discovery with Nmap
nmap -sS -sV -O target_ip > initial_scan.txt

# Phase 2: Service-specific enumeration based on Nmap results
# If HTTP detected:
nikto -h http://target_ip
gobuster dir -u http://target_ip -w /usr/share/wordlists/dirb/common.txt

# If SSH detected:
ssh-audit target_ip

# If SMB detected:
enum4linux target_ip
```

### Secondary Integration: Nmap → Vulnerability Assessment
```bash
# Use Nmap script scanning for vulnerability detection
nmap --script vuln target_ip

# Export results for analysis in other tools
nmap -oX scan_results.xml target_ip
# Import XML into tools like OpenVAS or Metasploit
```

### Advanced Workflows:
```bash
# Complete reconnaissance pipeline
nmap -sn network_range | grep "Nmap scan report" | awk '{print $5}' > live_hosts.txt
nmap -sS -sV -iL live_hosts.txt -oA network_scan
# Further analysis with discovered services
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** Capture terminal output showing command execution and results
2. **Command Outputs:** Save all scan results using `-oN`, `-oX`, and `-oG` formats
3. **Log Files:** Preserve detailed scan logs with timing and methodology information
4. **Configuration Files:** Document any custom Nmap configurations or scripts used

### Report Template Structure:
```markdown
## Nmap Scanning Results

### Target Information
- Target: demo.ine.local (192.197.148.3)
- Date/Time: 2024-07-10 14:28 IST
- Scan Duration: 278.19 seconds
- Nmap Version: 7.94SVN

### Commands Executed
```bash
# Host discovery and reachability
ping -c 4 demo.ine.local

# TCP port scanning
nmap demo.ine.local -p 177 -A

# UDP port scanning
nmap demo.ine.local -p 1-250 -sU

# Service detection
nmap demo.ine.local -p 134,177,234 -sUV
```

### Key Findings
- **DNS Service (Port 177/UDP):** ISC BIND 9.10.3-P4 running on Ubuntu Linux
- **SNMP Service (Port 234/UDP):** SNMPv1 server with net-snmp SNMPv3 server (public community)
- **TFTP Service (Port 134/UDP):** TFTP server accessible with anonymous authentication

### Security Implications
- SNMP service using default "public" community string
- TFTP service allowing anonymous access
- DNS service potentially vulnerable to zone transfer attacks
```

### Automation Scripts:
```bash
#!/bin/bash
# Automated Nmap scanning and documentation script
target=$1
timestamp=$(date +"%Y%m%d_%H%M%S")
output_dir="nmap_scan_$timestamp"

mkdir -p $output_dir
nmap -sS -sV -O $target -oA "$output_dir/tcp_scan"
nmap -sU --top-ports 1000 $target -oA "$output_dir/udp_scan"
nmap --script discovery $target -oN "$output_dir/script_scan.txt"

echo "Scan completed. Results saved in $output_dir/"
```

## 📚 Additional Resources

### Official Documentation:
- Official Nmap website: https://nmap.org
- Nmap Reference Guide: https://nmap.org/book/
- NSE Documentation: https://nmap.org/nsedoc/

### Learning Resources:
- Nmap Network Scanning Book: Comprehensive guide by Gordon Lyon
- SANS SEC560 Course: Network Penetration Testing and Ethical Hacking
- Cybrary Nmap Course: Free online training for beginners

### Community Resources:
- Nmap Users Mailing List: nmap-hackers@insecure.org
- Reddit r/netsec: Active community discussions
- Discord Infosec Community: Real-time help and discussions

### Related Tools:
- **Masscan:** High-speed port scanner for large networks - faster but less detailed than Nmap
- **Zmap:** Internet-wide network scanner - complements Nmap for large-scale discovery
- **Rustscan:** Modern port scanner written in Rust - faster initial discovery, feeds results to Nmap
