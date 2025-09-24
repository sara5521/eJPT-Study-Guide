# 🔧 Nmap - Network Discovery and Security Auditing Tool

Nmap (Network Mapper) is the most essential network discovery and security auditing tool for penetration testers. It's capable of discovering hosts, services, operating systems, and vulnerabilities across networks of any size.

**Location:** `02-reconnaissance/nmap-comprehensive-guide.md`

## 🎯 What is Nmap?

Nmap is a powerful, open-source network scanner that uses raw IP packets to determine what hosts are available on the network, what services those hosts are offering, what operating systems they are running, what type of packet filters/firewalls are in use, and dozens of other characteristics.

Key capabilities include:
- **Host Discovery:** Finding live hosts on networks
- **Port Scanning:** Identifying open/closed/filtered ports
- **Service Detection:** Determining service versions and protocols
- **OS Fingerprinting:** Identifying target operating systems
- **Vulnerability Scanning:** Using NSE scripts for security assessment

## 📦 Installation and Setup

### Prerequisites:
- Linux/Windows/macOS system
- Administrative/root privileges for advanced scans
- Network connectivity to target systems

### Installation:
```bash
# Kali Linux (pre-installed)
nmap --version

# Ubuntu/Debian
apt update && apt install nmap

# CentOS/RHEL
yum install nmap

# Verification
nmap --version
# Expected output: Nmap version 7.94 ( https://nmap.org )
```

### Initial Configuration:
```bash
# Update Nmap script database
nmap --script-updatedb

# Verify script installation
ls /usr/share/nmap/scripts/ | wc -l
# Expected: 600+ scripts available
```

## 🔧 Basic Usage and Syntax

### Basic Workflow:
1. **Host Discovery:** Find live systems on the network
2. **Port Scanning:** Identify open services and ports
3. **Service Enumeration:** Detect service versions and details
4. **Vulnerability Assessment:** Run security scripts against targets

### Command Structure:
```bash
# Basic syntax
nmap [Scan Type] [Options] {target specification}

# Basic host discovery
nmap 192.168.1.1

# Port scan with service detection
nmap -sV 192.168.1.1

# Comprehensive scan
nmap -A 192.168.1.1
```

## ⚙️ Command Line Options

### Host Discovery Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-sn` | Ping scan only (no port scan) | `nmap -sn 192.168.1.0/24` |
| `-Pn` | Skip host discovery (treat as online) | `nmap -Pn 192.168.1.1` |
| `-PS` | TCP SYN ping | `nmap -PS80,443 192.168.1.1` |
| `-PA` | TCP ACK ping | `nmap -PA80,443 192.168.1.1` |
| `-PU` | UDP ping | `nmap -PU53,161 192.168.1.1` |

### Scan Techniques:
| Option | Purpose | Example |
|--------|---------|---------|
| `-sS` | TCP SYN scan (stealth scan) | `nmap -sS 192.168.1.1` |
| `-sT` | TCP Connect scan | `nmap -sT 192.168.1.1` |
| `-sU` | UDP scan | `nmap -sU 192.168.1.1` |
| `-sA` | TCP ACK scan | `nmap -sA 192.168.1.1` |
| `-sF` | FIN scan | `nmap -sF 192.168.1.1` |

### Port Specification:
| Option | Purpose | Example |
|--------|---------|---------|
| `-p` | Specific ports | `nmap -p 80,443,8080 192.168.1.1` |
| `-p-` | All ports (1-65535) | `nmap -p- 192.168.1.1` |
| `--top-ports` | Scan most common ports | `nmap --top-ports 1000 192.168.1.1` |
| `-F` | Fast scan (top 100 ports) | `nmap -F 192.168.1.1` |

### Service/Version Detection:
| Option | Purpose | Example |
|--------|---------|---------|
| `-sV` | Version detection | `nmap -sV 192.168.1.1` |
| `-O` | OS detection | `nmap -O 192.168.1.1` |
| `-A` | Aggressive scan (OS, version, scripts) | `nmap -A 192.168.1.1` |
| `--version-intensity` | Set version detection intensity (0-9) | `nmap -sV --version-intensity 9 192.168.1.1` |

### Timing and Performance:
| Option | Purpose | Example |
|--------|---------|---------|
| `-T0` to `-T5` | Timing templates (paranoid to insane) | `nmap -T4 192.168.1.1` |
| `--min-rate` | Minimum packets per second | `nmap --min-rate 1000 192.168.1.1` |
| `--max-rate` | Maximum packets per second | `nmap --max-rate 5000 192.168.1.1` |
| `-n` | No DNS resolution | `nmap -n 192.168.1.1` |

### Output Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-oN` | Normal output to file | `nmap -oN scan.txt 192.168.1.1` |
| `-oX` | XML output | `nmap -oX scan.xml 192.168.1.1` |
| `-oG` | Greppable output | `nmap -oG scan.grep 192.168.1.1` |
| `-oA` | All output formats | `nmap -oA scan 192.168.1.1` |

## 🧪 Real Lab Examples

### Example 1: Network Discovery and Host Enumeration
```bash
# Phase 1: Network discovery
nmap -sn 192.168.1.0/24
# Output: Found 15 hosts online including 192.168.1.1, 192.168.1.10, 192.168.1.50

# Phase 2: Fast port scan on discovered hosts
nmap -F 192.168.1.1,10,50
# Output:
# 192.168.1.1: 22/tcp, 80/tcp, 443/tcp open
# 192.168.1.10: 21/tcp, 22/tcp, 80/tcp, 135/tcp, 445/tcp open
# 192.168.1.50: 22/tcp, 3306/tcp, 8080/tcp open

# Phase 3: Service version detection
nmap -sV -p 22,80,443 192.168.1.1
# Output:
# 22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
# 80/tcp  open  http    Apache httpd 2.4.41
# 443/tcp open  ssl/http Apache httpd 2.4.41

# Phase 4: OS detection and comprehensive scan
nmap -A 192.168.1.1
# Output: Linux 5.4.0-74-generic, Apache 2.4.41, OpenSSH 8.2p1
```

### Example 2: Web Server Enumeration
```bash
# Step 1: Identify web services
nmap -p 80,443,8080,8443 --open 192.168.1.0/24
# Output: Multiple web servers found on ports 80, 443, 8080

# Step 2: HTTP service enumeration with scripts
nmap -p 80,443 --script=http-enum,http-headers,http-methods 192.168.1.10
# Output:
# 80/tcp open http
# | http-enum:
# |   /admin/: Possible admin folder
# |   /backup/: Backup folder
# |   /login.php: Login page
# | http-headers:
# |   Server: Apache/2.4.41 (Ubuntu)
# |   X-Powered-By: PHP/7.4.3

# Step 3: SSL/TLS analysis
nmap -p 443 --script=ssl-enum-ciphers,ssl-cert 192.168.1.10
# Output: SSL certificate details, supported ciphers, potential vulnerabilities
```

### Example 3: SMB Service Assessment
```bash
# SMB discovery and enumeration
nmap -p 139,445 --script=smb-enum-shares,smb-enum-users,smb-os-discovery 192.168.1.10
# Output:
# 139/tcp open  netbios-ssn
# 445/tcp open  microsoft-ds
# | smb-enum-shares:
# |   Account used: guest
# |   \\192.168.1.10\ADMIN$: ERROR: Access denied
# |   \\192.168.1.10\C$: ERROR: Access denied
# |   \\192.168.1.10\IPC$: OK
# | smb-os-discovery:
# |   OS: Windows Server 2019 Standard
```

### Example 4: Vulnerability Scanning
```bash
# Comprehensive vulnerability scan
nmap -p- --script=vuln 192.168.1.10
# Output:
# 21/tcp open ftp
# | ftp-vsftpd-backdoor:
# |   VULNERABLE: vsFTPd backdoor (CVE-2011-2523)
# 80/tcp open http
# | http-slowloris-check:
# |   VULNERABLE: Slowloris DOS attack
# 445/tcp open microsoft-ds
# | smb-vuln-ms17-010:
# |   VULNERABLE: EternalBlue (MS17-010)
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **Network Discovery (25%):** Finding live hosts in target networks
- **Port Scanning (30%):** Identifying open services and applications
- **Service Enumeration (25%):** Gathering detailed service information
- **Basic Vulnerability Assessment (20%):** Using NSE scripts for security checks

### Critical Commands to Master:
```bash
# Network discovery (essential for exam)
nmap -sn 192.168.1.0/24

# Basic port scan (most common in exam)
nmap -sS -T4 192.168.1.1

# Service version detection (required skill)
nmap -sV 192.168.1.1

# Comprehensive scan (exam favorite)
nmap -A 192.168.1.1

# Specific service enumeration
nmap -p 80,443 --script=http-enum 192.168.1.1
nmap -p 139,445 --script=smb-enum-shares 192.168.1.1
```

### eJPT Exam Scenarios:

1. **Network Mapping Scenario:** 
   - Required skills: Host discovery, port identification, service detection
   - Expected commands: `-sn`, `-sS`, `-sV`, `-A`
   - Success criteria: Complete network map with services identified

2. **Web Application Discovery:**
   - Required skills: HTTP service enumeration, directory discovery
   - Expected commands: `--script=http-enum`, `--script=http-methods`
   - Success criteria: Identify web applications and potential entry points

3. **SMB Enumeration Challenge:**
   - Required skills: SMB share enumeration, user enumeration
   - Expected commands: `--script=smb-enum-*`, `--script=smb-os-discovery`
   - Success criteria: Extract SMB shares, users, and system information

### Exam Tips and Tricks:
- **Always start with host discovery** using `-sn` before port scanning
- **Use timing template `-T4`** for balanced speed and stealth in exams
- **Save all outputs** using `-oA` for documentation requirements
- **Focus on open ports** using `--open` to filter results efficiently
- **Use specific NSE scripts** rather than running all vulnerability scripts

### Common eJPT Questions:
- "Identify all live hosts in the 192.168.1.0/24 network"
- "What web applications are running on the discovered web servers?"
- "Enumerate SMB shares accessible on Windows systems"
- "Identify the operating system and service versions on target hosts"

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Scan Taking Too Long
**Problem:** Nmap scans are running extremely slowly
**Cause:** Default timing is too conservative, DNS resolution delays, or scanning all ports
**Solution:**
```bash
# Speed up scans with timing template
nmap -T4 192.168.1.1

# Skip DNS resolution
nmap -n -T4 192.168.1.1

# Limit port range
nmap --top-ports 1000 192.168.1.1
```

### Issue 2: No Results or "Host Down" Errors
**Problem:** Nmap reports hosts as down when they're actually online
**Cause:** Firewall blocking ping probes or host discovery methods
**Solution:**
```bash
# Skip host discovery
nmap -Pn 192.168.1.1

# Try different ping methods
nmap -PS80,443 192.168.1.1
nmap -PA80,443 192.168.1.1
```

### Issue 3: Permission Denied for SYN Scans
**Problem:** Cannot perform SYN scans due to insufficient privileges
**Solution:**
```bash
# Run as root/administrator
sudo nmap -sS 192.168.1.1

# Alternative: Use TCP connect scan
nmap -sT 192.168.1.1
```

### Issue 4: Blocked by Firewall/IDS
**Problem:** Target network has aggressive security measures
**Prevention:**
```bash
# Use stealth timing and fragmentation
nmap -T2 -f 192.168.1.1

# Randomize scan order
nmap --randomize-hosts 192.168.1.0/24

# Use decoy scanning
nmap -D RND:10 192.168.1.1
```

## 🔗 Integration with Other Tools

### Primary Integration: Nmap → Metasploit → Exploitation
```bash
# Step 1: Nmap discovers services
nmap -sV -oX scan.xml 192.168.1.1

# Step 2: Import to Metasploit
msfconsole
db_import scan.xml
services

# Step 3: Use discovered services for exploitation
search type:exploit platform:linux ssh
use exploit/linux/ssh/ssh_login
set RHOSTS 192.168.1.1
```

### Secondary Integration: Nmap → Burp Suite → Web Testing
```bash
# Nmap identifies web applications
nmap -p 80,443,8080 --script=http-enum 192.168.1.1

# Results guide Burp Suite configuration
# Configure proxy to intercept identified web applications
# Focus testing on discovered directories and services
```

### Advanced Workflows:
```bash
# Complete reconnaissance workflow
# 1. Network discovery
nmap -sn 192.168.1.0/24 > hosts.txt

# 2. Port scanning on live hosts
nmap -iL hosts.txt -p- --open -oA full_scan

# 3. Service enumeration
nmap -iL hosts.txt -sV -A -oA service_scan

# 4. Vulnerability assessment
nmap -iL hosts.txt --script=vuln -oA vuln_scan
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** Nmap output showing discovered hosts, open ports, service versions
2. **Command Outputs:** All scan results in multiple formats (-oA option)
3. **Log Files:** Detailed scan logs with timestamps for audit trail
4. **Network Maps:** Visual representation of discovered network topology

### Report Template Structure:
```markdown
## Network Reconnaissance Results

### Target Information
- Network Range: 192.168.1.0/24
- Scan Date/Time: 2024-01-15 14:30:00
- Nmap Version: 7.94

### Commands Executed
```bash
nmap -sn 192.168.1.0/24
nmap -sS -T4 -A 192.168.1.1-50
nmap --script=vuln 192.168.1.10
```

### Host Discovery Summary
- Total Hosts Scanned: 254
- Live Hosts Found: 15
- Response Rate: 5.9%

### Service Enumeration Results
| Host | Open Ports | Services | OS |
|------|------------|----------|-----|
| 192.168.1.1 | 22,80,443 | SSH,HTTP,HTTPS | Linux Ubuntu |
| 192.168.1.10 | 21,80,139,445 | FTP,HTTP,SMB | Windows Server 2019 |

### Security Findings
- CVE-2011-2523: vsFTPd backdoor on 192.168.1.10:21
- MS17-010: EternalBlue vulnerability on 192.168.1.10:445
- Weak SSL configuration on 192.168.1.1:443

### Recommendations
- Patch vulnerable services immediately
- Implement network segmentation
- Configure host-based firewalls
```

### Automation Scripts:
```bash
#!/bin/bash
# Automated Nmap scanning and reporting
NETWORK=$1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="nmap_scan_$TIMESTAMP"

mkdir $OUTPUT_DIR
cd $OUTPUT_DIR

# Host discovery
nmap -sn $NETWORK -oA host_discovery

# Port scanning
nmap -sS -T4 -p- --open $NETWORK -oA port_scan

# Service detection
nmap -sV -A $NETWORK -oA service_scan

# Vulnerability scanning
nmap --script=vuln $NETWORK -oA vuln_scan

# Generate summary report
echo "Scan completed: $(date)" > scan_summary.txt
echo "Network: $NETWORK" >> scan_summary.txt
grep "Nmap scan report" *.nmap | wc -l >> scan_summary.txt
```

## 📚 Additional Resources

### Official Documentation:
- Official Nmap website: https://nmap.org
- Nmap documentation: https://nmap.org/docs.html
- NSE script documentation: https://nmap.org/nsedoc/

### Learning Resources:
- Nmap Network Scanning book: https://nmap.org/book/
- SANS Nmap cheat sheet: Multiple online versions available
- Interactive Nmap tutorial: Various online platforms

### Community Resources:
- Nmap mailing lists: https://nmap.org/mailman/listinfo/
- Reddit r/netsec: Regular Nmap discussions and tips
- InfoSec community forums: Multiple platforms with Nmap sections

### Related Tools:
- **Masscan:** High-speed port scanner alternative to Nmap
- **Zmap:** Internet-wide network scanner for large-scale scanning  
- **Rustscan:** Modern port scanner with Nmap integration
- **Naabu:** Fast port scanner written in Go with Nmap compatibility
