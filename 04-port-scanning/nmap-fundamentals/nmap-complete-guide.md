# 🔧 Nmap - Network Mapper and Port Scanner

Network Mapper (Nmap) is the most essential tool for network discovery and security auditing. It's capable of discovering hosts, services, operating systems, and vulnerabilities across networks of all sizes.

**Location:** `04-port-scanning/nmap-fundamentals/nmap-complete-guide.md`

## 🎯 What is Nmap?

Network Mapper (Nmap) is a free and open-source network discovery and security auditing tool. Originally written by Gordon Lyon (Fyodor), Nmap has become the de facto standard for network reconnaissance and vulnerability discovery. Key capabilities include:

- **Host Discovery** - Identifying live hosts on networks
- **Port Scanning** - Detecting open/closed/filtered ports  
- **Service Detection** - Fingerprinting services and versions
- **OS Detection** - Identifying operating systems and versions
- **Vulnerability Scanning** - NSE scripts for vulnerability detection
- **Network Mapping** - Understanding network topology and routes

## 📦 Installation and Setup

### Prerequisites:
- Linux/Unix-based system (Kali Linux recommended for pentesting)
- Root/sudo privileges for advanced scanning techniques
- Network connectivity to target systems

### Installation:
```bash
# Kali Linux (pre-installed)
nmap --version

# Ubuntu/Debian
sudo apt update && sudo apt install nmap

# CentOS/RHEL
sudo yum install nmap

# Verification
nmap --version
# Expected output: Nmap version 7.94SVN ( https://nmap.org )
```

### Initial Configuration:
```bash
# Update Nmap scripts database
sudo nmap --script-updatedb

# Check script categories
ls /usr/share/nmap/scripts/ | head -10
```

## 🔧 Basic Usage and Syntax

### Basic Workflow:
1. **Host Discovery:** Identify live targets on the network
2. **Port Scanning:** Scan for open ports on discovered hosts
3. **Service Detection:** Identify services running on open ports
4. **Vulnerability Assessment:** Use NSE scripts for security testing

### Command Structure:
```bash
# Basic syntax
nmap [scan_type] [options] target_specification

# Example workflow progression
ping -c 4 target_ip                    # Verify connectivity
nmap target_ip                         # Basic port scan
nmap target_ip -p-                     # Full TCP port scan  
nmap target_ip -p ports -sV            # Service version detection
```

## ⚙️ Command Line Options

### Basic Scanning Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-sS` | TCP SYN scan (stealth) | `nmap -sS target_ip` |
| `-sT` | TCP connect scan | `nmap -sT target_ip` |
| `-sU` | UDP port scan | `nmap -sU target_ip` |
| `-sV` | Service version detection | `nmap -sV target_ip` |
| `-O` | OS detection | `nmap -O target_ip` |
| `-A` | Aggressive scan (OS, version, scripts) | `nmap -A target_ip` |

### Port Specification Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-p-` | Scan all 65535 TCP ports | `nmap -p- target_ip` |
| `-p 80,443` | Scan specific ports | `nmap -p 80,443 target_ip` |
| `-p 1-1000` | Scan port range | `nmap -p 1-1000 target_ip` |
| `--top-ports 1000` | Scan top 1000 ports | `nmap --top-ports 1000 target_ip` |

### Timing and Performance:
| Option | Purpose | Example |
|--------|---------|---------|
| `-T0` to `-T5` | Timing templates (0=paranoid, 5=insane) | `nmap -T4 target_ip` |
| `--min-rate 1000` | Minimum packets per second | `nmap --min-rate 1000 target_ip` |
| `-F` | Fast scan (top 100 ports) | `nmap -F target_ip` |

### Output Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-oN file` | Normal output to file | `nmap -oN scan.txt target_ip` |
| `-oX file` | XML output to file | `nmap -oX scan.xml target_ip` |
| `-oG file` | Grepable output | `nmap -oG scan.grep target_ip` |
| `-oA basename` | All formats | `nmap -oA scan target_ip` |

## 🧪 Real Lab Examples

### Example 1: eJPT Lab - Basic Host Discovery and Port Scanning
```bash
# Step 1: Verify target connectivity
ping -c 4 demo.ine.local
# Output: 4 packets transmitted, 4 received, 0% packet loss, time 3091ms

# Step 2: Basic Nmap scan (default - top 1000 ports)
nmap demo.ine.local
# Output: All 1000 scanned ports on demo.ine.local (192.39.148.3) are in ignored states.
# Output: Not shown: 1000 closed|filtered ports (reset)
# Explanation: Default scan only checks common ports, may miss services on non-standard ports

# Step 3: Full TCP port range scan
nmap demo.ine.local -p-
# Output: Starting Nmap 7.94SVN at 2024-07-10 13:58 IST
# Output: Host is up (0.000021s latency)
# Output: Not shown: 65532 closed tcp ports (reset)
# Output: PORT      STATE SERVICE
# Output: 6421/tcp  open  nim-wan
# Output: 41288/tcp open  unknown  
# Output: 55413/tcp open  unknown
# Output: Nmap done: 1 IP address (1 host up) scanned in 2.13 seconds
```

### Example 2: Service Version Detection
```bash
# Detailed service detection on discovered ports
nmap demo.ine.local -p 6421,41288,55413 -sV
# Output: Starting Nmap 7.94SVN at 2024-07-10 13:59 IST
# Output: PORT      STATE SERVICE   VERSION
# Output: 6421/tcp  open  mongodb   MongoDB 2.6.10
# Output: 41288/tcp open  memcached Memcached
# Output: 55413/tcp open  ftp       vsftpd 3.0.3
# Output: Service Info: OS: Unix
# Output: Service detection performed. Please report any incorrect results at https://nmap.org/submit/
# Output: Nmap done: 1 IP address (1 host up) scanned in 11.31 seconds
```

### Example 3: Comprehensive Network Scanning Workflow
```bash
# Phase 1: Network discovery
nmap -sn 192.168.1.0/24
# Discovers live hosts on the network

# Phase 2: Quick port scan on discovered hosts  
nmap -T4 -F 192.168.1.100-110
# Fast scan of top 100 ports on range

# Phase 3: Detailed scan of interesting hosts
nmap -A -T4 -oA detailed_scan 192.168.1.105
# Aggressive scan with OS detection, service versions, and scripts

# Phase 4: Vulnerability scanning
nmap --script vuln 192.168.1.105
# Run vulnerability detection scripts
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **Basic Port Scanning (25%)** - Understanding default vs full scans
- **Service Enumeration (30%)** - Version detection and service identification  
- **Network Discovery (20%)** - Host discovery techniques
- **Output Analysis (25%)** - Interpreting scan results correctly

### Critical Commands to Master:
```bash
# Basic connectivity test
ping -c 4 target_ip                    # Always verify connectivity first

# Default scan (top 1000 ports)
nmap target_ip                         # Quick initial assessment

# Full TCP port scan  
nmap target_ip -p-                     # Complete port discovery

# Service version detection
nmap target_ip -p ports -sV            # Identify service versions

# Comprehensive scan
nmap -A target_ip                      # OS, version, scripts, traceroute
```

### eJPT Exam Scenarios:

1. **Network Enumeration Scenario:**
   - Required skills: Host discovery, port scanning, service identification
   - Expected commands: `ping`, `nmap`, `nmap -sV`
   - Success criteria: Identify all open services and versions

2. **Service Discovery Scenario:**  
   - Required skills: Full port scanning, version detection
   - Expected commands: `nmap -p-`, `nmap -sV -p ports`
   - Success criteria: Find services on non-standard ports

3. **Target Assessment Scenario:**
   - Required skills: Comprehensive scanning, vulnerability identification
   - Expected commands: `nmap -A`, `nmap --script vuln`
   - Success criteria: Complete service fingerprinting and initial vulnerability assessment

### Exam Tips and Tricks:
- **Always start with connectivity testing** using `ping` before scanning
- **Use `-p-` for complete port discovery** - don't rely on default scans
- **Service version detection is crucial** - use `-sV` for detailed enumeration
- **Time management:** Use `-T4` for faster scans during exam
- **Document everything:** Save scan outputs with `-oA` for reporting

### Common eJPT Questions:
- Identifying services running on non-standard ports
- Determining service versions for vulnerability research
- Understanding the difference between filtered, closed, and open ports
- Using appropriate scan timing for different network conditions

## ⚠️ Common Issues & Troubleshooting

### Issue 1: No Ports Showing as Open (False Negatives)
**Problem:** Default Nmap scan shows no open ports when services exist
**Cause:** Default scan only checks top 1000 common ports, services may be on non-standard ports
**Solution:**
```bash
# Always follow default scan with full port scan
nmap target_ip              # Initial quick scan
nmap target_ip -p-          # Full port range scan
nmap target_ip -p- --reason # Show why ports are marked as closed/filtered
```

### Issue 2: Scan Taking Too Long
**Problem:** Full port scans taking excessive time to complete
**Solution:**
```bash
# Use timing templates for faster scanning
nmap -T4 target_ip -p-           # Aggressive timing
nmap --min-rate 1000 target_ip   # Minimum packet rate
nmap -F target_ip                # Fast scan (top 100 ports only)
```

### Issue 3: Permission Denied for SYN Scan
**Problem:** Cannot perform SYN scan due to insufficient privileges
**Solution:**
```bash
# Use TCP connect scan as non-root alternative
nmap -sT target_ip              # TCP connect scan
sudo nmap -sS target_ip         # SYN scan with sudo privileges
```

### Issue 4: Firewall Blocking Scans
**Problem:** Target firewall filtering scan attempts
**Optimization:**
```bash
# Use stealth techniques and fragmentation
nmap -f target_ip               # Fragment packets
nmap -D RND:10 target_ip        # Decoy scanning
nmap --source-port 53 target_ip # Source port spoofing
```

## 🔗 Integration with Other Tools

### Primary Integration: Reconnaissance → Nmap → Service Enumeration
```bash
# Complete workflow showing tool integration
ping -c 4 target_ip                    # Connectivity verification
nmap target_ip -p-                     # Port discovery
nmap target_ip -p ports -sV            # Service identification
nikto -h http://target_ip:port         # Web service enumeration
enum4linux target_ip                  # SMB enumeration
```

### Secondary Integration: Nmap → Vulnerability Assessment
```bash
# Feed Nmap results into vulnerability scanners
nmap -sV target_ip -oX scan.xml       # XML output for tools
nmap --script vuln target_ip          # Built-in vulnerability scripts
searchsploit service_version          # Search for exploits based on versions
```

### Advanced Workflows:
```bash
# Multi-stage reconnaissance
nmap -sn network_range                # Host discovery
nmap -iL live_hosts.txt -F            # Quick scan of live hosts  
nmap -iL interesting_hosts.txt -A     # Detailed scan of targets
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** Command execution and complete output results
2. **Command Outputs:** All scan results with timestamps and full details
3. **Port Lists:** Summary of all discovered open ports and services
4. **Service Versions:** Complete version information for vulnerability research

### Report Template Structure:
```markdown
## Nmap Port Scanning Results

### Target Information
- Target: demo.ine.local (192.39.148.3)
- Date/Time: 2024-07-10 13:58 IST
- Nmap Version: 7.94SVN

### Commands Executed
```bash
# Connectivity test
ping -c 4 demo.ine.local

# Initial port scan
nmap demo.ine.local

# Full TCP port scan
nmap demo.ine.local -p-

# Service version detection
nmap demo.ine.local -p 6421,41288,55413 -sV
```

### Key Findings
- **3 open TCP ports discovered** on target system
- **MongoDB service** running on port 6421 (version 2.6.10)
- **Memcached service** running on port 41288
- **FTP service** running on port 55413 (vsftpd 3.0.3)

### Security Implications
- MongoDB 2.6.10 has known vulnerabilities (CVE research required)
- FTP service may allow anonymous access (further enumeration needed)
- Non-standard ports indicate potential security through obscurity

### Recommendations
- Update MongoDB to latest secure version
- Assess FTP configuration for anonymous access
- Consider using standard ports or additional security measures
```

### Automation Scripts:
```bash
#!/bin/bash
# Automated Nmap scanning and documentation script
target=$1
output_dir="nmap_scan_$(date +%Y%m%d_%H%M%S)"
mkdir -p $output_dir

echo "Starting comprehensive Nmap scan of $target"
nmap $target -oA $output_dir/initial_scan
nmap $target -p- -oA $output_dir/full_tcp_scan  
nmap $target -sU --top-ports 1000 -oA $output_dir/udp_scan
nmap $target -A -oA $output_dir/aggressive_scan

echo "Scan completed. Results saved in $output_dir/"
```

## 📚 Additional Resources

### Official Documentation:
- Official Nmap website: https://nmap.org
- Nmap documentation: https://nmap.org/docs.html
- NSE script documentation: https://nmap.org/nsedoc/

### Learning Resources:
- Nmap Network Scanning book (Gordon Lyon): https://nmap.org/book/
- Nmap Tutorial series: https://nmap.org/book/man.html
- Interactive Nmap tutorial: https://hackertarget.com/nmap-tutorial/

### Community Resources:
- Nmap development mailing list: https://nmap.org/mailman/listinfo/dev
- Reddit r/netsec community: https://reddit.com/r/netsec
- InfoSec community Discord servers

### Related Tools:
- **Masscan:** Faster port scanner for large networks, complements Nmap
- **Zmap:** Internet-wide scanning tool, works with Nmap for detailed analysis  
- **Rustscan:** Modern port scanner that feeds results to Nmap for service detection
