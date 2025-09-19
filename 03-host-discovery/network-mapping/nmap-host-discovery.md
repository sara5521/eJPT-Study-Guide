# 🔧 Nmap Host Discovery - Comprehensive Network Reconnaissance

Network mapping and host discovery using Nmap to identify live hosts, open ports, and running services in target networks.
**Location:** `03-host-discovery/network-mapping/nmap-host-discovery.md`

## 🎯 What is Nmap Host Discovery?

Nmap (Network Mapper) host discovery is the process of identifying active hosts on a network without performing full port scans. It's essential for penetration testing as it helps map the network topology and identify potential targets. Key capabilities include:

- **Ping Scanning:** Various methods to detect live hosts
- **Port Discovery:** Identifying open ports and services
- **Service Detection:** Determining versions and applications
- **Firewall Detection:** Identifying filtered ports and security measures

## 📦 Installation and Setup

### Prerequisites:
- Kali Linux (pre-installed) or compatible Linux distribution
- Network access to target systems
- Appropriate authorization for testing

### Installation:
```bash
# Verify Nmap installation (pre-installed on Kali)
nmap --version
# Expected output: Nmap version 7.94SVN ( https://nmap.org )

# Update Nmap (if needed)
sudo apt update && sudo apt install nmap
```

### Initial Configuration:
```bash
# Verify network interface
ip addr show

# Check routing table
ip route show

# Test basic connectivity
ping -c 4 8.8.8.8
```

## 🔧 Basic Usage and Syntax

### Basic Workflow:
1. **Host Discovery:** Determine which hosts are alive
2. **Port Scanning:** Identify open ports on live hosts
3. **Service Detection:** Determine service versions
4. **Vulnerability Assessment:** Check for common security issues

### Command Structure:
```bash
# Basic syntax
nmap [scan_type] [options] target

# Host discovery workflow
ping target                    # Basic connectivity test
nmap target                   # Default scan
nmap -Pn target              # Skip ping, force scan
nmap -sV target              # Service version detection
```

## ⚙️ Command Line Options

### Host Discovery Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-Pn` | Skip host discovery (treat as online) | `nmap -Pn demo.ine.local` |
| `-sn` | Ping scan only, no port scan | `nmap -sn 192.168.1.0/24` |
| `-PS` | TCP SYN ping | `nmap -PS80,443 target` |
| `-PA` | TCP ACK ping | `nmap -PA80 target` |

### Port Scanning Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-p` | Specify ports | `nmap -p 80,443 target` |
| `-p-` | Scan all ports | `nmap -p- target` |
| `-sS` | TCP SYN scan (default) | `nmap -sS target` |
| `-sV` | Version detection | `nmap -sV target` |

### Output Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-v` | Verbose output | `nmap -v target` |
| `-oN` | Normal output to file | `nmap -oN scan.txt target` |
| `-oX` | XML output | `nmap -oX scan.xml target` |
| `-A` | Aggressive scan | `nmap -A target` |

## 🧪 Real Lab Examples

### Example 1: Basic Connectivity Test (INE Lab Scenario)
```bash
# Step 1: Initial ping test
ping -c 5 demo.ine.local
# Output: PING demo.ine.local (10.0.18.217) 56(84) bytes of data.
# Result: 5 packets transmitted, 0 received, 100% packet loss

# Step 2: Basic nmap scan
nmap demo.ine.local
# Output: Starting Nmap 7.94SVN at 2024-07-04 13:29 IST
# Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
# Nmap done: 1 IP address (0 hosts up) scanned in 3.06 seconds
```

### Example 2: Bypassing Ping with -Pn Option
```bash
# Step 3: Force scan bypassing ping
nmap -Pn demo.ine.local
# Output: Starting Nmap 7.94SVN at 2024-07-04 13:30 IST
# Nmap scan report for demo.ine.local (10.0.18.217)
# Host is up (0.002s latency).
# Not shown: 993 filtered tcp ports (no-response)
# PORT     STATE SERVICE
# 80/tcp   open  http
# 135/tcp  open  msrpc
# 139/tcp  open  netbios-ssn
# 445/tcp  open  microsoft-ds
# 3389/tcp open  ms-wbt-server
# 49154/tcp open unknown
# 49155/tcp open unknown
# Nmap done: 1 IP address (1 host up) scanned in 4.47 seconds
```

### Example 3: Testing Specific Closed Port
```bash
# Step 4: Test a specific port that should be filtered
nmap -Pn -p 443 demo.ine.local
# Output: Starting Nmap 7.94SVN at 2024-07-04 13:31 IST
# Nmap scan report for demo.ine.local (10.0.18.217)
# Host is up.
# PORT    STATE    SERVICE
# 443/tcp filtered https
# Nmap done: 1 IP address (1 host up) scanned in 2.05 seconds
```

### Example 4: Service Version Detection
```bash
# Step 5: Discover service versions on open ports
nmap -Pn -sV -p 80 demo.ine.local
# Output: Starting Nmap 7.94SVN at 2024-07-04 13:32 IST
# Nmap scan report for demo.ine.local (10.0.18.217)
# Host is up (0.002s latency).
# PORT   STATE SERVICE VERSION
# 80/tcp open  http    HttpFileServer httpd 2.3
# Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
# Service detection performed. Please report any incorrect results at https://nmap.org/submit/
# Nmap done: 1 IP address (1 host up) scanned in 6.34 seconds
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **Host Discovery (25%)** - Identifying live hosts behind firewalls
- **Port Enumeration (30%)** - Finding open services and applications
- **Service Fingerprinting (20%)** - Determining service versions
- **Firewall Detection (25%)** - Understanding filtered vs closed ports

### Critical Commands to Master:
```bash
# Must-know commands for eJPT exam
nmap -Pn target                    # Bypass ping, essential for Windows targets
nmap -sV target                    # Service version detection
nmap -p- target                    # Full port scan
nmap -sS -sV -O target            # Comprehensive scan with OS detection
```

### eJPT Exam Scenarios:
1. **Windows Host Behind Firewall:** 
   - Required skills: Using `-Pn` flag to bypass ICMP filtering
   - Expected commands: `nmap -Pn target`, `nmap -Pn -sV target`
   - Success criteria: Identifying open ports despite ping filtering

2. **Service Enumeration for Exploitation:**
   - Required skills: Version detection and service identification
   - Expected commands: `nmap -sV -p 80,443,21,22 target`
   - Success criteria: Finding vulnerable service versions

3. **Network Mapping and Reconnaissance:**
   - Required skills: Subnet scanning and host discovery
   - Expected commands: `nmap -sn 192.168.1.0/24`, `nmap -Pn -p- live_host`
   - Success criteria: Complete network topology mapping

### Exam Tips and Tricks:
- **Always use -Pn for Windows targets** - Windows often blocks ICMP
- **Start with common ports** before full scans to save time
- **Document filtered vs closed ports** - indicates firewall presence
- **Use -sV for service enumeration** - essential for finding exploit targets

### Common eJPT Questions:
- How to scan hosts that don't respond to ping?
- What's the difference between filtered and closed ports?
- How to identify service versions for vulnerability assessment?

## ⚠️ Common Issues & Troubleshooting

### Issue 1: "Host seems down" Error
**Problem:** Target appears offline but is actually protected by firewall
**Cause:** ICMP ping probes are being blocked by firewall or host configuration
**Solution:**
```bash
# Use -Pn flag to skip ping discovery
nmap -Pn target_ip
# Alternative: Use different ping methods
nmap -PS80,443 target_ip
```

### Issue 2: All Ports Show as "Filtered"
**Problem:** All scanned ports return filtered state
**Cause:** Aggressive firewall blocking or rate limiting
**Solution:**
```bash
# Reduce scan speed and timing
nmap -Pn -T2 target_ip
# Try specific ports known to be open
nmap -Pn -p 80,443,21,22 target_ip
```

### Issue 3: Slow Scanning Performance
**Problem:** Scans taking too long to complete
**Optimization:**
```bash
# Increase timing template (careful with detection)
nmap -Pn -T4 target_ip
# Scan specific ports only
nmap -Pn -p 1-1000 target_ip
```

### Issue 4: Permission Denied for SYN Scans
**Problem:** Cannot perform SYN scan without privileges
**Solution:**
```bash
# Run with sudo for raw socket access
sudo nmap -sS target_ip
# Alternative: Use connect scan (no privileges needed)
nmap -sT target_ip
```

## 🔗 Integration with Other Tools

### Primary Integration: Ping → Nmap → Service Enumeration
```bash
# Complete reconnaissance workflow
ping -c 1 target_ip              # Basic connectivity
nmap -Pn target_ip               # Host discovery and port scan
nmap -Pn -sV -p ports target_ip  # Service version detection

# Feed results to specialized tools
nmap -Pn -p 80 --script http-enum target_ip
nmap -Pn -p 445 --script smb-enum-shares target_ip
```

### Secondary Integration: Nmap → Vulnerability Scanners
```bash
# Export results for further analysis
nmap -Pn -sV -oX nmap_results.xml target_ip
# Import to vulnerability scanners like OpenVAS or Nessus
```

### Advanced Workflows:
```bash
# Automated reconnaissance pipeline
nmap -sn network/24 | grep "Nmap scan report" | cut -d " " -f 5 > live_hosts.txt
while read host; do nmap -Pn -sV $host; done < live_hosts.txt
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** Terminal outputs showing scan results and host status
2. **Command Outputs:** Save all nmap scan results with timestamps
3. **Network Diagrams:** Document discovered hosts and open services
4. **Service Lists:** Maintain inventory of identified applications and versions

### Report Template Structure:
```markdown
## Host Discovery Results

### Target Information
- Target: demo.ine.local (10.0.18.217)
- Scan Date: 2024-07-04 13:30 IST
- Nmap Version: 7.94SVN

### Commands Executed
```bash
# Host discovery attempts
ping -c 5 demo.ine.local          # Failed - 100% packet loss
nmap demo.ine.local              # Host appears down
nmap -Pn demo.ine.local          # Successful bypass
nmap -Pn -sV -p 80 demo.ine.local # Service detection
```

### Key Findings
- **Host Status:** Active but blocks ICMP ping probes
- **Open Ports:** 80, 135, 139, 445, 3389, 49154, 49155
- **Filtered Ports:** 443 (HTTPS) - likely firewall blocking
- **Critical Service:** HttpFileServer httpd 2.3 on port 80

### Security Implications
- Windows host with RDP (3389) and SMB (445) exposed
- Web service running potentially vulnerable HttpFileServer
- Firewall configured but inconsistent port filtering
```

### Automation Scripts:
```bash
#!/bin/bash
# Host discovery automation script
target=$1
echo "Starting host discovery for $target"
echo "================================"

# Test connectivity
echo "[+] Testing basic connectivity..."
ping -c 3 $target

# Nmap host discovery
echo "[+] Running Nmap host discovery..."
nmap -Pn $target

# Service detection on common ports
echo "[+] Service detection on common ports..."
nmap -Pn -sV -p 21,22,23,25,53,80,110,443,993,995 $target
```

## 📚 Additional Resources

### Official Documentation:
- Nmap Official Website: https://nmap.org
- Nmap Documentation: https://nmap.org/book/
- NSE Script Database: https://nmap.org/nsedoc/

### Learning Resources:
- "Nmap Network Scanning" by Gordon Lyon: Complete reference guide
- INE eJPT Course: Practical lab exercises with real scenarios
- Cybrary Nmap Course: Free video tutorials and exercises

### Community Resources:
- r/netsec: Reddit community for network security discussions
- Nmap Development Mailing List: Technical discussions and updates
- SANS Pen Testing Community: Professional networking and knowledge sharing

### Related Tools:
- **Masscan:** High-speed port scanner for large networks
- **Zmap:** Internet-wide network scanner
- **Netdiscover:** ARP-based network discovery tool for local networks
