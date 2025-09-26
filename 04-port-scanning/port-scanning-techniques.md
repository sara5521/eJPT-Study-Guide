# 🔧 Port Scanning Techniques - Complete eJPT Study Guide

**Advanced port scanning methodologies for network discovery, service identification, and firewall evasion**  
**Location:** `04-port-scanning/port-scanning-techniques.md`  
**eJPT Weight:** 🔥 **Critical (30% of exam)** 🔥

---

## 📋 Quick Reference Cheat Sheet

```bash
# Essential eJPT Commands (Copy & Paste Ready)
ping -c 3 target                     # Basic connectivity test
nmap target                          # Default scan (1000 common ports)
nmap -Pn target                      # Skip ping - MOST IMPORTANT for eJPT
nmap -Pn -p- target                  # Full port scan (all 65535 ports)
nmap -Pn -sV -p 80,443 target       # Service version detection
nmap -Pn -sC -sV target              # Default scripts + version detection
nmap -Pn -A target                   # Aggressive scan (OS, version, scripts)
nmap -Pn -sU --top-ports 100 target # UDP scan (top 100 ports)
```

---

## 🎯 What is Port Scanning?

Port scanning is the **foundation of penetration testing** - it's your first real look into a target system after host discovery. Think of it as "knocking on doors" to see which services are listening and potentially vulnerable.

**Core Concept:** Send specially crafted packets to TCP/UDP ports to determine:
- **Port State:** Open, Closed, or Filtered
- **Service Type:** HTTP, SSH, FTP, SMB, etc.
- **Service Version:** Apache 2.4.41, OpenSSH 8.0, etc.
- **Operating System:** Windows, Linux, Unix variants

### Why Port Scanning is Critical for eJPT:
1. **Entry Point Discovery** - Find services to attack
2. **Attack Surface Mapping** - Understand what's available
3. **Vulnerability Identification** - Match services to known exploits
4. **Firewall Detection** - Understand network security posture

---

## 📦 Installation and Lab Setup

### Prerequisites Check:
```bash
# Verify Nmap installation and version
nmap --version
# Expected: Nmap version 7.94SVN or higher

# Test network connectivity
ping -c 3 8.8.8.8
# Should show successful packets

# Check if you have root privileges (needed for some scan types)
sudo -l
# Should show sudo permissions
```

### Lab Environment Setup:
```bash
# Create organized workspace
mkdir -p ~/eJPT-labs/port-scanning/$(date +%Y-%m-%d)
cd ~/eJPT-labs/port-scanning/$(date +%Y-%m-%d)

# Set target variables (replace with your lab targets)
export TARGET="demo.ine.local"
export TARGET_IP="10.0.18.217"
export NETWORK="10.0.18.0/24"

# Verify target is reachable
ping -c 3 $TARGET || echo "Target may be blocking ICMP - use -Pn flag"
```

---

## 🔧 Port Scanning Fundamentals

### Understanding Port States:
| State | Meaning | What It Tells You |
|-------|---------|-------------------|
| **Open** | Service listening and accepting connections | **Attack vector available** |
| **Closed** | No service listening, but port reachable | Host is up, but no service |
| **Filtered** | Firewall/filter blocking probe packets | **Security mechanism present** |
| **Open\|Filtered** | Nmap can't determine (UDP scans) | Possible UDP service |
| **Closed\|Filtered** | Nmap can't determine if closed/filtered | Rare state |

### TCP vs UDP Scanning:
```bash
# TCP Scanning (most common in eJPT)
nmap -sS target    # SYN scan (stealth, requires root)
nmap -sT target    # Connect scan (full TCP handshake)
nmap -sA target    # ACK scan (firewall detection)

# UDP Scanning (slower but important)
nmap -sU target    # UDP scan (for DNS, DHCP, SNMP services)
```

---

## ⚙️ Comprehensive Command Reference

### Host Discovery Options:
| Option | Purpose | When to Use | Example |
|--------|---------|-------------|---------|
| `-Pn` | **Skip ping, assume host is up** | **Target blocks ICMP (most eJPT scenarios)** | `nmap -Pn target` |
| `-PS22,80,443` | TCP SYN ping to specific ports | When ICMP blocked but TCP allowed | `nmap -PS80 target` |
| `-PA80` | TCP ACK ping | Bypass stateful firewalls | `nmap -PA80 target` |
| `-PU53` | UDP ping to specific port | Test UDP connectivity | `nmap -PU53 target` |

### Scan Type Options:
| Option | Purpose | Speed | Stealth | eJPT Usage |
|--------|---------|-------|---------|------------|
| `-sS` | **SYN scan (default with root)** | Fast | High | **Primary scan type** |
| `-sT` | Connect scan | Medium | Low | When no root access |
| `-sU` | UDP scan | Very Slow | Medium | **DNS, SNMP discovery** |
| `-sA` | ACK scan | Fast | High | **Firewall detection** |
| `-sF` | FIN scan | Fast | Very High | Firewall evasion |

### Port Specification (Critical for eJPT):
| Option | Ports Scanned | Time | eJPT Scenario |
|--------|---------------|------|---------------|
| `(default)` | Top 1000 common ports | ~30 seconds | **Initial reconnaissance** |
| `-p 80,443,22,21` | Specific ports only | ~5 seconds | **Quick service check** |
| `-p 1-1000` | Port range | ~2-3 minutes | **Focused scanning** |
| `-p-` | **All 65535 ports** | ~10-30 minutes | **Complete enumeration** |
| `--top-ports 100` | Most common 100 ports | ~10 seconds | **Fast overview** |

### Service Detection (High eJPT Value):
| Option | Information Gathered | Time Impact | Example Output |
|--------|---------------------|-------------|----------------|
| `-sV` | **Service version detection** | +50% time | `80/tcp open http Apache httpd 2.4.41` |
| `-sC` | **Default NSE scripts** | +100% time | **Detailed service info** |
| `-A` | **OS + Version + Scripts** | +200% time | **Complete fingerprinting** |
| `--version-intensity 0-9` | Control detection depth | Variable | Higher = more accurate |

---

## 🧪 Real Lab Examples with Step-by-Step Analysis

### Example 1: Basic eJPT Reconnaissance Workflow
```bash
# Step 1: Test basic connectivity
ping -c 3 demo.ine.local
# Output Analysis:
# PING demo.ine.local (10.0.18.217) 56(84) bytes of data.
# --- demo.ine.local ping statistics ---
# 3 packets transmitted, 0 received, 100% packet loss
# ✅ LEARNING POINT: Target blocks ICMP - common in eJPT labs

# Step 2: Default Nmap scan (will likely fail)
nmap demo.ine.local
# Output Analysis:
# Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
# ✅ LEARNING POINT: Nmap relies on ping by default - must use -Pn

# Step 3: Force scan with -Pn (eJPT CRITICAL)
nmap -Pn demo.ine.local
# Output Analysis:
# PORT      STATE    SERVICE
# 80/tcp    open     http
# 135/tcp   open     msrpc
# 139/tcp   open     netbios-ssn
# 445/tcp   open     microsoft-ds
# 3389/tcp  open     ms-wbt-server
# ✅ EXAM INSIGHT: Found Windows target with web, SMB, and RDP services
```

### Example 2: Service Version Detection for Exploitation
```bash
# Step 1: Identify the web service version
nmap -Pn -sV -p 80 demo.ine.local
# Output Analysis:
# 80/tcp open http HttpFileServer httpd 2.3
# ✅ CRITICAL FINDING: HttpFileServer 2.3 - known vulnerable service!

# Step 2: Check for other service versions
nmap -Pn -sV -p 135,139,445,3389 demo.ine.local
# Output Analysis:
# 135/tcp  open  msrpc        Microsoft Windows RPC
# 139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
# 445/tcp  open  microsoft-ds Windows Server 2016 Standard microsoft-ds
# 3389/tcp open  ms-wbt-server Microsoft Terminal Services
# ✅ EXAM STRATEGY: Windows Server 2016 - check for MS17-010, BlueKeep

# Step 3: Run default scripts for more information
nmap -Pn -sC -p 80,445 demo.ine.local
# Output includes SMB shares, HTTP headers, security settings
```

### Example 3: Complete Port Discovery Process
```bash
# Step 1: Quick overview scan
nmap -Pn --top-ports 1000 demo.ine.local
# Time: ~30 seconds, covers 99% of common services

# Step 2: Full port scan (if time allows)
nmap -Pn -p- --min-rate 1000 demo.ine.local
# Time: ~10-15 minutes, discovers hidden services
# Example finding: Port 8080 (alternate HTTP), 1433 (SQL Server)

# Step 3: UDP scan for additional services
nmap -Pn -sU --top-ports 100 demo.ine.local
# Common UDP findings: 53 (DNS), 161 (SNMP), 69 (TFTP)

# Step 4: Comprehensive service detection
OPEN_PORTS=$(nmap -Pn demo.ine.local | grep "open" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
nmap -Pn -sV -sC -p $OPEN_PORTS demo.ine.local
```

### Example 4: Firewall Evasion Techniques
```bash
# Test for firewall presence
nmap -Pn -sA demo.ine.local
# Filtered results indicate firewall

# Try stealth scanning techniques
nmap -Pn -sF demo.ine.local        # FIN scan
nmap -Pn -sX demo.ine.local        # XMAS scan
nmap -Pn -sN demo.ine.local        # NULL scan

# Fragment packets to evade detection
nmap -Pn -f demo.ine.local         # Fragment packets
nmap -Pn -mtu 16 demo.ine.local    # Set MTU size
```

---

## 🎯 eJPT Exam Mastery Section

### Exam Weight Distribution:
- **🔥 Host Discovery with -Pn: 40%** (Most critical skill)
- **🔥 Service Version Detection: 30%** (Essential for exploitation)
- **🔥 Port State Understanding: 20%** (Open vs Filtered vs Closed)
- **🔥 Firewall Detection: 10%** (Understanding network security)

### Must-Master Commands (100% Exam Probability):
```bash
# Command 1: Skip ping discovery (appears in 90% of eJPT scenarios)
nmap -Pn target
# Why critical: Most lab machines block ICMP

# Command 2: Service version detection (needed for exploitation)
nmap -Pn -sV -p port target
# Why critical: Identifies vulnerable service versions

# Command 3: Full port scan (comprehensive enumeration)
nmap -Pn -p- target
# Why critical: Discovers non-standard service ports

# Command 4: Combined scripts and version detection
nmap -Pn -sC -sV target
# Why critical: Maximum information gathering

# Command 5: UDP service discovery
nmap -Pn -sU --top-ports 100 target
# Why critical: Finds DNS, SNMP, and other UDP services
```

### eJPT Exam Scenarios and Solutions:

#### 🎯 Scenario 1: "Target Appears Down"
**Problem:** Your scan shows "Host seems down" but you know it's active
**Solution Process:**
```bash
# Step 1: Confirm with ping
ping -c 3 target
# Expected: 100% packet loss

# Step 2: Force scan without ping
nmap -Pn target
# Expected: Discovers open ports

# Step 3: Document finding
echo "Target blocks ICMP but is active - using -Pn for all future scans"
```
**Exam Answer:** Use `-Pn` flag to skip host discovery

#### 🎯 Scenario 2: "Identify Web Service Version"
**Problem:** Need to find exploitable web service version
**Solution Process:**
```bash
# Step 1: Confirm web service is running
nmap -Pn -p 80,443,8080 target

# Step 2: Get detailed version information
nmap -Pn -sV -p 80 target

# Step 3: Gather additional HTTP information
nmap -Pn -sC -p 80 target
```
**Exam Answer:** `nmap -Pn -sV -p 80 target` provides version details

#### 🎯 Scenario 3: "Find All Running Services"
**Problem:** Complete service enumeration for attack planning
**Solution Process:**
```bash
# Step 1: Quick common port scan
nmap -Pn target

# Step 2: Comprehensive port discovery
nmap -Pn -p- --min-rate 1000 target

# Step 3: Service fingerprinting
nmap -Pn -sV -sC target
```
**Exam Answer:** Use `-p-` for complete port coverage

#### 🎯 Scenario 4: "Detect Firewall Presence"
**Problem:** Determine if target has firewall protection
**Solution Process:**
```bash
# Step 1: Look for filtered ports in scan results
nmap -Pn target | grep "filtered"

# Step 2: Use ACK scan for firewall detection
nmap -Pn -sA target

# Step 3: Try different scan types
nmap -Pn -sF target
```
**Exam Answer:** Filtered ports indicate firewall presence

### Time Management for eJPT:
- **Quick Discovery:** `nmap -Pn target` (30 seconds)
- **Service Check:** `nmap -Pn -sV target` (1-2 minutes)
- **Full Scan:** `nmap -Pn -p- target` (5-15 minutes)
- **Save time:** Focus on common ports first, full scan if needed

### Common eJPT Mistakes to Avoid:
1. **❌ Forgetting -Pn flag** → Target appears down
2. **❌ Not using -sV for versions** → Miss vulnerable services
3. **❌ Ignoring filtered ports** → Miss firewall indicators
4. **❌ Skipping UDP scans** → Miss DNS, SNMP services
5. **❌ Poor time management** → Running unnecessary full scans

---

## ⚠️ Troubleshooting and Problem Solving

### Issue 1: Host Appears Down (90% of eJPT Issues)
**Symptoms:**
```bash
nmap target
# Output: Host seems down. If it is really up, but blocking our ping probes, try -Pn
```
**Root Cause:** Target blocks ICMP ping packets (security measure)
**Solution:**
```bash
# Always use -Pn in eJPT environments
nmap -Pn target

# Alternative: Test with TCP ping
nmap -PS80,443,22 target
```
**Prevention:** Make `-Pn` your default scanning approach

### Issue 2: All Ports Show as Filtered
**Symptoms:**
```bash
nmap -Pn target
# Output: 1000 filtered tcp ports (no-response)
```
**Root Cause:** Aggressive firewall dropping all packets
**Solution:**
```bash
# Try stealth scans
nmap -Pn -sF target      # FIN scan
nmap -Pn -sN target      # NULL scan
nmap -Pn -sA target      # ACK scan for firewall mapping

# Use timing adjustment
nmap -Pn -T2 target      # Slower, more careful
```

### Issue 3: Scanning Takes Too Long
**Symptoms:** Scans running for 30+ minutes
**Root Cause:** Scanning all 65535 ports or slow network
**Solution:**
```bash
# Increase scan speed (carefully)
nmap -Pn --min-rate 1000 target

# Focus on specific ports
nmap -Pn --top-ports 1000 target

# Use timing templates
nmap -Pn -T4 target      # Aggressive timing
```

### Issue 4: Service Detection Fails
**Symptoms:** Ports show as open but no service info
**Solution:**
```bash
# Increase version detection intensity
nmap -Pn -sV --version-intensity 9 -p port target

# Use manual banner grabbing
nc -nv target port
telnet target port

# Try HTTP-specific checks
curl -I http://target:port
```

---

## 🔗 Tool Integration and Workflow

### Primary Workflow: Discovery → Enumeration → Exploitation
```bash
# Phase 1: Initial Discovery
nmap -Pn -oA initial_scan target
grep "open" initial_scan.nmap > open_ports.txt

# Phase 2: Service-Specific Enumeration
# For HTTP services found
nmap -Pn --script http-* -p 80,443,8080 target

# For SMB services found  
nmap -Pn --script smb-* -p 445 target

# For SSH services found
nmap -Pn --script ssh-* -p 22 target

# Phase 3: Vulnerability Assessment
nmap -Pn --script vuln -p $(cat open_ports.txt | cut -d'/' -f1 | tr '\n' ',') target
```

### Integration with Other Tools:
```bash
# Export for other tools
nmap -Pn -oX scan_results.xml target
# Import into: OpenVAS, Nessus, Metasploit

# Feed into service enumeration
nmap -Pn target | grep "80/tcp" && nikto -h http://target
nmap -Pn target | grep "445/tcp" && enum4linux target
nmap -Pn target | grep "22/tcp" && ssh-audit target

# Database integration
nmap -Pn -oX - target | python3 nmap_parser.py > database_import.csv
```

---

## 📝 Documentation and Reporting Templates

### Quick Scan Documentation:
```markdown
## Port Scan Results - [Target Name]

**Target:** demo.ine.local (10.0.18.217)  
**Date:** 2024-07-04  
**Scanner:** Nmap 7.94SVN  

### Executive Summary
- **Total Ports Scanned:** 1000 (top common ports)
- **Open Ports Found:** 7
- **Filtered Ports:** 993 (firewall present)
- **Critical Services:** HTTP (vulnerable version), SMB, RDP

### Open Ports and Services
| Port | State | Service | Version | Risk Level |
|------|-------|---------|---------|------------|
| 80/tcp | Open | HTTP | HttpFileServer 2.3 | 🔴 High |
| 135/tcp | Open | MSRPC | Microsoft Windows RPC | 🟡 Medium |
| 139/tcp | Open | NetBIOS | Microsoft Windows | 🟡 Medium |
| 445/tcp | Open | SMB | Windows Server 2016 | 🔴 High |
| 3389/tcp | Open | RDP | Microsoft Terminal Services | 🟡 Medium |

### Key Findings
1. **HttpFileServer 2.3** - Known vulnerable to CVE-2014-6287
2. **Windows Server 2016** - Potential MS17-010 target
3. **Open RDP** - Brute force attack vector
4. **Firewall Present** - 993 filtered ports indicate security measures

### Next Steps
- [ ] Test HttpFileServer for file upload vulnerabilities
- [ ] Enumerate SMB shares and permissions
- [ ] Check for MS17-010 (EternalBlue) vulnerability
- [ ] Attempt RDP brute force with common credentials
```

### Comprehensive Scan Log:
```bash
# Create detailed scan log
echo "=== Port Scanning Session ===" > scan_log.txt
echo "Date: $(date)" >> scan_log.txt
echo "Target: $TARGET" >> scan_log.txt
echo "Operator: $(whoami)" >> scan_log.txt
echo "" >> scan_log.txt

# Log each command and output
echo "Command: nmap -Pn $TARGET" >> scan_log.txt
nmap -Pn $TARGET | tee -a scan_log.txt
echo "" >> scan_log.txt

echo "Command: nmap -Pn -sV $TARGET" >> scan_log.txt
nmap -Pn -sV $TARGET | tee -a scan_log.txt
```

---

## 🎓 Advanced Techniques and eJPT Pro Tips

### Advanced Nmap Scripting for eJPT:
```bash
# HTTP service enumeration
nmap -Pn --script http-enum,http-headers,http-title -p 80,443 target

# SMB vulnerability assessment
nmap -Pn --script smb-vuln-* -p 445 target

# SSH security assessment
nmap -Pn --script ssh-auth-methods,ssh2-enum-algos -p 22 target

# Database service detection
nmap -Pn --script mysql-info,mysql-enum -p 3306 target
nmap -Pn --script ms-sql-info,ms-sql-enum -p 1433 target
```

### Network Range Scanning for eJPT:
```bash
# Scan entire subnet efficiently
nmap -Pn -sn 192.168.1.0/24 | grep "up" | cut -d' ' -f5 > live_hosts.txt

# Scan multiple targets from file
nmap -Pn -iL live_hosts.txt

# Distributed scanning for large networks
nmap -Pn --top-ports 100 192.168.1.1-50 &
nmap -Pn --top-ports 100 192.168.1.51-100 &
wait
```

### Performance Optimization:
```bash
# Balanced speed and accuracy
nmap -Pn -T4 --min-rate 1000 --max-retries 2 target

# Maximum speed (use carefully)
nmap -Pn -T5 --min-rate 5000 --max-rate 10000 target

# Stealth and accuracy
nmap -Pn -T2 --max-retries 3 target
```

---

## 🏆 eJPT Success Checklist

### Before the Exam:
- [ ] **Master the -Pn flag** - Practice on targets that block ping
- [ ] **Memorize service port numbers** - 80 (HTTP), 443 (HTTPS), 22 (SSH), 445 (SMB)
- [ ] **Practice version detection** - Know when to use -sV vs -A
- [ ] **Understand port states** - Open vs Closed vs Filtered
- [ ] **Time management skills** - Quick scans vs comprehensive scans

### During the Exam:
- [ ] **Always start with `nmap -Pn target`**
- [ ] **Document all findings immediately**
- [ ] **Use -sV on interesting ports for version info**
- [ ] **Look for filtered ports (firewall indicators)**
- [ ] **Save scan results with -oA option**

### Red Flags to Investigate:
- [ ] **HttpFileServer** - Usually vulnerable
- [ ] **Old SSH versions** - Potential exploits available
- [ ] **Windows XP/2003** - Legacy systems with known vulns
- [ ] **Unencrypted services** - Telnet, FTP, HTTP
- [ ] **Database services** - MySQL, MSSQL on non-standard ports

---

## 📚 Additional Learning Resources

### Essential Reading:
- **Nmap Network Scanning** by Gordon Lyon (Creator of Nmap)
- **eJPT Official Study Guide** - INE Security
- **The Art of Network Scanning** - SANS Documentation

### Practice Labs:
- **TryHackMe Nmap Room** - Interactive Nmap training
- **HackTheBox Starting Point** - Guided penetration testing
- **VulnHub Machines** - Downloadable vulnerable VMs
- **INE eJPT Labs** - Official exam preparation environment

### Video Resources:
- **ippsec YouTube Channel** - Real penetration testing demonstrations
- **The Cyber Mentor** - Ethical hacking tutorials
- **SANS SEC560 Preview** - Professional penetration testing course

### Community Support:
- **r/eJPT** - Reddit community for exam discussion
- **Discord: eJPT Study Group** - Real-time help and discussion
- **INE Community Forums** - Official support and Q&A

---

## 🎯 Final eJPT Exam Preparation

### Last-Minute Review Commands:
```bash
# The Big 5 - Commands that appear in 95% of eJPT exams
nmap -Pn target                    # Basic discovery
nmap -Pn -sV target               # Service versions
nmap -Pn -p- target               # Full port scan
nmap -Pn -sC -sV target           # Scripts + versions
nmap -Pn -A target                # Aggressive scan

# UDP scanning (often forgotten but important)
nmap -Pn -sU --top-ports 100 target

# Save everything
nmap -Pn -A -oA complete_scan target
```

### Mental Model for Port Scanning:
1. **"Is it alive?"** → `ping` or `nmap -Pn`
2. **"What's running?"** → `nmap -Pn target`
3. **"What versions?"** → `nmap -Pn -sV target`
4. **"Any vulnerabilities?"** → `nmap -Pn --script vuln target`
5. **"Did I miss anything?"** → `nmap -Pn -p- target`

**Remember:** Port scanning is not just about finding open ports - it's about understanding your target's attack surface and building a mental model of the system you're going to exploit. Every open port is a potential doorway, every service version is a potential vulnerability, and every filtered port tells you something about the security posture.

**Good luck with your eJPT exam! 🎯**
