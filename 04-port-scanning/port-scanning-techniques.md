# 🔧 Port Scanning Techniques - Complete Penetration Testing Guide

Advanced port scanning methodologies for network discovery, service identification, and firewall evasion in penetration testing scenarios.
**Location:** `04-port-scanning/port-scanning-techniques.md`

## 🎯 What is Port Scanning?

Port scanning is a fundamental reconnaissance technique used to discover open ports and running services on target systems. This process involves sending specially crafted packets to specific ports to determine their state (open, closed, or filtered) and identify the services running behind them.

Port scanning serves multiple purposes in penetration testing:
- **Service Discovery:** Identify running services and their versions
- **Attack Surface Mapping:** Determine potential entry points into systems
- **Firewall Detection:** Discover filtering rules and security mechanisms
- **Network Topology Understanding:** Map network infrastructure and connectivity

## 📦 Installation and Setup

### Prerequisites:
- Kali Linux or similar penetration testing distribution
- Basic understanding of TCP/IP protocols
- Network connectivity to target systems
- Proper authorization for testing

### Essential Tools:
```bash
# Verify Nmap installation
nmap --version
# Expected output: Nmap version 7.94SVN

# Install additional tools if needed
apt update && apt install nmap masscan rustscan

# Verify network connectivity
ping -c 3 target_ip
```

### Initial Configuration:
```bash
# Create results directory
mkdir -p ~/port-scans/$(date +%Y-%m-%d)
cd ~/port-scans/$(date +%Y-%m-%d)

# Set up environment variables
export TARGET="demo.ine.local"
export TARGET_IP="10.0.18.217"
```

## 🔧 Basic Usage and Syntax

### Basic Workflow:
1. **Host Discovery:** Verify if target is alive
2. **Port Discovery:** Identify open ports
3. **Service Detection:** Determine running services
4. **Version Detection:** Gather service version information

### Command Structure:
```bash
# Basic Nmap syntax
nmap [scan_type] [options] target

# Common scanning progression
ping -c 5 target                    # Basic connectivity test
nmap target                         # Default scan
nmap -Pn target                     # Skip host discovery
nmap -Pn -sV -p port target        # Service version detection
```

## ⚙️ Command Line Options

### Host Discovery Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-Pn` | Skip host discovery (treat as online) | `nmap -Pn target` |
| `-PS` | TCP SYN ping scan | `nmap -PS22,80,443 target` |
| `-PA` | TCP ACK ping scan | `nmap -PA80 target` |
| `-PU` | UDP ping scan | `nmap -PU53 target` |

### Scan Type Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-sS` | TCP SYN stealth scan (default) | `nmap -sS target` |
| `-sT` | TCP connect scan | `nmap -sT target` |
| `-sU` | UDP scan | `nmap -sU target` |
| `-sA` | ACK scan (firewall detection) | `nmap -sA target` |

### Port Specification:
| Option | Purpose | Example |
|--------|---------|---------|
| `-p 80` | Scan specific port | `nmap -p 80 target` |
| `-p 1-1000` | Scan port range | `nmap -p 1-1000 target` |
| `-p-` | Scan all ports (1-65535) | `nmap -p- target` |
| `--top-ports 1000` | Scan top 1000 ports | `nmap --top-ports 1000 target` |

### Service Detection Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-sV` | Version detection | `nmap -sV -p 80 target` |
| `-sC` | Default script scan | `nmap -sC target` |
| `-A` | Aggressive scan (OS+version+scripts) | `nmap -A target` |
| `-O` | OS detection | `nmap -O target` |

### Output Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-oN` | Normal output to file | `nmap -oN scan.txt target` |
| `-oX` | XML output | `nmap -oX scan.xml target` |
| `-oA` | All output formats | `nmap -oA scan_results target` |
| `-v` | Verbose output | `nmap -v target` |

## 🧪 Real Lab Examples

### Example 1: Basic Host Discovery and Port Scanning
```bash
# Phase 1: Initial connectivity test
ping -c 5 demo.ine.local
# Output: PING demo.ine.local (10.0.18.217) 56(84) bytes of data
# --- demo.ine.local ping statistics ---
# 5 packets transmitted, 0 received, 100% packet loss, time 4115ms

# Phase 2: Basic Nmap scan (host appears down)
nmap demo.ine.local
# Output: Starting Nmap 7.94SVN
# Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
# Nmap done: 1 IP address (0 hosts up) scanned in 3.06 seconds

# Phase 3: Force scan with -Pn option
nmap -Pn demo.ine.local
# Output: Starting Nmap 7.94SVN at 2024-07-04 13:30 IST
# Nmap scan report for demo.ine.local (10.0.18.217)
# Host is up (0.0023s latency)
# Not shown: 993 filtered tcp ports (no-response)
# PORT      STATE SERVICE
# 80/tcp    open  http
# 135/tcp   open  msrpc
# 139/tcp   open  netbios-ssn
# 445/tcp   open  microsoft-ds
# 3389/tcp  open  ms-wbt-server
# 49154/tcp open  unknown
# 49155/tcp open  unknown
```

### Example 2: Specific Port Testing and Service Detection
```bash
# Test specific port that appears filtered
nmap -Pn -p 443 demo.ine.local
# Output: Starting Nmap 7.94SVN at 2024-07-04 13:31 IST
# Nmap scan report for demo.ine.local (10.0.18.217)
# Host is up
# PORT      STATE    SERVICE
# 443/tcp   filtered https
# Nmap done: 1 IP address (1 host up) scanned in 2.05 seconds

# Service version detection on open port
nmap -Pn -sV -p 80 demo.ine.local
# Output: Starting Nmap 7.94SVN at 2024-07-04 13:32 IST
# Nmap scan report for demo.ine.local (10.0.18.217)
# Host is up (0.00285 latency)
# PORT   STATE SERVICE VERSION
# 80/tcp open  http    HttpFileServer httpd 2.3
# Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
# Service detection performed. Please report any incorrect results at https://nmap.org/submit/
# Nmap done: 1 IP address (1 host up) scanned in 6.34 seconds
```

### Example 3: Comprehensive Scanning with Different Techniques
```bash
# Full TCP port scan
nmap -Pn -p- --min-rate 1000 demo.ine.local
# Output: Discovers all 65535 ports (time-intensive)

# UDP scan on common ports
nmap -Pn -sU --top-ports 100 demo.ine.local
# Output: UDP service discovery

# Stealth scan with service detection
nmap -Pn -sS -sV -O demo.ine.local
# Output: Complete service and OS fingerprinting

# Script scan for additional information
nmap -Pn -sC -p 80,135,139,445 demo.ine.local
# Output: Default scripts provide detailed service information
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **Host Discovery Techniques (25%)** - Bypassing ICMP filtering with -Pn
- **Port State Understanding (30%)** - Distinguishing between open, closed, filtered
- **Service Identification (25%)** - Using -sV for version detection
- **Firewall Detection (20%)** - Recognizing filtered ports and evasion

### Critical Commands to Master:
```bash
# Essential eJPT scanning commands
ping -c 5 target                    # Basic connectivity test
nmap target                         # Default discovery scan
nmap -Pn target                     # Skip ping, force scan
nmap -Pn -p- target                 # Full port scan
nmap -Pn -sV -p port target         # Service version detection
nmap -Pn -sC -sV target             # Script + version scan
nmap -Pn -A target                  # Aggressive comprehensive scan
```

### eJPT Exam Scenarios:

1. **Scenario 1: Firewall Evasion**
   - Required skills: Understanding filtered vs closed ports
   - Expected commands: `nmap -Pn target`, `nmap -sA target`
   - Success criteria: Identify live hosts behind firewalls

2. **Scenario 2: Service Enumeration**
   - Required skills: Version detection and service identification
   - Expected commands: `nmap -sV -p ports target`
   - Success criteria: Identify vulnerable service versions

3. **Scenario 3: Network Mapping**
   - Required skills: Comprehensive port discovery
   - Expected commands: `nmap -Pn -p- --min-rate 1000 target`
   - Success criteria: Map complete attack surface

### Exam Tips and Tricks:
- **Tip 1: Always use -Pn option** - Many exam targets don't respond to ping
- **Tip 2: Start with default scan, then get specific** - Efficient time management
- **Tip 3: Document filtered ports** - They often indicate firewall presence
- **Tip 4: Use -sV for known open ports** - Version info crucial for exploitation

### Common eJPT Questions:
- How to scan hosts that don't respond to ping?
- What's the difference between filtered and closed ports?
- How to identify service versions on open ports?
- Which Nmap option skips host discovery?

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Target Appears Down But Is Actually Up
**Problem:** Nmap shows "Host seems down" even when target is accessible
**Cause:** ICMP filtering or host-based firewall blocking ping probes
**Solution:**
```bash
# Force scan without ping
nmap -Pn target
# Alternative: Use different ping methods
nmap -PS80,443 target
nmap -PA80 target
```

### Issue 2: All Ports Show as Filtered
**Problem:** Every scanned port returns "filtered" state
**Cause:** Firewall dropping packets without ICMP responses
**Solution:**
```bash
# Try different scan types
nmap -sA target          # ACK scan for firewall detection
nmap -sF target          # FIN scan
nmap -sX target          # XMAS scan
nmap --scanflags URG,ACK,PSH,RST,SYN,FIN target
```

### Issue 3: Slow Scanning Performance
**Problem:** Scans taking excessively long to complete
**Solution:**
```bash
# Increase scan speed (be careful with timing)
nmap --min-rate 1000 target
nmap -T4 target
# Focus on specific ports instead of full range
nmap --top-ports 1000 target
```

### Issue 4: Incomplete Service Detection
**Problem:** Service versions not detected properly
**Solution:**
```bash
# Increase service detection intensity
nmap -sV --version-intensity 9 target
# Combine with scripts for more info
nmap -sV -sC target
# Manual service testing
nc -nv target port
```

## 🔗 Integration with Other Tools

### Primary Integration: Nmap → Service Enumeration → Exploitation
```bash
# Complete workflow showing tool integration
nmap -Pn -sV -oA initial_scan target

# Parse results for specific services
grep "open" initial_scan.nmap | grep "http"
# Follow up with HTTP-specific tools
nikto -h http://target
dirb http://target

# For SMB services discovered
grep "445/tcp" initial_scan.nmap
smbclient -L target
enum4linux target
```

### Secondary Integration: Nmap → Vulnerability Assessment
```bash
# Nmap script engine for vulnerability detection
nmap --script vuln target
# Feed results into vulnerability scanners
nmap -oX scan.xml target
# Import into OpenVAS or Nessus for detailed assessment
```

### Advanced Workflows:
```bash
# Automated reconnaissance pipeline
nmap -Pn -sS -oA discovery target_network/24
# Extract live hosts
grep "Up" discovery.gnmap | cut -d" " -f2 > live_hosts.txt
# Detailed scan of live hosts
nmap -Pn -sV -sC -oA detailed -iL live_hosts.txt
# Service-specific enumeration
for host in $(cat live_hosts.txt); do
  nmap --script http-* -p 80,443,8080 $host
done
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** Command execution and results for each scan type
2. **Command Outputs:** Save all Nmap results in multiple formats (-oA)
3. **Log Files:** Preserve timing and performance metrics
4. **Network Diagrams:** Document discovered services and their relationships

### Report Template Structure:
```markdown
## Port Scanning Results

### Target Information
- Target: demo.ine.local (10.0.18.217)
- Date/Time: 2024-07-04 13:30 IST
- Scanner: Nmap 7.94SVN

### Commands Executed
```bash
# Initial connectivity test
ping -c 5 demo.ine.local

# Host discovery bypass
nmap -Pn demo.ine.local

# Service version detection
nmap -Pn -sV -p 80 demo.ine.local
```

### Key Findings
- **Firewall Detected:** Host does not respond to ICMP ping
- **Open Services:** HTTP (80), MSRPC (135), SMB (445), RDP (3389)
- **Filtered Ports:** HTTPS (443) - potential firewall rule
- **Service Versions:** HttpFileServer httpd 2.3 on port 80

### Port State Summary
- **Open Ports:** 7 (http, msrpc, netbios-ssn, microsoft-ds, ms-wbt-server, unknown x2)
- **Filtered Ports:** 993 (likely firewall-protected)
- **Closed Ports:** 0 (not explicitly closed)

### Security Implications
- Multiple Windows services exposed (SMB, RDP)
- Web service running potentially vulnerable HttpFileServer
- Firewall present but allows certain services through

### Recommendations
- Investigate HttpFileServer version 2.3 for known vulnerabilities
- Review firewall rules for port 443 filtering
- Consider restricting RDP access to specific networks
- Audit SMB share permissions and access controls
```

### Automation Scripts:
```bash
#!/bin/bash
# automated_port_scan.sh - Comprehensive scanning script

TARGET=$1
DATE=$(date +%Y%m%d_%H%M%S)
OUTDIR="scans_${DATE}"

mkdir -p $OUTDIR
cd $OUTDIR

echo "Starting automated port scanning for $TARGET"

# Phase 1: Host Discovery
echo "Phase 1: Host Discovery"
nmap -Pn -oA 01_discovery $TARGET

# Phase 2: Full Port Scan
echo "Phase 2: Full Port Discovery"
nmap -Pn -p- --min-rate 1000 -oA 02_full_ports $TARGET

# Phase 3: Service Detection
echo "Phase 3: Service Detection"
OPEN_PORTS=$(grep "open" 02_full_ports.gnmap | grep -o '[0-9]*/open/tcp' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
if [ ! -z "$OPEN_PORTS" ]; then
  nmap -Pn -sV -sC -p $OPEN_PORTS -oA 03_services $TARGET
fi

# Phase 4: Vulnerability Scripts
echo "Phase 4: Vulnerability Assessment"
nmap -Pn --script vuln -p $OPEN_PORTS -oA 04_vulns $TARGET

echo "Scanning completed. Results saved in $OUTDIR/"
```

## 📚 Additional Resources

### Official Documentation:
- Official Nmap website: https://nmap.org
- Nmap documentation: https://nmap.org/book/
- NSE Script database: https://nmap.org/nsedoc/

### Learning Resources:
- Nmap Network Scanning book (Gordon Lyon): Comprehensive reference
- SANS SEC560 course: Network penetration testing methodology
- Cybrary Nmap courses: Free online training modules

### Community Resources:
- r/netsec: Reddit community for network security
- Nmap mailing lists: Active community support
- Stack Overflow: Technical Q&A for specific issues

### Related Tools:
- **Masscan:** High-speed port scanner for large networks
- **RustScan:** Modern port scanner with faster performance
- **Zmap:** Internet-wide network scanner
- **Unicornscan:** Asynchronous network stimulus delivery engine
