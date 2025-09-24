# 🔧 Network Ranges Scanning - Complete Discovery Guide

Advanced network range scanning techniques for comprehensive host discovery and network topology mapping.
**Location:** `03-host-discovery/network-ranges-scanning.md`

## 🎯 What is Network Range Scanning?

Network range scanning is the systematic process of discovering active hosts across entire network segments or multiple IP ranges. Unlike single host discovery, range scanning involves scanning multiple subnets, CIDR blocks, or custom IP ranges to build a comprehensive network topology map.

This technique is essential for:
- **Network mapping** across multiple subnets
- **Asset discovery** in large environments
- **Network topology visualization**
- **Security assessment** of entire network segments
- **DHCP pool analysis** and static IP identification

## 📦 Installation and Setup

### Prerequisites:
- Nmap (primary scanning tool)
- Basic networking knowledge (CIDR notation, subnetting)
- Understanding of network topology

### Installation:
```bash
# Install nmap if not available
apt update && apt install nmap

# Install additional tools
apt install masscan zmap fping

# Verification
nmap --version
# Expected output: Nmap version 7.80 ( https://nmap.org )
```

### Initial Configuration:
```bash
# Create output directories
mkdir -p ~/network_scans/ranges
mkdir -p ~/network_scans/results

# Set environment variables
export SCAN_DIR=~/network_scans
export THREADS=100
```

## 🔧 Basic Usage and Syntax

### Basic Workflow:
1. **Range Definition:** Identify target network ranges (CIDR, IP ranges)
2. **Host Discovery:** Perform ping sweeps across ranges
3. **Analysis:** Analyze results and identify active networks
4. **Documentation:** Record findings and network topology

### Command Structure:
```bash
# Basic range scanning syntax
nmap [scan_type] [timing] [output] target_range

# Multiple range scanning
nmap -sn 192.168.1.0/24 192.168.2.0/24 10.0.0.0/8

# Advanced range scanning
nmap -sn --min-rate 1000 -oA scan_results target_ranges
```

## ⚙️ Command Line Options

### Range Specification Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `192.168.1.0/24` | CIDR notation scanning | `nmap -sn 192.168.1.0/24` |
| `192.168.1-5.1-254` | Range notation | `nmap -sn 192.168.1-5.1-254` |
| `192.168.1.1,10,20` | Specific IPs | `nmap -sn 192.168.1.1,10,20` |
| `-iL targets.txt` | Input from file | `nmap -sn -iL ranges.txt` |

### Discovery Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-sn` | Ping scan only (no port scan) | `nmap -sn 192.168.1.0/24` |
| `-Pn` | Skip ping, assume hosts up | `nmap -Pn 192.168.1.0/24` |
| `-PS` | TCP SYN ping | `nmap -PS80,443 192.168.1.0/24` |
| `-PA` | TCP ACK ping | `nmap -PA80 192.168.1.0/24` |

### Performance Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `--min-rate` | Minimum packets/sec | `nmap --min-rate 1000 target` |
| `--max-rate` | Maximum packets/sec | `nmap --max-rate 5000 target` |
| `-T4` | Aggressive timing | `nmap -T4 -sn target` |
| `--max-parallelism` | Parallel host scanning | `nmap --max-parallelism 100` |

### Output Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-oA basename` | All output formats | `nmap -sn -oA range_scan target` |
| `-oG greppable` | Greppable format | `nmap -sn -oG range.grep target` |
| `--stats-every` | Progress updates | `nmap --stats-every 30s target` |

## 🧪 Real Lab Examples

### Example 1: Corporate Network Range Discovery
```bash
# Phase 1: Initial range identification
nmap -sn 192.168.1.0/24
# Output: Starting Nmap 7.80 ( https://nmap.org ) at 2024-01-15 10:30
# Nmap scan report for 192.168.1.1
# Host is up (0.001s latency).
# Nmap scan report for 192.168.1.10
# Host is up (0.002s latency).
# ...
# Nmap done: 256 IP addresses (12 hosts up) scanned in 2.58 seconds

# Phase 2: Extended range scanning
nmap -sn 192.168.1-10.0/24
# Output: Scanning multiple subnets
# 192.168.1.0/24: 12 hosts up
# 192.168.2.0/24: 8 hosts up
# 192.168.3.0/24: 0 hosts up
# ...

# Phase 3: Fast comprehensive scan
nmap -sn --min-rate 2000 -T4 10.0.0.0/8 -oA enterprise_discovery
# Output: Nmap scan report saved to enterprise_discovery.*
# Total hosts discovered: 1,247 across enterprise network
```

### Example 2: Multi-Site Network Mapping
```bash
# Step 1: Create target file
cat > network_ranges.txt << EOF
192.168.1.0/24
192.168.10.0/24
10.0.0.0/16
172.16.0.0/12
EOF

# Step 2: Scan all ranges from file
nmap -sn -iL network_ranges.txt -oA multi_site_scan
# Output: Reading targets from network_ranges.txt
# Starting host discovery across 4 network ranges
# Range 1 (192.168.1.0/24): 15 hosts discovered
# Range 2 (192.168.10.0/24): 23 hosts discovered
# Range 3 (10.0.0.0/16): 342 hosts discovered
# Range 4 (172.16.0.0/12): 89 hosts discovered

# Step 3: Analyze results with grep
grep "Host is up" multi_site_scan.gnmap | wc -l
# Output: 469
```

### Example 3: High-Speed Range Scanning with Masscan
```bash
# Ultra-fast range discovery
masscan -p80,443,22,21 192.168.0.0/16 --rate=10000 -oG masscan_results.txt
# Output: Starting masscan 1.0.5 at 2024-01-15 11:45:22 GMT
# Initiating SYN Stealth Scan
# Scanning 65536 hosts [4 ports/host]
# Discovered open port 80/tcp on 192.168.1.100
# Discovered open port 443/tcp on 192.168.1.100
# Discovered open port 22/tcp on 192.168.2.50
# Rate: 9876.54 kpps, 0:01:15 elapsed

# Combine with nmap for detailed discovery
cat masscan_results.txt | grep "Host:" | cut -d" " -f2 | sort -u > active_hosts.txt
nmap -sn -iL active_hosts.txt -oA verified_hosts
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **Network range identification** - 25% of discovery phase
- **CIDR notation mastery** - Critical for proper targeting
- **Multi-subnet scanning** - 20% of network mapping tasks
- **Results analysis and filtering** - Essential for reporting

### Critical Commands to Master:
```bash
# Must-know commands for exam
nmap -sn 192.168.1.0/24                    # Basic range ping sweep
nmap -sn 192.168.1-3.0/24                  # Multiple subnet scan
nmap -sn --min-rate 1000 target_range      # Fast scanning
nmap -sn -iL targets.txt -oA results       # File input with output
```

### eJPT Exam Scenarios:
1. **Corporate Network Discovery:** Scan provided IP ranges to identify all active hosts
   - Required skills: CIDR interpretation, efficient scanning
   - Expected commands: `nmap -sn` with various range notations
   - Success criteria: Complete host inventory with timing efficiency

2. **Multi-Site Assessment:** Discover hosts across multiple network segments
   - Required skills: File-based targeting, result aggregation
   - Expected commands: `nmap -iL`, output parsing with grep/awk
   - Success criteria: Comprehensive network topology mapping

### Exam Tips and Tricks:
- **Time Management:** Use `--min-rate 1000` for faster scans in time-limited scenarios
- **Range Notation:** Master both CIDR (192.168.1.0/24) and dash notation (192.168.1-5.0/24)
- **Output Parsing:** Learn to quickly extract active IPs using `grep "Host is up" *.gnmap`
- **Documentation:** Always use `-oA` to save results in all formats for reporting

### Common eJPT Questions:
- How many active hosts exist in the 192.168.x.x network ranges?
- Which subnets contain the most active hosts?
- Create a comprehensive list of all discovered IP addresses

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Slow Scanning Performance
**Problem:** Range scanning takes too long, especially on large networks
**Cause:** Default timing is too conservative for large ranges
**Solution:**
```bash
# Increase scan speed
nmap -sn --min-rate 2000 -T4 target_range

# For very large ranges, use masscan
masscan --ping 192.168.0.0/16 --rate=10000

# Parallel scanning with xargs
echo "192.168.1.0/24 192.168.2.0/24" | xargs -P 4 -n 1 nmap -sn
```

### Issue 2: Incomplete Host Discovery
**Problem:** Some hosts not detected in ping sweep
**Solution:**
```bash
# Try different ping methods
nmap -PS80,443,22 192.168.1.0/24    # TCP SYN ping
nmap -PA80 192.168.1.0/24           # TCP ACK ping
nmap -PU53 192.168.1.0/24           # UDP ping

# Skip ping and scan directly
nmap -Pn 192.168.1.0/24
```

### Issue 3: Network Filtering/Firewall Interference
**Problem:** Corporate firewalls blocking ICMP or scan attempts
**Prevention:**
```bash
# Use TCP-based discovery methods
nmap -PS80,443,22,21,25 target_range

# Fragment packets to evade simple filters
nmap -sn -f target_range

# Use decoy scanning
nmap -sn -D RND:10 target_range
```

### Issue 4: Memory Issues with Large Ranges
**Problem:** System running out of memory on very large network ranges
**Optimization:**
```bash
# Scan in smaller chunks
for i in {1..254}; do nmap -sn 192.168.$i.0/24; done

# Use memory-efficient tools
fping -a -g 192.168.1.0/24 2>/dev/null

# Limit parallelism
nmap -sn --max-parallelism 50 large_range
```

## 🔗 Integration with Other Tools

### Primary Integration: Range Discovery → Service Enumeration
```bash
# Complete workflow showing tool integration
nmap -sn 192.168.1.0/24 -oG - | grep "Host is up" | cut -d" " -f2 > active_hosts.txt
nmap -sS -p- -iL active_hosts.txt -oA service_scan

# Explanation of each step
# Step 1: Ping sweep discovers active hosts
# Step 2: Service scan focuses on active hosts only
# Step 3: Results feed into vulnerability assessment
```

### Secondary Integration: Masscan → Nmap Validation
```bash
# High-speed discovery followed by detailed verification
masscan --ping 10.0.0.0/8 --rate=5000 -oG masscan_hosts.txt
grep "Host:" masscan_hosts.txt | cut -d" " -f2 > validated_targets.txt
nmap -sn -iL validated_targets.txt -oA confirmed_hosts
```

### Advanced Workflows:
```bash
# Complex multi-stage discovery pipeline
#!/bin/bash
# Stage 1: Fast range discovery
masscan --ping $1 --rate=10000 | grep "Discovered" | cut -d" " -f4 > stage1_hosts.txt

# Stage 2: Nmap validation and service detection
nmap -sS -p80,443,22,21 -iL stage1_hosts.txt -oA stage2_services

# Stage 3: Extract confirmed active hosts
grep "open" stage2_services.gnmap | cut -d" " -f2 | sort -u > final_targets.txt
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** Network topology diagrams, scan progress, and result summaries
2. **Command Outputs:** All scan results in greppable format for analysis
3. **Host Lists:** Organized lists of active hosts by subnet/range
4. **Timing Data:** Scan duration and performance metrics

### Report Template Structure:
```markdown
## Network Range Scanning Results

### Target Information
- Network Ranges: 192.168.1.0/24, 10.0.0.0/16, 172.16.0.0/12
- Scan Date/Time: 2024-01-15 10:30:00 UTC
- Tools Used: Nmap 7.80, Masscan 1.0.5
- Scan Duration: 45 minutes

### Commands Executed
```bash
# Primary discovery commands
nmap -sn 192.168.1.0/24 -oA subnet1_discovery
nmap -sn --min-rate 2000 10.0.0.0/16 -oA corporate_range
masscan --ping 172.16.0.0/12 --rate=5000 -oG masscan_results.txt
```

### Key Findings
- **Total Networks Scanned:** 3 major ranges
- **Active Hosts Discovered:** 1,247 hosts across all ranges
- **Subnet Distribution:**
  - 192.168.1.0/24: 23 active hosts (9% utilization)
  - 10.0.0.0/16: 1,156 active hosts (1.8% utilization)
  - 172.16.0.0/12: 68 active hosts (0.001% utilization)

### Network Topology Summary
- **Highly Active Subnets:** 192.168.1.0/24 (likely DMZ/server segment)
- **Sparsely Populated Ranges:** 172.16.0.0/12 (possible DHCP pool)
- **Corporate Network:** 10.0.0.0/16 (main user network)

### Recommendations
- Focus detailed enumeration on 192.168.1.0/24 (high host density)
- Investigate 10.0.0.0/16 for user workstations and services
- Consider 172.16.0.0/12 as lower priority (sparse population)
```

### Automation Scripts:
```bash
#!/bin/bash
# Automated range scanning and reporting script
RANGES="192.168.1.0/24 10.0.0.0/16 172.16.0.0/12"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTDIR="range_scan_$TIMESTAMP"

mkdir -p $OUTDIR
cd $OUTDIR

for range in $RANGES; do
    echo "Scanning $range..."
    nmap -sn --min-rate 1000 $range -oA "range_$(echo $range | tr '/' '_')"
done

# Generate summary report
echo "Range Scanning Summary - $(date)" > summary_report.txt
for file in *.gnmap; do
    echo "Range: $(basename $file .gnmap)" >> summary_report.txt
    echo "Active hosts: $(grep -c "Host is up" $file)" >> summary_report.txt
    echo "---" >> summary_report.txt
done
```

## 📚 Additional Resources

### Official Documentation:
- Nmap official website: https://nmap.org
- Nmap documentation: https://nmap.org/book/
- Masscan GitHub: https://github.com/robertdavidgraham/masscan

### Learning Resources:
- Nmap Network Scanning book: Comprehensive guide to network discovery
- SANS SEC560: Network penetration testing and ethical hacking
- Practice labs: VulnHub and HackTheBox network challenges

### Community Resources:
- Nmap forums: https://seclists.org/nmap-dev/
- Reddit: r/netsec and r/AskNetsec
- Discord: InfoSec communities with network scanning channels

### Related Tools:
- **Zmap:** Internet-wide scanning alternative to Masscan
- **Fping:** Lightweight ping tool for range scanning
- **Advanced IP Scanner:** Windows-based network discovery tool
