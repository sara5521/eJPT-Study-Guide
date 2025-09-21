# 🔧 Zenmap - GUI Network Discovery and Security Scanner

Zenmap is the official Nmap Security Scanner GUI - a multi-platform (Linux, Windows, Mac OS X, BSD, etc.) free and open-source application that aims to make Nmap easy for beginners to use while providing advanced features for experienced Nmap users.

**Location:** `03-host-discovery/network-mapping/zenmap.md`

## 🎯 What is Zenmap?

Zenmap is the official graphical user interface (GUI) for the Nmap Security Scanner. It is a multi-platform application that makes Nmap easy for beginners to use while providing advanced features for experienced Nmap users. Key capabilities include:

- **Interactive Command Builder** - Visual interface for creating complex Nmap commands
- **Scan Result Visualization** - Graphical representation of network topology
- **Profile Management** - Save and reuse scan configurations
- **Diff Functionality** - Compare scan results over time
- **Network Topology Mapping** - Visual network diagrams with host relationships
- **Searchable Results Database** - Store and search historical scan data

## 📦 Installation and Setup

### Prerequisites:
- Python 2.7 or later
- GTK+ libraries (Linux/Unix)
- Administrative privileges for some scan types

### Installation:

#### Windows:
```bash
# Download from official Nmap website
# https://nmap.org/download.html
# Install using the Windows installer package

# Verification
zenmap --version
# Expected output: Zenmap 7.91 ( https://nmap.org/zenmap/ )
```

#### Linux (Debian/Ubuntu):
```bash
# Installation
sudo apt update
sudo apt install zenmap

# Verification  
zenmap --version
```

#### Linux (Red Hat/CentOS):
```bash
# Installation
sudo yum install zenmap
# or
sudo dnf install zenmap

# Verification
zenmap --version
```

### Initial Configuration:
```bash
# Launch Zenmap
zenmap

# For command-line usage
zenmap --help
```

## 🔧 Basic Usage and Syntax

### Basic Workflow:
1. **Launch Zenmap** - Start the GUI application
2. **Set Target** - Enter IP address, hostname, or network range
3. **Choose Profile** - Select scan type or create custom profile
4. **Execute Scan** - Run the scan and monitor progress
5. **Analyze Results** - Review hosts, services, and topology

### Command Structure:
```bash
# GUI Launch
zenmap

# Command line with target
zenmap --target=10.0.17.0/20

# With specific profile
zenmap --profile="Intense scan"
```

## ⚙️ Command Line Options

### Global Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `--target` | Set scan target | `zenmap --target=192.168.1.0/24` |
| `--profile` | Use predefined profile | `zenmap --profile="Quick scan"` |
| `--command` | Execute specific Nmap command | `zenmap --command="nmap -sS target"` |
| `--help` | Display help information | `zenmap --help` |

### Profile Options:
| Profile | Nmap Command | Purpose |
|---------|--------------|---------|
| **Intense scan** | `nmap -T4 -A -v` | Comprehensive scan with OS detection |
| **Quick scan** | `nmap -T4 -F` | Fast scan of most common ports |
| **Ping scan** | `nmap -sn` | Host discovery only |
| **Regular scan** | `nmap` | Default Nmap scan |

### Output Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `--save` | Save scan results | Results saved automatically in GUI |
| `--export` | Export results | Use GUI File → Export menu |
| `--diff` | Compare scans | Use GUI Tools → Compare Results |

## 🧪 Real Lab Examples

### Example 1: Network Host Discovery
```bash
# Step 1: Check local IP configuration
ipconfig
# Output: IPv4 Address: 10.0.17.63, Subnet Mask: 255.255.240.0

# Step 2: Launch Zenmap and set target
Target: 10.0.17.0/20
Command: nmap -T4 -A -v 10.0.17.0/20

# Step 3: Execute scan
# Output: Starting Nmap 7.91 at 2020-12-26 13:06
# NSE: Loaded 153 scripts for scanning
# Initiating NSE at 13:06
# Completed NSE at 13:06, 0.08s elapsed
# Initiating ARP Ping Scan at 13:06
# Scanning 4095 hosts [1 port/host]
# Completed ARP Ping Scan at 13:06, 14.88s elapsed
```

### Example 2: Service Discovery and Analysis
```bash
# Discovered hosts from lab:
# ip-10-0-16-1.ap-southeast-1.compute.internal (10.0.16.1)
# ip-10-0-17-63.ap-southeast-1.compute.internal (10.0.17.63)  
# ip-10-0-22-246.ap-southeast-1.compute.internal (10.0.22.246)
# ip-10-0-30-248.ap-southeast-1.compute.internal (10.0.30.248)

# Services tab analysis:
# 10.0.30.248:80 - HTTP (HttpFileServer httpd 2.3)
# Multiple hosts with Microsoft Windows RPC on ports 135, 49154, 49155

# Results interpretation:
# - 4 hosts discovered in network range
# - Port 80 (HTTP) found on 10.0.30.248 running HFS 2.3
# - Multiple Windows machines identified via RPC services
```

### Example 3: Network Topology Visualization
```bash
# Navigate to Topology tab in Zenmap
# Enable Fisheye view for network diagram

# Topology analysis from lab:
# Yellow node: 10.0.17.63 (attacker machine/localhost)
# Green nodes: Accessible hosts (10.0.16.1, 10.0.22.246)
# Red node: 10.0.30.248 (alive but limited access)

# Color meanings:
# Green = Machine is accessible/responding
# Red = Machine is alive but not responding/not directly accessible
# Yellow = Local machine (scan origin point)
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **Network Discovery (25%)** - Finding live hosts in target networks
- **Service Enumeration (30%)** - Identifying running services and versions
- **Topology Mapping (20%)** - Understanding network layout and relationships
- **Result Analysis (25%)** - Interpreting scan outputs for vulnerability assessment

### Critical Commands to Master:
```bash
# Host discovery scan
nmap -T4 -A -v 10.0.17.0/20  # Complete network reconnaissance

# Quick service scan
nmap -T4 -F target_ip  # Fast common port scan

# Ping sweep
nmap -sn network_range  # Host discovery without port scan
```

### eJPT Exam Scenarios:
1. **Network Reconnaissance:** Given a network range, identify all live hosts
   - Required skills: Network scanning, CIDR notation understanding
   - Expected commands: `nmap -T4 -A -v network/mask`
   - Success criteria: Complete host inventory with services

2. **Service Identification:** Determine running services on discovered hosts
   - Required skills: Port scanning, service fingerprinting
   - Expected commands: Service enumeration scans
   - Success criteria: Accurate service versions and potential vulnerabilities

### Exam Tips and Tricks:
- **Time Management:** Use Intense scan profile for comprehensive results
- **Documentation:** Always save scan results for report generation
- **Visual Analysis:** Use topology view to understand network relationships
- **Service Focus:** Pay attention to HTTP services and version numbers

### Common eJPT Questions:
- How many hosts are alive in the given network range?
- What services are running on specific ports?
- Which host appears to be the most vulnerable based on service versions?

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Zenmap Won't Start on Windows
**Problem:** Zenmap fails to launch or shows Python errors
**Cause:** Missing Python dependencies or PATH issues
**Solution:**
```bash
# Reinstall with all components
# Download latest Nmap package from nmap.org
# Ensure "Register Path" option is checked during installation

# Verify installation
nmap --version
zenmap --version
```

### Issue 2: Permission Denied for SYN Scans
**Problem:** Cannot perform SYN scans (-sS) from GUI
**Solution:**
```bash
# Run Zenmap as administrator (Windows)
# Right-click → Run as administrator

# Linux - use sudo
sudo zenmap
```

### Issue 3: Slow Scan Performance
**Problem:** Scans taking too long to complete
**Optimization:**
```bash
# Use faster timing template
nmap -T4 target  # Aggressive timing

# Limit port range
nmap -F target   # Fast scan (100 most common ports)

# Reduce host timeout
nmap --host-timeout 30s target
```

### Issue 4: Network Range Discovery Issues
**Problem:** Not finding expected number of hosts
**Prevention:**
```bash
# Verify network range calculation
# Use online CIDR calculators
# Check local network configuration with ipconfig/ifconfig

# Test with ping sweep first
nmap -sn network_range
```

## 🔗 Integration with Other Tools

### Primary Integration: Nmap → Zenmap → Report Tools
```bash
# Workflow: Command line to GUI analysis
nmap -oX scan_results.xml target
# Import XML into Zenmap for visual analysis
# Export results to various formats

# Integration steps:
# 1. Nmap generates XML output
# 2. Zenmap imports and visualizes
# 3. Results exported for reporting
```

### Secondary Integration: Zenmap → Vulnerability Scanners
```bash
# Export discovered hosts for further scanning
# File → Export → Host List (Plain text)
# Use host list with tools like Nikto, SQLmap

# Example workflow:
# Zenmap discovery → Extract HTTP services → Nikto scan
```

### Advanced Workflows:
```bash
# Scheduled scanning with result comparison
# Use Zenmap's diff functionality to track changes
# Tools → Compare Results
# Select two different scan dates for comparison
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** Host discovery results, service enumeration, topology diagrams
2. **Command Outputs:** Full Nmap command strings and results
3. **XML Files:** Exported scan results in XML format
4. **Host Lists:** Extracted lists of discovered hosts and services

### Report Template Structure:
```markdown
## Network Discovery Results

### Scan Information
- Target Range: 10.0.17.0/20
- Scan Date: 2020-12-26 13:06
- Tool Version: Zenmap 7.91
- Profile Used: Intense scan

### Commands Executed
```bash
nmap -T4 -A -v 10.0.17.0/20
```

### Host Discovery Summary
- Total Hosts Scanned: 4,095
- Live Hosts Found: 4
- Services Identified: 15+

### Key Findings
- HTTP service on 10.0.30.248:80 (HFS 2.3)
- Multiple Windows RPC services identified
- Network topology suggests domain environment

### Network Topology
[Include Zenmap topology screenshot]

### Recommendations
- Investigate HTTP service for potential vulnerabilities
- Enumerate Windows services for privilege escalation paths
```

### Automation Scripts:
```bash
# Automated Zenmap scanning script
#!/bin/bash
zenmap --target=$1 --profile="Intense scan" &
sleep 300  # Wait for scan completion
zenmap --export=xml:results_$(date +%Y%m%d).xml
```

## 📚 Additional Resources

### Official Documentation:
- Official Zenmap website: https://nmap.org/zenmap/
- Nmap documentation: https://nmap.org/docs.html
- GitHub repository: https://github.com/nmap/nmap

### Learning Resources:
- Nmap Network Scanning book: Free online version available
- Zenmap tutorial videos: Multiple platforms (YouTube, Cybrary)
- Practice labs: TryHackMe, HackTheBox

### Community Resources:
- Nmap-hackers mailing list: Community support
- Reddit r/netsec: Network security discussions
- Discord servers: Cybersecurity communities

### Related Tools:
- **Nmap (CLI):** Command-line version with more options
- **Masscan:** High-speed port scanner for large networks
- **Zmap:** Internet-wide network scanner for research
