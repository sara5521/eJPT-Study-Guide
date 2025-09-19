# 🌐 Subnetting - Network Segmentation Fundamentals

**Master IP subnetting for effective network reconnaissance and penetration testing**
**Location:** `01-theory-foundations/networking-basics/subnetting.md`

## 🎯 What is Subnetting?

Subnetting is the practice of dividing a large network into smaller, more manageable subnetworks (subnets). This process involves borrowing bits from the host portion of an IP address to create additional network segments. For penetration testers, understanding subnetting is crucial for network reconnaissance, identifying network boundaries, planning attack strategies, and understanding network topology during assessments.

Subnetting knowledge helps pentesters determine network scope, identify potential pivot points, and understand how networks are segmented for security purposes.

## 📦 IP Address Structure Fundamentals

### IPv4 Address Components:
```bash
# IP Address: 192.168.1.100/24
# 192.168.1.100 = Host IP Address
# /24 = Subnet Mask (CIDR notation)
# 255.255.255.0 = Subnet Mask (dotted decimal)

# Binary representation:
# 192.168.1.100 = 11000000.10101000.00000001.01100100
# 255.255.255.0 = 11111111.11111111.11111111.00000000
```

### Network Classes (Legacy but still relevant):
```bash
# Class A: 1.0.0.0 to 126.255.255.255 (/8)
# Default mask: 255.0.0.0
# Private range: 10.0.0.0/8

# Class B: 128.0.0.0 to 191.255.255.255 (/16)  
# Default mask: 255.255.0.0
# Private range: 172.16.0.0/12

# Class C: 192.0.0.0 to 223.255.255.255 (/24)
# Default mask: 255.255.255.0
# Private range: 192.168.0.0/16
```

## 🔧 CIDR Notation and Subnet Masks

### CIDR to Subnet Mask Conversion:
```bash
# Common CIDR notations and their meanings
/8  = 255.0.0.0     (16,777,214 hosts)
/16 = 255.255.0.0   (65,534 hosts)
/24 = 255.255.255.0 (254 hosts)
/25 = 255.255.255.128 (126 hosts)
/26 = 255.255.255.192 (62 hosts)
/27 = 255.255.255.224 (30 hosts)
/28 = 255.255.255.240 (14 hosts)
/29 = 255.255.255.248 (6 hosts)
/30 = 255.255.255.252 (2 hosts)
```

### Subnet Calculation Process:
```bash
# Example: 192.168.1.0/26
# Step 1: Determine subnet mask
# /26 = 255.255.255.192

# Step 2: Calculate subnet size
# 32 - 26 = 6 host bits
# 2^6 = 64 addresses per subnet

# Step 3: List subnets
# 192.168.1.0/26   (0-63)
# 192.168.1.64/26  (64-127)
# 192.168.1.128/26 (128-191)
# 192.168.1.192/26 (192-255)
```

## ⚙️ Subnetting Reference Tables

### CIDR Notation Quick Reference:
| CIDR | Subnet Mask | Wildcard Mask | Hosts per Subnet | Number of Subnets (in /24) |
|------|-------------|---------------|------------------|----------------------------|
| /24 | 255.255.255.0 | 0.0.0.255 | 254 | 1 |
| /25 | 255.255.255.128 | 0.0.0.127 | 126 | 2 |
| /26 | 255.255.255.192 | 0.0.0.63 | 62 | 4 |
| /27 | 255.255.255.224 | 0.0.0.31 | 30 | 8 |
| /28 | 255.255.255.240 | 0.0.0.15 | 14 | 16 |
| /29 | 255.255.255.248 | 0.0.0.7 | 6 | 32 |
| /30 | 255.255.255.252 | 0.0.0.3 | 2 | 64 |

### Binary Subnet Mask Table:
| CIDR | Last Octet Binary | Last Octet Decimal | Subnet Increment |
|------|-------------------|-------------------|------------------|
| /24 | 00000000 | 0 | 256 |
| /25 | 10000000 | 128 | 128 |
| /26 | 11000000 | 192 | 64 |
| /27 | 11100000 | 224 | 32 |
| /28 | 11110000 | 240 | 16 |
| /29 | 11111000 | 248 | 8 |
| /30 | 11111100 | 252 | 4 |

### Common Private Network Subnets:
| Network | CIDR | Subnet Mask | Host Range | Broadcast |
|---------|------|-------------|------------|-----------|
| Class A Private | 10.0.0.0/8 | 255.0.0.0 | 10.0.0.1 - 10.255.255.254 | 10.255.255.255 |
| Class B Private | 172.16.0.0/12 | 255.240.0.0 | 172.16.0.1 - 172.31.255.254 | 172.31.255.255 |
| Class C Private | 192.168.0.0/16 | 255.255.0.0 | 192.168.0.1 - 192.168.255.254 | 192.168.255.255 |

## 🧪 Real Lab Examples

### Example 1: Network Discovery with Subnetting
```bash
# Discovering the current subnet
ip addr show
# Output: inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0

# Calculate subnet details for 192.168.1.0/24
# Network: 192.168.1.0
# Broadcast: 192.168.1.255  
# Usable range: 192.168.1.1 - 192.168.1.254
# Total hosts: 254

# Scan the entire subnet
nmap -sn 192.168.1.0/24
# Output: Discovers all active hosts in the subnet
# Nmap scan report for 192.168.1.1
# Nmap scan report for 192.168.1.100
# Nmap scan report for 192.168.1.150
```

### Example 2: Subnet Enumeration in Different Networks
```bash
# Example: Target network 10.10.10.0/26
# Calculate subnet boundaries
# /26 = 255.255.255.192 (64 addresses per subnet)
# Subnets: 10.10.10.0/26, 10.10.10.64/26, 10.10.10.128/26, 10.10.10.192/26

# Scan specific subnet
nmap -sn 10.10.10.0/26
# Output: Scans 10.10.10.1 - 10.10.10.62 (usable range)

# Scan multiple subnets efficiently
nmap -sn 10.10.10.0/24
# Output: Scans entire /24 network including all /26 subnets
```

### Example 3: VLSM (Variable Length Subnet Masking) Analysis
```bash
# Enterprise network with multiple subnet sizes
# Main network: 172.16.0.0/16

# Subnet 1: Servers (/27 - 30 hosts)
nmap -sn 172.16.1.0/27
# Range: 172.16.1.1 - 172.16.1.30

# Subnet 2: Workstations (/24 - 254 hosts)  
nmap -sn 172.16.2.0/24
# Range: 172.16.2.1 - 172.16.2.254

# Subnet 3: Point-to-point links (/30 - 2 hosts)
nmap -sn 172.16.3.0/30
# Range: 172.16.3.1 - 172.16.3.2
```

### Example 4: Subnet Route Discovery
```bash
# Analyze routing table for subnet information
ip route show
# Output:
# default via 192.168.1.1 dev eth0
# 192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100
# 10.10.10.0/24 via 192.168.1.1 dev eth0

# Traceroute to understand network topology
traceroute 10.10.10.100
# Output: Shows routing path between subnets
# 1  192.168.1.1 (192.168.1.1)  1.234 ms
# 2  10.10.10.1 (10.10.10.1)    5.678 ms
# 3  10.10.10.100 (10.10.10.100)  2.345 ms
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT (25% of networking fundamentals):
- **Subnet calculation** and network boundary identification (35%)
- **Network scope determination** for penetration testing (30%)
- **Subnet scanning** and host discovery techniques (25%)
- **Network topology understanding** through routing analysis (10%)

### Critical Calculations to Master:
```bash
# Quick subnet calculations
# Given: 192.168.1.0/27
# Hosts per subnet: 2^(32-27) - 2 = 30 hosts
# Network increment: 256 - 224 = 32
# Subnets: .0, .32, .64, .96, .128, .160, .192, .224

# Subnet identification from IP
# Given IP: 192.168.1.50/27
# Subnet: 192.168.1.32/27 (because 50 falls in 32-63 range)
# Range: 192.168.1.33 - 192.168.1.62 (usable)
```

### Essential Commands for eJPT:
```bash
# Network discovery commands
nmap -sn network/cidr           # Ping sweep
nmap -sn 192.168.1.0/24        # Specific example

# Route analysis
ip route show                   # Linux routing table
route -n                       # Alternative routing table view

# Interface analysis  
ip addr show                    # Interface configuration
ifconfig                       # Alternative interface view
```

### eJPT Exam Scenarios:
1. **Network Scope Definition:** Determining penetration testing boundaries
   - Required skills: CIDR calculation and subnet identification
   - Expected commands: Network discovery with proper CIDR notation
   - Success criteria: Complete network mapping within scope

2. **Subnet Enumeration:** Discovering all subnets in target environment
   - Required skills: Subnet calculation and systematic scanning
   - Expected commands: Multi-subnet scanning techniques
   - Success criteria: Identification of all network segments

3. **Network Topology Mapping:** Understanding network architecture
   - Required skills: Route analysis and subnet relationship mapping
   - Expected commands: Traceroute and route table analysis
   - Success criteria: Clear network topology documentation

### Exam Tips and Tricks:
- **Tip 1:** Practice mental subnet calculation - exam time is limited
- **Tip 2:** Use /24 as reference point for quick calculations
- **Tip 3:** Remember common CIDR notations (/24, /26, /27, /28, /30)
- **Tip 4:** Document network boundaries clearly in your assessment

### Common eJPT Questions:
- Calculate the number of hosts in a given subnet
- Identify which subnet an IP address belongs to
- Determine network and broadcast addresses
- Plan scanning approach for multiple subnets

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Incorrect Subnet Calculation
**Problem:** Getting wrong host count or subnet boundaries
**Cause:** Confusion between network addresses, host addresses, and broadcast addresses
**Solution:**
```bash
# Remember the formula:
# Total addresses = 2^(host bits)
# Usable hosts = 2^(host bits) - 2
# -2 accounts for network and broadcast addresses

# Example: /26 network
# Host bits = 32 - 26 = 6
# Total addresses = 2^6 = 64
# Usable hosts = 64 - 2 = 62
```

### Issue 2: CIDR Notation Confusion
**Problem:** Mixing up CIDR notation with subnet mask notation
**Solution:**
```bash
# CIDR /24 = Subnet mask 255.255.255.0
# CIDR /26 = Subnet mask 255.255.255.192
# CIDR /30 = Subnet mask 255.255.255.252

# Quick conversion: subtract CIDR from 32 for host bits
# /24: 32-24 = 8 host bits
# /26: 32-26 = 6 host bits
```

### Issue 3: Scanning Wrong Subnet Range
**Problem:** Missing hosts due to incorrect subnet range calculation
**Solution:**
```bash
# Always verify subnet boundaries before scanning
# Given: 10.10.10.50/28
# Calculate: /28 = 16 addresses per subnet
# Subnets: .0, .16, .32, .48, .64, .80, .96, etc.
# 10.10.10.50 belongs to 10.10.10.48/28 subnet
# Correct scan: nmap -sn 10.10.10.48/28
```

### Issue 4: Large Network Scanning Inefficiency
**Problem:** Scanning takes too long on large networks
**Solution:**
```bash
# Break large networks into smaller chunks
# Instead of: nmap -sn 10.0.0.0/8 (16M hosts)
# Use targeted approach:
nmap -sn 10.10.10.0/24        # Specific subnet
nmap -sn 10.10.0.0/16 --top-ports 100  # Limited port scan
```

## 🔗 Integration with Other Tools

### Primary Integration: Subnet Discovery → Host Enumeration → Service Scanning
```bash
# Step 1: Discover network configuration
ip route show
ip addr show

# Step 2: Calculate and scan subnets
# Based on discovered configuration (e.g., 192.168.1.100/24)
nmap -sn 192.168.1.0/24       # Ping sweep

# Step 3: Target discovered hosts
nmap -sS 192.168.1.1,100,150  # Port scan active hosts

# Step 4: Service enumeration on discovered services
nmap -sV -p 22,80,443 192.168.1.100
```

### Secondary Integration: Route Analysis → Network Mapping
```bash
# Analyze routing for network topology
ip route show
traceroute target_ip

# Map network segments
nmap -sn --traceroute target_subnet

# Document network relationships
nmap -sn 192.168.1.0/24 > network_map.txt
```

### Advanced Workflows:
```bash
# Comprehensive network discovery workflow
# 1. Interface analysis
ip addr show | grep inet

# 2. Route table analysis  
ip route show

# 3. Systematic subnet scanning
for subnet in 192.168.{1..10}.0/24; do
    echo "Scanning $subnet"
    nmap -sn $subnet
done

# 4. Cross-subnet analysis
nmap --traceroute -sn discovered_networks
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Network Configuration:** Interface configurations and routing tables
2. **Subnet Calculations:** Show calculation work for subnet boundaries
3. **Discovery Results:** Complete host discovery results per subnet
4. **Network Topology:** Visual representation of network segments

### Report Template Structure:
```markdown
## Network Segmentation Analysis

### Target Environment Overview
- Primary Interface: eth0 (192.168.1.100/24)
- Gateway: 192.168.1.1
- Assessment Date: 2025-01-15

### Subnet Analysis
```bash
ip addr show
ip route show
```

#### Network: 192.168.1.0/24
- **Subnet Mask:** 255.255.255.0
- **Network Address:** 192.168.1.0
- **Broadcast Address:** 192.168.1.255
- **Usable Range:** 192.168.1.1 - 192.168.1.254
- **Total Hosts:** 254

#### Host Discovery Results
```bash
nmap -sn 192.168.1.0/24
```
**Active Hosts Found:**
- 192.168.1.1 (Gateway)
- 192.168.1.100 (Target host)
- 192.168.1.150 (Additional host)
- 192.168.1.200 (Additional host)

### Additional Network Segments
```bash
ip route show | grep -v default
```

#### Network: 10.10.10.0/26
- **Subnet Mask:** 255.255.255.192
- **Usable Range:** 10.10.10.1 - 10.10.10.62
- **Purpose:** Server segment (based on host analysis)

### Network Topology Summary
- **DMZ Segment:** 192.168.1.0/24 (4 active hosts)
- **Internal Segment:** 10.10.10.0/26 (routed via 192.168.1.1)
- **Connectivity:** Inter-segment routing enabled

### Recommendations
- **Network Segmentation:** Review firewall rules between segments
- **Scope Verification:** Confirm assessment boundaries include all segments
- **Documentation:** Maintain network topology for ongoing assessments
```

## 📚 Subnetting Quick Reference

### Subnet Calculation Shortcuts:
```bash
# Magic number method
# Subnet mask 255.255.255.224 (/27)
# Magic number = 256 - 224 = 32
# Subnets increment by 32: 0, 32, 64, 96, 128, 160, 192, 224

# Binary method for /26
# 11111111.11111111.11111111.11000000
# Host bits: 6 (last 6 zeros)
# Subnets: 2^2 = 4 (borrowed 2 bits)
# Hosts per subnet: 2^6 - 2 = 62
```

### Common Penetration Testing Scenarios:
| Scenario | Network | CIDR | Hosts | Scanning Approach |
|----------|---------|------|-------|------------------|
| Small Office | 192.168.1.0 | /24 | 254 | Full subnet scan |
| Department | 172.16.10.0 | /26 | 62 | Targeted scanning |
| Server Farm | 10.1.1.0 | /27 | 30 | Service-focused |
| Point-to-Point | 172.16.1.0 | /30 | 2 | Direct targeting |
| Large Enterprise | 10.0.0.0 | /16 | 65534 | Segmented approach |

### Nmap Subnet Scanning Examples:
```bash
# Common scanning patterns
nmap -sn 192.168.1.0/24        # Standard /24 network
nmap -sn 10.10.10.0/26         # Smaller /26 subnet  
nmap -sn 172.16.0.0/16         # Large /16 network (use with caution)
nmap -sn 192.168.0.0/16        # Entire Class C private space

# Efficient scanning for large networks
nmap -sn --top-ports 100 10.0.0.0/16    # Top ports only
nmap -sn -T4 192.168.0.0/16             # Faster timing
```
