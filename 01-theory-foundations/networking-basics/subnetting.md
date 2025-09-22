# 🌐 Subnetting - Network Division and CIDR Notation

Understanding IP addressing, subnetting, and CIDR notation for network segmentation and security assessment.
**Location:** `01-theory-foundations/networking-basics/subnetting.md`

## 🎯 What is Subnetting?

Subnetting is the practice of dividing a network into smaller sub-networks (subnets) to improve security, performance, and organization. It's essential for penetration testers to understand network boundaries and identify target ranges during assessments.

Key concepts include:
- IP address classes and private ranges
- Subnet masks and CIDR notation
- Network and broadcast addresses
- Calculating available hosts
- VLSM (Variable Length Subnet Masking)

## 📦 IP Address Fundamentals

### IP Address Classes:
```bash
# Class A: 1.0.0.0 to 126.255.255.255
# Default subnet mask: 255.0.0.0 (/8)
# Private range: 10.0.0.0/8

# Class B: 128.0.0.0 to 191.255.255.255  
# Default subnet mask: 255.255.0.0 (/16)
# Private range: 172.16.0.0/12

# Class C: 192.0.0.0 to 223.255.255.255
# Default subnet mask: 255.255.255.0 (/24)
# Private range: 192.168.0.0/16
```

### CIDR Notation Basics:
```bash
# CIDR format: IP_ADDRESS/PREFIX_LENGTH
192.168.1.0/24    # /24 = 255.255.255.0
10.0.0.0/8        # /8 = 255.0.0.0
172.16.0.0/16     # /16 = 255.255.0.0
```

## 🔧 Subnet Calculation Methods

### Binary Method:
```bash
# Converting 192.168.1.0/26 to understand the subnet

# IP address in binary:
192.168.1.0 = 11000000.10101000.00000001.00000000

# /26 subnet mask in binary:
255.255.255.192 = 11111111.11111111.11111111.11000000

# Network bits: First 26 bits
# Host bits: Last 6 bits (64 possible addresses)
```

### Quick Calculation Table:
| CIDR | Subnet Mask | Hosts per Subnet | Number of Subnets |
|------|-------------|------------------|-------------------|
| /24 | 255.255.255.0 | 254 | 1 |
| /25 | 255.255.255.128 | 126 | 2 |
| /26 | 255.255.255.192 | 62 | 4 |
| /27 | 255.255.255.224 | 30 | 8 |
| /28 | 255.255.255.240 | 14 | 16 |
| /29 | 255.255.255.248 | 6 | 32 |
| /30 | 255.255.255.252 | 2 | 64 |

## ⚙️ Subnetting Formulas and Calculations

### Essential Formulas:
| Calculation | Formula | Purpose |
|-------------|---------|---------|
| Number of Subnets | 2^(borrowed bits) | How many subnets created |
| Hosts per Subnet | 2^(host bits) - 2 | Available host addresses |
| Subnet Increment | 256 - subnet mask octet | Spacing between subnets |
| Network Address | First address in range | Identifies the subnet |
| Broadcast Address | Last address in range | Subnet broadcast |
| Host Range | Network + 1 to Broadcast - 1 | Assignable addresses |

### Step-by-Step Calculation:
```bash
# Example: 192.168.1.0/26

# Step 1: Identify host bits
32 - 26 = 6 host bits

# Step 2: Calculate hosts per subnet  
2^6 - 2 = 64 - 2 = 62 hosts

# Step 3: Find subnet increment
256 - 192 = 64

# Step 4: List the subnets
192.168.1.0/26    (hosts: .1 to .62)
192.168.1.64/26   (hosts: .65 to .126)  
192.168.1.128/26  (hosts: .129 to .190)
192.168.1.192/26  (hosts: .193 to .254)
```

## 🧪 Real Lab Examples

### Example 1: Basic Subnet Identification
```bash
# Given network: 10.10.10.0/24
# Need to create 4 subnets

# Calculation:
# Need 2 bits for 4 subnets (2^2 = 4)
# New subnet mask: /24 + 2 = /26

# Result subnets:
10.10.10.0/26     # Range: 10.10.10.1 - 10.10.10.62
10.10.10.64/26    # Range: 10.10.10.65 - 10.10.10.126
10.10.10.128/26   # Range: 10.10.10.129 - 10.10.10.190
10.10.10.192/26   # Range: 10.10.10.193 - 10.10.10.254
```

### Example 2: VLSM Scenario
```bash
# Network: 172.16.0.0/16
# Requirements:
# - Sales: 500 hosts
# - IT: 100 hosts  
# - Management: 50 hosts
# - Point-to-point links: 2 hosts each (3 links needed)

# Solution (largest to smallest):
# Sales: 172.16.0.0/23 (510 hosts available)
# IT: 172.16.2.0/25 (126 hosts available)
# Management: 172.16.2.128/26 (62 hosts available)
# Link 1: 172.16.2.192/30 (2 hosts available)
# Link 2: 172.16.2.196/30 (2 hosts available)
# Link 3: 172.16.2.200/30 (2 hosts available)
```

### Example 3: Pentesting Scenario
```bash
# Target network discovery during assessment:
# Found network: 192.168.100.0/22

# Understanding the scope:
# /22 = 255.255.252.0
# Network range: 192.168.100.0 - 192.168.103.255
# Total hosts: 1022 (4 x /24 networks combined)

# Individual /24 subnets within /22:
192.168.100.0/24  # DMZ network
192.168.101.0/24  # User network  
192.168.102.0/24  # Server network
192.168.103.0/24  # Management network
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **CIDR to subnet mask conversion** (85% importance)
- **Host range calculation** (90% importance)
- **Network boundary identification** (95% importance)
- **Subnet scope determination** (80% importance)

### Critical Calculations to Master:
```bash
# Must-know conversions for exam
/24 = 255.255.255.0    # Standard Class C
/16 = 255.255.0.0      # Standard Class B  
/8 = 255.0.0.0         # Standard Class A
/30 = 255.255.255.252  # Point-to-point links
/26 = 255.255.255.192  # Common subnet size
```

### eJPT Exam Scenarios:
1. **Network Scope Identification:** Determine scanning range
   - Given: Target IP with CIDR
   - Required: Calculate full network range
   - Success criteria: Identify all possible hosts

2. **Subnet Boundary Recognition:** Understanding network segments
   - Required skills: CIDR interpretation
   - Expected commands: Network range calculations
   - Success criteria: Identify separate subnets

### Exam Tips and Tricks:
- **Tip 1:** Memorize common CIDR notations (/24, /16, /8, /30)
- **Tip 2:** Use the "256 minus" rule for quick subnet increments
- **Tip 3:** Always subtract 2 from host calculations (network + broadcast)
- **Tip 4:** Practice with penetration testing tools that show CIDR

### Common eJPT Questions:
- Convert CIDR notation to subnet mask and vice versa
- Calculate the number of hosts in a given subnet
- Identify if two IPs are in the same subnet

## ⚠️ Common Issues & Troubleshooting

### Issue 1: CIDR Conversion Errors
**Problem:** Incorrect subnet mask calculations
**Cause:** Confusion between network and host bits
**Solution:**
```bash
# Remember the relationship
/24 means 24 network bits, 8 host bits
24 network bits = 11111111.11111111.11111111.00000000
This equals = 255.255.255.0

# Quick verification:
32 total bits - CIDR value = host bits
32 - 24 = 8 host bits = 256 possible addresses
```

### Issue 2: Host Count Confusion
**Problem:** Forgetting to subtract network and broadcast addresses
**Solution:**
```bash
# Always remember the formula
Available hosts = 2^(host bits) - 2

# Example: /26 subnet
Host bits = 32 - 26 = 6
Total addresses = 2^6 = 64
Available hosts = 64 - 2 = 62
```

### Issue 3: Subnet Range Miscalculation
**Problem:** Incorrect subnet boundaries in VLSM scenarios
**Prevention:**
```bash
# Always work from largest to smallest subnet requirements
# Use structured approach:
1. List requirements in descending order
2. Calculate required subnet size for each
3. Assign subnets sequentially
4. Verify no overlap exists
```

## 🔗 Integration with Other Tools

### Primary Integration: Subnetting + Network Discovery
```bash
# Use subnet knowledge to plan nmap scans
nmap -sn 192.168.1.0/24        # Ping sweep entire subnet
nmap -sS -p80,443 10.0.0.0/16  # TCP scan across large network
nmap --top-ports 1000 172.16.0.0/12  # Scan private Class B range

# Explanation of integration:
# Step 1: Calculate subnet scope from CIDR
# Step 2: Use nmap to discover active hosts  
# Step 3: Further enumerate discovered systems
```

### Secondary Integration: Subnetting → Target Selection
```bash
# How subnet understanding guides pentesting workflow
# 1. Identify network segments
netdiscover -r 192.168.1.0/24

# 2. Map subnet boundaries  
nmap -sn 192.168.0.0/16 --exclude 192.168.1.0/24

# 3. Focus on specific segments
nmap -sS -sV 192.168.100.0/26  # Server subnet
nmap -sS -sV 192.168.101.0/26  # User subnet
```

### Advanced Workflows:
```bash
# Complex network mapping using subnet knowledge
for subnet in $(seq 0 4 252); do
    nmap -sn 192.168.$subnet.0/24
done

# Systematic enumeration by subnet
nmap -sn 10.0.0.0/8 | grep "Nmap scan report" | awk '{print $5}'
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Network Diagrams:** Document discovered subnet boundaries
2. **IP Range Documentation:** Record active subnets and host counts
3. **Scope Verification:** Confirm target networks match engagement scope
4. **Subnet Analysis:** Document network segmentation findings

### Report Template Structure:
```markdown
## Network Subnet Analysis

### Target Network Information
- Primary Network: 192.168.0.0/16
- Discovered Subnets: 
  - DMZ: 192.168.10.0/24 (45 active hosts)
  - Users: 192.168.20.0/24 (120 active hosts)
  - Servers: 192.168.30.0/26 (15 active hosts)

### Subnet Boundaries
```bash
# Network discovery commands used
nmap -sn 192.168.0.0/16
netdiscover -r 192.168.0.0/16
```

### Security Implications
- Network segmentation analysis
- Inter-subnet communication rules
- Potential for lateral movement

### Recommendations
- Implement proper subnet isolation
- Review firewall rules between segments
- Monitor inter-VLAN traffic
```

## 📚 Additional Resources

### Online Subnet Calculators:
- Subnet Calculator: https://www.subnet-calculator.com/
- CIDR Calculator: https://www.ipaddressguide.com/cidr
- Visual Subnet Calculator: http://www.davidc.net/sites/default/subnets/subnets.html

### Learning Resources:
- Cisco Networking Academy: Comprehensive subnetting course
- Professor Messer Network+: Free subnet training videos
- IPv4 Subnetting Practice: Interactive exercises

### Practice Tools:
- SubnetEzer: Mobile app for subnet practice
- Subnetting.org: Online practice problems
- Packet Tracer: Cisco network simulation with subnetting labs

### Related eJPT Topics:
- Network discovery techniques: How subnetting guides scanning
- VLAN hopping attacks: Understanding network boundaries  
- Lateral movement: Moving between network segments
