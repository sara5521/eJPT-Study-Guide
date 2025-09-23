# 🔥 Networking Fundamentals - Complete eJPT Guide

**Comprehensive networking concepts essential for eJPT success and penetration testing methodology**

**Location:** `01-theory-foundations/networking-fundamentals.md`

## 🎯 What is Networking Fundamentals?

Networking fundamentals form the foundation of all cybersecurity and penetration testing activities. Understanding how networks operate at different layers, how protocols communicate, and how data flows through network infrastructure is crucial for identifying vulnerabilities, planning attacks, and conducting systematic security assessments. These concepts enable penetration testers to make informed decisions about target selection, attack vectors, and exploitation techniques.

Key capabilities include:
- Network architecture analysis and attack surface mapping
- Protocol behavior understanding for targeted exploitation
- Subnet calculation and network scope determination
- Service identification and vulnerability assessment
- Layer-specific attack planning and execution
- Network troubleshooting and defensive analysis

## 📦 Core Components Overview

Networking fundamentals encompass four critical knowledge areas that work together to provide comprehensive network understanding:

- **OSI Model & Network Communication (35%)** - Seven-layer architecture and attack vector mapping
- **TCP/UDP Protocols & Transport Analysis (30%)** - Protocol behavior and scanning methodology  
- **Subnetting & Network Architecture (25%)** - Network scoping and boundary identification
- **Port Services & Security Analysis (10%)** - Service enumeration and vulnerability identification

## 🔧 OSI Model & Network Communication (35%)

### Understanding the OSI Seven-Layer Model
The OSI (Open Systems Interconnection) model provides a structured framework for understanding network communication and identifying attack vectors at each layer. Each layer has specific functions and security implications that penetration testers must understand.

### Layer-by-Layer Analysis

#### Layer 7: Application Layer 🖥️
**Function:** User interface and network services  
**Protocols:** HTTP, HTTPS, FTP, SSH, Telnet, SMTP, DNS  
**Pentesting Focus:** Web application attacks, protocol exploitation, service enumeration

```bash
# Application layer reconnaissance
curl -I http://target.com                    # HTTP header analysis
nmap --script http-enum target.com           # Web service enumeration
nikto -h http://target.com                   # Web vulnerability scanning
```

#### Layer 6: Presentation Layer 🎨
**Function:** Data formatting, encryption, compression  
**Protocols:** SSL/TLS, JPEG, GIF, ASCII  
**Pentesting Focus:** Encryption weaknesses, certificate analysis, data format attacks

#### Layer 5: Session Layer 🤝
**Function:** Session management, connection establishment  
**Protocols:** NetBIOS, RPC, SQL sessions  
**Pentesting Focus:** Session hijacking, session fixation, connection manipulation

#### Layer 4: Transport Layer 🚛
**Function:** End-to-end communication, reliability  
**Protocols:** TCP, UDP  
**Pentesting Focus:** Port scanning, service enumeration, protocol analysis

#### Layer 3: Network Layer 🗺️
**Function:** Routing, logical addressing  
**Protocols:** IP, ICMP, ARP, OSPF  
**Pentesting Focus:** IP spoofing, routing attacks, ICMP tunneling, network mapping

#### Layer 2: Data Link Layer 🔗
**Function:** Frame formatting, error detection, MAC addressing  
**Protocols:** Ethernet, WiFi (802.11), PPP  
**Pentesting Focus:** MAC spoofing, ARP poisoning, WiFi attacks, switch attacks

#### Layer 1: Physical Layer ⚡
**Function:** Physical transmission of raw bits  
**Components:** Cables, switches, hubs, wireless signals  
**Pentesting Focus:** Physical access, cable tapping, wireless interception

### OSI Model Attack Mapping

| Layer | Attack Types | Common Tools | eJPT Relevance |
|-------|-------------|--------------|----------------|
| **7 - Application** | Web attacks, service exploits | Burp Suite, SQLmap | ⭐⭐⭐ |
| **4 - Transport** | Port scanning, service enum | Nmap, Netcat | ⭐⭐⭐ |
| **3 - Network** | IP spoofing, routing attacks | Hping3, Route tools | ⭐⭐ |
| **2 - Data Link** | ARP poisoning, MAC spoofing | Ettercap, Macchanger | ⭐⭐ |

### Practical OSI Application Example
```bash
# HTTP communication layer analysis
# Layer 7: HTTP GET request analysis
curl -v http://target.com/admin
# Layer 4: TCP connection on port 80
# Layer 3: IP routing to target
# Layer 2: Ethernet frame delivery
# Layer 1: Physical transmission

# Complete layer interaction demonstration
tcpdump -i eth0 -n host target.com and port 80
# Captures all layers of HTTP communication
```

## ⚙️ TCP/UDP Protocols & Transport Analysis (30%)

### Protocol Characteristics and Behavior

#### TCP (Transmission Control Protocol)
**Key Features:**
- Connection-oriented with three-way handshake
- Reliable delivery with acknowledgments
- Flow control and error correction
- Sequential packet delivery guarantee

**Security Implications:**
- Predictable connection establishment
- State tracking opportunities
- Reliable data transfer for payloads
- Connection fingerprinting possible

#### UDP (User Datagram Protocol)
**Key Features:**
- Connectionless communication
- Best-effort delivery (no guarantees)
- Minimal overhead for speed
- Fire-and-forget transmission

**Security Implications:**
- Difficult to track connection state
- Potential for amplification attacks
- Faster for reconnaissance activities
- Less detectable in some scenarios

### Protocol Comparison for Penetration Testing

| Aspect | TCP | UDP | Pentesting Impact |
|--------|-----|-----|-------------------|
| **Scanning Speed** | Slower | Faster | UDP preferred for quick recon |
| **Reliability** | Guaranteed | Best-effort | TCP for stable connections |
| **Detectability** | Higher | Lower | UDP more stealthy |
| **State Tracking** | Stateful | Stateless | TCP easier to monitor |

### Protocol-Specific Scanning Techniques
```bash
# TCP scanning methods
nmap -sS target.com                          # SYN scan (stealth)
nmap -sT target.com                          # Connect scan (reliable)
nmap -sF target.com                          # FIN scan (firewall evasion)

# UDP scanning methods  
nmap -sU target.com                          # UDP scan
nmap -sU --top-ports 100 target.com         # Common UDP ports
nmap -sU -sV target.com                      # UDP service detection
```

### Three-Way Handshake Analysis
```bash
# TCP connection establishment
Client → Server: SYN (Synchronize)
Server → Client: SYN-ACK (Synchronize-Acknowledge)  
Client → Server: ACK (Acknowledge)
# Connection established for data transfer

# Practical handshake observation
tcpdump -i eth0 "tcp[tcpflags] & (tcp-syn|tcp-ack) != 0"
# Captures handshake packets for analysis
```

### Common TCP and UDP Services

#### Critical TCP Services for eJPT
| Port | Service | Usage | Attack Vectors |
|------|---------|--------|----------------|
| **21** | FTP | File transfer | Anonymous login, clear-text |
| **22** | SSH | Secure shell | Brute force, key attacks |
| **23** | Telnet | Remote access | Clear-text credentials |
| **80** | HTTP | Web traffic | Web application attacks |
| **443** | HTTPS | Secure web | Certificate attacks, web vulns |
| **445** | SMB | File sharing | Lateral movement, enumeration |

#### Essential UDP Services for eJPT
| Port | Service | Usage | Reconnaissance Value |
|------|---------|--------|---------------------|
| **53** | DNS | Domain resolution | Zone transfers, enumeration |
| **69** | TFTP | Trivial file transfer | Unauthenticated access |
| **161** | SNMP | Network management | Information disclosure |
| **500** | IKE | VPN key exchange | VPN identification |

## 🌐 Subnetting & Network Architecture (25%)

### IP Address Classes and Private Ranges
```bash
# Class A networks
Range: 1.0.0.0 to 126.255.255.255
Default mask: 255.0.0.0 (/8)
Private: 10.0.0.0/8 (16,777,214 hosts)

# Class B networks  
Range: 128.0.0.0 to 191.255.255.255
Default mask: 255.255.0.0 (/16)
Private: 172.16.0.0/12 (1,048,574 hosts)

# Class C networks
Range: 192.0.0.0 to 223.255.255.255
Default mask: 255.255.255.0 (/24)
Private: 192.168.0.0/16 (65,534 hosts)
```

### CIDR Notation and Subnet Calculations

#### Essential CIDR Reference Table
| CIDR | Subnet Mask | Hosts | Subnets | Common Use |
|------|-------------|-------|---------|------------|
| /8 | 255.0.0.0 | 16,777,214 | 1 | Large networks |
| /16 | 255.255.0.0 | 65,534 | 1 | Medium networks |
| /24 | 255.255.255.0 | 254 | 1 | Small networks |
| /25 | 255.255.255.128 | 126 | 2 | Small subnets |
| /26 | 255.255.255.192 | 62 | 4 | Workgroup subnets |
| /27 | 255.255.255.224 | 30 | 8 | Department subnets |
| /30 | 255.255.255.252 | 2 | 64 | Point-to-point |

#### Subnet Calculation Formulas
```bash
# Essential calculations for eJPT
Number of Subnets = 2^(borrowed bits)
Hosts per Subnet = 2^(host bits) - 2
Subnet Increment = 256 - (subnet mask octet)
Network Address = First address in subnet
Broadcast Address = Last address in subnet
Host Range = Network + 1 to Broadcast - 1
```

### Practical Subnetting Examples
```bash
# Example: 192.168.1.0/26 analysis
# Step 1: Host bits calculation
32 - 26 = 6 host bits

# Step 2: Hosts per subnet
2^6 - 2 = 62 usable hosts

# Step 3: Subnet increment  
256 - 192 = 64

# Step 4: Subnet breakdown
192.168.1.0/26    → .1 to .62 (62 hosts)
192.168.1.64/26   → .65 to .126 (62 hosts)
192.168.1.128/26  → .129 to .190 (62 hosts)
192.168.1.192/26  → .193 to .254 (62 hosts)
```

### Network Scope Identification for Pentesting
```bash
# Target network scope analysis
# Given: 10.0.0.0/22 network scope

# Calculation process
/22 = 255.255.252.0 (1022 hosts)
Network range: 10.0.0.0 - 10.0.3.255

# Individual /24 subnets within scope
10.0.0.0/24   # Potential DMZ
10.0.1.0/24   # User workstations  
10.0.2.0/24   # Servers
10.0.3.0/24   # Management network

# Nmap scanning approach
nmap -sn 10.0.0.0/22                        # Network discovery
nmap -sS -p- 10.0.0.0/22                    # Comprehensive scan
```

### Port Services & Security Analysis

#### Port State Classifications
| State | Description | Security Implication | Action Required |
|-------|-------------|---------------------|-----------------|
| **Open** | Service listening | Direct attack vector | Immediate enumeration |
| **Closed** | Port accessible, no service | System reachable | Note for later |
| **Filtered** | Blocked by firewall | Security controls present | Evasion techniques |
| **Unfiltered** | Accessible but state unknown | Further testing needed | Additional probing |

#### Service Enumeration Workflow
```bash
# Phase 1: Port discovery
nmap -sS --top-ports 1000 target_range      # Initial scan

# Phase 2: Service identification  
nmap -sV -p open_ports target               # Version detection

# Phase 3: Script enumeration
nmap -sC -p open_ports target               # Default scripts

# Phase 4: Service-specific enumeration
nmap --script http-enum -p 80,443 target    # HTTP enumeration
nmap --script smb-enum-shares -p 445 target # SMB enumeration
```

## 🧪 Real Lab Examples

### Example 1: Complete Network Assessment Workflow
```bash
# Target: Corporate network 192.168.100.0/24
# Phase 1: Network discovery using subnetting knowledge
nmap -sn 192.168.100.0/24
# Result: 45 live hosts identified

# Phase 2: Protocol-aware port scanning
nmap -sS -sU --top-ports 100 192.168.100.0/24
# TCP Results: 80, 443, 22, 445 commonly open
# UDP Results: 53, 161 services discovered  

# Phase 3: OSI layer 7 application enumeration
nmap -sV -sC -p 80,443 192.168.100.0/24
# HTTP servers: Apache 2.4.41, nginx 1.18
# HTTPS: Valid certificates, potential subdomain info

# Phase 4: Layer-specific analysis
# Layer 7: Web application testing
nikto -h http://192.168.100.50
# Layer 4: Service version exploitation research
searchsploit Apache 2.4.41
```

### Example 2: Protocol-Based Attack Planning
```bash
# Discovered services analysis
# TCP 21 (FTP): vsftpd 3.0.3
# TCP 22 (SSH): OpenSSH 7.4  
# TCP 80 (HTTP): Apache 2.4.6
# UDP 161 (SNMP): Net-SNMP 5.7.2

# TCP service exploitation approach
ftp target.com                              # Test anonymous login
hydra -l admin -P passwords.txt target ssh  # SSH brute force
curl -I http://target/admin                 # HTTP directory testing

# UDP service enumeration approach  
snmpwalk -v2c -c public target             # SNMP enumeration
onesixtyone -c community.txt target        # SNMP community testing
```

### Example 3: Subnet-Based Target Prioritization
```bash
# Network scope: 172.16.0.0/16 (Class B private)
# Subnet analysis for systematic assessment

# High-value subnets identification
172.16.1.0/24    # DMZ - externally accessible
172.16.10.0/24   # Server subnet - critical assets
172.16.50.0/24   # Management - high privileges
172.16.100.0/24  # User workstations - lateral movement

# Systematic scanning approach
nmap -sS --top-ports 1000 172.16.1.0/24    # DMZ priority scanning  
nmap -sS -p 445,3389 172.16.10.0/24        # Server enumeration
nmap -sU -p 161 172.16.50.0/24             # Management SNMP
```

## 🎯 eJPT Exam Focus

### Essential Skills Distribution

#### Critical Skills (50% - Essential for eJPT Success)
- **Subnetting calculations and CIDR conversion**: Manual calculation without tools
- **TCP/UDP protocol identification**: Recognizing services by protocol type  
- **Port service enumeration**: Identifying services running on discovered ports
- **Network scope determination**: Understanding target boundaries from IP ranges

#### Important Skills (30% - Supporting Knowledge)
- **OSI layer attack vector mapping**: Understanding where attacks occur
- **Protocol behavior analysis**: TCP handshake vs UDP connectionless behavior
- **Subnet boundary identification**: Determining network segments and VLANs
- **Service version correlation**: Linking discovered services to potential vulnerabilities

#### Useful Skills (20% - Advanced Understanding)
- **Advanced networking theory**: Routing protocols and network design
- **Network troubleshooting**: Diagnostic techniques and tools
- **Protocol deep analysis**: Advanced TCP/UDP features and flags
- **Network security architecture**: Defense mechanisms and bypass techniques

### Critical Commands for eJPT Success
```bash
# Network discovery and mapping
nmap -sn 192.168.1.0/24                     # Host discovery
nmap -sS --top-ports 1000 target            # TCP port scanning
nmap -sU --top-ports 100 target             # UDP service discovery
nmap -sV -sC target                         # Service enumeration

# Protocol-specific testing
nc -nv target 80                            # Manual TCP connection
nc -u target 53                             # UDP service testing
telnet target port                          # Interactive service testing

# Network analysis
arp -a                                      # ARP table analysis
route -n                                    # Routing table examination
netstat -rn                                 # Network connections
```

### eJPT Exam Scenarios and Solutions

#### Scenario 1: Network Scope Identification
**Question:** "Given IP range 10.50.0.0/22, determine the total number of hosts and identify all /24 subnets within this range."

**Solution Process:**
```bash
# Step 1: Calculate total hosts
/22 = 22 network bits, 10 host bits
Total hosts = 2^10 - 2 = 1022 hosts

# Step 2: Determine address range
10.50.0.0/22 covers: 10.50.0.0 - 10.50.3.255

# Step 3: Identify /24 subnets
10.50.0.0/24 (hosts .1-.254)
10.50.1.0/24 (hosts .1-.254) 
10.50.2.0/24 (hosts .1-.254)
10.50.3.0/24 (hosts .1-.254)
```

#### Scenario 2: Service Protocol Identification
**Question:** "Identify which scanning technique is most appropriate for discovering DNS services and explain why."

**Solution:**
```bash
# DNS runs on both TCP and UDP port 53
# UDP 53: Primary DNS queries (most common)
# TCP 53: Zone transfers and large responses

# Optimal scanning approach
nmap -sU -sT -p 53 target_range             # Both protocols
dig @target any domain.com                  # DNS functionality test
nmap --script dns-zone-transfer target      # Zone transfer attempt
```

### Common eJPT Questions and Answers
1. **Convert /26 to subnet mask:** 255.255.255.192
2. **How many hosts in /28 subnet:** 14 hosts (2^4 - 2)
3. **TCP vs UDP for DNS:** Both, but UDP primary for queries
4. **OSI layer for port scanning:** Layer 4 (Transport)
5. **Private IP ranges:** 10.x.x.x, 172.16-31.x.x, 192.168.x.x

## ⚠️ Common Issues & Troubleshooting

### Subnetting Calculation Errors
**Issue:** Incorrect host count or subnet boundaries
**Common Mistakes:**
- Forgetting to subtract 2 for network and broadcast addresses
- Confusing network bits with host bits
- Incorrect CIDR to subnet mask conversion

**Solutions:**
```bash
# Double-check calculations
# /24 = 8 host bits = 2^8 - 2 = 254 hosts
# /25 = 7 host bits = 2^7 - 2 = 126 hosts
# /26 = 6 host bits = 2^6 - 2 = 62 hosts

# Verification with tools
ipcalc 192.168.1.0/24                       # Subnet calculator
sipcalc 10.0.0.0/16                        # Alternative calculator
```

### Protocol Identification Confusion
**Issue:** Misidentifying TCP vs UDP services
**Prevention:**
```bash
# Check both protocols for ambiguous services
nmap -sT -sU -p 53 target                   # DNS on both
nmap -sV target                             # Version detection clarifies
```

### OSI Layer Misconceptions
**Issue:** Confusing attack vectors with inappropriate layers
**Clarification:**
```bash
# Layer 7: Application attacks (web, email, DNS)
# Layer 4: Port scanning, service enumeration
# Layer 3: IP attacks, routing, ICMP
# Layer 2: ARP, MAC attacks, switching
```

## 🔗 Integration with Other Tools

### Primary Integration: Networking Knowledge → Reconnaissance Tools
```bash
# Network understanding enhances tool usage
# Subnetting knowledge improves nmap efficiency
nmap -sn 192.168.1.0/24                     # Proper network discovery

# Protocol knowledge guides scanning strategy  
nmap -sU --top-ports 100 target             # UDP services priority
nmap -sS -F target                          # Fast TCP scanning

# OSI understanding improves attack planning
# Layer 7 → Web application testing
# Layer 4 → Service exploitation
# Layer 3 → Network-based attacks
```

### Secondary Integration: Network Analysis → Exploitation Planning
```bash
# Service discovery informs exploitation choices
# TCP 21 FTP → Anonymous login testing
# TCP 445 SMB → Share enumeration, lateral movement
# UDP 161 SNMP → Information disclosure attacks

# Subnet knowledge guides lateral movement
# Identify network segments for privilege escalation
# Map trust relationships between subnets
# Plan multi-hop attack paths
```

### Advanced Integration Workflows
```bash
# Complete assessment workflow integration
# Phase 1: Network discovery (networking fundamentals)
nmap -sn target_network

# Phase 2: Service enumeration (protocol knowledge)  
nmap -sV -sC discovered_hosts

# Phase 3: Vulnerability assessment (service analysis)
nmap --script vuln discovered_services

# Phase 4: Exploitation (layer-specific attacks)
# Apply OSI knowledge to target appropriate layers
```

## 📝 Documentation and Reporting

### Network Analysis Documentation Template
```markdown
## Network Assessment Report

### Network Scope Analysis
- Target Network: 192.168.100.0/24
- Total Hosts: 254 available addresses
- Subnet Breakdown: Single /24 network
- Address Range: 192.168.100.1 - 192.168.100.254

### Protocol Analysis Results
#### TCP Services Discovered:
- Port 21 (FTP): vsftpd 3.0.3 - Anonymous access enabled
- Port 22 (SSH): OpenSSH 7.4 - Key-based authentication  
- Port 80 (HTTP): Apache 2.4.6 - Default installation
- Port 445 (SMB): Samba 4.6.2 - Share enumeration possible

#### UDP Services Discovered:
- Port 53 (DNS): ISC BIND 9.11.4 - Zone transfer disabled
- Port 161 (SNMP): Net-SNMP 5.7.2 - Public community string

### OSI Layer Assessment
- **Layer 7 Issues:** Default web pages, information disclosure
- **Layer 4 Issues:** Unnecessary services running  
- **Layer 3 Issues:** No network segmentation observed
- **Layer 2 Issues:** Single broadcast domain identified

### Risk Assessment
- **Critical:** Anonymous FTP access with write permissions
- **High:** SNMP with default community string
- **Medium:** Outdated service versions with known CVEs
- **Low:** Information disclosure through service banners
```

### Network Mapping Automation
```bash
#!/bin/bash
# network_assessment.sh - Automated network analysis

NETWORK=$1
OUTPUT_DIR="network_assessment_$(date +%Y%m%d_%H%M%S)"
mkdir -p $OUTPUT_DIR

echo "[+] Starting network assessment for $NETWORK"

# Phase 1: Host discovery
echo "[+] Discovering live hosts..."
nmap -sn $NETWORK > $OUTPUT_DIR/host_discovery.txt

# Phase 2: Port scanning
echo "[+] Scanning for services..."
nmap -sS --top-ports 1000 -iL $OUTPUT_DIR/live_hosts.txt > $OUTPUT_DIR/port_scan.txt

# Phase 3: Service enumeration
echo "[+] Enumerating services..."
nmap -sV -sC -iL $OUTPUT_DIR/live_hosts.txt > $OUTPUT_DIR/service_enum.txt

# Phase 4: UDP scanning
echo "[+] Scanning UDP services..."
nmap -sU --top-ports 100 -iL $OUTPUT_DIR/live_hosts.txt > $OUTPUT_DIR/udp_scan.txt

echo "[+] Network assessment completed. Results in: $OUTPUT_DIR"
```

## 📚 Additional Resources and References

### Essential Learning Materials
- **RFC 791:** Internet Protocol (IP) specification
- **RFC 793:** Transmission Control Protocol (TCP) specification  
- **RFC 768:** User Datagram Protocol (UDP) specification
- **RFC 1918:** Address allocation for private internets (private IP ranges)

### Online Learning Resources
- **Cisco Networking Academy:** CCNA routing and switching fundamentals
- **Professor Messer:** Network+ training videos and resources
- **Cybrary:** Free networking and security courses
- **PacketLife.net:** Network reference sheets and cheat sheets

### Practical Tools and References
- **Wireshark:** Network protocol analyzer for traffic analysis
- **GNS3:** Network simulation platform for hands-on practice
- **Packet Tracer:** Cisco network simulation and learning tool
- **Online subnet calculators:** ipcalc, sipcalc for verification

### eJPT-Specific Preparation
- **eLearnSecurity PTS:** Official preparation course
- **TryHackMe:** Network fundamentals learning paths
- **HackTheBox:** Practical networking in penetration testing contexts
- **VulnHub:** Network-based vulnerable machines for practice

This comprehensive guide provides all networking fundamentals necessary for eJPT success, integrating OSI model understanding, protocol analysis, subnetting expertise, and practical penetration testing applications into a unified learning resource optimized for exam preparation and real-world security assessment scenarios.
