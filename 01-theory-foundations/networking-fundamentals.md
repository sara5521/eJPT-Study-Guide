# 🌐 Networking Fundamentals - Complete Guide

Understanding networking fundamentals is essential for penetration testing and the eJPT certification. This comprehensive guide covers all core networking concepts required for successful security assessments.

**Location:** `01-theory-foundations/networking-fundamentals.md`

## 📋 Table of Contents
1. [OSI Model - 7 Layer Architecture](#osi-model)
2. [TCP vs UDP - Protocol Comparison](#tcp-vs-udp) 
3. [Subnetting & CIDR Notation](#subnetting)
4. [Ports & Protocols Essentials](#ports-protocols)
5. [eJPT Network Requirements](#ejpt-requirements)
6. [Practical Integration Examples](#practical-examples)

---

## 🎯 OSI Model - 7 Layer Architecture {#osi-model}

The OSI (Open Systems Interconnection) model is a conceptual framework that standardizes network communication functions into seven distinct layers. Each layer has specific responsibilities and communicates with the layers directly above and below it.

### Why OSI Matters for Pentesting
- **Attack Vector Mapping:** Understand where attacks can occur in network communication
- **Systematic Troubleshooting:** Debug network issues layer by layer
- **Security Assessment:** Identify vulnerabilities at different network levels
- **Targeted Exploitation:** Plan attacks against specific network layers

### The 7 Layers of OSI Model

#### Layer 7: Application Layer 🖥️
**Function:** User interface and network services  
**Protocols:** HTTP, HTTPS, FTP, SSH, Telnet, SMTP, DNS  
**Pentesting Focus:** Web application attacks, protocol exploitation

#### Layer 6: Presentation Layer 🎨
**Function:** Data formatting, encryption, compression  
**Protocols:** SSL/TLS, JPEG, GIF, ASCII  
**Pentesting Focus:** Encryption weaknesses, data format attacks

#### Layer 5: Session Layer 🤝
**Function:** Session management, connection establishment  
**Protocols:** NetBIOS, RPC, SQL sessions  
**Pentesting Focus:** Session hijacking, session fixation

#### Layer 4: Transport Layer 🚛
**Function:** End-to-end communication, reliability  
**Protocols:** TCP, UDP  
**Pentesting Focus:** Port scanning, service enumeration

#### Layer 3: Network Layer 🗺️
**Function:** Routing, logical addressing  
**Protocols:** IP, ICMP, ARP, OSPF  
**Pentesting Focus:** IP spoofing, routing attacks, ICMP tunneling

#### Layer 2: Data Link Layer 🔗
**Function:** Frame formatting, error detection, MAC addressing  
**Protocols:** Ethernet, WiFi (802.11), PPP  
**Pentesting Focus:** MAC spoofing, ARP poisoning, WiFi attacks

#### Layer 1: Physical Layer ⚡
**Function:** Physical transmission of raw bits  
**Components:** Cables, switches, hubs, wireless signals  
**Pentesting Focus:** Physical access, cable tapping, wireless interception

### OSI Layer Examples

#### HTTP Communication Analysis
```bash
# Capturing HTTP traffic to analyze OSI layers
tcpdump -i eth0 -n host 192.168.1.100 and port 80

# Layer analysis in captured packet:
# Layer 1: Physical - Ethernet cable transmission
# Layer 2: Data Link - Ethernet frame (MAC addresses)
# Layer 3: Network - IP packet (192.168.1.50 → 192.168.1.100)
# Layer 4: Transport - TCP segment (port 45678 → 80)
# Layer 5: Session - HTTP session establishment
# Layer 6: Presentation - HTML/CSS formatting
# Layer 7: Application - HTTP GET request
```

#### SSH Connection Layers
```bash
# SSH connection establishment
ssh user@192.168.1.100

# Complete layer interaction:
# Layer 7: SSH application protocol
# Layer 6: SSH encryption/compression
# Layer 5: SSH session management
# Layer 4: TCP connection (port 22)
# Layer 3: IP routing
# Layer 2: Ethernet framing
# Layer 1: Physical transmission
```

### OSI vs TCP/IP Model Comparison

| OSI Layer | TCP/IP Layer | Key Protocols | Pentesting Focus |
|-----------|--------------|---------------|------------------|
| Application (7) | Application | HTTP, FTP, SSH | Web attacks, service exploitation |
| Presentation (6) | Application | SSL/TLS, encryption | Crypto attacks, format manipulation |
| Session (5) | Application | NetBIOS, RPC | Session attacks, hijacking |
| Transport (4) | Transport | TCP, UDP | Port scanning, service enum |
| Network (3) | Internet | IP, ICMP, ARP | IP spoofing, routing attacks |
| Data Link (2) | Network Access | Ethernet, WiFi | ARP poisoning, MAC spoofing |
| Physical (1) | Network Access | Cables, wireless | Physical access, interception |

### Memory Aids and Mnemonics

**Popular Mnemonics:**
- **"All People Seem To Need Data Processing"** (Application → Physical)
- **"Please Do Not Throw Sausage Pizza Away"** (Physical → Application)
- **"All Pentesters Should Try New Data Protocols"** (Security-focused version)

**Layer Function Summary:**
```
7 - Application:  "What the user sees"
6 - Presentation: "How data is formatted"  
5 - Session:      "Managing conversations"
4 - Transport:    "End-to-end delivery"
3 - Network:      "Finding the path"
2 - Data Link:    "Node-to-node delivery"
1 - Physical:     "Bits on the wire"
```

---

## 🔧 TCP vs UDP - Protocol Comparison {#tcp-vs-udp}

TCP (Transmission Control Protocol) and UDP (User Datagram Protocol) are the two primary transport layer protocols. Understanding their differences is crucial for network reconnaissance, service enumeration, and exploitation techniques.

### Protocol Characteristics

#### TCP (Transmission Control Protocol)
- **Connection-oriented:** Establishes a session before data transfer
- **Reliable:** Guarantees packet delivery and order
- **Flow control:** Manages data transmission rate
- **Error checking:** Built-in error detection and correction
- **Use Cases:** HTTP, HTTPS, SSH, FTP, SMTP, POP3

#### UDP (User Datagram Protocol)
- **Connectionless:** No session establishment required
- **Unreliable:** No delivery guarantee
- **Fast:** Minimal overhead for quick transmission
- **Fire-and-forget:** Sends data without confirmation
- **Use Cases:** DNS, DHCP, SNMP, TFTP, Video streaming

### Technical Differences

#### TCP Three-Way Handshake
```bash
# TCP Connection Process
Client → Server: SYN (Synchronize)
Server → Client: SYN-ACK (Synchronize-Acknowledge)  
Client → Server: ACK (Acknowledge)
# Connection established
```

#### UDP Communication
```bash
# UDP Communication Process
Client → Server: Data packet
# No handshake, no confirmation required
```

### Protocol Comparison Table

| Feature | TCP | UDP |
|---------|-----|-----|
| **Connection** | Connection-oriented | Connectionless |
| **Reliability** | Reliable delivery | Best-effort delivery |
| **Speed** | Slower (overhead) | Faster (minimal overhead) |
| **Header Size** | 20 bytes minimum | 8 bytes fixed |
| **Flow Control** | Yes | No |
| **Error Recovery** | Yes | No |
| **Ordering** | Guaranteed order | No ordering guarantee |
| **Use Cases** | Web, email, file transfer | DNS, DHCP, streaming |

### Pentesting Applications

#### TCP Connection Analysis with Nmap
```bash
# TCP SYN scan showing connection-oriented behavior
nmap -sS -p 80,443 192.168.1.100

# Expected output
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https
```

#### UDP Service Discovery
```bash
# UDP scan for common UDP services
nmap -sU -p 53,67,161 192.168.1.100

# Expected output  
PORT    STATE         SERVICE
53/udp  open          domain
67/udp  open|filtered dhcps
161/udp open|filtered snmp
```

#### Protocol Behavior with Netcat
```bash
# TCP connection test
nc -v 192.168.1.100 80
# Output: Connection to 192.168.1.100 80 port [tcp/http] succeeded!

# UDP connection test  
nc -u -v 192.168.1.100 53
# Output: Connection to 192.168.1.100 53 port [udp/domain] succeeded!
```

### Common TCP and UDP Ports

#### Essential TCP Ports
| Port | Service | Usage |
|------|---------|--------|
| 21 | FTP | File transfer |
| 22 | SSH | Secure shell |
| 23 | Telnet | Remote access |
| 25 | SMTP | Email transfer |
| 53 | DNS | Domain resolution |
| 80 | HTTP | Web traffic |
| 110 | POP3 | Email retrieval |
| 143 | IMAP | Email access |
| 443 | HTTPS | Secure web |
| 993 | IMAPS | Secure IMAP |
| 995 | POP3S | Secure POP3 |

#### Essential UDP Ports
| Port | Service | Usage |
|------|---------|--------|
| 53 | DNS | Domain queries |
| 67/68 | DHCP | IP assignment |
| 69 | TFTP | Trivial file transfer |
| 123 | NTP | Time synchronization |
| 161/162 | SNMP | Network management |
| 500 | IKE | VPN key exchange |
| 514 | Syslog | System logging |
| 1194 | OpenVPN | VPN connection |

---

## 🌐 Subnetting & CIDR Notation {#subnetting}

Subnetting is the practice of dividing a network into smaller sub-networks (subnets) to improve security, performance, and organization. It's essential for penetration testers to understand network boundaries and identify target ranges during assessments.

### IP Address Fundamentals

#### IP Address Classes
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

#### CIDR Notation Basics
```bash
# CIDR format: IP_ADDRESS/PREFIX_LENGTH
192.168.1.0/24    # /24 = 255.255.255.0
10.0.0.0/8        # /8 = 255.0.0.0
172.16.0.0/16     # /16 = 255.255.0.0
```

### Subnet Calculation Methods

#### Quick Calculation Table
| CIDR | Subnet Mask | Hosts per Subnet | Number of Subnets |
|------|-------------|------------------|-------------------|
| /24 | 255.255.255.0 | 254 | 1 |
| /25 | 255.255.255.128 | 126 | 2 |
| /26 | 255.255.255.192 | 62 | 4 |
| /27 | 255.255.255.224 | 30 | 8 |
| /28 | 255.255.255.240 | 14 | 16 |
| /29 | 255.255.255.248 | 6 | 32 |
| /30 | 255.255.255.252 | 2 | 64 |

#### Essential Formulas
| Calculation | Formula | Purpose |
|-------------|---------|---------|
| Number of Subnets | 2^(borrowed bits) | How many subnets created |
| Hosts per Subnet | 2^(host bits) - 2 | Available host addresses |
| Subnet Increment | 256 - subnet mask octet | Spacing between subnets |
| Network Address | First address in range | Identifies the subnet |
| Broadcast Address | Last address in range | Subnet broadcast |
| Host Range | Network + 1 to Broadcast - 1 | Assignable addresses |

#### Step-by-Step Calculation Example
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

### Practical Pentesting Examples

#### Network Scope Identification
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

#### VLSM Scenario
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

---

## 🔌 Ports & Protocols Essentials {#ports-protocols}

Understanding network ports and protocols is fundamental to penetration testing and network security assessment. Ports are communication endpoints that allow different services to run simultaneously on a single system.

### Port Categories and Ranges

#### Port Range Classification
```bash
# Well-known ports (System Ports)
Range: 0-1023
Usage: Reserved for system services
Access: Requires administrative privileges

# Registered ports (User Ports)  
Range: 1024-49151
Usage: Applications and services
Access: Normal user privileges

# Dynamic/Private ports (Ephemeral Ports)
Range: 49152-65535
Usage: Temporary client connections
Access: Automatically assigned
```

#### Port States in Scanning
| State | Description | Security Implication |
|-------|-------------|---------------------|
| **Open** | Service actively listening | Potential attack vector |
| **Closed** | Port accessible but no service | System is reachable |
| **Filtered** | Blocked by firewall/filter | Security controls present |
| **Unfiltered** | Accessible but state unknown | Requires further testing |
| **Open\|Filtered** | Nmap cannot determine state | Possible stealth filtering |

### Critical Ports for Penetration Testing

#### Web Services Ports
| Port | Service | Protocol | Security Focus |
|------|---------|----------|----------------|
| **80** | HTTP | TCP | Unencrypted web traffic |
| **443** | HTTPS | TCP | Encrypted web traffic |
| **8080** | HTTP Proxy | TCP | Alternative HTTP port |
| **8443** | HTTPS Alternative | TCP | Alternative HTTPS port |

#### File Transfer Ports
| Port | Service | Protocol | Attack Vectors |
|------|---------|----------|----------------|
| **21** | FTP | TCP | Anonymous login, clear-text |
| **22** | SSH/SFTP | TCP | Brute force, weak keys |
| **69** | TFTP | UDP | No authentication |
| **989/990** | FTPS | TCP | Encrypted FTP variants |

#### Email Services Ports
| Port | Service | Protocol | Vulnerabilities |
|------|---------|----------|----------------|
| **25** | SMTP | TCP | Email relay, spam |
| **110** | POP3 | TCP | Clear-text authentication |
| **143** | IMAP | TCP | Email access protocols |
| **993/995** | IMAPS/POP3S | TCP | Encrypted email variants |

#### Database Ports
| Port | Service | Protocol | Common Attacks |
|------|---------|----------|----------------|
| **3306** | MySQL | TCP | Default credentials, injection |
| **1433** | MSSQL | TCP | SA account, stored procedures |
| **5432** | PostgreSQL | TCP | Privilege escalation |
| **1521** | Oracle | TCP | TNS listener attacks |

#### Network Services Ports
| Port | Service | Protocol | Exploitation Notes |
|------|---------|----------|-------------------|
| **53** | DNS | TCP/UDP | Zone transfers, cache poisoning |
| **135** | RPC Endpoint | TCP | Windows RPC services |
| **139** | NetBIOS | TCP | SMB over NetBIOS |
| **445** | SMB | TCP | File sharing, lateral movement |

#### Remote Access Ports
| Port | Service | Protocol | Security Risks |
|------|---------|----------|----------------|
| **3389** | RDP | TCP | Windows Remote Desktop |
| **5900** | VNC | TCP | Virtual Network Computing |
| **23** | Telnet | TCP | Clear-text remote access |
| **512-514** | R-services | TCP | Rlogin, rexec, rsh |

### Protocol-Specific Examples

#### Port Scanning and Service Identification
```bash
# Quick port scan of common services
nmap -sS -p 21,22,23,25,53,80,110,139,143,443,993,995,1433,3306,3389,5432 192.168.1.100

# Output Analysis:
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh  
80/tcp   open  http
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3306/tcp open  mysql

# Service version detection
nmap -sV -p 21,22,80,3306 192.168.1.100

# Output:
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 7.4
80/tcp   open  http    Apache httpd 2.4.6
3306/tcp open  mysql   MySQL 5.7.26
```

#### Protocol-Specific Enumeration
```bash
# HTTP service enumeration
curl -I http://192.168.1.100
# Output: Server headers and version information

# FTP service testing  
ftp 192.168.1.100
# Test: anonymous login attempt
Name: anonymous
Password: anonymous@domain.com

# SSH service testing
ssh -V 192.168.1.100
# Output: Protocol versions and algorithms supported

# MySQL service testing
mysql -h 192.168.1.100 -u root -p
# Test: Default credentials and access
```

#### UDP Service Discovery
```bash
# UDP port scanning (slower but important)
nmap -sU --top-ports 100 192.168.1.100

# Common UDP services found:
PORT    STATE SERVICE
53/udp  open  dns
69/udp  open  tftp  
161/udp open  snmp

# SNMP enumeration example
snmpwalk -v2c -c public 192.168.1.100
# Output: System information via SNMP
```

---

## 🎯 eJPT Network Requirements {#ejpt-requirements}

### Essential Skills for eJPT (Coverage Percentages)

#### OSI Model Knowledge (30% exam relevance)
- **Layer identification** during network analysis
- **Protocol classification** by OSI layer
- **Attack vector mapping** to specific layers
- **Troubleshooting approach** using layer methodology

#### TCP/UDP Understanding (25% exam relevance)
- **Protocol recognition** in network traffic
- **Port scanning methodology** differences
- **Service enumeration** based on protocol type
- **Firewall evasion** techniques

#### Subnetting Skills (85% exam importance)
- **CIDR to subnet mask conversion**
- **Host range calculation** 
- **Network boundary identification**
- **Subnet scope determination**

#### Port/Protocol Knowledge (90% exam importance)
- **Service identification** during reconnaissance
- **Attack surface mapping** and vulnerability assessment
- **Protocol-specific exploitation** techniques
- **Common service vulnerabilities**

### Critical Commands to Master

#### Network Discovery
```bash
# Essential scanning commands
nmap -sn 192.168.1.0/24              # Network discovery
nmap -sS -sU target_ip                # TCP/UDP scanning
nmap -sV target_ip                    # Service version detection
nmap -p- target_ip                    # Full port range scan
nmap --top-ports 1000 target_ip       # Most common 1000 ports
```

#### Service Enumeration
```bash
curl -I http://target_ip              # HTTP header analysis
telnet target_ip port_number          # Manual service interaction
nc -nv target_ip port_number          # Netcat connection testing
```

### Exam Tips and Best Practices

#### Networking Fundamentals
- **Tip 1:** Memorize OSI layer functions and common protocols
- **Tip 2:** Understand TCP vs UDP differences for scanning strategies
- **Tip 3:** Practice CIDR calculations manually and with tools
- **Tip 4:** Know default ports for major services by memory

#### Common eJPT Questions
- Convert between CIDR notation and subnet masks
- Identify which protocols services typically use (TCP/UDP)
- Calculate network ranges and host counts
- Map attack techniques to appropriate OSI layers

---

## 🧪 Practical Integration Examples {#practical-examples}

### Layer-Based Attack Approach
```bash
# Layer 1 - Physical attacks
Physical network access
Cable tapping
Wireless signal interception

# Layer 2 - Data Link attacks
arp-scan -l                    # ARP scanning
ettercap -T -M arp:remote     # ARP poisoning

# Layer 3 - Network attacks
nmap -sn 192.168.1.0/24       # Network discovery
hping3 -S -p 80 target        # IP spoofing

# Layer 4 - Transport attacks
nmap -sS target               # TCP SYN scanning
nmap -sU target               # UDP scanning

# Layer 7 - Application attacks
nikto -h target               # Web vulnerability scanning
hydra -l admin -P passwords.txt target http-get
```

### Integrated Workflow Example
```bash
# Step 1: Network Discovery (using subnetting knowledge)
nmap -sn 192.168.1.0/24

# Step 2: Port Scanning (TCP/UDP understanding)
nmap -sS -sU -p- discovered_hosts

# Step 3: Service Enumeration (port/protocol knowledge)
nmap -sV -sC -p open_ports targets

# Step 4: Layer-specific Analysis (OSI model application)
# Layer 7: HTTP services → nikto, gobuster
# Layer 4: Transport → detailed port analysis
# Layer 3: Network → routing and subnet analysis
```

### Documentation Template
```markdown
## Network Analysis - Complete Assessment

### Network Scope (Subnetting)
- Target Network: 192.168.1.0/24
- Available Hosts: 254
- Subnet Analysis: Single /24 network

### Protocol Analysis (TCP/UDP)
- TCP Services: 21, 22, 80, 443, 3306
- UDP Services: 53, 161
- Mixed Protocol: DNS (53/tcp, 53/udp)

### OSI Layer Findings
- Layer 7 (Application): HTTP, SSH, FTP services
- Layer 4 (Transport): TCP/UDP port analysis
- Layer 3 (Network): IP addressing and routing
- Layer 2 (Data Link): ARP table analysis

### Port/Service Summary
- Critical Services: SSH (22), HTTP (80), MySQL (3306)
- Security Concerns: Anonymous FTP, default credentials
- Recommendations: Service hardening, access controls
```

---

## 📚 Quick Reference

### Must-Know Conversions
```bash
/24 = 255.255.255.0    # Standard Class C
/16 = 255.255.0.0      # Standard Class B  
/8 = 255.0.0.0         # Standard Class A
/30 = 255.255.255.252  # Point-to-point links
/26 = 255.255.255.192  # Common subnet size
```

### Common Port Mnemonics
- **HTTP:** "80 is Great!"
- **HTTPS:** "443 is Secure!"
- **SSH:** "22 is the Key!"
- **FTP:** "21 for Fun Transfer!"
- **Telnet:** "23 is Clear Text!"

### OSI Memory Aid
**"All Pentesters Should Try New Data Protocols"**
- **A**pplication, **P**resentation, **S**ession, **T**ransport, **N**etwork, **D**ata Link, **P**hysical

This comprehensive guide provides all networking fundamentals necessary for eJPT success, integrating OSI model understanding, protocol analysis, subnetting skills, and port/service knowledge into a unified learning resource.
