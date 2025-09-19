# 🏗️ OSI Model - Network Communication Framework

**Understanding the 7-layer network communication model essential for penetration testing**
**Location:** `01-theory-foundations/networking-basics/osi-model.md`

## 🎯 What is the OSI Model?

The Open Systems Interconnection (OSI) model is a conceptual framework that standardizes the functions of a communication system into seven distinct layers. Each layer serves specific functions and communicates with the layers directly above and below it. For penetration testers, understanding the OSI model is crucial as it helps identify where vulnerabilities exist, which protocols operate at each layer, and how attacks can target specific network functions.

The OSI model provides a systematic approach to network troubleshooting and security assessment, making it an essential foundation for eJPT candidates.

## 📦 The Seven Layers Overview

### Layer Structure (Bottom to Top):
```
Layer 7: Application    (HTTP, FTP, SSH, DNS)
Layer 6: Presentation   (SSL/TLS, encryption, compression)
Layer 5: Session        (NetBIOS, RPC, SQL sessions)
Layer 4: Transport      (TCP, UDP)
Layer 3: Network        (IP, ICMP, routing)
Layer 2: Data Link      (Ethernet, WiFi, ARP)
Layer 1: Physical       (Cables, wireless signals)
```

### Memory Aid:
**"All People Seem To Need Data Processing"**
- **A**pplication
- **P**resentation  
- **S**ession
- **T**ransport
- **N**etwork
- **D**ata Link
- **P**hysical

## 🔧 Detailed Layer Analysis

### Layer 1: Physical Layer
```bash
# Physical layer deals with raw bits transmission
# Examples: Ethernet cables, WiFi signals, fiber optics
# Pentesting relevance: Physical access attacks, cable tapping
```

**Functions:**
- Electrical and physical specifications
- Bit transmission over physical medium
- Signal encoding and timing

**Penetration Testing Considerations:**
- Physical security assessments
- Cable interception attacks
- Wireless signal analysis

### Layer 2: Data Link Layer
```bash
# Ethernet frame structure
# Source MAC | Destination MAC | EtherType | Data | CRC
# Example: ARP spoofing attacks target this layer
```

**Functions:**
- Frame formatting and error detection
- MAC address handling
- Media access control

**Common Protocols:**
- Ethernet (IEEE 802.3)
- WiFi (IEEE 802.11)
- ARP (Address Resolution Protocol)

### Layer 3: Network Layer
```bash
# IP packet structure and routing
# Example: IP spoofing and routing attacks
ping 192.168.1.1
traceroute 8.8.8.8
```

**Functions:**
- Logical addressing (IP addresses)
- Routing between networks
- Packet forwarding

**Common Protocols:**
- IPv4/IPv6
- ICMP
- OSPF, BGP (routing protocols)

### Layer 4: Transport Layer
```bash
# TCP connection establishment
# Client -> Server: SYN
# Server -> Client: SYN-ACK  
# Client -> Server: ACK

# UDP connectionless communication
# Direct data transmission without handshake
```

**Functions:**
- End-to-end communication
- Port addressing
- Flow control and error recovery

**Common Protocols:**
- TCP (reliable, connection-oriented)
- UDP (fast, connectionless)

### Layer 5: Session Layer
```bash
# Session management examples
# NetBIOS session establishment
# RPC remote procedure calls
# SQL database sessions
```

**Functions:**
- Session establishment and management
- Dialog control
- Session checkpointing and recovery

**Common Protocols:**
- NetBIOS
- RPC (Remote Procedure Call)
- PPTP (Point-to-Point Tunneling)

### Layer 6: Presentation Layer
```bash
# Encryption and data transformation
# SSL/TLS handshake process
# Data compression and decompression
# Character encoding (ASCII, Unicode)
```

**Functions:**
- Data encryption and decryption
- Compression and decompression
- Data format translation

**Common Protocols:**
- SSL/TLS
- JPEG, GIF (image formats)
- ASCII, EBCDIC (character encoding)

### Layer 7: Application Layer
```bash
# User-facing protocols and services
curl -I http://example.com        # HTTP
nslookup example.com             # DNS
ssh user@192.168.1.100          # SSH
ftp 192.168.1.100               # FTP
```

**Functions:**
- User interface and application services
- Network process to application
- Direct user interaction

**Common Protocols:**
- HTTP/HTTPS
- FTP/SFTP
- SSH
- DNS
- SMTP/POP3/IMAP

## ⚙️ OSI Model Layer Comparison Table

| Layer | Name | Function | Protocols | Pentesting Focus |
|-------|------|----------|-----------|------------------|
| **7** | Application | User services | HTTP, FTP, SSH, DNS | Web attacks, service exploitation |
| **6** | Presentation | Data formatting | SSL/TLS, encryption | Crypto attacks, certificate issues |
| **5** | Session | Session management | NetBIOS, RPC, SQL | Session hijacking, authentication |
| **4** | Transport | End-to-end delivery | TCP, UDP | Port scanning, service enumeration |
| **3** | Network | Routing | IP, ICMP, routing | Network reconnaissance, routing attacks |
| **2** | Data Link | Frame delivery | Ethernet, ARP, WiFi | ARP spoofing, MAC flooding |
| **1** | Physical | Bit transmission | Cables, wireless | Physical access, signal interception |

### Protocol Distribution by Layer:
| Layer | Key Protocols | Port Examples |
|-------|---------------|---------------|
| **Layer 7** | HTTP, HTTPS, FTP, SSH, DNS, SMTP | 80, 443, 21, 22, 53, 25 |
| **Layer 4** | TCP, UDP | Port numbers (1-65535) |
| **Layer 3** | IPv4, IPv6, ICMP | IP addresses |
| **Layer 2** | Ethernet, ARP, WiFi | MAC addresses |

## 🧪 Real Lab Examples

### Example 1: Layer-by-Layer Network Analysis
```bash
# Layer 1-2: Network interface and MAC discovery
ip link show
# Output: Shows physical interfaces and MAC addresses
# eth0: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state UP
# link/ether 08:00:27:12:34:56 brd ff:ff:ff:ff:ff:ff

# Layer 3: IP configuration and routing
ip route show
# Output: Shows routing table
# default via 192.168.1.1 dev eth0 proto dhcp metric 100
# 192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100

# Layer 4: Port scanning (TCP/UDP)
nmap -sS -p 1-1000 192.168.1.100
# Output: TCP ports and services
# 22/tcp  open  ssh
# 80/tcp  open  http
# 443/tcp open  https

# Layer 7: Application service detection
nmap -sV -p 80,443 192.168.1.100
# Output: Application layer details
# 80/tcp  open  http    Apache httpd 2.4.41
# 443/tcp open  https   Apache httpd 2.4.41 (SSL-only)
```

### Example 2: OSI Model Attack Vectors by Layer
```bash
# Layer 2 Attack: ARP Spoofing
arp -a
# Output: Current ARP table
# gateway (192.168.1.1) at 00:50:56:12:34:56 [ether] on eth0

# Layer 3 Attack: ICMP reconnaissance
ping -c 4 192.168.1.100
# Output: Host reachability and response time
# 64 bytes from 192.168.1.100: icmp_seq=1 ttl=64 time=0.234 ms

# Layer 4 Attack: Port scanning
nmap -sS 192.168.1.100
# Output: Open TCP ports for further enumeration

# Layer 7 Attack: HTTP service enumeration
curl -I http://192.168.1.100
# Output: HTTP headers and server information
# HTTP/1.1 200 OK
# Server: Apache/2.4.41 (Ubuntu)
# X-Powered-By: PHP/7.4.3
```

### Example 3: Protocol Stack Analysis
```bash
# Wireshark-style packet analysis showing all layers
tcpdump -i eth0 -nn -X host 192.168.1.100
# Output shows:
# Layer 2: Ethernet header (MAC addresses)
# Layer 3: IP header (source/destination IPs)
# Layer 4: TCP header (ports, sequence numbers)
# Layer 7: HTTP data (GET requests, responses)
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT (20% of networking fundamentals):
- **Layer identification** during reconnaissance (30%)
- **Protocol mapping** to appropriate layers (25%)
- **Attack vector classification** by OSI layer (25%)
- **Tool selection** based on layer targeting (20%)

### Critical Concepts to Master:
```bash
# Layer 2: ARP and MAC address handling
arp -a                          # View ARP table
ip neighbor show               # Modern ARP table viewing

# Layer 3: IP routing and ICMP
ping target_ip                 # ICMP echo requests
traceroute target_ip          # Path discovery

# Layer 4: Transport layer scanning
nmap -sS target_ip            # TCP SYN scan
nmap -sU target_ip            # UDP scan

# Layer 7: Application enumeration
nmap -sV target_ip            # Service version detection
curl -I http://target_ip      # HTTP header analysis
```

### eJPT Exam Scenarios:
1. **Network Reconnaissance:** Identifying services at different OSI layers
   - Required skills: Layer-appropriate tool selection
   - Expected commands: Multi-layer scanning approach
   - Success criteria: Complete service enumeration across layers

2. **Vulnerability Assessment:** Understanding where vulnerabilities exist
   - Required skills: Mapping vulnerabilities to OSI layers
   - Expected commands: Layer-specific vulnerability scanning
   - Success criteria: Accurate vulnerability classification

3. **Attack Planning:** Selecting attacks based on exposed layers
   - Required skills: Attack vector identification by layer
   - Expected commands: Layer-targeted exploitation tools
   - Success criteria: Successful exploitation planning

### Exam Tips and Tricks:
- **Tip 1:** Always think "bottom-up" - start with lower layers in reconnaissance
- **Tip 2:** Map discovered services to their appropriate OSI layers
- **Tip 3:** Understand that attacks can target multiple layers simultaneously
- **Tip 4:** Know which tools operate at which layers for proper selection

### Common eJPT Questions:
- Identifying which OSI layer a specific protocol operates at
- Explaining how an attack targets a particular layer
- Selecting appropriate tools based on layer requirements
- Understanding protocol relationships across layers

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Confusion Between Layers 2 and 3
**Problem:** Mixing up MAC addresses (Layer 2) with IP addresses (Layer 3)
**Cause:** Both are addressing schemes but serve different purposes
**Solution:**
```bash
# Layer 2 addressing (local network segment)
arp -a                    # Shows IP to MAC mappings
ip neighbor show         # Modern way to view ARP table

# Layer 3 addressing (logical network addressing)
ip addr show            # Shows IP configuration
ip route show          # Shows routing table
```

### Issue 2: Protocol Layer Misidentification
**Problem:** Incorrectly identifying which layer a protocol belongs to
**Solution:**
```bash
# Remember the protocol stack:
# HTTP/HTTPS/FTP/SSH = Layer 7 (Application)
# TCP/UDP = Layer 4 (Transport)
# IP/ICMP = Layer 3 (Network)
# Ethernet/ARP = Layer 2 (Data Link)
```

### Issue 3: Tool Selection for Wrong Layer
**Problem:** Using inappropriate tools for the target layer
**Solution:**
```bash
# Layer 2 tools: arping, ettercap (ARP-based)
# Layer 3 tools: ping, traceroute (IP-based)
# Layer 4 tools: nmap, nc (port-based)
# Layer 7 tools: curl, wget, nikto (application-based)
```

## 🔗 Integration with Other Tools

### Primary Integration: OSI-Based Reconnaissance Workflow
```bash
# Layer 1-2: Physical and Data Link discovery
ip link show                    # Physical interfaces
arp-scan -l                    # Local network discovery via ARP

# Layer 3: Network layer reconnaissance  
nmap -sn 192.168.1.0/24       # Ping sweep (ICMP)
nmap -PR 192.168.1.0/24       # ARP ping scan

# Layer 4: Transport layer enumeration
nmap -sS 192.168.1.100        # TCP port scan
nmap -sU --top-ports 100 192.168.1.100  # UDP scan

# Layer 7: Application layer analysis
nmap -sV -sC 192.168.1.100    # Service detection with scripts
nikto -h http://192.168.1.100  # Web application scanning
```

### Secondary Integration: Layer-Specific Vulnerability Assessment
```bash
# Multi-layer vulnerability scanning approach
nmap --script vuln 192.168.1.100     # Layer 3-7 vulnerabilities
nmap --script broadcast-* 192.168.1.0/24  # Layer 2 broadcast attacks
```

### Advanced Workflows:
```bash
# Complete OSI model reconnaissance
# 1. Physical/Data Link reconnaissance
netdiscover -r 192.168.1.0/24

# 2. Network layer mapping
nmap -sn 192.168.1.0/24

# 3. Transport layer enumeration  
nmap -sS -sU 192.168.1.100

# 4. Application layer fingerprinting
nmap -sV -sC 192.168.1.100
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Layer-by-Layer Results:** Document findings organized by OSI layer
2. **Protocol Mapping:** Show which protocols were found at each layer
3. **Attack Surface:** Identify potential attack vectors per layer
4. **Tool Outputs:** Save complete command outputs for each layer

### Report Template Structure:
```markdown
## OSI Model Network Analysis

### Target Information
- Target: 192.168.1.100
- Date/Time: 2025-01-15 15:45
- Analysis Scope: Full OSI stack assessment

### Layer 1-2: Physical and Data Link Analysis
```bash
ip link show
arp-scan -l
```
**Findings:**
- Physical interfaces: eth0 (08:00:27:12:34:56)
- Local devices discovered: 15 hosts
- Potential ARP spoofing opportunities identified

### Layer 3: Network Layer Analysis
```bash
nmap -sn 192.168.1.0/24
ping -c 4 192.168.1.100
```
**Findings:**
- Active hosts: 192.168.1.1, 192.168.1.100, 192.168.1.105
- ICMP responses: Normal (no filtering detected)
- Routing: Standard gateway configuration

### Layer 4: Transport Layer Analysis
```bash
nmap -sS -sU -p 1-1000 192.168.1.100
```
**Findings:**
- Open TCP ports: 22, 80, 443
- Open UDP ports: 53, 161
- Filtered ports: None detected

### Layer 7: Application Layer Analysis
```bash
nmap -sV -sC 192.168.1.100
```
**Findings:**
- SSH: OpenSSH 8.2p1 (protocol 2.0)
- HTTP: Apache httpd 2.4.41
- HTTPS: Apache httpd 2.4.41 with SSL
- DNS: ISC BIND 9.16.1
- SNMP: Net-SNMP 5.8

### Attack Surface Summary by Layer
- **Layer 2:** ARP spoofing potential
- **Layer 3:** No IP filtering, ICMP enabled
- **Layer 4:** Multiple service ports exposed
- **Layer 7:** Web applications, SSH, DNS services
```

## 📚 OSI Model Quick Reference

### Layer Functions Summary:
| Layer | Primary Function | Key Concepts |
|-------|------------------|--------------|
| **7 - Application** | User interface | HTTP, FTP, SSH, DNS protocols |
| **6 - Presentation** | Data formatting | Encryption, compression, encoding |
| **5 - Session** | Session control | Connection management, dialog control |
| **4 - Transport** | End-to-end delivery | TCP reliability, UDP speed, ports |
| **3 - Network** | Routing | IP addressing, packet forwarding |
| **2 - Data Link** | Frame delivery | MAC addressing, error detection |
| **1 - Physical** | Bit transmission | Electrical signals, cables, wireless |

### Pentesting Tools by Layer:
| Layer | Common Tools | Purpose |
|-------|--------------|---------|
| **Layer 7** | nmap -sV, nikto, curl, gobuster | Application enumeration |
| **Layer 4** | nmap -sS/-sU, nc, masscan | Port scanning |
| **Layer 3** | ping, traceroute, nmap -sn | Network discovery |
| **Layer 2** | arp-scan, ettercap, netdiscover | Local network mapping |
| **Layer 1** | Physical access tools | Hardware attacks |

### Protocol Examples by Layer:
```
Layer 7: HTTP(80), HTTPS(443), SSH(22), FTP(21), DNS(53), SMTP(25)
Layer 6: SSL/TLS, encryption protocols
Layer 5: NetBIOS, RPC, SQL sessions  
Layer 4: TCP, UDP (port numbers)
Layer 3: IPv4, IPv6, ICMP
Layer 2: Ethernet, ARP, WiFi (802.11)
Layer 1: Physical cables, wireless signals
```
