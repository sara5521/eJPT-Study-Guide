# 🌐 OSI Model - 7-Layer Network Architecture

Understanding the Open Systems Interconnection (OSI) model is fundamental for network penetration testing and troubleshooting network communications.
**Location:** `01-theory-foundations/networking-basics/osi-model.md`

## 🎯 What is the OSI Model?

The OSI (Open Systems Interconnection) model is a conceptual framework that standardizes network communication functions into seven distinct layers. Each layer has specific responsibilities and communicates with the layers directly above and below it.

The OSI model is essential for penetration testers because it helps:
- Understand where attacks can occur in network communication
- Troubleshoot network issues systematically
- Identify security vulnerabilities at different network levels
- Plan targeted attacks against specific network layers

## 📋 The 7 Layers of OSI Model

### Layer 7: Application Layer 🖥️
**Function:** User interface and network services
**Protocols:** HTTP, HTTPS, FTP, SSH, Telnet, SMTP, DNS
**Pentesting Focus:** Web application attacks, protocol exploitation

### Layer 6: Presentation Layer 🎨
**Function:** Data formatting, encryption, compression
**Protocols:** SSL/TLS, JPEG, GIF, ASCII
**Pentesting Focus:** Encryption weaknesses, data format attacks

### Layer 5: Session Layer 🤝
**Function:** Session management, connection establishment
**Protocols:** NetBIOS, RPC, SQL sessions
**Pentesting Focus:** Session hijacking, session fixation

### Layer 4: Transport Layer 🚛
**Function:** End-to-end communication, reliability
**Protocols:** TCP, UDP
**Pentesting Focus:** Port scanning, service enumeration

### Layer 3: Network Layer 🗺️
**Function:** Routing, logical addressing
**Protocols:** IP, ICMP, ARP, OSPF
**Pentesting Focus:** IP spoofing, routing attacks, ICMP tunneling

### Layer 2: Data Link Layer 🔗
**Function:** Frame formatting, error detection, MAC addressing
**Protocols:** Ethernet, WiFi (802.11), PPP
**Pentesting Focus:** MAC spoofing, ARP poisoning, WiFi attacks

### Layer 1: Physical Layer ⚡
**Function:** Physical transmission of raw bits
**Components:** Cables, switches, hubs, wireless signals
**Pentesting Focus:** Physical access, cable tapping, wireless interception

## 🧪 Real Lab Examples

### Example 1: HTTP Communication Analysis
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

### Example 2: Ping Command Layer Analysis
```bash
# Simple ping command
ping 8.8.8.8

# Layer breakdown:
# Layer 7: Application - ping utility
# Layer 6: Presentation - Data formatting
# Layer 5: Session - ICMP session
# Layer 4: Transport - ICMP (no TCP/UDP)
# Layer 3: Network - IP routing to 8.8.8.8
# Layer 2: Data Link - Ethernet framing
# Layer 1: Physical - Network interface transmission
```

### Example 3: SSH Connection Layers
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

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **Layer identification** during network analysis (30%)
- **Protocol classification** by OSI layer (25%)
- **Attack vector mapping** to specific layers (25%)
- **Troubleshooting approach** using layer methodology (20%)

### Critical Knowledge Areas:
```bash
# Layer 4 - Transport protocols
TCP vs UDP characteristics
Port number ranges and services

# Layer 3 - Network addressing
IP addressing and subnetting
ARP protocol functionality

# Layer 7 - Application protocols
HTTP/HTTPS, FTP, SSH, DNS
Web application communication
```

### eJPT Exam Scenarios:
1. **Network Traffic Analysis:** Identify which OSI layer a captured packet belongs to
   - Required skills: Protocol identification, layer classification
   - Expected knowledge: TCP/IP stack understanding
   - Success criteria: Correctly identify layer functions

2. **Attack Planning:** Map penetration testing techniques to appropriate OSI layers
   - Required skills: Attack classification, layer targeting
   - Expected knowledge: Where different attacks operate
   - Success criteria: Strategic attack planning

### Exam Tips:
- **Remember the mnemonic:** "All People Seem To Need Data Processing"
- **Focus on Layers 3, 4, and 7** - most relevant for eJPT
- **Understand TCP/IP mapping** to OSI layers
- **Practice packet analysis** with real network traffic

## 📊 OSI vs TCP/IP Model Comparison

| OSI Layer | TCP/IP Layer | Key Protocols | Pentesting Focus |
|-----------|--------------|---------------|------------------|
| Application (7) | Application | HTTP, FTP, SSH | Web attacks, service exploitation |
| Presentation (6) | Application | SSL/TLS, encryption | Crypto attacks, format manipulation |
| Session (5) | Application | NetBIOS, RPC | Session attacks, hijacking |
| Transport (4) | Transport | TCP, UDP | Port scanning, service enum |
| Network (3) | Internet | IP, ICMP, ARP | IP spoofing, routing attacks |
| Data Link (2) | Network Access | Ethernet, WiFi | ARP poisoning, MAC spoofing |
| Physical (1) | Network Access | Cables, wireless | Physical access, interception |

## 🔧 Practical Penetration Testing Applications

### Layer-Based Attack Approach:
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

### Layer-Specific Enumeration:
```bash
# Application Layer (7) - Service identification
whatweb target
nmap -sV target

# Transport Layer (4) - Port discovery
nmap -p- target
masscan -p1-65535 target

# Network Layer (3) - Network mapping
nmap -sn network/24
netdiscover -r network/24
```

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Confusion Between OSI and TCP/IP
**Problem:** Mixing up OSI theoretical model with practical TCP/IP implementation
**Solution:** Focus on practical TCP/IP for hands-on work, use OSI for conceptual understanding

### Issue 2: Layer 5-6-7 Distinction
**Problem:** Difficulty distinguishing between Session, Presentation, and Application layers
**Solution:** Remember that in TCP/IP, these often merge into the Application layer

### Issue 3: Physical Layer Misunderstanding
**Problem:** Thinking Physical layer only includes cables
**Solution:** Remember it includes all transmission media: copper, fiber, wireless, Bluetooth

## 🔗 Integration with Other Topics

### Network Protocols Understanding:
- Builds foundation for **TCP vs UDP** concepts
- Essential for **Port Scanning** comprehension
- Critical for **Network Commands** usage

### Penetration Testing Methodology:
- Guides systematic **Information Gathering** approach
- Informs **Service Enumeration** strategies  
- Supports **Vulnerability Assessment** planning

## 📝 Documentation and Reporting

### Evidence Collection:
- **Network diagrams** showing layer interactions
- **Packet captures** demonstrating layer encapsulation
- **Protocol analysis** reports by layer
- **Attack surface mapping** across OSI layers

### Report Template:
```markdown
## Network Analysis - OSI Layer Breakdown

### Target Network: network_identifier
### Analysis Date: timestamp

### Layer 7 - Application Services
- HTTP services: findings
- FTP services: findings  
- SSH services: findings

### Layer 4 - Transport Analysis
- Open TCP ports: port_list
- Open UDP ports: port_list
- Service responses: analysis

### Layer 3 - Network Infrastructure
- IP addressing scheme: details
- Routing information: findings
- ICMP responses: analysis

### Recommendations by Layer
- Application layer security: recommendations
- Transport layer hardening: recommendations
- Network layer protection: recommendations
```

## 📚 Memory Aids and Mnemonics

### Popular Mnemonics:
- **"All People Seem To Need Data Processing"** (Application → Physical)
- **"Please Do Not Throw Sausage Pizza Away"** (Physical → Application)
- **"All Pentesters Should Try New Data Protocols"** (Security-focused version)

### Layer Function Summary:
```
7 - Application:  "What the user sees"
6 - Presentation: "How data is formatted"  
5 - Session:      "Managing conversations"
4 - Transport:    "End-to-end delivery"
3 - Network:      "Finding the path"
2 - Data Link:    "Node-to-node delivery"
1 - Physical:     "Bits on the wire"
```
