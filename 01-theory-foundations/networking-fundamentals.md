# 🌐 Networking Fundamentals - eJPT Study Guide

> **Complete networking foundations for penetration testing and eJPT certification success**

**Document Path:** `01-theory-foundations/networking-fundamentals.md`  

---

## 📋 Table of Contents

1. [Introduction to Network Security](#introduction)
2. [Network Models & Architecture](#network-models)
3. [Essential Protocols Deep Dive](#protocols)
4. [Port & Service Analysis](#ports-services)
5. [IP Addressing & Subnetting](#ip-addressing)
6. [Network Discovery & Reconnaissance](#network-discovery)
7. [Protocol Analysis & Traffic Inspection](#protocol-analysis)
8. [Common Network Vulnerabilities](#vulnerabilities)
9. [Practical Lab Exercises](#lab-exercises)
10. [eJPT Exam Preparation](#exam-prep)

---

## 🎯 Introduction to Network Security {#introduction}

### What is Networking for Penetration Testing?

Networking forms the **foundation** of all penetration testing activities. Every attack, every exploit, and every reconnaissance technique relies on understanding how networks communicate, function, and can be compromised.

#### Core Areas of Focus:
- **Network Architecture**: How networks are designed and connected
- **Protocol Stack**: Understanding communication layers and their vulnerabilities
- **Service Enumeration**: Identifying and analyzing running services
- **Traffic Analysis**: Monitoring and interpreting network communications
- **Attack Vectors**: Common network-based attack methods

#### Why This Matters for eJPT:
- **25% of exam content** involves network concepts
- **Foundation for all tools**: Nmap, Wireshark, Metasploit all rely on networking knowledge
- **Real-world relevance**: Networks are the primary attack surface in most environments

---

## 📚 Network Models & Architecture {#network-models}

### The OSI Model (Open Systems Interconnection)

The OSI model provides a **conceptual framework** for understanding network communications. Each layer has specific functions and potential attack vectors.

#### Complete OSI Layer Breakdown:

| Layer | Name | Function | Data Unit | Protocols/Examples | eJPT Attack Vectors |
|-------|------|----------|-----------|-------------------|-------------------|
| **7** | **Application** | User interface, network services | Data | HTTP/HTTPS, FTP, SSH, DNS, SMTP | Web app attacks, credential harvesting, service enumeration |
| **6** | **Presentation** | Data encryption, compression, translation | Data | SSL/TLS, JPEG, MPEG, ASCII | Certificate attacks, encryption weaknesses, data format exploits |
| **5** | **Session** | Session establishment, management, termination | Data | NetBIOS, SQL sessions, RPC | Session hijacking, authentication bypass, persistence |
| **4** | **Transport** | End-to-end delivery, flow control | Segments/Datagrams | TCP, UDP, SPX | Port scanning, service discovery, DoS attacks |
| **3** | **Network** | Routing, logical addressing | Packets | IP, ICMP, IPSec, OSPF | Network discovery, routing attacks, IP spoofing |
| **2** | **Data Link** | Physical addressing, frame delivery | Frames | Ethernet, PPP, ARP, STP | ARP poisoning, MAC flooding, VLAN hopping |
| **1** | **Physical** | Physical transmission of data | Bits | Cables, hubs, switches, WiFi | Physical access, cable tapping, signal interception |

#### Memory Device for OSI Layers:
**"Please Do Not Throw Sausage Pizza Away"** (Physical, Data Link, Network, Transport, Session, Presentation, Application)

### TCP/IP Model (Internet Protocol Suite)

The **practical model** used in real-world networking:

#### TCP/IP Layer Details:

| Layer | OSI Equivalent | Key Protocols | Primary Functions |
|-------|----------------|---------------|-------------------|
| **Application** | Layers 5-7 | HTTP, HTTPS, FTP, SSH, DNS, DHCP | User services, data formatting, session management |
| **Transport** | Layer 4 | TCP, UDP | Port addressing, connection management, data integrity |
| **Internet** | Layer 3 | IP, ICMP, ARP | Logical addressing, routing, error messaging |
| **Network Access** | Layers 1-2 | Ethernet, WiFi, PPP | Physical transmission, local addressing |

---

## 🔌 Essential Protocols Deep Dive {#protocols}

### Internet Protocol (IP)

#### IPv4 Structure & Analysis:
```bash
# IPv4 Address Components
192.168.1.100/24
├── Network Portion: 192.168.1.0 (24 bits)
├── Host Portion: 100 (8 bits)  
├── Subnet Mask: 255.255.255.0 (/24)
└── Broadcast: 192.168.1.255

# Address Classes (Historical)
Class A: 1.0.0.0 - 126.255.255.255    (/8 default)
Class B: 128.0.0.0 - 191.255.255.255  (/16 default)  
Class C: 192.0.0.0 - 223.255.255.255  (/24 default)
Class D: 224.0.0.0 - 239.255.255.255  (Multicast)
Class E: 240.0.0.0 - 255.255.255.255  (Reserved)
```

#### IPv6 Fundamentals:
```bash
# IPv6 Address Structure  
2001:0db8:85a3:0000:0000:8a2e:0370:7334
└── Expanded: 2001:db8:85a3::8a2e:370:7334 (compressed)

# IPv6 Address Types
Global Unicast:    2000::/3  (Internet routable)
Link-Local:        fe80::/10 (Local segment only)
Unique Local:      fc00::/7  (Private IPv6)
Multicast:         ff00::/8  (One-to-many)
```

### Transmission Control Protocol (TCP)

#### TCP Header Analysis:
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─────────────────┼─────────────────┼─────────────────┼─────────────────┤
│  Source Port    │ Destination Port│                                   │
├─────────────────┴─────────────────┼─────────────────────────────────────┤
│              Sequence Number                                          │
├─────────────────────────────────────┼─────────────────────────────────────┤
│            Acknowledgment Number                                      │
├───┬─────┬─┬─┬─┬─┬─┬─┬─────────────┼─────────────────────────────────────┤
│Hdr│ Res │U│A│P│R│S│F│   Window    │           Checksum    │  Urgent   │
│Len│     │R│C│S│S│Y│I│    Size     │                       │ Pointer   │
│   │     │G│K│H│T│N│N│             │                       │           │
└───┴─────┴─┴─┴─┴─┴─┴─┴─────────────┴─────────────────────────┴───────────┘
```

#### TCP Connection States:
```bash
# TCP State Transitions
CLOSED → SYN_SENT → SYN_RECEIVED → ESTABLISHED
          ↓              ↓              ↓
      TIME_WAIT ← FIN_WAIT ← CLOSE_WAIT ← ESTABLISHED

# Key States for Penetration Testing
LISTEN:      Port is open and accepting connections
ESTABLISHED: Active connection exists  
TIME_WAIT:   Connection recently closed
CLOSED:      Port is closed or filtered
```

#### TCP Flags in Detail:
| Flag | Bit | Purpose | Penetration Testing Use Cases |
|------|-----|---------|-------------------------------|
| **FIN** | 0x01 | Finish connection | FIN scan for stealth enumeration |
| **SYN** | 0x02 | Synchronize sequence numbers | SYN scan (most common), half-open connections |
| **RST** | 0x04 | Reset connection | Indicates closed port, connection termination |
| **PSH** | 0x08 | Push data immediately | Force immediate data transmission |
| **ACK** | 0x10 | Acknowledge receipt | ACK scan for firewall evasion |
| **URG** | 0x20 | Urgent pointer valid | Rarely used, can indicate data priority |
| **ECE** | 0x40 | ECN Echo | Congestion notification |
| **CWR** | 0x80 | Congestion Window Reduced | Congestion control |

### User Datagram Protocol (UDP)

#### UDP vs TCP Comparison:
| Feature | TCP | UDP | Penetration Testing Impact |
|---------|-----|-----|---------------------------|
| **Connection** | Connection-oriented | Connectionless | TCP easier to scan, UDP requires different techniques |
| **Reliability** | Reliable, ordered | Best-effort | UDP services may not respond to scans |
| **Speed** | Slower (overhead) | Faster | UDP good for real-time attacks (DNS, DHCP) |
| **Header Size** | 20 bytes minimum | 8 bytes | Less overhead in UDP |
| **Use Cases** | Web, email, file transfer | DNS, DHCP, streaming | Different services use different protocols |

#### UDP Header Structure:
```
 0      7 8     15 16    23 24    31
├────────┼────────┼────────┼────────┤
│ Source │ Destin │ Length │Checksum│
│  Port  │  Port  │        │        │
└────────┴────────┴────────┴────────┘
```

---

## 🚪 Comprehensive Port & Service Analysis {#ports-services}

### Critical TCP Ports for eJPT Mastery:

#### Web Services:
| Port | Service | Description | Common Vulnerabilities | Enumeration Commands |
|------|---------|-------------|----------------------|---------------------|
| **80** | HTTP | Hypertext Transfer Protocol | XSS, SQLi, directory traversal, CSRF | `curl -I target`, `dirb target` |
| **443** | HTTPS | HTTP over SSL/TLS | SSL/TLS misconfig, cert issues, weak ciphers | `sslscan target`, `testssl target` |
| **8080** | HTTP-Alt | Alternative HTTP port | Same as port 80, often less protected | `curl target:8080`, `nikto -h target:8080` |
| **8443** | HTTPS-Alt | Alternative HTTPS port | Same as port 443 | `curl -k https://target:8443` |

#### Remote Access Services:
| Port | Service | Description | Attack Vectors | Key Commands |
|------|---------|-------------|----------------|--------------|
| **22** | SSH | Secure Shell | Brute force, key-based attacks, tunneling | `ssh user@target`, `hydra -l user -P pass.txt ssh://target` |
| **23** | Telnet | Unencrypted remote access | Credential sniffing, clear text | `telnet target`, `nmap --script telnet-* target` |
| **3389** | RDP | Remote Desktop Protocol | Brute force, BlueKeep, credential attacks | `rdesktop target`, `ncrack -u admin -P pass.txt rdp://target` |
| **5985** | WinRM | Windows Remote Management | PS remoting, credential attacks | `evil-winrm -i target -u user -p pass` |

#### File Services:
| Port | Service | Description | Exploitation Techniques | Enumeration Methods |
|------|---------|-------------|----------------------|-------------------|
| **21** | FTP | File Transfer Protocol | Anonymous access, brute force, bounce | `ftp target`, `nmap --script ftp-* target` |
| **139** | NetBIOS-SSN | NetBIOS Session Service | Null sessions, SMB enumeration | `smbclient -L target`, `enum4linux target` |
| **445** | SMB | Server Message Block | EternalBlue, SMB relay, file access | `smbmap -H target`, `crackmapexec smb target` |
| **2049** | NFS | Network File System | Mount enumeration, file access | `showmount -e target`, `mount target:/share /mnt` |

#### Database Services:
| Port | Service | Description | Attack Methods | Connection Commands |
|------|---------|-------------|---------------|-------------------|
| **1433** | MSSQL | Microsoft SQL Server | SQLi, brute force, xp_cmdshell | `sqsh -S target -U sa`, `mssqlclient.py user@target` |
| **3306** | MySQL | MySQL Database | SQLi, brute force, privilege escalation | `mysql -h target -u root -p`, `nmap --script mysql-* target` |
| **5432** | PostgreSQL | PostgreSQL Database | SQLi, brute force, command execution | `psql -h target -U postgres`, `nmap --script pgsql-* target` |
| **1521** | Oracle | Oracle Database | TNS listener attacks, brute force | `sqlplus user/pass@target:1521/SID` |

#### Email Services:
| Port | Service | Description | Reconnaissance Value | Testing Commands |
|------|---------|-------------|---------------------|-----------------|
| **25** | SMTP | Simple Mail Transfer Protocol | User enumeration, relay testing | `telnet target 25`, `smtp-user-enum -M VRFY -U users.txt -t target` |
| **110** | POP3 | Post Office Protocol v3 | Credential attacks, email access | `telnet target 110`, `hydra -l user -P pass.txt pop3://target` |
| **143** | IMAP | Internet Message Access Protocol | Credential attacks, email enumeration | `telnet target 143`, `nmap --script imap-* target` |
| **993** | IMAPS | IMAP over SSL | Secure email access | `openssl s_client -connect target:993` |

### Critical UDP Ports for eJPT:

#### Network Infrastructure:
| Port | Service | Description | Attack Vectors | Discovery Commands |
|------|---------|-------------|----------------|-------------------|
| **53** | DNS | Domain Name System | Zone transfers, cache poisoning, enumeration | `dig @target example.com axfr`, `dnsrecon -d example.com` |
| **67/68** | DHCP | Dynamic Host Configuration | DHCP spoofing, network discovery | `nmap --script dhcp-discover target` |
| **123** | NTP | Network Time Protocol | Amplification attacks, time sync | `ntpq -p target`, `nmap -sU -p 123 target` |
| **161** | SNMP | Simple Network Management | Community string attacks, info disclosure | `snmpwalk -c public -v1 target`, `onesixtyone -c community.txt target` |

#### Real-time Services:
| Port | Service | Description | Exploitation Methods | Testing Approaches |
|------|---------|-------------|-------------------|------------------|
| **69** | TFTP | Trivial File Transfer Protocol | File enumeration, configuration extraction | `tftp target`, `nmap --script tftp-enum target` |
| **514** | Syslog | System Logging | Log injection, information disclosure | `nc -u target 514` |
| **520** | RIP | Routing Information Protocol | Route poisoning, network mapping | `nmap --script rip-discover target` |

---

## 🔢 Advanced IP Addressing & Subnetting {#ip-addressing}

### CIDR Notation Mastery:

#### Subnet Mask Reference Table:
| CIDR | Decimal Mask | Hosts | Networks | Use Case |
|------|--------------|-------|----------|----------|
| /30 | 255.255.255.252 | 2 | 16,777,216 | Point-to-point links |
| /29 | 255.255.255.248 | 6 | 8,388,608 | Small office networks |
| /28 | 255.255.255.240 | 14 | 4,194,304 | Department subnets |
| /27 | 255.255.255.224 | 30 | 2,097,152 | Small business |
| /26 | 255.255.255.192 | 62 | 1,048,576 | Medium office |
| /25 | 255.255.255.128 | 126 | 524,288 | Large department |
| /24 | 255.255.255.0 | 254 | 262,144 | Standard LAN |
| /23 | 255.255.254.0 | 510 | 131,072 | Large LAN |
| /22 | 255.255.252.0 | 1022 | 65,536 | Campus network |

### Subnetting Calculation Method:

#### Step-by-Step Subnet Analysis:
```bash
# Example: 192.168.1.64/26
# Step 1: Identify the subnet mask
/26 = 255.255.255.192

# Step 2: Calculate subnet size
32 - 26 = 6 host bits
2^6 = 64 total addresses
64 - 2 = 62 usable hosts

# Step 3: Find subnet boundaries
Block size = 256 - 192 = 64
Subnets: 0, 64, 128, 192

# Step 4: Complete subnet information
Network address:    192.168.1.64
First usable:       192.168.1.65  
Last usable:        192.168.1.126
Broadcast address:  192.168.1.127
Next subnet:        192.168.1.128
```

### Private vs Public IP Ranges:

#### RFC 1918 Private Address Ranges:
```bash
# Class A Private Range
10.0.0.0/8
└── Range: 10.0.0.0 - 10.255.255.255
└── Total IPs: 16,777,216
└── Use: Large enterprises, ISPs

# Class B Private Range  
172.16.0.0/12
└── Range: 172.16.0.0 - 172.31.255.255  
└── Total IPs: 1,048,576
└── Use: Medium enterprises

# Class C Private Range
192.168.0.0/16
└── Range: 192.168.0.0 - 192.168.255.255
└── Total IPs: 65,536  
└── Use: Home/small office
```

#### Special Purpose IP Addresses:
```bash
# Loopback Addresses
127.0.0.0/8          # 127.0.0.1 is localhost

# Link-Local Addresses  
169.254.0.0/16       # Auto-assigned when DHCP fails

# Multicast Addresses
224.0.0.0/4          # 224.0.0.0 - 239.255.255.255

# Broadcast Addresses
255.255.255.255      # Limited broadcast
x.x.x.255           # Directed broadcast (varies by subnet)
```

---

## 🔍 Network Discovery & Reconnaissance {#network-discovery}

### Host Discovery Techniques:

#### Ping Sweep Methods:
```bash
# Basic ping sweep
for i in {1..254}; do 
    ping -c 1 -W 1 192.168.1.$i > /dev/null 2>&1 && echo "192.168.1.$i is up"
done

# Advanced ping with different packet types
ping -c 3 target                    # Standard ICMP Echo
ping -c 3 -t 64 target             # Set TTL value  
ping -c 3 -s 1000 target           # Large packet size
ping -c 3 -i 0.2 target            # Fast ping (0.2s interval)

# Ping without ICMP (TCP/UDP alternatives)
nmap -sn -PS22,80,443 192.168.1.0/24  # TCP SYN ping
nmap -sn -PA80,443 192.168.1.0/24     # TCP ACK ping  
nmap -sn -PU53,161 192.168.1.0/24     # UDP ping
```

#### ARP-based Discovery:
```bash
# ARP sweep (local network only)
arp-scan -l                        # Scan local network
arp-scan 192.168.1.0/24           # Specific network range
netdiscover -r 192.168.1.0/24     # Passive ARP discovery
netdiscover -P 192.168.1.0/24     # Active ARP discovery

# ARP table analysis
arp -a                             # View current ARP table
ip neighbor show                   # Modern alternative to arp -a
```

### Port Scanning Strategies:

#### Nmap Scan Types Explained:
```bash
# TCP Connect Scan (-sT)
# Completes full TCP handshake
# Pros: Reliable, works without root
# Cons: Logged by target, slower
nmap -sT target

# TCP SYN Scan (-sS) [Default]  
# Half-open scan, doesn't complete handshake
# Pros: Stealthy, fast, accurate
# Cons: Requires root privileges  
nmap -sS target

# TCP ACK Scan (-sA)
# Sends ACK packets to determine firewall rules
# Pros: Firewall detection, mapping
# Cons: Doesn't identify open ports
nmap -sA target

# TCP FIN Scan (-sF)
# Sends FIN packets
# Pros: Evades some firewalls
# Cons: Unreliable on Windows
nmap -sF target

# UDP Scan (-sU)
# Scans UDP ports  
# Pros: Finds UDP services
# Cons: Slow, requires interpretation
nmap -sU target
```

#### Comprehensive Scanning Methodology:
```bash
# Phase 1: Quick discovery
nmap -sn 192.168.1.0/24

# Phase 2: Fast port scan
nmap -F target                     # Fast scan (100 most common ports)

# Phase 3: Comprehensive scan  
nmap -p- target                    # All 65535 ports

# Phase 4: Service enumeration
nmap -sV -sC -p open_ports target  # Version detection + scripts

# Phase 5: OS detection
nmap -O target                     # Operating system detection

# Combined comprehensive scan
nmap -sS -sV -sC -O -p- --script vuln target
```

---

## 📊 Protocol Analysis & Traffic Inspection {#protocol-analysis}

### Traffic Capture Fundamentals:

#### Tcpdump Command Reference:
```bash
# Basic capture commands
tcpdump -i eth0                    # Capture on interface eth0
tcpdump -i any                     # Capture on all interfaces  
tcpdump -c 100                     # Capture 100 packets only
tcpdump -w capture.pcap            # Write to file

# Protocol-specific filters
tcpdump tcp                        # TCP traffic only
tcpdump udp                        # UDP traffic only  
tcpdump icmp                       # ICMP traffic only
tcpdump arp                        # ARP traffic only

# Advanced filtering
tcpdump host 192.168.1.100         # Specific host
tcpdump net 192.168.1.0/24         # Network range
tcpdump port 80                     # Specific port
tcpdump src 192.168.1.100          # Source IP
tcpdump dst 192.168.1.100          # Destination IP

# Complex filter examples
tcpdump "tcp port 80 and src 192.168.1.100"
tcpdump "udp port 53 or tcp port 53"  
tcpdump "not port 22"              # Exclude SSH traffic
```

#### Reading Network Traffic:
```bash
# Analyze captured traffic
tcpdump -r capture.pcap -n         # Read file, no name resolution
tcpdump -r capture.pcap -v         # Verbose output
tcpdump -r capture.pcap -X         # Show packet contents in hex/ASCII

# Statistical analysis
tcpdump -r capture.pcap | awk '{print $3}' | sort | uniq -c | sort -nr
# Shows most active destinations

# Protocol distribution
tcpdump -r capture.pcap | awk '{print $2}' | sort | uniq -c
```

### Network Behavior Analysis:

#### Normal vs Suspicious Traffic Patterns:
| Traffic Type | Normal Behavior | Suspicious Indicators |
|--------------|-----------------|---------------------|
| **HTTP** | Regular page requests, standard user agents | Large downloads, unusual URIs, SQL injection attempts |
| **DNS** | Standard name resolution, cached responses | High query volume, DGA domains, tunneling |
| **SSH** | Periodic admin access, key-based auth | Brute force attempts, unusual login times |
| **SMB** | File sharing, printer access | Lateral movement, credential dumping |

---

## ⚠️ Common Network Vulnerabilities {#vulnerabilities}

### Layer 2 (Data Link) Attacks:

#### ARP Spoofing/Poisoning:
```bash
# Understanding ARP Process
1. Host A needs to reach Host B (192.168.1.100)  
2. Host A broadcasts: "Who has 192.168.1.100?"
3. Host B responds: "192.168.1.100 is at MAC:AA:BB:CC:DD:EE"
4. Attacker sends fake response: "192.168.1.100 is at MAC:FF:FF:FF:FF:FF"

# Detection methods
arp -a                             # Check for duplicate IPs
arpwatch                          # Monitor ARP activity  
tcpdump arp                       # Watch ARP traffic

# Protection measures
- Static ARP entries
- Dynamic ARP Inspection (DAI)
- Port security on switches
```

#### MAC Address Flooding:
```bash
# Attack concept
- Flood switch with fake MAC addresses
- Fill up MAC address table  
- Switch fails to hub mode
- Traffic becomes visible to all ports

# Detection signs
- High CPU on network devices
- Broadcast storms
- Network performance degradation
```

### Layer 3 (Network) Attacks:

#### IP Spoofing:
```bash
# Types of IP spoofing
1. Random spoofing: Random source IPs
2. Subnet spoofing: IPs from target's subnet  
3. Fixed spoofing: Single fake IP address

# Detection methods
ip route get [suspicious_ip]       # Check routing
traceroute [target]               # Trace packet path
```

### Layer 4 (Transport) Attacks:

#### TCP Session Hijacking:
```bash
# Attack requirements
1. Predict sequence numbers
2. Inject packets into existing connection  
3. Maintain session state

# Protection methods
- Use encrypted protocols (SSH, HTTPS)
- Implement proper sequence number randomization
- Use IPSec for sensitive communications
```

---

## 🧪 Practical Lab Exercises {#lab-exercises}

### Lab Exercise 1: Network Mapping
```bash
# Objective: Map a network segment and identify all active hosts
# Target: 192.168.1.0/24

# Step 1: Initial discovery
nmap -sn 192.168.1.0/24 > live_hosts.txt

# Step 2: Extract live IPs  
grep "Nmap scan report" live_hosts.txt | awk '{print $5}' > ip_list.txt

# Step 3: Port scanning
while read ip; do
    echo "Scanning $ip..."
    nmap -sS -T4 -p- "$ip" | grep "open" >> "$ip"_ports.txt
done < ip_list.txt

# Step 4: Service enumeration
while read ip; do
    nmap -sV -sC "$ip" > "$ip"_services.txt  
done < ip_list.txt
```

### Lab Exercise 2: Protocol Analysis  
```bash
# Objective: Analyze network traffic for security issues
# Requirements: Access to network traffic or packet capture

# Step 1: Capture network traffic
tcpdump -i eth0 -w network_traffic.pcap &
# Let it run for 5-10 minutes, then stop with Ctrl+C

# Step 2: Analyze HTTP traffic
tcpdump -r network_traffic.pcap -A | grep -i "GET\|POST\|password\|login"

# Step 3: Check for clear-text protocols
tcpdump -r network_traffic.pcap port 21    # FTP
tcpdump -r network_traffic.pcap port 23    # Telnet  
tcpdump -r network_traffic.pcap port 25    # SMTP

# Step 4: DNS analysis
tcpdump -r network_traffic.pcap port 53 | head -20
```

### Lab Exercise 3: Service Enumeration
```bash
# Objective: Enumerate services on discovered hosts
# Target: Previously discovered hosts

# Step 1: Web service enumeration
curl -I http://target_ip              # Check headers
dirb http://target_ip                 # Directory brute force

# Step 2: SSH enumeration  
ssh -V target_ip 2>&1 | grep OpenSSH # Version detection
nmap --script ssh2-enum-algos target_ip

# Step 3: SMB enumeration (if Windows/Samba)
smbclient -L \\target_ip -N          # List shares
enum4linux -a target_ip             # Comprehensive enumeration

# Step 4: SNMP enumeration (if available)
snmpwalk -c public -v1 target_ip     # Walk SNMP tree
```

### Lab Exercise 4: Network Vulnerability Assessment
```bash
# Objective: Identify common network vulnerabilities
# Scope: Complete network assessment

# Step 1: Quick vulnerability scan
nmap --script vuln target_range

# Step 2: Check for common misconfigurations
# Anonymous FTP
nmap --script ftp-anon target_range

# Open SNMP
nmap -sU -p 161 --script snmp-info target_range

# Default credentials  
nmap --script http-default-accounts target_range

# Step 3: SSL/TLS assessment
nmap --script ssl-enum-ciphers -p 443 target_range
```

---

## 🎯 eJPT Exam Preparation Guide {#exam-prep}

### Exam Structure & Weightings:

#### Network Fundamentals (25% of exam):
- **Subnetting calculations** (5-7 questions)
- **Protocol identification** (3-5 questions)  
- **Port/service knowledge** (4-6 questions)
- **OSI/TCP-IP models** (2-3 questions)

#### Practical Skills Required:
- Calculate subnet ranges without a calculator
- Identify services by port numbers
- Understand protocol behaviors  
- Interpret network tool outputs

### Essential Commands for eJPT Success:

#### Network Discovery Commands:
```bash
# Host discovery
ping -c 1 target                   # Test single host
nmap -sn network_range            # Ping sweep
arp -a                            # Local network discovery

# Interface and routing  
ip addr show                      # Show interfaces
ip route show                     # Show routing table
netstat -rn                       # Alternative routing table
```

#### Service Enumeration Commands:
```bash
# Port scanning
nmap -sS target                   # SYN scan
nmap -sU target                   # UDP scan  
nmap -sV target                   # Version detection

# Service identification
netstat -tlnp                     # Listening TCP services
ss -tlnp                          # Modern netstat alternative  
lsof -i                           # Network connections by process
```

#### Network Analysis Commands:
```bash
# Traffic analysis
tcpdump -i interface              # Capture traffic
tcpdump -r file.pcap             # Read capture file
wireshark capture.pcap           # GUI analysis tool

# Network troubleshooting
traceroute target                # Trace network path
mtr target                       # Continuous traceroute
nslookup domain                  # DNS lookup
dig domain                       # Advanced DNS queries
```

### Critical Knowledge Areas for eJPT:

#### 1. Subnetting Mastery (Must-Know):
```bash
# Quick subnetting formulas
Hosts = 2^(host_bits) - 2
Networks = 2^(network_bits)
Block_size = 256 - last_octet_of_mask

# Practice problems (solve these quickly):
Problem 1: What is the network address of 172.16.50.100/22?
Answer: 172.16.48.0

Problem 2: How many hosts in a /27 network?
Answer: 30 hosts (2^5 - 2 = 30)

Problem 3: What is the broadcast address of 10.1.1.64/26?
Answer: 10.1.1.127
```

#### 2. Port Number Memorization (Essential):
```bash
# TCP Ports (memorize these)
21  = FTP          22  = SSH         23  = Telnet
25  = SMTP         53  = DNS         80  = HTTP
110 = POP3         135 = RPC         139 = NetBIOS
143 = IMAP         443 = HTTPS       445 = SMB
993 = IMAPS        995 = POP3S       3389 = RDP

# UDP Ports (memorize these)  
53  = DNS          67/68 = DHCP      69  = TFTP
123 = NTP          161 = SNMP        500 = IKE
```

#### 3. Protocol Behavior Understanding:
```bash
# TCP vs UDP characteristics
TCP: Reliable, connection-oriented, ordered delivery
UDP: Fast, connectionless, best-effort delivery

# ICMP message types
Type 0: Echo Reply (ping response)
Type 3: Destination Unreachable  
Type 8: Echo Request (ping)
Type 11: Time Exceeded (traceroute)
```

### eJPT Exam Scenarios & Solutions:

#### Scenario 1: Network Discovery Task
**Question**: "You need to identify all live hosts on the 192.168.100.0/24 network. What command would you use?"

**Solution**:
```bash
# Multiple correct approaches
nmap -sn 192.168.100.0/24          # Ping sweep
fping -g 192.168.100.0/24          # Fast ping
ping -b 192.168.100.255            # Broadcast ping (if enabled)
```

**Key Points**: 
- Know multiple methods for host discovery
- Understand when ping might be blocked
- Consider ARP-based discovery for local networks

#### Scenario 2: Service Identification Challenge  
**Question**: "A port scan reveals port 1433 is open. What service is likely running and what tool would you use to enumerate it?"

**Solution**:
```bash
# Service identification
Port 1433 = Microsoft SQL Server

# Enumeration tools
nmap --script ms-sql-* 192.168.1.100 -p 1433
sqsh -S 192.168.1.100 -U sa
mssqlclient.py user@192.168.1.100
```

**Key Points**:
- Memorize port-to-service mappings
- Know appropriate enumeration tools for each service
- Understand default credentials for common services

#### Scenario 3: Network Troubleshooting
**Question**: "You cannot reach a target host. Describe the troubleshooting steps you would take."

**Solution**:
```bash
# Systematic troubleshooting approach
# Step 1: Check local connectivity
ping 127.0.0.1                     # Loopback test
ping $(hostname -I)                 # Local IP test

# Step 2: Check gateway connectivity  
ping $(ip route | grep default | awk '{print $3}')

# Step 3: Check DNS resolution
nslookup target_hostname

# Step 4: Check specific service
telnet target_ip target_port        # Test specific port
nmap -p target_port target_ip       # Verify port status
```

### eJPT Lab Environment Navigation:

#### Common Lab Tasks:
1. **Network Mapping**: Identify all hosts and services
2. **Service Enumeration**: Detailed analysis of discovered services  
3. **Vulnerability Assessment**: Find security weaknesses
4. **Documentation**: Record findings systematically

#### Time Management Tips:
- **5 minutes**: Initial network discovery
- **15 minutes**: Port scanning and service enumeration
- **10 minutes**: Vulnerability scanning
- **20 minutes**: Manual verification and documentation

### Exam-Specific Command Shortcuts:

#### Quick Reference Commands:
```bash
# One-liner host discovery
nmap -sn target_range | grep "Nmap scan report" | awk '{print $5}'

# Fast service scan
nmap -sS -T4 -F target             # Top 100 ports quickly

# Quick vulnerability check  
nmap --script vuln --script-args=unsafe=1 target

# Service banner grabbing
nc target port                     # Manual banner grab
telnet target port                 # Alternative banner grab
```

---

## 📚 Advanced Topics & Integration {#advanced-topics}

### Integration with Penetration Testing Methodology:

#### PTES (Penetration Testing Execution Standard) Integration:
```bash
# Phase 1: Pre-engagement
- Define network scope and boundaries
- Identify critical network assets
- Establish testing rules of engagement

# Phase 2: Intelligence Gathering  
- Passive network reconnaissance
- DNS enumeration and zone transfers
- WHOIS and network range identification

# Phase 3: Threat Modeling
- Identify network attack vectors
- Map network trust relationships  
- Analyze network segmentation

# Phase 4: Vulnerability Analysis
- Network vulnerability scanning
- Service enumeration and fingerprinting
- Protocol analysis and weakness identification

# Phase 5: Exploitation
- Network-based exploits
- Protocol manipulation
- Network service compromises

# Phase 6: Post Exploitation
- Network lateral movement
- Traffic tunneling and pivoting
- Persistence through network services

# Phase 7: Reporting
- Network architecture documentation
- Vulnerability impact assessment
- Remediation recommendations
```

### Network Security Controls:

#### Defensive Measures Understanding:
```bash
# Firewalls
- Packet filtering rules
- Stateful inspection
- Application layer filtering

# Network Segmentation  
- VLANs and network isolation
- DMZ implementation
- Network access control (NAC)

# Monitoring Systems
- Network intrusion detection (NIDS)  
- Security information and event management (SIEM)
- Network traffic analysis (NTA)

# Access Controls
- Network authentication (802.1X)
- VPN security
- Network access policies
```

---

## 🔧 Tools Reference & Cheat Sheets {#tools-reference}

### Essential Networking Tools:

#### Network Discovery Tools:
```bash
# Nmap - Network Mapper
nmap [scan_type] [options] target

# Common options:
-sS    # SYN scan (default)
-sU    # UDP scan  
-sV    # Version detection
-sC    # Default scripts
-O     # OS detection
-A     # Aggressive scan (sV + sC + O)
-p-    # All ports
-T4    # Timing template (faster)
--top-ports 1000  # Scan top 1000 ports

# Examples:
nmap -sS -sV -sC -O target
nmap -sU --top-ports 100 target  
nmap -p- -T4 target
```

#### Network Analysis Tools:
```bash
# Wireshark/Tshark - Packet Analysis
tshark -i interface -c 100         # Capture 100 packets
tshark -r file.pcap -Y "http"      # Filter HTTP traffic
tshark -r file.pcap -z io,phs      # Protocol hierarchy

# TCPdump - Command Line Packet Capture  
tcpdump -i interface host target   # Specific host
tcpdump -i interface -w file.pcap  # Save to file
tcpdump -r file.pcap 'port 80'     # Read and filter
```

#### Service Enumeration Tools:
```bash
# Netcat - Swiss Army Knife
nc target port                     # Connect to service
nc -l -p port                      # Listen on port
nc -e /bin/bash target port        # Bind shell

# Telnet - Service Banner Grabbing
telnet target port                 # Manual service interaction

# SSH - Secure Remote Access
ssh user@target                    # Standard connection
ssh -L 8080:localhost:80 user@target  # Local port forwarding
```

### Protocol-Specific Tools:

#### DNS Tools:
```bash
# Dig - DNS Lookup Tool
dig domain                         # Basic lookup
dig @nameserver domain             # Specific nameserver  
dig domain axfr                    # Zone transfer attempt
dig -x ip_address                  # Reverse lookup

# NSLookup - Name Server Lookup
nslookup domain                    # Interactive mode
nslookup domain nameserver         # Specific server

# DNSrecon - DNS Reconnaissance
dnsrecon -d domain                 # Standard enumeration
dnsrecon -d domain -t axfr         # Zone transfer
```

#### Web Application Tools:
```bash
# Curl - Command Line HTTP Client
curl -I http://target              # HEAD request only
curl -X POST http://target         # POST request
curl -H "Header: Value" http://target  # Custom headers

# Wget - Web Retrieval Tool  
wget http://target/file            # Download file
wget -r http://target              # Recursive download
```

---

## 🚨 Common Pitfalls & Troubleshooting {#troubleshooting}

### Network Connectivity Issues:

#### Issue 1: Cannot Reach Target Hosts
**Symptoms**:
- Ping timeouts
- Connection refused errors
- No response from services

**Diagnostic Steps**:
```bash
# Check local network configuration
ip addr show                       # Verify IP configuration
ip route show                      # Check routing table
cat /etc/resolv.conf              # Verify DNS settings

# Test connectivity layers
ping 127.0.0.1                    # Loopback (Layer 3)
ping gateway_ip                    # Gateway connectivity  
ping external_ip                   # Internet connectivity
nslookup google.com               # DNS resolution
```

**Common Solutions**:
- Verify network interface is up: `ip link set eth0 up`
- Check firewall rules: `iptables -L`
- Verify routing: `ip route add default via gateway_ip`

#### Issue 2: Slow Network Performance
**Symptoms**:
- High latency
- Packet loss
- Timeouts

**Diagnostic Commands**:
```bash
# Network performance testing
ping -c 10 -i 0.1 target          # Fast ping test
mtr target                        # Continuous traceroute
iperf3 -c target                  # Bandwidth testing

# Interface statistics
ip -s link show interface         # Interface packet counters
ethtool interface                 # Interface details
```

### Scanning and Enumeration Issues:

#### Issue 3: Nmap Scans Return No Results
**Possible Causes**:
- Firewall blocking scans
- Host-based IPS detection  
- Rate limiting
- Network segmentation

**Solutions**:
```bash
# Try different scan techniques
nmap -sS target                   # SYN scan
nmap -sT target                   # Connect scan
nmap -sF target                   # FIN scan
nmap -sA target                   # ACK scan

# Adjust timing and detection evasion
nmap -T2 target                   # Slower timing
nmap -f target                    # Fragment packets
nmap --source-port 53 target     # Source port manipulation
```

#### Issue 4: Service Enumeration Failures
**Problem**: Services don't respond to enumeration attempts

**Debugging Approach**:
```bash
# Verify service is actually running
netstat -tlnp | grep port        # Check if service is listening
ss -tlnp | grep port             # Alternative check

# Test manual connection
telnet target port               # Basic connectivity test
nc target port                   # Netcat connection test

# Check for service banners
nmap -sV -p port target          # Version detection
```

---

## 📖 Additional Study Resources {#study-resources}

### Recommended Reading:
- **TCP/IP Illustrated Series** by W. Richard Stevens
- **Network Security Assessment** by Chris McNab  
- **Nmap Network Scanning** by Gordon Lyon
- **Wireshark Network Analysis** by Laura Chappell

### Online Resources:
- **IANA Port Numbers**: https://www.iana.org/assignments/service-names-port-numbers/
- **RFC Documents**: https://www.rfc-editor.org/
- **Subnet Calculator**: https://www.subnet-calculator.com/
- **Packet Life**: http://packetlife.net/

### Practice Platforms:
- **TryHackMe Network Services**: Hands-on network enumeration
- **HackTheBox Academy**: Network penetration testing modules
- **PentesterLab**: Network-focused exercises
- **VulnHub**: Vulnerable VMs for practice

### Lab Setup Recommendations:
```bash
# Virtual Lab Environment
1. Hypervisor: VMware Workstation/VirtualBox
2. Attacker VM: Kali Linux/Parrot Security  
3. Target VMs: Metasploitable, DVWA, Windows Server
4. Network Setup: Multiple network segments
5. Tools: Wireshark, Nmap, Netcat, TCPdump
```

---

## 🎓 Final eJPT Preparation Checklist {#final-checklist}

### Knowledge Verification:
- [ ] Can calculate subnets without a calculator
- [ ] Know all well-known ports and services  
- [ ] Understand TCP vs UDP differences
- [ ] Can interpret nmap scan results
- [ ] Know OSI and TCP/IP model layers
- [ ] Understand ARP, DNS, DHCP operation
- [ ] Can troubleshoot basic network connectivity

### Practical Skills:
- [ ] Can perform comprehensive network discovery
- [ ] Comfortable with command-line tools
- [ ] Can analyze network traffic basics
- [ ] Know how to enumerate common services
- [ ] Can document findings systematically
- [ ] Understand basic network security concepts

### Exam Day Strategy:
1. **Read questions carefully** - Look for keywords
2. **Manage time effectively** - Don't spend too long on one question
3. **Use elimination method** - Rule out incorrect answers  
4. **Double-check calculations** - Especially subnetting problems
5. **Stay calm and methodical** - Follow systematic approaches

### Key Formulas to Remember:
```bash
# Subnetting formulas
Number of hosts = 2^(host bits) - 2
Number of networks = 2^(network bits)  
Block size = 256 - (last octet of subnet mask)

# Binary conversions (powers of 2)
2^1=2, 2^2=4, 2^3=8, 2^4=16, 2^5=32, 2^6=64, 2^7=128, 2^8=256
```

---

## 🏆 Conclusion

This enhanced networking fundamentals guide provides comprehensive coverage of all networking concepts essential for eJPT success. The structured approach, practical examples, and detailed explanations ensure thorough understanding of both theoretical concepts and practical applications.

**Key Success Factors**:
- **Practice regularly** with hands-on labs
- **Memorize essential information** (ports, protocols, formulas)
- **Understand concepts deeply** rather than just memorizing
- **Apply knowledge practically** through real-world scenarios

**Remember**: Networking is the foundation of all penetration testing activities. Master these fundamentals, and you'll be well-prepared not only for the eJPT exam but for a successful career in cybersecurity.

---

*Good luck with your eJPT preparation! 🚀*
