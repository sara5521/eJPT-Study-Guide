# 🌐 Networking Fundamentals - eJPT Foundation Knowledge

Essential networking concepts and protocols for penetration testing and the eJPT certification exam.
**Location:** `01-theory-foundations/networking-fundamentals.md`

## 🎯 What is Networking for Penetration Testing?

Networking forms the backbone of all penetration testing activities. Understanding how networks function, communicate, and can be exploited is crucial for successful ethical hacking. This foundation covers the essential protocols, services, and concepts that every penetration tester must master.

Key areas include:
- Network models and architecture
- TCP/IP protocol suite
- Common ports and services
- Network addressing and routing
- Protocol analysis and exploitation

## 📚 Network Models and Architecture

### OSI Model (7 Layers)
Understanding the OSI model helps identify where attacks occur and how to troubleshoot network issues.

| Layer | Name | Function | Protocols/Examples | eJPT Relevance |
|-------|------|----------|-------------------|----------------|
| 7 | Application | User interface | HTTP, FTP, SSH, DNS | Web attacks, service enumeration |
| 6 | Presentation | Data formatting | SSL/TLS, encryption | Certificate attacks, encryption flaws |
| 5 | Session | Session management | NetBIOS, SQL sessions | Session hijacking, persistence |
| 4 | Transport | End-to-end delivery | TCP, UDP | Port scanning, service discovery |
| 3 | Network | Routing | IP, ICMP, IPSec | Network discovery, routing attacks |
| 2 | Data Link | Frame delivery | Ethernet, ARP | ARP spoofing, MAC attacks |
| 1 | Physical | Hardware transmission | Cables, switches | Physical access, network tapping |

### TCP/IP Model (4 Layers)
The practical model used in real networks:

1. **Application Layer** (HTTP, FTP, SSH, DNS)
2. **Transport Layer** (TCP, UDP) 
3. **Internet Layer** (IP, ICMP)
4. **Network Access Layer** (Ethernet, ARP)

## 🔌 Essential Protocols for Penetration Testing

### Internet Protocol (IP)
```bash
# IPv4 Address Structure
192.168.1.100/24
# Network: 192.168.1.0
# Host: 100  
# Subnet Mask: 255.255.255.0 (/24)

# IPv6 Address Structure  
2001:db8::1/64
# Network: 2001:db8::/64
# Host: ::1
```

### Transmission Control Protocol (TCP)
**Characteristics:**
- Connection-oriented
- Reliable delivery
- Error checking
- Flow control

**TCP Three-Way Handshake:**
1. Client → Server: SYN
2. Server → Client: SYN-ACK  
3. Client → Server: ACK

**TCP Flags Important for Scanning:**
| Flag | Purpose | Penetration Testing Use |
|------|---------|------------------------|
| SYN | Synchronize | Port scanning, connection establishment |
| ACK | Acknowledge | Firewall evasion, connection tracking |
| FIN | Finish | Stealth scanning, connection termination |
| RST | Reset | Port closed indication, connection reset |
| PSH | Push | Data transmission priority |
| URG | Urgent | Data priority signaling |

### User Datagram Protocol (UDP)
**Characteristics:**
- Connectionless
- Fast transmission
- No reliability guarantees
- Used for real-time applications

## 🚪 Common Ports and Services

### Critical TCP Ports for eJPT:
| Port | Service | Description | Attack Vectors |
|------|---------|-------------|----------------|
| 21 | FTP | File Transfer Protocol | Anonymous access, brute force, bounce attacks |
| 22 | SSH | Secure Shell | Brute force, key-based attacks, tunneling |
| 23 | Telnet | Unencrypted remote access | Credential sniffing, clear text passwords |
| 25 | SMTP | Simple Mail Transfer Protocol | Email enumeration, relay attacks |
| 53 | DNS | Domain Name System | Zone transfers, DNS poisoning, enumeration |
| 80 | HTTP | Hypertext Transfer Protocol | Web application attacks, directory traversal |
| 110 | POP3 | Post Office Protocol v3 | Email credential attacks |
| 135 | RPC | Remote Procedure Call | Windows enumeration, privilege escalation |
| 139 | NetBIOS | Network Basic Input/Output System | SMB enumeration, null sessions |
| 143 | IMAP | Internet Message Access Protocol | Email credential attacks |
| 443 | HTTPS | HTTP Secure | SSL/TLS attacks, certificate issues |
| 445 | SMB | Server Message Block | File share enumeration, EternalBlue |
| 993 | IMAPS | IMAP Secure | Secure email attacks |
| 995 | POP3S | POP3 Secure | Secure email attacks |

### Critical UDP Ports for eJPT:
| Port | Service | Description | Attack Vectors |
|------|---------|-------------|----------------|
| 53 | DNS | Domain Name System | DNS enumeration, amplification attacks |
| 67/68 | DHCP | Dynamic Host Configuration Protocol | DHCP spoofing, network discovery |
| 69 | TFTP | Trivial File Transfer Protocol | File enumeration, configuration extraction |
| 123 | NTP | Network Time Protocol | Time-based attacks, amplification |
| 161 | SNMP | Simple Network Management Protocol | Community string attacks, information disclosure |
| 500 | IKE | Internet Key Exchange | VPN enumeration, IPSec attacks |

## 🧪 Real Lab Examples

### Example 1: Network Discovery with Ping
```bash
# Test single host connectivity
ping -c 4 192.168.1.1
# Output: 4 packets transmitted, 4 received, 0% packet loss

# Ping sweep for network discovery
ping -c 1 192.168.1.1 && echo "Host is up"
# Output: Host is up

# Advanced ping with specific packet size
ping -c 3 -s 1000 192.168.1.1
# Output: Testing with larger packets to detect MTU issues
```

### Example 2: Protocol Analysis with Netstat
```bash
# View active connections
netstat -an | head -10
# Output: Shows active TCP and UDP connections with numerical addresses

# View listening services
netstat -tlnp
# Output: Shows listening TCP services with process information

# View routing table
netstat -rn  
# Output: Displays routing table with gateway information
```

### Example 3: ARP Table Investigation
```bash
# View ARP table
arp -a
# Output: Shows IP to MAC address mappings on local network

# ARP for specific host
arp 192.168.1.1
# Output: Shows MAC address for gateway

# Clear ARP cache (requires sudo)
sudo arp -d 192.168.1.100
# Output: Removes specific ARP entry
```

### Example 4: Network Interface Analysis
```bash
# View network interfaces
ip addr show
# Output: Shows all network interfaces with IP assignments

# View interface statistics
ip -s link show eth0
# Output: Shows packet statistics for specific interface

# View routing table with IP command
ip route show
# Output: Shows routing table with more detailed information than netstat
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **Network addressing and subnetting** (15% of networking questions)
- **Protocol identification and analysis** (20% of networking questions)  
- **Port and service knowledge** (25% of networking questions)
- **Network discovery techniques** (20% of networking questions)
- **Traffic analysis basics** (20% of networking questions)

### Critical Commands to Master:
```bash
# Network discovery commands
ping -c 1 target_ip                    # Test connectivity
arp -a                                 # View ARP table  
netstat -rn                           # View routing table
ip addr show                          # Show interfaces
ip route show                         # Show routes

# Service identification commands  
netstat -tlnp                         # Show listening TCP services
ss -tlnp                              # Modern alternative to netstat
lsof -i                               # Show network connections by process
```

### eJPT Exam Scenarios:
1. **Network Discovery Scenario:**
   - Required skills: Identify live hosts on network segment
   - Expected commands: ping sweeps, arp scans
   - Success criteria: Create accurate network map

2. **Service Enumeration Scenario:**
   - Required skills: Identify running services and versions
   - Expected commands: netstat, ss, service detection
   - Success criteria: Document all accessible services

3. **Protocol Analysis Scenario:**
   - Required skills: Understand traffic flow and communication
   - Expected commands: tcpdump basics, netstat analysis
   - Success criteria: Identify communication patterns

### Exam Tips and Tricks:
- **Tip 1:** Memorize well-known ports - they appear in multiple questions
- **Tip 2:** Understand the difference between TCP and UDP scanning results
- **Tip 3:** Practice subnetting calculations without a calculator
- **Tip 4:** Know how to identify services even when running on non-standard ports

### Common eJPT Questions:
- What service typically runs on port 445?
- How do you identify if a host is alive without port scanning?
- What's the difference between TCP and UDP protocols?
- How do you determine the network range from an IP address?

## 🔢 Subnetting and IP Addressing

### CIDR Notation and Subnet Masks
```bash
# Common subnet masks and their meanings
/24 = 255.255.255.0    # 254 hosts
/25 = 255.255.255.128  # 126 hosts  
/26 = 255.255.255.192  # 62 hosts
/27 = 255.255.255.224  # 30 hosts
/28 = 255.255.255.240  # 14 hosts
/29 = 255.255.255.248  # 6 hosts
/30 = 255.255.255.252  # 2 hosts (point-to-point links)
```

### Private IP Address Ranges
```bash
# Class A Private
10.0.0.0/8        # 10.0.0.0 - 10.255.255.255

# Class B Private  
172.16.0.0/12     # 172.16.0.0 - 172.31.255.255

# Class C Private
192.168.0.0/16    # 192.168.0.0 - 192.168.255.255

# Loopback
127.0.0.0/8       # 127.0.0.0 - 127.255.255.255

# Link-Local
169.254.0.0/16    # 169.254.0.0 - 169.254.255.255
```

### Quick Subnetting Practice
```bash
# Example: Network 192.168.1.0/26
# Subnet mask: 255.255.255.192
# Network address: 192.168.1.0
# First usable: 192.168.1.1  
# Last usable: 192.168.1.62
# Broadcast: 192.168.1.63
# Next subnet: 192.168.1.64
```

## ⚠️ Common Networking Issues & Troubleshooting

### Issue 1: No Network Connectivity
**Problem:** Cannot reach target hosts or services
**Troubleshooting Steps:**
```bash
# Step 1: Check local interface
ip addr show

# Step 2: Test local connectivity  
ping -c 1 127.0.0.1

# Step 3: Test gateway connectivity
ping -c 1 $(ip route | grep default | awk '{print $3}')

# Step 4: Test DNS resolution
nslookup google.com
```

### Issue 2: Slow Network Performance
**Problem:** Network connections are slow or timing out
**Diagnosis:**
```bash
# Check for packet loss
ping -c 10 target_ip

# Check network interface errors
ip -s link show eth0

# Monitor network traffic
iftop -i eth0
```

### Issue 3: DNS Resolution Problems
**Problem:** Cannot resolve domain names
**Solution:**
```bash
# Test DNS servers
nslookup google.com 8.8.8.8

# Check DNS configuration
cat /etc/resolv.conf

# Test with different DNS
dig @1.1.1.1 example.com
```

## 🔗 Integration with Penetration Testing Tools

### Network Discovery Chain
```bash
# Phase 1: Network range identification
netdiscover -r 192.168.1.0/24

# Phase 2: Host discovery  
nmap -sn 192.168.1.0/24

# Phase 3: Service discovery
nmap -sS -O 192.168.1.100

# Phase 4: Service enumeration
nmap -sC -sV -p 80,443 192.168.1.100
```

### Protocol Analysis Workflow
```bash
# Capture network traffic
tcpdump -i eth0 -w capture.pcap

# Analyze protocols in captured traffic
tcpdump -r capture.pcap -n | head -20

# Filter specific protocols
tcpdump -r capture.pcap 'tcp port 80'
```

## 📝 Documentation and Reporting

### Network Documentation Requirements
When documenting network findings for eJPT reports:

1. **Network Topology:** Document discovered networks and their relationships
2. **Host Inventory:** List all discovered hosts with IP addresses and MAC addresses  
3. **Service Matrix:** Create a table showing which services run on which hosts
4. **Protocol Usage:** Document what protocols are in use on the network

### Report Template Structure
```markdown
## Network Assessment Results

### Network Scope
- Target networks: 192.168.1.0/24, 10.0.0.0/24
- Assessment date: [Date]
- Tools used: ping, netstat, arp, nmap

### Network Discovery  
- Live hosts identified: X hosts
- Network services: Y services across Z ports
- Network protocols: TCP, UDP, ICMP analysis

### Key Findings
1. **Open Services:** List of accessible services
2. **Network Protocols:** Protocols in use and potential vulnerabilities  
3. **Network Architecture:** Topology and routing information

### Recommendations
1. Close unnecessary services
2. Implement network segmentation
3. Monitor network traffic for anomalies
```

### Evidence Collection
```bash
# Network scan results
nmap -oA network_scan 192.168.1.0/24

# Service enumeration results  
netstat -tlnp > listening_services.txt

# Network interface configuration
ip addr show > network_interfaces.txt

# Routing table
ip route show > routing_table.txt
```

## 📚 Additional Resources

### Essential Reading
- **RFC 791:** Internet Protocol specification
- **RFC 793:** Transmission Control Protocol specification
- **IANA Port Numbers:** Official port assignments
- **Subnet Calculator Tools:** Online subnetting practice

### Practice Labs
- **GNS3:** Network simulation for protocol practice
- **Packet Tracer:** Cisco network simulation
- **VirtualBox Labs:** Create virtual networks for testing
- **TryHackMe Network Services:** Hands-on network enumeration

### Advanced Topics for Further Study
- **VLAN Concepts:** Virtual LAN implementation and attacks
- **VPN Technologies:** IPSec, SSL VPN, and tunneling protocols  
- **Network Security:** Firewalls, IDS/IPS, and network monitoring
- **IPv6 Security:** Next-generation protocol considerations
