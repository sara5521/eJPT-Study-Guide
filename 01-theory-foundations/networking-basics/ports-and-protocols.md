# 🔌 Ports and Protocols - Network Service Fundamentals

Understanding network ports and protocols is fundamental to penetration testing and network security assessment.
**Location:** `01-theory-foundations/networking-basics/ports-and-protocols.md`

## 🎯 What are Ports and Protocols?

**Ports** are communication endpoints that allow different services to run simultaneously on a single system. **Protocols** define the rules and formats for communication between network devices.

In penetration testing, port and protocol knowledge is essential for:
- **Service identification** during reconnaissance
- **Attack surface mapping** and vulnerability assessment
- **Protocol-specific exploitation** and payload delivery
- **Network traffic analysis** and detection evasion

## 📦 Port Categories and Ranges

### Port Ranges Classification:
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

### Port States in Scanning:
| State | Description | Security Implication |
|-------|-------------|---------------------|
| **Open** | Service actively listening | Potential attack vector |
| **Closed** | Port accessible but no service | System is reachable |
| **Filtered** | Blocked by firewall/filter | Security controls present |
| **Unfiltered** | Accessible but state unknown | Requires further testing |
| **Open\|Filtered** | Nmap cannot determine state | Possible stealth filtering |

## 🔧 Essential Protocols and Their Characteristics

### Core Internet Protocols:

#### TCP (Transmission Control Protocol)
```bash
# TCP Characteristics
Connection: Connection-oriented (3-way handshake)
Reliability: Guaranteed delivery with error correction
Flow Control: Built-in congestion and flow control
Overhead: Higher due to connection management
Use Cases: HTTP, HTTPS, SSH, FTP, SMTP, POP3

# TCP Connection Process
1. SYN: Client requests connection
2. SYN-ACK: Server acknowledges and requests
3. ACK: Client confirms connection established
```

#### UDP (User Datagram Protocol)  
```bash
# UDP Characteristics
Connection: Connectionless (fire-and-forget)
Reliability: No delivery guarantee
Flow Control: None - application handles it
Overhead: Lower, faster transmission
Use Cases: DNS, DHCP, SNMP, TFTP, Video streaming

# UDP Communication Process
1. Client sends data directly
2. No connection establishment required
3. No delivery confirmation
```

#### ICMP (Internet Control Message Protocol)
```bash
# ICMP Characteristics
Purpose: Network error reporting and diagnostics
Common Messages: Echo Request/Reply (ping), TTL Exceeded
Security Note: Often blocked by firewalls
Pentesting Use: Host discovery, path tracing
```

## ⚙️ Critical Ports for Penetration Testing

### Web Services Ports:
| Port | Service | Protocol | Security Focus |
|------|---------|----------|----------------|
| **80** | HTTP | TCP | Unencrypted web traffic |
| **443** | HTTPS | TCP | Encrypted web traffic |
| **8080** | HTTP Proxy | TCP | Alternative HTTP port |
| **8443** | HTTPS Alternative | TCP | Alternative HTTPS port |

### File Transfer Ports:
| Port | Service | Protocol | Attack Vectors |
|------|---------|----------|----------------|
| **21** | FTP | TCP | Anonymous login, clear-text |
| **22** | SSH/SFTP | TCP | Brute force, weak keys |
| **69** | TFTP | UDP | No authentication |
| **989/990** | FTPS | TCP | Encrypted FTP variants |

### Email Services Ports:
| Port | Service | Protocol | Vulnerabilities |
|------|---------|----------|----------------|
| **25** | SMTP | TCP | Email relay, spam |
| **110** | POP3 | TCP | Clear-text authentication |
| **143** | IMAP | TCP | Email access protocols |
| **993/995** | IMAPS/POP3S | TCP | Encrypted email variants |

### Database Ports:
| Port | Service | Protocol | Common Attacks |
|------|---------|----------|----------------|
| **3306** | MySQL | TCP | Default credentials, injection |
| **1433** | MSSQL | TCP | SA account, stored procedures |
| **5432** | PostgreSQL | TCP | Privilege escalation |
| **1521** | Oracle | TCP | TNS listener attacks |

### Network Services Ports:
| Port | Service | Protocol | Exploitation Notes |
|------|---------|----------|-------------------|
| **53** | DNS | TCP/UDP | Zone transfers, cache poisoning |
| **135** | RPC Endpoint | TCP | Windows RPC services |
| **139** | NetBIOS | TCP | SMB over NetBIOS |
| **445** | SMB | TCP | File sharing, lateral movement |

### Remote Access Ports:
| Port | Service | Protocol | Security Risks |
|------|---------|----------|----------------|
| **3389** | RDP | TCP | Windows Remote Desktop |
| **5900** | VNC | TCP | Virtual Network Computing |
| **23** | Telnet | TCP | Clear-text remote access |
| **512-514** | R-services | TCP | Rlogin, rexec, rsh |

## 🧪 Real Lab Examples

### Example 1: Port Scanning and Service Identification
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

### Example 2: Protocol-Specific Enumeration
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

### Example 3: UDP Service Discovery
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

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT (85% exam coverage):
- **Port scanning interpretation** - 25% of practical tasks
- **Service enumeration methodology** - 20% of assessment time  
- **Protocol-specific attack vectors** - 20% of exploitation scenarios
- **Common service vulnerabilities** - 20% of vulnerability identification

### Critical Commands to Master:
```bash
# Essential port scanning commands
nmap -sS target_ip                    # TCP SYN scan
nmap -sU target_ip                    # UDP scan  
nmap -sV target_ip                    # Service version detection
nmap -p- target_ip                    # Full port range scan
nmap --top-ports 1000 target_ip       # Most common 1000 ports

# Service-specific enumeration
curl -I http://target_ip              # HTTP header analysis
telnet target_ip port_number          # Manual service interaction
nc -nv target_ip port_number          # Netcat connection testing
```

### eJPT Exam Scenarios:
1. **Service Discovery Scenario:**
   - Identify all running services on target networks
   - Determine service versions and potential vulnerabilities
   - Map attack surface based on open ports

2. **Protocol Analysis Scenario:**
   - Analyze network traffic for clear-text protocols
   - Identify misconfigured services with default credentials
   - Exploit protocol-specific vulnerabilities

### Exam Tips and Tricks:
- **Tip 1:** Always scan both TCP and UDP - UDP services are often overlooked
- **Tip 2:** Use service version detection (-sV) to identify specific vulnerabilities
- **Tip 3:** Know default ports by memory for faster target assessment
- **Tip 4:** Understand when to use stealth vs. aggressive scanning techniques

### Common eJPT Questions:
- Which ports are typically used for web services and their security implications?
- How do TCP and UDP protocols differ in terms of pentesting approach?
- What information can be gathered from service banners and version detection?

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Ports Showing as Filtered
**Problem:** Nmap shows ports as filtered instead of open/closed
**Cause:** Firewall or IPS blocking scan attempts
**Solution:**
```bash
# Use different scan techniques
nmap -sS target_ip          # SYN scan (stealthier)
nmap -sF target_ip          # FIN scan (firewall bypass)
nmap -sA target_ip          # ACK scan (firewall detection)
nmap -f target_ip           # Fragment packets
```

### Issue 2: UDP Scans Taking Too Long
**Problem:** UDP scans are extremely slow and often incomplete
**Solution:**
```bash
# Focus on common UDP ports
nmap -sU --top-ports 100 target_ip

# Increase scan speed (less accurate)
nmap -sU -T4 --max-retries 1 target_ip

# Use specific UDP service detection
nmap -sU -sV -p 53,69,123,161 target_ip
```

### Issue 3: Service Version Not Detected
**Problem:** Nmap shows service as "unknown" or generic
**Solution:**
```bash
# Manual banner grabbing
telnet target_ip port_number
nc -nv target_ip port_number

# Aggressive service detection
nmap -sV --version-intensity 9 target_ip

# Use NSE scripts for specific services
nmap --script service-detection target_ip
```

## 🔗 Integration with Other Tools

### Primary Integration: Nmap → Service Enumeration Tools
```bash
# Workflow: Discover → Enumerate → Exploit
nmap -sV target_ip > nmap_results.txt

# Based on results, choose specific tools:
# If HTTP found (port 80/443):
nikto -h http://target_ip
gobuster dir -u http://target_ip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# If SSH found (port 22):
hydra -l admin -P /usr/share/wordlists/rockyou.txt target_ip ssh

# If SMB found (port 445):
enum4linux target_ip
smbclient -L //target_ip
```

### Secondary Integration: Protocol Analysis → Traffic Capture
```bash
# Capture specific protocol traffic
tcpdump -i eth0 port 80 -w http_traffic.pcap
tcpdump -i eth0 port 21 -w ftp_traffic.pcap

# Analyze with Wireshark
wireshark http_traffic.pcap
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Port Scan Results:** Complete nmap output with timestamps
2. **Service Versions:** Version detection results for vulnerability mapping
3. **Banner Information:** Service banners and response headers
4. **Protocol Analysis:** Traffic captures for clear-text protocols

### Report Template Structure:
```markdown
## Port and Service Analysis

### Target Information
- Target: 192.168.1.100
- Scan Date: 2025-09-23 14:30:00
- Scanner: Nmap 7.94

### Open Ports Summary
| Port | Protocol | Service | Version | Risk Level |
|------|----------|---------|---------|------------|
| 21   | TCP      | FTP     | vsftpd 3.0.3 | Medium |
| 80   | TCP      | HTTP    | Apache 2.4.6 | Low |
| 3306 | TCP      | MySQL   | 5.7.26 | High |

### Service-Specific Findings
#### FTP Service (Port 21)
- Anonymous login: Enabled
- Directory listing: Available
- Security concern: Clear-text authentication

#### HTTP Service (Port 80)  
- Server: Apache 2.4.6
- Technologies: PHP 7.2
- Security headers: Missing HSTS, CSP

### Recommendations
1. Disable anonymous FTP access
2. Implement HTTPS for web services
3. Update MySQL to latest stable version
4. Configure proper firewall rules
```

## 📚 Additional Resources

### Protocol Documentation:
- **RFC 793:** TCP Protocol Specification
- **RFC 768:** UDP Protocol Specification  
- **RFC 792:** ICMP Protocol Specification

### Port Reference Resources:
- **IANA Port Registry:** Official port assignments
- **Common Ports Cheat Sheet:** Quick reference for pentesters
- **Service Banner Database:** Known service fingerprints

### Practical Labs:
- **VulnHub:** Vulnerable machines for port scanning practice
- **HackTheBox:** Real-world port enumeration scenarios
- **PortSwigger Web Academy:** Protocol-specific attack techniques
