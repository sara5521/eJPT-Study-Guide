# 🔌 Ports and Protocols - Service Identification Guide

**Master port numbers and protocols for effective service enumeration and penetration testing**
**Location:** `01-theory-foundations/networking-basics/ports-and-protocols.md`

## 🎯 What are Ports and Protocols?

Ports are logical endpoints that allow multiple network services to run simultaneously on a single host. Combined with protocols (rules for communication), they form the foundation of network services. For penetration testers, understanding ports and protocols is essential for service identification, attack vector selection, and vulnerability assessment. Each port typically corresponds to a specific service, and knowing these associations helps in rapid service enumeration and exploitation planning.

Port knowledge enables pentesters to quickly identify running services, understand potential attack surfaces, and select appropriate tools and techniques for each discovered service.

## 📦 Port Categories and Ranges

### Port Range Classifications:
```bash
# Well-Known Ports (0-1023)
# - Reserved for system services
# - Require root/administrator privileges to bind
# - Standardized by IANA

# Registered Ports (1024-49151)  
# - Application-specific services
# - Registered with IANA but not reserved
# - Can be used by regular users

# Dynamic/Private Ports (49152-65535)
# - Ephemeral ports for client connections
# - Temporary port assignments
# - Used for outbound connections
```

### Protocol Types:
```bash
# TCP (Transmission Control Protocol)
# - Reliable, connection-oriented
# - Most web services, databases, remote access
# - Examples: HTTP(80), HTTPS(443), SSH(22)

# UDP (User Datagram Protocol)
# - Fast, connectionless
# - DNS, SNMP, streaming services
# - Examples: DNS(53), SNMP(161), DHCP(67/68)

# Both TCP and UDP
# - Some services use both protocols
# - Examples: DNS(53), NTP(123)
```

## 🔧 Well-Known Ports Reference

### Critical TCP Ports for Penetration Testing:
| Port | Service | Description | Security Implications |
|------|---------|-------------|----------------------|
| **21** | FTP | File Transfer Protocol | Anonymous access, clear-text credentials |
| **22** | SSH | Secure Shell | Brute force target, key-based auth |
| **23** | Telnet | Unencrypted remote access | Clear-text credentials, deprecated |
| **25** | SMTP | Simple Mail Transfer | Email relay abuse, user enumeration |
| **53** | DNS | Domain Name System | Zone transfers, DNS poisoning |
| **80** | HTTP | Web traffic | Web application vulnerabilities |
| **110** | POP3 | Email retrieval | Clear-text authentication |
| **135** | RPC | Windows RPC endpoint | Remote code execution vectors |
| **139** | NetBIOS | Windows file sharing | SMB enumeration, null sessions |
| **143** | IMAP | Email access | Authentication attacks |
| **443** | HTTPS | Secure web traffic | SSL/TLS vulnerabilities, web apps |
| **445** | SMB | Windows file sharing | EternalBlue, credential attacks |
| **993** | IMAPS | Secure IMAP | Encrypted email access |
| **995** | POP3S | Secure POP3 | Encrypted email retrieval |
| **1433** | MSSQL | Microsoft SQL Server | Database attacks, injection |
| **3306** | MySQL | MySQL Database | Database enumeration, injection |
| **3389** | RDP | Windows Remote Desktop | Brute force, BlueKeep vulnerability |
| **5432** | PostgreSQL | PostgreSQL Database | Database attacks, privilege escalation |

### Critical UDP Ports for Penetration Testing:
| Port | Service | Description | Security Implications |
|------|---------|-------------|----------------------|
| **53** | DNS | Domain Name System | DNS enumeration, cache poisoning |
| **67/68** | DHCP | Dynamic Host Configuration | Network information disclosure |
| **69** | TFTP | Trivial File Transfer | Unauthenticated file access |
| **123** | NTP | Network Time Protocol | Amplification attacks |
| **161** | SNMP | Network Management | Community string brute force |
| **162** | SNMP Trap | SNMP notifications | Information disclosure |
| **500** | IPSec | VPN protocol | VPN enumeration |
| **514** | Syslog | System logging | Log injection, information disclosure |
| **1194** | OpenVPN | VPN service | VPN attacks |
| **1701** | L2TP | VPN protocol | VPN enumeration |

### High-Value Target Ports:
| Port Range | Services | Priority | Reason |
|------------|----------|----------|---------|
| **20-25** | FTP, SSH, Telnet, SMTP | High | Remote access, clear-text protocols |
| **53** | DNS | High | Information gathering, zone transfers |
| **80, 443** | HTTP, HTTPS | Critical | Web applications, most common attack vector |
| **135, 139, 445** | Windows SMB/RPC | Critical | Windows vulnerabilities, lateral movement |
| **1433, 3306, 5432** | Databases | High | Data access, injection attacks |
| **3389** | RDP | High | Remote access, recent vulnerabilities |

## 🧪 Real Lab Examples

### Example 1: Comprehensive Port Scanning
```bash
# Quick TCP port scan of common ports
nmap -sS --top-ports 1000 192.168.1.100
# Output:
# 22/tcp  open  ssh
# 80/tcp  open  http
# 443/tcp open  https
# 3306/tcp open mysql

# Comprehensive TCP scan with service detection
nmap -sS -sV -p 1-65535 192.168.1.100
# Output:
# 21/tcp  open  ftp      vsftpd 3.0.3
# 22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu
# 80/tcp  open  http     Apache httpd 2.4.41
# 443/tcp open  https    Apache httpd 2.4.41 (SSL-only)
# 3306/tcp open mysql    MySQL 8.0.25-0ubuntu0.20.04.1

# UDP port scanning
nmap -sU --top-ports 100 192.168.1.100
# Output:
# 53/udp  open     domain
# 161/udp open     snmp
# 514/udp filtered syslog
```

### Example 2: Service-Specific Enumeration
```bash
# HTTP service enumeration (port 80)
curl -I http://192.168.1.100
# Output:
# HTTP/1.1 200 OK
# Server: Apache/2.4.41 (Ubuntu)
# X-Powered-By: PHP/7.4.3

# SSH banner grabbing (port 22)
nc 192.168.1.100 22
# Output: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5

# MySQL service enumeration (port 3306)
nmap -sV --script mysql-info -p 3306 192.168.1.100
# Output:
# 3306/tcp open  mysql   MySQL 8.0.25-0ubuntu0.20.04.1
# | mysql-info:
# |   Protocol: 10
# |   Version: 8.0.25-0ubuntu0.20.04.1
# |   Thread ID: 12
# |   Capabilities flags: 65535
```

### Example 3: Protocol-Specific Discovery
```bash
# SMB enumeration (ports 139, 445)
nmap -sS --script smb-protocols -p 139,445 192.168.1.100
# Output:
# 139/tcp open  netbios-ssn
# 445/tcp open  microsoft-ds
# | smb-protocols:
# |   dialects:
# |     2.02
# |     2.10
# |     3.00
# |     3.02

# SNMP enumeration (port 161 UDP)
nmap -sU --script snmp-sysdescr -p 161 192.168.1.100
# Output:
# 161/udp open  snmp
# | snmp-sysdescr: Linux hostname 5.4.0-74-generic
```

### Example 4: Port and Service Correlation
```bash
# Multiple service discovery
nmap -sS -sV -sC -p 21,22,80,443,3306 192.168.1.100
# Output Analysis:
# Port 21: FTP with anonymous access allowed
# Port 22: SSH with password authentication
# Port 80: Apache web server with PHP
# Port 443: Same Apache with SSL certificate
# Port 3306: MySQL with remote access enabled

# Service interaction testing
# FTP anonymous access test
echo "anonymous" | ftp 192.168.1.100
# HTTP directory enumeration
gobuster dir -u http://192.168.1.100 -w /usr/share/wordlists/dirb/common.txt
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT (30% of service enumeration):
- **Port identification** and service correlation (40%)
- **Protocol recognition** and appropriate tool selection (25%)
- **Service enumeration** techniques per protocol (25%)
- **Vulnerability association** with specific ports/services (10%)

### Critical Ports to Memorize for eJPT:
```bash
# Essential TCP ports (must know)
21  - FTP      (file transfer, anonymous access)
22  - SSH      (secure remote access)
23  - Telnet   (insecure remote access)
25  - SMTP     (email sending)
53  - DNS      (name resolution)
80  - HTTP     (web traffic)
110 - POP3     (email retrieval)
143 - IMAP     (email access)
443 - HTTPS    (secure web)
445 - SMB      (Windows file sharing)
993 - IMAPS    (secure IMAP)
995 - POP3S    (secure POP3)
3389- RDP      (Windows remote desktop)

# Essential UDP ports (must know)
53  - DNS      (name resolution)
69  - TFTP     (trivial file transfer)
161 - SNMP     (network management)
162 - SNMP-trap(SNMP notifications)
```

### eJPT Scanning Strategies:
```bash
# Phase 1: Quick discovery
nmap -sS --top-ports 1000 target_ip

# Phase 2: Service identification  
nmap -sS -sV discovered_ports target_ip

# Phase 3: Protocol-specific enumeration
nmap -sS -sC -p specific_ports target_ip

# Phase 4: UDP scanning
nmap -sU --top-ports 100 target_ip
```

### eJPT Exam Scenarios:
1. **Service Identification:** Rapid port scanning and service correlation
   - Required skills: Port-to-service mapping knowledge
   - Expected commands: Nmap with service detection
   - Success criteria: Accurate service identification

2. **Protocol Selection:** Choosing correct enumeration approach
   - Required skills: Protocol understanding and tool selection
   - Expected commands: Protocol-specific enumeration tools
   - Success criteria: Effective service enumeration

3. **Vulnerability Mapping:** Associating services with potential vulnerabilities
   - Required skills: Common vulnerability knowledge per service
   - Expected commands: Vulnerability scanning per service
   - Success criteria: Accurate vulnerability identification

### Exam Tips and Tricks:
- **Tip 1:** Memorize top 20 TCP and top 10 UDP ports with services
- **Tip 2:** Practice rapid port-to-service association under time pressure
- **Tip 3:** Know which ports commonly run together (80+443, 139+445)
- **Tip 4:** Understand when to use TCP vs UDP scanning

### Common eJPT Questions:
- Identify the service running on a specific port
- Select appropriate enumeration tools for discovered services
- Correlate open ports with potential attack vectors
- Explain the purpose of specific protocol combinations

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Port Scan Results Inconsistency
**Problem:** Different tools showing different open ports
**Cause:** Firewall filtering, scan timing, or detection evasion
**Solution:**
```bash
# Try different scan types
nmap -sS target_ip              # SYN scan
nmap -sT target_ip              # Connect scan
nmap -sF target_ip              # FIN scan
nmap -sA target_ip              # ACK scan (firewall detection)

# Adjust timing and detection evasion
nmap -sS -T2 target_ip          # Slower, stealthier
nmap -sS -f target_ip           # Fragment packets
```

### Issue 2: Service Version Detection Failure
**Problem:** Nmap shows "unknown" for service versions
**Cause:** Custom services, non-standard configurations, or version hiding
**Solution:**
```bash
# Enhanced service detection
nmap -sV --version-intensity 9 -p port target_ip
nmap -sV --version-all -p port target_ip

# Manual banner grabbing
nc target_ip port
telnet target_ip port

# HTTP specific techniques
curl -I http://target_ip:port
wget --server-response --spider http://target_ip:port
```

### Issue 3: UDP Scanning Challenges
**Problem:** UDP scans showing all ports as "open|filtered"
**Cause:** UDP is connectionless, making definitive state determination difficult
**Solution:**
```bash
# Use service-specific UDP probes
nmap -sU -sV --script discovery target_ip

# Target specific UDP services
nmap -sU -p 53,161,123,514 target_ip

# Combine with version detection
nmap -sU -sV --script default -p 161 target_ip
```

### Issue 4: False Positive Port Results
**Problem:** Ports appear open but no service responds
**Cause:** Honeypots, load balancers, or firewall configurations
**Solution:**
```bash
# Verify with service interaction
nc -nv target_ip port           # Manual connection test
telnet target_ip port          # Interactive verification

# Use multiple verification methods
nmap -sS -p port target_ip     # SYN scan
nmap -sT -p port target_ip     # Connect scan
```

## 🔗 Integration with Other Tools

### Primary Integration: Port Discovery → Service Enumeration → Vulnerability Assessment
```bash
# Step 1: Port discovery
nmap -sS --top-ports 1000 192.168.1.100

# Step 2: Service identification
nmap -sS -sV discovered_ports 192.168.1.100

# Step 3: Service-specific enumeration
# Web services (80, 443)
nikto -h http://192.168.1.100
gobuster dir -u http://192.168.1.100 -w wordlist

# SSH service (22)
ssh-audit 192.168.1.100

# SMB service (445)
enum4linux 192.168.1.100
smbclient -L //192.168.1.100

# Database services (3306, 1433, 5432)
nmap --script mysql-* -p 3306 192.168.1.100
```

### Secondary Integration: Protocol Analysis → Attack Vector Selection
```bash
# Analyze discovered services for attack vectors
# Clear-text protocols (FTP:21, Telnet:23, HTTP:80)
hydra -L users.txt -P passwords.txt ftp://192.168.1.100

# Encrypted protocols (SSH:22, HTTPS:443)
ssh2john id_rsa > hash.txt
john hash.txt

# Database protocols (MySQL:3306, MSSQL:1433)
sqlmap -u "http://192.168.1.100/page.php?id=1"
```

### Advanced Workflows:
```bash
# Comprehensive port and service analysis
# 1. Initial discovery
nmap -sS --top-ports 1000 -oA initial_scan target_ip

# 2. Service enumeration
nmap -sS -sV -sC -oA service_scan -p $(cat initial_scan.nmap | grep open | cut -d'/' -f1 | tr '\n' ',') target_ip

# 3. Protocol-specific deep enumeration
for port in $(cat service_scan.nmap | grep open | cut -d'/' -f1); do
    echo "Enumerating port $port"
    case $port in
        21) nmap --script ftp-* -p 21 target_ip ;;
        22) ssh-audit target_ip ;;
        80|443) nikto -h http://target_ip:$port ;;
        139|445) enum4linux target_ip ;;
        *) echo "Manual enumeration needed for port $port" ;;
    esac
done
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Port Scan Results:** Complete nmap outputs with timestamps
2. **Service Identification:** Version information and banners
3. **Protocol Analysis:** Service-specific enumeration results
4. **Vulnerability Correlation:** Map services to potential vulnerabilities

### Report Template Structure:
```markdown
## Port and Service Analysis

### Target Information
- Target: 192.168.1.100
- Scan Date: 2025-01-15 16:30
- Scanner: Nmap 7.94

### Port Scanning Results
```bash
nmap -sS --top-ports 1000 192.168.1.100
```

#### Open TCP Ports
| Port | State | Service | Version |
|------|-------|---------|---------|
| 21 | Open | FTP | vsftpd 3.0.3 |
| 22 | Open | SSH | OpenSSH 8.2p1 |
| 80 | Open | HTTP | Apache 2.4.41 |
| 443 | Open | HTTPS | Apache 2.4.41 |
| 3306 | Open | MySQL | MySQL 8.0.25 |

#### Open UDP Ports
| Port | State | Service | Version |
|------|-------|---------|---------|
| 53 | Open | DNS | ISC BIND 9.16.1 |
| 161 | Open | SNMP | Net-SNMP 5.8 |

### Service-Specific Findings

#### FTP Service (Port 21)
- **Version:** vsftpd 3.0.3
- **Anonymous Access:** Enabled
- **Security Issues:** Clear-text authentication, anonymous access

#### Web Services (Ports 80, 443)
- **Server:** Apache httpd 2.4.41
- **Technologies:** PHP 7.4.3
- **SSL Certificate:** Valid, expires 2025-12-31
- **Security Headers:** Missing security headers

#### Database Service (Port 3306)
- **Version:** MySQL 8.0.25
- **Remote Access:** Enabled
- **Authentication:** Password required
- **Security Issues:** Remote access without SSL

### Attack Surface Summary
- **High Priority:** Web services (80, 443), Database (3306)
- **Medium Priority:** SSH (22), FTP (21)
- **Information Gathering:** DNS (53), SNMP (161)

### Recommendations
1. Disable FTP anonymous access
2. Implement web application security headers
3. Restrict MySQL remote access
4. Enable SSH key-based authentication
5. Monitor SNMP community strings
```

## 📚 Comprehensive Port Reference

### Database Ports:
| Port | Service | Default Auth | Common Attacks |
|------|---------|--------------|----------------|
| **1433** | MSSQL | Windows/SQL auth | SQLi, privilege escalation |
| **1521** | Oracle | Username/password | TNS poisoning, SQLi |
| **3306** | MySQL | Username/password | SQLi, privilege escalation |
| **5432** | PostgreSQL | Username/password | SQLi, command execution |
| **6379** | Redis | None (default) | Unauthorized access, RCE |
| **27017** | MongoDB | None (default) | NoSQL injection, data theft |

### Web-Related Ports:
| Port | Service | Security Focus |
|------|---------|---------------|
| **80** | HTTP | Web app vulnerabilities, clear-text |
| **443** | HTTPS | SSL/TLS issues, web app vulnerabilities |
| **8080** | HTTP Proxy | Admin interfaces, proxy abuse |
| **8443** | HTTPS Alt | Same as 443, alternate port |
| **9000** | Various | Often admin interfaces |
| **9090** | Various | Management interfaces |

### Remote Access Ports:
| Port | Service | Attack Vectors |
|------|---------|---------------|
| **22** | SSH | Brute force, key attacks, tunneling |
| **23** | Telnet | Clear-text, easy exploitation |
| **3389** | RDP | Brute force, BlueKeep, tunneling |
| **5900** | VNC | Weak passwords, screen access |
| **5985/5986** | WinRM | PowerShell remoting, privilege escalation |

### Email Ports:
| Port | Protocol | Security Issues |
|------|----------|----------------|
| **25** | SMTP | Open relay, user enumeration |
| **110** | POP3 | Clear-text authentication |
| **143** | IMAP | Clear-text authentication |
| **465** | SMTPS | SSL/TLS certificate issues |
| **587** | SMTP Submission | Authentication bypass |
| **993** | IMAPS | SSL/TLS certificate issues |
| **995** | POP3S | SSL/TLS certificate issues |
