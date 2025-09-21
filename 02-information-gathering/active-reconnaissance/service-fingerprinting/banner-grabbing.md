# 🔧 Banner Grabbing - Service Fingerprinting and Information Disclosure

Banner grabbing is a reconnaissance technique used to identify services, versions, and configuration details of network services by capturing service banners and responses.
**Location:** `02-information-gathering/active-reconnaissance/service-fingerprinting/banner-grabbing.md`

## 🎯 What is Banner Grabbing?

Banner grabbing is the process of capturing and analyzing service banners - text strings that services send when a connection is established. These banners often contain valuable information such as service type, version numbers, operating system details, and sometimes configuration information that can be crucial for vulnerability assessment and exploitation planning.

Banner grabbing capabilities include:
- Service identification and version detection
- Operating system fingerprinting
- Configuration information disclosure
- Vulnerability research preparation
- Attack surface enumeration

## 📦 Installation and Setup

### Prerequisites:
- Basic networking knowledge
- Understanding of TCP/UDP protocols
- Familiarity with common network services

### Tools Installation:
```bash
# Most tools are pre-installed on Kali Linux
# Netcat verification
nc -h

# Telnet verification
telnet --help

# Nmap verification
nmap --version
# Expected output: Nmap version 7.x.x

# Additional tools installation if needed
apt update
apt install netcat-traditional telnet nmap curl wget
```

### Initial Configuration:
```bash
# No special configuration needed
# Verify network connectivity
ping -c 3 8.8.8.8

# Check available network interfaces
ip addr show
```

## 🔧 Basic Usage and Syntax

### Basic Workflow:
1. **Target Identification:** Determine target IP/hostname and ports
2. **Connection Establishment:** Connect to target service ports
3. **Banner Capture:** Retrieve service banners and responses
4. **Analysis:** Interpret collected information for vulnerabilities

### Command Structure:
```bash
# Basic netcat syntax
nc [options] target_ip port

# Basic telnet syntax
telnet target_ip port

# Basic nmap banner grabbing
nmap -sV target_ip
```

## ⚙️ Command Line Options

### Netcat Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-v` | Verbose output | `nc -v target_ip 80` |
| `-n` | Skip DNS resolution | `nc -nv target_ip 22` |
| `-z` | Zero-I/O mode (scanning) | `nc -znv target_ip 1-1000` |
| `-w` | Timeout setting | `nc -w 3 target_ip 21` |

### Nmap Service Detection:
| Option | Purpose | Example |
|--------|---------|---------|
| `-sV` | Version detection | `nmap -sV target_ip` |
| `-sC` | Default scripts | `nmap -sC target_ip` |
| `-A` | Aggressive scan | `nmap -A target_ip` |
| `--version-intensity` | Detection intensity | `nmap -sV --version-intensity 9 target_ip` |

### Curl/Wget Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-I` | Head request only | `curl -I http://target_ip` |
| `-v` | Verbose output | `curl -v http://target_ip` |
| `--connect-timeout` | Connection timeout | `curl --connect-timeout 5 target_ip` |
| `-A` | User agent string | `curl -A "Custom-Agent" target_ip` |

## 🧪 Real Lab Examples

### Example 1: HTTP Banner Grabbing
```bash
# Using netcat to grab HTTP banner
nc -nv 192.168.1.100 80
# Send HTTP request
GET / HTTP/1.1
Host: 192.168.1.100

# Expected output:
HTTP/1.1 200 OK
Date: Mon, 15 Jan 2024 10:30:00 GMT
Server: Apache/2.4.41 (Ubuntu)
Last-Modified: Wed, 10 Jan 2024 15:20:30 GMT
Content-Type: text/html

# Using curl for HTTP banner
curl -I http://192.168.1.100
# Output: Server version and configuration details
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/7.4.3
```

### Example 2: SSH Banner Grabbing
```bash
# Using netcat for SSH banner
nc -nv 192.168.1.100 22
# Expected output:
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5

# Using nmap for detailed SSH information
nmap -sV -p 22 192.168.1.100
# Output:
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)

# Banner grab with timeout
timeout 5 nc -nv 192.168.1.100 22
# Output: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
```

### Example 3: FTP Banner Grabbing
```bash
# Using telnet for FTP banner
telnet 192.168.1.100 21
# Expected output:
220 (vsFTPd 3.0.3)

# Using netcat for FTP banner
nc -nv 192.168.1.100 21
# Output:
220 ProFTPD 1.3.5e Server (Debian)

# Multiple service banner grab with nmap
nmap -sV -p 21,22,80,443 192.168.1.100
# Output: Complete service enumeration with versions
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **HTTP/HTTPS banner analysis** - 25% importance
- **SSH service identification** - 20% importance  
- **FTP service enumeration** - 20% importance
- **Multi-service banner grabbing** - 15% importance
- **Banner interpretation for vulnerabilities** - 20% importance

### Critical Commands to Master:
```bash
# Essential banner grabbing commands for exam
nc -nv target_ip port          # Basic netcat banner grab
nmap -sV target_ip            # Service version detection
curl -I http://target_ip      # HTTP header analysis
telnet target_ip port         # Interactive banner grab
```

### eJPT Exam Scenarios:
1. **Web Server Identification:** Identify web server type and version for vulnerability research
   - Required skills: HTTP banner analysis, version identification
   - Expected commands: `curl -I`, `nc -nv target 80`
   - Success criteria: Accurate server identification and version

2. **SSH Service Analysis:** Determine SSH version for exploit selection
   - Required skills: SSH banner interpretation, version comparison
   - Expected commands: `nc -nv target 22`, `nmap -sV -p 22`
   - Success criteria: SSH version identification and security assessment

### Exam Tips and Tricks:
- **Tip 1:** Always use `-n` flag with netcat to avoid DNS delays
- **Tip 2:** Set timeouts to prevent hanging connections in exam environment
- **Tip 3:** Document all banner information for vulnerability correlation
- **Tip 4:** Use multiple techniques to verify service information

### Common eJPT Questions:
- Service version identification from banner output
- Vulnerability correlation based on service versions
- Operating system identification from service banners

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Connection Timeout or Refused
**Problem:** Target service not responding or connection being refused
**Cause:** Service not running, firewall blocking, or incorrect port
**Solution:**
```bash
# Verify port is open first
nmap -p port_number target_ip

# Use shorter timeout
nc -w 3 -nv target_ip port

# Try alternative connection method
telnet target_ip port
```

### Issue 2: No Banner Displayed
**Problem:** Connection established but no banner received
**Solution:**
```bash
# Send appropriate protocol request
# For HTTP:
echo -e "GET / HTTP/1.1\r\nHost: target\r\n\r\n" | nc target_ip 80

# For FTP:
echo "USER anonymous" | nc target_ip 21
```

### Issue 3: Incomplete Banner Information
**Problem:** Banner provides limited information
**Solution:**
```bash
# Use nmap scripts for detailed enumeration
nmap --script banner target_ip

# Try different HTTP methods
curl -X OPTIONS -v http://target_ip
```

### Issue 4: SSL/TLS Services
**Problem:** Cannot grab banners from encrypted services
**Solution:**
```bash
# Use OpenSSL for SSL services
openssl s_client -connect target_ip:443

# Use nmap SSL scripts
nmap --script ssl-enum-ciphers target_ip
```

## 🔗 Integration with Other Tools

### Primary Integration: Nmap → Banner Grabbing → Vulnerability Research
```bash
# Complete workflow showing tool integration
nmap -sn 192.168.1.0/24 > live_hosts.txt
nmap -sV -iL live_hosts.txt > service_versions.txt
nc -nv target_ip 80 > http_banner.txt

# Explanation of each step
# Step 1: Nmap discovers live hosts
# Step 2: Service version detection on live hosts
# Step 3: Manual banner grabbing for additional details
```

### Secondary Integration: Banner Grabbing → Searchsploit
```bash
# How banner information feeds into exploit research
nc -nv 192.168.1.100 80 | grep Server
# Output: Server: Apache/2.4.41

searchsploit apache 2.4.41
# Search for specific vulnerabilities based on banner
```

### Advanced Workflows:
```bash
# Automated banner grabbing script
for port in 21 22 23 25 53 80 110 443 993 995; do
    echo "Checking port $port"
    timeout 3 nc -nv target_ip $port
done
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** Terminal outputs showing banner responses
2. **Command Outputs:** Save all banner grabbing results to files
3. **Service Inventory:** Maintain comprehensive service version list
4. **Vulnerability Mapping:** Correlate versions with known vulnerabilities

### Report Template Structure:
```markdown
## Banner Grabbing Results

### Target Information
- Target: 192.168.1.100
- Date/Time: 2024-01-15 10:30:00
- Scope: Ports 21,22,80,443

### Commands Executed
```bash
# Service enumeration commands with timestamps
nmap -sV 192.168.1.100 > nmap_versions.txt
nc -nv 192.168.1.100 80 > http_banner.txt
nc -nv 192.168.1.100 22 > ssh_banner.txt
```

### Key Findings
- HTTP Server: Apache/2.4.41 (Ubuntu) - Potential vulnerabilities identified
- SSH Service: OpenSSH 8.2p1 - Version up to date
- FTP Service: ProFTPD 1.3.5e - Known vulnerabilities present

### Vulnerability Correlation
- Apache 2.4.41: CVE-2021-44790 (Medium severity)
- ProFTPD 1.3.5e: CVE-2019-12815 (High severity)

### Recommendations
- Update Apache to latest version
- Patch ProFTPD or implement access controls
- Regular service version monitoring
```

### Automation Scripts:
```bash
#!/bin/bash
# Banner grabbing automation script
target=$1
ports="21 22 23 25 53 80 110 443 993 995"

for port in $ports; do
    echo "=== Port $port ===" >> banners_$target.txt
    timeout 5 nc -nv $target $port >> banners_$target.txt 2>&1
    echo "" >> banners_$target.txt
done
```

## 📚 Additional Resources

### Official Documentation:
- Netcat documentation: https://nc110.sourceforge.io/
- Nmap documentation: https://nmap.org/book/
- RFC specifications for common protocols

### Learning Resources:
- OWASP Testing Guide: Banner grabbing techniques
- SANS penetration testing: Service enumeration
- Cybrary courses: Network reconnaissance

### Community Resources:
- r/netsec: Banner grabbing discussions
- Stack Overflow: Troubleshooting connection issues
- GitHub: Banner grabbing automation scripts

### Related Tools:
- Masscan: High-speed banner grabbing for large networks
- Zmap: Internet-wide banner grabbing capabilities
- Banner-plus: Enhanced banner grabbing with additional features
