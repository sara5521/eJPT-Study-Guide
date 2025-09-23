# 🔍 Information Gathering Basics - Complete eJPT Guide

**Master the fundamentals of reconnaissance and information gathering for penetration testing and eJPT exam success**
**Location:** `01-theory-foundations/information-gathering-basics.md`

## 🎯 What is Information Gathering?

Information gathering is the systematic collection of data about a target organization, network, or application before conducting penetration testing activities. It serves as the reconnaissance phase that provides the foundation for all subsequent testing phases and is crucial for eJPT success, comprising approximately 25% of the exam content.

Information gathering involves both passive techniques (collecting publicly available information without direct target interaction) and active techniques (directly probing target systems while maintaining stealth). The goal is to map the attack surface, identify potential entry points, and understand the target environment's structure and technologies.

**Why Information Gathering Matters:**
- Reduces testing time by focusing efforts on viable targets
- Identifies potential attack vectors and entry points
- Helps avoid detection by understanding security measures
- Provides context for vulnerability assessment and exploitation
- Forms the basis for comprehensive penetration testing methodology

## 📦 Core Components Overview

### 1. Reconnaissance Types (35% of methodology)
- **Passive Reconnaissance:** Gathering information without target interaction
- **Active Reconnaissance:** Direct target system interaction and probing
- **Semi-Active Reconnaissance:** Indirect target interaction through third parties

### 2. Information Sources (30% of methodology)  
- **Public Sources:** Search engines, social media, public databases
- **DNS Infrastructure:** Domain registration, DNS records, subdomains
- **Network Infrastructure:** IP ranges, network topology, routing information
- **Technical Sources:** Code repositories, configuration files, error messages

### 3. Target Profiling (25% of methodology)
- **Organizational Intelligence:** Company structure, employees, business relationships
- **Technical Infrastructure:** Servers, applications, technologies, versions
- **Network Architecture:** Subnets, VLANs, security controls, entry points
- **Digital Footprint:** Online presence, exposed services, leaked information

### 4. Documentation and Analysis (10% of methodology)
- **Data Organization:** Systematic recording of discovered information
- **Threat Modeling:** Identifying potential attack paths and scenarios
- **Risk Assessment:** Prioritizing targets based on value and accessibility

## 🔧 Passive Information Gathering

### OSINT (Open Source Intelligence) Fundamentals:
```bash
# Search engine reconnaissance - Google dorking basics
site:target.com                     # All indexed pages
site:target.com filetype:pdf        # Specific file types
site:target.com inurl:admin         # URL patterns
site:target.com intitle:"login"     # Page titles
site:target.com "confidential"      # Sensitive keywords

# Advanced Google dork examples for eJPT
site:target.com ext:sql             # Database dumps
site:target.com inurl:wp-content    # WordPress installations  
site:target.com "Index of"          # Directory listings
site:target.com intext:"password"   # Password references
```

### WHOIS and Domain Intelligence:
```bash
# Basic WHOIS queries
whois target.com                    # Domain registration details
whois 192.168.1.100                # IP address ownership

# Expected WHOIS information:
# - Domain registrant details
# - Administrative and technical contacts
# - Registration and expiration dates
# - Name servers and DNS information
# - Registrar information and status

# WHOIS analysis for eJPT:
# 1. Identify organization structure
# 2. Find email address formats
# 3. Discover additional domains
# 4. Map DNS infrastructure
# 5. Identify geographic locations
```

### Social Media Intelligence (SOCMINT):
```bash
# LinkedIn reconnaissance targets:
# - Employee names and job titles
# - Organizational hierarchy
# - Technology preferences mentioned
# - Company connections and partners
# - Email address format patterns

# Information gathering checklist:
# 1. Key personnel identification
# 2. Technology stack mentions
# 3. Business relationships
# 4. Geographic locations
# 5. Contact information patterns

# Example employee information extraction:
# Name: John Smith
# Title: Senior Network Administrator  
# Email likely: jsmith@target.com or john.smith@target.com
# Technologies mentioned: Cisco, VMware, Windows Server
```

### Public Database Mining:
```bash
# Certificate Transparency logs
# - SSL certificate information
# - Subdomain discovery
# - Certificate authority data
# - Historical certificate data

# Shodan.io intelligence gathering
# - Internet-connected device discovery
# - Service version identification
# - Geographic device distribution
# - Security vulnerability exposure

# Archive.org (Wayback Machine)
# - Historical website versions
# - Deleted content discovery
# - Technology evolution tracking
# - Configuration file exposure
```

### Automated OSINT Tools:
```bash
# theHarvester - Email and subdomain harvesting
theharvester -d target.com -l 100 -b google
theharvester -d target.com -b bing,yahoo,linkedin
# Output: email addresses, subdomains, hosts

# Recon-ng - Comprehensive OSINT framework
recon-ng
[recon-ng][default] > workspaces create target_company
[recon-ng][target_company] > modules load recon/domains-hosts/google_site_web
[recon-ng][target_company] > run

# Maltego - Visual intelligence platform
# - Relationship mapping
# - Data correlation
# - Social network analysis
# - Infrastructure mapping
```

## ⚙️ Active Information Gathering

### Network Discovery Techniques:
```bash
# Live host identification methods
ping target_ip                     # Basic connectivity test
ping -c 4 target_ip                # Limited ping count

# Nmap host discovery scans
nmap -sn 192.168.1.0/24           # Ping sweep (no port scan)
nmap -PS22,80,443 192.168.1.0/24  # TCP SYN ping specific ports
nmap -PA22,80,443 192.168.1.0/24  # TCP ACK ping specific ports  
nmap -PU53,161,123 192.168.1.0/24 # UDP ping specific ports

# Alternative discovery tools
fping -a -g 192.168.1.0/24        # Fast ping sweep
netdiscover -r 192.168.1.0/24     # ARP-based discovery
arp-scan -l                       # Local network ARP scan

# Expected discovery results:
# 192.168.1.1 - Gateway/Router
# 192.168.1.100 - Target server
# 192.168.1.150 - Additional host
```

### Port Scanning Essentials:
```bash
# Basic TCP scanning approaches
nmap -sS target_ip                # SYN scan (stealth)
nmap -sT target_ip                # Connect scan (full connection)
nmap -sS --top-ports 1000 target_ip # Quick discovery scan

# Port range specifications
nmap -p 1-100 target_ip           # Specific range
nmap -p 22,80,443,3389 target_ip  # Specific ports
nmap -p- target_ip                # All 65535 ports (slow)

# UDP scanning basics
nmap -sU target_ip                # Basic UDP scan
nmap -sU --top-ports 100 target_ip # Top UDP ports
nmap -sU -p 53,161,123,514 target_ip # Common UDP services

# Timing and performance
nmap -T4 target_ip                # Faster scan timing
nmap -T2 target_ip                # Slower, stealthier timing
```

### Service Version Detection:
```bash
# Service fingerprinting techniques
nmap -sV target_ip                # Version detection
nmap -sV --version-intensity 5 target_ip # Aggressive version detection
nmap -sV -p discovered_ports target_ip    # Specific ports only

# Default script scanning
nmap -sC target_ip                # Default NSE scripts
nmap -sS -sV -sC target_ip        # Combined scan approach

# Example service detection output:
# 22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
# 80/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))
# 443/tcp open  https   Apache httpd 2.4.41 ((Ubuntu))
# 3306/tcp open mysql   MySQL 8.0.25-0ubuntu0.20.04.1
```

### DNS Enumeration Basics:
```bash
# Standard DNS queries
nslookup target.com               # Basic DNS lookup
dig target.com                    # Detailed DNS information
dig target.com A                  # A record (IPv4 address)
dig target.com AAAA               # AAAA record (IPv6 address)
dig target.com MX                 # Mail exchange records
dig target.com NS                 # Name server records
dig target.com TXT                # Text records

# DNS zone transfer attempts
dig @ns1.target.com target.com AXFR
nslookup
> set type=any
> ls -d target.com

# Subdomain enumeration basics
dnsrecon -d target.com -t std     # Standard DNS enumeration
sublist3r -d target.com           # Subdomain enumeration tool
```

## 🧪 Real Lab Examples

### Example 1: Complete Network Discovery Workflow
```bash
# Step 1: Determine network scope
ip route show
# Output: default via 192.168.1.1 dev eth0
#         192.168.1.0/24 dev eth0 scope link

ifconfig                          # Alternative: ip addr show
# Output: eth0: 192.168.1.50/24

# Step 2: Live host discovery
nmap -sn 192.168.1.0/24
# Output:
# Starting Nmap 7.91 ( https://nmap.org )
# Nmap scan report for 192.168.1.1
# Host is up (0.001s latency).
# Nmap scan report for 192.168.1.100  
# Host is up (0.002s latency).
# Nmap scan report for 192.168.1.150
# Host is up (0.003s latency).
# Nmap done: 256 IP addresses (3 hosts up) scanned in 2.5 seconds

# Step 3: Verify with ARP scan
arp-scan -l
# Output:
# 192.168.1.1    00:50:56:12:34:56    VMware, Inc.
# 192.168.1.100  00:0c:29:ab:cd:ef    VMware, Inc.
# 192.168.1.150  00:0c:29:12:34:56    VMware, Inc.

# Step 4: Document live hosts
echo "192.168.1.1" > live_hosts.txt
echo "192.168.1.100" >> live_hosts.txt  
echo "192.168.1.150" >> live_hosts.txt
```

### Example 2: Service Discovery and Enumeration
```bash
# Step 1: Quick port scan on discovered hosts
nmap -sS --top-ports 1000 192.168.1.100
# Output:
# Starting Nmap 7.91 ( https://nmap.org )
# Nmap scan report for 192.168.1.100
# Host is up (0.001s latency).
# Not shown: 996 closed ports
# PORT     STATE SERVICE
# 22/tcp   open  ssh
# 80/tcp   open  http
# 443/tcp  open  https
# 3306/tcp open  mysql

# Step 2: Detailed service version detection
nmap -sV -sC -p 22,80,443,3306 192.168.1.100
# Output:
# 22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux)
# | ssh-hostkey:
# |   3072 f0:e6:24:fb:9e:b0:7a:1a:bd:f7:b1:85:23:7f:b1:6f (RSA)
# |   256 99:c8:74:31:45:10:58:b0:ce:cc:63:b4:7a:82:57:3d (ECDSA)
# |_  256 f2:fc:6c:75:08:20:b1:b2:51:2d:94:d6:94:d7:51:4f (ED25519)
# 
# 80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
# |_http-title: Welcome to Target Web Server
# |_http-server-header: Apache/2.4.41 (Ubuntu)
# 
# 443/tcp  open  ssl/http Apache httpd 2.4.41 ((Ubuntu))
# |_http-title: Secure Target Web Server
# | ssl-cert: Subject: commonName=target.local/organizationName=Target Org
# 
# 3306/tcp open  mysql   MySQL 8.0.25-0ubuntu0.20.04.1
# | mysql-info:
# |   Protocol: 10
# |   Version: 8.0.25-0ubuntu0.20.04.1
# |   Thread ID: 12
# |   Capabilities flags: 65535

# Step 3: Document discovered services
echo "Host: 192.168.1.100" > services.txt
echo "SSH: OpenSSH 8.2p1" >> services.txt
echo "HTTP: Apache 2.4.41" >> services.txt
echo "HTTPS: Apache 2.4.41 with SSL" >> services.txt
echo "MySQL: 8.0.25" >> services.txt
```

### Example 3: Web Application Discovery
```bash
# Step 1: HTTP service analysis
curl -I http://192.168.1.100
# Output:
# HTTP/1.1 200 OK
# Date: Mon, 15 Jan 2025 21:30:00 GMT
# Server: Apache/2.4.41 (Ubuntu)
# X-Powered-By: PHP/7.4.3
# Content-Type: text/html; charset=UTF-8

# Step 2: Web technology identification
whatweb http://192.168.1.100
# Output:
# http://192.168.1.100 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], 
# HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], 
# IP[192.168.1.100], PHP[7.4.3], Title[Welcome to Target Web Server]

# Step 3: Basic directory enumeration
gobuster dir -u http://192.168.1.100 -w /usr/share/wordlists/dirb/common.txt -x php,html
# Output:
# ===============================================================
# 2025/01/15 21:30:00 Starting gobuster
# ===============================================================
# /admin               (Status: 200) [Size: 1234]
# /backup              (Status: 301) [Size: 178] [--> http://192.168.1.100/backup/]
# /config.php          (Status: 200) [Size: 0]
# /index.html          (Status: 200) [Size: 10918]
# /info.php            (Status: 200) [Size: 95329]  
# /uploads             (Status: 301) [Size: 178] [--> http://192.168.1.100/uploads/]

# Step 4: Document web application findings
echo "Web Server: Apache 2.4.41" > webapp_info.txt
echo "Scripting: PHP 7.4.3" >> webapp_info.txt
echo "Admin Interface: /admin" >> webapp_info.txt
echo "Backup Directory: /backup/" >> webapp_info.txt
echo "Upload Directory: /uploads/" >> webapp_info.txt
echo "Info Page: /info.php (potential information disclosure)" >> webapp_info.txt
```

### Example 4: DNS and Domain Intelligence
```bash
# Step 1: Basic DNS enumeration
nslookup target.com
# Output:
# Server:         8.8.8.8
# Address:        8.8.8.8#53
# 
# Non-authoritative answer:
# Name:    target.com
# Address: 203.0.113.100

# Step 2: Comprehensive DNS record enumeration
dig target.com ANY
# Output:
# target.com.     300    IN      A       203.0.113.100
# target.com.     300    IN      MX      10 mail.target.com.
# target.com.     300    IN      NS      ns1.target.com.
# target.com.     300    IN      NS      ns2.target.com.
# target.com.     300    IN      TXT     "v=spf1 include:_spf.target.com ~all"

# Step 3: Subdomain enumeration attempt
sublist3r -d target.com
# Output:
# mail.target.com
# www.target.com
# admin.target.com
# dev.target.com
# ftp.target.com

# Step 4: Zone transfer attempt
dig @ns1.target.com target.com AXFR
# Output: (Usually fails due to security configurations)
# ; Transfer failed.
# ; communications error to ns1.target.com#53: timed out

# Step 5: Document DNS findings
echo "Main Domain: target.com (203.0.113.100)" > dns_info.txt
echo "Mail Server: mail.target.com" >> dns_info.txt  
echo "Subdomains: www, admin, dev, ftp" >> dns_info.txt
echo "Name Servers: ns1.target.com, ns2.target.com" >> dns_info.txt
```

## 🎯 eJPT Exam Focus

### Essential Information Gathering Skills for eJPT Success:
**Network Discovery (30% importance):**
- Identify all active hosts in target networks
- Map network topology and ranges
- Document live systems and their roles

**Service Enumeration (35% importance):**
- Discover all running services and versions
- Identify potential entry points
- Document service configurations and anomalies

**Web Application Discovery (20% importance):**
- Map web application structure and technologies
- Discover hidden directories and files
- Identify web-based attack surfaces

**Information Correlation (15% importance):**
- Connect discovered information into attack scenarios
- Prioritize targets based on value and accessibility
- Plan systematic exploitation approaches

### Critical Commands for eJPT Information Gathering:
```bash
# Network discovery essentials
nmap -sn network/cidr              # Host discovery
netdiscover -r network/cidr        # ARP-based discovery
arp-scan -l                        # Local ARP enumeration

# Service discovery essentials  
nmap -sS --top-ports 1000 target  # Quick TCP scan
nmap -sV -sC target               # Service detection with scripts
nmap -sU --top-ports 100 target   # UDP service discovery

# Web reconnaissance essentials
whatweb http://target             # Technology identification
curl -I http://target             # HTTP header analysis
gobuster dir -u http://target -w wordlist # Directory enumeration

# DNS enumeration essentials
dig target.com ANY                # All DNS records
nslookup target.com               # Basic DNS lookup
sublist3r -d target.com          # Subdomain enumeration
```

### eJPT Exam Scenarios and Expected Outcomes:

**Scenario 1: Network Mapping Exercise**
- **Task:** Map complete network topology for 192.168.1.0/24
- **Expected approach:** Progressive scanning from discovery to detailed enumeration
- **Success criteria:** Document all active hosts with services and versions
- **Common commands sequence:**
```bash
nmap -sn 192.168.1.0/24           # Step 1: Host discovery
nmap -sS --top-ports 1000 targets # Step 2: Port scanning  
nmap -sV -sC discovered_services  # Step 3: Service detection
```

**Scenario 2: Web Application Assessment Preparation**
- **Task:** Gather intelligence on web applications before vulnerability testing
- **Expected approach:** Technology identification, directory enumeration, service analysis
- **Success criteria:** Complete web application profile with technologies and structure
- **Common commands sequence:**
```bash
whatweb http://target             # Technology stack
curl -I http://target             # Server information
gobuster dir -u http://target -w wordlist # Content discovery
```

**Scenario 3: Service-Specific Intelligence**
- **Task:** Deep enumeration of discovered services (SSH, FTP, SMB, databases)
- **Expected approach:** Service-specific enumeration techniques
- **Success criteria:** Detailed service configuration and potential security issues
- **Common commands sequence:**
```bash
nmap --script service-* -p port target    # Service-specific scripts
banner grabbing techniques                # Manual service interaction
service-specific enumeration tools        # Specialized tool usage
```

### Time Management for eJPT Information Gathering:
- **Network Discovery:** 15-20 minutes maximum
- **Service Enumeration:** 20-30 minutes depending on scope
- **Web Application Discovery:** 15-25 minutes per web service
- **Documentation and Analysis:** 10-15 minutes throughout process

### Common eJPT Mistakes to Avoid:
1. **Incomplete network mapping** - Missing hosts due to single scan technique
2. **Insufficient service detection** - Not using version detection (-sV)
3. **Ignoring web applications** - Missing directory enumeration
4. **Poor documentation** - Not organizing findings systematically
5. **Time management issues** - Spending too much time on single targets

## ⚠️ Common Issues & Troubleshooting

### Network Discovery Problems:
**Issue:** Nmap ping sweep missing active hosts
**Symptoms:** Known hosts not appearing in scan results
**Diagnosis:**
```bash
# Test connectivity manually
ping -c 1 known_host_ip
# Check if ICMP is filtered
nmap -PS80,443,22 known_host_ip
# Try ARP discovery for local networks
arp-scan -l
```
**Solution:**
```bash
# Use multiple discovery techniques
nmap -sn target_network           # Standard ping sweep  
nmap -PS22,80,443 target_network  # TCP SYN ping
nmap -PA22,80,443 target_network  # TCP ACK ping
netdiscover -r target_network     # ARP-based discovery
```

### Service Detection Issues:
**Issue:** Services showing as "unknown" or version detection failing
**Symptoms:** Nmap showing open ports but no service information
**Diagnosis:**
```bash
# Manual banner grabbing
nc target_ip port
telnet target_ip port
# Check if service responds to connections
```
**Solution:**
```bash
# Enhanced version detection
nmap -sV --version-intensity 9 target_ip
nmap -sV --version-all target_ip
# Try service-specific enumeration
nmap --script banner target_ip
```

### False Positive Results:
**Issue:** Tools reporting services that don't actually exist
**Symptoms:** Inconsistent results between different tools
**Diagnosis:**
```bash
# Manual verification
nc -nv target_ip port
telnet target_ip port
# Cross-reference with multiple tools
masscan -p port target_ip
```
**Solution:**
```bash
# Verify results with multiple approaches
# Use different scan types
nmap -sS target_ip              # SYN scan
nmap -sT target_ip              # Connect scan
# Manual connection testing
for port in 22 80 443; do
    nc -zv target_ip $port
done
```

### DNS Resolution Problems:
**Issue:** DNS queries failing or returning incomplete information
**Symptoms:** DNS lookups timing out or missing records
**Diagnosis:**
```bash
# Test DNS server connectivity
dig @8.8.8.8 target.com
dig @1.1.1.1 target.com
# Check local DNS configuration
cat /etc/resolv.conf
```
**Solution:**
```bash
# Use alternative DNS servers
dig @8.8.8.8 target.com ANY
dig @1.1.1.1 target.com ANY
# Try different record types individually
dig target.com A
dig target.com MX
dig target.com NS
dig target.com TXT
```

### Performance and Timing Issues:
**Issue:** Scans taking too long or triggering security controls
**Symptoms:** Slow scan progress, connection timeouts, potential detection
**Diagnosis:**
```bash
# Check current scan timing
nmap -T3 target_ip              # Default timing
# Monitor network usage
iftop                           # Network traffic monitoring
```
**Solution:**
```bash
# Adjust scan timing and techniques
nmap -T2 target_ip              # Polite timing
nmap --scan-delay 1s target_ip  # Add delays between probes
# Use source port randomization
nmap --source-port 53 target_ip # Source port 53 (DNS)
```

## 🔗 Integration with Other Tools

### Information Gathering to Vulnerability Assessment Workflow:
```bash
# Step 1: Information gathering results
nmap -sS -sV -oA initial_scan target_network

# Step 2: Extract service information
grep "open" initial_scan.nmap > services.txt

# Step 3: Feed to vulnerability scanner
nmap --script vuln target_ip
nikto -h http://target_ip
```

### Automated Information Gathering Pipeline:
```bash
#!/bin/bash
# Complete information gathering automation

TARGET_NETWORK="192.168.1.0/24"
OUTPUT_DIR="recon_results"

# Create output directory
mkdir -p $OUTPUT_DIR

# Phase 1: Network discovery
echo "[+] Starting network discovery..."
nmap -sn $TARGET_NETWORK | grep "Nmap scan report" | cut -d' ' -f5 > $OUTPUT_DIR/live_hosts.txt

# Phase 2: Port scanning
echo "[+] Scanning discovered hosts..."
nmap -sS --top-ports 1000 -iL $OUTPUT_DIR/live_hosts.txt -oA $OUTPUT_DIR/port_scan

# Phase 3: Service enumeration
echo "[+] Enumerating services..."
nmap -sV -sC -iL $OUTPUT_DIR/live_hosts.txt -oA $OUTPUT_DIR/service_scan

# Phase 4: Web service discovery
echo "[+] Identifying web services..."
for host in $(cat $OUTPUT_DIR/live_hosts.txt); do
    if nmap -p 80,443,8080,8443 $host | grep -q "open"; then
        echo $host >> $OUTPUT_DIR/web_hosts.txt
        whatweb http://$host > $OUTPUT_DIR/${host}_whatweb.txt 2>/dev/null
        curl -I http://$host > $OUTPUT_DIR/${host}_headers.txt 2>/dev/null
    fi
done

# Phase 5: Generate summary report
echo "[+] Generating summary report..."
echo "Information Gathering Results - $(date)" > $OUTPUT_DIR/summary.txt
echo "=======================================" >> $OUTPUT_DIR/summary.txt
echo "Live Hosts: $(wc -l < $OUTPUT_DIR/live_hosts.txt)" >> $OUTPUT_DIR/summary.txt
echo "Web Services: $(if [[ -f $OUTPUT_DIR/web_hosts.txt ]]; then wc -l < $OUTPUT_DIR/web_hosts.txt; else echo "0"; fi)" >> $OUTPUT_DIR/summary.txt

echo "[+] Information gathering complete. Results in $OUTPUT_DIR/"
```

### Integration with Metasploit Framework:
```bash
# Import Nmap results into Metasploit
msfconsole
msf6 > db_nmap -sS -sV target_network
msf6 > hosts                    # View discovered hosts
msf6 > services                 # View discovered services
msf6 > vulns                    # View potential vulnerabilities
```

## 📝 Documentation and Reporting

### Information Gathering Report Template:
```markdown
# Information Gathering Report
**Target:** [Organization/IP Range]
**Date:** [Scan Date and Time]
**Tester:** [Your Name]
**Scope:** [Defined Scope and Limitations]

## Executive Summary
Brief overview of reconnaissance activities, scope, and key findings.

## Methodology
Description of information gathering approach and tools used.

## Network Discovery Results
### Live Host Summary
| IP Address | MAC Address | Hostname | Response Time | Notes |
|------------|-------------|----------|---------------|--------|
| 192.168.1.1 | 00:50:56:12:34:56 | gateway | 0.001s | Gateway/Router |
| 192.168.1.100 | 00:0c:29:ab:cd:ef | target-server | 0.002s | Primary target |

### Network Topology
Visual or textual representation of discovered network structure.

## Service Discovery Results  
### Port Scan Summary
```bash
# Commands used
nmap -sS --top-ports 1000 target_range
nmap -sV -sC discovered_hosts
```

### Service Inventory
#### Host: 192.168.1.100
| Port | Protocol | Service | Version | State | Notes |
|------|----------|---------|---------|--------|--------|
| 22 | TCP | SSH | OpenSSH 8.2p1 | Open | Ubuntu system |
| 80 | TCP | HTTP | Apache 2.4.41 | Open | Web server |
| 443 | TCP | HTTPS | Apache 2.4.41 | Open | SSL enabled |
| 3306 | TCP | MySQL | 8.0.25 | Open | Database server |

## Web Application Discovery
### Technology Stack Analysis
- **Web Server:** Apache 2.4.41 (Ubuntu)
- **Scripting Language:** PHP 7.4.3
- **Database:** MySQL 8.0.25
- **SSL Certificate:** target.local (self-signed)

### Directory Enumeration Results
```bash
gobuster dir -u http://192.168.1.100 -w common.txt
```
| Directory/File | Status | Size | Notes |
|----------------|--------|------|-------|
| /admin | 200 | 1234 | Admin interface |
| /backup | 301 | 178 | Backup directory |
| /uploads | 301 | 178 | File upload location |
| /info.php | 200 | 95329 | PHP info (sensitive) |

## DNS and Domain Intelligence
### DNS Records
```bash
dig target.com ANY
```
- **A Record:** 203.0.113.100
- **MX Record:** mail.target.com (priority 10)
- **NS Records:** ns1.target.com, ns2.target.com  
- **TXT Records:** SPF configuration present

### Subdomain Discovery
- mail.target.com
- www.target.com
- admin.target.com
- dev.target.com

## Attack Surface Analysis
### High-Priority Targets
1. **Web Applications** (ports 80, 443)
   - Multiple directories discovered
   - PHP info page exposed
   - Admin interface accessible

2. **Database Service** (port 3306)
   - MySQL service exposed
   - Version identified (8.0.25)
   - Potential authentication bypass targets

3. **SSH Service** (port 22)
   - OpenSSH service
   - Potential brute force target
   - Key-based authentication analysis needed

### Potential Attack Vectors
- Web application vulnerabilities
- Database authentication attacks
- SSH brute force attempts
- File upload exploitation
- Information disclosure via PHP info

## Recommendations for Next Phase
1. **Vulnerability Assessment:** Focus on identified services
2. **Web Application Testing:** Comprehensive web app security testing
3. **Authentication Testing:** Database and SSH authentication analysis
4. **Network Segmentation Analysis:** Test for lateral movement possibilities

## Appendices
### Appendix A: Raw Tool Output
[Include raw tool outputs, screenshots, and detailed logs]

### Appendix B: Commands Reference
[List all commands used during information gathering]
```

### Quick Documentation Checklist:
- [ ] Network scope clearly defined
- [ ] All discovery methods documented  
- [ ] Live hosts identified and verified
- [ ] Services enumerated with versions
- [ ] Web applications mapped
- [ ] DNS infrastructure documented
- [ ] Attack surface prioritized
- [ ] Next steps recommended
- [ ] Raw data preserved for reference

## 📚 Information Gathering Quick Reference Card

### Essential Discovery Commands:
```bash
# Network discovery
nmap -sn network/cidr              # Host discovery
netdiscover -r network/cidr        # ARP discovery
arp-scan -l                        # Local ARP scan

# Port scanning
nmap -sS --top-ports 1000 target  # Quick TCP scan
nmap -sU --top-ports 100 target   # Quick UDP scan
nmap -sV target                    # Service version detection

# Web reconnaissance
whatweb http://target              # Technology identification
curl -I http://target              # HTTP headers
gobuster dir -u http://target -w wordlist # Directory enumeration

# DNS enumeration
dig target.com ANY                 # All DNS records
nslookup target.com                # Basic DNS lookup
sublist3r -d target.com           # Subdomain enumeration
```

### OSINT Quick Commands:
```bash
# Search engine reconnaissance
site:target.com filetype:pdf       # PDF documents
site:target.com inurl:admin        # Admin interfaces
site:target.com "confidential"     # Sensitive content

# Domain intelligence
whois target.com                   # Domain registration
whois target_ip                    # IP ownership
theharvester -d target.com -b google # Email harvesting
```

### Service-Specific Enumeration:
```bash
# HTTP/HTTPS services
nikto -h http://target             # Web vulnerability scanner
dirb http://target                 # Directory brute force
wafw00f http://target             # WAF detection

# SSH services
nmap --script ssh-* -p 22 target  # SSH enumeration scripts
ssh-audit target                   # SSH configuration audit

# FTP services
nmap --script ftp-* -p 21 target  # FTP enumeration scripts
ftp target                        # Manual FTP connection

# SMB services
enum4linux target                 # SMB enumeration
smbclient -L //target             # SMB share listing
```

### eJPT Exam Priority Rankings:
⭐⭐⭐ **Critical (Must Know):**
- Network discovery with nmap ping sweeps
- Basic port scanning techniques
- Service version detection
- Web technology identification
- Directory enumeration basics

⭐⭐ **Important (Should Know):**
- DNS enumeration techniques  
- OSINT and Google dorking
- Banner grabbing methods
- Alternative discovery tools
- Service-specific enumeration

⭐ **Useful (Good to Know):**
- Advanced OSINT frameworks
- Automated reconnaissance pipelines
- Social media intelligence
- Certificate transparency mining
- Network topology mapping

### Time Management Guide for eJPT:
```bash
# Recommended time allocation for information gathering phase:
# Total time budget: 60-90 minutes for complete reconnaissance

# Phase 1: Network Discovery (15-20 minutes)
nmap -sn target_network            # 2-3 minutes
netdiscover -r target_network      # 3-5 minutes  
arp-scan verification              # 2-3 minutes
Documentation and analysis         # 8-10 minutes

# Phase 2: Service Enumeration (25-35 minutes)
nmap -sS --top-ports 1000 targets # 5-8 minutes
nmap -sV detailed enumeration     # 10-15 minutes
Service-specific enumeration       # 10-12 minutes

# Phase 3: Web Application Discovery (15-25 minutes)
Technology identification          # 3-5 minutes
Directory enumeration             # 8-12 minutes
HTTP analysis and documentation   # 4-8 minutes

# Phase 4: Documentation and Planning (5-10 minutes)
Results organization              # 3-5 minutes
Attack surface prioritization     # 2-5 minutes
```

### Common eJPT Exam Gotchas:
1. **UDP Services:** Don't forget UDP scanning (-sU flag)
2. **Service Versions:** Always use -sV for version detection
3. **Web Directories:** Check for common admin/backup directories
4. **Documentation:** Keep organized notes throughout the process
5. **Time Management:** Don't spend too much time on single hosts
6. **Network Scope:** Ensure you're scanning the complete target range
7. **Service Scripts:** Use -sC for additional service information

### Troubleshooting Quick Fixes:
```bash
# Host discovery issues
nmap -Pn target                    # Skip ping, assume host is up
nmap -PS80,443,22 target          # TCP SYN ping specific ports

# Service detection problems  
nmap -sV --version-intensity 9 target # Aggressive version detection
nc target port                     # Manual banner grabbing

# DNS resolution issues
dig @8.8.8.8 target.com           # Use Google DNS
dig @1.1.1.1 target.com           # Use Cloudflare DNS

# Scan performance optimization
nmap -T4 target                    # Faster timing template
nmap --min-rate 1000 target       # Minimum packet rate
```

This comprehensive guide covers all essential information gathering techniques required for eJPT success. The methodology progresses logically from passive reconnaissance through active enumeration, with practical examples and real-world scenarios that mirror the exam environment. Remember to always document findings systematically and prioritize targets based on their potential value and accessibility for the exploitation phase.
