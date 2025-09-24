# 🕵️ Information Gathering Basics - Reconnaissance Fundamentals

Information gathering is the critical first phase of penetration testing where we collect data about our target to identify potential attack vectors and vulnerabilities.
**Location:** `01-theory-foundations/information-gathering-basics.md`

## 🎯 What is Information Gathering?

Information gathering (also known as reconnaissance or OSINT - Open Source Intelligence) is the systematic process of collecting publicly available information about a target organization, its infrastructure, and personnel. This phase forms the foundation of any successful penetration test.

Key objectives of information gathering include:
- **Target Identification:** Discovering IP ranges, domains, and subdomains
- **Technology Stack Discovery:** Identifying web servers, databases, and frameworks
- **Personnel Information:** Finding employee names, emails, and social media profiles
- **Infrastructure Mapping:** Understanding network topology and services
- **Attack Surface Analysis:** Identifying potential entry points and vulnerabilities

## 📦 Installation and Setup

### Prerequisites:
- Linux environment (Kali Linux recommended)
- Internet connection for OSINT activities
- Basic understanding of DNS and networking concepts
- Web browser with security extensions

### Essential Tools Installation:
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install core reconnaissance tools
sudo apt install dnsutils whois dig nslookup curl wget -y

# Install additional OSINT tools
sudo apt install theharvester recon-ng maltego -y

# Install web reconnaissance tools
sudo apt install dirb gobuster nikto whatweb -y

# Verification
whois --version
dig -v
theharvester --help
```

### Browser Extensions Setup:
```bash
# Install useful browser extensions:
# - Wappalyzer (technology detection)
# - BuiltWith (technology profiler)  
# - Shodan (network scanner)
# - Have I Been Pwned (breach checker)
```

## 🔧 Basic Usage and Methodology

### Information Gathering Workflow:
1. **Passive Reconnaissance:** Collecting information without direct target interaction
2. **Semi-Passive:** Limited interaction through public services
3. **Active Reconnaissance:** Direct interaction with target systems
4. **Analysis & Documentation:** Processing and organizing collected data

### OSINT Framework:
```bash
# Phase 1: Domain and subdomain discovery
whois target.com
dig target.com
nslookup target.com

# Phase 2: Technology identification
whatweb target.com
curl -I https://target.com

# Phase 3: Email and personnel discovery
theharvester -d target.com -b google,bing,linkedin
```

## ⚙️ Information Types and Sources

### Domain and DNS Information:
| Information Type | Tools Used | Example Command |
|-----------------|------------|-----------------|
| **WHOIS Data** | whois, online databases | `whois target.com` |
| **DNS Records** | dig, nslookup, host | `dig target.com ANY` |
| **Subdomains** | sublist3r, amass | `sublist3r -d target.com` |
| **Reverse DNS** | dig, host | `dig -x 192.168.1.1` |

### Web Application Information:
| Information Type | Tools Used | Example Command |
|-----------------|------------|-----------------|
| **Technology Stack** | whatweb, wappalyzer | `whatweb target.com` |
| **HTTP Headers** | curl, burp suite | `curl -I https://target.com` |
| **Robots.txt** | curl, wget | `curl https://target.com/robots.txt` |
| **Directory Structure** | dirb, gobuster | `dirb https://target.com` |

### Social and Personnel Information:
| Information Type | Tools Used | Example Command |
|-----------------|------------|-----------------|
| **Email Addresses** | theharvester, hunter.io | `theharvester -d target.com -b all` |
| **Employee Names** | linkedin, social media | Manual research |
| **Breach Data** | haveibeenpwned.com | Online service |
| **Social Media** | sherlock, social-searcher | `sherlock username` |

### Network Infrastructure:
| Information Type | Tools Used | Example Command |
|-----------------|------------|-----------------|
| **IP Ranges** | whois, arin.net | `whois -h whois.arin.net target.com` |
| **Network Blocks** | bgp.he.net, robtex | Online research |
| **ASN Information** | whois, bgpview | `whois -h whois.radb.net AS12345` |
| **Geolocation** | geoiplookup, online tools | `geoiplookup 8.8.8.8` |

## 🧪 Real Lab Examples

### Example 1: Complete Domain Reconnaissance
```bash
# Phase 1: Basic domain information
whois testphp.vulnweb.com
# Output: Domain registrar, creation date, nameservers, registrant info

# Phase 2: DNS enumeration
dig testphp.vulnweb.com ANY
# Output: A, MX, NS, TXT records
# A record: 44.228.249.3
# MX record: mail.vulnweb.com
# NS records: ns1.vulnweb.com, ns2.vulnweb.com

# Phase 3: Subdomain discovery
dig @8.8.8.8 testphp.vulnweb.com
dig @8.8.8.8 www.testphp.vulnweb.com
dig @8.8.8.8 mail.testphp.vulnweb.com
# Output: Additional subdomains and IP addresses

# Phase 4: Reverse DNS lookup
dig -x 44.228.249.3
# Output: PTR record showing hostname
```

### Example 2: Web Application Technology Discovery
```bash
# Step 1: HTTP header analysis
curl -I http://testphp.vulnweb.com
# Output:
# HTTP/1.1 200 OK
# Server: nginx/1.19.0
# X-Powered-By: PHP/5.6.40
# Set-Cookie: PHPSESSID=abc123

# Step 2: Technology fingerprinting
whatweb http://testphp.vulnweb.com
# Output: 
# nginx 1.19.0, PHP 5.6.40, MySQL detected
# jQuery 1.4.2, Bootstrap framework

# Step 3: Directory discovery
dirb http://testphp.vulnweb.com
# Output:
# + http://testphp.vulnweb.com/admin/ (CODE:200)
# + http://testphp.vulnweb.com/backup/ (CODE:403)
# + http://testphp.vulnweb.com/config/ (CODE:403)

# Step 4: Robots.txt analysis
curl http://testphp.vulnweb.com/robots.txt
# Output:
# User-agent: *
# Disallow: /admin/
# Disallow: /backup/
# Disallow: /config/
```

### Example 3: Email and Personnel Discovery
```bash
# Step 1: Email harvesting
theharvester -d vulnweb.com -b google,bing,linkedin -l 100
# Output:
# admin@vulnweb.com
# support@vulnweb.com  
# info@vulnweb.com
# john.doe@vulnweb.com

# Step 2: Social media reconnaissance
# Manual research on LinkedIn, Twitter, Facebook
# Found: John Doe - Security Engineer at VulnWeb
# Found: Jane Smith - Web Developer at VulnWeb

# Step 3: Breach data checking
# Check emails on haveibeenpwned.com
# Result: admin@vulnweb.com found in 3 breaches
# - Adobe breach (2013)
# - LinkedIn breach (2012)
# - Collection #1 (2019)
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **Domain enumeration** (25% of information gathering questions)
- **Technology identification** (20% of web application assessment)
- **DNS analysis** (15% of network discovery)
- **Directory enumeration** (20% of web reconnaissance)

### Critical Commands to Master:
```bash
# DNS enumeration (High priority for eJPT)
dig target.com ANY                    # Complete DNS record dump
nslookup target.com                   # Basic DNS lookup
host target.com                       # Simple hostname resolution

# WHOIS information (Medium priority)
whois target.com                      # Domain registration info
whois 192.168.1.1                     # IP ownership info

# Web technology discovery (High priority)
whatweb http://target.com             # Technology fingerprinting
curl -I http://target.com             # HTTP headers analysis
curl http://target.com/robots.txt     # Robots.txt discovery
```

### eJPT Exam Scenarios:

1. **Scenario 1: Domain Intelligence Collection**
   - Required skills: DNS enumeration, WHOIS lookup, subdomain discovery
   - Expected commands: dig, whois, nslookup
   - Success criteria: Identify nameservers, mail servers, and IP ranges

2. **Scenario 2: Web Application Reconnaissance**  
   - Required skills: Technology identification, directory discovery, HTTP analysis
   - Expected commands: whatweb, dirb, curl
   - Success criteria: Identify web server, framework, and hidden directories

3. **Scenario 3: Network Infrastructure Mapping**
   - Required skills: IP range identification, network topology discovery
   - Expected commands: whois, dig, traceroute
   - Success criteria: Map network boundaries and identify critical infrastructure

### Exam Tips and Tricks:
- **Tip 1:** Always start with passive reconnaissance before active scanning
- **Tip 2:** Document everything - even negative results can be valuable
- **Tip 3:** Use multiple sources to verify information (DNS propagation delays)
- **Tip 4:** Focus on publicly available information first
- **Tip 5:** Remember legal boundaries - only gather information that's publicly available

### Common eJPT Questions:
- "What technology is running on the web server?" → Use whatweb or curl -I
- "What are the nameservers for this domain?" → Use dig target.com NS
- "Find hidden directories on the website" → Use dirb or gobuster
- "What is the IP range owned by this organization?" → Use whois and ARIN databases

## ⚠️ Common Issues & Troubleshooting

### Issue 1: DNS Resolution Problems
**Problem:** DNS queries fail or return incomplete results
**Cause:** DNS server issues, rate limiting, or network connectivity
**Solution:**
```bash
# Try different DNS servers
dig @8.8.8.8 target.com              # Google DNS
dig @1.1.1.1 target.com              # Cloudflare DNS  
dig @208.67.222.222 target.com       # OpenDNS

# Verify network connectivity
ping 8.8.8.8                         # Test internet connection
nslookup google.com                   # Test basic DNS functionality
```

### Issue 2: Rate Limiting and Blocking
**Problem:** Getting blocked or rate limited by target services
**Solution:**
```bash
# Add delays between requests
sleep 5 && curl http://target.com

# Use different User-Agent strings
curl -H "User-Agent: Mozilla/5.0..." http://target.com

# Rotate through proxy servers
curl --proxy proxy1:8080 http://target.com
```

### Issue 3: Incomplete Email Harvesting
**Problem:** theharvester returns limited results
**Prevention:**
```bash
# Use multiple search engines
theharvester -d target.com -b google,bing,yahoo,linkedin,twitter

# Try different search engines separately
theharvester -d target.com -b google -l 200
theharvester -d target.com -b bing -l 200
```

### Issue 4: Technology Detection Failures
**Problem:** whatweb or wappalyzer don't detect technologies
**Optimization:**
```bash
# Manual header analysis
curl -s -I http://target.com | grep -i server
curl -s -I http://target.com | grep -i x-powered-by

# Source code analysis
curl -s http://target.com | grep -i "generator\|framework\|version"
```

## 🔗 Integration with Other Tools

### Primary Integration: Information Gathering → Network Discovery → Service Enumeration
```bash
# Step 1: Gather domain information
dig target.com A | grep -E '^target\.com' | awk '{print $5}' > ip_list.txt

# Step 2: Feed IPs to network scanner
nmap -sn -iL ip_list.txt > live_hosts.txt

# Step 3: Enumerate services on live hosts
nmap -sV -sC -iL live_hosts.txt -oN service_scan.txt

# Complete workflow integration
information_gathering_phase → network_discovery → service_enumeration → vulnerability_assessment
```

### Secondary Integration: OSINT → Social Engineering → Password Attacks
```bash
# Collect email addresses for password attacks
theharvester -d target.com -b all > emails.txt

# Extract clean email list
grep -E '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' emails.txt > clean_emails.txt

# Use emails for targeted password attacks
hydra -L clean_emails.txt -P common_passwords.txt target.com http-post-form
```

### Advanced Workflows:
```bash
# Automated reconnaissance pipeline
#!/bin/bash
DOMAIN=$1

# Phase 1: Domain intelligence
whois $DOMAIN > recon_results/$DOMAIN/whois.txt
dig $DOMAIN ANY > recon_results/$DOMAIN/dns.txt

# Phase 2: Subdomain discovery  
sublist3r -d $DOMAIN -o recon_results/$DOMAIN/subdomains.txt

# Phase 3: Technology profiling
whatweb http://$DOMAIN > recon_results/$DOMAIN/technology.txt

# Phase 4: Directory discovery
dirb http://$DOMAIN > recon_results/$DOMAIN/directories.txt
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** WHOIS results, DNS records, technology detection outputs
2. **Command Outputs:** All reconnaissance commands with timestamps
3. **Data Exports:** Email lists, subdomain lists, IP ranges in structured format
4. **Source Attribution:** Document information sources for verification

### Report Template Structure:
```markdown
## Information Gathering Results

### Target Information
- Primary Domain: target.com
- Date/Time: 2025-09-24 10:30:00 UTC
- Scope: target.com and *.target.com
- Tools Used: dig, whois, whatweb, theharvester, dirb

### Domain Intelligence
```bash
# WHOIS Information
whois target.com
# Output: [Include relevant WHOIS data]

# DNS Records  
dig target.com ANY
# Output: [Include DNS record details]
```

### Key Findings
- **Domain Registration:** Registered 2015-03-10, expires 2026-03-10
- **Nameservers:** ns1.target.com, ns2.target.com
- **Mail Server:** mail.target.com (192.168.1.100)
- **Web Technologies:** nginx 1.19.0, PHP 7.4.3, MySQL 5.7
- **Email Addresses:** 15 addresses discovered across multiple sources
- **Subdomains:** 8 subdomains identified (www, mail, ftp, admin, api, dev, staging, test)

### Attack Surface Summary
- **Web Applications:** 3 web applications identified
- **Email Services:** SMTP, POP3, IMAP services detected
- **File Transfer:** FTP service on ftp.target.com
- **Administrative Interfaces:** admin.target.com requires authentication

### Recommendations for Next Phase
- Perform detailed port scanning on identified IP ranges
- Enumerate services on discovered subdomains
- Test administrative interfaces for default credentials
- Conduct web application security assessment
```

### Automation Scripts:
```bash
# Comprehensive information gathering script
#!/bin/bash
# recon_automation.sh

DOMAIN=$1
OUTPUT_DIR="recon_results/$DOMAIN"
mkdir -p $OUTPUT_DIR

echo "[+] Starting reconnaissance for $DOMAIN"
echo "[+] Results will be saved to $OUTPUT_DIR"

# Domain information
echo "[+] Collecting domain information..."
whois $DOMAIN > $OUTPUT_DIR/whois.txt 2>/dev/null
dig $DOMAIN ANY > $OUTPUT_DIR/dns_records.txt 2>/dev/null

# Technology detection
echo "[+] Identifying web technologies..."
whatweb http://$DOMAIN > $OUTPUT_DIR/technology.txt 2>/dev/null
curl -I http://$DOMAIN > $OUTPUT_DIR/http_headers.txt 2>/dev/null

# Email harvesting
echo "[+] Harvesting email addresses..."
theharvester -d $DOMAIN -b google,bing -l 100 > $OUTPUT_DIR/emails.txt 2>/dev/null

# Directory discovery
echo "[+] Discovering directories..."
dirb http://$DOMAIN -o $OUTPUT_DIR/directories.txt > /dev/null 2>&1

echo "[+] Reconnaissance complete! Check $OUTPUT_DIR for results"
```

## 📚 Additional Resources

### Official Documentation:
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- SANS Information Gathering: https://www.sans.org/white-papers/

### Learning Resources:
- eJPT Official Course: https://elearnsecurity.com/product/ejpt-certification/
- Cybrary OSINT Course: https://www.cybrary.it/course/open-source-intelligence/
- OSINT Framework: https://osintframework.com/

### Community Resources:
- Reddit r/OSINT: https://www.reddit.com/r/OSINT/
- OSINT Curious: https://osintcurio.us/
- Bellingcat Online Investigation Toolkit: https://www.bellingcat.com/resources/

### Related Tools:
- **Maltego:** Advanced OSINT and link analysis platform
- **Recon-ng:** Full-featured reconnaissance framework  
- **Amass:** Advanced subdomain enumeration tool
- **Shodan:** Internet-connected device search engine
- **SpiderFoot:** Automated OSINT collection tool
