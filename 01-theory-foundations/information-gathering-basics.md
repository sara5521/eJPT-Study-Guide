---
title: "Information Gathering Basics - Complete eJPT Guide"
topic: "Reconnaissance"
exam_objective: "Host and network discovery, OSINT gathering, DNS enumeration"
difficulty: "Easy"
tools:
  - "dig"
  - "nslookup"
  - "whois"
  - "theharvester"
  - "whatweb"
  - "dirb"
  - "sublist3r"
related_labs:
  - "passive-reconnaissance.md"
  - "dns-enumeration.md"
  - "web-directory-enumeration.md"
file_path: "01-theory-foundations/information-gathering-basics.md"
last_updated: "2025-09-30"
tags:
  - "reconnaissance"
  - "osint"
  - "dns-enumeration"
  - "subdomain-discovery"
  - "information-gathering"
---

# 🔍 Information Gathering Basics - Complete eJPT Guide

**Essential reconnaissance fundamentals for penetration testing and eJPT certification preparation**

**📍 File Location:** `01-theory-foundations/information-gathering-basics.md`

---

## 🎯 What is Information Gathering?

Information Gathering (also called Reconnaissance or OSINT) is the first step in penetration testing. It means collecting publicly available information about a target to find potential attack methods. Think of it like doing research before a job interview - you want to know everything possible about the company.

### 🔍 **What Information Gathering Does:**
- **Find target details** like IP addresses, domains, and subdomains
- **Discover technologies** used by web servers and applications
- **Collect employee information** like names and email addresses
- **Map network infrastructure** to understand the target's setup
- **Identify potential weaknesses** in the target's security

### 💡 **Why This Matters for eJPT:**
Information gathering is tested heavily in the eJPT exam. You'll need to find domains, discover web technologies, enumerate DNS records, and collect email addresses. These skills form the foundation for all other penetration testing activities.

---

## 📦 Installation and Setup

### **Already Installed On:**
- ✅ Kali Linux
- ✅ Parrot Security OS
- ✅ Most penetration testing systems

### **Check If Tools Are Available:**
```bash
# Check essential DNS tools
dig --version
nslookup --version
whois --version

# Check web reconnaissance tools
whatweb --version
dirb
gobuster --help

# Check OSINT tools
theharvester --help
sublist3r --help
```

### **Install Missing Tools:**
```bash
# Update system first
sudo apt update && sudo apt upgrade -y

# Install basic network utilities
sudo apt install dnsutils whois curl wget -y

# Install web reconnaissance tools
sudo apt install whatweb nikto dirb gobuster -y

# Install OSINT tools
sudo apt install theharvester sublist3r -y

# Install Python-based tools
pip3 install sherlock-project
```

### **Requirements:**
- Stable internet connection for DNS queries
- Basic understanding of domain names and IP addresses
- Text editor for documenting findings

---

## 🔧 Basic Usage and Process

### **📋 Simple Process:**
1. **🎯 Define Target:** Identify what you're investigating (domain, company, IP)
2. **🔍 DNS Discovery:** Find IP addresses, mail servers, and name servers
3. **🌐 Web Analysis:** Discover web technologies and directory structure
4. **📧 Email Collection:** Gather email addresses for social engineering
5. **📝 Document Results:** Record all findings for analysis and reporting

### **⚙️ Basic Command Flow:**
```bash
# Step 1: Basic domain information
dig target.com ANY
whois target.com

# Step 2: Web technology discovery
whatweb http://target.com
curl -I http://target.com

# Step 3: Directory discovery
dirb http://target.com

# Step 4: Email harvesting
theharvester -d target.com -b google
```

---

## ⚙️ Essential Commands You Need to Know

### **🎯 DNS Reconnaissance Commands:**

| Command | What It Does | Example | eJPT Important |
|---------|--------------|---------|----------------|
| `dig target.com ANY` | Get all DNS records | `dig google.com ANY` | ⭐⭐⭐⭐⭐ Critical |
| `dig target.com A` | Get IP addresses | `dig google.com A` | ⭐⭐⭐⭐⭐ Critical |
| `dig target.com MX` | Get mail servers | `dig google.com MX` | ⭐⭐⭐⭐ High |
| `dig target.com NS` | Get name servers | `dig google.com NS` | ⭐⭐⭐⭐ High |
| `nslookup target.com` | Alternative DNS lookup | `nslookup google.com` | ⭐⭐⭐⭐ High |
| `whois target.com` | Domain registration info | `whois google.com` | ⭐⭐⭐ Medium |

### **🌐 Web Technology Discovery:**

| Command | What It Does | Example | When to Use |
|---------|--------------|---------|-------------|
| `whatweb target.com` | Identify web technologies | `whatweb http://testphp.vulnweb.com` | Technology fingerprinting |
| `curl -I target.com` | Get HTTP headers | `curl -I http://google.com` | Server identification |
| `dirb http://target.com` | Find directories | `dirb http://testphp.vulnweb.com` | Directory discovery |
| `gobuster dir -u http://target.com -w wordlist.txt` | Fast directory search | `gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt` | Advanced directory enumeration |

### **📧 Information Collection:**

| Command | What It Does | Example | eJPT Critical |
|---------|--------------|---------|---------------|
| `theharvester -d target.com -b google` | Collect emails | `theharvester -d tesla.com -b google` | ⭐⭐⭐⭐ High |
| `sublist3r -d target.com` | Find subdomains | `sublist3r -d google.com` | ⭐⭐⭐ Medium |
| `fierce -dns target.com` | DNS enumeration | `fierce -dns google.com` | ⭐⭐⭐ Medium |

---

## 🧪 Real Lab Examples with Step-by-Step Results

### **Example 1: Complete DNS Analysis of testphp.vulnweb.com**

**Lab Context:** Performing comprehensive DNS reconnaissance on a known vulnerable web application to understand the infrastructure.

#### **Step 1: Basic DNS Information**
```bash
# Get all DNS records
dig testphp.vulnweb.com ANY +noall +answer

# Expected Output:
testphp.vulnweb.com.    3600    IN      A       44.228.249.3
testphp.vulnweb.com.    3600    IN      NS      ns1.vulnweb.com.
testphp.vulnweb.com.    3600    IN      NS      ns2.vulnweb.com.
```

**🔍 What This Shows:**
- **IP Address:** 44.228.249.3 (target for further testing)
- **Name Servers:** ns1.vulnweb.com and ns2.vulnweb.com
- **TTL:** 3600 seconds (1 hour cache time)
- **Record Types:** A records for IP mapping, NS records for DNS authority

#### **Step 2: Specific Record Analysis**
```bash
# Get just the IP addresses
dig testphp.vulnweb.com A +short
# Output: 44.228.249.3

# Check for mail servers
dig testphp.vulnweb.com MX +short
# Output: (no MX records found)

# Get name servers
dig testphp.vulnweb.com NS +short
# Output:
# ns1.vulnweb.com.
# ns2.vulnweb.com.
```

**📝 Intelligence Gathered:**
- Single IP address hosting the site
- No email infrastructure (no MX records)
- Two name servers for DNS redundancy
- Simple hosting setup suggests smaller organization

#### **Step 3: Reverse DNS Lookup**
```bash
# Check what domain points to this IP
dig -x 44.228.249.3

# Expected Output:
3.249.228.44.in-addr.arpa. 3600 IN PTR testphp.vulnweb.com.
```

**🎯 What This Confirms:**
- IP address correctly maps back to the domain
- No shared hosting detected (single domain per IP)
- Proper DNS configuration in place

---

### **Example 2: Web Technology Discovery and Analysis**

**Lab Context:** Identifying the technology stack of testphp.vulnweb.com to understand potential attack vectors.

#### **Technology Fingerprinting**
```bash
# Identify web technologies
whatweb http://testphp.vulnweb.com

# Expected Output:
http://testphp.vulnweb.com [200 OK] Country[UNITED STATES][US], 
HTTPServer[nginx/1.19.0], IP[44.228.249.3], MySQL, PHP[5.6.40], 
PoweredBy[PHP/5.6.40], Script, Title[Home of Acunetix Art], 
UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], 
X-Powered-By[PHP/5.6.40]
```

**🔧 Technology Stack Identified:**
- **Web Server:** nginx 1.19.0
- **Backend Language:** PHP 5.6.40 (outdated version)
- **Database:** MySQL detected
- **Security Headers:** Some basic protection in place
- **Location:** United States hosting

#### **HTTP Header Analysis**
```bash
# Get detailed HTTP headers
curl -I http://testphp.vulnweb.com

# Expected Output:
HTTP/1.1 200 OK
Server: nginx/1.19.0
Date: Mon, 30 Sep 2024 10:15:32 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Powered-By: PHP/5.6.40
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
```

**⚠️ Security Assessment:**
- **Outdated PHP:** Version 5.6.40 is end-of-life (security risk)
- **Server Version Disclosure:** nginx version exposed
- **Missing Security Headers:** No CSP, HSTS missing
- **Basic Protection:** X-Frame-Options present (good)

---

### **Example 3: Directory Discovery and Structure Analysis**

**Lab Context:** Mapping the directory structure to find hidden or sensitive areas of the web application.

#### **Basic Directory Enumeration**
```bash
# Discover common directories
dirb http://testphp.vulnweb.com

# Sample Output (abbreviated):
-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Mon Sep 30 10:20:15 2024
URL_BASE: http://testphp.vulnweb.com/
WORDLIST_FILE: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://testphp.vulnweb.com/ ----
+ http://testphp.vulnweb.com/admin (CODE:401|SIZE:458)
+ http://testphp.vulnweb.com/images (CODE:301|SIZE:185)
+ http://testphp.vulnweb.com/index (CODE:200|SIZE:4958)
+ http://testphp.vulnweb.com/index.php (CODE:200|SIZE:4958)
```

**📂 Directory Analysis:**
- **Admin Area:** /admin (401 Unauthorized - requires authentication)
- **Images Directory:** /images (301 Redirect - publicly accessible)
- **Main Page:** /index.php (200 OK - standard homepage)
- **Directory Indexing:** Likely disabled (security measure)

#### **Advanced Directory Search**
```bash
# Search for specific file types
gobuster dir -u http://testphp.vulnweb.com -w /usr/share/wordlists/dirb/common.txt -x php,html,txt

# Expected findings:
/login.php (Status: 200)
/search.php (Status: 200)
/artists.php (Status: 200)
/userinfo.php (Status: 200)
/categories.php (Status: 200)
```

**🎯 Attack Surface Identified:**
- **Login Form:** /login.php (potential authentication bypass)
- **Search Function:** /search.php (SQL injection testing target)
- **User Information:** /userinfo.php (information disclosure)
- **Categories:** /categories.php (parameter manipulation)

---

### **Example 4: Email and Subdomain Discovery**

**Lab Context:** Collecting intelligence about email addresses and subdomains associated with the vulnweb.com domain.

#### **Email Address Harvesting**
```bash
# Collect email addresses from search engines
theharvester -d vulnweb.com -b google,bing -l 100

# Sample Output:
*******************************************************************
*  _   _                                            _            *
* | |_| |__   ___    /\  /\__ _ _ ____   _____  ___| |_ ___ _ __  *
* | __|  _ \ / _ \  /  \/ / _` | '__\ \ / / _ \/ __| __/ _ \ '__| *
* | |_| | | |  __/ / /\  / (_| | |   \ V /  __/\__ \ ||  __/ |    *
*  \__|_| |_|\___| \/  \/ \__,_|_|    \_/ \___||___/\__\___|_|    *
*                                                                 *
* theHarvester 4.0.3 *
* Coded by Christian Martorella *
* Edge-Security Research *
* cmartorella@edge-security.com *
*******************************************************************

[*] Target: vulnweb.com
[*] Searching Google...
[*] Searching Bing...

[*] Emails found:
------------------
support@vulnweb.com
admin@vulnweb.com
info@vulnweb.com

[*] Hosts found:
---------------
testphp.vulnweb.com
www.vulnweb.com
```

**📧 Intelligence Value:**
- **Support Contact:** support@vulnweb.com (customer service target)
- **Administrative:** admin@vulnweb.com (high-value target)
- **General Information:** info@vulnweb.com (general inquiries)
- **Subdomains:** Multiple sites discovered for expanded testing

#### **Subdomain Enumeration**
```bash
# Discover subdomains using multiple sources
sublist3r -d vulnweb.com

# Expected Output:
                 ____        _     _ _     _   _____
                / ___| _   _| |__ | (_)___| |_|___ / _ __
                \___ \| | | | '_ \| | / __| __| |_ \| '__|
                 ___) | |_| | |_) | | \__ \ |_ ___) | |
                |____/ \__,_|_.__/|_|_|___/\__|____/|_|

                # Coded By Ahmed Aboul-Ela - @aboul3la

[-] Enumerating subdomains now for vulnweb.com
[-] Searching now in Baidu..
[-] Searching now in Yahoo..
[-] Searching now in Google..
[-] Searching now in Bing..

[-] Total Unique Subdomains Found: 4
testphp.vulnweb.com
www.vulnweb.com
mail.vulnweb.com
ftp.vulnweb.com
```

**🌐 Attack Surface Expansion:**
- **Test Environment:** testphp.vulnweb.com (vulnerable application)
- **Main Website:** www.vulnweb.com (corporate site)
- **Email Server:** mail.vulnweb.com (email infrastructure)
- **File Transfer:** ftp.vulnweb.com (FTP service - potential weakness)

---

## 🎯 eJPT Exam Success Guide

### **📊 How Important This Is:**
Understanding the importance of information gathering skills for eJPT success:

- **DNS Enumeration:** 70% of reconnaissance questions
- **Web Technology Identification:** 60% of web application scenarios
- **Directory Discovery:** 50% of initial access techniques
- **Email Collection:** 40% of social engineering setups

### **🏆 Commands You Must Know for eJPT:**

#### **Level 1 - Essential (You WILL see this):**
```bash
# DNS basics - FUNDAMENTAL SKILLS
dig target.com ANY +noall +answer
dig target.com A +short
dig target.com MX +short
nslookup target.com

# Web technology identification - CORE SKILL
whatweb http://target.com
curl -I http://target.com

# Directory discovery - CRITICAL TECHNIQUE
dirb http://target.com
```

#### **Level 2 - Important (Good chance you'll see this):**
```bash
# Advanced DNS queries
dig target.com NS +short
whois target.com

# Email harvesting
theharvester -d target.com -b google

# Subdomain discovery
sublist3r -d target.com
```

#### **Level 3 - Advanced (Might appear):**
```bash
# Reverse DNS lookup
dig -x IP_ADDRESS

# Advanced directory search
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -x php,html

# Zone transfer attempts
dig @ns1.target.com target.com AXFR
```

### **🎯 Common eJPT Exam Scenarios:**

#### **Scenario 1: Basic Domain Analysis**
**Given:** Domain name "examtarget.com"
**Your Job:** Find IP address, mail servers, and name servers
**Time Limit:** 3-5 minutes

**How to Approach:**
```bash
# Step 1: Get all DNS records (2 minutes)
dig examtarget.com ANY +noall +answer
# Look for A, MX, NS records

# Step 2: Verify specific records (1-2 minutes)
dig examtarget.com A +short        # IP addresses
dig examtarget.com MX +short       # Mail servers
dig examtarget.com NS +short       # Name servers

# Step 3: Document findings (1 minute)
# Record all discovered information for next steps
```

#### **Scenario 2: Web Application Technology Assessment**
**Given:** Web application at http://192.168.1.100
**Your Job:** Identify web server, programming language, and framework
**Time Limit:** 4-6 minutes

**How to Approach:**
```bash
# Step 1: Technology fingerprinting (2-3 minutes)
whatweb http://192.168.1.100
# Look for server type, PHP/ASP/JSP, database

# Step 2: HTTP header analysis (1-2 minutes)
curl -I http://192.168.1.100
# Check Server header, X-Powered-By, other indicators

# Step 3: Additional verification (1 minute)
curl -s http://192.168.1.100 | grep -i "generator\|framework\|powered"
# Look for meta tags and comments
```

#### **Scenario 3: Directory Structure Discovery**
**Given:** Web server at http://testsite.local
**Your Job:** Find administrative interfaces and hidden directories
**Time Limit:** 5-8 minutes

**How to Approach:**
```bash
# Step 1: Quick directory scan (3-4 minutes)
dirb http://testsite.local
# Note any 200, 301, 403 responses

# Step 2: Check common admin paths (1-2 minutes)
curl -I http://testsite.local/admin
curl -I http://testsite.local/administrator
curl -I http://testsite.local/wp-admin

# Step 3: Document accessible areas (1-2 minutes)
# List all discovered directories and access status
```

### **📝 eJPT Exam Tips:**

#### **⏰ Time Management:**
- **DNS queries:** 1-2 minutes maximum per target
- **Technology identification:** 2-3 minutes per web application
- **Directory discovery:** 3-5 minutes depending on size
- **Documentation:** Always reserve 1-2 minutes for notes

#### **🎯 Mistakes to Avoid:**
1. **Too Much Detail** → Focus on key information, not every DNS record
2. **Wrong Commands** → Practice basic syntax until it's automatic
3. **Missing Documentation** → Always record findings immediately
4. **Time Waste** → Set time limits and stick to them

#### **✅ Signs You're Doing Well:**
- **Quick DNS Results:** Getting answers in under 2 minutes
- **Technology Clarity:** Clear identification of web stack
- **Organized Notes:** Structured documentation of findings
- **Efficient Workflow:** Moving smoothly between reconnaissance steps

### **🔍 Typical Exam Questions:**
1. **"What is the IP address of domain.com?"**
   - Use `dig domain.com A +short`

2. **"What web server is running on the target?"**
   - Use `curl -I http://target` or `whatweb http://target`

3. **"Find the mail servers for example.com"**
   - Use `dig example.com MX +short`

4. **"What directories are accessible on the web server?"**
   - Use `dirb http://target` and document 200/301 responses

---

## ⚠️ Common Problems and Solutions

### **❌ Problem 1: DNS Queries Don't Work**
**What You See:**
```bash
dig google.com
; <<>> DiG 9.18.1 <<>> google.com
;; connection timed out; no servers could be reached
```

**How to Fix:**
```bash
# Step 1: Check network connectivity
ping 8.8.8.8
# Should get replies if internet works

# Step 2: Test different DNS servers
dig @8.8.8.8 google.com A
dig @1.1.1.1 google.com A
# Use public DNS servers directly

# Step 3: Check local DNS configuration
cat /etc/resolv.conf
# Verify nameserver entries exist

# Solution commands:
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
echo "nameserver 1.1.1.1" | sudo tee -a /etc/resolv.conf
```

**Solutions:**
- Test network connectivity before DNS queries
- Use public DNS servers (8.8.8.8, 1.1.1.1) when local DNS fails
- Check firewall settings aren't blocking DNS traffic
- Restart network services if configuration changes don't work

---

### **❌ Problem 2: Web Tools Give Wrong Results**
**What You See:**
```bash
whatweb http://target.com
ERROR: no response for http://target.com
```

**How to Fix:**
```bash
# Step 1: Test basic connectivity
curl -I http://target.com
# Check if site responds at all

# Step 2: Try different protocols and paths
curl -I https://target.com
curl -I http://www.target.com
# Test HTTPS and www variations

# Step 3: Check for redirects or blocks
curl -L -v http://target.com
# Follow redirects with verbose output

# Alternative tools:
nmap -p 80,443 target.com
# Verify ports are open
```

**Solutions:**
- Always test basic connectivity before using specialized tools
- Try both HTTP and HTTPS protocols
- Check for geographic blocking or rate limiting
- Use verbose modes to understand what's happening

---

### **❌ Problem 3: Directory Discovery Takes Too Long**
**What You See:**
- Dirb runs for hours without finishing
- Results come very slowly
- Connection timeouts or errors

**How to Fix:**
```bash
# Step 1: Use smaller wordlists for speed
dirb http://target.com /usr/share/dirb/wordlists/small.txt

# Step 2: Limit scan scope
dirb http://target.com -z 1000
# Add 1 second delay between requests

# Step 3: Use faster tools
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -t 20
# Use 20 threads for faster scanning

# Quick alternatives:
curl -I http://target.com/admin
curl -I http://target.com/backup
curl -I http://target.com/config
# Manually test common directories
```

**Solutions:**
- Start with small wordlists for quick results
- Use threading carefully to avoid overwhelming target
- Test common directories manually first
- Set reasonable timeouts for exam time constraints

---

### **❌ Problem 4: Tools Not Installed or Not Working**
**What You See:**
```bash
command not found: theharvester
command not found: sublist3r
```

**How to Fix:**
```bash
# Step 1: Check what's available
which dig nslookup whois curl
# Use basic tools that are always installed

# Step 2: Install missing tools quickly
sudo apt update
sudo apt install theharvester sublist3r -y

# Step 3: Use alternatives if installation fails
# Instead of theharvester:
curl -s "https://www.google.com/search?q=site:target.com+email" | grep -o "[a-zA-Z0-9._%+-]*@[a-zA-Z0-9.-]*\.[a-zA-Z]{2,}"

# Instead of sublist3r:
dig target.com
dig www.target.com
dig mail.target.com
dig ftp.target.com
```

**Solutions:**
- Master basic tools (dig, curl, nslookup) that are always available
- Have backup manual methods for when tools fail
- Practice installation commands for common tools
- Know alternative approaches for each reconnaissance task

---

## 🔗 Using Multiple Tools Together

### **🎯 Complete Reconnaissance Workflow:**

This comprehensive approach combines multiple tools for thorough information gathering.

#### **Phase 1: Domain Intelligence (5 minutes)**
```bash
# Basic domain information
dig target.com ANY +noall +answer > dns_records.txt
whois target.com > whois_info.txt

# Parse key information
grep -E "(A|MX|NS|CNAME)" dns_records.txt
grep -E "(Registrar|Creation Date|Expiry)" whois_info.txt

# Test reverse DNS
for ip in $(dig target.com A +short); do
    dig -x $ip +short
done
```

#### **Phase 2: Web Application Analysis (7 minutes)**
```bash
# Technology identification
whatweb http://target.com > tech_analysis.txt
curl -I http://target.com > http_headers.txt
curl -I https://target.com > https_headers.txt

# Extract key details
grep -E "(Server|X-Powered-By|X-AspNet-Version)" *_headers.txt
grep -E "(WordPress|Joomla|Drupal)" tech_analysis.txt

# Quick directory check
for dir in admin administrator backup config wp-admin; do
    echo "Testing /$dir: $(curl -I http://target.com/$dir 2>/dev/null | head -1)"
done
```

#### **Phase 3: Intelligence Collection (8 minutes)**
```bash
# Email and subdomain discovery
theharvester -d target.com -b google,bing -l 100 > emails.txt
sublist3r -d target.com > subdomains.txt

# Clean and organize results
grep -E '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' emails.txt | sort | uniq > clean_emails.txt
cat subdomains.txt | grep -v "^\[-\]" | sort | uniq > clean_subdomains.txt

# Test discovered subdomains
for subdomain in $(cat clean_subdomains.txt); do
    echo "Testing $subdomain: $(curl -I http://$subdomain 2>/dev/null | head -1)"
done
```

### **🔧 Quick Automation Script:**

For efficient reconnaissance during exams or professional assessments:

```bash
#!/bin/bash
# quick_recon.sh - Fast reconnaissance automation

TARGET=$1
OUTPUT_DIR="recon_$TARGET"

# Validate input
if [ -z "$1" ]; then
    echo "Usage: $0 <target_domain>"
    echo "Example: $0 example.com"
    exit 1
fi

# Create output directory
mkdir -p $OUTPUT_DIR
cd $OUTPUT_DIR

echo "[+] Starting reconnaissance for $TARGET"
echo "[+] Results will be saved to $OUTPUT_DIR/"

# DNS enumeration (2 minutes)
echo "[+] DNS enumeration..."
dig $TARGET ANY +noall +answer > dns_all.txt
dig $TARGET A +short > ip_addresses.txt
dig $TARGET MX +short > mail_servers.txt
dig $TARGET NS +short > name_servers.txt

# Web analysis (3 minutes)
echo "[+] Web technology analysis..."
whatweb http://$TARGET > web_tech.txt 2>/dev/null
curl -I http://$TARGET > http_headers.txt 2>/dev/null
curl -I https://$TARGET > https_headers.txt 2>/dev/null

# Quick directory check (2 minutes)
echo "[+] Directory discovery..."
echo "Directory scan results:" > directories.txt
for dir in admin administrator wp-admin backup config phpinfo; do
    result=$(curl -I http://$TARGET/$dir 2>/dev/null | head -1)
    echo "/$dir: $result" >> directories.txt
done

# Email collection (3 minutes)
echo "[+] Email harvesting..."
theharvester -d $TARGET -b google -l 50 > emails_raw.txt 2>/dev/null
grep -E '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' emails_raw.txt | sort | uniq > emails.txt

# Generate summary report
echo "[+] Generating summary..."
cat > summary.txt << EOF
Reconnaissance Summary for $TARGET
Generated: $(date)

IP Addresses Found:
$(cat ip_addresses.txt)

Mail Servers:
$(cat mail_servers.txt)

Name Servers:
$(cat name_servers.txt)

Web Technology:
$(grep -E "(Server|X-Powered-By)" *_headers.txt 2>/dev/null)

Email Addresses:
$(cat emails.txt)

Accessible Directories:
$(grep "200 OK" directories.txt)

Total Files Created: $(ls -1 | wc -l)
EOF

echo "[+] Reconnaissance complete!"
echo "[+] Summary:"
echo "    - IP addresses: $(wc -l < ip_addresses.txt)"
echo "    - Email addresses: $(wc -l < emails.txt)"
echo "    - Check $OUTPUT_DIR/summary.txt for full results"
```

**Usage:**
```bash
# Make script executable
chmod +x quick_recon.sh

# Run reconnaissance
./quick_recon.sh target.com

# View results
cat recon_target.com/summary.txt
```

---

## 📊 Quick Command Reference

### **🚀 Essential Commands Summary:**

#### **DNS Operations:**
```bash
dig target.com ANY +noall +answer           # All DNS records
dig target.com A +short                     # IP addresses only
dig target.com MX +short                    # Mail servers only
dig target.com NS +short                    # Name servers only
nslookup target.com                         # Alternative DNS lookup
whois target.com                            # Domain registration info
dig -x IP_ADDRESS                           # Reverse DNS lookup
```

#### **Web Analysis:**
```bash
whatweb http://target.com                   # Technology identification
curl -I http://target.com                   # HTTP headers
curl -s http://target.com | grep -i "powered"  # Framework detection
dirb http://target.com                      # Directory discovery
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt  # Fast directory scan
```

#### **Information Collection:**
```bash
theharvester -d target.com -b google        # Email harvesting
sublist3r -d target.com                     # Subdomain discovery
fierce -dns target.com                      # DNS enumeration
```

### **💡 Efficiency Tips:**

#### **Command Shortcuts:**
```bash
# Quick DNS check
alias dnscheck='dig $1 ANY +noall +answer'
dnscheck google.com

# Fast web analysis
alias webcheck='whatweb $1 && curl -I $1'
webcheck http://target.com

# Email collection shortcut
alias emailhunt='theharvester -d $1 -b google,bing -l 100'
emailhunt target.com
```

#### **One-Line Combinations:**
```bash
# Complete domain analysis
dig target.com ANY +noall +answer && whois target.com | grep -E "(Registrar|Creation|Expiry)"

# Web technology stack
whatweb http://target.com && curl -I http://target.com | grep -E "(Server|X-Powered-By)"

# Email and subdomain combo
theharvester -d target.com -b google -l 50 && sublist3r -d target.com
```

---

## 📝 Writing Professional Reports

### **📋 Quick Summary Template:**
```markdown
## Information Gathering Report

**Target:** [target_domain]
**Assessment Date:** [date]
**Assessment Type:** Passive Reconnaissance
**Tester:** [your_name]

### DNS Intelligence:
- **Primary IP:** [ip_address]
- **Mail Servers:** [mx_records]
- **Name Servers:** [ns_records]
- **Additional Records:** [other_findings]

### Web Application Analysis:
- **Web Server:** [server_type_and_version]
- **Programming Language:** [php/asp/jsp_version]
- **Framework:** [wordpress/joomla/custom]
- **Database:** [mysql/mssql/oracle_if_detected]

### Directory Structure:
| Directory | Status Code | Access Level | Security Risk |
|-----------|-------------|--------------|---------------|
| /admin | 401 | Restricted | Medium |
| /backup | 403 | Forbidden | High |
| /config | 404 | Not Found | Low |

### Email Addresses Discovered:
- admin@target.com (Administrative contact)
- support@target.com (Customer service)
- info@target.com (General inquiries)

### Subdomains Found:
- www.target.com (Main website)
- mail.target.com (Email server)
- ftp.target.com (File transfer)

### Security Observations:
- [List any security headers missing]
- [Note any outdated software versions]
- [Identify potential attack vectors]

### Recommendations:
1. Review directory access controls
2. Update outdated software components
3. Implement security headers
4. Monitor for subdomain proliferation
```

### **🔧 Detailed Technical Report:**
```markdown
## Technical Reconnaissance Details

### Commands Executed:
```bash
# DNS enumeration
dig target.com ANY +noall +answer
dig target.com A +short
dig target.com MX +short
whois target.com

# Web analysis
whatweb http://target.com
curl -I http://target.com
dirb http://target.com

# Intelligence gathering
theharvester -d target.com -b google
sublist3r -d target.com
```

### Detailed Findings:

#### DNS Records Analysis:
```
target.com.    3600    IN    A       192.0.2.100
target.com.    3600    IN    MX      10 mail.target.com.
target.com.    3600    IN    NS      ns1.target.com.
target.com.    3600    IN    NS      ns2.target.com.
```

#### HTTP Response Headers:
```
HTTP/1.1 200 OK
Server: nginx/1.18.0
X-Powered-By: PHP/7.4.3
Content-Type: text/html; charset=UTF-8
```

#### Technology Stack Summary:
- **Infrastructure:** nginx web server with PHP backend
- **Version Information:** Moderately current versions detected
- **Security Posture:** Basic protection mechanisms in place
- **Attack Surface:** Standard web application exposure
```

---

## 🎓 Quick Study Guide and Memory Aids

### **🧠 Memory Card for eJPT:**
```bash
# Essential commands to memorize for the exam
dig target.com ANY +noall +answer             # All DNS records
dig target.com A +short                       # Just IP addresses
whatweb http://target.com                     # Web technologies
curl -I http://target.com                     # HTTP headers
dirb http://target.com                        # Find directories
theharvester -d target.com -b google          # Collect emails
nslookup target.com                           # Alternative DNS
whois target.com                              # Domain info
```

### **💡 Easy Ways to Remember:**
- **DIG** = **D**iscover **I**P and **G**eneral DNS info
- **WHOIS** = **WHO** **I**s responsible for this **S**ite
- **WHATWEB** = **WHAT** **WEB** technologies are used
- **DIRB** = **DIR**ectory **B**ruteforce
- **HARVESTER** = **HARVEST** email addresses **E**verywhere **R**eachable

### **🎯 eJPT Exam Checklist:**
- [ ] Can perform basic DNS queries with dig
- [ ] Know how to identify web server technologies
- [ ] Can discover hidden directories
- [ ] Understand how to collect email addresses
- [ ] Can analyze HTTP headers for information
- [ ] Know how to find subdomains

### **⏰ Time Management for Exam:**
- **DNS queries:** 2-3 minutes maximum
- **Web analysis:** 3-4 minutes per target
- **Directory discovery:** 4-5 minutes (use small wordlists)
- **Email collection:** 2-3 minutes
- **Documentation:** 1-2 minutes per target

---

## 🔗 Learning More

### **📖 Official Resources:**
- **Dig Manual:** `man dig` (comprehensive DNS query guide)
- **RFC Documentation:** DNS standards and protocols
- **OWASP Testing Guide:** Information gathering methodologies

### **🎥 Video Learning:**
- Search for "DNS enumeration for penetration testing"
- "eJPT information gathering tutorials"
- "OSINT techniques for cybersecurity"

### **📚 Books to Read:**
- "The Art of Intelligence Gathering" by Robert Laird
- "Open Source Intelligence Techniques" by Michael Bazzell
- "Reconnaissance for Penetration Testers" by various SANS authors

### **🏃‍♂️ Practice Labs:**
- **TryHackMe:** OSINT and reconnaissance rooms
- **HackTheBox:** Information gathering challenges
- **VulnHub:** Download VMs for practice
- **OverTheWire:** Bandit wargames for command line practice

#### **Local Practice Setup:**
```bash
# Set up local DNS server for practice
sudo apt install bind9 bind9utils
# Configure test domains for enumeration practice

# Create test web applications
sudo apt install apache2 php
# Set up vulnerable web apps for directory discovery

# Practice with real targets (legally)
# Use testphp.vulnweb.com
# Use demo.ine.local (if available)
# Use intentionally vulnerable sites
```

### **🔧 Related Tools to Master:**
- **Nmap:** Network discovery and service enumeration
- **Gobuster:** Fast directory and file brute-forcing
- **Amass:** Advanced subdomain enumeration
- **Recon-ng:** Reconnaissance framework
- **Maltego:** Visual intelligence gathering

---

## 🆘 Quick Help

### **When Commands Don't Work:**
1. **Check spelling:** `dig google.com` not `dig goggle.com`
2. **Verify network:** `ping 8.8.8.8`
3. **Test DNS servers:** `dig @8.8.8.8 google.com`
4. **Check permissions:** Some tools need sudo

### **Emergency Troubleshooting:**
```bash
# Network connectivity test
ping -c 3 8.8.8.8 && echo "Internet OK" || echo "Network problem"

# DNS resolution test
nslookup google.com 8.8.8.8

# Web connectivity test
curl -I https://google.com

# Tool availability check
which dig nslookup whois curl whatweb dirb theharvester

# Alternative DNS servers
dig @1.1.1.1 target.com    # Cloudflare DNS
dig @208.67.222.222 target.com    # OpenDNS
```

### **Getting Help:**
- **Command help:** `dig --help`, `curl --help`
- **Manual pages:** `man dig`, `man curl`
- **Online communities:** Reddit r/AskNetsec, Discord servers
- **Study groups:** Join eJPT preparation groups

---

## 📞 Final Notes for eJPT Success

Remember: Information gathering is the foundation of penetration testing. In the eJPT exam:
- Master the basic DNS commands (dig, nslookup)
- Know how to identify web technologies quickly
- Practice directory discovery with time limits
- Document everything you find systematically
- Use multiple tools to verify important findings

The key to success is consistent practice with real targets and understanding what each piece of information tells you about the target's security posture. Focus on the practical application of these tools rather than memorizing every possible option.

This comprehensive guide provides everything you need to master information gathering for both penetration testing and eJPT exam success. Regular practice with the commands and techniques outlined here will build the confidence and efficiency needed for professional security assessments.
