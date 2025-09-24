# 🌐 HTTP Enumeration - Complete Web Service Analysis

Comprehensive guide for enumerating HTTP/HTTPS services to identify web technologies, directories, files, and potential vulnerabilities.
**Location:** `05-service-enumeration/http-enumeration-complete.md`

## 🎯 What is HTTP Enumeration?

HTTP enumeration is the process of gathering detailed information about web services running on target systems. This includes identifying web server software, versions, directory structures, hidden files, authentication mechanisms, and potential entry points for further exploitation.

HTTP enumeration is critical for understanding the attack surface of web applications and forms the foundation for web application penetration testing. Key capabilities include:
- Web server fingerprinting and version detection
- Directory and file discovery
- Technology stack identification
- Authentication mechanism analysis
- Configuration file discovery
- Administrative interface location

## 📦 Installation and Setup

### Prerequisites:
- Kali Linux with Metasploit Framework
- Basic understanding of HTTP protocol
- Target web service accessibility

### Verification:
```bash
# Verify Metasploit installation
msfconsole --version
# Expected output: Framework Version information

# Check connectivity to target
ping -c 3 target_ip
# Expected output: Successful ping responses
```

### Initial Configuration:
```bash
# Start Metasploit console
msfconsole -q

# Verify auxiliary HTTP modules are available
search auxiliary/scanner/http
```

## 🔧 Basic Usage and Syntax

### Basic Workflow:
1. **Connectivity Test:** Verify target is reachable via HTTP/HTTPS
2. **Service Detection:** Identify web server and technologies
3. **Directory Discovery:** Find hidden directories and files
4. **Content Analysis:** Examine discovered resources
5. **Authentication Testing:** Identify login mechanisms
6. **User Enumeration:** Discover valid usernames if applicable

### Command Structure:
```bash
# Basic Metasploit HTTP enumeration workflow
use auxiliary/scanner/http/[module_name]
set RHOSTS target_ip
set [additional_options] values
run
```

## ⚙️ Command Line Options

### Core HTTP Modules:
| Module | Purpose | Primary Use Case |
|--------|---------|------------------|
| `http_version` | Server version detection | Initial fingerprinting |
| `http_header` | HTTP header analysis | Technology identification |
| `robots_txt` | Robots.txt discovery | Directory enumeration prep |
| `dir_scanner` | Directory brute forcing | Hidden path discovery |
| `dir_listing` | Directory listing check | Information disclosure |
| `files_dir` | File enumeration | Sensitive file discovery |
| `http_login` | Login form discovery | Authentication testing |
| `apache_userdir_enum` | User directory enumeration | Username discovery |

### Common Module Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `RHOSTS` | Target IP/range | `set RHOSTS 192.168.1.100` |
| `RPORT` | Target port | `set RPORT 8080` |
| `SSL` | Enable HTTPS | `set SSL true` |
| `TARGETURI` | Specific URI path | `set TARGETURI /admin` |
| `PATH` | Directory path | `set PATH /data` |
| `DICTIONARY` | Custom wordlist | `set DICTIONARY /path/to/wordlist.txt` |
| `VERBOSE` | Detailed output | `set VERBOSE false` |

### File and Directory Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `FILENAME` | Specific filename | `set FILENAME config.php` |
| `FILEDATA` | File content for upload | `set FILEDATA "test content"` |
| `ACTION` | HTTP method | `set ACTION DELETE` |
| `USER_FILE` | Username wordlist | `set USER_FILE /usr/share/wordlists/users.txt` |

## 🧪 Real Lab Examples

### Example 1: Complete Apache Server Enumeration
```bash
# Phase 1: Basic connectivity test
ping -c 5 victim-1
# Output: 5 packets transmitted, 5 received, 0% packet loss

# Phase 2: Start Metasploit and enumerate HTTP version
msfconsole -q
use auxiliary/scanner/http/http_version
set RHOSTS victim-1
run
# Output: [+] 192.74.12.3:80 Apache/2.4.18 (Ubuntu)

# Phase 3: Analyze HTTP headers
use auxiliary/scanner/http/http_header
set RHOSTS victim-1
run
# Output: 
# [+] 192.74.12.3:80 : CONTENT-TYPE: text/html
# [+] 192.74.12.3:80 : LAST-MODIFIED: Wed, 27 Feb 2019 04:21:01 GMT
# [+] 192.74.12.3:80 : SERVER: Apache/2.4.18 (Ubuntu)

# Phase 4: Check for restricted content discovery
use auxiliary/scanner/http/http_header
set RHOSTS victim-1
set TARGETURI /secure
run
# Output: [+] 192.74.12.3:80 : WWW-AUTHENTICATE: Basic realm="Restricted Content"
```

### Example 2: Directory and File Discovery
```bash
# Step 1: Check robots.txt for directory hints
use auxiliary/scanner/http/robots_txt
set RHOSTS victim-1
run
# Output: 
# [+] [192.74.12.3] /robots.txt found
# [+] Contents of Robots.txt:
# # robots.txt for attackdefense
# User-agent: test
# # Directories
# Allow: /webmail
# User-agent: *
# # Directories  
# Disallow: /data
# Disallow: /secure

# Step 2: Perform directory brute force
use auxiliary/scanner/http/brute_dirs
set RHOSTS victim-1
run
# Output: 
# [+] Using code '404' as not found.
# [+] Found http://victim-1:80/doc/ 200
# [+] Found http://victim-1:80/pro/ 200

# Step 3: Advanced directory scanning with custom wordlist
use auxiliary/scanner/http/dir_scanner
set RHOSTS victim-1
set DICTIONARY /usr/share/metasploit-framework/data/wordlists/directory.txt
run
# Output: Multiple directories discovered including /data, /webmail, /secure, etc.
```

### Example 3: File Manipulation and Authentication Testing
```bash
# Step 1: Enumerate specific files
use auxiliary/scanner/http/files_dir
set RHOSTS victim-1
set VERBOSE false
run
# Output: 
# [+] Found http://victim-1:80/index.html 200
# [+] Found http://victim-1:80/test.php 200
# [+] File discovery results showing various file extensions

# Step 2: File upload testing
use auxiliary/scanner/http/http_put
set RHOSTS victim-1
set PATH /data
set FILENAME test.txt
set FILEDATA "Welcome To AttackDefense"
run
# Output: [+] File uploaded: http://192.74.12.3:80/data/test.txt

# Step 3: Verify uploaded file
wget http://victim-1:80/data/test.txt
cat test.txt
# Output: Welcome To AttackDefense

# Step 4: File deletion testing
use auxiliary/scanner/http/http_put
set RHOSTS victim-1
set PATH /data
set FILENAME test.txt
set ACTION DELETE
run
# Output: [+] File deleted: http://192.74.12.3:80/data/test.txt

# Step 5: Verify deletion
wget http://victim-1:80/data/test.txt
# Output: HTTP request sent, awaiting response... 404 Not Found
```

### Example 4: Authentication and User Enumeration
```bash
# Step 1: Login form discovery
use auxiliary/scanner/http/http_login
set RHOSTS victim-1
set AUTH_URI /secure/
set VERBOSE false
run
# Output: 
# [+] Attempting to login to http://victim-1:80/secure/ (192.236.2.3)
# [+] 192.236.2.3:80 - Success: 'bob:123321'

# Step 2: User directory enumeration
use auxiliary/scanner/http/apache_userdir_enum
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set RHOSTS victim-1
set VERBOSE false
run
# Output: 
# [+] http://192.74.12.3/ - Apache UserDir: 'root' found
# [+] http://192.74.12.3/ - Apache UserDir: 'backup' found
# [+] http://192.74.12.3/ - Apache UserDir: 'daemon' found
# [+] Users found: backup, bin, daemon, games, gnats, irc, list, lp, mail, man, news, nobody, proxy, rooty, sync, sys, uucp
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **HTTP Service Identification** (25% of web enumeration tasks)
- **Directory Discovery** (30% of enumeration scenarios)
- **File Upload/Download Testing** (20% of web application tests)
- **Basic Authentication Testing** (15% of access control tests)
- **Technology Stack Recognition** (10% of information gathering)

### Critical Commands to Master:
```bash
# Must-know for eJPT exam
use auxiliary/scanner/http/http_version    # Always start here for web services
use auxiliary/scanner/http/dir_scanner     # Essential for finding hidden content
use auxiliary/scanner/http/robots_txt      # Quick wins for directory discovery
use auxiliary/scanner/http/http_header     # Technology identification
use auxiliary/scanner/http/files_dir       # Sensitive file discovery
```

### eJPT Exam Scenarios:
1. **Web Service Discovery:** Identify running web services and their versions
   - Required skills: HTTP version detection, header analysis
   - Expected commands: `http_version`, `http_header`
   - Success criteria: Web server type and version identified

2. **Hidden Content Discovery:** Find administrative interfaces and sensitive files
   - Required skills: Directory enumeration, robots.txt analysis
   - Expected commands: `dir_scanner`, `robots_txt`, `files_dir`
   - Success criteria: Administrative panels or config files located

3. **File Upload Exploitation:** Test for insecure file upload capabilities
   - Required skills: HTTP PUT method testing, file manipulation
   - Expected commands: `http_put` with various payloads
   - Success criteria: Successful file upload and verification

4. **Authentication Bypass:** Identify weak authentication mechanisms
   - Required skills: Login form discovery, basic credential testing
   - Expected commands: `http_login`, credential list testing
   - Success criteria: Valid credentials discovered or bypass identified

### Exam Tips and Tricks:
- **Start with robots.txt:** Always check for directory hints before brute forcing
- **Use default wordlists:** Metasploit's built-in wordlists are sufficient for eJPT
- **Document everything:** Screenshot all discovered directories and files
- **Test file operations:** Always verify file uploads/downloads work as expected
- **Check common paths:** /admin, /manager, /phpmyadmin are frequent targets

### Common eJPT Questions:
- What web server software and version is running on the target?
- What directories are disclosed in the robots.txt file?
- Can you upload files to the web server? If so, to which directory?
- What authentication mechanism is used for protected directories?

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Connection Timeouts During Enumeration
**Problem:** Modules hang or timeout when connecting to target web services
**Cause:** Network connectivity issues, firewall blocking, or service unavailability
**Solution:**
```bash
# Verify basic connectivity first
ping -c 3 target_ip

# Test HTTP connectivity manually
curl -I http://target_ip:port

# Adjust timeout settings in Metasploit
set HttpClientTimeout 30
set HttpReadTimeout 30
```

### Issue 2: SSL/TLS Certificate Errors
**Problem:** HTTPS enumeration fails due to certificate validation
**Solution:**
```bash
# Enable SSL and ignore certificate validation
set SSL true
set HttpClientVerifySSL false

# Alternative: Test with curl first
curl -k -I https://target_ip
```

### Issue 3: Rate Limiting and Detection Avoidance
**Problem:** Target implements rate limiting or intrusion detection
**Prevention:**
```bash
# Slow down scanning to avoid detection
set DELAY 2

# Use minimal verbosity to reduce noise
set VERBOSE false

# Test with smaller wordlists first
set DICTIONARY /usr/share/metasploit-framework/data/wordlists/short_list.txt
```

### Issue 4: Metasploit Module Loading Issues
**Problem:** HTTP scanner modules fail to load or execute
**Optimization:**
```bash
# Update Metasploit framework
msfupdate

# Reload modules if needed
reload_all

# Check module dependencies
info auxiliary/scanner/http/module_name
```

## 🔗 Integration with Other Tools

### Primary Integration: Nmap → HTTP Enumeration → Web Application Testing
```bash
# Complete workflow showing tool integration
nmap -sV -p80,443,8080 target_ip | grep "open"

# Feed discovered web ports into Metasploit
msfconsole -q
use auxiliary/scanner/http/http_version
set RHOSTS target_ip
set RPORT discovered_port
run

# Use results for targeted web application testing
```

### Secondary Integration: HTTP Enumeration → Manual Verification
```bash
# Export discovered URLs for manual testing
# Results from dir_scanner can be imported into:
burpsuite      # For detailed web application analysis
dirb           # Alternative directory enumeration
gobuster       # High-speed directory/file brute forcer
```

### Advanced Workflows:
```bash
# Multi-stage enumeration approach
# Stage 1: Service identification
use auxiliary/scanner/http/http_version

# Stage 2: Content discovery  
use auxiliary/scanner/http/robots_txt
use auxiliary/scanner/http/dir_scanner

# Stage 3: Vulnerability assessment
use auxiliary/scanner/http/files_dir
use auxiliary/scanner/http/http_put
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** Metasploit module outputs showing discovered services and directories
2. **Command Outputs:** All successful enumeration results with timestamps
3. **File Samples:** Downloaded configuration files or sensitive documents
4. **URL Lists:** Complete inventory of discovered web resources

### Report Template Structure:
```markdown
## HTTP Enumeration Results

### Target Information
- Target: victim-1 (192.74.12.3)
- Ports: 80/HTTP, 443/HTTPS
- Date/Time: 2024-08-27 13:10:00
- Tools: Metasploit Framework v6.x

### Commands Executed
```bash
# Service identification
use auxiliary/scanner/http/http_version
set RHOSTS victim-1
run

# Directory enumeration
use auxiliary/scanner/http/dir_scanner
set RHOSTS victim-1
run
```

### Key Findings
- **Web Server:** Apache/2.4.18 (Ubuntu) running on port 80
- **Hidden Directories:** /data, /secure, /webmail, /admin discovered
- **Sensitive Files:** robots.txt reveals restricted directories
- **File Upload:** PUT method enabled in /data directory
- **Authentication:** Basic authentication on /secure directory

### Security Implications
- Information disclosure via robots.txt and directory listings
- Potential file upload vulnerability in /data directory
- Weak authentication mechanisms may allow credential attacks

### Recommendations
- Implement proper access controls for sensitive directories
- Disable unnecessary HTTP methods (PUT, DELETE)
- Remove or secure robots.txt file
- Implement strong authentication mechanisms
```

### Automation Scripts:
```bash
# Script for automated HTTP enumeration documentation
#!/bin/bash
TARGET=$1
OUTPUT_FILE="http_enum_${TARGET}_$(date +%Y%m%d_%H%M%S).txt"

echo "HTTP Enumeration Report for $TARGET" > $OUTPUT_FILE
echo "Generated: $(date)" >> $OUTPUT_FILE
echo "========================================" >> $OUTPUT_FILE

# Log all enumeration commands and outputs
msfconsole -q -x "
use auxiliary/scanner/http/http_version;
set RHOSTS $TARGET;
run;
exit" >> $OUTPUT_FILE 2>&1
```

## 📚 Additional Resources

### Official Documentation:
- Metasploit Framework: https://www.metasploit.com/
- Apache HTTP Server: https://httpd.apache.org/docs/
- HTTP RFC Specifications: https://tools.ietf.org/html/rfc7231

### Learning Resources:
- OWASP Web Security Testing Guide: Comprehensive web application testing methodology
- Metasploit Unleashed: Free online course covering framework usage
- Web Application Hacker's Handbook: Essential reading for web application security

### Community Resources:
- Metasploit Community: https://community.rapid7.com/
- OWASP Community: https://owasp.org/
- Offensive Security Community: https://www.offensive-security.com/community/

### Related Tools:
- **Burp Suite:** Advanced web application security testing platform
- **OWASP ZAP:** Free alternative to Burp Suite with similar capabilities  
- **Nikto:** Web server scanner for comprehensive vulnerability assessment
- **Dirb:** Alternative directory and file brute forcing tool
- **Gobuster:** Fast directory/file enumeration tool written in Go
