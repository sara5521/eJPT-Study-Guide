# 🔧 Web Directory Enumeration - Comprehensive Web Path Discovery

Web directory enumeration involves discovering hidden directories, files, and endpoints on web applications using various tools and techniques.
**Location:** `05-service-enumeration/web-directory-enumeration.md`

## 🎯 What is Web Directory Enumeration?

Web directory enumeration is the process of discovering hidden or unlinked directories and files on web servers. Key capabilities include:
- Directory and file discovery using wordlists
- Common web application path identification
- Administrative interface discovery
- Backup file and configuration file detection
- API endpoint enumeration
- Technology-specific path discovery

## 📦 Installation and Setup

### Prerequisites:
- Web server target with HTTP/HTTPS services
- Wordlists for directory/file names
- Basic understanding of web application structure

### Installation:
```bash
# Install common enumeration tools
apt update && apt install gobuster dirb dirbuster wfuzz ffuf

# Install wordlists
apt install wordlists
locate dirb
# Expected: /usr/share/dirb/wordlists/

# Verify installations
gobuster version
dirb
```

### Wordlist Preparation:
```bash
# Common wordlist locations
ls /usr/share/wordlists/dirb/
ls /usr/share/wordlists/dirbuster/
ls /usr/share/seclists/Discovery/Web-Content/

# Most useful wordlists for eJPT
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirb/big.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

## 🔧 Basic Usage and Syntax

### Basic Workflow:
1. **Target Identification:** Identify web services from port scans
2. **Tool Selection:** Choose appropriate enumeration tool
3. **Wordlist Selection:** Select relevant wordlists
4. **Enumeration:** Execute directory discovery
5. **Analysis:** Review discovered paths and files

### Command Structure:
```bash
# Basic enumeration (extending from lab context)
# After discovering HTTP service on port 80
curl demo1.ine.local  # Initial reconnaissance
gobuster dir -u http://demo1.ine.local -w /usr/share/wordlists/dirb/common.txt
```

## ⚙️ Command Line Options

### Gobuster Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `dir` | Directory enumeration mode | `gobuster dir -u target -w wordlist` |
| `-u URL` | Target URL | `gobuster dir -u http://target -w wordlist` |
| `-w wordlist` | Wordlist file | `gobuster dir -u target -w /usr/share/wordlists/dirb/common.txt` |
| `-x extensions` | File extensions to search | `gobuster dir -u target -w wordlist -x php,txt,html` |

### Dirb Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-r` | Non-recursive scanning | `dirb http://target wordlist -r` |
| `-w` | Non-interactive mode | `dirb http://target wordlist -w` |
| `-X extensions` | File extensions | `dirb http://target wordlist -X .php,.txt` |
| `-o filename` | Output to file | `dirb http://target wordlist -o results.txt` |

### Ffuf Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-u URL` | Target URL with FUZZ keyword | `ffuf -u http://target/FUZZ -w wordlist` |
| `-w wordlist` | Wordlist file | `ffuf -u http://target/FUZZ -w common.txt` |
| `-e extensions` | File extensions | `ffuf -u http://target/FUZZ -w wordlist -e .php,.txt` |
| `-mc codes` | Match HTTP status codes | `ffuf -u target/FUZZ -w wordlist -mc 200,301,302` |

## 🧪 Real Lab Examples

### Example 1: Basic Directory Discovery (Building on Lab Context)
```bash
# Based on lab showing HTTP service discovery
# After nmap revealed port 80 open with HTTP service

# Step 1: Initial web reconnaissance
curl -I demo1.ine.local
# Output: Server headers and technology information

# Step 2: Directory enumeration with gobuster
gobuster dir -u http://demo1.ine.local -w /usr/share/wordlists/dirb/common.txt
# Expected output:
# /admin               (Status: 301)
# /backup              (Status: 200)
# /upload              (Status: 200)
# /config              (Status: 403)

# Step 3: Check discovered directories
curl http://demo1.ine.local/upload
# Output: File upload interface (as mentioned in XODA context)
```

### Example 2: File Extension Enumeration
```bash
# Enumerate common web files on discovered paths
gobuster dir -u http://demo1.ine.local -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,xml,js

# Expected discoveries:
# /config.php          (Status: 200)
# /readme.txt          (Status: 200)  
# /index.html          (Status: 200)
# /upload.php          (Status: 200) # Key for XODA exploitation

# Examine key files
curl http://demo1.ine.local/config.php
curl http://demo1.ine.local/readme.txt
```

### Example 3: Advanced Enumeration with Multiple Tools
```bash
# Multi-tool approach for comprehensive coverage
# Tool 1: Dirb for broad discovery
dirb http://demo1.ine.local /usr/share/wordlists/dirb/big.txt -o dirb_results.txt

# Tool 2: Gobuster for fast enumeration  
gobuster dir -u http://demo1.ine.local -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50

# Tool 3: Ffuf for custom patterns
ffuf -u http://demo1.ine.local/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -c
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **Directory discovery (40%)** - Finding hidden admin panels and upload forms
- **File enumeration (30%)** - Locating configuration files and backups
- **Upload form identification (20%)** - Critical for file upload attacks
- **Technology fingerprinting (10%)** - Understanding web application stack

### Critical Commands to Master:
```bash
# Must-know commands for exam
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt           # Basic directory scan
gobuster dir -u http://target -w wordlist -x php,txt,html,xml                  # File extension scan
dirb http://target /usr/share/wordlists/dirb/common.txt                        # Alternative enumeration
ffuf -u http://target/FUZZ -w wordlist -mc 200,301,302 -c                     # Fast enumeration
```

### eJPT Exam Scenarios:
1. **Web Application Upload Discovery:** Find file upload functionality for exploitation
   - Required skills: Directory enumeration, form identification
   - Expected commands: `gobuster` with common wordlists, manual verification
   - Success criteria: Locate upload.php or similar upload interfaces

2. **Administrative Interface Discovery:** Find admin panels and configuration areas
   - Required skills: Administrative path enumeration, access verification
   - Expected commands: Admin-specific wordlists, status code analysis
   - Success criteria: Discover /admin/, /config/, or similar administrative paths

### Exam Tips and Tricks:
- **Start with common.txt:** Most efficient wordlist for exam time constraints
- **Check status codes:** 200, 301, 302, 403 all indicate discovered content
- **Follow redirects:** 301/302 responses often lead to valuable content
- **Manual verification:** Always verify enumeration results manually

### Common eJPT Questions:
- Discover file upload functionality on web application
- Find administrative interfaces for privilege escalation
- Locate configuration files containing sensitive information

## ⚠️ Common Issues & Troubleshooting

### Issue 1: False Positives from Web Applications
**Problem:** Dynamic web applications returning 200 for non-existent paths
**Cause:** Application frameworks handling all requests with generic responses
**Solution:**
```bash
# Use content length filtering
gobuster dir -u http://target -w wordlist --exclude-length 1234

# Filter by response size with ffuf
ffuf -u http://target/FUZZ -w wordlist -fs 1234 -mc 200
```

### Issue 2: Rate Limiting and Blocking
**Problem:** Web server blocking or rate limiting enumeration requests
**Solution:**
```bash
# Reduce thread count and add delays
gobuster dir -u http://target -w wordlist -t 10 --delay 100ms

# Use different User-Agent strings
gobuster dir -u http://target -w wordlist -a "Mozilla/5.0 (compatible; crawler)"
```

### Issue 3: HTTPS Certificate Issues
**Problem:** SSL certificate errors preventing enumeration
**Solution:**
```bash
# Skip certificate verification
gobuster dir -u https://target -w wordlist -k

# Use curl for manual verification
curl -k https://target/discovered-path
```

### Issue 4: Large Wordlists Taking Too Long
**Problem:** Comprehensive wordlists taking excessive time during exams
**Optimization:**
```bash
# Use smaller, targeted wordlists
gobuster dir -u http://target -w /usr/share/wordlists/dirb/small.txt

# Combine multiple small scans
gobuster dir -u http://target -w admin-wordlist.txt
gobuster dir -u http://target -w upload-wordlist.txt
```

## 🔗 Integration with Other Tools

### Primary Integration: Nmap → Directory Enumeration → Manual Testing
```bash
# Step 1: Port scanning discovers HTTP service
nmap -p 80,443,8080 -sV target
# Output: 80/tcp open http

# Step 2: Directory enumeration discovers paths  
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt
# Output: /upload/ directory discovered

# Step 3: Manual testing of discovered paths
curl http://target/upload/
# Verify upload functionality for exploitation
```

### Secondary Integration: Directory Enumeration → Nikto → Burp Suite
```bash
# Use enumeration results to guide vulnerability scanning
gobuster dir -u http://target -w wordlist -o discovered_paths.txt

# Feed discovered paths to Nikto for vulnerability assessment
nikto -h http://target -C all

# Import discovered URLs into Burp Suite for manual testing
```

### Advanced Workflows:
```bash
# Comprehensive web enumeration pipeline
#!/bin/bash
target=$1

echo "=== Basic Directory Enumeration ==="
gobuster dir -u http://$target -w /usr/share/wordlists/dirb/common.txt -o basic_dirs.txt

echo "=== File Extension Enumeration ==="
gobuster dir -u http://$target -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,xml -o files.txt

echo "=== Admin Path Discovery ==="
gobuster dir -u http://$target -w /usr/share/wordlists/dirb/admin.txt -o admin_paths.txt

echo "=== Manual Verification ==="
grep "Status: 200" *.txt | while read line; do
    path=$(echo $line | awk '{print $1}')
    echo "Checking: http://$target$path"
    curl -I http://$target$path
done
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** Tool outputs showing discovered directories and files
2. **Command Outputs:** Complete enumeration results with status codes
3. **Manual Verification:** Screenshots of discovered web interfaces
4. **File Contents:** Configuration files or interesting discovered files

### Report Template Structure:
```markdown
## Web Directory Enumeration Results

### Target Information
- Target: demo1.ine.local (192.63.4.3)
- Services: HTTP/80, HTTPS/443
- Date/Time: 2024-11-26 13:08 IST
- Tools Used: Gobuster, Dirb, manual verification

### Commands Executed
```bash
# Initial reconnaissance
curl -I http://demo1.ine.local

# Directory enumeration
gobuster dir -u http://demo1.ine.local -w /usr/share/wordlists/dirb/common.txt

# File enumeration  
gobuster dir -u http://demo1.ine.local -w /usr/share/wordlists/dirb/common.txt -x php,txt,xml
```

### Discovered Paths and Files
- `/admin/` (Status: 301) - Administrative interface redirect
- `/upload/` (Status: 200) - File upload functionality 
- `/config.php` (Status: 200) - Configuration file
- `/backup/` (Status: 403) - Backup directory (access denied)
- `/readme.txt` (Status: 200) - Documentation file

### Key Findings
- XODA web application identified from upload interface
- File upload functionality available at /upload.php
- Administrative paths present but require authentication
- Configuration files accessible revealing application details

### Attack Vectors Identified
- File upload vulnerability via /upload.php interface
- Potential privilege escalation through admin interface
- Information disclosure through configuration files

### Recommendations
- Implement proper access controls on administrative interfaces
- Validate and restrict file upload functionality
- Remove or protect configuration files from web root
- Implement directory browsing restrictions
```

### Automation Scripts:
```bash
# Web enumeration automation script
#!/bin/bash
TARGET_URL=$1
OUTPUT_DIR="web-enum-$(date +%Y%m%d-%H%M%S)"
mkdir $OUTPUT_DIR

echo "Starting comprehensive web enumeration of $TARGET_URL"

# Basic directory enumeration
echo "[+] Running basic directory enumeration..."
gobuster dir -u $TARGET_URL -w /usr/share/wordlists/dirb/common.txt -o $OUTPUT_DIR/basic_dirs.txt -q

# File enumeration with common extensions
echo "[+] Enumerating files with common extensions..."
gobuster dir -u $TARGET_URL -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,xml,js,css -o $OUTPUT_DIR/files.txt -q

# Admin-specific enumeration
echo "[+] Searching for administrative interfaces..."
gobuster dir -u $TARGET_URL -w /usr/share/wordlists/dirb/admin.txt -o $OUTPUT_DIR/admin.txt -q

# Parse and summarize results
echo "[+] Summarizing discoveries..."
echo "=== DISCOVERED DIRECTORIES ===" > $OUTPUT_DIR/summary.txt
grep "Status: 200\|Status: 301\|Status: 302" $OUTPUT_DIR/basic_dirs.txt >> $OUTPUT_DIR/summary.txt

echo "=== DISCOVERED FILES ===" >> $OUTPUT_DIR/summary.txt
grep "Status: 200" $OUTPUT_DIR/files.txt >> $OUTPUT_DIR/summary.txt

echo "[+] Enumeration complete! Results saved in $OUTPUT_DIR/"
echo "[+] Review summary.txt for quick overview of discoveries"

# Generate curl commands for manual verification
echo "[+] Generating manual verification commands..."
grep "Status: 200" $OUTPUT_DIR/*.txt | awk -F: '{print $2}' | awk '{print "curl -I " url $1}' url="$TARGET_URL" > $OUTPUT_DIR/manual_checks.sh
chmod +x $OUTPUT_DIR/manual_checks.sh
```

## 📚 Additional Resources

### Official Documentation:
- Gobuster GitHub: https://github.com/OJ/gobuster
- Dirb documentation: https://tools.kali.org/web-applications/dirb  
- Ffuf documentation: https://github.com/ffuf/ffuf

### Learning Resources:
- Web application enumeration techniques
- Directory traversal and path manipulation
- HTTP status code interpretation for security testing

### Community Resources:
- SecLists wordlists: https://github.com/danielmiessler/SecLists
- Directory enumeration methodologies
- Web application testing guides and CTF writeups

### Related Tools:
- Wfuzz: Advanced web fuzzing capabilities
- Dirsearch: Python-based directory scanner
- Feroxbuster: Fast recursive directory scanner
