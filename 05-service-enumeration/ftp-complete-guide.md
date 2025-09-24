# 🔧 FTP Enumeration - Complete File Transfer Protocol Analysis

FTP (File Transfer Protocol) enumeration involves discovering FTP services, testing for anonymous access, and enumerating directory structures and files.
**Location:** `05-service-enumeration/ftp-complete-guide.md`

## 🎯 What is FTP Enumeration?

FTP enumeration is the process of analyzing File Transfer Protocol services to identify accessible content, user accounts, and potential security weaknesses. Key capabilities include:
- Anonymous FTP access testing
- Directory and file structure enumeration
- User account discovery through brute force
- FTP bounce attack identification
- Version fingerprinting and vulnerability assessment
- Writable directory identification

## 📦 Installation and Setup

### Prerequisites:
- FTP client tools (ftp, lftp, ncftp)
- Network scanning tools (nmap with NSE scripts)
- Username and password wordlists

### Installation:
```bash
# Install FTP clients and tools
apt update && apt install ftp lftp ncftp hydra

# Verify FTP service discovery
nmap -sV -p 21 target
# Expected: 21/tcp open ftp

# Test basic FTP connectivity
ftp target
```

### NSE Scripts for FTP:
```bash
# List FTP-related NSE scripts
ls /usr/share/nmap/scripts/ftp*
# Available scripts:
# ftp-anon.nse - Anonymous FTP access
# ftp-bounce.nse - FTP bounce attack
# ftp-brute.nse - FTP brute force
# ftp-syst.nse - FTP system information
```

## 🔧 Basic Usage and Syntax

### Basic Workflow:
1. **Service Discovery:** Identify FTP services on target ports
2. **Version Detection:** Determine FTP server software and version
3. **Anonymous Access:** Test for anonymous login capabilities
4. **Directory Enumeration:** Map accessible directory structures
5. **File Discovery:** Identify interesting files and content
6. **Permission Testing:** Check read/write permissions

### Command Structure:
```bash
# Basic FTP enumeration (extending lab context)
nmap -p 21 -sV --script ftp-anon target
ftp target
# Try anonymous login: user=anonymous, password=anonymous
```

## ⚙️ Command Line Options

### Nmap NSE FTP Scripts:
| Script | Purpose | Example |
|--------|---------|---------|
| `ftp-anon` | Test anonymous access | `nmap --script ftp-anon -p 21 target` |
| `ftp-bounce` | Check FTP bounce capability | `nmap --script ftp-bounce -p 21 target` |
| `ftp-brute` | Brute force authentication | `nmap --script ftp-brute -p 21 target` |
| `ftp-syst` | Get system information | `nmap --script ftp-syst -p 21 target` |

### FTP Client Commands:
| Command | Purpose | Example |
|---------|---------|---------|
| `ls` / `dir` | List directory contents | `ls -la` |
| `cd` | Change directory | `cd /home/user` |
| `pwd` | Print working directory | `pwd` |
| `get` | Download file | `get filename` |
| `put` | Upload file | `put localfile` |
| `binary` | Set binary transfer mode | `binary` |
| `passive` | Enable passive mode | `passive` |

### Hydra FTP Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-l username` | Single username | `hydra -l admin -P wordlist ftp://target` |
| `-L userlist` | Username wordlist | `hydra -L users.txt -P pass.txt ftp://target` |
| `-p password` | Single password | `hydra -l admin -p password ftp://target` |
| `-P passlist` | Password wordlist | `hydra -l admin -P rockyou.txt ftp://target` |

## 🧪 Real Lab Examples

### Example 1: Basic FTP Service Discovery and Anonymous Access
```bash
# Based on lab context showing FTP service on port 21
# Step 1: Service identification
nmap -p 21 -sV 192.180.108.3
# Output: 21/tcp open ftp vsftpd 3.0.3

# Step 2: Test anonymous access with NSE
nmap --script ftp-anon -p 21 192.180.108.3
# Expected output:
# | ftp-anon: Anonymous FTP login allowed
# |_drwxr-xr-x    2 ftp      ftp          4096 Nov 26 07:30 pub

# Step 3: Manual anonymous login
ftp 192.180.108.3
# Username: anonymous
# Password: anonymous (or blank)
# Output: 230 Login successful
```

### Example 2: Directory and File Enumeration
```bash
# After successful anonymous login
ftp> pwd
# Output: 257 "/" is the current directory

ftp> ls -la
# Output: Directory listing with permissions and file details
# drwxr-xr-x    2 ftp      ftp          4096 Nov 26 07:30 pub
# -rw-r--r--    1 ftp      ftp           234 Nov 26 07:25 readme.txt

ftp> cd pub
ftp> ls -la
# Check for additional files and subdirectories

# Download interesting files for analysis
ftp> get readme.txt
# Output: 226 Transfer complete
```

### Example 3: Permission Testing and Upload Attempts
```bash
# Test write permissions
ftp> pwd
ftp> put test.txt
# If successful: 226 Transfer complete
# If failed: 550 Permission denied

# Check if uploaded file is accessible
ftp> ls -la
# Look for test.txt in directory listing

# Try to access upload directory
ftp> cd upload
ftp> ls -la
# Check for writable upload directories
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **Anonymous access testing (40%)** - Primary FTP attack vector
- **Directory enumeration (30%)** - Mapping accessible content
- **File download/analysis (20%)** - Extracting valuable information
- **Upload capability testing (10%)** - Identifying writable areas

### Critical Commands to Master:
```bash
# Must-know commands for exam
nmap --script ftp-anon -p 21 target                    # Anonymous access test
ftp target                                             # Manual FTP connection
ls -la                                                 # Detailed directory listing
get filename                                           # Download files
put testfile                                           # Test upload permissions
```

### eJPT Exam Scenarios:
1. **Anonymous FTP Access:** Discover and exploit anonymous FTP login
   - Required skills: Service identification, anonymous login, file retrieval
   - Expected commands: NSE scripts, manual FTP client usage
   - Success criteria: Access FTP content without authentication

2. **FTP File Retrieval:** Download and analyze files from FTP server
   - Required skills: Directory navigation, file download, content analysis  
   - Expected commands: FTP client navigation and transfer commands
   - Success criteria: Extract sensitive information from FTP files

### Exam Tips and Tricks:
- **Always test anonymous:** First attempt should be anonymous/anonymous login
- **Check permissions:** Use `ls -la` to identify writable directories
- **Binary mode:** Use `binary` command for non-text file transfers
- **Passive mode:** Enable if active mode connections fail

### Common eJPT Questions:
- Test for anonymous FTP access on discovered services
- Download configuration files or user data from FTP servers
- Identify writable FTP directories for potential file upload attacks

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Connection Refused or Timeouts
**Problem:** FTP service not responding or blocking connections
**Cause:** Firewall blocking, service not running, or wrong port
**Solution:**
```bash
# Verify FTP service is running
nmap -p 21 target

# Try alternative FTP ports
nmap -p 21,2121,990 target

# Check for FTP over SSL (FTPS)
nmap --script ssl-enum-ciphers -p 990 target
```

### Issue 2: Active vs Passive Mode Issues
**Problem:** Data connections failing during file transfers
**Cause:** Firewall or NAT issues with FTP data connections
**Solution:**
```bash
# Enable passive mode in FTP client
ftp> passive
# Output: Passive mode on

# Or use lftp which uses passive mode by default
lftp ftp://target
```

### Issue 3: Anonymous Access Denied
**Problem:** Anonymous login rejected by FTP server
**Solution:**
```bash
# Try different anonymous credentials
# Username: anonymous, Password: (blank)
# Username: anonymous, Password: anonymous
# Username: ftp, Password: ftp
# Username: guest, Password: guest

# Use NSE to test multiple anonymous login methods
nmap --script ftp-anon -p 21 target
```

### Issue 4: Permission Denied for File Operations
**Problem:** Cannot download or upload files despite successful login
**Solution:**
```bash
# Check current directory permissions
ftp> ls -la

# Try different directories
ftp> cd pub
ftp> cd upload  
ftp> cd tmp

# Set correct transfer mode
ftp> binary    # For binary files
ftp> ascii     # For text files
```

## 🔗 Integration with Other Tools

### Primary Integration: Nmap → FTP Enumeration → File Analysis
```bash
# Step 1: Discover FTP service
nmap -p 21 -sV target
# Output: 21/tcp open ftp vsftpd 3.0.3

# Step 2: Test anonymous access and enumerate
nmap --script ftp-anon,ftp-syst -p 21 target
# Output: Anonymous access allowed, system information

# Step 3: Manual enumeration and file retrieval
ftp target
# Download interesting files for analysis
```

### Secondary Integration: FTP → Hydra → Metasploit
```bash
# If anonymous access fails, try brute force
hydra -L users.txt -P passwords.txt ftp://target

# Use discovered credentials in Metasploit FTP modules
msfconsole
use auxiliary/scanner/ftp/ftp_login
set RHOSTS target
set USER_FILE users.txt  
set PASS_FILE passwords.txt
run
```

### Advanced Workflows:
```bash
# Comprehensive FTP enumeration pipeline
#!/bin/bash
target=$1

echo "=== FTP Service Discovery ==="
nmap -p 21,990,2121 -sV $target

echo "=== Anonymous Access Testing ==="
nmap --script ftp-anon,ftp-syst -p 21 $target

echo "=== Manual FTP Enumeration ==="
# Automated FTP enumeration script
expect << EOF
spawn ftp $target
expect "Name"
send "anonymous\r"
expect "Password:"
send "anonymous\r"
expect "ftp>"
send "ls -la\r"
expect "ftp>"
send "pwd\r"
expect "ftp>"
send "quit\r"
EOF
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** FTP client sessions showing successful login and file listings
2. **Command Outputs:** Nmap NSE script results and manual FTP commands
3. **Downloaded Files:** Any files retrieved from FTP server for analysis
4. **Directory Structure:** Map of accessible FTP directory hierarchy

### Report Template Structure:
```markdown
## FTP Enumeration Results

### Target Information
- Target: 192.180.108.3
- Service: FTP/21 (vsftpd 3.0.3)
- Date/Time: 2024-11-26 13:08 IST
- Access Method: Anonymous login

### Commands Executed
```bash
# Service discovery
nmap -p 21 -sV 192.180.108.3

# Anonymous access testing  
nmap --script ftp-anon -p 21 192.180.108.3

# Manual enumeration
ftp 192.180.108.3
# Username: anonymous
# Password: anonymous
```

### FTP Access Results
- **Authentication:** Anonymous login successful
- **Root Directory:** / (accessible)
- **Subdirectories:** /pub/ (readable), /upload/ (writable)
- **Permissions:** Read access to most directories, write access to /upload/

### Discovered Files
- `/readme.txt` (234 bytes) - Server configuration information
- `/pub/userlist.txt` (1.2KB) - List of system users
- `/pub/config/` - Directory containing configuration files

### Security Findings
- Anonymous FTP access enabled (high risk)
- Sensitive user information accessible without authentication
- Upload directory allows file placement (potential for malicious uploads)
- Configuration files exposed in /pub/config/

### Attack Vectors
- Information disclosure through accessible files
- Potential malware upload via writable directories
- User enumeration from exposed user lists

### Recommendations
- Disable anonymous FTP access
- Implement proper access controls and authentication
- Remove sensitive files from FTP accessible directories
- Regular audit of FTP permissions and content
```

### Automation Scripts:
```bash
# FTP enumeration automation script
#!/bin/bash
TARGET=$1
OUTPUT_DIR="ftp-enum-$(date +%Y%m%d-%H%M%S)"
mkdir $OUTPUT_DIR

echo "Starting FTP enumeration of $TARGET"

# Service discovery
echo "[+] Discovering FTP services..."
nmap -p 21,990,2121 -sV $TARGET > $OUTPUT_DIR/service_discovery.txt

# NSE script enumeration
echo "[+] Running NSE scripts..."
nmap --script ftp-anon,ftp-bounce,ftp-syst -p 21 $TARGET > $OUTPUT_DIR/nse_scripts.txt

# Test common anonymous credentials
echo "[+] Testing anonymous access..."
for user in anonymous ftp guest; do
    for pass in "" anonymous ftp guest; do
        echo "Testing $user:$pass" >> $OUTPUT_DIR/login_attempts.txt
        timeout 10 expect << EOF >> $OUTPUT_DIR/login_attempts.txt
spawn ftp $TARGET
expect "Name"
send "$user\r"
expect "Password:"
send "$pass\r"
expect {
    "Login successful" { 
        send "pwd\r"
        expect "ftp>"
        send "ls -la\r"
        expect "ftp>"
        send "quit\r"
    }
    "Login incorrect" { send "quit\r" }
}
EOF
    done
done

echo "[+] FTP enumeration complete! Results in $OUTPUT_DIR/"
```

## 📚 Additional Resources

### Official Documentation:
- vsftpd documentation: https://security.appspot.com/vsftpd.html
- ProFTPD documentation: http://www.proftpd.org/docs/
- FTP RFC 959: https://tools.ietf.org/html/rfc959

### Learning Resources:
- FTP protocol deep dive and security implications
- Anonymous FTP security best practices  
- FTP bounce attack techniques and prevention

### Community Resources:
- HackTricks FTP enumeration: https://book.hacktricks.xyz/pentesting/pentesting-ftp
- OWASP FTP testing guide
- FTP exploitation techniques in penetration testing

### Related Tools:
- FileZilla: GUI FTP client for manual enumeration
- WinSCP: Windows FTP/SFTP client
- TFTP enumeration tools for UDP/69 services
