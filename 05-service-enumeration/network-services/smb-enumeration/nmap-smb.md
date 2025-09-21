# 🔧 Nmap SMB Scripts - Windows SMB Enumeration and Security Assessment

Comprehensive SMB (Server Message Block) enumeration using Nmap's powerful NSE (Nmap Scripting Engine) scripts for penetration testing and security assessment.
**Location:** `05-service-enumeration/network-services/smb-enumeration/nmap-smb.md`

## 🎯 What are Nmap SMB Scripts?

Nmap SMB scripts are specialized NSE (Nmap Scripting Engine) modules designed to enumerate and assess SMB/CIFS services on Windows and Linux systems. These scripts provide comprehensive information about SMB protocols, security configurations, shared resources, and potential vulnerabilities.

Key capabilities include:
- **Protocol Detection:** Identify SMB versions and dialects
- **Security Assessment:** Analyze authentication mechanisms and encryption
- **Share Enumeration:** Discover available network shares and permissions
- **Session Analysis:** Enumerate active sessions and logged-in users
- **Vulnerability Detection:** Identify common SMB security misconfigurations

## 📦 Installation and Setup

### Prerequisites:
- Nmap 7.94SVN or later (includes latest NSE scripts)
- Network connectivity to target SMB services
- Appropriate permissions for network scanning

### Installation:
```bash
# Verify Nmap installation and version
nmap --version

# Update NSE script database
nmap --script-updatedb

# Verify SMB scripts are available
nmap --script-help smb*
```

### Initial Configuration:
```bash
# Ensure target is reachable
ping -c 4 target_ip

# Check if SMB port is open
nmap -p 445 target_ip
```

## 🔧 Basic Usage and Syntax

### Basic Workflow:
1. **Host Discovery:** Verify target is alive and responsive
2. **Port Scanning:** Identify open SMB ports (139, 445)
3. **Protocol Enumeration:** Determine supported SMB protocols and dialects
4. **Security Assessment:** Analyze authentication and security configurations
5. **Share Discovery:** Enumerate available shares and permissions
6. **Session Analysis:** Identify active sessions and users

### Command Structure:
```bash
# Basic SMB script syntax
nmap -p445 --script smb-script-name target_ip

# Multiple scripts execution
nmap -p445 --script "smb-*" target_ip

# Script with arguments
nmap -p445 --script script-name --script-args arg1=value1,arg2=value2 target_ip
```

## ⚙️ Command Line Options

### Essential SMB Scripts:
| Script | Purpose | Usage |
|--------|---------|-------|
| `smb-protocols` | Detect supported SMB dialects | `nmap -p445 --script smb-protocols target` |
| `smb-security-mode` | Analyze authentication requirements | `nmap -p445 --script smb-security-mode target` |
| `smb-enum-sessions` | Enumerate active SMB sessions | `nmap -p445 --script smb-enum-sessions target` |
| `smb-enum-shares` | Discover available network shares | `nmap -p445 --script smb-enum-shares target` |
| `smb-enum-users` | Enumerate SMB users | `nmap -p445 --script smb-enum-users target` |
| `smb-enum-groups` | Enumerate user groups and membership | `nmap -p445 --script smb-enum-groups target` |
| `smb-enum-domains` | Discover domain information | `nmap -p445 --script smb-enum-domains target` |
| `smb-enum-services` | Enumerate running services | `nmap -p445 --script smb-enum-services target` |
| `smb-server-stats` | Get server statistics and activity | `nmap -p445 --script smb-server-stats target` |
| `smb-ls` | List files and directories in SMB shares | `nmap -p445 --script smb-ls target` |

### Authentication Options:
| Script Argument | Purpose | Example |
|-----------------|---------|---------|
| `smbusername` | Specify SMB username | `--script-args smbusername=admin` |
| `smbpassword` | Specify SMB password | `--script-args smbpassword=password123` |
| `smbdomain` | Specify SMB domain | `--script-args smbdomain=WORKGROUP` |
| `smbtype` | Authentication type | `--script-args smbtype=v1` |

### Output Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-oN` | Normal output to file | `-oN smb_scan.txt` |
| `-oX` | XML output format | `-oX smb_scan.xml` |
| `-v` | Verbose output | `-v` |
| `--script-trace` | Debug script execution | `--script-trace` |

## 🧪 Real Lab Examples

### Example 1: Complete SMB Reconnaissance Workflow
```bash
# Phase 1: Host Discovery
ping -c 5 demo.ine.local
# Output: 5 packets transmitted, 5 received, 0% packet loss

# Phase 2: Port Scanning
nmap demo.ine.local
# Output: 
# PORT     STATE SERVICE
# 135/tcp  open  msrpc
# 139/tcp  open  netbios-ssn
# 445/tcp  open  microsoft-ds
# 3389/tcp open  ms-wbt-server

# Phase 3: SMB Protocol Detection
nmap -p445 --script smb-protocols demo.ine.local
# Output:
# Host script results:
# | smb-protocols:
# |   dialects:
# |     NT LM 0.12 (SMBv1) [dangerous, but default]
# |     2:0:2
# |     2:1:0
# |     3:0:0
# |     3:0:2

# Phase 4: Security Mode Analysis
nmap -p445 --script smb-security-mode demo.ine.local
# Output:
# | smb-security-mode:
# |   account_used: guest
# |   authentication_level: user
# |   challenge_response: supported
# |   message_signing: disabled (dangerous, but default)
```

### Example 2: Session and User Enumeration
```bash
# Enumerate active sessions without credentials
nmap -p445 --script smb-enum-sessions demo.ine.local
# Output:
# | smb-enum-sessions:
# |   Users logged in
# |     WIN-OMCNBRK6GMN\bob since <unknown>

# Enumerate sessions with credentials
nmap -p445 --script smb-enum-sessions --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
# Output:
# | smb-enum-sessions:
# |   Users logged in
# |     WIN-OMCNBRK6GMN\bob since 2024-07-04T10:21:16
# |   Active SMB sessions
# |     ADMINISTRATOR is connected from \\10.10.31.2 for [just logged in, it's probably you], idle for [not idle]
```

### Example 3: Complete Share Enumeration with Authentication
```bash
# Discover shares with authenticated credentials
nmap -p445 --script smb-enum-shares --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
# Output:
# | smb-enum-shares:
# |   account_used: administrator
# |   \\10.0.30.254\ADMIN$:
# |     Type: STYPE_DISKTREE_HIDDEN
# |     Comment: Remote Admin
# |     Users: 0
# |     Max Users: <unlimited>
# |     Path: C:\Windows
# |     Anonymous access: <none>
# |     Current user access: READ/WRITE
# |   \\10.0.30.254\C$:
# |     Type: STYPE_DISKTREE_HIDDEN
# |     Comment: Default share
# |     Users: 0
# |     Max Users: <unlimited>
# |     Path: C:\
# |     Anonymous access: <none>
# |     Current user access: READ/WRITE
# |   \\10.0.30.254\D$:
# |     Type: STYPE_DISKTREE_HIDDEN
# |     Comment: Default share
# |     Users: 0
# |     Max Users: <unlimited>
# |     Path: D:\
# |     Anonymous access: <none>
# |     Current user access: READ/WRITE
# |   \\10.0.30.254\Documents:
# |     Type: STYPE_DISKTREE
# |     Comment:
# |     Users: 0
# |     Max Users: <unlimited>
# |     Path: C:\Users\Administrator\Documents
# |     Anonymous access: <none>
# |     Current user access: READ
# |   \\10.0.30.254\Downloads:
# |     Type: STYPE_DISKTREE
# |     Comment:
# |     Users: 0
# |     Max Users: <unlimited>
# |     Path: C:\Users\Administrator\Downloads
# |     Anonymous access: <none>
# |     Current user access: READ
# |   \\10.0.30.254\IPC$:
# |     Type: STYPE_IPC_HIDDEN
# |     Comment: Remote IPC
# |     Users: 1
# |     Max Users: <unlimited>
# |     Anonymous access: <none>
# |     Current user access: READ/WRITE
# |   \\10.0.30.254\print$:
# |     Type: STYPE_DISKTREE
# |     Comment: Printer Drivers
# |     Users: 0
# |     Max Users: <unlimited>
# |     Path: C:\Windows\system32\spool\drivers
# |     Anonymous access: <none>
# |     Current user access: READ
```

### Example 4: User and Group Enumeration
```bash
# Enumerate Windows users
nmap -p445 --script smb-enum-users --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
# Output:
# | smb-enum-users:
# |   WIN-OMCNBRK6GMN\Administrator (RID: 500)
# |     Description: Built-in account for administering the computer/domain
# |     Flags: Normal user account, Password does not expire
# |   WIN-OMCNBRK6GMN\bob (RID: 1010)
# |     Flags: Normal user account, Password does not expire
# |   WIN-OMCNBRK6GMN\Guest (RID: 501)
# |     Description: Built-in account for guest access to the computer/domain
# |     Flags: Normal user account, Password not required, Password does not expire

# Enumerate user groups
nmap -p445 --script smb-enum-groups --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
# Output:
# | smb-enum-groups:
# |   Builtin\Administrators (RID: 544): Administrator, bob
# |   Builtin\Users (RID: 545): bob
# |   Builtin\Guests (RID: 546): Guest
# |   Builtin\Power Users (RID: 547): <empty>
# |   Builtin\Print Operators (RID: 550): <empty>
# |   Builtin\Backup Operators (RID: 551): <empty>
# |   Builtin\Replicator (RID: 552): <empty>
# |   Builtin\Remote Desktop Users (RID: 555): bob
# |   Builtin\Network Configuration Operators (RID: 556): <empty>
# |   Builtin\Performance Monitor Users (RID: 558): <empty>
# |   Builtin\Performance Log Users (RID: 559): <empty>
# |   Builtin\Distributed COM Users (RID: 562): <empty>
# |   Builtin\IIS_IUSRS (RID: 568): <empty>
# |   Builtin\Cryptographic Operators (RID: 569): <empty>
# |   Builtin\Event Log Readers (RID: 573): <empty>
# |   WIN-OMCNBRK6GMN\WinRMRemoteWMIUsers__ (RID: 1000): <empty>
```

### Example 6: Service Enumeration and File Listing
```bash
# Enumerate running Windows services
nmap -p445 --script smb-enum-services --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
# Output:
# | smb-enum-services:
# |   AmazonSSMAgent:
# |     display_name: Amazon SSM Agent
# |     state:
# |       SERVICE_PAUSED
# |       SERVICE_RUNNING
# |       SERVICE_CONTINUE_PENDING
# |       SERVICE_PAUSE_PENDING
# |     type:
# |       SERVICE_TYPE_WIN32
# |       SERVICE_TYPE_WIN32_OWN_PROCESS
# |     controls_accepted:
# |       SERVICE_CONTROL_STOP
# |       SERVICE_CONTROL_NETBINDENABLE
# |       SERVICE_CONTROL_NETBINDADD0
# |       SERVICE_CONTROL_INTERROGATE
# |       SERVICE_CONTROL_CONTINUE
# |       SERVICE_CONTROL_PARAMCHANGE
# |   DiagTrack:
# |     display_name: Diagnostics Tracking Service
# |     state:
# |       SERVICE_PAUSED
# |       SERVICE_RUNNING
# |       SERVICE_CONTINUE_PENDING
# |       SERVICE_PAUSE_PENDING
# |   Ec2Config:
# |     display_name: Ec2Config
# |     state:
# |       SERVICE_PAUSED
# |       SERVICE_RUNNING
# |       SERVICE_CONTINUE_PENDING
# |       SERVICE_PAUSE_PENDING
# |   MSDTC:
# |     display_name: Distributed Transaction Coordinator
# |   Spooler:
# |     display_name: Print Spooler
# |     state:
# |       SERVICE_PAUSED
# |       SERVICE_RUNNING
# |       SERVICE_CONTINUE_PENDING
# |       SERVICE_PAUSE_PENDING

# List files and directories within SMB shares
nmap -p445 --script smb-enum-shares,smb-ls --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
# Output:
# | smb-ls: Volume \\10.0.30.254\ADMIN$
# |   maxfiles limit reached (10)
# |   SIZE   TIME                 FILENAME
# |   <DIR>  2013-08-22T13:36:16  .
# |   <DIR>  2013-08-22T13:36:16  ..
# |   <DIR>  2013-08-22T15:39:31  ADFS
# |   <DIR>  2013-08-22T15:39:31  ADFS\ar
# |   <DIR>  2013-08-22T15:39:31  ADFS\bg
# |   <DIR>  2013-08-22T15:39:31  ADFS\cs
# |   <DIR>  2013-08-22T15:39:31  ADFS\da
# |   <DIR>  2013-08-22T15:39:31  ADFS\de
# |   <DIR>  2013-08-22T15:39:31  ADFS\el
# |   <DIR>  2013-08-22T15:39:31  ADFS\en
# |
# | Volume \\10.0.30.254\C$
# |   maxfiles limit reached (10)
# |   SIZE     TIME                 FILENAME
# |   <DIR>    2013-08-22T15:39:30  PerfLogs
# |   <DIR>    2013-08-22T13:36:16  Program Files
# |   <DIR>    2014-05-17T10:36:57  Program Files\Amazon
# |   <DIR>    2013-08-22T13:36:16  Program Files\Common Files
# |   <DIR>    2014-10-15T05:58:49  Program Files\DIFX
# |   <DIR>    2020-08-12T04:13:47  Program Files\Windows Mail
# |   <DIR>    2013-08-22T15:39:31  Program Files\Windows NT
# |   <DIR>    2013-08-22T15:39:31  Program Files\WindowsPowerShell
# |
# | Volume \\10.0.30.254\Documents
# |   SIZE   TIME                 FILENAME
# |   <DIR>  2020-09-10T09:50:27  .
# |   <DIR>  2020-09-10T09:50:27  ..
# |
# | Volume \\10.0.30.254\Downloads
# |   SIZE   TIME                 FILENAME
# |   <DIR>  2020-09-10T09:50:27  .
# |   <DIR>  2020-09-10T09:50:27  ..
# |
# | Volume \\10.0.30.254\print$
# |   maxfiles limit reached (10)
# |   <DIR>    2013-08-22T15:39:31  ..
# |   <DIR>    2013-08-22T15:39:31  color
# |   1058     2013-08-22T06:54:44  color\D50.camp
# |   1079     2013-08-22T06:54:44  color\D65.camp
# |   797      2013-08-22T06:54:44  color\Graphics.gmmp
# |   838      2013-08-22T06:54:44  color\MediaSim.gmmp
# |   786      2013-08-22T06:54:44  color\Photo.gmmp
# |   822      2013-08-22T06:54:44  color\Proofing.gmmp
# |   218103   2013-08-22T06:54:44  color\RSWOP.icm
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **SMB Enumeration (25%)** - Critical for Windows penetration testing
- **Protocol Analysis (20%)** - Understanding SMB versions and security
- **Share Discovery (20%)** - Finding accessible network resources
- **Security Assessment (15%)** - Identifying misconfigurations
- **Session Analysis (20%)** - User enumeration and access control

### Critical Commands to Master:
```bash
# Must-know commands for eJPT exam
nmap -p445 --script smb-protocols target_ip                    # Protocol detection
nmap -p445 --script smb-security-mode target_ip                # Security analysis
nmap -p445 --script smb-enum-shares target_ip                  # Share enumeration
nmap -p445 --script smb-enum-sessions target_ip                # Session discovery
nmap -p445 --script smb-enum-users --script-args smbusername=user,smbpassword=pass target_ip  # User enumeration
nmap -p445 --script smb-enum-groups --script-args smbusername=user,smbpassword=pass target_ip # Group membership
nmap -p445 --script smb-enum-domains --script-args smbusername=user,smbpassword=pass target_ip # Domain info
nmap -p445 --script smb-enum-services --script-args smbusername=user,smbpassword=pass target_ip # Service enum
nmap -p445 --script smb-server-stats --script-args smbusername=user,smbpassword=pass target_ip # Server stats
nmap -p445 --script smb-enum-shares,smb-ls --script-args smbusername=user,smbpassword=pass target_ip # File listing
nmap -p445 --script "smb-enum-*" target_ip                     # Comprehensive enumeration
```

### eJPT Exam Scenarios:
1. **Windows Network Reconnaissance:** Students must identify SMB services and enumerate shares
   - Required skills: Port scanning, protocol detection, share discovery
   - Expected commands: Basic SMB scripts without authentication
   - Success criteria: Discover readable shares and identify SMB version

2. **Authentication Bypass Assessment:** Evaluate guest access and anonymous login capabilities
   - Required skills: Security mode analysis, anonymous enumeration
   - Expected commands: smb-security-mode, smb-enum-shares with guest access
   - Success criteria: Identify guest-accessible resources and security weaknesses

3. **User and Session Enumeration:** Discover active users and sessions on target systems
   - Required skills: Session enumeration, user discovery, credential usage
   - Expected commands: smb-enum-sessions with and without credentials
   - Success criteria: Enumerate logged-in users and active connections

### Exam Tips and Tricks:
- **Start with Protocol Detection:** Always identify SMB version first - SMBv1 indicates potential vulnerabilities
- **Check Guest Access:** Many exam targets allow guest/anonymous access for initial enumeration
- **Document Share Permissions:** Note which shares allow READ vs WRITE access - critical for exploitation
- **Time Management:** SMB enumeration is fast - spend 5-10 minutes maximum per target
- **Credential Testing:** If you find credentials elsewhere, always test them against SMB

### Common eJPT Questions:
- What SMB protocol versions are supported by the target?
- Which network shares are accessible without authentication?
- What users are currently logged into the SMB server?
- Does the target allow guest/anonymous SMB access?

## ⚠️ Common Issues & Troubleshooting

### Issue 1: SMB Scripts Fail to Execute
**Problem:** Nmap SMB scripts return no results or fail with connection errors
**Cause:** SMB ports may be filtered, or SMB service is not running
**Solution:**
```bash
# Verify SMB ports are open
nmap -p139,445 target_ip

# Test SMB connectivity
telnet target_ip 445

# Use alternative enumeration
enum4linux target_ip
```

### Issue 2: Authentication Required Errors
**Problem:** Scripts fail with "NT_STATUS_ACCESS_DENIED" or authentication errors
**Solution:**
```bash
# Try with explicit guest credentials
nmap -p445 --script smb-enum-shares --script-args smbusername=guest,smbpassword= target_ip

# Use null session
nmap -p445 --script smb-enum-shares --script-args smbusername=,smbpassword= target_ip
```

### Issue 3: Incomplete Results from SMB Scripts
**Problem:** Scripts return partial information or miss important details
**Prevention:**
```bash
# Run comprehensive SMB enumeration
nmap -p445 --script "smb-enum-*,smb-protocols,smb-security-mode" target_ip

# Increase verbosity for debugging
nmap -p445 --script smb-enum-shares -v target_ip
```

### Issue 4: Script Timeout Issues
**Problem:** SMB scripts hang or timeout on slower networks
**Optimization:**
```bash
# Reduce timeout values
nmap -p445 --script smb-enum-shares --script-args timeout=10s target_ip

# Run scripts individually instead of batch
nmap -p445 --script smb-protocols target_ip
nmap -p445 --script smb-enum-shares target_ip
```

## 🔗 Integration with Other Tools

### Primary Integration: Nmap → SMBClient → Enum4Linux
```bash
# Step 1: Nmap discovers SMB shares
nmap -p445 --script smb-enum-shares target_ip > smb_shares.txt

# Step 2: Connect to discovered shares with SMBClient
smbclient //target_ip/sharename

# Step 3: Comprehensive enumeration with Enum4Linux
enum4linux -a target_ip
```

### Secondary Integration: Nmap SMB → Metasploit
```bash
# Nmap identifies SMB version and shares
nmap -p445 --script smb-protocols,smb-enum-shares target_ip

# Feed results into Metasploit for exploitation
msfconsole
use auxiliary/scanner/smb/smb_version
set RHOSTS target_ip
run
```

### Advanced Workflows:
```bash
# Complete SMB assessment workflow
# 1. Protocol detection
nmap -p445 --script smb-protocols target_ip

# 2. Security analysis
nmap -p445 --script smb-security-mode target_ip

# 3. Share enumeration
nmap -p445 --script smb-enum-shares target_ip

# 4. Session analysis
nmap -p445 --script smb-enum-sessions target_ip

# 5. Vulnerability scanning
nmap -p445 --script smb-vuln-* target_ip
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** Capture all SMB script outputs showing protocols, shares, and sessions
2. **Command Outputs:** Save complete nmap outputs with timestamps
3. **Share Access:** Document which shares are accessible and permission levels
4. **Security Findings:** Record authentication requirements and guest access status

### Report Template Structure:
```markdown
## SMB Enumeration Results

### Target Information
- Target: demo.ine.local (10.0.30.254)
- Date/Time: 2024-07-04 15:53 IST
- Nmap Version: 7.94SVN

### Commands Executed
```bash
# Protocol detection
nmap -p445 --script smb-protocols demo.ine.local

# Security assessment
nmap -p445 --script smb-security-mode demo.ine.local

# Share enumeration
nmap -p445 --script smb-enum-shares demo.ine.local

# Session analysis
nmap -p445 --script smb-enum-sessions demo.ine.local
```

### Key Findings
- **SMB Protocol:** SMBv1 enabled (dangerous, but default), SMBv2 and SMBv3 supported
- **Authentication:** Guest access allowed, message signing disabled, administrator account active
- **Network Shares:** 8 shares discovered including ADMIN$, C$, D$, Documents, Downloads, IPC$, print$
- **Share Permissions:** Administrator has READ/WRITE on C$, D$, ADMIN$; READ on Documents, Downloads
- **Active Sessions:** User 'bob' logged in, Administrator session active from 10.10.31.2
- **User Accounts:** 3 users identified - Administrator (RID: 500), bob (RID: 1010), Guest (RID: 501)
- **Group Membership:** bob is member of Administrators and Remote Desktop Users groups
- **Domain Info:** WIN-OMCNBRK6GMN domain, password policy allows 42-day maximum age
- **Server Statistics:** 37 failed logins, 7 permission errors, 35 files opened since boot
- **IPC$ Share:** READ/WRITE access available (null session connection possible)
- **Running Services:** Amazon SSM Agent, Diagnostics Tracking, Ec2Config, MSDTC, Print Spooler identified
- **File System Access:** Can browse C$ root directory, Program Files, Windows folders
- **Printer Drivers:** print$ share contains color management files and ICC profiles
- **System Information:** Windows installation dating back to 2013, multiple AWS-related services

### Security Recommendations
- Disable SMBv1 protocol to prevent downgrade attacks
- Enable SMB message signing for integrity protection
- Restrict guest access to SMB shares
- Implement proper access controls for administrative shares
```

### Automation Scripts:
```bash
#!/bin/bash
# SMB enumeration automation script
target=$1
output_dir="smb_enum_$(date +%Y%m%d_%H%M%S)"
mkdir -p $output_dir

echo "Starting SMB enumeration for $target"

# Protocol detection
nmap -p445 --script smb-protocols $target -oN $output_dir/smb_protocols.txt

# Security mode
nmap -p445 --script smb-security-mode $target -oN $output_dir/smb_security.txt

# Share enumeration
nmap -p445 --script smb-enum-shares $target -oN $output_dir/smb_shares.txt

# Session enumeration
nmap -p445 --script smb-enum-sessions $target -oN $output_dir/smb_sessions.txt

echo "SMB enumeration complete. Results saved to $output_dir/"
```

## 🎯 Complete SMB Enumeration Workflow Summary

Based on the comprehensive lab demonstration, here's the complete SMB reconnaissance methodology using Nmap scripts:

### Phase 1: Basic Discovery
```bash
# 1. Verify target connectivity
ping -c 5 demo.ine.local

# 2. Identify open SMB ports
nmap demo.ine.local

# 3. Detect SMB protocols and dialects
nmap -p445 --script smb-protocols demo.ine.local
```

### Phase 2: Security Assessment
```bash
# 4. Analyze authentication requirements
nmap -p445 --script smb-security-mode demo.ine.local

# 5. Enumerate active sessions (anonymous)
nmap -p445 --script smb-enum-sessions demo.ine.local
```

### Phase 3: Authenticated Enumeration
```bash
# 6. Share discovery with credentials
nmap -p445 --script smb-enum-shares --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local

# 7. User enumeration
nmap -p445 --script smb-enum-users --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local

# 8. Group membership analysis
nmap -p445 --script smb-enum-groups --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local

# 9. Domain information gathering
nmap -p445 --script smb-enum-domains --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local

# 10. Service enumeration
nmap -p445 --script smb-enum-services --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local

# 11. Server statistics
nmap -p445 --script smb-server-stats --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local

# 12. File system browsing
nmap -p445 --script smb-enum-shares,smb-ls --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
```

### Key Intelligence Gathered:
- **Protocol Vulnerabilities:** SMBv1 enabled (EternalBlue potential)
- **Authentication Weaknesses:** Guest access, disabled message signing
- **Access Control Issues:** Administrative shares accessible, IPC$ writeable
- **User Intelligence:** 3 accounts identified with privilege mapping
- **System Profiling:** Windows Server 2012/2016 with AWS services
- **File System Access:** Complete C: drive browsability
- **Service Attack Surface:** Multiple services for potential exploitation

This comprehensive enumeration provides sufficient intelligence for the next phases of penetration testing including vulnerability assessment and exploitation planning.

## 📚 Additional Resources

### Official Documentation:
- Nmap NSE Documentation: https://nmap.org/nsedoc/
- SMB Script Reference: https://nmap.org/nsedoc/scripts/smb-security-mode.html
- Nmap Scripting Engine: https://nmap.org/book/nse.html

### Learning Resources:
- eJPT SMB Enumeration Labs: INE Security Training Platform
- SMB Protocol Deep Dive: Microsoft SMB/CIFS Technical Reference
- Practical SMB Testing: SANS SEC560 Course Materials

### Community Resources:
- Nmap Scripting Forum: https://seclists.org/nmap-dev/
- Penetration Testing Communities: r/netsec, r/AskNetsec
- eJPT Study Groups: Discord channels and Telegram groups

### Related Tools:
- **SMBClient:** Direct SMB share access and file operations
- **Enum4Linux:** Comprehensive Linux-based SMB enumeration
- **RPCClient:** RPC endpoint enumeration and testing
- **NBTScan:** NetBIOS name service enumeration
