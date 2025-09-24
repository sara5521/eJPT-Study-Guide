# 🔧 SSH Enumeration - Secure Shell Service Analysis

SSH (Secure Shell) enumeration involves identifying SSH services, version detection, user enumeration, and testing authentication methods.
**Location:** `05-service-enumeration/ssh-enumeration.md`

## 🎯 What is SSH Enumeration?

SSH enumeration is the process of analyzing SSH services to identify versions, supported authentication methods, and potential security vulnerabilities. This is a critical skill for both legitimate penetration testing and understanding SSH security.

## 📦 Installation and Setup

SSH enumeration typically uses tools already available on most Linux systems:

```bash
# Verify SSH client is available
ssh -V
# Output: OpenSSH_8.x, OpenSSL x.x.x

# Install additional tools if needed
apt install hydra nmap

# Verify nmap NSE scripts for SSH
ls /usr/share/nmap/scripts/ssh*
```

## 🔧 Basic Usage and Syntax

### Command Structure:
```bash
# Basic SSH service detection (building on lab context)
nmap -p 22 -sV target

# Banner grabbing
nc target 22
telnet target 22
```

## ⚙️ Command Line Options

### Nmap SSH Scripts:
| Option | Purpose | Example |
|--------|---------|---------|
| `ssh-hostkey` | Get SSH host key information | `nmap --script ssh-hostkey -p 22 target` |
| `ssh-auth-methods` | Enumerate authentication methods | `nmap --script ssh-auth-methods -p 22 target` |
| `ssh-brute` | SSH brute force attack | `nmap --script ssh-brute -p 22 target` |

### SSH Client Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-v` | Verbose output | `ssh -v user@target` |
| `-p port` | Specify port | `ssh -p 2222 user@target` |
| `-o option` | Set SSH option | `ssh -o PreferredAuthentications=password user@target` |

## 🧪 Real Lab Examples

### Example 1: SSH Service Discovery and Banner Grabbing
```bash
# Based on lab context showing SSH service on port 22
# Step 1: Service identification  
nmap -p 22 -sV 192.180.108.3
# Output: 22/tcp open ssh OpenSSH 7.4 (protocol 2.0)

# Step 2: Banner grabbing with netcat
nc 192.180.108.3 22
# Output: SSH-2.0-OpenSSH_7.4

# Step 3: Get detailed SSH information
nmap --script ssh-hostkey,ssh-auth-methods -p 22 192.180.108.3
# Output: Host keys, supported authentication methods
```

### Example 2: SSH User Enumeration
```bash
# Check for common usernames
ssh root@192.180.108.3
# Note: Connection attempt and response timing

ssh admin@192.180.108.3
ssh user@192.180.108.3

# Automated user enumeration with hydra
hydra -L users.txt -p password ssh://192.180.108.3
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **Service identification (30%)** - Detecting SSH services and versions
- **Banner analysis (25%)** - Understanding SSH version information
- **Authentication testing (25%)** - Testing common credentials
- **Vulnerability assessment (20%)** - Identifying SSH security issues

### Critical Commands to Master:
```bash
# Must-know commands for exam
nmap -p 22 -sV target                              # SSH service detection
nc target 22                                       # Banner grabbing  
ssh user@target                                    # Connection testing
nmap --script ssh-hostkey -p 22 target            # Host key information
```

### eJPT Exam Scenarios:
1. **SSH Service Discovery:** Identify SSH services in network scanning
   - Required skills: Port scanning, service version detection
   - Expected commands: nmap with service detection flags
   - Success criteria: Identify SSH version and configuration

2. **SSH Authentication Testing:** Test for weak SSH credentials
   - Required skills: Common credential testing, brute force basics
   - Expected commands: Manual SSH attempts, basic automation
   - Success criteria: Identify accessible SSH accounts

### Exam Tips and Tricks:
- **Check default ports:** SSH commonly runs on ports 22, 2222, 22022
- **Note SSH versions:** Older versions may have known vulnerabilities
- **Test common credentials:** root/root, admin/admin, user/user
- **Document banner information:** SSH version strings provide valuable intel

### Common eJPT Questions:
- Identify SSH service version on target systems
- Test for default or weak SSH credentials
- Determine SSH authentication methods available

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Connection Refused
**Problem:** SSH service not responding
**Solution:**
```bash
# Check if SSH is running on different ports
nmap -p 22,2222,22022 target

# Verify service is actually SSH
nmap -sV -p 22 target
```

### Issue 2: Authentication Method Restrictions
**Problem:** Cannot connect due to authentication restrictions
**Solution:**
```bash
# Check supported authentication methods
nmap --script ssh-auth-methods -p 22 target

# Try different authentication methods
ssh -o PreferredAuthentications=password user@target
ssh -o PreferredAuthentications=publickey user@target
```

### Issue 3: Key Exchange Issues
**Problem:** SSH connection fails during key exchange
**Solution:**
```bash
# Use verbose mode to debug
ssh -vvv user@target

# Try legacy key exchange methods for older
