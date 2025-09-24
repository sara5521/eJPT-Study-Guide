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

# Try legacy key exchange methods for older SSH versions
ssh -o KexAlgorithms=+diffie-hellman-group1-sha1 user@target
```

### Issue 4: Host Key Verification Failures
**Problem:** Host key verification fails preventing connection
**Solution:**
```bash
# Disable host key checking (for testing only)
ssh -o StrictHostKeyChecking=no user@target

# Remove problematic host key
ssh-keygen -R target
```

## 🔗 Integration with Other Tools

### Primary Integration: Nmap → SSH Enumeration → Hydra
```bash
# Step 1: Discover SSH service (from lab context)
nmap -p 22 -sV 192.180.108.3
# Output: 22/tcp open ssh OpenSSH 7.4

# Step 2: Enumerate SSH details
nmap --script ssh-hostkey,ssh-auth-methods -p 22 192.180.108.3
# Output: SSH configuration and authentication methods

# Step 3: Test authentication if needed
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.180.108.3
```

### Secondary Integration: SSH → Post-Exploitation
```bash
# After successful SSH access
ssh user@target

# Enumerate system information
uname -a
whoami
id
cat /etc/passwd
```

### Advanced Workflows:
```bash
# Comprehensive SSH enumeration pipeline
#!/bin/bash
target=$1

echo "=== SSH Service Discovery ==="
nmap -p 22,2222,22022 -sV $target

echo "=== SSH Banner Grabbing ==="
timeout 5 nc $target 22

echo "=== SSH Host Key Enumeration ==="
nmap --script ssh-hostkey -p 22 $target

echo "=== SSH Authentication Methods ==="
nmap --script ssh-auth-methods -p 22 $target

echo "=== Common Credential Testing ==="
for user in root admin user guest; do
    timeout 10 sshpass -p $user ssh -o ConnectTimeout=5 $user@$target "whoami" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[+] Success: $user:$user"
    fi
done
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** SSH connection attempts and banner information
2. **Command Outputs:** Nmap results and SSH client verbose output
3. **Version Information:** SSH server version and configuration details
4. **Authentication Results:** Successful login attempts and credentials

### Report Template Structure:
```markdown
## SSH Enumeration Results

### Target Information
- Target: 192.180.108.3
- Service: SSH/22 (OpenSSH 7.4)
- Date/Time: 2024-11-26 13:08 IST
- Protocol: SSH-2.0

### Commands Executed
```bash
# Service discovery
nmap -p 22 -sV 192.180.108.3

# Banner grabbing
nc 192.180.108.3 22

# Host key enumeration
nmap --script ssh-hostkey -p 22 192.180.108.3
```

### SSH Service Details
- **Version:** OpenSSH 7.4 (protocol 2.0)
- **Host Key Types:** RSA, ECDSA, ED25519
- **Authentication Methods:** password, publickey
- **Encryption:** AES, ChaCha20
- **MAC:** HMAC-SHA2-256, HMAC-SHA2-512

### Security Assessment
- **Version Analysis:** OpenSSH 7.4 released 2016 (check for known CVEs)
- **Authentication:** Password authentication enabled
- **Key Exchange:** Modern algorithms supported
- **Potential Vulnerabilities:** User enumeration possible, brute force attacks viable

### Recommendations
- Update to latest OpenSSH version
- Disable password authentication where possible
- Implement fail2ban or similar brute force protection
- Use strong authentication methods (keys, 2FA)
- Consider changing default SSH port
```

### Automation Scripts:
```bash
# SSH enumeration automation script
#!/bin/bash
TARGET=$1
OUTPUT_DIR="ssh-enum-$(date +%Y%m%d-%H%M%S)"
mkdir $OUTPUT_DIR

echo "Starting SSH enumeration of $TARGET"

# Service discovery on common SSH ports
echo "[+] Discovering SSH services..."
nmap -p 22,2222,22022 -sV $TARGET > $OUTPUT_DIR/service_discovery.txt

# Extract SSH port if found
SSH_PORT=$(grep -E "22.*ssh" $OUTPUT_DIR/service_discovery.txt | head -1 | awk '{print $1}' | cut -d'/' -f1)

if [ ! -z "$SSH_PORT" ]; then
    echo "[+] SSH found on port $SSH_PORT"
    
    # Banner grabbing
    echo "[+] Grabbing SSH banner..."
    timeout 3 nc $TARGET $SSH_PORT > $OUTPUT_DIR/banner.txt 2>&1
    
    # NSE script enumeration
    echo "[+] Running NSE scripts..."
    nmap --script ssh-hostkey,ssh-auth-methods -p $SSH_PORT $TARGET > $OUTPUT_DIR/nse_results.txt
    
    # Test common credentials
    echo "[+] Testing common credentials..."
    for user in root admin user guest; do
        for pass in $user password 123456; do
            echo "Testing $user:$pass" >> $OUTPUT_DIR/auth_tests.txt
            timeout 5 sshpass -p $pass ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no $user@$TARGET "echo 'Login successful'" >> $OUTPUT_DIR/auth_tests.txt 2>&1
        done
    done
    
    echo "[+] SSH enumeration complete! Results in $OUTPUT_DIR/"
else
    echo "[-] No SSH service found on target"
fi
```

## 📚 Additional Resources

### Official Documentation:
- OpenSSH Documentation: https://www.openssh.com/manual.html
- SSH RFC 4251: https://tools.ietf.org/html/rfc4251
- SSH Security Best Practices: https://stribika.github.io/2015/01/04/secure-secure-shell.html

### Learning Resources:
- SSH protocol deep dive and security analysis
- SSH key management and authentication methods
- SSH tunneling and port forwarding techniques

### Community Resources:
- HackTricks SSH enumeration: https://book.hacktricks.xyz/pentesting/pentesting-ssh
- SSH security hardening guides
- SSH penetration testing methodologies

### Related Tools:
- ssh-audit: SSH configuration and security scanner
- ssh-keyscan: Bulk SSH host key collection
- paramiko: Python SSH library for custom tools
