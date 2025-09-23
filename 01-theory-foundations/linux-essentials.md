# 🐧 Linux Essentials - Complete eJPT Foundations Guide

**Master essential Linux skills for penetration testing and eJPT certification success**
**Location:** `01-theory-foundations/linux-essentials.md`

## 🎯 What are Linux Essentials?

Linux Essentials encompass the fundamental command-line skills, file operations, and system understanding required for effective penetration testing. This comprehensive guide combines basic commands, file permissions management, and network operations - the three pillars of Linux proficiency needed for eJPT success.

For penetration testers, Linux mastery is non-negotiable as most security tools run on Linux platforms, compromised systems often require command-line interaction, and the eJPT exam extensively tests these foundational skills across all practical scenarios.

## 📦 Core Components Overview

### Essential Linux Skills Categories:
1. **System Navigation & File Operations (35%)**
   - Directory navigation and file manipulation
   - Text processing and content analysis
   - Process and system information gathering

2. **File Permissions & Security (30%)**
   - Permission analysis and modification
   - SUID/SGID identification for privilege escalation
   - Ownership and security configuration

3. **Network Operations (35%)**
   - Connectivity testing and network discovery
   - Service enumeration and port scanning
   - DNS resolution and network configuration

## 🔧 System Navigation & File Operations

### Essential Navigation Commands:
```bash
# Directory Operations
pwd                           # Print current working directory
ls -la                        # List files with detailed permissions
cd /path/to/directory         # Change directory
cd ~                          # Navigate to home directory
cd -                          # Return to previous directory

# File System Exploration
find / -name "filename" 2>/dev/null    # Search for files system-wide
find /home -type f -name "*.txt"       # Find text files in home directories
find / -perm -4000 2>/dev/null         # Find SUID files (privilege escalation)
locate filename                        # Quick file search using database
which command                          # Find command location
whereis command                        # Locate binary, source, manual
```

### File Content Analysis:
```bash
# Viewing File Contents
cat /etc/passwd               # Display user accounts
cat /etc/hosts               # View host entries
less /var/log/syslog         # Paginated file viewing
tail -f /var/log/auth.log    # Monitor file changes in real-time
head -n 20 logfile.txt       # Display first 20 lines

# Text Processing for Security Analysis
grep "Failed password" /var/log/auth.log    # Find failed login attempts
grep -r "password" /etc/ 2>/dev/null        # Search for password references
grep -i "error" /var/log/* 2>/dev/null      # Case-insensitive error search
cut -d: -f1 /etc/passwd                     # Extract usernames only
sort /etc/passwd | uniq                     # Remove duplicate entries
wc -l /etc/passwd                           # Count user accounts
```

### File Manipulation:
```bash
# File and Directory Operations
mkdir -p /path/to/nested/dir  # Create nested directories
cp -r source_dir dest_dir     # Copy directories recursively
mv old_name new_name          # Rename files/directories
rm -rf directory              # Force remove directory and contents
touch filename                # Create empty file or update timestamp

# Content Creation and Editing
echo "text content" > file.txt          # Create file with content
echo "additional text" >> file.txt      # Append to file
nano filename                            # Simple text editor
vi filename                              # Advanced text editor
```

## 🔐 File Permissions & Security

### Understanding Permission Structure:
```bash
# Permission Format: -rwxrwxrwx
# Position 1: File type (- = file, d = directory, l = link)
# Positions 2-4: Owner permissions (rwx)
# Positions 5-7: Group permissions (rwx)  
# Positions 8-10: Other permissions (rwx)

# Permission Types:
# r (read): View file contents or list directory contents
# w (write): Modify file contents or create/delete files in directory
# x (execute): Run file as program or access directory
```

### Permission Analysis Commands:
```bash
# View Detailed Permissions
ls -la filename                         # Show permissions, ownership, timestamps
stat filename                           # Detailed file information
stat -c "%a %n" filename               # Show octal permissions

# Example Output Analysis:
# -rw-r--r-- 1 user group 1024 Jan 15 10:30 document.txt
# d = directory, - = regular file
# rw- = owner can read/write, no execute
# r-- = group can only read
# r-- = others can only read
```

### Security-Focused Permission Discovery:
```bash
# Critical Security Checks
find / -perm -4000 -type f 2>/dev/null          # SUID files (run as owner)
find / -perm -2000 -type f 2>/dev/null          # SGID files (run as group)
find / -perm -1000 -type d 2>/dev/null          # Sticky bit directories
find / -type f -perm -002 2>/dev/null           # World-writable files
find / -type d -writable 2>/dev/null            # Writable directories
find /home -type f -readable 2>/dev/null        # Readable files in home dirs

# Common SUID Files for Privilege Escalation:
# /usr/bin/passwd - Change user passwords
# /usr/bin/sudo - Execute commands as other users
# /usr/bin/su - Switch user identity
# /bin/ping - ICMP packets (requires root privileges)
```

### Permission Modification:
```bash
# Symbolic Permission Changes
chmod u+x script.sh              # Add execute for owner
chmod g-w filename               # Remove write for group
chmod o=r filename               # Set read-only for others
chmod a+r filename               # Add read for all users

# Octal Permission Changes
chmod 755 script.sh              # rwxr-xr-x (executable script)
chmod 644 document.txt           # rw-r--r-- (readable document)
chmod 600 private_key            # rw------- (private file)
chmod 777 shared_dir             # rwxrwxrwx (full access - dangerous!)

# Ownership Changes (requires appropriate privileges)
chown user:group filename        # Change owner and group
chown -R user:group directory    # Recursive ownership change
chgrp newgroup filename          # Change group only
```

## 🌐 Network Operations

### Network Configuration Analysis:
```bash
# Interface Information
ifconfig                         # Display all network interfaces
ifconfig eth0                    # Show specific interface
ip addr show                     # Modern interface information
ip link show                     # Show link layer information

# Routing and Network Path
route -n                         # Display routing table
ip route show                    # Modern routing information
traceroute target_host           # Trace network path to target
tracepath target_host            # Alternative path tracing
```

### Connectivity Testing:
```bash
# ICMP Testing
ping -c 4 8.8.8.8               # Test connectivity to Google DNS
ping -c 1 192.168.1.1           # Test gateway connectivity
ping -I eth0 target_ip           # Ping from specific interface

# TCP/UDP Port Testing
nc -zv target_ip 80              # Test TCP port 80
nc -zuv target_ip 53             # Test UDP port 53
telnet target_ip 22              # Interactive TCP connection test
timeout 3 bash -c "</dev/tcp/target_ip/port" # Bash TCP test

# Port Scanning with Built-in Tools
for port in 21 22 23 25 53 80 110 443 993 995; do
    nc -zv target_ip $port 2>&1 | grep succeeded
done
```

### DNS Operations:
```bash
# DNS Resolution
nslookup domain.com              # Basic DNS lookup
nslookup domain.com 8.8.8.8     # Use specific DNS server
dig domain.com A                 # Query A records
dig domain.com MX                # Query mail exchange records
dig -x 8.8.8.8                  # Reverse DNS lookup
host domain.com                  # Simple hostname resolution

# DNS Configuration Analysis
cat /etc/resolv.conf             # Check DNS servers
cat /etc/hosts                   # Check local host entries
```

### Network Service Discovery:
```bash
# Local Service Analysis
netstat -tulpn                   # Show listening services
netstat -tulpn | grep LISTEN     # Only listening services
ss -tulpn                        # Modern netstat replacement
lsof -i                          # Files opened by network connections
lsof -i :80                      # Processes using port 80

# Network Connection Analysis
netstat -an                      # All network connections
ss -an                          # Modern connection listing
netstat -rn                     # Routing table numeric
```

### File Transfer Operations:
```bash
# Web-based File Transfer
wget http://example.com/file.txt              # Download file
wget -r http://example.com/directory/         # Recursive download
curl -O http://example.com/file.txt           # Download with curl
curl -I http://example.com                    # HTTP headers only
curl -X POST -d "data" http://example.com     # POST request

# Secure File Transfer
scp file.txt user@host:/tmp/                  # Secure copy to remote
scp user@host:/tmp/file.txt .                 # Secure copy from remote
rsync -avz source/ user@host:/destination/    # Synchronized transfer

# Network File Sharing
python3 -m http.server 8080                  # Simple HTTP server
nc -l -p 1234 < file.txt                     # Send file via netcat
nc target_ip 1234 > received_file.txt        # Receive file via netcat
```

## 🧪 Real Lab Examples

### Example 1: Complete System Assessment
```bash
# Step 1: System Information Gathering
whoami                          # Current user: pentester
id                             # User ID and groups
uname -a                       # Kernel and system info
hostname                       # System hostname
uptime                         # System uptime and load

# Step 2: Network Configuration Analysis
ifconfig | grep -E "(inet|ether)"    # IP and MAC addresses
route -n | grep "^0.0.0.0"          # Default gateway
cat /etc/resolv.conf                  # DNS configuration
netstat -tulpn | grep ":22"         # SSH service check

# Step 3: File System Security Analysis
find / -perm -4000 2>/dev/null | head -10    # SUID files
find /home -type f -readable 2>/dev/null     # Readable files
ls -la /etc/passwd /etc/shadow               # User account files
find /tmp -type f -executable 2>/dev/null    # Executable files in /tmp

# Step 4: Service and Process Analysis
ps aux | grep -v grep                        # Running processes
netstat -tulpn | grep LISTEN                # Listening services
lsof -i | grep LISTEN                       # Network listeners
```

### Example 2: Log Analysis and Incident Investigation
```bash
# Authentication Log Analysis
tail -n 100 /var/log/auth.log                      # Recent auth events
grep "Failed password" /var/log/auth.log           # Failed login attempts
grep "Accepted password" /var/log/auth.log         # Successful logins
grep "sudo:" /var/log/auth.log                     # Sudo usage

# System Log Analysis
tail -f /var/log/syslog                            # Monitor system logs
grep -i "error\|warning" /var/log/syslog          # System errors
grep "kernel:" /var/log/syslog                     # Kernel messages

# Web Server Log Analysis (if applicable)
tail -n 50 /var/log/apache2/access.log            # Web access logs
grep "404" /var/log/apache2/access.log            # Not found errors
grep -E "POST|PUT" /var/log/apache2/access.log    # Write operations
```

### Example 3: Privilege Escalation Discovery
```bash
# SUID Binary Analysis
find / -perm -4000 2>/dev/null | while read file; do
    ls -la "$file"
    echo "GTFOBins check: https://gtfobins.github.io/gtfobins/$(basename $file)/"
done

# Writable Directory Discovery
find / -type d -writable 2>/dev/null | grep -v "/proc\|/sys"

# Cron Job Analysis
crontab -l                                         # User cron jobs
cat /etc/crontab                                   # System cron jobs
ls -la /etc/cron.d/                               # Additional cron files

# Sudo Privileges Check
sudo -l                                            # Available sudo commands
cat /etc/sudoers 2>/dev/null                      # Sudoers configuration
```

## 🎯 eJPT Exam Focus

### Critical Skills Distribution:
- **File Operations & Navigation (25%)** - Essential for all practical tasks
- **Permission Analysis (20%)** - Key for privilege escalation scenarios
- **Network Discovery (20%)** - Foundation for all network-based attacks
- **Service Enumeration (20%)** - Critical for identifying attack vectors
- **System Information Gathering (15%)** - Required for situational awareness

### Must-Know Command Combinations:
```bash
# System Reconnaissance One-Liners
ps aux | grep -v grep | wc -l                     # Count running processes
netstat -tulpn | grep -c LISTEN                   # Count listening services
find / -perm -4000 2>/dev/null | wc -l           # Count SUID files
cat /etc/passwd | cut -d: -f1 | wc -l            # Count user accounts

# Security Assessment Commands
find /home -name "*.txt" -readable 2>/dev/null    # Find readable text files
grep -r "password" /home/ 2>/dev/null | head -5   # Search for passwords
find / -name "*.conf" -readable 2>/dev/null       # Find config files
ls -la /etc/cron* /var/spool/cron 2>/dev/null    # Check scheduled tasks
```

### eJPT Exam Scenarios:
1. **Post-Exploitation System Assessment:**
   - Commands: `whoami`, `id`, `uname -a`, `ifconfig`, `netstat -tulpn`
   - Expected outcome: Complete system and network understanding
   - Time allocation: 5-10 minutes

2. **Privilege Escalation Discovery:**
   - Commands: `find / -perm -4000`, `sudo -l`, `crontab -l`, `find / -writable`
   - Expected outcome: Identification of escalation vectors
   - Time allocation: 10-15 minutes

3. **Network Service Enumeration:**
   - Commands: `netstat -tulpn`, `nc -zv`, `telnet`, `curl -I`
   - Expected outcome: Service identification and basic enumeration
   - Time allocation: 10-15 minutes

### Exam Tips and Best Practices:
- **Always redirect errors:** Use `2>/dev/null` to clean command output
- **Combine commands effectively:** Master pipe (|) usage for complex operations
- **Use time-saving shortcuts:** `!!` for last command, `!$` for last argument
- **Document findings quickly:** Use `tee` to save output while displaying
- **Practice command recall:** Use `history` and reverse search (Ctrl+R)

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Permission Denied Errors
**Problem:** Cannot access files or execute commands due to insufficient permissions
**Solution:**
```bash
# Check current user context
whoami && id

# Verify file permissions
ls -la problematic_file

# Use alternative approaches
find / -name "*filename*" -readable 2>/dev/null    # Find readable alternatives
sudo command                                        # Use elevated privileges if available
```

### Issue 2: Command Not Found
**Problem:** Essential commands are not available or not in PATH
**Solution:**
```bash
# Check command availability
which command_name
whereis command_name

# Check PATH variable
echo $PATH

# Use alternative commands
# netstat → ss
# ifconfig → ip addr
# route → ip route
```

### Issue 3: Network Commands Failing
**Problem:** Network commands timeout or fail to connect
**Solution:**
```bash
# Check network connectivity
ping -c 1 8.8.8.8                                 # Test external connectivity
ping -c 1 $(route -n | grep "^0.0.0.0" | awk '{print $2}')  # Test gateway

# Verify network configuration
ip addr show | grep "inet "                        # Check IP addresses
ip route show | grep default                       # Check default route
```

### Issue 4: Large Output Overwhelming Terminal
**Problem:** Commands produce too much output to analyze effectively
**Solution:**
```bash
# Use output control
command | head -20                                 # Limit to first 20 lines
command | tail -20                                 # Show last 20 lines
command | grep "pattern"                          # Filter relevant content
command | less                                     # Paginated viewing

# Save output for analysis
command > output.txt                               # Save to file
command | tee output.txt                          # Display and save
```

## 🔗 Integration with Penetration Testing Tools

### Linux Commands → Nmap Integration:
```bash
# Network discovery feeds nmap targets
ping -c 1 192.168.1.1 && nmap -sn 192.168.1.0/24
netstat -rn | grep "^0.0.0.0" | awk '{print $2}' | xargs nmap -sS

# Service discovery enhances nmap scanning
netstat -tulpn | grep ":80" && nmap -sV -p80 localhost
```

### Linux Commands → Metasploit Integration:
```bash
# System info gathering for exploit selection
uname -a | grep -i ubuntu                         # OS identification for exploit matching
ps aux | grep apache                              # Service identification for targeting
```

### Linux Commands → Manual Testing:
```bash
# File permission analysis guides manual exploitation
find / -perm -4000 2>/dev/null | xargs ls -la     # SUID analysis
find /var/www -type f -writable 2>/dev/null       # Web application file permissions
```

## 📝 Documentation and Reporting

### Evidence Collection Templates:
```bash
#!/bin/bash
# Linux Assessment Evidence Collection Script

echo "=== SYSTEM INFORMATION ===" > linux_assessment.txt
echo "Date: $(date)" >> linux_assessment.txt
echo "Assessor: $(whoami)" >> linux_assessment.txt
echo "" >> linux_assessment.txt

echo "--- System Details ---" >> linux_assessment.txt
uname -a >> linux_assessment.txt
hostname >> linux_assessment.txt
uptime >> linux_assessment.txt
echo "" >> linux_assessment.txt

echo "--- Network Configuration ---" >> linux_assessment.txt
ifconfig >> linux_assessment.txt
route -n >> linux_assessment.txt
cat /etc/resolv.conf >> linux_assessment.txt
echo "" >> linux_assessment.txt

echo "--- Security Analysis ---" >> linux_assessment.txt
echo "SUID Files:" >> linux_assessment.txt
find / -perm -4000 2>/dev/null >> linux_assessment.txt
echo "" >> linux_assessment.txt
echo "Listening Services:" >> linux_assessment.txt
netstat -tulpn | grep LISTEN >> linux_assessment.txt
echo "" >> linux_assessment.txt

echo "Assessment completed. Review linux_assessment.txt for details."
```

### Report Structure for eJPT:
```markdown
## Linux System Assessment

### Target Information
- **Hostname:** target_hostname
- **Operating System:** Linux distribution and version
- **Assessment Date:** timestamp
- **User Context:** current_user_privileges

### System Configuration
- **Network Interfaces:** IP addresses and network configuration
- **Routing:** Default gateway and routing table
- **DNS Configuration:** DNS servers and host entries

### Security Analysis
- **User Accounts:** Total count and privileged users
- **SUID/SGID Files:** Count and security implications
- **Network Services:** Listening services and potential attack vectors
- **File Permissions:** Writable locations and misconfigurations

### Key Findings
- **Critical Issues:** High-impact security vulnerabilities
- **Medium Issues:** Moderate security concerns
- **Low Issues:** Minor security observations

### Recommendations
- **Immediate Actions:** Critical security fixes
- **Short-term Improvements:** Security enhancements
- **Long-term Strategies:** Security architecture improvements
```

### Command Reference Quick Card:
```bash
# Navigation Essentials
pwd; ls -la; cd /path; find / -name "file" 2>/dev/null

# Permission Analysis  
ls -la; find / -perm -4000 2>/dev/null; chmod +x file

# Network Operations
ifconfig; netstat -tulpn; ping -c 4 target; nc -zv target port

# System Information
whoami; id; uname -a; ps aux; route -n

# File Operations
cat file; grep "pattern" file; head -20 file; tail -f file
```

This comprehensive Linux Essentials guide consolidates all fundamental skills needed for eJPT success, providing both theoretical knowledge and practical command examples essential for penetration testing scenarios.
