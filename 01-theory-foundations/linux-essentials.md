# 🐧 Linux Essentials for eJPT - Complete Command Line Mastery Guide

**Document Path:** `01-theory-foundations/linux-essentials.md`  

## 📋 Table of Contents
1. [Introduction & Objectives](#introduction--objectives)
2. [Linux Foundation Concepts](#linux-foundation-concepts)
3. [File System Navigation & Management](#file-system-navigation--management)
4. [Text Processing & Data Analysis](#text-processing--data-analysis)
5. [Process & System Management](#process--system-management)
6. [Permissions & Security](#permissions--security)
7. [Network Commands](#network-commands)
8. [Advanced Command Techniques](#advanced-command-techniques)
9. [Practical Lab Scenarios](#practical-lab-scenarios)
10. [eJPT Exam Focus](#ejpt-exam-focus)
11. [Quick Reference Cards](#quick-reference-cards)

---

## 🎯 Introduction & Objectives

### Why Linux Commands Matter for Pentesting
- **95%** of penetration testing tools run on Linux
- **Essential** for post-exploitation activities
- **Required** for log analysis and evidence collection
- **Fundamental** for understanding target systems

### Learning Objectives
- Navigate Linux file systems with confidence
- Analyze system configurations and log files
- Manage processes and system resources
- Configure network settings and troubleshoot connectivity
- Apply security concepts through file permissions
- Automate repetitive tasks with command combinations

---

## 🏗️ Linux Foundation Concepts

### File System Hierarchy Standard (FHS)
```
/                      # Root directory - everything starts here
├── bin/               # Essential user binaries (ls, cp, mv)
├── boot/              # Boot loader files and kernel
├── dev/               # Device files (/dev/sda1, /dev/null)
├── etc/               # System configuration files
│   ├── passwd         # User account information
│   ├── shadow         # Encrypted passwords
│   ├── group          # Group information
│   ├── hosts          # Host name resolution
│   └── crontab        # Scheduled tasks
├── home/              # User home directories
├── lib/               # Essential shared libraries
├── tmp/               # Temporary files (cleared on reboot)
├── usr/               # User programs and data
├── var/               # Variable data
│   ├── log/           # System log files
│   ├── www/           # Web server data
│   └── spool/         # Queued data
└── root/              # Root user home directory
```

### Command Structure
```bash
command [options] [arguments]

# Example breakdown:
ls -la /home/user
│  │   └── argument (path)
│  └── options (long format + hidden files)
└── command
```

### Essential Concepts
| Concept | Description | Example |
|---------|-------------|---------|
| **Absolute Path** | Full path from root | `/home/user/file.txt` |
| **Relative Path** | Path from current directory | `../file.txt` |
| **Hidden Files** | Files starting with dot | `.bashrc`, `.ssh/` |
| **Wildcards** | Pattern matching | `*.txt`, `file?` |

---

## 📁 File System Navigation & Management

### Core Navigation Commands

#### Directory Navigation
```bash
# Show current location
pwd                          # Print Working Directory

# List directory contents
ls                           # Basic listing
ls -l                        # Long format with permissions
ls -la                       # Include hidden files
ls -lah                      # Human-readable sizes
ls -lt                       # Sort by modification time
ls -lS                       # Sort by file size

# Change directory
cd /path/to/directory        # Absolute path
cd relative/path             # Relative path
cd ..                        # Parent directory
cd ~                         # Home directory
cd -                         # Previous directory
```

#### File Operations
```bash
# Create files and directories
touch filename               # Create empty file
mkdir dirname                # Create directory
mkdir -p path/to/nested/dir  # Create nested directories

# View file contents
cat filename                 # Display entire file
less filename                # Page through file
head filename                # First 10 lines
tail filename                # Last 10 lines
tail -f filename             # Follow file changes

# Copy, move, delete
cp source destination        # Copy file
cp -r source_dir dest_dir    # Copy directory recursively
mv oldname newname           # Move/rename
rm filename                  # Remove file
rm -rf directory             # Remove directory recursively
```

### File Searching
```bash
# Find command - the Swiss Army knife
find /path -name "filename"      # Find by name
find /path -name "*.txt"         # Find by pattern
find /path -type f               # Files only
find /path -type d               # Directories only
find /path -size +100M           # Files larger than 100MB
find /path -mtime -7             # Modified in last 7 days
find /path -perm 755             # By permissions
find /path -user username        # By owner

# Other search tools
locate filename              # Fast database search
which command                # Find command location
whereis command              # Find binaries and manuals
```

---

## 📝 Text Processing & Data Analysis

### Pattern Matching with Grep
```bash
# Basic grep operations
grep "pattern" file.txt          # Search for pattern
grep -i "pattern" file.txt       # Case-insensitive
grep -v "pattern" file.txt       # Invert match (exclude)
grep -n "pattern" file.txt       # Show line numbers
grep -r "pattern" /path/         # Recursive search

# Advanced patterns
grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" file.txt  # IP addresses
grep "^pattern" file.txt         # Start of line
grep "pattern$" file.txt         # End of line
```

### Text Processing Tools

#### AWK - Pattern Scanning
```bash
# Basic AWK operations
awk '{print $1}' file.txt        # Print first field
awk '{print $1, $3}' file.txt    # Print specific fields
awk -F: '{print $1}' /etc/passwd # Use colon as separator
awk '/pattern/' file.txt         # Lines matching pattern

# Advanced examples
awk '{sum+=$1} END {print sum}' numbers.txt    # Sum first column
awk 'length($0) > 80' file.txt                # Lines longer than 80 chars
```

#### SED - Stream Editor
```bash
# Basic SED operations
sed 's/old/new/' file.txt        # Replace first occurrence
sed 's/old/new/g' file.txt       # Replace all occurrences
sed -i 's/old/new/g' file.txt    # In-place editing
sed -n '5p' file.txt             # Print line 5 only
sed '/pattern/d' file.txt        # Delete lines matching pattern
```

#### Sort and Unique Operations
```bash
# Sort operations
sort file.txt                    # Alphabetical sort
sort -n file.txt                 # Numerical sort
sort -r file.txt                 # Reverse sort
sort -k2 file.txt                # Sort by 2nd field

# Unique operations
uniq file.txt                    # Remove consecutive duplicates
uniq -c file.txt                 # Count occurrences
sort file.txt | uniq -c | sort -nr  # Count and sort by frequency
```

#### Cut and Field Extraction
```bash
# Cut operations
cut -d: -f1 /etc/passwd          # Extract first field
cut -d: -f1,3 /etc/passwd        # Extract fields 1 and 3
cut -c1-10 file.txt              # Extract characters 1-10
```

---

## ⚙️ Process & System Management

### Process Information and Control

#### Viewing Processes
```bash
# Basic process listing
ps                               # Processes in current terminal
ps aux                           # All processes, detailed
ps aux --sort=-%cpu              # Sort by CPU usage
ps aux --sort=-%mem              # Sort by memory usage
ps -ef                           # Full format listing

# Process tree
pstree                           # Process tree view
pstree -p                        # Include process IDs

# Real-time monitoring
top                              # Real-time process monitor
htop                             # Enhanced version (if available)
```

#### Process Control
```bash
# Starting processes
command &                        # Run in background
nohup command &                  # Run immune to hangups

# Job control
jobs                             # List active jobs
fg                               # Foreground last job
bg                               # Background last job

# Stopping processes
kill PID                         # Send TERM signal
kill -9 PID                      # Send KILL signal (force)
killall process_name             # Kill all by name
pkill -f pattern                 # Kill by pattern
```

### System Information Commands
```bash
# System details
uname -a                         # All system information
hostname                         # System hostname
uptime                           # System uptime and load
whoami                           # Current username
id                               # User and group IDs
who                              # Logged in users

# Hardware information
lscpu                            # CPU information
lsblk                            # Block devices
free -h                          # Memory usage
df -h                            # Disk usage

# Environment
env                              # Environment variables
echo $PATH                       # PATH variable
```

---

## 🔒 Permissions & Security

### Understanding Permissions
```bash
# Permission structure
-rwxrwxrwx
│││││││││
│││└┴┴─── Other permissions (r=read, w=write, x=execute)
││└┴──── Group permissions  
│└───── Owner permissions
└────── File type

# Numeric representation
r = 4, w = 2, x = 1
755 = rwxr-xr-x (7=rwx, 5=r-x, 5=r-x)
644 = rw-r--r-- (6=rw-, 4=r--, 4=r--)
```

### Permission Commands
```bash
# Viewing permissions
ls -l filename                   # Show file permissions
ls -ld directory                 # Show directory permissions

# Changing permissions
chmod 755 filename               # Numeric method
chmod u+x filename               # Add execute for owner
chmod g-w filename               # Remove write for group
chmod -R 644 directory           # Recursive change

# Changing ownership
chown user filename              # Change owner
chown user:group filename        # Change owner and group
chgrp group filename             # Change group only
```

### Special Permissions
```bash
# SUID (Set User ID)
find / -perm -4000 2>/dev/null   # Find SUID files
chmod 4755 filename              # Set SUID

# SGID (Set Group ID) 
find / -perm -2000 2>/dev/null   # Find SGID files
chmod 2755 filename              # Set SGID

# Sticky bit
chmod 1755 directory             # Set sticky bit
```

### User and Group Management
```bash
# User information
whoami                           # Current username
id                               # User and group IDs
groups                           # Current user groups

# Important files
cat /etc/passwd                  # User accounts
cat /etc/shadow                  # Encrypted passwords (requires sudo)
cat /etc/group                   # Group information
```

---

## 🌐 Network Commands

### Network Interface Information
```bash
# Modern tools (ip command)
ip addr show                     # Show all interfaces
ip route show                    # Show routing table
ip neighbor show                 # Show ARP table

# Legacy tools
ifconfig                         # Show interfaces
route -n                         # Show routing table
arp -a                           # Show ARP table
```

### Network Connectivity
```bash
# Basic connectivity
ping -c 4 google.com             # Ping with count limit
traceroute google.com            # Trace route to destination

# DNS resolution
nslookup google.com              # DNS lookup
dig google.com                   # Detailed DNS info
host google.com                  # Simple DNS lookup

# Port testing
nc -zv hostname port             # Test port connectivity
telnet hostname port             # Interactive connection
```

### Network Services and Connections
```bash
# Active connections
netstat -tuln                    # TCP/UDP listening ports
netstat -tulnp                   # Include process info
ss -tuln                         # Modern alternative to netstat
ss -tulnp                        # Include process info

# Process and port information
lsof -i                          # All network connections
lsof -i :22                      # Connections on port 22
lsof -i tcp:80                   # TCP connections on port 80
```

---

## 🚀 Advanced Command Techniques

### Command Chaining
```bash
# Command sequencing
command1 && command2             # Run command2 if command1 succeeds
command1 || command2             # Run command2 if command1 fails
command1 ; command2              # Run command2 regardless

# Examples
mkdir newdir && cd newdir        # Create and enter directory
ls file.txt || touch file.txt   # Create if doesn't exist
```

### Input/Output Redirection
```bash
# Output redirection
command > file.txt               # Redirect to file (overwrite)
command >> file.txt              # Redirect to file (append)
command 2> error.log             # Redirect errors only
command > output.txt 2>&1        # Redirect both stdout and stderr

# Pipes
command1 | command2              # Pipe output to next command
command1 | tee file.txt | command2  # Save to file and continue pipe
```

### Advanced Text Processing
```bash
# Log analysis examples
cat /var/log/apache2/access.log | \
    awk '{print $1}' | \
    sort | uniq -c | \
    sort -nr | head -10          # Top 10 IP addresses

# Find large files
find /var/log -type f -exec du -h {} \; | \
    sort -hr | head -20          # 20 largest files

# System resource analysis
ps aux | sort -nrk 3,3 | head -5    # Top CPU processes
ps aux | sort -nrk 4,4 | head -5    # Top memory processes
```

### File Compression
```bash
# TAR archives
tar -cvf archive.tar files/      # Create tar archive
tar -czvf archive.tar.gz files/  # Create compressed archive
tar -xvf archive.tar             # Extract archive

# ZIP operations
zip -r archive.zip files/        # Create zip archive
unzip archive.zip                # Extract zip archive

# Other compression
gzip file.txt                    # Compress file
gunzip file.txt.gz               # Decompress file
```

---

## 🧪 Practical Lab Scenarios

### Scenario 1: System Information Gathering
```bash
# Complete reconnaissance script
echo "=== SYSTEM RECONNAISSANCE ==="
echo "Date: $(date)"
echo "User: $(whoami)"
echo "System: $(uname -a)"
echo ""

echo "=== NETWORK INFO ==="
hostname -I 2>/dev/null || ip addr show | grep "inet "
ss -tuln | grep LISTEN | head -5
echo ""

echo "=== USER INFO ==="
who
cat /etc/passwd | tail -3
echo ""

echo "=== PROCESSES ==="
ps aux --sort=-%cpu | head -5
```

### Scenario 2: Log Analysis
```bash
# Security log analysis
echo "=== SECURITY ANALYSIS ==="

# Failed login attempts
echo "Failed login attempts:"
grep "Failed password" /var/log/auth.log 2>/dev/null | \
    awk '{print $11}' | sort | uniq -c | sort -nr | head -5

# SSH connections
echo "SSH connections:"
grep "Accepted password" /var/log/auth.log 2>/dev/null | tail -5

# Web server analysis
echo "Suspicious web requests:"
grep -E "(union|select|script)" /var/log/apache2/access.log 2>/dev/null | tail -3
```

### Scenario 3: Network Analysis
```bash
# Network diagnostic script
echo "=== NETWORK DIAGNOSTICS ==="

# Connectivity tests
ping -c 1 8.8.8.8 > /dev/null 2>&1 && echo "Internet: OK" || echo "Internet: FAILED"
ping -c 1 google.com > /dev/null 2>&1 && echo "DNS: OK" || echo "DNS: FAILED"

# Interface status
echo "Interfaces:"
ip addr show | grep -E "^[0-9]+:|inet "

# Active services
echo "Listening services:"
ss -tuln | grep LISTEN | head -5
```

---

## 🎯 eJPT Exam Focus

### Critical Skills for eJPT Success

#### File System Navigation (25% of exam weight)
**Must master:**
- Quick directory navigation
- Efficient file searching
- Understanding file hierarchy

**Essential commands:**
```bash
find /etc -name "*ssh*" -type f      # Find SSH configs
ls -la $(which nmap)                 # Command details
cd /var/www/html && find . -name "*.php"  # Web exploration
```

#### Text Processing (20% of exam weight)
**Key abilities:**
- Extract information from files
- Search through multiple files
- Process log files efficiently

**Critical commands:**
```bash
grep -r "password" /etc/             # Find password references
awk -F: '$3 >= 1000 {print $1}' /etc/passwd  # Regular users
tail -f /var/log/auth.log | grep ssh # Monitor SSH
```

#### Process Management (15% of exam weight)
**Important skills:**
- Monitor running processes
- Control process execution
- Identify suspicious activity

**Key commands:**
```bash
ps aux --sort=-%cpu | head -5        # Top CPU processes
lsof -i :80                          # What's using port 80
kill -9 $(pgrep suspicious_process)  # Force kill process
```

#### Network Analysis (15% of exam weight)
**Network skills:**
- Identify listening services
- Analyze connections
- Troubleshoot connectivity

**Essential commands:**
```bash
ss -tuln | grep :22                  # SSH service check
netstat -tulnp | grep :80            # Web service check
nc -zv target 80                     # Port connectivity test
```

#### Permissions & Security (15% of exam weight)
**Security focus:**
- Understand permission implications
- Find privilege escalation opportunities
- Analyze file ownership

**Security commands:**
```bash
find / -perm -4000 2>/dev/null       # SUID binaries
find /etc -writable 2>/dev/null      # Writable configs
ls -la /etc/passwd /etc/shadow       # Critical files
```

#### System Information (10% of exam weight)
**Information gathering:**
- Collect system details
- Identify services
- Map system architecture

**Info commands:**
```bash
uname -a; cat /etc/*release; whoami; id  # System fingerprint
ps aux | grep -E "(apache|mysql|ssh)"    # Service discovery
```

### Exam Success Tips

#### Time Management
- Practice commands until they become muscle memory
- Use tab completion efficiently
- Learn keyboard shortcuts (Ctrl+R for history)

#### Common Pitfalls to Avoid
```bash
# Wrong - relative paths in exam
find . -name config.txt

# Correct - absolute paths
find /etc -name config.txt

# Wrong - messy output
find / -name "*.conf"

# Correct - clean output
find / -name "*.conf" 2>/dev/null
```

#### Scoring Strategy
Focus practice time based on exam weight:
1. **File System** (25%) - Most important
2. **Text Processing** (20%) - High impact
3. **Process Management** (15%) - Medium priority
4. **Network** (15%) - Medium priority
5. **Security** (15%) - Critical for pentesting
6. **System Info** (10%) - Quick wins

---

## 🔖 Quick Reference Cards

### Essential Commands Summary

#### File Operations
| Command | Purpose | Example |
|---------|---------|---------|
| `ls -la` | List with permissions | `ls -la /etc/` |
| `find` | Search files | `find /etc -name "*.conf"` |
| `grep -r` | Search in files | `grep -r "password" /etc/` |
| `cat` | Display file | `cat /etc/passwd` |
| `tail -f` | Follow changes | `tail -f /var/log/syslog` |

#### Process Management
| Command | Purpose | Example |
|---------|---------|---------|
| `ps aux` | List processes | `ps aux \| grep apache` |
| `top` | Real-time monitor | `top -o %CPU` |
| `kill` | Terminate process | `kill -9 1234` |
| `lsof` | Open files | `lsof -i :80` |

#### Network Commands
| Command | Purpose | Example |
|---------|---------|---------|
| `ss -tuln` | Network connections | `ss -tuln \| grep :80` |
| `ping` | Test connectivity | `ping -c 4 google.com` |
| `netstat` | Network statistics | `netstat -tulnp` |

#### System Information
| Command | Purpose | Example |
|---------|---------|---------|
| `uname -a` | System info | `uname -a` |
| `whoami` | Current user | `whoami` |
| `df -h` | Disk usage | `df -h` |
| `free -h` | Memory usage | `free -h` |

### Permission Quick Reference

| Numeric | Symbolic | Meaning |
|---------|----------|---------|
| `755` | `rwxr-xr-x` | Owner: full, Others: read+execute |
| `644` | `rw-r--r--` | Owner: read+write, Others: read |
| `600` | `rw-------` | Owner only: read+write |
| `777` | `rwxrwxrwx` | All: full permissions |

### Common One-Liners

#### System Analysis
```bash
# System overview
echo "System: $(uname -a)"; echo "Users: $(who | wc -l)"; echo "Load: $(uptime)"

# Top processes by CPU
ps aux --sort=-%cpu | head -5 | awk '{printf "%-15s %s\n", $1, $11}'

# Disk usage summary
df -h | awk '$5+0 > 80 {print $5, $6}'
```

#### Network Analysis
```bash
# Active connections summary
ss -tuln | grep LISTEN | awk '{print $5}' | cut -d: -f2 | sort -n | uniq -c

# Top IPs from access log
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -nr | head -5
```

#### Security Checks
```bash
# Failed login attempts by IP
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr

# Find SUID files
find / -perm -4000 2>/dev/null | grep -v '/usr/bin/\(passwd\|su\|sudo\)'
```

---

**Remember:** Practice these commands regularly, understand their output, and learn to chain them together for complex analysis tasks. The key to eJPT success is building muscle memory and confidence with these essential Linux skills.

**Good luck with your eJPT preparation!**
