---
title: "Linux Essentials for eJPT"
topic: "Linux Command Line"
exam_objective: "Command line proficiency for penetration testing operations"
difficulty: "Medium"
tools:
  - "bash"
  - "grep"
  - "find"
  - "awk"
  - "sed"
related_labs:
  - "networking-fundamentals.md"
  - "information-gathering-basics.md"
file_path: "01-theory-foundations/linux-essentials.md"
last_updated: "2025-09-29"
tags:
  - "linux"
  - "command-line"
  - "file-system"
  - "text-processing"
  - "bash"
---

# 🐧 Linux Essentials for eJPT - Complete Command Line Guide

**Master the Linux command line skills you need for successful penetration testing**

**📍 File Location:** `01-theory-foundations/linux-essentials.md`

---

## 🎯 What Are Linux Essentials?

Linux is the main operating system used in penetration testing. Almost all hacking tools run on Linux, and you'll use Linux commands during every phase of a penetration test. This guide teaches you the exact Linux skills you need for the eJPT exam and real-world pentesting.

### 🔍 **Why Linux Commands Matter:**
- **95% of pentest tools** run on Linux (Kali, Parrot OS)
- **Essential for exam success** - you'll use Linux in almost every question
- **Required for real work** - log analysis, system exploration, exploit deployment
- **Foundation skill** - everything else builds on this knowledge

### 💡 **What You'll Learn:**
- Navigate file systems quickly and confidently
- Search for files and information efficiently
- Analyze log files and configuration files
- Manage processes and system resources
- Use network commands for reconnaissance
- Chain commands together for powerful results

---

## 📦 What You Need to Start

### **Already Have Everything On:**
- ✅ Kali Linux (main pentesting OS)
- ✅ Parrot Security OS
- ✅ Any Linux system
- ✅ Windows WSL (Windows Subsystem for Linux)

### **Check Your System:**
```bash
# See what system you're using
uname -a
# Output: Linux kali 5.10.0-kali9-amd64 #1 SMP Debian x86_64 GNU/Linux

# Check your shell
echo $SHELL
# Output: /bin/bash

# See your username
whoami
# Output: kali
```

### **What Everything Means:**
- **Terminal:** The black window where you type commands
- **Shell:** The program that runs your commands (usually bash)
- **Command:** Instructions you type to make the computer do something
- **Directory:** Same as a folder in Windows

---

## 🏗️ Understanding the Linux File System

### **File System Structure:**
```
/                           # Root - the very top of everything
├── bin/                    # Basic commands everyone can use (ls, cat, cp)
├── boot/                   # Files needed to start the computer
├── dev/                    # Hardware devices (hard drives, USB)
├── etc/                    # System configuration files - IMPORTANT FOR PENTESTING
│   ├── passwd              # List of all users
│   ├── shadow              # Encrypted passwords (need root to read)
│   ├── hosts               # Computer names and IP addresses
│   └── ssh/                # SSH server configuration
├── home/                   # User home folders
│   └── kali/               # Your home folder
├── root/                   # Root user's home folder
├── tmp/                    # Temporary files (deleted on reboot)
├── usr/                    # Programs and applications
│   └── share/              # Shared data (like wordlists)
├── var/                    # Files that change often - IMPORTANT FOR PENTESTING
│   ├── log/                # System and application logs
│   └── www/                # Web server files
└── opt/                    # Optional software installations
```

### **Important Directories for Pentesting:**

| Directory | What's Inside | Why It Matters |
|-----------|---------------|----------------|
| `/etc/` | Configuration files | Find passwords, service settings, user accounts |
| `/var/log/` | System logs | See what happened, find evidence, analyze activity |
| `/tmp/` | Temporary files | Upload and run exploits (usually writable) |
| `/home/` | User files | Find user data, SSH keys, bash history |
| `/root/` | Root's files | High-value target for privilege escalation |

### **Path Types Explained:**

```bash
# Absolute path - starts from root (/)
/home/kali/Documents/report.txt
# Always works, no matter where you are

# Relative path - starts from where you are now
Documents/report.txt
# Only works if you're in /home/kali/

# Special paths
.           # Current directory (where you are now)
..          # Parent directory (one level up)
~           # Your home directory (/home/kali)
-           # Previous directory (where you just were)
```

---

## 📁 Moving Around and Managing Files

### **Basic Navigation:**

#### **Where Am I? Where Can I Go?**
```bash
# Show current location
pwd
# Output: /home/kali

# List files in current directory
ls
# Output: Desktop  Documents  Downloads

# List with details
ls -l
# Output: drwxr-xr-x 2 kali kali 4096 Sep 29 10:30 Desktop

# Show hidden files (start with .)
ls -a
# Output: .  ..  .bash_history  .ssh  Desktop

# Best option - detailed with hidden files and readable sizes
ls -lah
# Output: drwxr-xr-x  2 kali kali 4.0K Sep 29 10:30 Desktop
```

#### **Moving Between Directories:**
```bash
# Go to specific directory
cd /etc
# Now you're in: /etc

# Go to your home directory
cd ~
# Now you're in: /home/kali

# Go up one level
cd ..
# If you were in /home/kali, now you're in /home

# Go back to previous directory
cd -
# Returns to wherever you just were

# Quick navigation examples
cd /var/log              # Go to log directory
cd ~/Desktop             # Go to Desktop in your home
cd ../../etc             # Go up two levels then into etc
```

### **Working With Files:**

#### **Creating and Viewing Files:**
```bash
# Create empty file
touch newfile.txt
# Creates: newfile.txt with 0 bytes

# Create directory
mkdir myfolder
# Creates: myfolder directory

# Create nested directories at once
mkdir -p hack/tools/scripts
# Creates: hack, then tools inside it, then scripts inside that

# View entire file
cat filename.txt
# Shows everything at once

# View file page by page (better for big files)
less filename.txt
# Press Space for next page, q to quit

# View first 10 lines
head filename.txt
# Shows: first 10 lines

# View last 10 lines
tail filename.txt
# Shows: last 10 lines

# Watch file changes in real-time (great for logs)
tail -f /var/log/auth.log
# Updates automatically when new lines added
```

#### **Copying, Moving, Deleting:**
```bash
# Copy file
cp source.txt destination.txt
# Result: destination.txt is copy of source.txt

# Copy directory (need -r for recursive)
cp -r folder1 folder2
# Result: folder2 is copy of folder1 with all contents

# Move or rename file
mv oldname.txt newname.txt
# Result: file renamed to newname.txt

mv file.txt /tmp/
# Result: file moved to /tmp/ directory

# Delete file
rm file.txt
# Result: file.txt is deleted (careful - no trash bin!)

# Delete directory and everything in it
rm -rf folder
# Result: folder and all contents deleted
# WARNING: This is permanent! Double-check before using!
```

### **Finding Files:**

#### **Find Command - Your Best Friend:**
```bash
# Find by name
find /etc -name "passwd"
# Searches: /etc directory for file named "passwd"
# Output: /etc/passwd

# Find by pattern (use wildcards)
find /var/log -name "*.log"
# Searches: all files ending in .log
# Output: Lists all log files

# Find only files (not directories)
find /home -type f -name "*.txt"
# Result: Only text files, not folders

# Find only directories
find /etc -type d -name "ssh*"
# Result: Only directories with names starting with ssh

# Find large files (over 100MB)
find /var -size +100M
# Result: Files bigger than 100 megabytes

# Find recently modified files (last 7 days)
find /home -mtime -7
# Result: Files changed in past week

# Find files with specific permissions
find /usr/bin -perm 4755
# Result: Files with SUID bit set (important for privilege escalation)

# Hide error messages (clean output)
find / -name "config.xml" 2>/dev/null
# Result: Only shows results, hides "Permission denied" errors
```

#### **Other Search Tools:**
```bash
# Locate - fast database search
locate passwd
# Output: All files with "passwd" in name (very fast)

# Which - find command location
which nmap
# Output: /usr/bin/nmap

# Whereis - find binaries and manuals
whereis nmap
# Output: nmap: /usr/bin/nmap /usr/share/man/man1/nmap.1.gz
```

---

## 📝 Searching and Processing Text

### **Grep - Search Inside Files:**

#### **Basic Grep Operations:**
```bash
# Search for word in file
grep "password" file.txt
# Shows: All lines containing "password"

# Case-insensitive search (ignore UPPER/lower case)
grep -i "password" file.txt
# Finds: password, Password, PASSWORD, etc.

# Show line numbers
grep -n "error" logfile.txt
# Output: 45: ERROR: Connection failed
#         78: ERROR: Timeout occurred

# Search all files in directory
grep -r "admin" /etc/
# Searches: Every file under /etc/ for "admin"

# Invert match (show lines that DON'T match)
grep -v "success" results.txt
# Shows: Only lines without "success"

# Count matches
grep -c "failed" auth.log
# Output: 23 (number of times "failed" appears)
```

#### **Practical Grep Examples:**
```bash
# Find IP addresses in file
grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" access.log
# Shows: All IP address patterns like 192.168.1.100

# Find lines starting with specific text
grep "^root" /etc/passwd
# Shows: Lines that begin with "root"

# Find lines ending with specific text
grep "sh$" /etc/passwd
# Shows: Lines ending with "sh" (shell users)

# Combine with other commands
cat /etc/passwd | grep "/bin/bash"
# Shows: Only users with bash shell
```

### **AWK - Column Processing:**

```bash
# Print first column
awk '{print $1}' file.txt
# Shows: First word from each line

# Print multiple columns
awk '{print $1, $3}' file.txt
# Shows: First and third words from each line

# Use different separator (default is space)
awk -F: '{print $1}' /etc/passwd
# Uses: colon as separator
# Shows: Just usernames from /etc/passwd

# Filter and print
awk '/root/ {print $0}' /etc/passwd
# Shows: Only lines containing "root"

# Sum numbers in column
awk '{sum+=$1} END {print sum}' numbers.txt
# Result: Total of all numbers in first column

# Print lines longer than 80 characters
awk 'length($0) > 80' file.txt
# Shows: Only long lines
```

### **Sed - Text Editing:**

```bash
# Replace text (first occurrence per line)
sed 's/old/new/' file.txt
# Changes: First "old" to "new" on each line

# Replace all occurrences
sed 's/old/new/g' file.txt
# Changes: Every "old" to "new"

# Edit file in place (save changes)
sed -i 's/old/new/g' file.txt
# Result: File permanently changed

# Delete lines matching pattern
sed '/error/d' logfile.txt
# Shows: File without lines containing "error"

# Print specific line
sed -n '10p' file.txt
# Shows: Only line 10
```

### **Sort and Unique:**

```bash
# Sort alphabetically
sort file.txt
# Output: Lines in A-Z order

# Sort numerically
sort -n numbers.txt
# Output: Lines in 1-9 order (not alphabetically)

# Sort in reverse
sort -r file.txt
# Output: Lines in Z-A order

# Remove duplicate lines (only works on sorted data)
sort file.txt | uniq
# Result: Each unique line appears once

# Count duplicates
sort file.txt | uniq -c
# Output: Number before each line shows how many times it appeared

# Most common items (sorted by frequency)
sort file.txt | uniq -c | sort -nr
# Result: Most frequent items at top
```

### **Cut - Extract Columns:**

```bash
# Extract first field (colon separator)
cut -d: -f1 /etc/passwd
# Shows: Just usernames

# Extract multiple fields
cut -d: -f1,3 /etc/passwd
# Shows: Username and user ID

# Extract by character position
cut -c1-10 file.txt
# Shows: First 10 characters of each line
```

---

## ⚙️ Managing Processes and System

### **Viewing Processes:**

```bash
# Show your processes
ps
# Output: Processes in your current terminal

# Show all processes (detailed)
ps aux
# Output: Every running process with full details
# Columns: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND

# Understand ps aux output:
# USER = who started it
# PID = process ID number
# %CPU = how much CPU it's using
# %MEM = how much memory it's using
# COMMAND = what program is running

# Sort by CPU usage
ps aux --sort=-%cpu
# Shows: Most CPU-intensive processes first

# Sort by memory usage
ps aux --sort=-%mem
# Shows: Most memory-hungry processes first

# Find specific process
ps aux | grep apache
# Shows: Only processes with "apache" in name

# Show process tree
pstree
# Output: Processes shown as parent-child relationships

# Real-time process monitor
top
# Updates every few seconds
# Press q to quit, h for help
```

### **Controlling Processes:**

```bash
# Run command in background
command &
# Example: nmap 192.168.1.0/24 &
# Result: Command runs, you get prompt back immediately

# Run command immune to logout
nohup command &
# Result: Process keeps running even if you disconnect

# See background jobs
jobs
# Output: [1]+ Running    nmap 192.168.1.0/24 &

# Bring job to foreground
fg
# Result: Last background job comes back to terminal

# Send job to background
bg
# Result: Paused job continues in background

# Stop process (graceful shutdown)
kill PID
# Example: kill 1234
# Result: Process 1234 receives termination signal

# Force kill process (immediate)
kill -9 PID
# Example: kill -9 1234
# Result: Process 1234 stopped immediately (no cleanup)

# Kill all processes by name
killall firefox
# Result: All firefox processes stopped

# Kill by pattern
pkill -f "python.*script"
# Result: All python scripts matching pattern stopped
```

### **System Information:**

```bash
# Show system details
uname -a
# Output: Linux version, architecture, kernel version

# Show computer name
hostname
# Output: kali

# System uptime and load
uptime
# Output: 10:30:45 up 2 days, 3:15, 1 user, load average: 0.5, 0.3, 0.2

# Current user
whoami
# Output: kali

# User and group info
id
# Output: uid=1000(kali) gid=1000(kali) groups=1000(kali),27(sudo)

# Who's logged in
who
# Output: kali tty7 2025-09-29 08:15

# CPU information
lscpu
# Output: CPU details, cores, speed, architecture

# Memory usage
free -h
# Output: Total, used, free memory in human-readable format
#              total        used        free      shared
# Mem:          7.7G        2.3G        4.1G        156M

# Disk usage
df -h
# Output: Disk space by partition
# Filesystem      Size  Used Avail Use% Mounted on
# /dev/sda1        50G   15G   33G  31% /

# Environment variables
env
# Shows: All environment settings

# Show PATH variable
echo $PATH
# Output: /usr/local/bin:/usr/bin:/bin:/usr/games
```

---

## 🔒 File Permissions and Security

### **Understanding Permissions:**

```
-rwxr-xr-x  1 kali kali 4096 Sep 29 10:30 script.sh
│││││││││  │  │    │    │    │
│││└┴┴─────┼──┼────┼────┼────┴─ Other: read + execute
││└┴───────┼──┼────┼────┴────── Group: read + execute  
│└─────────┼──┼────┴─────────── Owner: read + write + execute
└──────────┼──┴──────────────── File type: - = file, d = directory
           │
           └───────────────────── Number of links

Permission meanings:
r = read (4)    - can view file contents
w = write (2)   - can modify file
x = execute (1) - can run as program
- = no permission (0)
```

### **Common Permission Numbers:**

| Number | Permissions | Meaning | Use Case |
|--------|-------------|---------|----------|
| `755` | `rwxr-xr-x` | Owner can do everything, others can read/execute | Scripts, programs |
| `644` | `rw-r--r--` | Owner can read/write, others can only read | Text files, configs |
| `600` | `rw-------` | Only owner can read/write | Private files, SSH keys |
| `777` | `rwxrwxrwx` | Everyone can do everything | Rarely used (insecure) |
| `700` | `rwx------` | Only owner can do anything | Private directories |

### **Changing Permissions:**

```bash
# View permissions
ls -l filename
# Output: -rw-r--r-- 1 kali kali 1234 Sep 29 10:30 filename

# Change with numbers
chmod 755 script.sh
# Result: rwxr-xr-x (owner full, others read/execute)

# Change with letters
chmod u+x script.sh
# Result: Add execute for user (owner)

chmod g-w filename
# Result: Remove write for group

chmod o+r filename
# Result: Add read for others

# Change recursively (all files in directory)
chmod -R 644 myfolder/
# Result: All files in myfolder set to rw-r--r--

# Change owner
chown newuser filename
# Result: newuser now owns file

# Change owner and group
chown newuser:newgroup filename
# Result: newuser owns, newgroup is group

# Change group only
chgrp newgroup filename
# Result: Group changed to newgroup
```

### **Special Permissions (Important for Pentesting):**

```bash
# Find SUID files (run as owner, not current user)
find / -perm -4000 2>/dev/null
# Why important: Potential privilege escalation
# Example output: /usr/bin/passwd (runs as root)

# Find SGID files (run with group privileges)
find / -perm -2000 2>/dev/null
# Why important: Another escalation vector

# Find world-writable files (anyone can modify)
find / -perm -002 2>/dev/null
# Why important: May allow unauthorized modifications

# Set SUID bit
chmod 4755 filename
# Result: File runs with owner's privileges

# Set SGID bit
chmod 2755 filename
# Result: File runs with group's privileges

# Set sticky bit
chmod 1755 directory
# Result: Only owner can delete files in directory
```

### **User and Group Files:**

```bash
# User accounts
cat /etc/passwd
# Format: username:x:UID:GID:comment:home:shell
# Example: kali:x:1000:1000:Kali,,,:/home/kali:/bin/bash

# Encrypted passwords (requires root)
sudo cat /etc/shadow
# Format: username:encrypted_password:last_change:...
# Example: kali:$6$xyz...:18920:0:99999:7:::

# Group information
cat /etc/group
# Format: groupname:x:GID:members
# Example: sudo:x:27:kali

# Your groups
groups
# Output: kali sudo
```

---

## 🌐 Network Commands

### **Network Interface Info:**

```bash
# Show all network interfaces (modern way)
ip addr show
# Output: Shows all network cards with IP addresses
# Example:
# 2: eth0: <BROADCAST,MULTICAST,UP>
#     inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0

# Show routing table
ip route show
# Output: default via 192.168.1.1 dev eth0
#         192.168.1.0/24 dev eth0 scope link

# Show ARP table (IP to MAC mappings)
ip neighbor show
# Output: 192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE

# Old way (still works on many systems)
ifconfig
# Output: Similar to ip addr but older format

# Old routing table command
route -n
# Output: Routing table in old format

# Old ARP command
arp -a
# Output: ARP cache in old format
```

### **Testing Connectivity:**

```bash
# Test if host is reachable
ping -c 4 google.com
# -c 4 = send 4 packets then stop
# Output: Shows if packets reach destination and response time

# Trace route to destination
traceroute google.com
# Output: Shows each router hop along the way
# Example:
# 1  192.168.1.1 (192.168.1.1)  1.234 ms
# 2  10.0.0.1 (10.0.0.1)  10.456 ms
# 3  google.com (172.217.1.1)  15.789 ms

# DNS lookup
nslookup google.com
# Output: Shows IP address for domain name

# Detailed DNS info
dig google.com
# Output: Complete DNS query results with all records

# Simple DNS lookup
host google.com
# Output: google.com has address 172.217.1.1

# Test port connectivity with netcat
nc -zv target.com 80
# -z = scan mode (don't send data)
# -v = verbose
# Output: Connection to target.com 80 port [tcp/http] succeeded!

# Test with telnet
telnet target.com 80
# Result: Connects to port 80 if open
# Type: GET / HTTP/1.0 and press Enter twice to test web server
```

### **Active Connections:**

```bash
# Show listening ports (modern way)
ss -tuln
# -t = TCP
# -u = UDP  
# -l = listening
# -n = numeric (don't resolve names)
# Output: Shows all services waiting for connections

# Include process info (requires root)
sudo ss -tulnp
# -p = process
# Output: Shows which program is using each port

# Old way (still common)
netstat -tuln
# Output: Same info as ss but older command

# Show all connections (not just listening)
ss -tun
# Output: All active TCP/UDP connections

# Show what's using specific port
lsof -i :22
# Output: What process is using port 22
# Example: sshd 1234 root 3u IPv4 TCP *:ssh (LISTEN)

# Show all network connections for process
lsof -i -n -P
# -i = internet connections
# -n = don't resolve IPs
# -P = don't resolve ports
```

---

## 🚀 Advanced Techniques

### **Command Chaining:**

```bash
# Run second command only if first succeeds
mkdir newfolder && cd newfolder
# Result: Creates folder AND enters it (both must work)

# Run second command only if first fails
ls file.txt || touch file.txt
# Result: If file doesn't exist, create it

# Run both regardless
command1 ; command2
# Result: Runs command1, then command2 no matter what

# Practical examples
ping -c 1 target > /dev/null && echo "Host is up" || echo "Host is down"
# Result: Shows if host responds to ping

find /etc -name "*.conf" 2>/dev/null | wc -l
# Result: Count config files (hiding errors)
```

### **Input/Output Redirection:**

```bash
# Save output to file (overwrite)
command > output.txt
# Example: ls -la > filelist.txt

# Append to file
command >> output.txt
# Example: echo "New line" >> log.txt

# Redirect errors only
command 2> errors.log
# Result: Errors saved to errors.log, normal output shown

# Redirect both output and errors
command > output.txt 2>&1
# Result: Everything saved to output.txt

# Hide errors
command 2>/dev/null
# Result: Error messages disappear

# Pipe output to next command
command1 | command2
# Example: cat file.txt | grep "error"
# Result: Search file contents

# Save to file AND continue pipe
command1 | tee file.txt | command2
# Result: Saves output to file.txt and sends to command2
```

### **Practical Command Combinations:**

```bash
# Find top 10 IP addresses in log
cat access.log | awk '{print $1}' | sort | uniq -c | sort -nr | head -10
# Breaks down to:
# 1. Show log file
# 2. Extract first column (IP addresses)
# 3. Sort them
# 4. Count duplicates
# 5. Sort by count (highest first)
# 6. Show top 10

# Find largest files in directory
find /var/log -type f -exec du -h {} \; | sort -hr | head -20
# Result: 20 biggest files with sizes

# Find top CPU processes
ps aux | sort -nrk 3 | head -5
# Result: 5 processes using most CPU

# Find top memory processes  
ps aux | sort -nrk 4 | head -5
# Result: 5 processes using most memory

# Count files by type
find . -type f | sed 's/.*\.//' | sort | uniq -c | sort -nr
# Result: How many .txt, .jpg, etc files

# Find recently modified files
find /home -type f -mtime -1 -ls
# Result: Files changed in last 24 hours with details
```

### **File Compression:**

```bash
# Create tar archive
tar -cvf archive.tar folder/
# -c = create
# -v = verbose (show progress)
# -f = file name
# Result: archive.tar contains everything in folder/

# Create compressed archive
tar -czvf archive.tar.gz folder/
# -z = gzip compression
# Result: Smaller file size

# Extract tar archive
tar -xvf archive.tar
# -x = extract
# Result: Files extracted to current directory

# Extract to specific location
tar -xvf archive.tar -C /tmp/
# Result: Extracted to /tmp/

# List archive contents without extracting
tar -tvf archive.tar
# -t = list
# Result: Shows what's inside

# Create zip file
zip -r archive.zip folder/
# -r = recursive
# Result: archive.zip created

# Extract zip file
unzip archive.zip
# Result: Files extracted

# Compress single file
gzip file.txt
# Result: file.txt becomes file.txt.gz (original deleted)

# Decompress
gunzip file.txt.gz
# Result: Back to file.txt
```

---

## 🧪 Real Pentesting Scenarios

### **Scenario 1: Complete System Recon**

**Your Job:** Gather all basic info about the system you've accessed

**Time: 3-5 minutes**

```bash
#!/bin/bash
# Quick recon script

echo "=== SYSTEM RECONNAISSANCE ==="
echo "Date: $(date)"
echo ""

echo "=== WHO AM I? ==="
whoami
id
echo ""

echo "=== SYSTEM INFO ==="
uname -a
cat /etc/*-release | head -5
hostname
echo ""

echo "=== NETWORK INFO ==="
ip addr show | grep "inet " | grep -v "127.0.0.1"
ip route show | grep default
cat /etc/hosts | grep -v "^#" | grep -v "^$"
echo ""

echo "=== USERS ==="
cat /etc/passwd | grep "/bin/bash"
who
last -n 5
echo ""

echo "=== LISTENING SERVICES ==="
ss -tuln | grep LISTEN | head -10
echo ""

echo "=== RECENT PROCESSES ==="
ps aux --sort=-%cpu | head -5
echo ""

echo "=== WRITEABLE DIRECTORIES ==="
find / -writable -type d 2>/dev/null | grep -v "/proc" | head -10
```

**What This Gets You:**
- Current user and permissions
- Operating system version
- Network configuration
- Other users on system
- Running services
- Resource usage
- Potential upload locations

---

### **Scenario 2: Log File Analysis for Security Events**

**Your Job:** Find suspicious activity in system logs

**Time: 5-7 minutes**

```bash
#!/bin/bash
# Security log analysis

echo "=== SECURITY LOG ANALYSIS ==="
echo "Target: $1"
echo "Date: $(date)"
echo ""

# Failed login attempts
echo "=== FAILED LOGIN ATTEMPTS ==="
if [ -f /var/log/auth.log ]; then
    grep "Failed password" /var/log/auth.log | \
        awk '{print $(NF-3)}' | \
        sort | uniq -c | sort -nr | head -10
    echo "Total failed attempts: $(grep -c "Failed password" /var/log/auth.log)"
else
    echo "auth.log not found"
fi
echo ""

# Successful logins
echo "=== SUCCESSFUL SSH LOGINS ==="
if [ -f /var/log/auth.log ]; then
    grep "Accepted password" /var/log/auth.log | tail -10
else
    echo "auth.log not found"
fi
echo ""

# Suspicious commands in bash history
echo "=== SUSPICIOUS HISTORY ==="
if [ -f ~/.bash_history ]; then
    cat ~/.bash_history | grep -E "(nc|ncat|/dev/tcp|wget|curl|chmod|chown)" | tail -10
else
    echo "No bash history found"
fi
echo ""

# Web server suspicious requests
echo "=== SUSPICIOUS WEB REQUESTS ==="
if [ -f /var/log/apache2/access.log ]; then
    grep -E "(union|select|script|\.\.\/|exec)" /var/log/apache2/access.log | tail -10
elif [ -f /var/log/nginx/access.log ]; then
    grep -E "(union|select|script|\.\.\/|exec)" /var/log/nginx/access.log | tail -10
else
    echo "Web server logs not found"
fi
echo ""

# Port scans detected
echo "=== PORT SCAN ATTEMPTS ==="
if [ -f /var/log/syslog ]; then
    grep -i "port.*scan" /var/log/syslog | tail -5
else
    echo "syslog not found"
fi
```

**What This Shows:**
- Which IPs tried to login (and failed)
- Successful SSH connections
- Suspicious commands in history
- SQL injection or XSS attempts
- Possible port scans

---

### **Scenario 3: Finding Sensitive Information**

**Your Job:** Search system for passwords, keys, and sensitive files

**Time: 5-7 minutes**

```bash
#!/bin/bash
# Find sensitive information

echo "=== SEARCHING FOR SENSITIVE DATA ==="
echo ""

# Find files with "password" in name
echo "=== FILES WITH 'PASSWORD' IN NAME ==="
find / -name "*password*" -type f 2>/dev/null | head -20
echo ""

# Find SSH keys
echo "=== SSH KEYS ==="
find / -name "id_rsa" -o -name "id_dsa" -o -name "*.pem" 2>/dev/null
echo ""

# Search for passwords in files
echo "=== SEARCHING CONFIGS FOR PASSWORDS ==="
grep -r -i "password" /etc/ 2>/dev/null | grep -v "Binary" | head -10
echo ""

# Database config files
echo "=== DATABASE CONFIGS ==="
find / -name "database.yml" -o -name "db.config" -o -name "wp-config.php" 2>/dev/null
echo ""

# Check bash history for credentials
echo "=== CREDENTIALS IN HISTORY ==="
cat ~/.bash_history 2>/dev/null | grep -E "(password|passwd|pass=|pwd=)" | head -10
echo ""

# Readable shadow file (shouldn't happen but worth checking)
echo "=== CHECKING SHADOW FILE ==="
if [ -r /etc/shadow ]; then
    echo "WARNING: /etc/shadow is readable!"
    ls -la /etc/shadow
else
    echo "Shadow file protected (normal)"
fi
```

**What You Might Find:**
- SSH private keys for lateral movement
- Database credentials
- Password files
- Configuration with hardcoded passwords
- Backup files with sensitive data

---

### **Scenario 4: Network Service Discovery**

**Your Job:** Map all network services on the system

**Time: 3-5 minutes**

```bash
#!/bin/bash
# Network service enumeration

echo "=== NETWORK SERVICE DISCOVERY ==="
echo "Host: $(hostname)"
echo "Date: $(date)"
echo ""

# Listening TCP ports
echo "=== TCP SERVICES ==="
ss -tlnp 2>/dev/null | grep LISTEN | \
    awk '{print $4, $6}' | \
    sed 's/.*://' | \
    sort -n | head -20
echo ""

# Listening UDP ports
echo "=== UDP SERVICES ==="
ss -ulnp 2>/dev/null | \
    awk '{print $4, $5}' | \
    sed 's/.*://' | \
    sort -n | head -20
echo ""

# What processes own these ports
echo "=== PROCESS TO PORT MAPPING ==="
sudo lsof -i -P -n | grep LISTEN | head -10
echo ""

# Network connections
echo "=== ACTIVE CONNECTIONS ==="
ss -tn | grep ESTAB | awk '{print $4, $5}' | head -10
echo ""

# Firewall rules
echo "=== FIREWALL STATUS ==="
if command -v iptables >/dev/null 2>&1; then
    sudo iptables -L -n | head -20
else
    echo "iptables not found"
fi
```

**What This Reveals:**
- All listening services (potential attack surface)
- Which programs are using which ports
- Active connections to other systems
- Firewall configuration

---

## 🎯 eJPT Exam Success Guide

### **How Important Are These Skills?**

Understanding where Linux commands appear in the eJPT exam:

- **File System Navigation:** 25% of exam questions
- **Text Processing (grep, awk):** 20% of exam questions
- **Process Management:** 15% of exam questions
- **Network Commands:** 15% of exam questions
- **Permissions & Security:** 15% of exam questions
- **System Information:** 10% of exam questions

### **🏆 Commands You MUST Know:**

#### **Level 1 - Critical (You WILL see these):**

```bash
# Finding files - APPEARS IN 80% OF EXAMS
find /etc -name "*.conf" 2>/dev/null
# Why important: Locating config files is essential

# Searching file contents - APPEARS IN 75% OF EXAMS
grep -r "password" /etc/ 2>/dev/null
# Why important: Finding credentials and info

# Viewing files - APPEARS IN 90% OF EXAMS
cat /etc/passwd
cat /etc/shadow
# Why important: User enumeration

# Listing with permissions - APPEARS IN 85% OF EXAMS
ls -la /home
ls -la /var/www
# Why important: Understanding access and file structure

# Process listing - APPEARS IN 70% OF EXAMS
ps aux
ps aux | grep apache
# Why important: Finding running services
```

#### **Level 2 - Important (High probability):**

```bash
# Network connections - APPEARS IN 65% OF EXAMS
ss -tuln
netstat -tuln
# Why important: Service discovery

# File permissions - APPEARS IN 60% OF EXAMS
chmod 755 script.sh
find / -perm -4000 2>/dev/null
# Why important: Privilege escalation

# System info - APPEARS IN 55% OF EXAMS
uname -a
whoami
id
# Why important: Target identification

# Text processing - APPEARS IN 50% OF EXAMS
awk -F: '{print $1}' /etc/passwd
cut -d: -f1 /etc/passwd
# Why important: Extracting specific data

# Watching logs - APPEARS IN 45% OF EXAMS
tail -f /var/log/auth.log
tail -f /var/log/apache2/access.log
# Why important: Real-time monitoring
```

#### **Level 3 - Useful (Might appear):**

```bash
# Command chaining - APPEARS IN 40% OF EXAMS
command1 && command2
command1 | command2
# Why important: Efficient workflow

# Output redirection - APPEARS IN 35% OF EXAMS
command > output.txt
command 2>/dev/null
# Why important: Clean output and logging

# Advanced grep - APPEARS IN 30% OF EXAMS
grep -E "regex_pattern" file
grep -v "exclude_this" file
# Why important: Complex searches
```

### **🎯 Common eJPT Scenarios:**

#### **Scenario 1: User Enumeration**
**Question:** "How many users have bash shell access?"
**Time:** 2 minutes

```bash
# Method 1: Direct approach
cat /etc/passwd | grep "/bin/bash" | wc -l
# Output: 3

# Method 2: Using awk
awk -F: '$7 == "/bin/bash" {print $1}' /etc/passwd
# Output: root
#         kali
#         admin

# Method 3: List usernames only
cat /etc/passwd | grep "/bin/bash" | cut -d: -f1
# Output: root, kali, admin
```

**Common Mistakes:**
- Forgetting to check for `/bin/sh` as well
- Not using `2>/dev/null` when searching
- Counting system users by mistake

---

#### **Scenario 2: Finding Web Application Files**
**Question:** "Find all PHP files in the web directory"
**Time:** 3 minutes

```bash
# Step 1: Find web root
ls -la /var/www/
ls -la /var/www/html/

# Step 2: Find all PHP files
find /var/www -name "*.php" -type f
# Output: /var/www/html/index.php
#         /var/www/html/config.php
#         /var/www/html/login.php

# Step 3: Look for interesting files
find /var/www -name "*config*.php"
find /var/www -name "*admin*.php"
find /var/www -name "*backup*.php"

# Step 4: Check for writable files
find /var/www -writable -type f 2>/dev/null
```

---

#### **Scenario 3: Service Identification**
**Question:** "What service is running on port 8080?"
**Time:** 2 minutes

```bash
# Method 1: Using ss/netstat
ss -tlnp | grep :8080
# Output: tcp   LISTEN   0.0.0.0:8080   users:(("apache2",pid=1234))

# Method 2: Using lsof
sudo lsof -i :8080
# Output: apache2  1234  www-data  4u  IPv4  TCP *:8080 (LISTEN)

# Method 3: Process list
ps aux | grep 1234
# Output: www-data  1234  apache2 -k start

# Answer: Apache web server (PID 1234)
```

---

#### **Scenario 4: Log Analysis for Failed Logins**
**Question:** "Which IP address had the most failed login attempts?"
**Time:** 3-4 minutes

```bash
# Step 1: Check auth log exists
ls -la /var/log/auth.log

# Step 2: Find failed attempts
grep "Failed password" /var/log/auth.log

# Step 3: Extract IPs and count
grep "Failed password" /var/log/auth.log | \
    awk '{print $(NF-3)}' | \
    sort | uniq -c | sort -nr | head -1
# Output: 45 192.168.1.50

# Alternative method
grep "Failed password" /var/log/auth.log | \
    grep -oE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | \
    sort | uniq -c | sort -nr | head -1

# Answer: 192.168.1.50 with 45 failed attempts
```

---

#### **Scenario 5: Finding SUID Binaries**
**Question:** "List all SUID binaries on the system"
**Time:** 2-3 minutes

```bash
# Find SUID files (potential privilege escalation)
find / -perm -4000 -type f 2>/dev/null

# Common output:
# /usr/bin/passwd
# /usr/bin/sudo
# /usr/bin/pkexec
# /usr/lib/openssh/ssh-keysign

# Find unusual SUID files (exclude common ones)
find / -perm -4000 -type f 2>/dev/null | \
    grep -v -E "(passwd|sudo|su|pkexec|ssh-keysign)"

# Check if specific binary has SUID
ls -la /usr/bin/find
# If output starts with -rwsr-x--- then it has SUID
```

---

### **📝 eJPT Exam Tips:**

#### **⏰ Time Management Strategy:**
1. **Read question carefully** (15 seconds)
2. **Choose right command** (15 seconds)
3. **Execute and verify** (1-2 minutes)
4. **Document answer** (30 seconds)
5. **Move to next question** (no dwelling)

**Total per question: 2-3 minutes maximum**

#### **🎯 Exam Day Checklist:**

```bash
# Before starting, verify these work:
find / -name test 2>/dev/null       # File finding works
grep "test" /etc/passwd              # Grep works
ps aux | head                        # Process listing works
ss -tuln | head                      # Network commands work
ls -la /etc | head                   # Permissions visible

# If any fail, troubleshoot before starting exam
```

#### **Common Mistakes to Avoid:**

**❌ Wrong:**
```bash
# Mistake 1: Not hiding errors
find / -name config.txt
# Result: Screen filled with "Permission denied"

# Mistake 2: Relative paths in exams
find . -name config.txt
# Problem: Only searches current directory

# Mistake 3: Forgetting to count
grep "user" /etc/passwd
# Problem: Shows lines but doesn't count them

# Mistake 4: Wrong field separator
cut -f1 /etc/passwd
# Problem: Doesn't specify colon separator
```

**✅ Correct:**
```bash
# Fix 1: Hide errors
find / -name config.txt 2>/dev/null

# Fix 2: Use absolute paths
find /etc -name config.txt 2>/dev/null

# Fix 3: Count results
grep "user" /etc/passwd | wc -l

# Fix 4: Specify separator
cut -d: -f1 /etc/passwd
```

---

## ⚠️ Common Problems and Solutions

### **❌ Problem 1: Permission Denied Errors**
**What You See:**
```bash
find / -name "*.conf"
find: '/root': Permission denied
find: '/var/lib/private': Permission denied
# ... hundreds of error lines
```

**How to Fix:**
```bash
# Solution 1: Hide error messages
find / -name "*.conf" 2>/dev/null
# Result: Only shows files you can access

# Solution 2: Use sudo if available
sudo find / -name "*.conf"
# Result: Searches everything

# Solution 3: Search only accessible areas
find /home -name "*.conf"
find /var/www -name "*.conf"
# Result: Target specific directories
```

---

### **❌ Problem 2: Command Not Found**
**What You See:**
```bash
ifconfig
bash: ifconfig: command not found
```

**How to Fix:**
```bash
# Solution 1: Try modern alternative
ip addr show
# Modern systems use 'ip' instead of 'ifconfig'

# Solution 2: Find where command is
which ifconfig
whereis ifconfig
# May show: /usr/sbin/ifconfig

# Solution 3: Use full path
/usr/sbin/ifconfig
# Some commands need full path

# Solution 4: Check if installed
dpkg -l | grep net-tools
# ifconfig is in net-tools package
```

**Common Command Alternatives:**
| Old Command | New Alternative |
|-------------|-----------------|
| `ifconfig` | `ip addr show` |
| `route -n` | `ip route show` |
| `arp -a` | `ip neighbor show` |
| `netstat` | `ss` |

---

### **❌ Problem 3: File Not Found**
**What You See:**
```bash
cat /var/log/auth.log
cat: /var/log/auth.log: No such file or directory
```

**How to Fix:**
```bash
# Solution 1: Check if file exists
ls -la /var/log/ | grep auth
# May be named differently: auth.log, secure, authentication.log

# Solution 2: Find similar files
find /var/log -name "*auth*" -type f 2>/dev/null
# Shows all authentication-related logs

# Solution 3: Check alternative locations
cat /var/log/secure          # Red Hat/CentOS
cat /var/log/authentication  # Some systems
cat /var/log/syslog | grep ssh  # Combined log

# Solution 4: List all logs
ls -la /var/log/
# See what's actually available
```

---

### **❌ Problem 4: No Results from Search**
**What You See:**
```bash
grep "password" config.txt
# No output at all
```

**How to Fix:**
```bash
# Solution 1: Check if file has content
cat config.txt
# Verify file isn't empty

# Solution 2: Try case-insensitive search
grep -i "password" config.txt
# Finds: password, Password, PASSWORD, etc.

# Solution 3: Search for partial match
grep -i "pass" config.txt
# Broader search

# Solution 4: Check if pattern is too specific
grep ".*password.*" config.txt
# Use wildcards

# Solution 5: Verify file path
ls -la config.txt
# Make sure file exists and is readable
```

---

## 🔗 Using Commands Together

### **🎯 Complete Penetration Testing Workflows:**

#### **Workflow 1: Initial System Assessment**
```bash
# Quick one-liner for system overview
echo "System: $(uname -a)" && \
echo "User: $(whoami) ($(id))" && \
echo "IP: $(hostname -I)" && \
echo "Services: $(ss -tuln | grep LISTEN | wc -l)" && \
echo "Users: $(cat /etc/passwd | grep /bin/bash | wc -l)"

# Result: Complete system summary in seconds
```

#### **Workflow 2: Finding and Exploiting Weak Permissions**
```bash
# Step 1: Find writable directories
find / -writable -type d 2>/dev/null | grep -v "/proc" > writable_dirs.txt

# Step 2: Find SUID binaries
find / -perm -4000 -type f 2>/dev/null > suid_bins.txt

# Step 3: Check for weak file permissions
find /etc -writable -type f 2>/dev/null

# Step 4: Look for interesting files
find / -name "*password*" -o -name "*secret*" 2>/dev/null

# Step 5: Combine results for analysis
cat suid_bins.txt writable_dirs.txt | sort | uniq
```

#### **Workflow 3: Network Service Mapping**
```bash
# Complete network profile in one command chain
ss -tuln | grep LISTEN | awk '{print $5}' | \
    cut -d: -f2 | sort -n | uniq | \
    while read port; do
        echo -n "Port $port: "
        lsof -i :$port 2>/dev/null | tail -1 | awk '{print $1}'
    done

# Result: Port number mapped to service name
```

#### **Workflow 4: Log Analysis Pipeline**
```bash
# Analyze authentication events
cat /var/log/auth.log | \
    grep -E "(Failed|Accepted)" | \
    awk '{print $1, $2, $3, $11, $NF}' | \
    sort | uniq -c | sort -nr > auth_summary.txt

# Show results
cat auth_summary.txt | head -20

# Find suspicious patterns
cat auth_summary.txt | grep "Failed" | head -10
```

---

## 📊 Quick Reference Cards

### **Essential Commands - Copy This:**

```bash
# NAVIGATION (Use daily)
pwd                    # Where am I?
ls -lah               # Show everything
cd /path              # Go somewhere
find / -name file 2>/dev/null  # Find file

# TEXT SEARCH (Critical for exams)
grep "text" file.txt                    # Find in file
grep -r "text" /etc/ 2>/dev/null       # Find in directory
grep -i "text" file.txt                 # Ignore case
cat file.txt | grep "text" | wc -l     # Count matches

# FILE OPERATIONS (Basic skills)
cat file.txt          # View file
head file.txt         # First 10 lines
tail file.txt         # Last 10 lines
tail -f file.txt      # Watch changes
cp source dest        # Copy
mv old new            # Move/rename
rm file               # Delete

# SYSTEM INFO (Always needed)
whoami                # Current user
id                    # User details
uname -a              # System info
ps aux                # All processes
ps aux | grep name    # Find process

# NETWORK (Service discovery)
ss -tuln              # Listening ports
ss -tulnp             # With process info
ip addr show          # IP addresses
ping -c 4 host        # Test connection
nc -zv host port      # Test port

# PERMISSIONS (Security checks)
ls -la file           # Check permissions
chmod 755 file        # Change permissions
find / -perm -4000 2>/dev/null  # SUID files
find / -writable 2>/dev/null    # Writable files

# TEXT PROCESSING (Data extraction)
cut -d: -f1 /etc/passwd              # Extract column
awk '{print $1}' file.txt            # Print column
sed 's/old/new/g' file.txt           # Replace text
sort file.txt | uniq -c              # Count unique

# USEFUL COMBINATIONS (Exam savers)
command 2>/dev/null                  # Hide errors
command1 | command2                  # Pipe output
command && next_command              # Run if success
command > file.txt                   # Save output
```

### **One-Liners for Common Tasks:**

```bash
# Top 10 largest files
find / -type f -exec du -h {} \; 2>/dev/null | sort -hr | head -10

# Users with bash shells
awk -F: '$7 == "/bin/bash" {print $1}' /etc/passwd

# Count files by extension
find . -type f | sed 's/.*\.//' | sort | uniq -c | sort -nr

# Process using most CPU
ps aux --sort=-%cpu | head -2

# Most common IPs in log
awk '{print $1}' access.log | sort | uniq -c | sort -nr | head -10

# Find PHP files in web directory
find /var/www -name "*.php" -type f 2>/dev/null

# All listening services
ss -tuln | grep LISTEN | awk '{print $5}' | cut -d: -f2 | sort -n

# Failed SSH logins by IP
grep "Failed" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr
```

---

## 🎓 Study Tips and Memory Aids

### **Easy Ways to Remember:**

**FIND command = F.I.N.D.**
- **F**ile location
- **I**nformation gathering
- **N**ame or pattern
- **D**on't forget 2>/dev/null

**GREP command = G.R.E.P.**
- **G**et text from files
- **R**ecursive with -r
- **E**xtended regex with -E
- **P**ipe results to other commands

**LS options = L.A.H.**
- **L**ong format (-l)
- **A**ll files including hidden (-a)
- **H**uman readable sizes (-h)

**PS AUX = Process Status A.U.X.**
- **A**ll users
- **U**ser-oriented format
- **X**include processes without terminal

### **Practice Routine:**

**Week 1: Navigation**
- Practice cd, ls, pwd for 15 minutes daily
- Navigate entire filesystem
- Find files in different locations

**Week 2: Text Processing**
- Use grep, awk, cut on real files
- Practice on /etc/passwd
- Analyze log files

**Week 3: Process & Network**
- Practice ps, top, ss commands
- Identify running services
- Map network connections

**Week 4: Integration**
- Chain commands together
- Create one-liners
- Time yourself on tasks

---

## 📚 Learning More

### **Official Documentation:**
```bash
# Built-in help (always available)
man command        # Full manual
command --help     # Quick help
info command       # Info pages
```

### **Practice Environments:**
- **OverTheWire: Bandit** - Linux basics game
- **HackTheBox** - Real pentesting practice
- **TryHackMe** - Guided learning paths
- **Local VM** - Set up Kali or Ubuntu

### **Next Steps:**
1. Master these basics first
2. Learn bash scripting
3. Practice on CTF challenges
4. Build your own lab
5. Take the eJPT exam

---

## 🆘 Quick Help

### **When Commands Don't Work:**

1. **Check spelling:** Linux is case-sensitive
2. **Try sudo:** May need root privileges
3. **Check path:** Use full path if needed
4. **Hide errors:** Add `2>/dev/null`
5. **Read error:** Errors usually tell you the problem

### **Emergency Command List:**

```bash
# Lost? Start here:
pwd                          # Where am I?
ls -la                       # What's here?
whoami                       # Who am I?
id                          # What can I do?

# Can't find something?
find / -name "filename" 2>/dev/null
locate filename
which command

# Need help?
man command
command --help
command -h
```

---

## 📞 Final Notes for eJPT Success

**Remember These Key Points:**

1. **Practice daily** - 30 minutes is enough
2. **Use real systems** - Set up your own lab
3. **Time yourself** - Speed matters in exams
4. **Chain commands** - Efficiency wins
5. **Hide errors** - Clean output saves time
6. **Document results** - Take notes as you work

**eJPT Exam Reality:**
- You'll use these commands in EVERY exam question
- Speed comes from practice, not memorization
- Understanding is better than memorizing
- Test your commands before final submission

**Your Success Formula:**
```
Practice (30 min/day × 30 days) + 
Real labs (5-10 challenges) + 
Command chaining (10 one-liners) = 
eJPT Success
```

This guide contains everything you need to master Linux for the eJPT exam. Practice regularly, build confidence, and you'll succeed. Good luck with your certification journey!
