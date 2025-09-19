# 🐧 Basic Linux Commands - Essential Terminal Skills

**Master fundamental Linux commands for effective penetration testing and eJPT success**
**Location:** `01-theory-foundations/linux-fundamentals/basic-commands.md`

## 🎯 What are Basic Linux Commands?

Basic Linux commands are the fundamental building blocks for interacting with Linux systems through the command line interface. For penetration testers, mastering these commands is essential as most penetration testing tools run on Linux, and compromised systems often require command-line interaction. Linux command proficiency is crucial for eJPT success, as it underlies all practical testing activities, from initial reconnaissance to post-exploitation tasks.

Understanding these commands enables efficient system navigation, file manipulation, process management, and information gathering during penetration tests.

## 📦 Command Categories Overview

### File System Navigation:
```bash
# Essential commands for moving around the file system
pwd                    # Print current working directory
ls                     # List directory contents
cd                     # Change directory
find                   # Search for files and directories
locate                 # Quick file location using database
```

### File and Directory Operations:
```bash
# Commands for file and directory manipulation
mkdir                  # Create directories
rmdir                  # Remove empty directories
rm                     # Remove files and directories
cp                     # Copy files and directories
mv                     # Move/rename files and directories
```

### File Content Operations:
```bash
# Commands for viewing and editing file contents
cat                    # Display file contents
less/more              # View file contents page by page
head                   # Display first lines of file
tail                   # Display last lines of file
grep                   # Search text patterns in files
```

### System Information:
```bash
# Commands for gathering system information
whoami                 # Current username
id                     # User and group IDs
uname                  # System information
ps                     # Running processes
top                    # Dynamic process viewer
```

## 🔧 File System Navigation Commands

### Directory Navigation:
```bash
# Print current working directory
pwd
# Output: /home/user/Documents

# List directory contents
ls                     # Basic listing
ls -l                  # Long format (detailed)
ls -la                 # Include hidden files
ls -lh                 # Human-readable file sizes
ls -R                  # Recursive listing

# Example ls -la output:
# drwxr-xr-x 2 user user 4096 Jan 15 10:30 .
# drwxr-xr-x 3 user user 4096 Jan 15 10:25 ..
# -rw-r--r-- 1 user user  220 Jan 15 10:30 .bashrc
# -rw-r--r-- 1 user user 1024 Jan 15 10:30 document.txt

# Change directory
cd /home/user          # Absolute path
cd Documents           # Relative path
cd ..                  # Parent directory
cd ~                   # Home directory
cd -                   # Previous directory
cd /                   # Root directory
```

### File and Directory Searching:
```bash
# Find command - powerful file search
find /path -name "filename"           # Find by name
find /home -name "*.txt"             # Find with wildcards
find . -type f -name "*.log"         # Find files only
find . -type d -name "test*"         # Find directories only
find / -perm -4000 2>/dev/null       # Find SUID files (security)
find / -user root -writable 2>/dev/null  # Find writable files by root

# Locate command - fast database search
locate filename                      # Quick file location
locate -i filename                   # Case-insensitive search
updatedb                            # Update locate database (as root)

# Which command - find executable location
which python                        # Find python executable path
which nmap                          # Find nmap location
```

### Directory Operations:
```bash
# Create directories
mkdir test_dir                      # Create single directory
mkdir -p path/to/nested/dir         # Create nested directories
mkdir dir1 dir2 dir3               # Create multiple directories

# Remove directories
rmdir empty_dir                     # Remove empty directory
rm -r directory                     # Remove directory and contents
rm -rf directory                    # Force remove (dangerous!)

# Copy and move
cp file1 file2                      # Copy file
cp -r dir1 dir2                     # Copy directory recursively
mv old_name new_name                # Rename file/directory
mv file /path/to/destination        # Move file
```

## ⚙️ File Content Manipulation Commands

### Viewing File Contents:
```bash
# Cat command - display entire file
cat /etc/passwd                     # Display user accounts
cat /etc/hosts                      # Display hosts file
cat file1 file2                     # Display multiple files
cat -n filename                     # Display with line numbers

# Less and More - paginated viewing
less /var/log/syslog                # View large files
more /etc/services                  # Alternative pager
# Navigation in less: q (quit), / (search), n (next match)

# Head and Tail - partial file viewing
head -n 10 /var/log/auth.log        # First 10 lines
tail -n 20 /var/log/syslog          # Last 20 lines
tail -f /var/log/auth.log           # Follow file changes (real-time)

# Example viewing /etc/passwd:
# root:x:0:0:root:/root:/bin/bash
# daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
# bin:x:2:2:bin:/bin:/usr/sbin/nologin
```

### Text Processing Commands:
```bash
# Grep - pattern searching
grep "error" /var/log/syslog         # Find error messages
grep -i "warning" /var/log/*         # Case-insensitive search
grep -r "password" /etc/             # Recursive search
grep -v "comment" file               # Invert match (exclude)
grep -n "pattern" file               # Show line numbers

# Cut - extract columns
cut -d: -f1 /etc/passwd             # Extract usernames
cut -d: -f3 /etc/passwd             # Extract user IDs
cut -c1-10 file                     # Extract characters 1-10

# Sort and Uniq - organize text
sort /etc/passwd                    # Sort lines alphabetically
sort -n numbers.txt                 # Numerical sort
uniq sorted_file                    # Remove duplicate lines
sort file | uniq -c                 # Count occurrences

# Wc - word count
wc filename                         # Lines, words, characters
wc -l /etc/passwd                   # Count lines only
wc -w document.txt                  # Count words only
```

### File Editing:
```bash
# Nano - beginner-friendly editor
nano filename                       # Open file in nano
# Ctrl+X to exit, Ctrl+O to save

# Vi/Vim - powerful editor
vi filename                         # Open file in vi
# Press 'i' for insert mode, 'Esc' for command mode, ':wq' to save and quit

# Echo - create simple files
echo "Hello World" > file.txt       # Create file with content
echo "New line" >> file.txt         # Append to file
```

## 🧪 Real Lab Examples

### Example 1: System Reconnaissance Commands
```bash
# Identify current user and system
whoami
# Output: pentester

id
# Output: uid=1000(pentester) gid=1000(pentester) groups=1000(pentester),4(adm),24(cdrom),27(sudo)

# System information gathering
uname -a
# Output: Linux kali 5.14.0-kali4-amd64 #1 SMP Debian 5.14.16-1kali1 x86_64 GNU/Linux

hostnamectl
# Output: 
# Static hostname: kali
# Icon name: computer-laptop
# Chassis: laptop
# Machine ID: abc123def456...
# Operating System: Kali GNU/Linux Rolling

# Network interface information
ip addr show
# Output: Shows all network interfaces with IP addresses

# Check current directory and list contents
pwd
# Output: /home/pentester

ls -la
# Output: Shows all files including hidden ones with permissions
```

### Example 2: Log Analysis and Investigation
```bash
# Examine authentication logs
tail -n 50 /var/log/auth.log
# Output: Recent authentication attempts

# Search for failed login attempts
grep "Failed password" /var/log/auth.log
# Output: Shows failed login attempts with timestamps and IPs

# Count failed login attempts
grep "Failed password" /var/log/auth.log | wc -l
# Output: 15 (number of failed attempts)

# Find unique IP addresses attempting login
grep "Failed password" /var/log/auth.log | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq
# Output: List of unique IP addresses

# Check for successful logins
grep "Accepted password" /var/log/auth.log
# Output: Successful authentication events
```

### Example 3: File System Exploration for Security Testing
```bash
# Find world-writable files (security issue)
find / -type f -perm -002 2>/dev/null
# Output: Files writable by everyone

# Find SUID files (potential privilege escalation)
find / -type f -perm -4000 2>/dev/null
# Output: 
# /usr/bin/sudo
# /usr/bin/passwd
# /usr/bin/su
# /bin/ping

# Search for configuration files
find /etc -name "*.conf" -type f
# Output: List of configuration files

# Look for backup files (potential information disclosure)
find / -name "*.bak" -o -name "*.backup" -o -name "*~" 2>/dev/null
# Output: Potential backup files with sensitive information

# Search for files containing passwords
grep -r "password" /etc/ 2>/dev/null
# Output: Configuration files mentioning passwords
```

### Example 4: Process and Service Investigation
```bash
# List running processes
ps aux
# Output: All running processes with details

# Find specific processes
ps aux | grep ssh
# Output: SSH-related processes

# Check listening network services
netstat -tulnp
# Output: Listening ports and associated processes

# Monitor system activity in real-time
top
# Output: Dynamic view of running processes

# Check system resource usage
df -h
# Output: Disk space usage
# Filesystem      Size  Used Avail Use% Mounted on
# /dev/sda1        20G  8.5G   11G  45% /

free -h
# Output: Memory usage
# total        used        free      shared  buff/cache   available
# Mem:          4.0G        1.5G        1.0G        100M        1.5G        2.2G
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT (Foundation for all practical tasks):
- **System navigation** and file system understanding (25%)
- **Log analysis** and information gathering (30%)
- **Process management** and service identification (20%)
- **File manipulation** and text processing (25%)

### Critical Linux Commands for eJPT:
```bash
# System information (must know)
whoami                              # Current user identification
id                                  # User privileges and groups
uname -a                           # System information
ps aux                             # Running processes
netstat -tulnp                     # Network connections

# File operations (must know)
ls -la                             # Detailed directory listing
find / -name "filename" 2>/dev/null  # File searching
grep -r "pattern" /path/           # Text pattern searching
cat /etc/passwd                    # View user accounts
tail -f /var/log/auth.log          # Monitor log files

# Navigation (must know)
cd /path/to/directory              # Change directory
pwd                                # Current location
which command                      # Find command location
```

### eJPT Command Usage Scenarios:
1. **Initial System Assessment:** Understanding compromised system
   - Required commands: whoami, id, uname, ls, pwd
   - Expected usage: Post-exploitation system identification
   - Success criteria: Complete system and user context understanding

2. **Information Gathering:** Finding sensitive data and configurations
   - Required commands: find, grep, cat, less
   - Expected usage: Locating configuration files, logs, and sensitive data
   - Success criteria: Discovery of actionable information

3. **Privilege Escalation Research:** Finding escalation vectors
   - Required commands: find with SUID, sudo -l, crontab -l
   - Expected usage: Identifying privilege escalation opportunities
   - Success criteria: Discovery of escalation paths

### Exam Tips and Tricks:
- **Tip 1:** Always use `2>/dev/null` to suppress error messages in find commands
- **Tip 2:** Combine commands with pipes (|) for powerful one-liners
- **Tip 3:** Use `history` command to review previously executed commands
- **Tip 4:** Master file permissions interpretation for security assessment

### Common eJPT Command Combinations:
```bash
# Essential one-liners for exam
ps aux | grep -v root               # Non-root processes
find / -type f -perm -4000 2>/dev/null | xargs ls -la  # SUID files with details
grep -r "password" /etc/ 2>/dev/null | head -10       # Password references
netstat -tulnp | grep LISTEN       # Only listening services
tail -f /var/log/auth.log | grep "Failed password"    # Real-time failed logins
```

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Permission Denied Errors
**Problem:** Cannot access files or directories due to insufficient permissions
**Cause:** Attempting to access files without proper read/execute permissions
**Solution:**
```bash
# Check file permissions
ls -la filename

# Check current user permissions
id
groups

# Use sudo if available
sudo cat /etc/shadow
sudo find /root -name "*.txt"

# Alternative approaches
# Look for world-readable files
find / -type f -perm -004 2>/dev/null
```

### Issue 2: Command Not Found
**Problem:** System reports command not found
**Cause:** Command not installed or not in PATH
**Solution:**
```bash
# Check if command exists
which command_name
whereis command_name

# Check PATH variable
echo $PATH

# Find executable
find / -name "command_name" 2>/dev/null

# Use full path if found
/usr/bin/command_name

# Alternative commands
# Instead of netstat, use ss
ss -tulnp
```

### Issue 3: Large Output Overwhelming Terminal
**Problem:** Commands produce too much output to read effectively
**Cause:** Not using proper output control or filtering
**Solution:**
```bash
# Use pagination
command | less
command | more

# Limit output
command | head -20
command | tail -10

# Filter output
command | grep "pattern"
command 2>/dev/null

# Save output to file
command > output.txt
command | tee output.txt  # Show and save
```

### Issue 4: Difficulty Finding Files
**Problem:** Cannot locate specific files or information
**Cause:** Incorrect search parameters or file location
**Solution:**
```bash
# Use multiple search methods
find / -name "*filename*" 2>/dev/null
locate filename
grep -r "text_content" /

# Search case-insensitively
find / -iname "*filename*" 2>/dev/null
grep -ri "pattern" /path/

# Use wildcards effectively
find / -name "*.conf" 2>/dev/null
find / -name "*.log" 2>/dev/null
```

## 🔗 Integration with Penetration Testing

### Commands in Information Gathering Phase:
```bash
# System enumeration
uname -a                           # OS version
cat /etc/issue                     # Distribution info
cat /etc/passwd                    # User accounts
cat /etc/group                     # Group information

# Network enumeration
cat /etc/hosts                     # Host entries
cat /etc/resolv.conf              # DNS configuration
netstat -tulnp                    # Network connections
ss -tulnp                         # Modern netstat alternative
```

### Commands in Privilege Escalation:
```bash
# SUID binary discovery
find / -type f -perm -4000 2>/dev/null

# Writable directories
find / -type d -writable 2>/dev/null

# Scheduled tasks
crontab -l                        # User cron jobs
cat /etc/crontab                  # System cron jobs
ls -la /etc/cron.*               # Cron directories

# Sudo privileges
sudo -l                          # Available sudo commands
```

### Commands in Post-Exploitation:
```bash
# Data gathering
find /home -name "*.txt" 2>/dev/null
find /home -name "*.pdf" 2>/dev/null
grep -r "password" /home/ 2>/dev/null

# System information for reporting
ps aux                           # Running processes
df -h                           # Disk usage
free -h                         # Memory usage
last                            # Login history
```

## 📝 Command Documentation and Cheat Sheet

### Quick Reference Commands:
```bash
# Navigation
pwd                              # Print working directory
ls -la                          # List all files with details
cd /path                        # Change directory
find / -name "file" 2>/dev/null # Find files

# File operations
cat filename                    # Display file content
grep "pattern" file            # Search in file
head -n 10 file               # First 10 lines
tail -f file                  # Follow file changes

# System info
whoami                         # Current user
id                            # User ID and groups
uname -a                      # System information
ps aux                        # Process list

# Network
netstat -tulnp                # Network connections
ss -tulnp                     # Modern network tool
```

### Command Syntax Patterns:
| Command | Basic Syntax | Common Options | Example |
|---------|--------------|----------------|---------|
| **ls** | `ls [options] [path]` | `-l`, `-a`, `-h`, `-R` | `ls -la /home` |
| **find** | `find [path] [criteria]` | `-name`, `-type`, `-perm` | `find / -name "*.conf"` |
| **grep** | `grep [options] pattern [file]` | `-r`, `-i`, `-v`, `-n` | `grep -r "password" /etc/` |
| **ps** | `ps [options]` | `aux`, `-ef` | `ps aux \| grep ssh` |
| **cat** | `cat [options] file` | `-n`, `-A` | `cat /etc/passwd` |

### File Permission Interpretation:
```bash
# Permission format: drwxrwxrwx
# d = directory, - = file
# rwx = read, write, execute (owner)
# rwx = read, write, execute (group)  
# rwx = read, write, execute (others)

# Examples:
# -rw-r--r-- = regular file, owner read/write, group/others read only
# drwxr-xr-x = directory, owner full access, group/others read/execute
# -rwsr-xr-x = SUID file, runs with owner privileges
```

### Essential File Locations:
```bash
# System configuration
/etc/passwd                     # User accounts
/etc/shadow                     # Password hashes (root only)
/etc/group                      # Group information
/etc/hosts                      # Host name resolution
/etc/resolv.conf               # DNS configuration

# Log files
/var/log/auth.log              # Authentication logs
/var/log/syslog                # System logs
/var/log/apache2/access.log    # Web server logs
/var/log/messages              # General system messages

# Important directories
/home                          # User home directories
/tmp                           # Temporary files
/var/www                       # Web server files
/etc                           # Configuration files
```
