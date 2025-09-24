# 🐧 Linux Essentials for eJPT - Command Line Mastery

Essential Linux command line skills and file system knowledge for penetration testing and eJPT exam success.
**Location:** `01-theory-foundations/linux-essentials.md`

## 🎯 What is Linux Command Line Proficiency?

Linux command line proficiency is fundamental for penetration testing and cybersecurity. The eJPT exam expects candidates to navigate Linux systems efficiently, manage files, processes, and networks using terminal commands. Key capabilities include:
- File system navigation and manipulation
- Process management and monitoring
- Network configuration and troubleshooting
- Text processing and data analysis
- Permission management and user control

## 📦 Essential Linux Concepts

### Linux File System Hierarchy:
```bash
/               # Root directory
├── bin/        # Essential binary commands
├── etc/        # Configuration files
├── home/       # User home directories
├── tmp/        # Temporary files
├── var/        # Variable data (logs)
├── usr/        # User programs
└── opt/        # Optional software
```

### Command Structure:
```bash
# Basic syntax
command [options] [arguments]

# Example
ls -la /home/user
```

## 🔧 File System Navigation and Management

### Navigation Commands:
```bash
# Print working directory
pwd

# List directory contents
ls                    # Basic listing
ls -l                 # Long format
ls -la                # Include hidden files
ls -lh                # Human readable sizes

# Change directory
cd /path/to/directory # Absolute path
cd ../                # Parent directory
cd ~                  # Home directory
cd -                  # Previous directory
```

### File Operations:
| Command | Purpose | Example |
|---------|---------|---------|
| `cp` | Copy files/directories | `cp file1 file2` |
| `mv` | Move/rename files | `mv oldname newname` |
| `rm` | Remove files | `rm filename` |
| `mkdir` | Create directory | `mkdir dirname` |
| `rmdir` | Remove empty directory | `rmdir dirname` |
| `touch` | Create empty file | `touch filename` |
| `find` | Search for files | `find /path -name "*.txt"` |
| `locate` | Quick file search | `locate filename` |

### File Content Management:
```bash
# View file contents
cat filename          # Display entire file
less filename         # Page through file
head filename         # First 10 lines
tail filename         # Last 10 lines
tail -f filename      # Follow file changes

# Text processing
grep "pattern" file   # Search for pattern
grep -r "text" /path  # Recursive search
sort filename         # Sort file contents
uniq filename         # Remove duplicates
wc filename          # Word count
```

## ⚙️ Process and System Management

### Process Commands:
| Command | Purpose | Example |
|---------|---------|---------|
| `ps` | List running processes | `ps aux` |
| `top` | Real-time processes | `top` |
| `htop` | Enhanced process viewer | `htop` |
| `kill` | Terminate process | `kill PID` |
| `killall` | Kill by name | `killall firefox` |
| `jobs` | List active jobs | `jobs` |
| `nohup` | Run command immune to hangups | `nohup command &` |

### System Information:
```bash
# System details
uname -a              # System information
whoami               # Current user
id                   # User and group IDs
uptime               # System uptime
df -h                # Disk usage
free -h              # Memory usage
lscpu                # CPU information

# Network information
ifconfig             # Network interfaces (deprecated)
ip addr show         # Network interfaces (modern)
netstat -tuln        # Network connections
ss -tuln             # Socket statistics (modern)
```

## 🔒 Permissions and Ownership

### Understanding Permissions:
```bash
# Permission format: rwxrwxrwx (owner group other)
# r = read (4), w = write (2), x = execute (1)

# View permissions
ls -l filename

# Example output:
-rwxr-xr--  1 user group 1024 Jan 15 10:30 filename
# ^ file type
#  ^^^ owner permissions (rwx = 7)
#     ^^^ group permissions (r-x = 5)  
#        ^^^ other permissions (r-- = 4)
```

### Permission Commands:
```bash
# Change permissions
chmod 755 filename    # Numeric method
chmod u+x filename    # Symbolic method
chmod -R 644 /path    # Recursive

# Change ownership
chown user:group file # Change owner and group
chown user file       # Change owner only
chgrp group file      # Change group only

# Special permissions
chmod +t directory    # Sticky bit
chmod u+s file        # SUID bit
chmod g+s file        # SGID bit
```

## 🧪 Real Lab Examples

### Example 1: Basic File System Navigation
```bash
# Navigate and explore system
pwd
# Output: /home/pentester

cd /etc
ls -la | head -10
# Output: Configuration files listing

find /etc -name "*.conf" | head -5
# Output: 
# /etc/dhcp/dhclient.conf
# /etc/kernel-img.conf
# /etc/adduser.conf
# /etc/debconf.conf
# /etc/deluser.conf

grep -r "127.0.0.1" /etc/hosts
# Output: 127.0.0.1	localhost
```

### Example 2: Process Management in Penetration Testing
```bash
# Start background process
nmap -sS 192.168.1.0/24 > scan_results.txt &
# Output: [1] 1234

# Check running processes
ps aux | grep nmap
# Output: pentester 1234  0.1  0.2  12345  2345 pts/0 R+ 10:30 0:01 nmap -sS 192.168.1.0/24

# Monitor system resources
top -p 1234
# Output: Real-time process information

# Check scan results
tail -f scan_results.txt
# Output: Live scan progress
```

### Example 3: File Analysis and Data Processing
```bash
# Analyze web server logs
tail -100 /var/log/apache2/access.log | grep "404"
# Output: 404 error entries from last 100 lines

# Extract unique IP addresses
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -nr | head -10
# Output: Top 10 IP addresses by request count

# Search for suspicious patterns
grep -i "sql\|union\|select" /var/log/apache2/access.log
# Output: Potential SQL injection attempts
```

### Example 4: Network Configuration and Troubleshooting
```bash
# Check network interfaces
ip addr show
# Output: Network interface details with IP addresses

# View routing table
ip route show
# Output: 
# default via 192.168.1.1 dev eth0 proto dhcp metric 100
# 192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100

# Check listening ports
ss -tuln | grep :80
# Output: tcp LISTEN 0 128 *:80 *:*

# Test connectivity
ping -c 3 8.8.8.8
# Output: 3 ping packets to Google DNS with response times
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT (85% exam importance):
- **File system navigation (25%)** - Navigate directories efficiently during labs
- **File content analysis (20%)** - Analyze configuration files and logs  
- **Process management (15%)** - Manage scanning tools and payloads
- **Permission management (15%)** - Understand file permissions for exploitation
- **Network troubleshooting (10%)** - Diagnose connectivity issues

### Critical Commands to Master:
```bash
# File system navigation (must-know)
ls -la                # Essential for file discovery
find /path -name "*"  # Critical for file searching  
grep -r "pattern" /   # Required for content searching
cat /etc/passwd       # Standard file for user enum

# Process management (exam required)
ps aux               # Process listing for exploit verification
netstat -tuln        # Network service identification
kill -9 PID          # Force kill processes if needed
```

### eJPT Exam Scenarios:
1. **File System Exploration:**
   - Required skills: Navigate to specific directories, find configuration files
   - Expected commands: `ls`, `cd`, `find`, `cat`
   - Success criteria: Locate target files within time limit

2. **Log Analysis for Evidence:**
   - Required skills: Search through log files for specific patterns
   - Expected commands: `grep`, `tail`, `awk`, `sort`
   - Success criteria: Extract relevant information from logs

3. **Service Discovery:**
   - Required skills: Identify running services and network configurations
   - Expected commands: `ps`, `netstat`, `ss`, `lsof`
   - Success criteria: Map running services to exploit opportunities

### Exam Tips and Tricks:
- **Practice path completion:** Use Tab key for faster navigation
- **Command history:** Use `history` and `!number` to repeat commands
- **Multiple terminals:** Open several terminals for parallel tasks
- **Output redirection:** Save command outputs for later reference

### Common eJPT Questions:
- Navigate to specific directories and locate configuration files
- Extract specific information from system logs
- Identify running services and their configurations
- Manage file permissions for payload deployment

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Permission Denied Errors
**Problem:** Cannot access files or execute commands due to insufficient permissions
**Cause:** Lack of appropriate read, write, or execute permissions
**Solution:**
```bash
# Check current permissions
ls -l filename

# Fix permissions if you own the file
chmod +r filename      # Add read permission
chmod +x filename      # Add execute permission

# Use sudo for administrative tasks (if available)
sudo cat /etc/shadow   # Read privileged files
```

### Issue 2: Command Not Found
**Problem:** System cannot find the specified command
**Solution:**
```bash
# Check if command exists
which command_name     # Show command location
type command_name      # Show command type

# Update PATH if needed
echo $PATH            # Show current PATH
export PATH=$PATH:/new/path  # Add new path

# Install missing package (if possible)
apt search package_name
sudo apt install package_name
```

### Issue 3: File System Navigation Confusion
**Problem:** Getting lost in the file system hierarchy
**Prevention:**
```bash
# Always know where you are
pwd                   # Print working directory

# Use absolute paths for certainty
ls /etc/apache2/      # Absolute path
ls -la $(pwd)         # List current directory explicitly

# Bookmark important locations
alias logs='cd /var/log'
alias config='cd /etc'
```

### Issue 4: Process Management Problems
**Problem:** Processes not responding or consuming too many resources
**Solution:**
```bash
# Identify problematic processes
top                   # Interactive process monitor
ps aux --sort=-%cpu   # Sort by CPU usage

# Graceful termination
kill PID              # Send TERM signal
kill -15 PID          # Explicit TERM signal

# Force termination if needed
kill -9 PID           # Send KILL signal
killall process_name  # Kill all instances
```

## 🔗 Integration with Other Tools

### Primary Integration: Linux Commands + Penetration Testing Tools
```bash
# File system exploration before exploitation
find /var/www -name "*.php" -exec grep -l "mysql_connect" {} \;
# Find PHP files with database connections

# Process management for tool execution
nmap -sS target_ip > results.txt 2>&1 &  # Background scan
jobs                                      # Check job status
fg %1                                     # Bring job to foreground

# Log analysis after exploitation
tail -f /var/log/auth.log | grep ssh     # Monitor SSH attempts
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c
```

### Integration with Network Tools:
```bash
# Combine network discovery with file operations
nmap -sn 192.168.1.0/24 | grep "Nmap scan report" | awk '{print $5}' > live_hosts.txt
for host in $(cat live_hosts.txt); do nmap -sV $host; done
```

### Integration with Web Testing:
```bash
# Analyze web server configurations
find /etc -name "*apache*" -o -name "*nginx*" | xargs ls -la
grep -r "DocumentRoot" /etc/apache2/
grep -r "server_name" /etc/nginx/
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Command History:** Save all executed commands for audit trail
2. **System Information:** Document target system details
3. **File Discoveries:** Record interesting files and their locations
4. **Permission Analysis:** Note unusual file permissions

### Report Template Structure:
```markdown
## Linux System Analysis

### Target System Information
- Hostname: $(hostname)
- OS Version: $(cat /etc/os-release)  
- Kernel Version: $(uname -r)
- Current User: $(whoami)
- User Privileges: $(id)

### Commands Executed
```bash
# Timestamped command history
history | tail -20
```

### Key Findings
- Configuration files discovered
- Interesting permissions found
- Running services identified
- Log entries of interest

### File System Structure
- Important directories mapped
- Writable locations identified  
- SUID/SGID files found
```

### Automation Scripts:
```bash
#!/bin/bash
# Linux enumeration script
echo "=== System Information ==="
uname -a
cat /etc/os-release

echo "=== User Information ==="
whoami
id
cat /etc/passwd

echo "=== Network Configuration ==="
ip addr show
ss -tuln

echo "=== Running Processes ==="
ps aux --sort=-%cpu | head -10
```

## 📚 Additional Resources

### Official Documentation:
- Linux man pages: `man command_name`
- GNU Coreutils: https://www.gnu.org/software/coreutils/
- Linux Documentation Project: https://tldp.org/

### Learning Resources:
- OverTheWire Bandit: https://overthewire.org/wargames/bandit/
- Linux Journey: https://linuxjourney.com/
- ExplainShell: https://explainshell.com/

### Community Resources:
- r/linux4noobs: Reddit community for beginners
- Linux.org forums: https://www.linux.org/forums/
- Stack Overflow Linux tag: For specific questions

### Related Tools:
- Bash scripting: Automation and advanced command combinations
- Vim/nano: Text editors for configuration files
- Screen/tmux: Terminal multiplexers for session management
