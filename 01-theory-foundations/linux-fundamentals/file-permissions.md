# 🔐 Linux File Permissions - Permission Management & Security

Understanding and manipulating file permissions is crucial for penetration testing, privilege escalation, and system security assessment.
**Location:** `01-theory-foundations/linux-fundamentals/file-permissions.md`

## 🎯 What are Linux File Permissions?

Linux file permissions control who can read, write, or execute files and directories. Every file and directory has three types of permissions for three categories of users: owner (user), group, and others. Understanding permissions is essential for identifying security misconfigurations and potential privilege escalation vectors.

## 📦 Permission System Overview

### Permission Types:
- **Read (r):** View file contents or list directory contents
- **Write (w):** Modify file contents or create/delete files in directory  
- **Execute (x):** Run file as program or access directory

### User Categories:
- **Owner (u):** The user who owns the file
- **Group (g):** Users belonging to the file's group
- **Others (o):** All other users on the system

## 🔧 Basic Commands and Syntax

### Viewing Permissions:
```bash
# List files with detailed permissions
ls -l filename
ls -la directory/

# View permissions for specific file
stat filename

# Show permissions in octal format
stat -c "%a %n" filename
```

### Changing Permissions:
```bash
# Using symbolic notation
chmod u+x filename      # Add execute for owner
chmod g-w filename      # Remove write for group  
chmod o=r filename      # Set read-only for others
chmod a+r filename      # Add read for all

# Using octal notation
chmod 755 filename      # rwxr-xr-x
chmod 644 filename      # rw-r--r--
chmod 777 filename      # rwxrwxrwx
```

## ⚙️ Permission Commands Reference

### Basic Permission Commands:
| Command | Purpose | Example |
|---------|---------|---------|
| `ls -l` | View detailed permissions | `ls -l /etc/passwd` |
| `chmod` | Change permissions | `chmod 755 script.sh` |
| `chown` | Change ownership | `chown user:group file` |
| `chgrp` | Change group | `chgrp newgroup file` |
| `umask` | Set default permissions | `umask 022` |

### Advanced Permission Commands:
| Command | Purpose | Example |
|---------|---------|---------|
| `find` | Find files by permissions | `find / -perm -4000 2>/dev/null` |
| `getfacl` | View ACL permissions | `getfacl filename` |
| `setfacl` | Set ACL permissions | `setfacl -m u:user:rwx file` |
| `lsattr` | View file attributes | `lsattr filename` |

## 🧪 Real Lab Examples

### Example 1: Basic Permission Analysis
```bash
# Check file permissions in home directory
ls -la /home/user/
# Output: -rw-r--r-- 1 user user 1024 Jan 15 10:30 document.txt
#         drwxr-xr-x 2 user user 4096 Jan 15 10:25 scripts/

# Analyze the output:
# document.txt: Owner can read/write, group and others can only read
# scripts/: Directory with read/write/execute for owner, read/execute for others
```

### Example 2: Finding SUID/SGID Files
```bash
# Find SUID files (potential privilege escalation)
find / -perm -4000 -type f 2>/dev/null
# Output: /usr/bin/passwd
#         /usr/bin/sudo  
#         /usr/bin/su

# Find SGID files
find / -perm -2000 -type f 2>/dev/null
# Output: /usr/bin/write
#         /usr/bin/ssh-agent

# Find world-writable files
find / -perm -002 -type f 2>/dev/null
```

### Example 3: Permission Modification for Exploitation
```bash
# Make script executable for privilege escalation
chmod +x exploit.sh
ls -l exploit.sh
# Output: -rwxr-xr-x 1 user user 2048 Jan 15 11:00 exploit.sh

# Set SUID bit on binary (if you have root access)
chmod u+s binary_file
ls -l binary_file
# Output: -rwsr-xr-x 1 root root 8192 Jan 15 11:05 binary_file
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **SUID/SGID identification (25%)** - Finding privilege escalation vectors
- **Permission analysis (20%)** - Understanding file access controls
- **World-writable files (15%)** - Identifying security misconfigurations
- **Permission modification (25%)** - Changing permissions for exploitation
- **Ownership analysis (15%)** - Understanding user/group relationships

### Critical Commands to Master:
```bash
find / -perm -4000 2>/dev/null     # Find SUID files - essential for privesc
find / -perm -2000 2>/dev/null     # Find SGID files  
find / -writable 2>/dev/null       # Find writable files/directories
chmod +x script.sh                 # Make files executable
ls -la                            # View detailed permissions
```

### eJPT Exam Scenarios:
1. **Privilege Escalation via SUID:** 
   - Required skills: Finding SUID binaries, understanding execution context
   - Expected commands: `find / -perm -4000`, analyzing GTFOBins
   - Success criteria: Escalate from user to root privileges

2. **Configuration File Analysis:**
   - Required skills: Identifying readable config files, finding credentials
   - Expected commands: `find /etc -readable`, `ls -la /etc/`
   - Success criteria: Extract passwords or sensitive information

### Exam Tips and Tricks:
- **Always check for SUID/SGID** - First step in any privilege escalation
- **Look for world-writable directories** - Often contain useful files or scripts
- **Check /tmp and /var/tmp permissions** - Common areas for exploitation
- **Verify script permissions before execution** - chmod +x is often needed

### Common eJPT Questions:
- How to find all SUID files on the system?
- What permissions allow privilege escalation?
- How to make a script executable?
- What do the permission bits mean in octal notation?

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Permission Denied Errors
**Problem:** Cannot execute scripts or access files during penetration testing
**Cause:** Insufficient permissions or incorrect file attributes
**Solution:**
```bash
# Check current permissions
ls -l filename
# Add execute permission
chmod +x filename
# Verify changes
ls -l filename
```

### Issue 2: Finding SUID Files Takes Too Long
**Problem:** `find` command runs slowly when searching entire filesystem
**Solution:**
```bash
# Redirect errors and run in background
find / -perm -4000 2>/dev/null &
# Or search specific directories first
find /usr -perm -4000 2>/dev/null
find /bin -perm -4000 2>/dev/null
```

### Issue 3: Cannot Change File Ownership
**Problem:** `chown` command fails during post-exploitation
**Prevention:**
```bash
# Check if you have sufficient privileges
id
# Use sudo if available
sudo chown user:group filename
```

## 🔗 Integration with Other Tools

### Primary Integration: find + ls + chmod Workflow
```bash
# Complete privilege escalation discovery workflow
find / -perm -4000 2>/dev/null | head -20    # Find SUID files
ls -la /usr/bin/passwd                       # Analyze specific binary
find /home -writable 2>/dev/null             # Find writable areas

# Exploitation preparation
chmod +x exploit.sh                          # Make exploit executable
./exploit.sh                                # Execute privilege escalation
```

### Integration with Privilege Escalation Tools:
```bash
# Use with automated tools
./linpeas.sh | grep -i "suid\|writable"     # Combine with LinPEAS
./linux-exploit-suggester.sh               # Check for kernel exploits
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** Permission listings showing SUID/SGID files
2. **Command Outputs:** Complete find command results  
3. **File Listings:** Detailed ls -la outputs for critical files
4. **Permission Changes:** Before and after chmod commands

### Report Template Structure:
```markdown
## File Permission Analysis

### Target Information
- Target: target_hostname_or_ip
- Date/Time: analysis_timestamp  
- User Context: current_user_privileges

### SUID/SGID Files Discovered
```bash
find / -perm -4000 2>/dev/null
# Results:
/usr/bin/passwd
/usr/bin/sudo
/custom/binary
```

### World-Writable Locations
- /tmp (expected)
- /var/tmp (expected)  
- /custom/upload (misconfiguration)

### Privilege Escalation Vectors
- Binary: /custom/binary (SUID root)
- Exploit: GTFOBins technique applicable
- Impact: Complete system compromise

### Recommendations
- Remove unnecessary SUID bits
- Implement proper file permissions
- Regular permission audits
```

### Key Commands for Documentation:
```bash
# Generate comprehensive permission report
find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null > suid_sgid_files.txt
find / -writable 2>/dev/null | grep -v "/proc\|/sys" > writable_locations.txt
ls -la /etc/passwd /etc/shadow /etc/group > important_files_perms.txt
```
