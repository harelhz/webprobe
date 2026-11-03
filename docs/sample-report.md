# Web security scan: http://127.0.0.1:8000/

- **Date:** 2026-11-03 14:53 UTC
- **Tool:** webprobe 0.1.0
- **Checks:** headers, cookies, tls, exposed-files, content-discovery, cors, http-methods, reflected-input, sql-errors
- **Coverage:** 5 pages crawled, 163 requests

## Summary

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 3 |
| Medium | 5 |
| Low | 6 |
| Info | 4 |

## Findings

### 1. [Critical] Environment file exposed

**URL:** `http://127.0.0.1:8000/.env`  
**Check:** `exposed-files`

A dotenv file with application configuration is publicly readable.

**Evidence**

```
APP_ENV=production
DB_HOST=10.0.0.5
DB_PASSWORD=lab****
SECRET_KEY=lab****
```

**Remediation:** Remove the file from the web root and block access to dotfiles/backups at the web server. Treat any credentials it contained as compromised and rotate them.

### 2. [High] CORS trusts arbitrary origin with credentials

**URL:** `http://127.0.0.1:8000/`  
**Check:** `cors`

The server reflects any Origin into Access-Control-Allow-Origin. Because credentials are allowed, a malicious site can read authenticated responses (account data, CSRF tokens) as the victim.

**Evidence**

```
Origin: https://webprobe-attacker.example
Access-Control-Allow-Origin: https://webprobe-attacker.example
Access-Control-Allow-Credentials: true
```

**Remediation:** Validate Origin against an exact allow-list of trusted origins; never reflect it or trust 'null'.

**References:** <https://portswigger.net/web-security/cors>

### 3. [High] Git repository exposed

**URL:** `http://127.0.0.1:8000/.git/HEAD`  
**Check:** `exposed-files`

The .git directory is web-accessible. Tools like git-dumper can rebuild the full source code and history, often including secrets.

**Evidence**

```
ref: refs/heads/main
```

**Remediation:** Remove the file from the web root and block access to dotfiles/backups at the web server. Treat any credentials it contained as compromised and rotate them.

### 4. [High] Possible SQL injection in 'id' (MySQL/MariaDB error)

**URL:** `http://127.0.0.1:8000/product?id=1%27`  
**Check:** `sql-errors`

Adding ' to parameter 'id' triggers a MySQL/MariaDB error message, and doubling it makes the error disappear. The input is very likely concatenated into a SQL query.

**Evidence**

```
Probe: id=1'
HTTP 500
Error: SQL syntax; check the manual that corresponds to your MySQL
Balanced '': no error (HTTP 200)
```

**Remediation:** Use parameterised queries / prepared statements everywhere, and stop returning raw database errors to clients.

**References:** <https://owasp.org/www-community/attacks/SQL_Injection>, <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html>

### 5. [Medium] Session-like cookie 'sessionid' missing HttpOnly, SameSite

**URL:** `http://127.0.0.1:8000/`  
**Check:** `cookies`

Missing HttpOnly: JavaScript (including injected XSS payloads) can read the cookie; Missing SameSite: cross-site requests rely on browser defaults for CSRF protection.

**Evidence**

```
Set-Cookie: sessionid=9f8e…; Path=/
```

**Remediation:** Set cookies with Secure; HttpOnly; SameSite=Lax (or Strict) unless there is a specific reason not to.

**References:** <https://developer.mozilla.org/docs/Web/HTTP/Cookies#restrict_access_to_cookies>

### 6. [Medium] Clickjacking protection missing

**URL:** `http://127.0.0.1:8000/`  
**Check:** `headers`

The page can be framed by any site (no X-Frame-Options or CSP frame-ancestors), enabling clickjacking.

**Evidence**

```
X-Frame-Options: (absent)
```

**Remediation:** Send "Content-Security-Policy: frame-ancestors 'self'" (and X-Frame-Options: SAMEORIGIN for old browsers).

**References:** <https://owasp.org/www-community/attacks/Clickjacking>

### 7. [Medium] Content-Security-Policy header missing

**URL:** `http://127.0.0.1:8000/`  
**Check:** `headers`

Without a CSP the browser will execute any injected script, so a single XSS bug becomes fully exploitable.

**Remediation:** Define a restrictive policy, e.g. "default-src 'self'; object-src 'none'; base-uri 'self'", and tighten from there.

**References:** <https://developer.mozilla.org/docs/Web/HTTP/CSP>

### 8. [Medium] Reflected input not encoded in 'q' (possible XSS)

**URL:** `http://127.0.0.1:8000/search`  
**Check:** `reflected-input`

The value of parameter 'q' is reflected into the page (html context) and the characters " ' < > ` come back unencoded. That usually means script can be injected; confirm manually with a context-appropriate payload.

**Evidence**

```
Request: http://127.0.0.1:8000/search?q=wp07f97188%22%27%3C%3E%60pw6453e8d8
Injected: wp07f97188"'<>`pw6453e8d8
Context: html
Unencoded: " ' < > `
```

**Remediation:** HTML-encode output for the context it lands in (use the template engine's auto-escaping) and add a strict Content-Security-Policy as defence in depth.

**References:** <https://owasp.org/www-community/attacks/xss/>, <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>

### 9. [Medium] Site served over plain HTTP

**URL:** `http://127.0.0.1:8000/`  
**Check:** `tls`

Traffic, including credentials and session cookies, can be read and modified by anyone on the network path.

**Remediation:** Serve the site over HTTPS only and redirect HTTP to HTTPS.

### 10. [Low] Administrative interface reachable

**URL:** `http://127.0.0.1:8000/admin`  
**Check:** `content-discovery`

An admin area is reachable without network restriction; make sure it's protected by strong auth and ideally an allow-list.

**Evidence**

```
200  /admin  (146B)
```

### 11. [Low] Software version disclosed in Server header

**URL:** `http://127.0.0.1:8000/`  
**Check:** `headers`

Exact version numbers let attackers look up known CVEs for this software without any probing.

**Evidence**

```
Server: Apache/2.4.29 (Ubuntu)
```

**Remediation:** Remove the Server header or strip the version (e.g. ServerTokens Prod / server_tokens off).

### 12. [Low] Software version disclosed in X-Powered-By header

**URL:** `http://127.0.0.1:8000/`  
**Check:** `headers`

Exact version numbers let attackers look up known CVEs for this software without any probing.

**Evidence**

```
X-Powered-By: PHP/7.2.1
```

**Remediation:** Remove the X-Powered-By header or strip the version (e.g. ServerTokens Prod / server_tokens off).

### 13. [Low] X-Content-Type-Options header missing

**URL:** `http://127.0.0.1:8000/`  
**Check:** `headers`

Browsers may MIME-sniff responses, which can turn user uploads into executable content.

**Remediation:** Send "X-Content-Type-Options: nosniff" on all responses.

**References:** <https://owasp.org/www-project-secure-headers/>

### 14. [Low] HTTP TRACE method enabled

**URL:** `http://127.0.0.1:8000/`  
**Check:** `http-methods`

TRACE echoes the request back, including headers. Combined with other bugs it can expose HttpOnly cookies or auth headers (Cross-Site Tracing).

**Evidence**

```
Request header X-Webprobe-Trace: c40221d4ca8f1f4d was echoed in the response body
```

**Remediation:** Disable TRACE (Apache: TraceEnable off).

**References:** <https://owasp.org/www-community/attacks/Cross_Site_Tracing>

### 15. [Low] Potentially dangerous HTTP methods advertised

**URL:** `http://127.0.0.1:8000/`  
**Check:** `http-methods`

The server advertises DELETE, PUT, TRACE. Advertised isn't the same as allowed: verify manually (on a throwaway path) whether e.g. PUT can create files.

**Evidence**

```
Allow: GET, POST, PUT, DELETE, TRACE, OPTIONS
```

**Remediation:** Disable methods the application doesn't need at the web server.

### 16. [Info] Discovered 2 paths

**URL:** `http://127.0.0.1:8000/`  
**Check:** `content-discovery`

Paths that exist on the server (status code, size, redirect target). Review each one manually.

**Evidence**

```
200  /admin  (146B)
200  /internal-reports/  (54B)
```

### 17. [Info] robots.txt discloses paths

**URL:** `http://127.0.0.1:8000/robots.txt`  
**Check:** `content-discovery`

robots.txt is not access control; entries often point at areas the owner considers sensitive.

**Evidence**

```
/admin
/internal-reports/
```

### 18. [Info] Permissions-Policy header missing

**URL:** `http://127.0.0.1:8000/`  
**Check:** `headers`

No Permissions-Policy restricts powerful browser features (camera, geolocation, ...) for this origin and its frames.

**Remediation:** Send a Permissions-Policy disabling features the app doesn't use, e.g. "camera=(), microphone=(), geolocation=()".

### 19. [Info] Referrer-Policy header missing

**URL:** `http://127.0.0.1:8000/`  
**Check:** `headers`

Modern browsers default to strict-origin-when-cross-origin, but an explicit policy avoids leaking full URLs (and any tokens in them) on older clients.

**Remediation:** Send "Referrer-Policy: strict-origin-when-cross-origin" or stricter.
