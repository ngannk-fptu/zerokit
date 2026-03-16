# OWASP A01-A10 Attack Patterns — Harness Reference

Per-category attack patterns for generating Hypotheses during Phase 3.
Each section maps to specific `VulnerabilityCategory` enum values and CWEs.

---

## A01:2021 — Broken Access Control

**VulnerabilityCategory**: `IDOR`, `CSRF`
**Primary CWEs**: CWE-22, CWE-352, CWE-434, CWE-639, CWE-862

### Attack Patterns
- **Forced browsing**: Access `?page=admin` or `/wp-admin/ajax.php` without auth check
- **Parameter tampering**: Change `user_id`, `order_id`, `post_id` to another user's value
- **Privilege escalation**: Modify `role`, `is_admin`, `capability` parameters
- **Path traversal**: `../../etc/passwd` in file path parameters
- **File upload bypass**: Upload `.php` by changing MIME type or bypassing extension check

### Hypothesis Generation Triggers
- Any endpoint with `id`, `user`, `file`, `path` parameter from HTTP input
- Any function called from `wp_ajax_nopriv_` hook (unauthenticated AJAX)
- File operations using `basename($_GET['file'])`

---

## A02:2021 — Cryptographic Failures

**VulnerabilityCategory**: `OTHER`
**Primary CWEs**: CWE-259, CWE-326, CWE-327, CWE-330, CWE-798

### Attack Patterns
- **Weak hashing**: MD5/SHA1 for passwords without salt
- **Hard-coded credentials**: API keys, DB passwords in source code
- **Insecure random**: `rand()` for token generation
- **Cleartext transmission**: HTTP (not HTTPS) for sensitive data

### Hypothesis Generation Triggers
- `md5(`, `sha1(`, `base64_encode(` used for "security" purposes
- String literals matching API key format (`sk_live_`, `AKIA`, etc.)

---

## A03:2021 — Injection

**VulnerabilityCategory**: `SQL_INJECTION`, `XSS`, `COMMAND_INJECTION`
**Primary CWEs**: CWE-78, CWE-79, CWE-89, CWE-94, CWE-917

### Attack Patterns
- **SQLi**: Unsanitized `$_GET` in `$wpdb->query()` or `mysql_query()`
- **XSS**: `echo $_POST['field']` without `esc_html()` or `esc_attr()`
- **Command injection**: `exec("ping " . $_GET['host'])`
- **Code injection**: `eval($_POST['code'])` or `preg_replace('/e', ...)`
- **SSTI**: Template engines (Twig, Smarty) rendering user input as template

### Hypothesis Generation Triggers
- Any `echo`, `print`, `printf` receiving un-escaped HTTP input
- Any `$wpdb->query()` or `mysql_query()` with string concatenation
- Any `exec()`, `shell_exec()`, `system()`, `passthru()` with user data
- PHP `eval()` or `preg_replace` with `/e` modifier

---

## A04:2021 — Insecure Design

**VulnerabilityCategory**: `LOGIC_ERROR`
**Primary CWEs**: CWE-209, CWE-256, CWE-501, CWE-522

### Attack Patterns
- **Missing rate limiting**: Login, API, or form submission endpoints
- **Verbose error messages**: Stack traces exposed to users
- **Insecure defaults**: Debug mode left enabled
- **Business logic flaws**: See `logic_flaw_catalog.md`

---

## A05:2021 — Security Misconfiguration

**VulnerabilityCategory**: `XXE`, `OTHER`
**Primary CWEs**: CWE-16, CWE-611, CWE-614, CWE-776

### Attack Patterns
- **XXE**: XML parsing without entity resolution disabled
- **Insecure CORS**: `Access-Control-Allow-Origin: *` with credentials
- **Missing security headers**: No CSP, X-Frame-Options, HSTS
- **Open admin interfaces**: Debug endpoints accessible without auth

### Hypothesis Generation Triggers
- `simplexml_load_string()`, `DOMDocument`, `XMLReader` without `LIBXML_NOENT`
- `header("Access-Control-Allow-Origin: *")` with cookie-based auth

---

## A06:2021 — Vulnerable Components

**VulnerabilityCategory**: `OTHER`
**Primary CWEs**: CWE-1035, CWE-1104

### Detection
- Read `composer.json`, `package.json`, `requirements.txt` for pinned versions
- Cross-reference with Trivy output or NVD
- Check if vulnerable functions from known CVEs are called

### Phase 3 Role
Minimal hypothesis generation here — defer to Trivy/SCA tools in Phase 4.
Only generate hypothesis if a specific CVE's vulnerable code pattern is found in the target.

---

## A07:2021 — Authentication Failures

**VulnerabilityCategory**: `OTHER`
**Primary CWEs**: CWE-287, CWE-306, CWE-307, CWE-521, CWE-798

### Attack Patterns
- **Missing auth**: Admin function callable without `is_user_logged_in()` check
- **Brute force**: No lockout after N failed attempts
- **Weak tokens**: Predictable reset/session tokens
- **Credential exposure**: Passwords in logs, URLs, or source code

### WordPress-Specific Checks
- `add_action('wp_ajax_nopriv_{action}')` calling privileged operations → Missing auth
- `current_user_can()` not called before sensitive `update_option()` / `delete_post()`

---

## A08:2021 — Software & Data Integrity

**VulnerabilityCategory**: `DESERIALIZATION`, `PROTOTYPE_POLLUTION`
**Primary CWEs**: CWE-345, CWE-502, CWE-829, CWE-915

### Attack Patterns
- **PHP unserialize**: `unserialize($_COOKIE['cart'])` → POP chain RCE
- **YAML unsafe load**: `yaml.load()` vs `yaml.safe_load()` in Python
- **Prototype pollution** (JS): `_.merge()`, `Object.assign()` with user input
- **Mass assignment**: `update_post_meta($id, ...array_merge($safe, $_POST))`

### Hypothesis Generation Triggers
- `unserialize(` with any user-controlled input
- `yaml.load(` without `Loader=yaml.SafeLoader`

---

## A09:2021 — Logging & Monitoring Failures

**VulnerabilityCategory**: `OTHER`
**Primary CWEs**: CWE-117, CWE-223, CWE-532

### Attack Patterns
- **Log injection**: Newlines in user input inserted into logs
- **Sensitive data logging**: Passwords/tokens logged in plaintext
- **Missing security events**: Failed auth attempts not logged

### Phase 3 Role
Low priority for hypothesis generation. Flag if sensitive functions have no audit logging.

---

## A10:2021 — Server-Side Request Forgery (SSRF)

**VulnerabilityCategory**: `SSRF`
**Primary CWEs**: CWE-918

### Attack Patterns
- **URL fetch with user input**: `file_get_contents($_GET['url'])`
- **Webhook callbacks**: User-specified callback URL fetched by server
- **PDF/image generators**: URL parameter passed to wkhtmltopdf or similar
- **Cloud metadata access**: `http://169.254.169.254/latest/meta-data/`

### Hypothesis Generation Triggers
- `curl_exec()`, `file_get_contents()`, `wp_remote_get()` with user-controlled URL
- Any "import from URL" or "preview URL" feature

### SSRF Verification Plan
```
1. Submit URL pointing to attacker-controlled server (e.g., Burp Collaborator)
2. Observe incoming request — confirms blind SSRF
3. Try: http://127.0.0.1:22 (SSH banner leak)
4. Try: http://169.254.169.254/ (cloud metadata)
```
