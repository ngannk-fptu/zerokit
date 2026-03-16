# Logic Flaw Vulnerability Catalog — Harness Reference

Logic flaws are vulnerabilities in business logic that SAST tools cannot detect.
These MUST be generated as Hypotheses manually during Phase 3.

## Category 1: Authorization & Access Control Flaws

### 1.1 IDOR (Insecure Direct Object Reference) — CWE-639

**Pattern**: User controls an ID/key used to access another user's resource.

**Hypothesis template**:
```
description: "IDOR in {endpoint}: user-controlled {param} directly accesses {resource} without ownership check"
verification_plan: "Test: change user_id param from own ID to another user's ID, observe if access granted"
metadata.priority: CRITICAL
```

**Look for**:
- `GET /api/orders?id={user_input}` without `WHERE user_id = current_user`
- File downloads using filename/ID from request
- `update_post()` / `wp_update_post()` without `current_user_can('edit_post', $post_id)`

**Detection hint**: Search for `$_GET['id']` or `$_POST['id']` used directly in DB query without an owner check.

---

### 1.2 Privilege Escalation via Role Parameter — CWE-269

**Pattern**: User can manipulate their own role/permission level.

**Hypothesis template**:
```
description: "Role escalation: {parameter} from user input controls permission level"
verification_plan: "POST request with admin role value, verify backend re-checks from DB"
metadata.priority: CRITICAL
```

**Look for**:
- `$_POST['role']` assigned to `wp_update_user()`
- `$_REQUEST['is_admin']` without server-side validation

---

### 1.3 Function-Level Auth Bypass — CWE-862

**Pattern**: Admin-only function accessible without auth check.

**Hypothesis template**:
```
description: "Missing auth check on {function}: capability check absent before privileged operation"
verification_plan: "Access {endpoint} as unauthenticated user, check if operation succeeds"
metadata.priority: CRITICAL
```

**Look for** (WordPress): `add_action('wp_ajax_nopriv_{action}', ...)` calling admin operations.

---

## Category 2: Input Flow & State Flaws

### 2.1 TOCTOU (Time-of-Check-Time-of-Use) — CWE-362

**Pattern**: Resource state changes between when it's checked and when it's used.

**Hypothesis template**:
```
description: "TOCTOU in {operation}: {resource} checked at T1 but used at T2, race allows inconsistent state"
verification_plan: "Concurrent request test: two requests simultaneously triggering {operation}"
metadata.priority: HIGH
```

**Look for**:
- File existence check → file read as separate operations
- Permission check → privileged operation with delay between

---

### 2.2 Negative Logic Failure — CWE-754

**Pattern**: Security check only handles success case; failure case falls through.

```php
// VULNERABLE: if auth fails, no else clause
if (is_user_logged_in()) {
    return true;
}
// Code continues even if not logged in!
do_sensitive_action();
```

**Hypothesis template**:
```
description: "Negative case bypass in {function}: auth check lacks early return on failure"
verification_plan: "Call {function} without authentication, verify it returns early or errors"
metadata.priority: CRITICAL
```

---

### 2.3 Multi-Step Process Skip — CWE-841

**Pattern**: Multi-step operation (e.g., checkout flow) can skip intermediate steps.

**Hypothesis template**:
```
description: "Step skip in {workflow}: step {N} can be invoked without completing step {N-1}"
verification_plan: "Direct POST to step {N} endpoint, skip expected preceding step"
metadata.priority: HIGH
```

---

## Category 3: Data Integrity Flaws

### 3.1 Mass Assignment — CWE-915

**Pattern**: User-controlled fields mapped directly to model/DB without whitelist.

```php
// VULNERABLE
update_user_meta($user_id, ...array_merge($defaults, $_POST));
```

**Hypothesis template**:
```
description: "Mass assignment in {handler}: {POST/body} data merged into {model} without field whitelist"
verification_plan: "Send additional fields (e.g., role=admin) in POST body, verify they are persisted"
metadata.priority: HIGH
```

---

### 3.2 Business Rule Bypass — CWE-840

**Pattern**: Business constraint (rate limit, quantity check, price validation) enforced client-side only.

**Hypothesis template**:
```
description: "Business rule bypass in {feature}: {constraint} enforced only in frontend JS"
verification_plan: "Direct API call bypassing UI, test {constraint} holds server-side"
metadata.priority: MEDIUM
```

---

### 3.3 Integer Overflow in Quantity/Price — CWE-190

**Pattern**: Large integer input causes overflow leading to negative/zero price.

**Hypothesis template**:
```
description: "Integer overflow in {calculation}: quantity * price with large values may overflow"
verification_plan: "Submit quantity=999999999, verify total price is not negative or zero"
metadata.priority: HIGH
```

---

## Category 4: Session & Token Flaws

### 4.1 Session Fixation — CWE-384

**Pattern**: Session ID not regenerated after authentication.

**Hypothesis template**:
```
description: "Session fixation in login: session ID not regenerated post-authentication"
verification_plan: "Record session ID before login, verify it changes after successful auth"
metadata.priority: HIGH
```

---

### 4.2 Predictable Token Generation — CWE-330

**Pattern**: Reset tokens, CSRF tokens, or API keys generated with weak entropy.

**Look for**: `rand()`, `mt_rand()`, `time()` used as token basis instead of `random_bytes()` / `wp_generate_password()`.

**Hypothesis template**:
```
description: "Weak token entropy in {feature}: token uses predictable {rand/time} as seed"
verification_plan: "Generate multiple tokens, analyze entropy/pattern"
metadata.priority: HIGH
```

---

## Generating Hypotheses from Logic Flaws

For each pattern found, create a Hypothesis:

```python
Hypothesis(
    id=str(uuid.uuid4()),
    description="[LOGIC] {pattern_name} in {file}:{function}",
    target_code="{file_path}:{function_name}",
    verification_plan="Manual PoC required — {specific_test_steps}",
    metadata={
        "priority": "CRITICAL|HIGH|MEDIUM",
        "cwe": "CWE-{id}",
        "owasp": "A0{X}:2021",
        "vuln_category": "LOGIC_ERROR",
        "requires_manual_poc": True,
        "llm_reasoning": "{why this pattern is suspect here}"
    }
)
```

> **Note**: Logic flaw hypotheses with `requires_manual_poc: True` → Verifier must use
> `llm_gateway.generate_poc()` since no Semgrep rule can prove them.
