#!/usr/bin/env python3
"""
PoC Template: Command Injection (Python)
Auto-generated from ZeroKit finding

Vulnerability: {{CATEGORY}}
Location: {{FILE}}:{{LINE}}
"""

import subprocess
import sys
import os

print("=" * 50)
print("🎯 PoC: Command Injection (Python)")
print(f"Location: {{{{FILE}}}}:{{{{LINE}}}}")
print("=" * 50)
print()

# Test payload
payload = "echo ZEROKIT_PROOF"
payload_dangerous = "cat /etc/passwd"

print(f"[*] Testing payload: {payload}")

# Vulnerable code execution
try:
    {{VULNERABLE_CODE}}
    
    # Verification
    if "ZEROKIT_PROOF" in output:
        print("✅ VULNERABILITY CONFIRMED: Command injection successful")
        print("\n" + "=" * 50)
        print("🚨 RESULT: EXPLOITABLE (CRITICAL)")
        sys.exit(0)
    else:
        print("❌ Command did not execute as expected")
        sys.exit(1)
        
except Exception as e:
    print(f"❌ Exception: {e}")
    sys.exit(1)
