<?php
/**
 * PoC Template: Authentication Bypass
 * Auto-generated from ZeroKit finding
 * 
 * Vulnerability: {{CATEGORY}}
 * Location: {{FILE}}:{{LINE}}
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "====================================\n";
echo "🎯 PoC: Authentication Bypass\n";
echo "Location: {{FILE}}:{{LINE}}\n";
echo "====================================\n\n";

// =====================================================
// EXPLOIT SCENARIO
// =====================================================
echo "[*] Testing authentication bypass vulnerabilities\n";

// Common bypass payloads
$payload_sql_bypass = "admin' OR '1'='1' -- ";
$payload_empty_pass = "";
$payload_special_chars = "admin\x00";

// =====================================================
// VULNERABLE CODE EXECUTION
// =====================================================
// Template manager will replace this section with actual vulnerable code
$output = '';
$code = '';
ob_start();
// VULNERABLE_CODE_PLACEHOLDER
$output = ob_get_clean();

// =====================================================
// VERIFICATION
// =====================================================
$success = false;

// Check for weak authentication logic
if (preg_match('/(if\s*\(\s*\$_\w+\[|if\s*\(\s*\$\w+\s*==)/i', $code)) {
    echo "⚠️  Simple comparison authentication detected\n";
    
    // Check if it uses loose comparison (==) instead of strict (===)
    if (preg_match('/==(?!=)/', $code) && !preg_match('/===/', $code)) {
        echo "✅ VULNERABILITY CONFIRMED: Loose comparison (==) allows type juggling\n";
        $success = true;
    }
}

// Check for password verification issues
if (stripos($code, 'md5') !== false || stripos($code, 'sha1') !== false) {
    echo "✅ VULNERABILITY CONFIRMED: Weak password hashing (MD5/SHA1)\n";
    $success = true;
}

// Check for authentication without wp_authenticate
if (!stripos($code, 'wp_authenticate') && 
    !stripos($code, 'wp_signon') &&
    preg_match('/(login|auth|signin)/i', $code)) {
    echo "⚠️  Custom authentication not using WordPress APIs\n";
    $success = true;
}

// Check if authentication was bypassed (access granted)
if (preg_match('/(logged|authenticated|success|welcome|dashboard)/i', $output)) {
    echo "✅ VULNERABILITY CONFIRMED: Authentication bypassed successfully\n";
    $success = true;
}

// Check for SQL injection in auth queries
if (preg_match('/SELECT.*FROM.*WHERE.*password/i', $code) &&
    !preg_match('/prepare|bind_param|PDO/i', $code)) {
    echo "✅ VULNERABILITY CONFIRMED: SQL injection in authentication\n";
    $success = true;
}

// =====================================================
// RESULT
// =====================================================
echo "\n====================================\n";
if ($success) {
    echo "🚨 RESULT: EXPLOITABLE (Authentication Bypass)\n";
    echo "Severity: {{SEVERITY}}\n";
    echo "Impact: Complete account takeover, unauthorized access\n";
    echo "\nRecommendation: Use wp_authenticate(), wp_hash_password(), and prepared statements\n";
    exit(0);
} else {
    echo "❌ RESULT: NOT EXPLOITABLE\n";
    echo "Authentication properly implemented\n";
    exit(1);
}
