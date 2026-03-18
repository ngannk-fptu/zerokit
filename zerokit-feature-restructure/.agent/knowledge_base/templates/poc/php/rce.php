<?php
/**
 * PoC Template: Remote Code Execution (RCE)
 * Auto-generated from ZeroKit finding
 * 
 * Vulnerability: {{CATEGORY}}
 * Location: {{FILE}}:{{LINE}}
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "====================================\n";
echo "🎯 PoC: Remote Code Execution\n";
echo "Location: {{FILE}}:{{LINE}}\n";
echo "====================================\n\n";

// Test payload - execute system command
$payload = "echo 'ZEROKIT_PROOF_OF_CONCEPT'";
$payload_dangerous = "cat /etc/passwd"; // For real exploitation

echo "[*] Testing RCE with payload: $payload\n";

// =====================================================
// VULNERABLE CODE EXECUTION
// =====================================================
// Template manager will replace this section with actual vulnerable code
$output = '';
ob_start();
// VULNERABLE_CODE_PLACEHOLDER
$output = ob_get_clean();

// Verification
$success = false;
if (preg_match('/ZEROKIT_PROOF_OF_CONCEPT/', $output)) {
    echo "✅ VULNERABILITY CONFIRMED: Command execution successful\n";
    $success = true;
}

echo "\n====================================\n";
if ($success) {
    echo "🚨 RESULT: EXPLOITABLE (CRITICAL)\n";
    exit(0);
} else {
    echo "❌ RESULT: NOT EXPLOITABLE\n";
    exit(1);
}
