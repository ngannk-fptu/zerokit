<?php
/**
 * PoC Template: Missing Authorization / Broken Access Control (IDOR)
 * Auto-generated from ZeroKit finding
 * 
 * Vulnerability: {{CATEGORY}}
 * Location: {{FILE}}:{{LINE}}
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "====================================\n";
echo "🎯 PoC: Missing Authorization (IDOR)\n";
echo "Location: {{FILE}}:{{LINE}}\n";
echo "====================================\n\n";

// =====================================================
// EXPLOIT SCENARIO
// =====================================================
echo "[*] Testing for missing authorization checks\n";
echo "[*] Attempting to access resource without authentication...\n";

// Test payloads - try to access admin/privileged resources
$payload_user_id = "1"; // Try to access admin user
$payload_post_id = "999"; // Try to access private post
$payload_file_id = "sensitive.txt";

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

// Check if WordPress capability checks are missing
$wp_checks = [
    'current_user_can',
    'wp_verify_nonce',
    'check_admin_referer',
    'is_admin',
    'is_user_logged_in'
];

$has_auth_check = false;
foreach ($wp_checks as $check) {
    if (stripos($code, $check) !== false) {
        $has_auth_check = true;
        break;
    }
}

if (!$has_auth_check) {
    echo "✅ VULNERABILITY CONFIRMED: No authorization checks found\n";
    $success = true;
}

// Check if sensitive data was accessed
if (!empty($output)) {
    if (preg_match('/(admin|user_pass|password|email|token|api_key)/i', $output)) {
        echo "✅ VULNERABILITY CONFIRMED: Sensitive data accessed without authorization\n";
        $success = true;
    }
    
    if (preg_match('/(deleted|updated|modified|created)/i', $output)) {
        echo "✅ VULNERABILITY CONFIRMED: Action executed without authorization\n";
        $success = true;
    }
}

// Check for direct database queries without capability checks
if (preg_match('/\$wpdb->(get_|query|update|delete|insert)/i', $code) && !$has_auth_check) {
    echo "⚠️  Direct database access without authorization check\n";
    $success = true;
}

// Check for AJAX actions without nonce/capability
if (preg_match('/wp_ajax_/i', $code) && !$has_auth_check) {
    echo "✅ VULNERABILITY CONFIRMED: AJAX endpoint lacks authorization\n";
    $success = true;
}

// =====================================================
// RESULT
// =====================================================
echo "\n====================================\n";
if ($success) {
    echo "🚨 RESULT: EXPLOITABLE (Missing Authorization)\n";
    echo "Severity: {{SEVERITY}}\n";
    echo "Impact: IDOR, unauthorized data access, privilege bypass\n";
    echo "\nRecommendation: Add current_user_can() or capability checks\n";
    exit(0);
} else {
    echo "❌ RESULT: NOT EXPLOITABLE\n";
    echo "Authorization checks present\n";
    exit(1);
}
