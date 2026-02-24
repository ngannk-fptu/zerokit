<?php
/**
 * PoC Template: Cross-Site Scripting (XSS)
 * Auto-generated from ZeroKit finding
 * 
 * Vulnerability: {{CATEGORY}}
 * Location: {{FILE}}:{{LINE}}
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "====================================\n";
echo "🎯 PoC: Cross-Site Scripting (XSS)\n";
echo "Location: {{FILE}}:{{LINE}}\n";
echo "====================================\n\n";

// =====================================================
// EXPLOIT PAYLOADS
// =====================================================
$payload_basic = "<script>alert('ZEROKIT_XSS')</script>";
$payload_img = "<img src=x onerror=alert('ZEROKIT_XSS')>";
$payload_svg = "<svg onload=alert('ZEROKIT_XSS')>";

echo "[*] Testing XSS payload: $payload_basic\n";

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

// Check if payload appears unescaped in output
if (strpos($output, "<script>alert('ZEROKIT_XSS')</script>") !== false) {
    echo "✅ VULNERABILITY CONFIRMED: Script tag not escaped\n";
    $success = true;
}

if (strpos($output, "onerror=alert") !== false) {
    echo "✅ VULNERABILITY CONFIRMED: Event handler injection\n";
    $success = true;
}

if (strpos($output, "<svg onload=") !== false) {
    echo "✅ VULNERABILITY CONFIRMED: SVG-based XSS\n";
    $success = true;
}

// Check if sanitization is absent
if (!empty($code) && !preg_match('/(esc_html|htmlspecialchars|htmlentities|wp_kses)/i', $code)) {
    echo "⚠️  NO SANITIZATION DETECTED\n";
}

// =====================================================
// RESULT
// =====================================================
echo "\n====================================\n";
if ($success) {
    echo "🚨 RESULT: EXPLOITABLE (XSS)\n";
    echo "Severity: {{SEVERITY}}\n";
    echo "Impact: Session hijacking, credential theft, defacement\n";
    exit(0);
} else {
    echo "❌ RESULT: NOT EXPLOITABLE\n";
    echo "Payload was properly escaped/sanitized\n";
    exit(1);
}
