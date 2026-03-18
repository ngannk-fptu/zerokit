<?php
/**
 * PoC Template: Insecure SDK & API Vulnerabilities
 * Auto-generated from ZeroKit finding
 * 
 * Vulnerability: {{CATEGORY}}
 * Location: {{FILE}}:{{LINE}}
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "====================================\n";
echo "🎯 PoC: Insecure SDK & API Usage\n";
echo "Location: {{FILE}}:{{LINE}}\n";
echo "====================================\n\n";

// =====================================================
// EXPLOIT SCENARIO
// =====================================================
echo "[*] Testing for insecure third-party SDK/API usage\n";

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

// Check for hardcoded API credentials
if (preg_match('/(api[_-]?key|api[_-]?secret|client[_-]?secret)\s*=\s*[\'"][a-zA-Z0-9]{10,}/i', $code)) {
    echo "🚨 CRITICAL: Hardcoded API credentials in source code!\n";
    $success = true;
}

// Check for insecure HTTP API calls (should use HTTPS)
if (preg_match('/http:\/\/.*api\./i', $code)) {
    echo "✅ VULNERABILITY CONFIRMED: API calls over HTTP (not HTTPS)\n";
    $success = true;
}

// Check for missing SSL verification
if (preg_match('/(CURLOPT_SSL_VERIFYPEER.*false|verify.*false)/i', $code)) {
    echo "✅ VULNERABILITY CONFIRMED: SSL verification disabled (MITM risk)\n";
    $success = true;
}

// Check for API responses without validation
if (preg_match('/(curl_exec|file_get_contents|wp_remote_get)/i', $code) &&
    !preg_match('/(json_decode|xml_parse|verify|validate)/i', $code)) {
    echo "⚠️  API response used without validation\n";
    $success = true;
}

// Check for exposed API endpoints without authentication
if (preg_match('/add_action.*rest_api_init|register_rest_route/i', $code) &&
    !preg_match('/permission_callback/i', $code)) {
    echo "✅ VULNERABILITY CONFIRMED: REST API endpoint without authentication\n";
    $success = true;
}

// Check for insecure JWT usage
if (stripos($code, 'jwt') !== false) {
    if (!preg_match('/(verify|validate).*signature/i', $code)) {
        echo "✅ VULNERABILITY CONFIRMED: JWT signature not verified\n";
        $success = true;
    }
    if (preg_match('/algorithm.*none/i', $code)) {
        echo "🚨 CRITICAL: JWT 'none' algorithm allowed!\n";
        $success = true;
    }
}

// Check for OAuth misconfigurations
if (preg_match('/(oauth|access[_-]?token)/i', $code)) {
    if (preg_match('/redirect[_-]?uri.*\$_(GET|POST)/i', $code)) {
        echo "✅ VULNERABILITY CONFIRMED: Open redirect in OAuth flow\n";
        $success = true;
    }
    if (!preg_match('/(state|nonce)/i', $code)) {
        echo "⚠️  OAuth without CSRF protection (missing state parameter)\n";
        $success = true;
    }
}

// Check for rate limiting absence
if (preg_match('/(wp_ajax|rest_api_init|api.*endpoint)/i', $code) &&
    !preg_match('/(rate.*limit|throttle|transient.*count)/i', $code)) {
    echo "⚠️  API endpoint without rate limiting (DoS risk)\n";
    $success = true;
}

// Check for GraphQL introspection enabled
if (stripos($code, 'graphql') !== false &&
    !preg_match('/disable.*introspection/i', $code)) {
    echo "✅ VULNERABILITY CONFIRMED: GraphQL introspection enabled\n";
    $success = true;
}

// Check for XML External Entity (XXE) vulnerabilities
if (preg_match('/(simplexml_load|xml_parse|DOMDocument)/i', $code) &&
    !preg_match('/LIBXML_NOENT.*false|disable.*entity/i', $code)) {
    echo "✅ VULNERABILITY CONFIRMED: XXE vulnerability (XML entity expansion)\n";
    $success = true;
}

// Check for insecure deserialization
if (preg_match('/unserialize\(\s*\$_(GET|POST|REQUEST|COOKIE)/i', $code)) {
    echo "🚨 CRITICAL: Insecure deserialization from user input!\n";
    $success = true;
}

// =====================================================
// RESULT
// =====================================================
echo "\n====================================\n";
if ($success) {
    echo "🚨 RESULT: EXPLOITABLE (Insecure SDK/API)\n";
    echo "Severity: {{SEVERITY}}\n";
    echo "Impact: Credential theft, MITM attacks, data breach, RCE\n";
    echo "\nRecommendation:\n";
    echo "  - Store API keys in environment variables or wp-config.php\n";
    echo "  - Always use HTTPS for API calls\n";
    echo "  - Enable SSL verification (CURLOPT_SSL_VERIFYPEER = true)\n";
    echo "  - Add permission_callback to REST API routes\n";
    echo "  - Validate JWT signatures and disallow 'none' algorithm\n";
    echo "  - Implement rate limiting on API endpoints\n";
    echo "  - Disable XML external entities (LIBXML_NOENT = false)\n";
    echo "  - Never unserialize() user input\n";
    exit(0);
} else {
    echo "❌ RESULT: NOT EXPLOITABLE\n";
    echo "SDK/API security properly implemented\n";
    exit(1);
}
