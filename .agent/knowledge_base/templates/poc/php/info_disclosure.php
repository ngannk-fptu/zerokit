<?php
/**
 * PoC Template: Sensitive Information Disclosure
 * Auto-generated from ZeroKit finding
 * 
 * Vulnerability: {{CATEGORY}}
 * Location: {{FILE}}:{{LINE}}
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "====================================\n";
echo "🎯 PoC: Sensitive Information Disclosure\n";
echo "Location: {{FILE}}:{{LINE}}\n";
echo "====================================\n\n";

// =====================================================
// EXPLOIT SCENARIO
// =====================================================
echo "[*] Testing for sensitive data exposure\n";

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
$severity = "MEDIUM";

// Check for password exposure
if (preg_match('/(password|passwd|pwd|user_pass).*[\'"][^\'\"]{6,}/i', $output)) {
    echo "🚨 CRITICAL: Password exposed in output!\n";
    $success = true;
    $severity = "CRITICAL";
}

// Check for API keys/tokens
if (preg_match('/(api[_-]?key|api[_-]?secret|token|auth[_-]?key|access[_-]?token|bearer)/i', $output)) {
    echo "🚨 CRITICAL: API key/token exposed!\n";
    $success = true;
    $severity = "CRITICAL";
}

// Check for database credentials
if (preg_match('/(DB_PASSWORD|DB_USER|DB_HOST|database.*password)/i', $output)) {
    echo "🚨 CRITICAL: Database credentials exposed!\n";
    $success = true;
    $severity = "CRITICAL";
}

// Check for email addresses without authorization
if (preg_match('/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/i', $output) &&
    !preg_match('/current_user_can/i', $code)) {
    echo "✅ VULNERABILITY CONFIRMED: Email addresses exposed\n";
    $success = true;
}

// Check for user enumeration
if (preg_match('/(user_login|user_email|display_name)/i', $output) &&
    !preg_match('/current_user_can/i', $code)) {
    echo "✅ VULNERABILITY CONFIRMED: User enumeration possible\n";
    $success = true;
}

// Check for directory listing
if (preg_match('/Index of|Directory listing|\.\.\/|Parent Directory/i', $output)) {
    echo "✅ VULNERABILITY CONFIRMED: Directory listing exposed\n";
    $success = true;
}

// Check for PHP error messages with paths
if (preg_match('/(Warning|Notice|Fatal error).*in\s+\/.*\.php/i', $output)) {
    echo "✅ VULNERABILITY CONFIRMED: PHP errors reveal paths\n";
    $success = true;
}

// Check for SQL errors with query details
if (preg_match('/(SQL syntax|mysql_fetch|You have an error.*SQL)/i', $output)) {
    echo "✅ VULNERABILITY CONFIRMED: SQL errors expose schema\n";
    $success = true;
}

// Check for WordPress debug info
if (preg_match('/(wpdb|WordPress database error|wp-config)/i', $output)) {
    echo "✅ VULNERABILITY CONFIRMED: WordPress debug information exposed\n";
    $success = true;
}

// Check for phpinfo() output
if (preg_match('/(PHP Version|phpinfo\(\)|System.*Linux)/i', $output)) {
    echo "🚨 CRITICAL: phpinfo() exposed!\n";
    $success = true;
    $severity = "CRITICAL";
}

// Check for backup file access (.sql, .bak, wp-config.php~)
if (preg_match('/\.(sql|bak|backup|old|~)$/i', $code)) {
    echo "✅ VULNERABILITY CONFIRMED: Backup file accessible\n";
    $success = true;
}

// =====================================================
// RESULT
// =====================================================
echo "\n====================================\n";
if ($success) {
    echo "🚨 RESULT: EXPLOITABLE (Information Disclosure)\n";
    echo "Severity: $severity\n";
    echo "Impact: Data breach, credential theft, system reconnaissance\n";
    echo "\nRecommendation:\n";
    echo "  - Disable WP_DEBUG in production\n";
    echo "  - Add authorization checks before displaying sensitive data\n";
    echo "  - Use proper error handling (log, don't display)\n";
    echo "  - Remove phpinfo() and debug endpoints\n";
    echo "  - Block access to backup files via .htaccess\n";
    exit(0);
} else {
    echo "❌ RESULT: NOT EXPLOITABLE\n";
    echo "No sensitive information disclosed\n";
    exit(1);
}
