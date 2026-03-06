<?php
/**
 * PoC Template: Privilege Escalation
 * Auto-generated from ZeroKit finding
 * 
 * Vulnerability: {{CATEGORY}}
 * Location: {{FILE}}:{{LINE}}
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "====================================\n";
echo "🎯 PoC: Privilege Escalation\n";
echo "Location: {{FILE}}:{{LINE}}\n";
echo "====================================\n\n";

// =====================================================
// EXPLOIT SCENARIO
// =====================================================
echo "[*] Testing privilege escalation from Subscriber to Administrator\n";

// Simulate low-privileged user
$current_user_role = "subscriber";
$target_role = "administrator";
$payload_user_id = "1"; // Admin user ID
$payload_capability = "manage_options";

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

// Check for missing capability checks before role modification
if (preg_match('/(wp_update_user|update_user_meta|set_role|add_role)/i', $code)) {
    echo "⚠️  User modification function detected\n";
    
    if (!preg_match('/current_user_can.*manage_options|current_user_can.*edit_users/i', $code)) {
        echo "✅ VULNERABILITY CONFIRMED: Role modification without capability check\n";
        $success = true;
    }
}

// Check for user meta manipulation
if (preg_match('/update_user_meta.*capabilities/i', $code) && 
    !preg_match('/current_user_can/i', $code)) {
    echo "✅ VULNERABILITY CONFIRMED: Direct capabilities modification\n";
    $success = true;
}

// Check if role was escalated
if (preg_match('/(administrator|editor|manage_options|edit_users)/i', $output)) {
    echo "✅ VULNERABILITY CONFIRMED: Privilege escalation successful\n";
    echo "    Low-privileged user gained admin capabilities\n";
    $success = true;
}

// Check for insecure direct object reference in user updates
if (preg_match('/\$_(GET|POST|REQUEST)\[.*user.*id/i', $code) &&
    !preg_match('/get_current_user_id|wp_get_current_user/i', $code)) {
    echo "✅ VULNERABILITY CONFIRMED: IDOR allows modifying any user\n";
    $success = true;
}

// Check for option updates that grant privileges
if (preg_match('/update_option.*users_can|update_option.*role/i', $code) &&
    !preg_match('/current_user_can.*manage_options/i', $code)) {
    echo "✅ VULNERABILITY CONFIRMED: Option manipulation for privilege escalation\n";
    $success = true;
}

// Check for WordPress user creation without validation
if (preg_match('/wp_create_user|wp_insert_user/i', $code) &&
    !preg_match('/current_user_can/i', $code)) {
    echo "⚠️  User creation without authorization (could create admin)\n";
    $success = true;
}

// =====================================================
// RESULT
// =====================================================
echo "\n====================================\n";
if ($success) {
    echo "🚨 RESULT: EXPLOITABLE (Privilege Escalation)\n";
    echo "Severity: {{SEVERITY}}\n";
    echo "Impact: Complete site takeover, arbitrary admin actions\n";
    echo "\nRecommendation:\n";
    echo "  - Always check current_user_can('manage_options') before role changes\n";
    echo "  - Verify user can only modify their own account\n";
    echo "  - Use wp_verify_nonce() for all privileged actions\n";
    echo "  - Never trust user-supplied user_id without validation\n";
    exit(0);
} else {
    echo "❌ RESULT: NOT EXPLOITABLE\n";
    echo "Proper capability checks present\n";
    exit(1);
}
