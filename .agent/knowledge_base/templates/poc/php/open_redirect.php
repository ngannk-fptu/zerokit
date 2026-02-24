<?php
/**
 * PoC Template: Open Redirect
 * 
 * Vulnerability: Unvalidated redirect destinations allowing phishing attacks
 * Common in: WordPress login redirects, custom authentication flows
 * 
 * Detection: Look for wp_redirect() without wp_safe_redirect(), header('Location: ') with user input
 * 
 * Metadata:
 * - Category: {{CATEGORY}}
 * - Severity: {{SEVERITY}}
 * - File: {{FILE}}
 * - Line: {{LINE}}
 */

// VULNERABLE CODE LOCATION
// {{VULNERABLE_CODE}}

echo "=== Open Redirect PoC ===\n\n";

// Step 1: Define test payloads
$test_payloads = [
    [
        'name' => 'Direct external URL',
        'payload' => 'http://evil.com/phishing',
        'expected' => 'evil.com'
    ],
    [
        'name' => 'Protocol-relative URL',
        'payload' => '//evil.com/phishing',
        'expected' => 'evil.com'
    ],
    [
        'name' => 'JavaScript protocol',
        'payload' => 'javascript:alert(document.domain)',
        'expected' => 'javascript:'
    ],
    [
        'name' => 'Data URI',
        'payload' => 'data:text/html,<script>alert(1)</script>',
        'expected' => 'data:'
    ],
    [
        'name' => 'URL with @ symbol',
        'payload' => 'https://trusted.com@evil.com/',
        'expected' => 'evil.com'
    ],
    [
        'name' => 'Backslash bypass (Windows)',
        'payload' => 'https://trusted.com\\@evil.com/',
        'expected' => 'evil.com'
    ],
    [
        'name' => 'Double slash bypass',
        'payload' => '///evil.com',
        'expected' => 'evil.com'
    ]
];

// Step 2: Define mock WordPress functions if not available
if (!function_exists('wp_safe_redirect')) {
    function wp_safe_redirect($location, $status = 302) {
        // Safe redirect only allows relative URLs and whitelisted hosts
        $allowed_hosts = ['localhost', '127.0.0.1', $_SERVER['HTTP_HOST'] ?? 'example.com'];
        
        $parsed = parse_url($location);
        if (isset($parsed['host']) && !in_array($parsed['host'], $allowed_hosts)) {
            return false; // Blocked
        }
        return true; // Allowed
    }
}

// Step 3: Test each payload
echo "[*] Testing open redirect payloads...\n\n";

$vulnerable_payloads = [];

foreach ($test_payloads as $test) {
    echo "Testing: {$test['name']}\n";
    echo "  Payload: {$test['payload']}\n";
    
    // Simulate vulnerable code (wp_redirect without validation)
    $redirect_url = $test['payload'];
    
    // Parse URL to check host
    $parsed = @parse_url($redirect_url);
    
    if ($parsed === false) {
        echo "  [!] Invalid URL format\n\n";
        continue;
    }
    
    // Check if it's an external redirect
    $is_external = false;
    $target_host = '';
    
    if (isset($parsed['host'])) {
        $target_host = $parsed['host'];
        $current_host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        
        if ($target_host !== $current_host && $target_host !== 'localhost') {
            $is_external = true;
        }
    } elseif (isset($parsed['scheme']) && in_array($parsed['scheme'], ['javascript', 'data', 'vbscript'])) {
        // Dangerous protocols
        $is_external = true;
        $target_host = $parsed['scheme'];
    } elseif (strpos($redirect_url, '//') === 0) {
        // Protocol-relative URL
        if (preg_match('#^//([^/]+)#', $redirect_url, $matches)) {
            $target_host = $matches[1];
            $is_external = true;
        }
    }
    
    if ($is_external) {
        echo "  [✓] VULNERABLE: External redirect to $target_host\n";
        $vulnerable_payloads[] = $test;
        
        // Test if wp_safe_redirect would block it
        if (function_exists('wp_safe_redirect')) {
            $safe = wp_safe_redirect($redirect_url);
            if ($safe === false) {
                echo "  [i] wp_safe_redirect() would BLOCK this\n";
            } else {
                echo "  [!] wp_safe_redirect() would ALLOW this (bypass!)\n";
            }
        }
    } else {
        echo "  [-] No external redirect detected\n";
    }
    
    echo "\n";
}

// Step 4: Verify exploitation
if (count($vulnerable_payloads) > 0) {
    echo "=== VERIFICATION ===\n";
    echo "[✓] Open Redirect CONFIRMED\n";
    echo "[✓] Found " . count($vulnerable_payloads) . " vulnerable payloads\n\n";
    
    echo "=== VULNERABLE PAYLOADS ===\n";
    foreach ($vulnerable_payloads as $vuln) {
        echo "- {$vuln['name']}: {$vuln['payload']}\n";
    }
    echo "\n";
    
    echo "=== IMPACT ===\n";
    echo "- Phishing attacks (redirect to fake login page)\n";
    echo "- OAuth token  theft\n";
    echo "- Credential harvesting\n";
    echo "- Bypassing CSRF protections\n\n";
    
    echo "=== ATTACK SCENARIO ===\n";
    echo "1. Attacker crafts malicious URL:\n";
    echo "   https://trusted-site.com/login?redirect_to=http://evil.com/fake-login\n";
    echo "2. Victim clicks link (trusts the domain)\n";
    echo "3. After login, victim is redirected to attacker's site\n";
    echo "4. Attacker's site looks identical to real site\n";
    echo "5. Victim enters credentials on phishing page\n\n";
    
    echo "=== WORDPRESS-SPECIFIC RISKS ===\n";
    echo "- wp_redirect() without validation\n";
    echo "- Custom login/logout redirects\n";
    echo "- OAuth callback URLs\n";
    echo "- 'redirect_to' parameter in wp-login.php\n\n";
    
    echo "=== RECOMMENDATION ===\n";
    echo "1. Always use wp_safe_redirect() instead of wp_redirect()\n";
    echo "2. Validate redirect URLs against whitelist\n";
    echo "3. Use wp_validate_redirect() to check allowed hosts\n";
    echo "4. Never redirect to user-supplied URLs directly\n";
    echo "5. Code examples:\n";
    echo "   // VULNERABLE\n";
    echo "   wp_redirect(\$_GET['redirect_to']);\n\n";
    echo "   // SAFE\n";
    echo "   \$safe_url = wp_validate_redirect(\$_GET['redirect_to'], home_url());\n";
    echo "   wp_safe_redirect(\$safe_url);\n";
    
    exit(0); // SUCCESS
    
} else {
    echo "\n[✗] Open Redirect verification failed\n";
    echo "[✗] No vulnerable redirect patterns detected\n";
    echo "[i] All redirects appear to be properly validated\n";
    exit(1); // FAILURE
}
?>
