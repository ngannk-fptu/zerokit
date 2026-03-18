<?php
/**
 * Plugin Name: Advanced Vulnerable Plugin
 */

// Case 1: Taint Propagation through apply_filters
// Data flow: $_GET['xss'] -> $unsafe -> apply_filters -> $final -> echo
function test_apply_filters_xss() {
    $unsafe = $_GET['xss'];
    // Semgrep usually loses taint here without config
    $final = apply_filters('my_custom_filter', $unsafe); 
    echo $final; 
}

// Case 2: Context-Aware wpdb->prepare
function test_unsafe_prepare() {
    global $wpdb;
    $id = $_GET['id'];
    
    // UNSAFE: Concatenation inside prepare
    // Should be CRITICAL SQLi, not Safe
    $wpdb->query($wpdb->prepare("SELECT * FROM users WHERE id = " . $id));
    
    // SAFE: Placeholder usage
    $wpdb->query($wpdb->prepare("SELECT * FROM users WHERE id = %d", $id));
}

// Case 3: Hidden Entry Point (Direct Global Access)
// Not triggered by hooks, just raw PHP execution flow or manual include
if (isset($_POST['cmd'])) {
    // Hidden RCE
    system($_POST['cmd']);
}

function custom_router() {
    // URI-based routing
    if (strpos($_SERVER['REQUEST_URI'], '/custom-api') !== false) {
        // Vulnerable logic reachable via custom route
        $data = $_GET['data'];
        echo $data;
    }
}
