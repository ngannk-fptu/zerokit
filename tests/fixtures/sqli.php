<?php
/**
 * Plugin Name: Vulnerable Test Plugin
 */

function vulnerable_function() {
    global $wpdb;
    $id = $_GET['id'];
    
    // VULNERABILITY: SQL Injection
    // Line 10 should be flagged
    $wpdb->query("SELECT * FROM wp_users WHERE ID = $id");
}

function safe_function() {
    global $wpdb;
    $id = intval($_GET['id']);
    
    // SAFE: Sanitized
    $wpdb->query("SELECT * FROM wp_users WHERE ID = $id");
}
