"""
Variant Analyzer - Single-Repo Pattern Matching

Takes VERIFIED vulnerabilities and generates variant detection rules to find
similar patterns across the entire codebase.

Strategy:
1. Extract pattern from verified finding (sink + source + missing sanitizer)
2. Generate language-specific Semgrep rules for variant detection
3. Run full-repo scan (not differential)
4. Return candidates for verification
"""
import logging
import os
import tempfile
import yaml
from typing import List, Dict, Optional
from ..models import VerifiedVuln, StaticFinding, FindingSeverity, VulnerabilityCategory
from ..tools.semgrep_runner import SemgrepRunner

logger = logging.getLogger(__name__)


class VariantAnalyzer:
    """
    Finds vulnerability variants by pattern matching.
    
    Workflow:
    - Input: 1 verified SQL Injection
    - Output: 3-5 similar SQL Injection candidates
    """
    
    def __init__(self, semgrep_runner: Optional[SemgrepRunner] = None):
        self.semgrep = semgrep_runner or SemgrepRunner()
        self.variant_rules_cache = {}
    
    async def find_variants(
        self, 
        verified_vuln: VerifiedVuln, 
        repo_path: str,
        original_finding: Optional[StaticFinding] = None
    ) -> List[StaticFinding]:
        """
        Find variants of a verified vulnerability.
        
        Args:
            verified_vuln: Confirmed vulnerability
            repo_path: Repository path to scan
            original_finding: Original StaticFinding for context
            
        Returns:
            List of potential variant findings
        """
        logger.info(f"\n=== Variant Analysis for {verified_vuln.finding_id} ===")
        
        # Step 1: Extract pattern
        pattern = self._extract_pattern(verified_vuln, original_finding)
        
        if not pattern:
            logger.warning("Could not extract pattern from verified vuln")
            return []
        
        logger.info(f"  Pattern: {pattern['type']}")
        logger.info(f"  Sink: {pattern.get('sink', 'unknown')}")
        logger.info(f"  Source: {pattern.get('source', 'unknown')}")
        
        # Step 2: Generate variant detection rules
        rules_yaml = self._generate_variant_rules(pattern, verified_vuln)
        
        if not rules_yaml:
            logger.warning("Could not generate variant rules")
            return []
        
        # Step 3: Run full-repo scan
        variants = await self._scan_for_variants(rules_yaml, repo_path, verified_vuln)
        
        logger.info(f"  Found {len(variants)} potential variants")
        
        return variants
    
    def _extract_pattern(
        self, 
        verified_vuln: VerifiedVuln,
        original_finding: Optional[StaticFinding]
    ) -> Optional[Dict]:
        """
        Extract vulnerability pattern for matching.
        
        Returns pattern dict with:
        - type: Vulnerability category
        - sink: Dangerous function/method
        - source: User input source
        - language: Programming language
        """
        # Get category from metadata or description
        vuln_type = None
        
        if original_finding:
            vuln_type = original_finding.metadata.get("category")
            language = original_finding.metadata.get("language", "PHP")
            evidence = original_finding.evidence
        else:
            # Infer from description
            desc = verified_vuln.description or ""
            language = "PHP"  # Default to PHP
            evidence = verified_vuln.evidence
        
        # Pattern extraction based on evidence
        sink = self._identify_sink(evidence, vuln_type)
        source = self._identify_source(evidence)
        
        if not sink:
            return None
        
        return {
            "type": vuln_type or "UNKNOWN",
            "sink": sink,
            "source": source,
            "language": language,
            "evidence": evidence
        }
    
    def _identify_sink(self, evidence: str, vuln_type: Optional[str]) -> Optional[str]:
        """Identify dangerous function (sink) from evidence."""
        # PHP sinks mapping
        php_sinks = {
            "SQL_INJECTION": ["query", "prepare", "get_results", "get_var", "wpdb->"],
            "COMMAND_INJECTION": ["exec", "shell_exec", "system", "passthru", "popen"],
            "XSS": ["echo", "print", "printf", "file_get_contents"],
            "PATH_TRAVERSAL": ["file_get_contents", "fopen", "include", "require"],
            "DESERIALIZATION": ["unserialize", "maybe_unserialize"],
            "XXE": ["simplexml_load_string", "simplexml_load_file", "DOMDocument"],
        }
        
        # Check evidence for known sinks
        for category, sinks in php_sinks.items():
            if vuln_type and category in vuln_type:
                for sink in sinks:
                    if sink in evidence.lower():
                        return sink
        
        # Fallback: extract from evidence
        import re
        # Match function calls: functionName(
        matches = re.findall(r'(\w+(?:->\w+)?)\s*\(', evidence)
        if matches:
            return matches[0]
        
        return None
    
    def _identify_source(self, evidence: str) -> Optional[str]:
        """Identify user input source from evidence."""
        sources = ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER"]
        
        for source in sources:
            if source in evidence:
                return source
        
        return "user_input"
    
    def _generate_variant_rules(
        self, 
        pattern: Dict, 
        verified_vuln: VerifiedVuln
    ) -> Optional[str]:
        """
        Generate Semgrep rules for variant detection.
        
        Rules are more relaxed than original detection to find similar patterns.
        """
        vuln_type = pattern["type"]
        sink = pattern["sink"]
        language = pattern["language"].lower()
        
        # Generate rule based on vulnerability type
        if "SQL" in vuln_type or "sql" in vuln_type:
            return self._generate_sql_injection_variant_rule(sink, language)
        elif "COMMAND" in vuln_type or "RCE" in vuln_type:
            return self._generate_command_injection_variant_rule(sink, language)
        elif "XSS" in vuln_type:
            return self._generate_xss_variant_rule(sink, language)
        elif "DESERIAL" in vuln_type:
            return self._generate_deserialization_variant_rule(sink, language)
        elif "XXE" in vuln_type:
            return self._generate_xxe_variant_rule(sink, language)
        else:
            logger.warning(f"No variant rule generator for type: {vuln_type}")
            return None
    
    def _generate_sql_injection_variant_rule(self, sink: str, language: str) -> str:
        """Generate SQL injection variant detection rule."""
        rule_id = f"variant-sql-injection-{sink.replace('->', '-')}"
        
        return f"""
rules:
  - id: {rule_id}
    pattern-either:
      - pattern: |
          $wpdb->query("... " . $VAR . " ...")
      - pattern: |
          $wpdb->query("... {{$VAR}} ...")
      - pattern: |
          $wpdb->get_results("... " . $VAR . " ...")
      - pattern: |
          $wpdb->get_var("... " . $VAR . " ...")
      - pattern: |
          {sink}("... " . $VAR . " ...")
    pattern-not-inside: |
      $wpdb->prepare(...)
    message: "Potential SQL injection variant (similar to verified finding)"
    severity: WARNING
    languages: [{language}]
    metadata:
      category: SQL_INJECTION_VARIANT
      confidence: MEDIUM
"""
    
    def _generate_command_injection_variant_rule(self, sink: str, language: str) -> str:
        """Generate command injection variant rule."""
        rule_id = f"variant-command-injection-{sink}"
        
        return f"""
rules:
  - id: {rule_id}
    pattern-either:
      - pattern: exec($VAR)
      - pattern: shell_exec($VAR)
      - pattern: system($VAR)
      - pattern: passthru($VAR)
      - pattern: {sink}($VAR)
    pattern-not-inside: |
      escapeshellarg(...)
    message: "Potential command injection variant (similar to verified finding)"
    severity: WARNING
    languages: [{language}]
    metadata:
      category: COMMAND_INJECTION_VARIANT
      confidence: MEDIUM
"""
    
    def _generate_xss_variant_rule(self, sink: str, language: str) -> str:
        """Generate XSS variant rule."""
        rule_id = f"variant-xss-{sink}"
        
        return f"""
rules:
  - id: {rule_id}
    pattern-either:
      - pattern: echo $VAR
      - pattern: print $VAR
      - pattern: printf($VAR)
      - pattern: {sink} $VAR
    pattern-not-inside: |
      esc_html(...)
    pattern-not-inside: |
      esc_attr(...)
    message: "Potential XSS variant (similar to verified finding)"
    severity: WARNING
    languages: [{language}]
    metadata:
      category: XSS_VARIANT
      confidence: MEDIUM
"""
    
    def _generate_deserialization_variant_rule(self, sink: str, language: str) -> str:
        """Generate deserialization variant rule."""
        rule_id = f"variant-deserialization-{sink}"
        
        return f"""
rules:
  - id: {rule_id}
    pattern-either:
      - pattern: unserialize($VAR)
      - pattern: maybe_unserialize($VAR)
    pattern-not-inside: |
      hash_equals(...)
    message: "Potential deserialization variant (similar to verified finding)"
    severity: WARNING
    languages: [{language}]
    metadata:
      category: DESERIALIZATION_VARIANT
      confidence: MEDIUM
"""
    
    def _generate_xxe_variant_rule(self, sink: str, language: str) -> str:
        """Generate XXE variant rule."""
        rule_id = f"variant-xxe-{sink}"
        
        return f"""
rules:
  - id: {rule_id}
    pattern-either:
      - pattern: simplexml_load_string($VAR)
      - pattern: simplexml_load_file($VAR)
      - pattern: |
          $doc = new DOMDocument();
          $doc->loadXML($VAR);
    pattern-not-inside: |
      libxml_disable_entity_loader(true)
    message: "Potential XXE variant (similar to verified finding)"
    severity: WARNING
    languages: [{language}]
    metadata:
      category: XXE_VARIANT
      confidence: MEDIUM
"""
    
    async def _scan_for_variants(
        self, 
        rules_yaml: str, 
        repo_path: str,
        verified_vuln: VerifiedVuln
    ) -> List[StaticFinding]:
        """Run Semgrep scan for variants across entire repo."""
        # Write temp rule file
        with tempfile.NamedTemporaryFile(
            mode='w', 
            suffix='.yaml', 
            delete=False,
            encoding='utf-8'
        ) as f:
            f.write(rules_yaml)
            rule_path = f.name
        
        try:
            logger.info(f"  Scanning {repo_path} for variants...")
            
            # Run Semgrep on ENTIRE repo (not differential)
            result = await self.semgrep.run_scan_async(
                target_path=repo_path,
                rule_config=rule_path
            )
            
            findings = result.get("findings", [])
            
            # Filter out the original finding location
            original_location = verified_vuln.poc.get("location", "")
            variants = [
                f for f in findings 
                if f.location != original_location
            ]
            
            logger.info(f"  Filtered {len(findings)} → {len(variants)} (excluded original)")
            
            return variants
            
        except Exception as e:
            logger.error(f"Variant scan failed: {str(e)}")
            return []
            
        finally:
            # Cleanup temp rule file
            try:
                os.unlink(rule_path)
            except:
                pass
