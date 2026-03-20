import logging
import uuid
from typing import List, Optional, Dict, Any
from ..models import AttackSurface, Hypothesis, EntryPointType
from ..llm_gateway import LLMGateway
from ..utils import extract_json

logger = logging.getLogger(__name__)

class ThreatModeler:
    """
    AI-Powered Threat Modeling Agent.
    Uses LLMGateway to analyze entry points and generate security hypotheses.
    """
    
    def __init__(self, llm_gateway: Optional[LLMGateway] = None):
        self.llm = llm_gateway or LLMGateway()

    async def generate_hypotheses(self, surface: AttackSurface, security_profile: Optional[Any] = None, code_graph: Optional[Dict] = None, repo_path: str = "") -> List[Hypothesis]:
        hypotheses = []
        logger.info(f"Threat Modeling started for {len(surface.entry_points)} entry points")
        
        # Pre-calculate Reachable Sinks from code_graph
        reachable_sinks = []
        if code_graph:
            reachable_sinks = self._get_reachable_sinks(code_graph)
            logger.info(f"  [Semantic] Identified {len(reachable_sinks)} reachable sinks from graph.")

        for ep in surface.entry_points:
            # Skip trivial entry points (simple assets, empty files)
            if self._is_trivial(ep.code_location):
                continue

            try:
                # Prepare summary of code graph for this specific entry point
                graph_summary = "No graph data"
                if code_graph:
                    # Find potential sinks reachable from this EP
                    reachable = [s for s in reachable_sinks if s.get('entry_point') == ep.code_location]
                    if reachable:
                        graph_summary = f"Reachable Sinks: {', '.join([s['name'] for s in reachable])}"
                    else:
                        graph_summary = "No obvious direct paths to sinks found in call graph."

                # Parse file path and line number
                import os
                filepath = ep.code_location
                target_line = 1
                if ":" in filepath:
                    parts = filepath.rsplit(":", 1)
                    if len(parts) == 2 and parts[1].isdigit():
                        filepath = parts[0]
                        target_line = int(parts[1])
                
                source_code_context = ep.code_location # Fallback
                if repo_path:
                    abs_path = os.path.join(repo_path, filepath)
                    if os.path.isfile(abs_path):
                        try:
                            with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                                lines = f.readlines()
                                start_idx = max(0, target_line - 1 - 50)
                                end_idx = min(len(lines), target_line - 1 + 150)
                                source_code_context = "".join(lines[start_idx:end_idx])
                        except Exception as e:
                            logger.warning(f"Failed to read {abs_path}: {e}")

                # Call LLM with enriched context
                # OPTIMIZATION: Only pass the relevant language skill to prevent context explosion
                lang = security_profile.language if security_profile else "Unknown"
                lang_skill_ref = f"@[skills/{lang}-security-patterns]" if lang != "Unknown" else ""
                
                response = self.llm.generate_hypotheses(
                    filename=ep.code_location,
                    source_code_context=source_code_context,
                    route_info=ep.description or "Internal Function",
                    language=lang,
                    security_profile=f"{security_profile.json() if security_profile else '{}'}\nRelevant Patterns: {lang_skill_ref}",
                    code_graph_summary=graph_summary
                )
                
                # Parse JSON Response
                # Clean markdown code blocks if present
                if "```json" in response:
                    response = response.split("```json")[1].split("```")[0].strip()
                elif "```" in response:
                    response = response.split("```")[1].split("```")[0].strip()
                    
                risks = extract_json(response, default=[])
                
                for risk in risks:
                    h = Hypothesis(
                        id=str(uuid.uuid4()),
                        description=f"{risk.get('risk', 'Risk')}: {risk.get('reasoning', '')}",
                        target_code=ep.code_location,
                        verification_plan=risk.get('suggested_check', "Standard Verification"),
                        metadata={
                            "priority": risk.get('severity', "MEDIUM"),
                            "original_entry_point_type": ep.category,
                            "llm_reasoning": risk.get('reasoning'),
                            "cwe_id": risk.get('cwe_id', "UNKNOWN"),
                            "trust_boundary": risk.get('trust_boundary', "Unknown"),
                            "source": risk.get('source', "Unknown"),
                            "sink": risk.get('sink', "Unknown")
                        }
                    )
                    hypotheses.append(h)
                    logger.info(f"Generated Hypothesis: {h.description} ({h.metadata['priority']})")
                    
            except Exception as e:
                logger.error(f"Failed to generate hypothesis for {ep.code_location}: {e}")
                # Fallback to Basic Heuristic if LLM fails
                self._fallback_heuristic(ep, hypotheses)
        
        # Sort hypotheses by priority: CRITICAL -> HIGH -> MEDIUM -> LOW
        priority_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        hypotheses.sort(key=lambda h: priority_rank.get(h.metadata.get("priority", "LOW"), 99))

        # ── Cross-Endpoint Attack Chain Analysis ──────────────────────────
        # After per-endpoint analysis, look at the big picture for chained exploits.
        chain_hypotheses = self._analyze_cross_endpoint_chains(
            hypotheses, surface, security_profile
        )
        hypotheses.extend(chain_hypotheses)

        return hypotheses

    def _get_reachable_sinks(self, code_graph: Dict) -> List[Dict]:
        """
        Identify sinks that have a path from identified entry points/sources.
        """
        nodes = code_graph.get("nodes", [])
        edges = code_graph.get("edges", [])
        
        sinks = [n for n in nodes if n.get("type") == "sink"]
        reachable = []
        
        # Build reverse adjacency list (to trace back from sinks)
        from collections import defaultdict
        incoming = defaultdict(list)
        for edge in edges:
            incoming[edge["to"]].append(edge["from"])
            
        def find_entry_point(node_name, visited):
            if node_name in visited: return None
            visited.add(node_name)
            
            # Check if current node is a known entry point (matches profile signature)
            # nodes list might have 'fullName' if it's from Joern
            node = next((n for n in nodes if n["name"] == node_name or n.get("id") == node_name), None)
            if node and node.get("file"): # Simple heuristic: if it's in a file, it might be an entry point
                return node["file"]
            
            for parent in incoming[node_name]:
                res = find_entry_point(parent, visited)
                if res: return res
            return None

        for sink in sinks:
            entry_point = find_entry_point(sink["name"], set())
            if entry_point:
                reachable.append({
                    "name": sink["name"],
                    "entry_point": entry_point,
                    "location": f"{sink.get('file')}:{sink.get('line')}"
                })
                
        return reachable

    # -----------------------------------------------------------------
    # Cross-Endpoint Attack Chain Discovery
    # -----------------------------------------------------------------

    # Sensitive keywords that mark an endpoint as worth including in
    # the cross-endpoint attack-chain analysis. Endpoints that don't
    # match any keyword are skipped to avoid N² combinatorial explosion.
    _CHAIN_KEYWORDS = {
        "upload", "download", "file", "admin", "config", "auth",
        "token", "login", "register", "password", "session",
        "profile", "avatar", "export", "import", "debug", "log",
        "reset", "invite", "api_key", "webhook", "callback",
    }

    def _analyze_cross_endpoint_chains(
        self,
        hypotheses: List[Hypothesis],
        surface: 'AttackSurface',
        security_profile: Optional[Any] = None,
    ) -> List[Hypothesis]:
        """
        After per-endpoint hypothesis generation, aggregate all findings
        into a structured table and ask the LLM to discover multi-step
        exploit chains across endpoints.

        Pre-filters endpoints by sensitive keywords to avoid token explosion.
        """
        if len(hypotheses) < 2:
            logger.info("  [ChainAnalysis] Skipped — need ≥ 2 hypotheses for chain discovery.")
            return []

        # ── Step 1: Pre-filter — only endpoints with sensitive keywords ──
        relevant = []
        for h in hypotheses:
            location_lower = h.target_code.lower()
            description_lower = h.description.lower()
            combined = location_lower + " " + description_lower
            if any(kw in combined for kw in self._CHAIN_KEYWORDS):
                relevant.append(h)

        if len(relevant) < 2:
            logger.info(f"  [ChainAnalysis] Only {len(relevant)} relevant endpoint(s) after keyword filter. Skipping.")
            return []

        logger.info(f"  [ChainAnalysis] Analyzing {len(relevant)} endpoints for cross-endpoint chains...")

        # ── Step 2: Build structured summary table ──────────────────────
        rows = ["| Endpoint | Method | Input Params | Detected Weakness | Note |",
                "|:---|:---|:---|:---|:---|"]

        for h in relevant:
            endpoint = h.target_code.split(":")[0] if h.target_code else "Unknown"
            method = h.metadata.get("original_entry_point_type", "UNKNOWN")
            params = h.metadata.get("source", "Unknown")
            weakness = h.description[:80]
            note = h.metadata.get("llm_reasoning", "")[:60]
            rows.append(f"| {endpoint} | {method} | {params} | {weakness} | {note} |")

        table = "\n".join(rows)

        # ── Step 3: Call LLM ────────────────────────────────────────────
        profile_str = ""
        if security_profile:
            try:
                profile_str = security_profile.json()
            except Exception:
                profile_str = str(security_profile)

        try:
            response = self.llm.generate_attack_chains(
                endpoints_summary=table,
                security_profile=profile_str[:2000]  # Cap profile to avoid token explosion
            )
        except Exception as e:
            logger.warning(f"  [ChainAnalysis] LLM call failed: {e}")
            return []

        # ── Step 4: Parse JSON → Hypothesis objects ─────────────────────
        from ..utils import extract_json
        chains = extract_json(response, default=[])

        chain_hypotheses = []
        for chain in chains:
            if not isinstance(chain, dict):
                continue

            steps = chain.get("steps", [])
            if len(steps) < 2:
                continue

            h = Hypothesis(
                id=str(uuid.uuid4()),
                description=f"[CHAIN] {chain.get('chain_name', 'Multi-Endpoint Attack')}",
                target_code="Multi-Endpoint",
                verification_plan=chain.get("verification_plan", "Custom multi-step PoC required"),
                is_chain=True,
                chain_steps=steps,
                metadata={
                    "priority": chain.get("severity", "CRITICAL"),
                    "confidence": chain.get("confidence", "MEDIUM"),
                    "chain_name": chain.get("chain_name"),
                    "is_chain": True,
                }
            )
            chain_hypotheses.append(h)
            logger.info(f"  ⛓️ Attack Chain Found: {chain.get('chain_name')} ({len(steps)} steps)")

        logger.info(f"  [ChainAnalysis] Discovered {len(chain_hypotheses)} attack chain(s).")
        return chain_hypotheses

    def _is_trivial(self, location: str) -> bool:
        """Skip non-code or static assets"""
        ignored_exts = ['.css', '.js.map', '.png', '.jpg', '.svg', '.md', '.txt']
        return any(location.endswith(ext) for ext in ignored_exts)

    def _fallback_heuristic(self, ep, hypotheses_list):
        """Legacy keyword-based fallback"""
        priority = "LOW"
        KEYWORDS = ["admin", "auth", "login", "payment", "upload", "token"]
        content = (ep.code_location + " " + (ep.description or "")).lower()
        
        if ep.category == EntryPointType.HTTP:
            priority = "HIGH"
        if any(k in content for k in KEYWORDS):
            priority = "CRITICAL"
            
        h = Hypothesis(
            id=str(uuid.uuid4()),
            description=f"Fallback Security Check for {ep.category}",
            target_code=ep.code_location,
            verification_plan="Standard Static Scan",
            metadata={"priority": priority, "note": "Generated via Fallback"}
        )
        hypotheses_list.append(h)
