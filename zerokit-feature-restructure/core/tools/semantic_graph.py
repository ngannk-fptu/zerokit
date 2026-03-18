"""
SemanticGraph: Unified Code Property Graph (CPG) builder.

Dispatches to the correct static analysis engine based on language:
  - C/C++, Java  → Joern (via joern_runner.py)
  - C#            → CodeQL (via codeql_runner.py)
  - Python, JS,
    Go, Ruby, PHP → Tree-sitter (AST traversal, lightweight)

Output: code_graph.json with nodes (functions, sinks, sources) and edges (calls, data_flow).
"""

import os
import json
import logging
import subprocess
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

TREE_SITTER_LANGUAGES = ["python", "javascript", "typescript", "go", "ruby", "php", "rust"]
JOERN_LANGUAGES      = ["c", "cpp", "java"]
CODEQL_LANGUAGES     = ["csharp", "cs"]


class SemanticGraph:
    """
    Unified entry point for building Code Property Graphs.
    Selects the optimal engine per language.
    """

    def __init__(self, repo_path: str, language: str, workspace: str = None):
        self.repo_path = os.path.abspath(repo_path)
        self.language  = language.lower().strip()
        self.workspace = workspace or os.path.join("storage", "workspaces", "semantic_graph")
        os.makedirs(self.workspace, exist_ok=True)
        self.output_path = os.path.join(self.workspace, "code_graph.json")

    async def build(self) -> Dict:
        """
        Build the code graph for the given repo+language.
        Returns the graph dict and writes it to code_graph.json.
        """
        if self.language in JOERN_LANGUAGES:
            logger.info(f"[SemanticGraph] Using Joern CPG for {self.language}")
            graph = await self._build_with_joern()
        elif self.language in CODEQL_LANGUAGES:
            logger.info(f"[SemanticGraph] Using CodeQL for {self.language}")
            graph = self._build_with_codeql()
        elif self.language in TREE_SITTER_LANGUAGES:
            logger.info(f"[SemanticGraph] Using Tree-sitter for {self.language}")
            graph = self._build_with_tree_sitter()
        else:
            logger.warning(f"[SemanticGraph] Unknown language '{self.language}', falling back to Tree-sitter")
            graph = self._build_with_tree_sitter()

        self._write_graph(graph)
        logger.info(f"[SemanticGraph] Graph built: {len(graph.get('nodes', []))} nodes, {len(graph.get('edges', []))} edges")
        return graph

    # ─────────────────────────────────────────────────────────
    # Engine 1: Joern (C/C++, Java)
    # ─────────────────────────────────────────────────────────
    async def _build_with_joern(self) -> Dict:
        """Build CPG using Joern. Reuses the existing JoernRunner."""
        try:
            from ..tools.joern_runner import JoernRunner
            joern = JoernRunner()
            
            # 1. Parse code to CPG
            cpg_path = await joern.parse_code_async(self.repo_path, self.language)
            
            # 2. Extract structured graph
            graph = await joern.get_code_graph_structured(cpg_path)
            graph["engine"] = "joern"
            graph["language"] = self.language
            return graph
            
        except Exception as e:
            logger.error(f"[SemanticGraph][Joern] Error: {e}")
            return self._empty_graph("joern", str(e))

    # ─────────────────────────────────────────────────────────
    # Engine 2: CodeQL (C#)
    # ─────────────────────────────────────────────────────────
    def _build_with_codeql(self) -> Dict:
        """Build data-flow graph using CodeQL DB + query."""
        try:
            from ..tools.codeql_runner import CodeQLRunner
            from ..config import config
            codeql = CodeQLRunner(codeql_path=config.CODEQL_BIN)

            db_path = os.path.join(self.workspace, "codeql_db")
            # Create DB
            codeql.create_database(self.repo_path, db_path, language="csharp")

            # Query for sources, sinks, and call edges
            query = """
import csharp
import semmle.code.csharp.dataflow.DataFlow

from DataFlow::Node source, DataFlow::Node sink
where DataFlow::localFlow(source, sink)
select source, sink, "Local data flow"
"""
            sarif = codeql.run_inline_query(db_path, query)
            return self._parse_codeql_sarif(sarif)
        except Exception as e:
            logger.error(f"[SemanticGraph][CodeQL] Error: {e}")
            return self._empty_graph("codeql", str(e))

    # ─────────────────────────────────────────────────────────
    # Engine 3: Tree-sitter (Python, JS, Go, etc.)
    # ─────────────────────────────────────────────────────────
    def _build_with_tree_sitter(self) -> Dict:
        """
        Lightweight AST traversal using tree-sitter.
        Extracts function definitions and call sites without running code.
        """
        nodes: List[Dict] = []
        edges: List[Dict] = []

        try:
            import tree_sitter_python as tspython
            import tree_sitter_javascript as tsjavascript
            from tree_sitter import Language, Parser

            lang_map = {
                "python": tspython.language(),
                "javascript": tsjavascript.language(),
                "typescript": tsjavascript.language(),
            }

            ts_lang = lang_map.get(self.language)
            if not ts_lang:
                return self._fallback_regex_walk()

            parser = Parser(Language(ts_lang))
            nodes, edges = self._walk_repo_tree_sitter(parser, self.language)

        except ImportError:
            logger.warning("[SemanticGraph][Tree-sitter] Not installed. Falling back to regex walk.")
            return self._fallback_regex_walk()
        except Exception as e:
            logger.error(f"[SemanticGraph][Tree-sitter] Error: {e}")
            return self._empty_graph("tree-sitter", str(e))

        return {"engine": "tree-sitter", "language": self.language, "nodes": nodes, "edges": edges}

    def _walk_repo_tree_sitter(self, parser, language: str):
        """Walk all source files and extract function defs + calls."""
        nodes, edges = [], []
        ext_map = {"python": ".py", "javascript": ".js", "typescript": ".ts"}
        target_ext = ext_map.get(language, ".py")

        for root, _, files in os.walk(self.repo_path):
            for f in files:
                if f.endswith(target_ext):
                    fpath = os.path.join(root, f)
                    try:
                        with open(fpath, "rb") as fp:
                            code = fp.read()
                        tree = parser.parse(code)
                        file_nodes, file_edges = self._extract_from_ast(tree.root_node, fpath, code)
                        nodes.extend(file_nodes)
                        edges.extend(file_edges)
                    except Exception:
                        pass
        return nodes, edges

    def _extract_from_ast(self, node, filepath: str, source: bytes):
        """Recursively extract functions and calls from AST node."""
        nodes, edges = [], []
        rel_path = os.path.relpath(filepath, self.repo_path)

        def walk(n):
            if n.type in ("function_definition", "function_declaration", "method_definition"):
                name_node = n.child_by_field_name("name")
                if name_node:
                    name = source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="ignore")
                    nodes.append({"id": f"{rel_path}::{name}", "type": "function", "name": name, "file": rel_path, "line": n.start_point[0] + 1})
            elif n.type == "call":
                func_node = n.child_by_field_name("function")
                if func_node:
                    call_name = source[func_node.start_byte:func_node.end_byte].decode("utf-8", errors="ignore")
                    edges.append({"from": rel_path, "to": call_name, "type": "call", "line": n.start_point[0] + 1})
            for child in n.children:
                walk(child)

        walk(node)
        return nodes, edges

    def _fallback_regex_walk(self) -> Dict:
        """Regex-based fallback when tree-sitter is unavailable."""
        import re
        nodes, edges = [], []
        fn_patterns = {
            "python": r"def\s+(\w+)\s*\(",
            "javascript": r"(?:function\s+(\w+)|const\s+(\w+)\s*=\s*(?:async\s*)?\()",
            "go": r"func\s+(\w+)\s*\(",
            "ruby": r"def\s+(\w+)",
            "php": r"function\s+(\w+)\s*\(",
        }
        call_patterns = {
            "python": r"(\w+)\s*\(",
            "javascript": r"(\w+)\s*\(",
            "go": r"(\w+)\s*\(",
        }
        fn_re  = re.compile(fn_patterns.get(self.language, r"def\s+(\w+)\s*\("))
        call_re = re.compile(call_patterns.get(self.language, r"(\w+)\s*\("))

        for root, _, files in os.walk(self.repo_path):
            if ".git" in root or "__pycache__" in root:
                continue
            for fname in files:
                if fname.endswith((".py", ".js", ".ts", ".go", ".rb", ".php")):
                    fpath = os.path.join(root, fname)
                    rel   = os.path.relpath(fpath, self.repo_path)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
                            for i, line in enumerate(fp, 1):
                                for m in fn_re.finditer(line):
                                    name = next(g for g in m.groups() if g)
                                    nodes.append({"id": f"{rel}::{name}", "type": "function", "name": name, "file": rel, "line": i})
                                for m in call_re.finditer(line):
                                    edges.append({"from": rel, "to": m.group(1), "type": "call", "line": i})
                    except Exception:
                        pass
        return {"engine": "regex-fallback", "language": self.language, "nodes": nodes, "edges": edges}

    # ─────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────
    def _parse_joern_output(self, raw: str) -> Dict:
        return {"engine": "joern", "language": self.language, "nodes": [], "edges": [], "raw": raw}

    def _parse_codeql_sarif(self, sarif: dict) -> Dict:
        nodes, edges = [], []
        for run in sarif.get("runs", []):
            for result in run.get("results", []):
                locs = result.get("locations", [])
                rel_msg = result.get("relatedLocations", [])
                if locs:
                    src = locs[0].get("physicalLocation", {})
                    edges.append({"from": src.get("artifactLocation", {}).get("uri", ""), "to": rel_msg[0].get("message", {}).get("text", "") if rel_msg else "", "type": "data_flow"})
        return {"engine": "codeql", "language": self.language, "nodes": nodes, "edges": edges}

    def _write_graph(self, graph: Dict):
        with open(self.output_path, "w", encoding="utf-8") as f:
            json.dump(graph, f, indent=2)

    def _empty_graph(self, engine: str, error: str) -> Dict:
        return {"engine": engine, "language": self.language, "nodes": [], "edges": [], "error": error}
