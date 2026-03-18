"""
HarnessAgent: Automated Fuzz Harness Generator

Workflow:
  1. Read target_function from a StaticFinding.
  2. Parse function signature via AST (or regex fallback).
  3. Fill a language-specific template (C/C++, Java, Python).
  4. Compile — if fails, ask LLM Worker API for a fix, retry (max 5 × 60s).
  5. If success, return harness path for AFL++ / Jazzer / Atheris.
"""

import os
import re
import ast
import uuid
import logging
import subprocess
import tempfile
from typing import Optional, Dict, Tuple
from ..utils import extract_json

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# Harness templates
# ─────────────────────────────────────────────────────────────
C_CPP_TEMPLATE = """\
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Auto-generated fuzz harness for: {func_name}
// Signature: {signature}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size == 0) return 0;
    char buf[size + 1];
    memcpy(buf, data, size);
    buf[size] = '\\0';
    // TODO: call {func_name} with buf
    {call_site}
    return 0;
}}
"""

JAVA_TEMPLATE = """\
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
// Auto-generated fuzz harness for: {func_name}
public class {class_name}Fuzzer {{
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {{
        String input = data.consumeRemainingAsString();
        try {{
            {call_site}
        }} catch (Exception e) {{
            // Expected exception
        }}
    }}
}}
"""

PYTHON_TEMPLATE = """\
import atheris
import sys

# Auto-generated fuzz harness for: {func_name}
@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    s = fdp.ConsumeUnicodeNoSurrogates(100)
    try:
        {call_site}
    except Exception:
        pass

if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
"""


class HarnessAgent:
    """Automatically generates and compiles fuzz harnesses for target functions."""

    MAX_RETRIES = 5
    RETRY_TIMEOUT = 60  # seconds per compile attempt

    TEMPLATES = {
        "c": C_CPP_TEMPLATE,
        "cpp": C_CPP_TEMPLATE,
        "java": JAVA_TEMPLATE,
        "python": PYTHON_TEMPLATE,
    }

    def __init__(self, llm_gateway=None):
        self.llm = llm_gateway
        self.workspace = os.path.join("storage", "workspaces", "harnesses")
        os.makedirs(self.workspace, exist_ok=True)

    async def generate(
        self,
        hypothesis_id: str,
        target_function: str,
        repo_path: str,
        language: str,
        description: str = ""
    ) -> Optional[str]:
        """
        Generate a fuzz harness for target_function using LLM.
        """
        logger.info(f"[HarnessAgent] Generating harness for '{target_function}' ({language})")

        # 1. Find the source code for the target function
        source_code = self._extract_source_code(target_function, repo_path, language)
        if not source_code:
            logger.warning(f"[HarnessAgent] Could not find source code for {target_function}")
            source_code = f"// Source code for {target_function} not found. Generate harness based on name."

        # 2. Call LLM to generate harness
        response = self.llm.generate_fuzz_harness(
            hypothesis_id=hypothesis_id,
            description=description,
            language=language,
            target_function=target_function,
            source_code=source_code
        )

        # Parse JSON response
        try:
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0].strip()
            elif "```" in response:
                response = response.split("```")[1].split("```")[0].strip()
            
            data = extract_json(response, default={})
            harness_code = data.get("harness_code", "")
        except Exception as e:
            logger.error(f"[HarnessAgent] Failed to parse LLM response: {e}")
            return None

        if not harness_code:
            logger.warning("[HarnessAgent] LLM returned empty harness code")
            return None

        # 3. Repair loop — compile and fix
        harness_path = os.path.join(self.workspace, f"harness_{uuid.uuid4().hex[:8]}.{self._ext(language)}")
        success = await self._repair_loop(hypothesis_id, harness_code, harness_path, language)

        if success:
            logger.info(f"[HarnessAgent] ✅ Harness ready: {harness_path}")
            return harness_path

        return None

    def _extract_source_code(self, func_name: str, repo_path: str, language: str) -> Optional[str]:
        """Search for the function definition and return its source code."""
        # This is a simplified version, ideally uses Tree-sitter or Joern
        ext_map = {"python": ".py", "java": ".java", "c": ".c", "cpp": ".cpp"}
        target_ext = ext_map.get(language.lower(), ".py")
        
        for root, _, files in os.walk(repo_path):
            for f in files:
                if f.endswith(target_ext):
                    path = os.path.join(root, f)
                    try:
                        with open(path, "r", encoding="utf-8", errors="ignore") as fp:
                            content = fp.read()
                            # Use regex to find the function block (very basic)
                            # In Upgrade 1, we should use the Semantic Graph here.
                            if func_name in content:
                                # For now, just return the whole file context if found
                                return f"// Found in {f}\n" + content
                    except:
                        continue
        return None


    async def _repair_loop(self, hypothesis_id: str, code: str, harness_path: str, language: str) -> bool:
        """
        Write → compile → if error → patch → retry (max 5 times).
        """
        current_code = code

        for attempt in range(1, self.MAX_RETRIES + 1):
            logger.info(f"[HarnessAgent] Compile attempt {attempt}/{self.MAX_RETRIES}")

            # Write harness to disk
            with open(harness_path, "w", encoding="utf-8") as f:
                f.write(current_code)

            success, error_msg = await self._compile_check(harness_path, language)
            if success:
                return True

            logger.warning(f"[HarnessAgent] Compile failed: {error_msg[:200]}")

            # Attempt a repair via LLM
            response = self.llm.repair_fuzz_harness(
                hypothesis_id=hypothesis_id,
                failed_harness=current_code,
                error_msg=error_msg,
                language=language,
                attempt_number=attempt
            )

            # Parse JSON
            try:
                if "```json" in response:
                    response = response.split("```json")[1].split("```")[0].strip()
                elif "```" in response:
                    response = response.split("```")[1].split("```")[0].strip()
                
                data = extract_json(response, default={})
                current_code = data.get("harness_code", current_code)
            except Exception as e:
                logger.error(f"[HarnessAgent] Failed to parse repair response: {e}")
                # Fallback: continue to next attempt or break
                pass

        return False

    async def _compile_check(self, harness_path: str, language: str) -> Tuple[bool, str]:
        """Try to compile the harness. Return (success, error_message)."""
        try:
            if language.lower() == "python":
                # For Python, we use py_compile to ensure it's syntactically valid
                proc = await asyncio.create_subprocess_exec(
                    "python", "-m", "py_compile", harness_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, err = await asyncio.wait_for(proc.communicate(), timeout=self.RETRY_TIMEOUT)
                return proc.returncode == 0, err.decode()

            elif language.lower() in ("c", "cpp"):
                # For C/C++, we use g++ with -fsyntax-only
                compiler = "g++" if language == "cpp" else "gcc"
                # Note: This might fail if headers are missing, but LLM should try to fix includes
                proc = await asyncio.create_subprocess_exec(
                    compiler, "-fsyntax-only", harness_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, err = await asyncio.wait_for(proc.communicate(), timeout=self.RETRY_TIMEOUT)
                return proc.returncode == 0, err.decode()

            elif language.lower() == "java":
                # For Java, we use javac
                proc = await asyncio.create_subprocess_exec(
                    "javac", harness_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, err = await asyncio.wait_for(proc.communicate(), timeout=self.RETRY_TIMEOUT)
                return proc.returncode == 0, err.decode()

        except asyncio.TimeoutError:
            return False, "Compile timeout exceeded"
        except Exception as e:
            return False, f"Execution error: {str(e)}"

        return True, ""

    # ─────────────────────────────────────────────────────────
    # Utility
    # ─────────────────────────────────────────────────────────
    def _to_class_name(self, func_name: str) -> str:
        return "".join(w.capitalize() for w in func_name.split("_"))

    def _ext(self, language: str) -> str:
        return {"python": "py", "java": "java", "c": "c", "cpp": "cpp"}.get(language, "txt")
