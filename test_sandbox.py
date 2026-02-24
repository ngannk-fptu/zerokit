"""
Quick test script for sandbox execution
"""
import asyncio
import sys
sys.path.insert(0, 'd:/WLD/SSI/research/1/trilm/ZeroKit2')

from _agent.pipeline.tools.sandbox_executor import SandboxExecutor

async def test_php_execution():
    print("Testing PHP sandbox execution...")
    
    executor = SandboxExecutor()
    
    # Simple PHP script
    php_code = """<?php
echo "Hello from Docker!\\n";
echo "PHP Version: " . phpversion() . "\\n";
$result = 5 + 3;
echo "Calculation result: $result\\n";
?>"""
    
    print("\n--- Executing PHP script ---")
    result = await executor.execute_php(php_code)
    
    print(f"\nExit Code: {result.exit_code}")
    print(f"Execution Time: {result.execution_time:.3f}s")
    print(f"Timed Out: {result.timed_out}")
    print(f"\n--- STDOUT ---\n{result.stdout}")
    if result.stderr:
        print(f"\n--- STDERR ---\n{result.stderr}")
    
    return result.exit_code == 0

if __name__ == "__main__":
    success = asyncio.run(test_php_execution())
    sys.exit(0 if success else 1)
