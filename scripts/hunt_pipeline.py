import sys
import os
import argparse

# Add .agent to path to allow imports
current_dir = os.path.dirname(os.path.abspath(__file__))
agent_dir = os.path.join(current_dir, '.agent')
sys.path.append(agent_dir)

try:
    from core.orchestrator import Orchestrator
except ImportError as e:
    print(f"Error importing Orchestrator: {e}")
    print(f"sys.path: {sys.path}")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Run ZeroKit2 Security Pipeline")
    parser.add_argument("target", help="Target directory to scan")
    parser.add_argument("--config", help="Path to config file", default=None)
    
    args = parser.parse_args()
    
    target_path = os.path.abspath(args.target)
    if not os.path.exists(target_path):
        print(f"Error: Target path '{target_path}' does not exist.")
        sys.exit(1)
        
    print(f"🚀 Starting Hunt Pipeline for: {target_path}")
    
    orch = Orchestrator()
    report = orch.run_full_pipeline(target_path)
    
    print("\n✅ Pipeline Complete!")
    print("\n--- REPORT SUMMARY ---\n")
    print(report)
    
    # Save report to file if not already handled by Orchestrator
    report_path = os.path.join(current_dir, "report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\n📄 Report saved to: {report_path}")

if __name__ == "__main__":
    main()
