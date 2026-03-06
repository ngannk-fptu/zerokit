#!/usr/bin/env python3
"""
ZeroKit2 - Interactive Hunt Menu
Allows running specific phases of the security pipeline or full automation.
"""

import sys
import os
import argparse
from typing import Optional

# Add .agent to path
current_dir = os.path.dirname(os.path.abspath(__file__))
agent_dir = os.path.join(current_dir, '.agent')
sys.path.append(agent_dir)

try:
    from pipeline.orchestrator import Orchestrator
    from pipeline.models import PipelineContext
except ImportError as e:
    print(f"Error importing modules: {e}")
    sys.exit(1)

# Color codes (ANSI)
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    @staticmethod
    def disable():
        Colors.HEADER = ''
        Colors.BLUE = ''
        Colors.CYAN = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.RED = ''
        Colors.ENDC = ''
        Colors.BOLD = ''
        Colors.UNDERLINE = ''


class InteractiveHuntMenu:
    PHASES = [
        ("Profiling & Attack Surface Mapping", "profiling"),
        ("Threat Modeling", "hypothesis"),
        ("Static Detection (Hybrid Scout)", "detection"),
        ("Dynamic Verification", "verification"),
        ("Variant Analysis Loop", "feedback"),
        ("Root Cause Analysis", "rca"),
        ("Autonomous Patching", "patching"),
        ("Reporting", "reporting"),
    ]
    
    def __init__(self, target_path: str, no_color: bool = False):
        self.target_path = os.path.abspath(target_path)
        self.context_path = os.path.join(self.target_path, ".zerokit_context.pkl")
        self.orchestrator = Orchestrator()
        
        if no_color or os.name == 'nt':  # Windows might not support ANSI
            Colors.disable()
        
        # Try to load existing context
        self.load_context_if_exists()
    
    def load_context_if_exists(self):
        """Load existing context if available."""
        if os.path.exists(self.context_path):
            try:
                self.orchestrator.load_context(self.context_path)
                return True
            except Exception as e:
                print(f"{Colors.YELLOW}Warning: Could not load context: {e}{Colors.ENDC}")
                return False
        return False
    
    def display_header(self):
        """Display menu header with current status."""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'═' * 70}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.CYAN}🔍 ZeroKit2 - Interactive Hunt Menu{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'═' * 70}{Colors.ENDC}")
        
        print(f"\n{Colors.BOLD}Target:{Colors.ENDC} {self.target_path}")
        
        # Show status
        if self.orchestrator.context:
            status = self.get_status_summary()
            print(f"{Colors.BOLD}Status:{Colors.ENDC} {status}")
        else:
            print(f"{Colors.BOLD}Status:{Colors.ENDC} {Colors.YELLOW}Not started{Colors.ENDC}")
        
        print()
    
    def get_status_summary(self) -> str:
        """Get human-readable status summary."""
        if not self.orchestrator.context:
            return f"{Colors.YELLOW}Not initialized{Colors.ENDC}"
        
        completed = self.orchestrator.get_completed_phases()
        total = len(self.PHASES)
        
        if len(completed) == 0:
            return f"{Colors.YELLOW}Ready to start{Colors.ENDC}"
        elif len(completed) == total:
            return f"{Colors.GREEN}All phases completed ✓{Colors.ENDC}"
        else:
            last_phase = completed[-1] if completed else "None"
            return f"{Colors.CYAN}Phase {len(completed)}/{total} completed - Last: {last_phase}{Colors.ENDC}"
    
    def display_phases(self):
        """Display phase menu with completion status."""
        print(f"{Colors.BOLD}Phases:{Colors.ENDC}\n")
        
        completed_phases = self.orchestrator.get_completed_phases() if self.orchestrator.context else []
        
        for i, (name, phase_key) in enumerate(self.PHASES, 1):
            status_icon = f"{Colors.GREEN}✓{Colors.ENDC}" if phase_key in completed_phases else " "
            print(f"  {i}. [{status_icon}] {name}")
        
        print(f"\n  {Colors.BOLD}{'─' * 66}{Colors.ENDC}")
        print(f"  9. {Colors.BOLD}Run Full Pipeline{Colors.ENDC} (All Phases)")
        
        if completed_phases:
            print(f"  R. {Colors.CYAN}Resume from last checkpoint{Colors.ENDC}")
        
        print(f"  W. {Colors.BOLD}CWE Encyclopedia Lookup{Colors.ENDC}")
        print(f"  S. Show current context summary")
        print(f"  C. Clear context and restart")
        print(f"  Q. Quit")
        
        print(f"{Colors.BOLD}{Colors.CYAN}{'═' * 70}{Colors.ENDC}\n")
    
    def show_context_summary(self):
        """Display detailed context information."""
        if not self.orchestrator.context:
            print(f"{Colors.YELLOW}No context available. Start a scan first.{Colors.ENDC}")
            return
        
        ctx = self.orchestrator.context
        
        print(f"\n{Colors.BOLD}Context Summary:{Colors.ENDC}")
        print(f"  Run ID: {ctx.run_id}")
        print(f"  Started: {ctx.start_time}")
        print(f"  Entry Points: {len(ctx.surface.entry_points) if ctx.surface else 0}")
        print(f"  Hypotheses: {len(ctx.hypotheses)}")
        print(f"  Static Findings: {len(ctx.static_findings)}")
        print(f"  Verified Vulns: {len(ctx.verified_vulns)}")
        
        if ctx.verified_vulns:
            confirmed = sum(1 for v in ctx.verified_vulns if v.status.value == "CONFIRMED")
            print(f"    → Confirmed: {Colors.RED}{confirmed}{Colors.ENDC}")
        
        print()
    
    def clear_context(self):
        """Clear existing context."""
        if os.path.exists(self.context_path):
            os.remove(self.context_path)
            print(f"{Colors.GREEN}Context cleared.{Colors.ENDC}")
        
        self.orchestrator.context = None
    
    def run_phase(self, phase_num: int):
        """Run a specific phase."""
        if phase_num < 1 or phase_num > len(self.PHASES):
            print(f"{Colors.RED}Invalid phase number.{Colors.ENDC}")
            return
        
        phase_name, phase_key = self.PHASES[phase_num - 1]
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'─' * 70}{Colors.ENDC}")
        print(f"{Colors.BOLD}Running Phase {phase_num}: {phase_name}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'─' * 70}{Colors.ENDC}\n")
        
        try:
            # Initialize context if needed
            if not self.orchestrator.context:
                self.orchestrator.start_pipeline(self.target_path)
            
            # Run the phase
            result = self.orchestrator.run_phase(phase_key)
            
            print(f"\n{Colors.GREEN}✓ Phase {phase_num} completed successfully!{Colors.ENDC}")
            
            # Show quick summary
            if phase_key == "profiling":
                print(f"  Found {len(self.orchestrator.context.surface.entry_points)} entry points")
            elif phase_key == "hypothesis":
                print(f"  Generated {len(self.orchestrator.context.hypotheses)} hypotheses")
            elif phase_key == "detection":
                print(f"  Found {len(self.orchestrator.context.static_findings)} static findings")
            elif phase_key == "verification":
                confirmed = sum(1 for v in self.orchestrator.context.verified_vulns if v.status.value == "CONFIRMED")
                print(f"  Confirmed {Colors.RED}{confirmed}{Colors.ENDC} vulnerabilities")
            elif phase_key == "reporting" and result:
                print(f"  Report generated")
            
        except Exception as e:
            print(f"\n{Colors.RED}✗ Phase {phase_num} failed: {e}{Colors.ENDC}")
            import traceback
            traceback.print_exc()
    
    def run_full_pipeline(self):
        """Run the complete pipeline."""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'═' * 70}{Colors.ENDC}")
        print(f"{Colors.BOLD}Running Full Pipeline (All 9 Phases){Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'═' * 70}{Colors.ENDC}\n")
        
        try:
            report = self.orchestrator.run_full_pipeline(self.target_path)
            
            print(f"\n{Colors.GREEN}{Colors.BOLD}✓ Pipeline completed successfully!{Colors.ENDC}\n")
            
            # Show report summary
            if self.orchestrator.context.verified_vulns:
                confirmed = sum(1 for v in self.orchestrator.context.verified_vulns if v.status.value == "CONFIRMED")
                print(f"{Colors.BOLD}Final Results:{Colors.ENDC}")
                print(f"  Total Findings: {len(self.orchestrator.context.static_findings)}")
                print(f"  Verified Vulns: {len(self.orchestrator.context.verified_vulns)}")
                print(f"  Confirmed: {Colors.RED}{confirmed}{Colors.ENDC}")
            
            # Save report
            report_path = os.path.join(current_dir, "report.md")
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(report)
            
            print(f"\n📄 Report saved to: {Colors.CYAN}{report_path}{Colors.ENDC}")
            
        except Exception as e:
            print(f"\n{Colors.RED}✗ Pipeline failed: {e}{Colors.ENDC}")
            import traceback
            traceback.print_exc()
    
    def resume_from_checkpoint(self):
        """Resume execution from last completed phase."""
        if not self.orchestrator.context:
            print(f"{Colors.YELLOW}No checkpoint found. Start a new scan.{Colors.ENDC}")
            return
        
        completed = self.orchestrator.get_completed_phases()
        next_phase = len(completed) + 1
        
        if next_phase > len(self.PHASES):
            print(f"{Colors.GREEN}All phases already completed!{Colors.ENDC}")
            return
        
        print(f"{Colors.CYAN}Resuming from Phase {next_phase}...{Colors.ENDC}")
        self.run_phase(next_phase)
    
    def run(self):
        """Main menu loop."""
        while True:
            self.display_header()
            self.display_phases()
            
            try:
                choice = input(f"{Colors.BOLD}Choose an option: {Colors.ENDC}").strip().upper()
            except (KeyboardInterrupt, EOFError):
                print(f"\n{Colors.YELLOW}Exiting...{Colors.ENDC}")
                break
            
            if not choice:
                continue
            
            if choice == 'Q':
                print(f"\n{Colors.CYAN}Goodbye!{Colors.ENDC}\n")
                break
            
            elif choice == 'S':
                self.show_context_summary()
                input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")
            
            elif choice == 'C':
                confirm = input(f"{Colors.YELLOW}Clear all progress? (yes/no): {Colors.ENDC}").strip().lower()
                if confirm == 'yes':
                    self.clear_context()
                    input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")
            
            elif choice == 'R':
                self.resume_from_checkpoint()
                input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")
            
            elif choice == 'W':
                self.cwe_lookup_menu()
                input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")
            
            elif choice == '9':
                self.run_full_pipeline()
                input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")
            
            elif choice.isdigit():
                phase_num = int(choice)
                if 1 <= phase_num <= len(self.PHASES):
                    self.run_phase(phase_num)
                    input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.ENDC}")
                else:
                    print(f"{Colors.RED}Invalid option.{Colors.ENDC}")
            
            else:
                print(f"{Colors.RED}Invalid option.{Colors.ENDC}")

    def cwe_lookup_menu(self):
        """Interactive CWE lookup and search utility."""
        from pipeline.tools.cwe_manager import CweManager
        mgr = CweManager()
        
        while True:
            print(f"\n{Colors.BOLD}{Colors.CYAN}{'─' * 70}{Colors.ENDC}")
            print(f"{Colors.BOLD}📖 CWE Encyclopedia Lookup{Colors.ENDC}")
            print(f"{Colors.BOLD}{Colors.CYAN}{'─' * 70}{Colors.ENDC}\n")
            
            query = input(f"{Colors.BOLD}Enter CWE ID (e.g., 89) or Keyword (e.g., SQLi) [Q to back]: {Colors.ENDC}").strip()
            
            if not query or query.upper() == 'Q':
                break
                
            if query.isdigit() or (query.upper().startswith("CWE-") and query[4:].isdigit()):
                # ID Lookup
                cwe_id = query.upper().replace("CWE-", "")
                result = mgr.get_cwe(cwe_id)
                if result:
                    self._display_cwe_details(result)
                else:
                    print(f"{Colors.RED}No CWE found with ID {cwe_id}.{Colors.ENDC}")
            else:
                # Search
                results = mgr.search_cwe(query)
                if results:
                    print(f"\n{Colors.GREEN}Found {len(results)} matches:{Colors.ENDC}")
                    for i, res in enumerate(results[:10], 1):
                        attr = res.get("attr", {})
                        print(f"  {i}. CWE-{attr.get('@_ID')}: {attr.get('@_Name')}")
                    
                    if len(results) > 10:
                        print(f"  ... and {len(results) - 10} more.")
                        
                    sel = input(f"\n{Colors.BOLD}Enter number to view details or press Enter to skip: {Colors.ENDC}").strip()
                    if sel.isdigit() and 1 <= int(sel) <= min(len(results), 10):
                        self._display_cwe_details(results[int(sel)-1])
                else:
                    print(f"{Colors.RED}No CWE matches found for '{query}'.{Colors.ENDC}")

    def _display_cwe_details(self, cwe_data: dict):
        """Format and print CWE details."""
        attr = cwe_data.get("attr", {})
        cwe_id = attr.get("@_ID")
        print(f"\n{Colors.BOLD}{Colors.GREEN}CWE-{cwe_id}: {attr.get('@_Name')}{Colors.ENDC}")
        print(f"{Colors.YELLOW}{'─' * 50}{Colors.ENDC}")
        print(f"{Colors.BOLD}Description:{Colors.ENDC}")
        print(f"  {cwe_data.get('Description', 'No description available.')}")
        
        from pipeline.tools.cwe_manager import CweManager
        mgr = CweManager()
        memberships = mgr.get_memberships(cwe_id)
        if memberships:
            print(f"\n{Colors.BOLD}Memberships:{Colors.ENDC}")
            for m in memberships:
                print(f"  • {m.get('membershipName')}: {m.get('memberId')}")
        
        print(f"\n{Colors.BLUE}Mitigation Strategy Excerpt:{Colors.ENDC}")
        strategies = cwe_data.get("Mitigation_Strategies", {}).get("Strategy", [])
        if isinstance(strategies, dict): strategies = [strategies]
        
        if strategies:
            for s in strategies[:2]: # Show first 2 strategies
                desc = s.get("Description", "")
                if isinstance(desc, dict): desc = desc.get("#text", "")
                print(f"  • {desc[:200]}...")
        else:
            print("  No explicit strategies listed in dictionary.")
            
        print(f"\n{Colors.CYAN}Link:{Colors.ENDC} https://cwe.mitre.org/data/definitions/{cwe_id}.html")



def main():
    parser = argparse.ArgumentParser(
        description="ZeroKit2 Interactive Hunt Menu - Run security analysis phases interactively"
    )
    parser.add_argument("target", nargs='?', help="Target directory to scan")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    
    args = parser.parse_args()
    
    # Ask for target if not provided
    if not args.target:
        print(f"{Colors.BOLD}ZeroKit2 Interactive Hunt{Colors.ENDC}")
        args.target = input(f"{Colors.BOLD}Enter target directory: {Colors.ENDC}").strip()
    
    if not args.target or not os.path.exists(args.target):
        print(f"{Colors.RED}Error: Target path does not exist: {args.target}{Colors.ENDC}")
        sys.exit(1)
    
    menu = InteractiveHuntMenu(args.target, no_color=args.no_color)
    menu.run()


if __name__ == "__main__":
    main()
