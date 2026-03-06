import argparse
import json
import os
import subprocess
import shutil
import time

def run_batch_hunt(targets_file, output_dir):
    """
    Reads a targets.json and runs /hunt-pipeline on each.
    """
    if not os.path.exists(targets_file):
        print(f"Targets file not found: {targets_file}")
        return
        
    with open(targets_file, 'r') as f:
        targets = json.load(f)
        
    print(f"🚀 Starting Batch Hunt on {len(targets)} targets...\n")
    
    reports = []
    
    for i, target in enumerate(targets):
        name = target.get('name')
        url = target.get('url')
        print(f"[{i+1}/{len(targets)}] Processing: {name}")
        
        # 1. Clone to temp dir
        temp_dir = os.path.abspath(f"temp_hunt_{i}")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        os.makedirs(temp_dir)
        
        try:
            print(f"   Cloning {url}...")
            if target.get('type') == 'wordpress_plugin':
                # Download and Unzip
                zip_url = target.get('url')
                print(f"   Downloading {zip_url}...")
                import requests
                import zipfile
                import io
                
                r = requests.get(zip_url)
                r.raise_for_status()
                with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                    z.extractall(temp_dir)
                print("   Extracted.")
            else:
                subprocess.run(["git", "clone", url, temp_dir], check=True, capture_output=True)
                
            # 2. Run Hunt Pipeline
            # We call the python scripts directly since /hunt-pipeline is a shell alias concept
            # OR we execute the commands.
            
            print("   Running Surface Mapper...")
            subprocess.run(["python", ".agent/skills/architecture-mapper/scripts/map_routes.py", "--target", temp_dir, "--output", f"{temp_dir}/entrypoints.json"], check=True, capture_output=True)
            
            print("   Running Rule Runner...")
            subprocess.run(["python", ".agent/skills/rule-runner/scripts/run_semgrep.py", "--target", temp_dir, "--output", f"{temp_dir}/findings.json"], check=False, capture_output=True) # Don't crash on fail
            
            # 3. Check for Findings
            findings_file = f"{temp_dir}/findings.json"
            count = 0
            if os.path.exists(findings_file):
                with open(findings_file, 'r') as f:
                    data = json.load(f)
                    count = len(data)
            
            print(f"   Found {count} issues.")
            
            reports.append({
                "target": name,
                "url": url,
                "issues": count,
                "report_path": findings_file
            })
            
        except Exception as e:
            print(f"   Error: {e}")
        
        # Cleanup (Optional: Keep if findings > 0)
        # shutil.rmtree(temp_dir)
        
    # Summary
    print("\n Hunt Complete.")
    for r in reports:
        print(f"- {r['target']}: {r['issues']} issues")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--targets", default="targets.json")
    parser.add_argument("--workspace", default=".")
    
    args = parser.parse_args()
    
    run_batch_hunt(args.targets, args.workspace)
