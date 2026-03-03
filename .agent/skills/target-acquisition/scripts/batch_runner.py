import argparse
import json
import os
import subprocess
import shutil


def run_semgrep_scan(target_dir, output_file):
    """Run Semgrep directly and normalize findings to a plain list."""
    semgrep_cmd = [
        "semgrep",
        "--config",
        "auto",
        target_dir,
        "--json",
        "--output",
        output_file,
    ]
    result = subprocess.run(semgrep_cmd, check=False, capture_output=True, text=True)

    if result.returncode not in (0, 1):
        # Keep batch flow resilient if Semgrep is missing or fails hard.
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump([], f)
        return

    try:
        with open(output_file, "r", encoding="utf-8") as f:
            parsed = json.load(f)
    except Exception:
        parsed = {}

    if isinstance(parsed, dict) and "results" in parsed:
        findings = parsed.get("results", [])
    elif isinstance(parsed, list):
        findings = parsed
    else:
        findings = []

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)


def run_batch_hunt(targets_file, output_dir):
    """
    Reads a targets.json and runs batch hunt primitives on each target.
    """
    if not os.path.exists(targets_file):
        print(f"Targets file not found: {targets_file}")
        return

    with open(targets_file, "r", encoding="utf-8") as f:
        targets = json.load(f)

    print(f"🚀 Starting Batch Hunt on {len(targets)} targets...\n")

    reports = []

    for i, target in enumerate(targets):
        name = target.get("name")
        url = target.get("url")
        print(f"[{i + 1}/{len(targets)}] Processing: {name}")

        # 1. Clone to temp dir
        temp_dir = os.path.abspath(f"temp_hunt_{i}")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        os.makedirs(temp_dir)

        try:
            print(f"   Cloning {url}...")
            if target.get("type") == "wordpress_plugin":
                # Download and unzip plugin archive.
                zip_url = target.get("url")
                print(f"   Downloading {zip_url}...")
                import io
                import zipfile

                import requests

                r = requests.get(zip_url)
                r.raise_for_status()
                with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                    z.extractall(temp_dir)
                print("   Extracted.")
            else:
                subprocess.run(["git", "clone", url, temp_dir], check=True, capture_output=True)

            # 2. Run mapping + static scan primitives.
            print("   Running Surface Mapper...")
            subprocess.run(
                [
                    "python",
                    ".agent/skills/architecture-mapper/scripts/map_routes.py",
                    "--target",
                    temp_dir,
                    "--output",
                    f"{temp_dir}/entrypoints.json",
                ],
                check=True,
                capture_output=True,
            )

            print("   Running Semgrep...")
            findings_file = f"{temp_dir}/findings.json"
            run_semgrep_scan(temp_dir, findings_file)

            # 3. Check for findings
            count = 0
            if os.path.exists(findings_file):
                with open(findings_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    count = len(data)

            print(f"   Found {count} issues.")

            reports.append(
                {
                    "target": name,
                    "url": url,
                    "issues": count,
                    "report_path": findings_file,
                }
            )

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
