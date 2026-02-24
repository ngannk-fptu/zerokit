
import requests
import os
import zipfile
import shutil
import subprocess
import json
from pathlib import Path
from datetime import datetime, timedelta

# Configuration
MIN_INSTALLS = 1000
MAX_INSTALLS = 2000
MAX_PLUGINS = 20
UPDATE_THRESHOLD_DAYS = 90
BASE_DIR = Path("d:/WLD/SSI/research/1/trilm/ZeroKit2")
OUTPUT_DIR = BASE_DIR / "vul"
PIPELINE_SCRIPT = BASE_DIR / "hunt_pipeline.py"
REPORT_SOURCE = BASE_DIR / "report.md"

class MassHunter:
    def __init__(self):
        self.api_base = "https://api.wordpress.org/plugins/info/1.2/"
        self.download_base = "https://downloads.wordpress.org/plugin/"
        self.found_plugins = []
        
        # Ensure output directory exists
        OUTPUT_DIR.mkdir(exist_ok=True)

    def parse_installs(self, install_value):
        """Parse install count including '1,000+' etc"""
        if isinstance(install_value, int):
            return install_value
        string_val = str(install_value).replace(',', '').replace('+', '').lower()
        if 'million' in string_val:
            return int(float(string_val.split()[0]) * 1000000)
        if 'k' in string_val:
            return int(float(string_val.replace('k', '')) * 1000)
        try:
            return int(string_val)
        except:
            return 0

    def is_recently_updated(self, last_updated_str):
        """Check if updated within threshold"""
        try:
            # Format usually: 2023-10-25 12:34am GMT
            # But the API often returns ISO-like '2023-10-25'
            # Let's try parsing generic date
            last_date = datetime.strptime(str(last_updated_str).split()[0], "%Y-%m-%d")
            threshold_date = datetime.now() - timedelta(days=UPDATE_THRESHOLD_DAYS)
            return last_date >= threshold_date
        except Exception as e:
            # print(f"Date parse error: {e}")
            return False

    def search_plugins(self):
        """Search for valid plugins via WP API"""
        print(f"🔍 Searching for plugins (1k-2k installs, updated < {UPDATE_THRESHOLD_DAYS} days)...")
        page = 1
        
        while len(self.found_plugins) < MAX_PLUGINS:
            try:
                params = {
                    'action': 'query_plugins',
                    'request[page]': page,
                    'request[per_page]': 100,
                    'request[browse]': 'popular' 
                }
                resp = requests.get(self.api_base, params=params, timeout=30)
                data = resp.json()
                
                if 'plugins' not in data or not data['plugins']:
                    break
                
                for p in data['plugins']:
                    installs = self.parse_installs(p.get('active_installs', 0))
                    slug = p['slug']
                    last_updated = p.get('last_updated', '')
                    
                    # Filtering Logic
                    # Note: WP API 'popular' sort puts highest installs first. 
                    # We might need to page deep to find 1k-2k.
                    # Alternatively, we can assume mixed results or use 'browse': 'new'? 
                    # 'popular' is best for install counts.
                    
                    if installs < MIN_INSTALLS:
                        # Since it's sorted by popularity (desc), if we hit < 1000, we are done looking
                        # But wait, WP API popularity sort isn't strict install count. 
                        # Let's just continue.
                        continue
                        
                    if installs > MAX_INSTALLS:
                        continue

                    if self.is_recently_updated(last_updated):
                        self.found_plugins.append({
                            'slug': slug,
                            'name': p['name'],
                            'version': p['version'],
                            'installs': installs,
                            'last_updated': last_updated,
                            'download_link': p.get('download_link', f"{self.download_base}{slug}.zip")
                        })
                        print(f"  ✅ Found: {slug} ({installs} installs, updated {last_updated.split()[0]})")
                        
                        if len(self.found_plugins) >= MAX_PLUGINS:
                            break
                
                page += 1
                if page > 500: # Safety break
                    print("⚠️ Scanned 500 pages, stopping search.")
                    break
                    
            except Exception as e:
                print(f"❌ Error searching page {page}: {e}")
                break

        print(f"🎉 Found {len(self.found_plugins)} plugins.")

    def run_hunt(self):
        for idx, plugin in enumerate(self.found_plugins, 1):
            slug = plugin['slug']
            print(f"\n[{idx}/{len(self.found_plugins)}] 🏹 Hunting {slug}...")
            
            zip_path = OUTPUT_DIR / f"{slug}.zip"
            extract_path = OUTPUT_DIR / slug
            
            # 1. Download
            if not zip_path.exists():
                print(f"  ⬇️ Downloading...")
                try:
                    r = requests.get(plugin['download_link'], stream=True)
                    with open(zip_path, 'wb') as f:
                        for chunk in r.iter_content(chunk_size=8192):
                            f.write(chunk)
                except Exception as e:
                    print(f"  ❌ Download failed: {e}")
                    continue
            
            # 2. Extract
            if extract_path.exists():
                shutil.rmtree(extract_path)
            
            print(f"  📦 Extracting...")
            try:
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(OUTPUT_DIR)
            except Exception as e:
                print(f"  ❌ Extraction failed: {e}")
                continue

            # 3. Run Pipeline
            print(f"  🕵️ Running Hunt Pipeline...")
            try:
                subprocess.run(
                    ["python", str(PIPELINE_SCRIPT), str(extract_path)], 
                    check=True,
                    cwd=str(BASE_DIR)
                )
            except subprocess.CalledProcessError as e:
                print(f"  ❌ Pipeline failed: {e}")
            
            # 4. Save Report
            report_dest = OUTPUT_DIR / f"{slug}_report.md"
            if REPORT_SOURCE.exists():
                shutil.move(str(REPORT_SOURCE), str(report_dest))
                print(f"  📄 Report saved: {report_dest.name}")
            else:
                print(f"  ⚠️ No report found for {slug}")

            # 5. Cleanup
            print(f"  🧹 Cleaning up project folder...")
            if extract_path.exists():
                shutil.rmtree(extract_path)

if __name__ == "__main__":
    hunter = MassHunter()
    hunter.search_plugins()
    if hunter.found_plugins:
        hunter.run_hunt()
