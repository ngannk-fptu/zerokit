import requests
import os
import zipfile
from pathlib import Path
import time
import json

class WordPressPluginDownloader:
    def __init__(self, min_installs=50000, output_dir="wordpress_plugins"):
        self.min_installs = min_installs
        self.output_dir = Path(output_dir)
        self.api_base = "https://api.wordpress.org/plugins/info/1.2/"
        self.download_base = "https://downloads.wordpress.org/plugin/"
        
        # Create output directory
        self.output_dir.mkdir(exist_ok=True)
        
    def get_plugins(self, page=1, per_page=100):
        """Fetch plugins from WordPress.org API"""
        params = {
            'action': 'query_plugins',
            'request[page]': page,
            'request[per_page]': per_page,
            'request[browse]': 'popular'  # Get popular plugins first
        }
        
        try:
            response = requests.get(self.api_base, params=params, timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"❌ Error fetching plugins page {page}: {e}")
            return None
    
    def get_plugin_details(self, slug):
        """Get detailed info for a specific plugin"""
        params = {
            'action': 'plugin_information',
            'request[slug]': slug
        }
        
        try:
            response = requests.get(self.api_base, params=params, timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"❌ Error fetching details for {slug}: {e}")
            return None
    
    def parse_installs(self, install_value):
        """Parse install count from string like '1+ million' or '50,000+' or integer"""
        if not install_value:
            return 0
        
        # If it's already an integer, return it directly
        if isinstance(install_value, int):
            return install_value
        
        install_string = str(install_value).lower().replace(',', '').replace('+', '')
        
        if 'million' in install_string:
            num = float(install_string.split()[0])
            return int(num * 1000000)
        elif 'k' in install_string:
            num = float(install_string.replace('k', ''))
            return int(num * 1000)
        else:
            try:
                return int(install_string)
            except:
                return 0
    
    def download_plugin(self, slug, version='latest'):
        """Download a plugin zip file"""
        if version == 'latest':
            download_url = f"{self.download_base}{slug}.zip"
        else:
            download_url = f"{self.download_base}{slug}.{version}.zip"
        
        output_path = self.output_dir / f"{slug}.zip"
        
        # Skip if already downloaded
        if output_path.exists():
            print(f"⏭️  Skipping {slug} (already downloaded)")
            return True
        
        try:
            print(f"⬇️  Downloading {slug}...", end=' ')
            response = requests.get(download_url, timeout=60, stream=True)
            response.raise_for_status()
            
            # Download with progress
            total_size = int(response.headers.get('content-length', 0))
            
            with open(output_path, 'wb') as f:
                if total_size == 0:
                    f.write(response.content)
                else:
                    downloaded = 0
                    for chunk in response.iter_content(chunk_size=8192):
                        downloaded += len(chunk)
                        f.write(chunk)
            
            file_size = output_path.stat().st_size / (1024 * 1024)  # MB
            print(f"✅ ({file_size:.1f} MB)")
            return True
            
        except Exception as e:
            print(f"❌ Failed: {e}")
            if output_path.exists():
                output_path.unlink()  # Remove partial download
            return False
    
    def collect_all_plugins(self):
        """Collect all plugins meeting the install threshold"""
        print(f"🔍 Searching for plugins with {self.min_installs:,}+ installs...\n")
        
        all_plugins = []
        page = 1
        
        while True:
            print(f"📄 Fetching page {page}...")
            data = self.get_plugins(page=page, per_page=100)
            
            if not data or 'plugins' not in data:
                break
            
            plugins = data['plugins']
            if not plugins:
                break
            
            for plugin in plugins:
                installs = self.parse_installs(plugin.get('active_installs', '0'))
                
                if installs >= self.min_installs:
                    all_plugins.append({
                        'slug': plugin['slug'],
                        'name': plugin['name'],
                        'installs': installs,
                        'version': plugin.get('version', 'latest')
                    })
                    print(f"  ✓ {plugin['name']} - {installs:,} installs")
            
            # Check if we should continue
            # If the last plugin on this page has fewer installs, we can stop
            if plugins:
                last_installs = self.parse_installs(plugins[-1].get('active_installs', '0'))
                if last_installs < self.min_installs:
                    print(f"\n⚠️  Reached plugins below threshold, stopping search")
                    break
            
            page += 1
            time.sleep(1)  # Be nice to the API
            
            # Safety limit
            if page > 100:
                print(f"\n⚠️  Reached page limit (100), stopping")
                break
        
        return all_plugins
    
    def run(self):
        """Main execution flow"""
        print("=" * 60)
        print("WordPress Plugin Bulk Downloader")
        print("=" * 60)
        print(f"Minimum installs: {self.min_installs:,}")
        print(f"Output directory: {self.output_dir.absolute()}\n")
        
        # Collect plugins
        plugins = self.collect_all_plugins()
        
        if not plugins:
            print("\n❌ No plugins found matching criteria")
            return
        
        # Sort by install count
        plugins.sort(key=lambda x: x['installs'], reverse=True)
        
        print(f"\n📊 Found {len(plugins)} plugins to download")
        print("=" * 60)
        
        # Save plugin list
        list_file = self.output_dir / "plugin_list.json"
        with open(list_file, 'w', encoding='utf-8') as f:
            json.dump(plugins, f, indent=2, ensure_ascii=False)
        print(f"💾 Plugin list saved to: {list_file}\n")
        
        # Download plugins
        successful = 0
        failed = 0
        
        for i, plugin in enumerate(plugins, 1):
            print(f"[{i}/{len(plugins)}] ", end='')
            if self.download_plugin(plugin['slug']):
                successful += 1
            else:
                failed += 1
            
            # Rate limiting
            time.sleep(0.5)
        
        # Summary
        print("\n" + "=" * 60)
        print("📊 Download Summary")
        print("=" * 60)
        print(f"✅ Successful: {successful}")
        print(f"❌ Failed: {failed}")
        print(f"📁 Location: {self.output_dir.absolute()}")
        print(f"💾 Total plugins: {len(plugins)}")

def main():
    # Configuration
    MIN_INSTALLS = 50000
    OUTPUT_DIR = "wordpress_plugins"
    
    downloader = WordPressPluginDownloader(
        min_installs=MIN_INSTALLS,
        output_dir=OUTPUT_DIR
    )
    
    try:
        downloader.run()
    except KeyboardInterrupt:
        print("\n\n⚠️  Download interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")

if __name__ == '__main__':
    main()