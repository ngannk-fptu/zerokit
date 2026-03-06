import requests
import argparse
import json
import sys

def fetch_trending_plugins(limit=10):
    """
    Fetches trending/new plugins from WordPress.org API.
    API: https://api.wordpress.org/plugins/info/1.2/
    """
    url = "https://api.wordpress.org/plugins/info/1.2/"
    params = {
        "action": "query_plugins",
        "request[browse]": "new", # 'new', 'popular', 'updated'
        "request[per_page]": limit,
        "request[fields][download_link]": True,
        "request[fields][active_installs]": True
    }
    
    print(f"Fetching {limit} trending plugins from WordPress.org...")
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        data = response.json()
        
        plugins = data.get("plugins", [])
        targets = []
        
        for p in plugins:
            targets.append({
                "name": p.get("name"),
                "slug": p.get("slug"),
                "version": p.get("version"),
                "installs": p.get("active_installs"),
                "url": p.get("download_link"),
                "type": "wordpress_plugin"
            })
            
        return targets
        
    except Exception as e:
        print(f"Error fetching WP plugins: {e}")
        return []

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=10, help="Number of plugins to fetch")
    parser.add_argument("--output", default="targets.json", help="Output file")
    
    args = parser.parse_args()
    
    targets = fetch_trending_plugins(args.limit)
    
    with open(args.output, "w") as f:
        json.dump(targets, f, indent=2)
        
    print(f"Saved {len(targets)} targets to {args.output}")
    for t in targets:
        print(f"- {t['name']} ({t['installs']} installs): {t['url']}")
