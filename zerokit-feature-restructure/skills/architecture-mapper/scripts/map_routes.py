import os
import re
import json
import argparse
from pathlib import Path

# Import WP Mapper (Assuming same directory)
try:
    from map_wordpress import map_wordpress_hooks
except ImportError:
    # Fallback if running from different cwd
    import sys
    sys.path.append(os.path.dirname(__file__))
    try:
        from map_wordpress import map_wordpress_hooks
    except ImportError:
        map_wordpress_hooks = lambda x: [] # No-op if missing

# ROUTE PATTERNS (Entry Points)
ROUTE_PATTERNS = {
    "node": [
        r"(app|router)\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]", 
        r"route\(['\"]([^'\"]+)['\"]",
    ],
    "python": [
        r"@app\.route\(\s*['\"]([^'\"]+)['\"]",
        r"path\(\s*['\"]([^'\"]+)['\"]",
    ],
    "java": [
        r"@(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)\(\s*value\s*=\s*['\"]([^'\"]+)['\"]",
    ],
    "php": [
        r"Route::(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]",
    ],
    "go": [
        r"\.(GET|POST|PUT|DELETE|PATCH)\(\s*['\"]([^'\"]+)['\"]",
    ]
}

# SINK PATTERNS (Dangerous Functions)
SINK_PATTERNS = {
    "exec": [r"exec\(", r"spawn\(", r"system\(", r"subprocess\.call", r"Runtime\.getRuntime"],
    "eval": [r"eval\(", r"literal_eval", r"ScriptEngine"],
    "sql": [r"execute\(", r"query\(", r"raw\(", r"text\("],
    "serialize": [r"unserialize", r"pickle\.loads", r"readObject"],
    "file": [r"fs\.readFile", r"open\(", r"Files\.read", r"file_get_contents"]
}

def scan_standard_routes(root_dir):
    routes = []
    sinks = []
    
    for root, dirs, files in os.walk(root_dir):
        # Exclude noise
        for ignore in ['node_modules', 'venv', '.git', 'dist', 'build']:
            if ignore in dirs: dirs.remove(ignore)
        
        for file in files:
            if not file.endswith(('.js', '.ts', '.py', '.java', '.php', '.go')):
                continue
                
            path = Path(root) / file
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.readlines()
                    
                for i, line in enumerate(content):
                    # Check Routes
                    for lang, patterns in ROUTE_PATTERNS.items():
                        for pattern in patterns:
                            match = re.search(pattern, line)
                            if match:
                                groups = match.groups()
                                method = groups[0].upper() if len(groups) > 1 else "ANY"
                                route_path = groups[-1]
                                routes.append({
                                    "type": "route",
                                    "method": method,
                                    "path": route_path,
                                    "file": str(path),
                                    "line": i + 1
                                })

                    # Check Sinks
                    for category, patterns in SINK_PATTERNS.items():
                        for pattern in patterns:
                            if re.search(pattern, line):
                                sinks.append({
                                    "type": "sink",
                                    "category": category,
                                    "snippet": line.strip()[:50],
                                    "file": str(path),
                                    "line": i + 1
                                })
            except Exception:
                pass 
                
    return routes, sinks

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Map Routes and Sinks")
    parser.add_argument("--target", default=".", help="Target directory")
    parser.add_argument("--output", default="architecture.json", help="Output file")
    
    args = parser.parse_args()
    
    print(f"Scanning {args.target}...")

    # 1. Standard Codebase Scan
    all_routes, all_sinks = scan_standard_routes(args.target)
            
    # 2. WordPress Specific Scan
    print("Checking for WordPress hooks...")
    try:
        wp_routes = map_wordpress_hooks(args.target)
        if wp_routes:
            print(f"Found {len(wp_routes)} WordPress entrypoints.")
            all_routes.extend(wp_routes)
    except Exception as e:
        print(f"WP Scan failed: {e}")

    data = {"routes": all_routes, "sinks": all_sinks}
    
    with open(args.output, "w") as f:
        json.dump(data, f, indent=2)
        
    print(f"Found {len(data['routes'])} routes and {len(data['sinks'])} sinks.")
    print(f"Saved to {args.output}")
