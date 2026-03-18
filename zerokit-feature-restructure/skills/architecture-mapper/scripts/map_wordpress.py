import re
import os
from pathlib import Path

def map_wordpress_hooks(directory):
    """
    Scans PHP files for WordPress hooks:
    - wp_ajax_(action)
    - wp_ajax_nopriv_(action)
    - register_rest_route
    """
    routes = []
    
    # Regex patterns
    # add_action('wp_ajax_my_action', 'function_name');
    img_ajax = re.compile(r"add_action\s*\(\s*['\"](wp_ajax_(nopriv_)?([a-zA-Z0-9_]+))['\"]\s*,\s*['\"]([a-zA-Z0-9_]+)['\"]\s*\)")
    
    # register_rest_route('my-namespace/v1', '/products', ...)
    img_rest = re.compile(r"register_rest_route\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]")

    for root, _, files in os.walk(directory):
        for file in files:
            if not file.endswith(".php"):
                continue
                
            filepath = os.path.join(root, file)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                # 1. AJAX Hooks
                for match in img_ajax.finditer(content):
                    action_full = match.group(1)
                    is_nopriv = "nopriv" in match.group(2) if match.group(2) else False
                    action_name = match.group(3)
                    handler = match.group(4)
                    
                    routes.append({
                        "type": "wp_hook",
                        "method": "POST", # AJAX is usually POST
                        "path": f"admin-ajax.php?action={action_name}",
                        "file": filepath,
                        "line": content[:match.start()].count('\n') + 1,
                        "auth_level": "public" if is_nopriv else "authenticated",
                        "handler": handler
                    })

                # 2. REST API
                for match in img_rest.finditer(content):
                    namespace = match.group(1)
                    route = match.group(2)
                    
                    routes.append({
                        "type": "wp_rest",
                        "method": "GET/POST",
                        "path": f"/wp-json/{namespace}{route}",
                        "file": filepath,
                        "line": content[:match.start()].count('\n') + 1,
                        "auth_level": "unknown", # Needs deep parsing of args
                        "handler": "closure_or_callback" 
                    })
                    
            except Exception as e:
                pass
                
    return routes
