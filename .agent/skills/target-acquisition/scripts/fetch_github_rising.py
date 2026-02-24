import requests
import argparse
import json
import os
from datetime import datetime, timedelta

def fetch_github_rising(limit=10, token=None):
    """
    Fetches rising repos from GitHub.
    """
    url = "https://api.github.com/search/repositories"
    
    # Created in last 30 days
    date_str = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
    
    # Query: created recently, >50 stars, PHP/JS/Python
    query = f"created:>{date_str} stars:50..500 language:php language:javascript language:python"
    
    params = {
        "q": query,
        "sort": "stars",
        "order": "desc",
        "per_page": limit
    }
    
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
        
    print(f"Fetching rising repos created after {date_str}...")
    
    try:
        response = requests.get(url, params=params, headers=headers)
        if response.status_code == 403:
            print("Error: GitHub API Rate Limit Exceeded. Provide a token.")
            return []
            
        response.raise_for_status()
        data = response.json()
        
        repos = data.get("items", [])
        targets = []
        
        for r in repos:
            targets.append({
                "name": r.get("full_name"),
                "stars": r.get("stargazers_count"),
                "url": r.get("clone_url"),
                "description": r.get("description"),
                "type": "github_repo"
            })
            
        return targets
        
    except Exception as e:
        print(f"Error fetching GitHub repos: {e}")
        return []

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--output", default="targets.json")
    parser.add_argument("--token", help="GitHub Personal Access Token")
    
    args = parser.parse_args()
    
    # Try env var for token if not passed
    token = args.token or os.environ.get("GITHUB_TOKEN")
    
    targets = fetch_github_rising(args.limit, token)
    
    with open(args.output, "w") as f:
        json.dump(targets, f, indent=2)
        
    print(f"Saved {len(targets)} targets to {args.output}")
    for t in targets:
        print(f"- {t['name']} ({t['stars']} stars): {t['url']}")
