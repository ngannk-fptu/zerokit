---
name: target-acquisition
description: Automated discovery of vulnerability targets (WP Plugins, GitHub Repos).
tools: Bash, Python
---

# Target Acquisition (The Scout)

This skill finds raw materials for the ZeroKit Factory.

## Scripts

### 1. `fetch_wp_trending.py`
Scrapes WordPress.org for plugins that are:
- Recently updated.
- Gaining installs.
- Not yet "too big to fail" (sweet spot for bugs).

### 2. `fetch_github_rising.py`
Uses GitHub API to find:
- New PHP/JS/Python repos.
- Rising stars (50-500).
- Relevant topics (cms, admin, dashboard).

## Usage

```bash
# Get 5 trending WP plugins
python .agent/skills/target-acquisition/scripts/fetch_wp_trending.py --limit 5

# Get 5 rising GitHub repos
python .agent/skills/target-acquisition/scripts/fetch_github_rising.py --limit 5 --token YOUR_TOKEN
```
