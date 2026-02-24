import os
import json
import logging
from typing import List, Dict, Optional, Any

logger = logging.getLogger(__name__)

class CweManager:
    """
    Python implementation of CWE Tool / cwe-sdk core logic.
    Provides lookup, search, and relationship mapping for CWEs.
    """
    
    def __init__(self, data_dir: Optional[str] = None):
        if not data_dir:
            # Default to .agent/pipeline/data in workspace root
            self.data_dir = os.path.join(os.getcwd(), ".agent", "pipeline", "data")
        else:
            self.data_dir = data_dir
            
        self.dictionary_path = os.path.join(self.data_dir, "cwe-dictionary.json")
        self.hierarchy_path = os.path.join(self.data_dir, "cwe-hierarchy.json")
        self.memberships_path = os.path.join(self.data_dir, "cwe-memberships.json")
        
        self.dictionary: Dict[str, Any] = {}
        self.hierarchy: List[Dict[str, str]] = []
        self.memberships: List[Dict[str, Any]] = []
        
        self._loaded = False

    def load_data(self):
        """Load JSON data files into memory."""
        if self._loaded:
            return
            
        try:
            if os.path.exists(self.dictionary_path):
                with open(self.dictionary_path, 'r', encoding='utf-8') as f:
                    self.dictionary = json.load(f)
            
            if os.path.exists(self.hierarchy_path):
                with open(self.hierarchy_path, 'r', encoding='utf-8') as f:
                    self.hierarchy = json.load(f)
                    
            if os.path.exists(self.memberships_path):
                with open(self.memberships_path, 'r', encoding='utf-8') as f:
                    self.memberships = json.load(f)
            
            self._loaded = True
            logger.info(f"CweManager: Loaded dictionary ({len(self.dictionary)} items), hierarchy, and memberships.")
        except Exception as e:
            logger.error(f"CweManager: Failed to load data: {e}")

    def get_cwe(self, cwe_id: str) -> Optional[Dict[str, Any]]:
        """Get details for a specific CWE ID."""
        self.load_data()
        return self.dictionary.get(str(cwe_id))

    def search_cwe(self, query: str) -> List[Dict[str, Any]]:
        """Search CWEs by name or description."""
        self.load_data()
        results = []
        query = query.lower()
        
        for cwe_id, data in self.dictionary.items():
            name = data.get("attr", {}).get("@_Name", "").lower()
            description = data.get("Description", "").lower()
            
            if query in name or query in description:
                results.append(data)
                
        return results

    def get_memberships(self, cwe_id: str) -> Optional[List[Dict[str, Any]]]:
        """Get memberships (e.g., OWASP Top 10) for a CWE ID."""
        self.load_data()
        for item in self.memberships:
            if item.get("weaknessId") == str(cwe_id):
                return item.get("memberships")
        return None

    def is_child_of(self, cwe_id: str, parent_id: str, indirect: bool = False) -> bool:
        """Check if a CWE is a child of another CWE."""
        self.load_data()
        
        if indirect:
            return self._is_child_of_indirect(str(cwe_id), str(parent_id))
            
        for item in self.hierarchy:
            if item.get("weaknessId") == str(cwe_id) and item.get("parentId") == str(parent_id):
                return True
                
        return False

    def _is_child_of_indirect(self, cwe_id: str, parent_id: str, visited: Optional[set] = None) -> bool:
        """Recursive indirect child-of check."""
        if visited is None:
            visited = set()
            
        if cwe_id in visited:
            return False
        visited.add(cwe_id)
        
        for item in self.hierarchy:
            if item.get("weaknessId") == cwe_id:
                curr_parent = item.get("parentId")
                if curr_parent == parent_id:
                    return True
                if self._is_child_of_indirect(curr_parent, parent_id, visited):
                    return True
                    
        return False

# Quick CLI test
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mgr = CweManager()
    
    # Test lookup
    cwe89 = mgr.get_cwe("89")
    if cwe89:
        print(f"CWE-89: {cwe89.get('attr', {}).get('@_Name')}")
    else:
        print("CWE-89 not found")
        
    # Test relationship
    is_child = mgr.is_child_of("89", "707", indirect=True)
    print(f"Is CWE-89 a child of CWE-707 (Improper Neutralization)? {is_child}")
    
    # Test search
    results = mgr.search_cwe("SQL Injection")
    print(f"Search 'SQL Injection' found {len(results)} results.")
