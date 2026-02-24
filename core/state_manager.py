import sqlite3
import hashlib
import os
import logging
import json
from datetime import datetime
from typing import List, Optional, Dict
from .models import StaticFinding, VerifiedVuln, FindingSeverity

logger = logging.getLogger(__name__)

class StateManager:
    def __init__(self, db_path: str = "storage/pipeline.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Table: File States (for differential scan)
        c.execute('''CREATE TABLE IF NOT EXISTS file_states (
            path TEXT PRIMARY KEY,
            hash TEXT,
            last_scan_time TEXT
        )''')
        
        # Table: Findings (for persistence)
        c.execute('''CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            file_path TEXT,
            line INTEGER,
            tool TEXT,
            severity TEXT,
            hash TEXT,
            status TEXT,
            verification_result TEXT
        )''')
        
        # Table: Rule Performance Stats
        c.execute('''CREATE TABLE IF NOT EXISTS rule_stats (
            rule_hash TEXT PRIMARY KEY,
            content TEXT,
            success_count INTEGER,
            failure_count INTEGER,
            last_error TEXT,
            last_updated TIMESTAMP
        )''')
            
        conn.commit()
        conn.close()

    # ... [existing methods] ...

    def record_rule_execution(self, content: str, success: bool, error_msg: str = None):
        """
        Record the execution result of a Semgrep rule.
        """
        rule_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Check if exists
        c.execute("SELECT success_count, failure_count FROM rule_stats WHERE rule_hash=?", (rule_hash,))
        row = c.fetchone()
        
        if row:
            s_count, f_count = row
        else:
            s_count, f_count = 0, 0
            
        if success:
            s_count += 1
        else:
            f_count += 1
            
        c.execute('''INSERT OR REPLACE INTO rule_stats 
            (rule_hash, content, success_count, failure_count, last_error, last_updated) 
            VALUES (?, ?, ?, ?, ?, ?)''',
            (rule_hash, content, s_count, f_count, error_msg, datetime.now()))
            
        conn.commit()
        conn.close()

    def is_rule_blacklisted(self, content: str, threshold: float = 0.8, min_runs: int = 3) -> bool:
        """
        Check if a rule is blacklisted based on failure ratio.
        Returns True if failure_rate > threshold and total_runs >= min_runs.
        """
        rule_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT success_count, failure_count FROM rule_stats WHERE rule_hash=?", (rule_hash,))
        row = c.fetchone()
        conn.close()
        
        if not row:
            return False
            
        s_count, f_count = row
        total = s_count + f_count
        
        if total < min_runs:
            return False
            
        failure_rate = f_count / total
        return failure_rate > threshold

    def get_rule_error(self, content: str) -> Optional[str]:
        """Get the last error message for a rule."""
        rule_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT last_error FROM rule_stats WHERE rule_hash=?", (rule_hash,))
        row = c.fetchone()
        conn.close()
        return row[0] if row else None
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return ""

    def should_scan_file(self, file_path: str) -> bool:
        """
        Check if file has changed since last scan.
        """
        current_hash = self._calculate_file_hash(file_path)
        if not current_hash: return True # Error, safely scan
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT hash FROM file_states WHERE path=?", (file_path,))
        row = c.fetchone()
        conn.close()
        
        if row and row[0] == current_hash:
            return False # Unchanged
        return True # Changed or New

    def update_file_state(self, file_path: str):
        """
        Update file hash after successful scan.
        """
        current_hash = self._calculate_file_hash(file_path)
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO file_states (path, hash, last_scan_time) VALUES (?, ?, ?)",
                  (file_path, current_hash, datetime.now().isoformat()))
        conn.commit()
        conn.close()

    def get_cached_findings(self, file_path: str) -> List[StaticFinding]:
        """
        Retrieve findings for an unchanged file.
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT * FROM findings WHERE file_path=?", (file_path,))
        rows = c.fetchall()
        conn.close()
        
        findings = []
        for row in rows:
            # Check status - Skip if REJECTED (False Positive)
            status = row[6]
            if status == "REJECTED":
                continue
                
            # Reconstruct StaticFinding
            f = StaticFinding(
                id=row[0],
                location=f"{row[1]}:{row[2]}",
                severity=row[4],
                tool_name=row[3],
                description="Cached Finding",
                evidence="Loaded from persistence"
            )
            findings.append(f)
        return findings

    def update_finding_status(self, finding_id: str, status: str, verification_result: str = ""):
        """
        Update the status of a finding (e.g., to REJECTED or CONFIRMED).
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("UPDATE findings SET status=?, verification_result=? WHERE id=?", 
                  (status, verification_result, finding_id))
        conn.commit()
        conn.close()

    def filter_rejected_findings(self, findings: List[StaticFinding]) -> List[StaticFinding]:
        """
        Filter out findings that have been previously REJECTED.
        """
        if not findings: return []
        
        ids = [f.id for f in findings]
        if not ids: return findings

        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Safe parameter substitution for list
        placeholders = ','.join('?' for _ in ids)
        query = f"SELECT id FROM findings WHERE status='REJECTED' AND id IN ({placeholders})"
        
        c.execute(query, ids)
        rejected_ids = {row[0] for row in c.fetchall()}
        conn.close()
        
        return [f for f in findings if f.id not in rejected_ids]

    def save_findings(self, findings: List[StaticFinding]):
        """
        Save findings to persistence.
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        for f in findings:
            # Parse file/line
            parts = f.location.split(":")
            path = parts[0]
            line = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            
            # Use specific hash for finding to track 'fixed' status?
            # For now, just linking to file.
            
            # Check if exists and is REJECTED
            c.execute("SELECT status FROM findings WHERE id=?", (f.id,))
            row = c.fetchone()
            if row and row[0] == "REJECTED":
                logger.debug(f"Skipping save for REJECTED finding {f.id}")
                continue

            c.execute('''INSERT OR REPLACE INTO findings 
                (id, file_path, line, tool, severity, status) 
                VALUES (?, ?, ?, ?, ?, ?)''',
                (f.id, path, line, f.tool_name, f.severity, "DETECTED"))
        conn.commit()
        conn.close()
