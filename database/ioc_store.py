"""
IOC Database + Knowledge Graph

SQLite-based storage for IOCs, findings, threat actors, and MITRE mappings
with relationship tracking for attack analysis.

Schema models a knowledge graph:
    Threat Actor -> uses -> Malware
    Malware -> communicates_with -> Domain
    Domain -> hosted_on -> IP
    Finding -> contains -> IOC
    Finding -> maps_to -> MITRE Technique

Can be upgraded to Neo4j or PostgreSQL by swapping this module.
"""

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


DB_PATH = Path("database/cti.db")


@contextmanager
def _get_conn(db_path: Path = DB_PATH):
    """Context manager for database connections with WAL mode for concurrency."""
    db_path.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


class IOCStore:
    """
    Persistent storage for threat intelligence data.

    Provides:
    - IOC storage with deduplication
    - Investigation tracking (link findings to investigations)
    - Threat actor profile storage
    - Relationship tracking (graph edges between entities)
    - Query methods for analysis
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DB_PATH
        self._init_schema()

    def _init_schema(self):
        """Create all tables if they don't exist."""
        with _get_conn(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS investigations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    topic TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    report_path TEXT,
                    executive_summary TEXT
                );

                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    value TEXT NOT NULL,
                    type TEXT NOT NULL,  -- ip, domain, md5, sha256, cve, email, url
                    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
                    last_seen TEXT NOT NULL DEFAULT (datetime('now')),
                    risk_score INTEGER DEFAULT 0,
                    enrichment_data TEXT,  -- JSON blob from enrichment agent
                    UNIQUE(value, type)
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id INTEGER NOT NULL,
                    topic TEXT NOT NULL,
                    analysis TEXT,
                    severity TEXT DEFAULT 'Unknown',
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    FOREIGN KEY (investigation_id) REFERENCES investigations(id)
                );

                CREATE TABLE IF NOT EXISTS finding_iocs (
                    finding_id INTEGER NOT NULL,
                    ioc_id INTEGER NOT NULL,
                    PRIMARY KEY (finding_id, ioc_id),
                    FOREIGN KEY (finding_id) REFERENCES findings(id),
                    FOREIGN KEY (ioc_id) REFERENCES iocs(id)
                );

                CREATE TABLE IF NOT EXISTS threat_actors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    aliases TEXT,  -- JSON array
                    motivation TEXT,
                    sophistication TEXT,
                    primary_targets TEXT,  -- JSON array
                    target_regions TEXT,  -- JSON array
                    techniques TEXT,  -- JSON array
                    malware_used TEXT,  -- JSON array
                    first_seen TEXT,
                    description TEXT,
                    associated_campaigns TEXT,  -- JSON array
                    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                );

                CREATE TABLE IF NOT EXISTS mitre_mappings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id INTEGER NOT NULL,
                    tactic TEXT NOT NULL,
                    technique_id TEXT NOT NULL,
                    technique TEXT NOT NULL,
                    confidence TEXT DEFAULT 'low',
                    FOREIGN KEY (investigation_id) REFERENCES investigations(id)
                );

                -- Knowledge graph edges: entity relationships
                CREATE TABLE IF NOT EXISTS relationships (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_type TEXT NOT NULL,  -- threat_actor, malware, domain, ip, ioc
                    source_value TEXT NOT NULL,
                    relationship TEXT NOT NULL,  -- uses, communicates_with, hosted_on, targets
                    target_type TEXT NOT NULL,
                    target_value TEXT NOT NULL,
                    confidence TEXT DEFAULT 'medium',
                    investigation_id INTEGER,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    FOREIGN KEY (investigation_id) REFERENCES investigations(id)
                );

                CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
                CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
                CREATE INDEX IF NOT EXISTS idx_relationships_source ON relationships(source_value);
                CREATE INDEX IF NOT EXISTS idx_relationships_target ON relationships(target_value);
            """)

    # ── Investigation Methods ──

    def create_investigation(
        self, topic: str, report_path: str = "", executive_summary: str = ""
    ) -> int:
        """Create a new investigation record and return its ID."""
        with _get_conn(self.db_path) as conn:
            cursor = conn.execute(
                "INSERT INTO investigations (topic, report_path, executive_summary) VALUES (?, ?, ?)",
                (topic, report_path, executive_summary),
            )
            return cursor.lastrowid

    def get_investigations(self, limit: int = 20) -> List[dict]:
        """Get recent investigations."""
        with _get_conn(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM investigations ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    # ── IOC Methods ──

    def store_ioc(
        self,
        value: str,
        ioc_type: str,
        risk_score: int = 0,
        enrichment_data: Optional[dict] = None,
    ) -> int:
        """
        Store or update an IOC. Returns the IOC's database ID.

        Uses UPSERT so duplicate IOCs update their last_seen and
        enrichment data rather than creating duplicates.
        """
        with _get_conn(self.db_path) as conn:
            enrichment_json = json.dumps(enrichment_data) if enrichment_data else None
            conn.execute(
                """INSERT INTO iocs (value, type, risk_score, enrichment_data)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(value, type) DO UPDATE SET
                       last_seen = datetime('now'),
                       risk_score = MAX(iocs.risk_score, excluded.risk_score),
                       enrichment_data = COALESCE(excluded.enrichment_data, iocs.enrichment_data)
                """,
                (value, ioc_type, risk_score, enrichment_json),
            )
            row = conn.execute(
                "SELECT id FROM iocs WHERE value = ? AND type = ?",
                (value, ioc_type),
            ).fetchone()
            return row["id"]

    def store_iocs_from_results(
        self, ioc_results, finding_id: Optional[int] = None
    ) -> List[int]:
        """Store all IOCs from an IOCResults object and optionally link to a finding."""
        ioc_ids = []
        type_map = {
            "ip": ioc_results.ipv4_addresses,
            "domain": ioc_results.domains,
            "url": ioc_results.urls,
            "md5": ioc_results.md5_hashes,
            "sha256": ioc_results.sha256_hashes,
            "cve": ioc_results.cve_ids,
            "email": ioc_results.emails,
            "malware": ioc_results.malware_names,
        }

        for ioc_type, values in type_map.items():
            for value in values:
                ioc_id = self.store_ioc(value, ioc_type)
                ioc_ids.append(ioc_id)
                if finding_id:
                    self._link_finding_ioc(finding_id, ioc_id)

        return ioc_ids

    def _link_finding_ioc(self, finding_id: int, ioc_id: int):
        """Link a finding to an IOC."""
        with _get_conn(self.db_path) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO finding_iocs (finding_id, ioc_id) VALUES (?, ?)",
                (finding_id, ioc_id),
            )

    def get_ioc(self, value: str) -> Optional[dict]:
        """Look up an IOC by value."""
        with _get_conn(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM iocs WHERE value = ?", (value,)
            ).fetchone()
            if row:
                result = dict(row)
                if result.get("enrichment_data"):
                    result["enrichment_data"] = json.loads(result["enrichment_data"])
                return result
            return None

    def get_high_risk_iocs(self, min_score: int = 50) -> List[dict]:
        """Get all IOCs above a risk score threshold."""
        with _get_conn(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM iocs WHERE risk_score >= ? ORDER BY risk_score DESC",
                (min_score,),
            ).fetchall()
            return [dict(r) for r in rows]

    # ── Finding Methods ──

    def store_finding(
        self, investigation_id: int, finding
    ) -> int:
        """Store a ResearchFinding and its IOCs."""
        with _get_conn(self.db_path) as conn:
            cursor = conn.execute(
                "INSERT INTO findings (investigation_id, topic, analysis, severity) VALUES (?, ?, ?, ?)",
                (investigation_id, finding.topic, finding.analysis, finding.severity),
            )
            finding_id = cursor.lastrowid

        # Store IOCs and link them
        self.store_iocs_from_results(finding.iocs, finding_id)
        return finding_id

    # ── Threat Actor Methods ──

    def store_threat_actor(self, profile) -> int:
        """Store or update a threat actor profile."""
        with _get_conn(self.db_path) as conn:
            conn.execute(
                """INSERT INTO threat_actors
                   (name, aliases, motivation, sophistication, primary_targets,
                    target_regions, techniques, malware_used, first_seen,
                    description, associated_campaigns)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(name) DO UPDATE SET
                       aliases = excluded.aliases,
                       motivation = excluded.motivation,
                       sophistication = excluded.sophistication,
                       primary_targets = excluded.primary_targets,
                       target_regions = excluded.target_regions,
                       techniques = excluded.techniques,
                       malware_used = excluded.malware_used,
                       description = excluded.description,
                       associated_campaigns = excluded.associated_campaigns,
                       updated_at = datetime('now')
                """,
                (
                    profile.name,
                    json.dumps(profile.aliases),
                    profile.motivation,
                    profile.sophistication,
                    json.dumps(profile.primary_targets),
                    json.dumps(profile.target_regions),
                    json.dumps(profile.techniques),
                    json.dumps(profile.malware_used),
                    profile.first_seen,
                    profile.description,
                    json.dumps(profile.associated_campaigns),
                ),
            )
            row = conn.execute(
                "SELECT id FROM threat_actors WHERE name = ?", (profile.name,)
            ).fetchone()
            return row["id"]

    def get_threat_actors(self) -> List[dict]:
        """Get all stored threat actor profiles."""
        with _get_conn(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM threat_actors ORDER BY updated_at DESC"
            ).fetchall()
            results = []
            for r in rows:
                d = dict(r)
                for field in [
                    "aliases", "primary_targets", "target_regions",
                    "techniques", "malware_used", "associated_campaigns",
                ]:
                    if d.get(field):
                        d[field] = json.loads(d[field])
                results.append(d)
            return results

    # ── MITRE Mapping Methods ──

    def store_mitre_mappings(
        self, investigation_id: int, mappings: list
    ):
        """Store MITRE ATT&CK mappings for an investigation."""
        with _get_conn(self.db_path) as conn:
            for m in mappings:
                conn.execute(
                    """INSERT INTO mitre_mappings
                       (investigation_id, tactic, technique_id, technique, confidence)
                       VALUES (?, ?, ?, ?, ?)""",
                    (investigation_id, m.tactic, m.technique_id, m.technique, m.confidence),
                )

    # ── Relationship / Knowledge Graph Methods ──

    def add_relationship(
        self,
        source_type: str,
        source_value: str,
        relationship: str,
        target_type: str,
        target_value: str,
        confidence: str = "medium",
        investigation_id: Optional[int] = None,
    ):
        """
        Add an edge to the knowledge graph.

        Example:
            add_relationship("threat_actor", "LockBit", "uses", "malware", "LockBit 3.0")
            add_relationship("domain", "evil.com", "hosted_on", "ip", "1.2.3.4")
        """
        with _get_conn(self.db_path) as conn:
            conn.execute(
                """INSERT INTO relationships
                   (source_type, source_value, relationship, target_type,
                    target_value, confidence, investigation_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (source_type, source_value, relationship, target_type,
                 target_value, confidence, investigation_id),
            )

    def build_relationships_from_profile(
        self, profile, investigation_id: Optional[int] = None
    ):
        """
        Automatically build knowledge graph edges from a threat actor profile.

        Creates relationships like:
            ThreatActor -> uses -> Malware
            ThreatActor -> uses_technique -> Technique
            ThreatActor -> targets -> Sector
        """
        for malware in profile.malware_used:
            self.add_relationship(
                "threat_actor", profile.name, "uses",
                "malware", malware, "high", investigation_id,
            )
        for technique in profile.techniques:
            self.add_relationship(
                "threat_actor", profile.name, "uses_technique",
                "technique", technique, "high", investigation_id,
            )
        for target in profile.primary_targets:
            self.add_relationship(
                "threat_actor", profile.name, "targets",
                "sector", target, "high", investigation_id,
            )

    def get_relationships(
        self, entity_value: Optional[str] = None
    ) -> List[dict]:
        """
        Query knowledge graph edges.

        If entity_value is provided, returns all relationships involving
        that entity (as source or target). Otherwise returns all.
        """
        with _get_conn(self.db_path) as conn:
            if entity_value:
                rows = conn.execute(
                    """SELECT * FROM relationships
                       WHERE source_value = ? OR target_value = ?
                       ORDER BY created_at DESC""",
                    (entity_value, entity_value),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM relationships ORDER BY created_at DESC LIMIT 100"
                ).fetchall()
            return [dict(r) for r in rows]

    def get_graph_summary(self) -> Dict[str, int]:
        """Get summary statistics of the knowledge graph."""
        with _get_conn(self.db_path) as conn:
            stats = {}
            stats["total_iocs"] = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
            stats["total_investigations"] = conn.execute("SELECT COUNT(*) FROM investigations").fetchone()[0]
            stats["total_threat_actors"] = conn.execute("SELECT COUNT(*) FROM threat_actors").fetchone()[0]
            stats["total_relationships"] = conn.execute("SELECT COUNT(*) FROM relationships").fetchone()[0]
            stats["total_mitre_mappings"] = conn.execute("SELECT COUNT(*) FROM mitre_mappings").fetchone()[0]
            stats["high_risk_iocs"] = conn.execute(
                "SELECT COUNT(*) FROM iocs WHERE risk_score >= 50"
            ).fetchone()[0]
            return stats
