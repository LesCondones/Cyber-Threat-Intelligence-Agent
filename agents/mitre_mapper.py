"""
MITRE ATT&CK Mapper

Maps threat analysis findings to real MITRE ATT&CK techniques.

Fetches the official Enterprise ATT&CK STIX 2.1 bundle from GitHub,
caches techniques in SQLite, and uses the real data for LLM prompt
context and output validation. No hardcoded technique tables.

Data source: https://github.com/mitre/cti
Cache refresh: every 30 days
"""

import json
import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate

from config import get_llm

logger = logging.getLogger(__name__)

ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/"
    "master/enterprise-attack/enterprise-attack.json"
)
CACHE_DB_PATH = Path("database/mitre_cache.db")
CACHE_MAX_AGE_DAYS = 30


# ── Pydantic Models ──

@dataclass
class MITREMapping:
    """A single MITRE ATT&CK technique mapping."""
    tactic: str
    technique_id: str
    technique: str
    confidence: str


class MITRETechniqueMapping(BaseModel):
    """Single technique mapping for structured output."""
    tactic: str = Field(description="ATT&CK tactic (e.g., Initial Access, Execution)")
    technique_id: str = Field(description="Technique ID (e.g., T1566, T1566.001)")
    technique: str = Field(description="Technique name")
    confidence: str = Field(description="high, medium, or low")


class MITREMappingOutput(BaseModel):
    """Structured output for MITRE ATT&CK mapping."""
    mappings: List[MITRETechniqueMapping] = Field(
        description="5-15 unique MITRE ATT&CK technique mappings"
    )


# ── MITRE Data Cache ──

class MITREDataCache:
    """
    Local SQLite cache of MITRE ATT&CK Enterprise techniques.

    Downloads the official STIX bundle (~30MB) from GitHub, parses
    attack-pattern objects, and stores technique metadata. Refreshes
    when cache is older than CACHE_MAX_AGE_DAYS.
    """

    def __init__(self, db_path: Path = CACHE_DB_PATH):
        self.db_path = db_path
        self._techniques: Dict[str, dict] = {}
        self._init_db()
        self._load_or_refresh()

    def _init_db(self):
        self.db_path.parent.mkdir(exist_ok=True)
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS mitre_techniques (
                    technique_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    tactics TEXT NOT NULL,
                    description TEXT,
                    url TEXT,
                    is_subtechnique INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)

    def _cache_age_days(self) -> float:
        with sqlite3.connect(str(self.db_path)) as conn:
            row = conn.execute(
                "SELECT value FROM cache_metadata WHERE key = 'last_updated'"
            ).fetchone()
            if row:
                try:
                    last = datetime.fromisoformat(row[0])
                    return (datetime.now() - last).total_seconds() / 86400
                except (ValueError, TypeError):
                    pass
        return float("inf")

    def _technique_count(self) -> int:
        with sqlite3.connect(str(self.db_path)) as conn:
            return conn.execute("SELECT COUNT(*) FROM mitre_techniques").fetchone()[0]

    def _load_or_refresh(self):
        age = self._cache_age_days()
        count = self._technique_count()

        if count == 0 or age > CACHE_MAX_AGE_DAYS:
            logger.info(f"MITRE cache needs refresh (count={count}, age={age:.0f}d)")
            if self._fetch_and_cache():
                logger.info(f"Cached {self._technique_count()} techniques")
            else:
                logger.warning("MITRE fetch failed, using existing cache")

        self._load_from_db()

    def _fetch_and_cache(self) -> bool:
        """Download the STIX bundle from GitHub and cache techniques in SQLite."""
        try:
            print("   Downloading MITRE ATT&CK data from GitHub...")
            response = requests.get(ATTACK_STIX_URL, timeout=120, stream=True)
            response.raise_for_status()

            bundle = response.json()
            techniques = []

            for obj in bundle.get("objects", []):
                if obj.get("type") != "attack-pattern":
                    continue
                if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                    continue

                technique_id, url = "", ""
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        technique_id = ref.get("external_id", "")
                        url = ref.get("url", "")
                        break

                if not technique_id:
                    continue

                tactics = [
                    phase["phase_name"].replace("-", " ").title()
                    for phase in obj.get("kill_chain_phases", [])
                    if phase.get("kill_chain_name") == "mitre-attack"
                ]

                techniques.append((
                    technique_id,
                    obj.get("name", ""),
                    json.dumps(tactics),
                    (obj.get("description", "") or "")[:500],
                    url,
                    1 if "." in technique_id else 0,
                ))

            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("DELETE FROM mitre_techniques")
                conn.executemany(
                    "INSERT INTO mitre_techniques VALUES (?, ?, ?, ?, ?, ?)",
                    techniques,
                )
                conn.execute(
                    "INSERT OR REPLACE INTO cache_metadata VALUES ('last_updated', ?)",
                    (datetime.now().isoformat(),),
                )

            print(f"   Cached {len(techniques)} MITRE ATT&CK techniques")
            return True

        except Exception as e:
            logger.error(f"MITRE fetch failed: {e}")
            print(f"   Warning: Could not fetch MITRE data: {e}")
            return False

    def _load_from_db(self):
        self._techniques.clear()
        with sqlite3.connect(str(self.db_path)) as conn:
            for tid, name, tactics_json, desc, url in conn.execute(
                "SELECT technique_id, name, tactics, description, url FROM mitre_techniques"
            ).fetchall():
                self._techniques[tid] = {
                    "name": name,
                    "tactics": json.loads(tactics_json),
                    "description": desc,
                    "url": url,
                }

    def get(self, technique_id: str) -> Optional[dict]:
        return self._techniques.get(technique_id)

    def validate_id(self, technique_id: str) -> bool:
        return technique_id in self._techniques

    def get_reference_text(self, limit: int = 50) -> str:
        """
        Build a reference list of real technique IDs for the LLM prompt.

        This gives the LLM accurate technique IDs to work with instead
        of hallucinating them. Prioritizes parent techniques for brevity.
        """
        parents = sorted(
            ((tid, d) for tid, d in self._techniques.items() if "." not in tid),
            key=lambda x: x[0],
        )
        lines = []
        for tid, data in parents[:limit]:
            tactics = ", ".join(data["tactics"][:2]) if data["tactics"] else "Unknown"
            lines.append(f"- {tid}: {data['name']} ({tactics})")
        return "\n".join(lines)

    @property
    def technique_count(self) -> int:
        return len(self._techniques)


# ── MITRE Mapper ──

class MITREMapper:
    """
    Maps threat findings to MITRE ATT&CK techniques using LLM + real data.

    Pipeline:
    1. Build prompt with real technique IDs from the cached STIX data
    2. LLM identifies applicable techniques (structured output)
    3. Validate each ID against the real ATT&CK dataset
    4. Correct names to official names, drop invalid IDs
    5. Deduplicate
    """

    def __init__(self, llm=None):
        self.llm = llm or get_llm()
        self.cache = MITREDataCache()

        technique_reference = self.cache.get_reference_text(limit=40)

        self.prompt = ChatPromptTemplate.from_messages([
            ("system", (
                "You are a MITRE ATT&CK framework specialist. "
                "You map threat intelligence to specific ATT&CK techniques. "
                "Only use REAL technique IDs. If unsure of an ID, omit it."
            )),
            ("human", (
                "Map this analysis to MITRE ATT&CK techniques:\n\n"
                "{analysis}\n\n"
                "REAL technique IDs for reference:\n"
                "{technique_reference}\n\n"
                "Provide 5-15 unique mappings covering different tactics. "
                "Use sub-techniques (e.g., T1566.001) when specific evidence supports it."
            )),
        ])
        self._technique_reference = technique_reference

    def map_techniques(self, analysis_text: str) -> List[MITREMapping]:
        """Map analysis text to validated MITRE ATT&CK techniques."""
        try:
            structured_llm = self.llm.with_structured_output(MITREMappingOutput)
            chain = self.prompt | structured_llm

            result = chain.invoke({
                "analysis": analysis_text,
                "technique_reference": self._technique_reference,
            })

            mappings = []
            seen = set()

            for item in result.mappings:
                tid = item.technique_id.strip()
                if not tid:
                    continue

                # Validate against real ATT&CK data
                real_tech = self.cache.get(tid)
                if real_tech:
                    technique_name = real_tech["name"]
                    tactic = item.tactic.strip()
                    if real_tech["tactics"] and tactic not in real_tech["tactics"]:
                        tactic = real_tech["tactics"][0]
                else:
                    logger.debug(f"Dropping invalid technique ID: {tid}")
                    continue

                dedup_key = (tactic, tid)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                mappings.append(MITREMapping(
                    tactic=tactic,
                    technique_id=tid,
                    technique=technique_name,
                    confidence=item.confidence.lower(),
                ))

            return mappings

        except Exception as e:
            logger.warning(f"MITRE mapping failed: {e}")
            return []
