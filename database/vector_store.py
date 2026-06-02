"""
Vector Store — Semantic Threat Search

Persistent Chroma collection that indexes the long-form text artifacts the
SQLite store can't search semantically: finding analyses, executive summaries,
threat actor profiles, recommendations, and detection rules.

SQLite remains the source of truth for structured records and relationships.
This module just answers "find prior work similar to X" queries.

Document IDs are deterministic (e.g. ``inv:42:summary``, ``actor:lockbit``) so
re-running an investigation upserts cleanly instead of duplicating entries.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import chromadb
from chromadb.config import Settings as ChromaSettings
from chromadb.utils import embedding_functions

logger = logging.getLogger(__name__)


COLLECTION_NAME = "cti_knowledge"

# Document types stored in the collection. Used as metadata for filtering.
TYPE_FINDING = "finding"
TYPE_SUMMARY = "summary"
TYPE_ACTOR = "actor"
TYPE_RECOMMENDATION = "recommendation"
TYPE_DETECTION = "detection"


@dataclass
class SearchHit:
    """A single semantic search result."""

    id: str
    type: str
    text: str
    metadata: dict
    score: float  # 1.0 - distance (higher is better)


def _slug(value: str) -> str:
    """Slugify a name for use in document IDs (handles whitespace/case)."""
    return re.sub(r"[^a-z0-9]+", "-", (value or "unknown").lower()).strip("-") or "unknown"


def _clean_meta(meta: dict) -> dict:
    """Chroma metadata values must be str/int/float/bool. Drop None and stringify lists."""
    cleaned: dict[str, Any] = {}
    for k, v in meta.items():
        if v is None or v == "":
            continue
        if isinstance(v, (str, int, float, bool)):
            cleaned[k] = v
        elif isinstance(v, (list, tuple)):
            cleaned[k] = ", ".join(str(x) for x in v if x)
        else:
            cleaned[k] = str(v)
    return cleaned


class VectorStore:
    """
    Persistent semantic store for CTI artifacts.

    One Chroma collection, with a ``type`` metadata field that distinguishes
    finding / summary / actor / recommendation / detection documents. Filter
    by type at query time via ``search(..., types=[...])``.

    All embedding work runs locally via sentence-transformers; no network
    calls and no API keys required.
    """

    def __init__(
        self,
        persist_dir: Optional[Path | str] = None,
        model_name: str = "all-MiniLM-L6-v2",
    ):
        self.persist_dir = Path(persist_dir) if persist_dir else Path("database/chroma")
        self.persist_dir.mkdir(parents=True, exist_ok=True)

        self._client = chromadb.PersistentClient(
            path=str(self.persist_dir),
            settings=ChromaSettings(anonymized_telemetry=False),
        )
        self._embedder = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=model_name
        )
        self._collection = self._client.get_or_create_collection(
            name=COLLECTION_NAME,
            embedding_function=self._embedder,
            metadata={"hnsw:space": "cosine"},
        )

    # ── Upserts ──────────────────────────────────────────────────────────

    def _upsert(self, doc_id: str, text: str, metadata: dict) -> None:
        """Single document upsert with empty-text guard and error isolation."""
        text = (text or "").strip()
        if not text:
            return
        try:
            self._collection.upsert(
                ids=[doc_id],
                documents=[text],
                metadatas=[_clean_meta(metadata)],
            )
        except Exception as e:
            logger.warning(f"VectorStore upsert failed for {doc_id}: {e}")

    def upsert_finding(
        self, investigation_id: int, topic: str, finding: Any, idx: int
    ) -> None:
        """Index a ResearchFinding (analysis + key_findings text)."""
        key_findings = getattr(finding, "key_findings", []) or []
        key_text = "\n".join(
            f"- {getattr(kf, 'finding', '')}" for kf in key_findings
            if getattr(kf, "finding", None)
        )
        analysis = getattr(finding, "analysis", "") or ""
        sub_topic = getattr(finding, "topic", "") or topic
        text = f"{sub_topic}\n{analysis}\n{key_text}".strip()

        self._upsert(
            doc_id=f"inv:{investigation_id}:finding:{idx}",
            text=text,
            metadata={
                "type": TYPE_FINDING,
                "investigation_id": investigation_id,
                "topic": topic,
                "subtopic": sub_topic,
                "severity": getattr(finding, "severity", ""),
            },
        )

    def upsert_executive_summary(
        self, investigation_id: int, topic: str, summary: str
    ) -> None:
        """Index the investigation's executive summary."""
        text = f"{topic}\n{summary}".strip()
        self._upsert(
            doc_id=f"inv:{investigation_id}:summary",
            text=text,
            metadata={
                "type": TYPE_SUMMARY,
                "investigation_id": investigation_id,
                "topic": topic,
            },
        )

    def upsert_threat_actor(self, profile: Any) -> None:
        """Index a threat actor profile (description + targets/techniques/malware)."""
        name = getattr(profile, "name", "") or "Unknown"
        aliases = getattr(profile, "aliases", []) or []
        description = getattr(profile, "description", "") or ""
        targets = getattr(profile, "primary_targets", []) or []
        techniques = getattr(profile, "techniques", []) or []
        malware = getattr(profile, "malware_used", []) or []
        campaigns = getattr(profile, "associated_campaigns", []) or []

        alias_part = f" ({', '.join(aliases)})" if aliases else ""
        text = (
            f"{name}{alias_part}\n"
            f"{description}\n"
            f"Targets: {', '.join(targets)}\n"
            f"Techniques: {', '.join(techniques)}\n"
            f"Malware: {', '.join(malware)}\n"
            f"Campaigns: {', '.join(campaigns)}"
        )

        self._upsert(
            doc_id=f"actor:{_slug(name)}",
            text=text,
            metadata={
                "type": TYPE_ACTOR,
                "actor_name": name,
                "motivation": getattr(profile, "motivation", ""),
                "sophistication": getattr(profile, "sophistication", ""),
            },
        )

    def upsert_recommendation(
        self, investigation_id: int, topic: str, rec: Any, idx: int
    ) -> None:
        """Index a single recommendation (action + rationale + references)."""
        action = getattr(rec, "action", "") or ""
        rationale = getattr(rec, "rationale", "") or ""
        references = getattr(rec, "references", []) or []
        ref_text = ", ".join(references) if references else ""
        text = f"{action}\nRationale: {rationale}\nReferences: {ref_text}".strip()

        self._upsert(
            doc_id=f"inv:{investigation_id}:rec:{idx}",
            text=text,
            metadata={
                "type": TYPE_RECOMMENDATION,
                "investigation_id": investigation_id,
                "topic": topic,
                "priority": getattr(rec, "priority", ""),
                "target": getattr(rec, "target", ""),
            },
        )

    def upsert_detection_rule(
        self, investigation_id: int, topic: str, rule_kind: str, rule: Any, idx: int
    ) -> None:
        """Index a Sigma/YARA/Splunk/KQL rule (title + description + body)."""
        if rule_kind == "sigma":
            title = getattr(rule, "title", "") or ""
            body = getattr(rule, "yaml", "") or ""
        elif rule_kind == "yara":
            title = getattr(rule, "name", "") or ""
            body = getattr(rule, "body", "") or ""
        else:  # splunk / kql HuntQuery
            title = getattr(rule, "title", "") or ""
            body = getattr(rule, "query", "") or ""
        description = getattr(rule, "description", "") or ""
        text = f"{title}\n{description}\n{body}".strip()

        self._upsert(
            doc_id=f"inv:{investigation_id}:{rule_kind}:{idx}",
            text=text,
            metadata={
                "type": TYPE_DETECTION,
                "investigation_id": investigation_id,
                "topic": topic,
                "rule_kind": rule_kind,
            },
        )

    # ── Query ─────────────────────────────────────────────────────────────

    def search(
        self,
        query: str,
        k: int = 10,
        types: Optional[list[str]] = None,
    ) -> list[SearchHit]:
        """
        Semantic search across all indexed CTI artifacts.

        ``types`` optionally restricts results to one or more of:
        finding, summary, actor, recommendation, detection.
        """
        query = (query or "").strip()
        if not query:
            return []

        where: Optional[dict] = None
        if types:
            where = {"type": {"$in": list(types)}} if len(types) > 1 else {"type": types[0]}

        try:
            res = self._collection.query(
                query_texts=[query],
                n_results=max(1, k),
                where=where,
            )
        except Exception as e:
            logger.warning(f"VectorStore search failed: {e}")
            return []

        hits: list[SearchHit] = []
        ids = (res.get("ids") or [[]])[0]
        docs = (res.get("documents") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        distances = (res.get("distances") or [[]])[0]

        for i, doc_id in enumerate(ids):
            distance = distances[i] if i < len(distances) else 1.0
            hits.append(SearchHit(
                id=doc_id,
                type=(metas[i] or {}).get("type", "unknown") if i < len(metas) else "unknown",
                text=docs[i] if i < len(docs) else "",
                metadata=metas[i] if i < len(metas) else {},
                score=max(0.0, 1.0 - float(distance)),
            ))
        return hits

    def count(self) -> int:
        """Total number of indexed documents (across all types)."""
        try:
            return self._collection.count()
        except Exception:
            return 0
