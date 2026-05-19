"""
Detection Logic Generator

Produces ready-to-deploy detection content from investigation data:
- Sigma rules (vendor-agnostic SIEM detection YAML)
- YARA rules (file/memory signatures)
- Splunk SPL hunt queries
- Microsoft KQL (Defender / Sentinel) hunt queries

The LLM is constrained by structured output and grounded in the actual
observed TTPs and IOCs so the rules reference real artifacts, not
hallucinated indicators.
"""

import logging
from dataclasses import dataclass, field
from typing import List, Optional

from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate

from config import get_llm

logger = logging.getLogger(__name__)


# ── Pydantic Models for Structured Output ──

class SigmaRuleModel(BaseModel):
    title: str = Field(description="Short rule title")
    description: str = Field(description="What this rule detects and why")
    yaml: str = Field(description=(
        "Full Sigma rule YAML body (no surrounding ```yaml fence). "
        "Must include: title, id, status, description, author, date, "
        "logsource, detection, falsepositives, level."
    ))


class YaraRuleModel(BaseModel):
    name: str = Field(description="Rule name (no spaces, ASCII identifier)")
    description: str = Field(description="What this rule detects")
    body: str = Field(description=(
        "Full YARA rule body starting with 'rule <name> {' through "
        "the closing '}'. Include meta, strings, and condition sections."
    ))


class HuntQueryModel(BaseModel):
    title: str = Field(description="What the hunt is looking for")
    description: str = Field(description="Tuning notes / how to triage matches")
    query: str = Field(description="Query body (no surrounding fences)")


class DetectionLogicOutput(BaseModel):
    """All generated detection content for a single investigation."""
    sigma_rules: List[SigmaRuleModel] = Field(
        default_factory=list,
        description="0-3 Sigma rules covering observed TTPs."
    )
    yara_rules: List[YaraRuleModel] = Field(
        default_factory=list,
        description="0-2 YARA rules covering observed hashes or file strings."
    )
    splunk_queries: List[HuntQueryModel] = Field(
        default_factory=list,
        description="0-3 Splunk SPL hunt queries pivoting on observed IOCs."
    )
    kql_queries: List[HuntQueryModel] = Field(
        default_factory=list,
        description="0-3 Microsoft KQL hunt queries for Defender / Sentinel."
    )


# ── Plain Data Classes ──

@dataclass
class SigmaRule:
    title: str
    description: str
    yaml: str


@dataclass
class YaraRule:
    name: str
    description: str
    body: str


@dataclass
class HuntQuery:
    title: str
    description: str
    query: str


@dataclass
class DetectionLogic:
    sigma_rules: List[SigmaRule] = field(default_factory=list)
    yara_rules: List[YaraRule] = field(default_factory=list)
    splunk_queries: List[HuntQuery] = field(default_factory=list)
    kql_queries: List[HuntQuery] = field(default_factory=list)

    def has_any(self) -> bool:
        return bool(
            self.sigma_rules or self.yara_rules
            or self.splunk_queries or self.kql_queries
        )


# ── Generator ──

class DetectionLogicGenerator:
    """Generates Sigma / YARA / SIEM hunt content grounded in observed IOCs+TTPs."""

    def __init__(self, llm=None):
        self.llm = llm or get_llm()

        self.chain = (
            ChatPromptTemplate.from_messages([
                ("system", (
                    "You are a senior detection engineer producing deployable "
                    "content for a CTI report. Generate detection rules and "
                    "hunt queries grounded in the SPECIFIC IOCs and TTPs "
                    "provided. Do NOT invent indicators. Rules and queries "
                    "should reference real values from the input only. "
                    "If a category has no signal, return an empty list for it."
                )),
                ("human", (
                    "Generate detection content for: {research_topic}\n\n"
                    "Observed MITRE Techniques:\n{mitre_text}\n\n"
                    "Indicators of Compromise:\n{ioc_text}\n\n"
                    "Threat Actors:\n{actors_text}\n\n"
                    "Produce:\n"
                    "- Up to 3 Sigma rules (YAML body) for TTPs in the data\n"
                    "- Up to 2 YARA rules for any hashes or distinctive strings\n"
                    "- Up to 3 Splunk SPL hunt queries pivoting on IPs/domains/hashes\n"
                    "- Up to 3 Microsoft KQL queries for Defender / Sentinel\n\n"
                    "Sigma YAML MUST be syntactically valid and include: title, "
                    "id (UUIDv4), status, description, author, date, logsource, "
                    "detection (selection + condition), falsepositives, level. "
                    "Reference T-codes in tags.\n\n"
                    "YARA bodies MUST start with 'rule <name> {{' and include "
                    "meta, strings, and condition sections.\n\n"
                    "Splunk SPL: use realistic sourcetypes and field names. "
                    "KQL: target standard Defender / Sentinel tables "
                    "(DeviceNetworkEvents, DeviceFileEvents, etc.)."
                )),
            ])
            | self.llm.with_structured_output(DetectionLogicOutput)
        )

    def generate(
        self,
        research_topic: str,
        mitre_mappings: Optional[list] = None,
        iocs: Optional[object] = None,
        threat_actor_profiles: Optional[list] = None,
    ) -> DetectionLogic:
        """Generate detection content. Returns empty result on LLM failure."""
        if mitre_mappings:
            mitre_text = "\n".join(
                f"- {m.tactic} / {m.technique_id} {m.technique}"
                for m in mitre_mappings[:20]
            )
        else:
            mitre_text = "None mapped."

        if iocs:
            parts = []
            if iocs.ipv4_addresses:
                parts.append(f"IPv4: {', '.join(iocs.ipv4_addresses[:15])}")
            if iocs.domains:
                parts.append(f"Domains: {', '.join(iocs.domains[:15])}")
            if iocs.md5_hashes:
                parts.append(f"MD5: {', '.join(iocs.md5_hashes[:10])}")
            if iocs.sha256_hashes:
                parts.append(f"SHA256: {', '.join(iocs.sha256_hashes[:10])}")
            if iocs.cve_ids:
                parts.append(f"CVEs: {', '.join(iocs.cve_ids[:10])}")
            if iocs.malware_names:
                parts.append(f"Malware: {', '.join(iocs.malware_names[:10])}")
            ioc_text = "\n".join(parts) if parts else "No IOCs extracted."
        else:
            ioc_text = "No IOCs extracted."

        if threat_actor_profiles:
            actors_text = ", ".join(p.name for p in threat_actor_profiles)
        else:
            actors_text = "None identified."

        try:
            result = self.chain.invoke({
                "research_topic": research_topic,
                "mitre_text": mitre_text,
                "ioc_text": ioc_text,
                "actors_text": actors_text,
            })
        except Exception as e:
            logger.warning(f"Detection logic generation failed: {e}")
            return DetectionLogic()

        return DetectionLogic(
            sigma_rules=[
                SigmaRule(title=s.title, description=s.description, yaml=s.yaml)
                for s in result.sigma_rules
            ],
            yara_rules=[
                YaraRule(name=y.name, description=y.description, body=y.body)
                for y in result.yara_rules
            ],
            splunk_queries=[
                HuntQuery(title=q.title, description=q.description, query=q.query)
                for q in result.splunk_queries
            ],
            kql_queries=[
                HuntQuery(title=q.title, description=q.description, query=q.query)
                for q in result.kql_queries
            ],
        )
