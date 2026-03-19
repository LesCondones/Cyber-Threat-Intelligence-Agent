"""
CTI Framework Analyst

Applies structured intelligence analysis frameworks to research findings:
- Diamond Model of Intrusion Analysis (adversary, capability, infrastructure, victim)
- Cyber Kill Chain mapping (recon through actions on objectives)
- Intelligence confidence assessment with Admiralty System grading

Uses LangChain structured output (with_structured_output) and LCEL chains
for reliable, validated framework outputs.
"""

import logging
from dataclasses import dataclass, field
from typing import List

from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate

from config import get_llm

logger = logging.getLogger(__name__)


# ── Pydantic Models for Structured Output ──

class DiamondModelOutput(BaseModel):
    """Diamond Model of Intrusion Analysis."""
    adversary: str = Field(description=(
        "Identified threat actor(s) with specific names, aliases, and attribution. "
        "If unknown, describe the type based on evidence."
    ))
    capability: str = Field(description=(
        "Specific tools, malware families, exploits (CVEs), and techniques observed. "
        "Name specific items from the source material."
    ))
    infrastructure: str = Field(description=(
        "C2 servers, domains, IPs, hosting providers, delivery infrastructure. "
        "Include specific infrastructure details from sources."
    ))
    victim: str = Field(description=(
        "Targeted organizations, sectors, regions. Include the primary target "
        "and any related victims mentioned in sources."
    ))
    meta_features: str = Field(description=(
        "Timeline of events, attack phases, methodology patterns. "
        "Include specific dates and sequences from sources."
    ))


class KillChainPhaseOutput(BaseModel):
    """Single Cyber Kill Chain phase with evidence."""
    phase: str = Field(description="Kill Chain phase name")
    description: str = Field(description="What specifically happened in this phase")
    evidence: str = Field(description="Specific facts from sources supporting this")


class KillChainOutput(BaseModel):
    """Complete Kill Chain analysis."""
    phases: List[KillChainPhaseOutput] = Field(
        description="Kill Chain phases with evidence (only phases with actual evidence)"
    )


class IntelAssessmentOutput(BaseModel):
    """Intelligence confidence and reliability assessment."""
    overall_confidence: str = Field(description="Low, Moderate, or High")
    source_reliability: str = Field(description="A-F rating with justification")
    information_credibility: str = Field(description="1-6 rating with justification")
    key_judgments: List[str] = Field(description="3-5 key analytical judgments")
    intelligence_gaps: List[str] = Field(description="2-4 things we don't know")
    collection_priorities: List[str] = Field(description="2-3 recommended next steps")


# ── Data Classes for Internal Use ──

@dataclass
class DiamondModel:
    adversary: str = "Unknown"
    capability: str = "Unknown"
    infrastructure: str = "Unknown"
    victim: str = "Unknown"
    meta_features: str = ""


@dataclass
class KillChainPhase:
    phase: str
    description: str
    evidence: str


@dataclass
class IntelAssessment:
    overall_confidence: str = "Low"
    source_reliability: str = "F - Cannot be judged"
    information_credibility: str = "6 - Cannot be judged"
    key_judgments: List[str] = field(default_factory=list)
    intelligence_gaps: List[str] = field(default_factory=list)
    collection_priorities: List[str] = field(default_factory=list)


@dataclass
class FrameworkAnalysis:
    diamond_model: DiamondModel = field(default_factory=DiamondModel)
    kill_chain: List[KillChainPhase] = field(default_factory=list)
    assessment: IntelAssessment = field(default_factory=IntelAssessment)


# ── Framework Analyst ──

class FrameworkAnalyst:
    """
    Applies CTI frameworks to research findings using structured output chains.

    Each framework analysis is an LCEL chain:
        ChatPromptTemplate | llm.with_structured_output(PydanticModel)
    """

    def __init__(self, llm=None):
        self.llm = llm or get_llm()

        # Diamond Model chain
        self.diamond_chain = (
            ChatPromptTemplate.from_messages([
                ("system", (
                    "You are a senior threat intelligence analyst applying the "
                    "Diamond Model of Intrusion Analysis. Be specific — reference "
                    "actual data from the sources. No generic descriptions."
                )),
                ("human", (
                    "Apply the Diamond Model to this threat:\n\n"
                    "Research Topic: {research_topic}\n\n"
                    "Findings:\n{findings_text}\n\n"
                    "Source Material:\n{sources_text}\n\n"
                    "Identify the adversary, capability, infrastructure, and victim "
                    "using SPECIFIC details from the sources."
                )),
            ])
            | self.llm.with_structured_output(DiamondModelOutput)
        )

        # Kill Chain chain
        self.killchain_chain = (
            ChatPromptTemplate.from_messages([
                ("system", (
                    "You are a senior analyst mapping an attack to the Cyber Kill Chain. "
                    "Only include phases with actual evidence from the sources. "
                    "Phases: Reconnaissance, Weaponization, Delivery, Exploitation, "
                    "Installation, Command and Control, Actions on Objectives."
                )),
                ("human", (
                    "Map this threat activity to the Kill Chain:\n\n"
                    "Research Topic: {research_topic}\n\n"
                    "Findings:\n{findings_text}\n\n"
                    "Source Material:\n{sources_text}\n\n"
                    "For each applicable phase, cite specific evidence from sources. "
                    "Skip phases with no evidence."
                )),
            ])
            | self.llm.with_structured_output(KillChainOutput)
        )

        # Intelligence Assessment chain
        self.assessment_chain = (
            ChatPromptTemplate.from_messages([
                ("system", (
                    "You are a senior intelligence analyst assessing report confidence "
                    "using the Admiralty System (NATO standard).\n\n"
                    "Source Reliability: A=Completely Reliable, B=Usually Reliable, "
                    "C=Fairly Reliable, D=Not Usually Reliable, E=Unreliable, F=Cannot Judge\n\n"
                    "Information Credibility: 1=Confirmed, 2=Probably True, 3=Possibly True, "
                    "4=Doubtfully True, 5=Improbable, 6=Cannot Judge"
                )),
                ("human", (
                    "Assess the intelligence quality:\n\n"
                    "Research Topic: {research_topic}\n"
                    "Sources Consulted: {source_count}\n"
                    "Source Types: {source_types}\n\n"
                    "Findings Summary:\n{findings_text}\n\n"
                    "Provide overall confidence, source reliability, information credibility, "
                    "key judgments, intelligence gaps, and collection priorities."
                )),
            ])
            | self.llm.with_structured_output(IntelAssessmentOutput)
        )

    def _build_texts(self, findings: list, all_sources: list):
        """Build text summaries for framework prompts."""
        findings_text = "\n\n".join(
            f"[{f.topic}] (Severity: {f.severity})\n{f.analysis}"
            for f in findings
        )
        sources_text = "\n\n".join(
            f"[Source: {title}] ({url})\n{content[:500]}"
            for title, url, content in all_sources[:30]
        )
        source_domains = set()
        for _, url, _ in all_sources:
            try:
                domain = url.split("/")[2] if "//" in url else ""
                if domain:
                    source_domains.add(domain)
            except IndexError:
                pass
        source_types = ", ".join(sorted(source_domains)[:15])

        return findings_text, sources_text, source_types

    def full_analysis(
        self, research_topic: str, findings: list, all_sources: list
    ) -> FrameworkAnalysis:
        """
        Run all framework analyses on the findings.

        Args:
            research_topic: The original research topic
            findings: List of ResearchFinding objects
            all_sources: List of (title, url, content) tuples
        """
        findings_text, sources_text, source_types = self._build_texts(
            findings, all_sources
        )
        inputs = {
            "research_topic": research_topic,
            "findings_text": findings_text,
            "sources_text": sources_text,
        }

        # Diamond Model
        print("   Applying Diamond Model...")
        try:
            dm_result = self.diamond_chain.invoke(inputs)
            diamond = DiamondModel(
                adversary=dm_result.adversary,
                capability=dm_result.capability,
                infrastructure=dm_result.infrastructure,
                victim=dm_result.victim,
                meta_features=dm_result.meta_features,
            )
        except Exception as e:
            logger.warning(f"Diamond Model analysis failed: {e}")
            diamond = DiamondModel()

        # Kill Chain
        print("   Mapping Cyber Kill Chain...")
        try:
            kc_result = self.killchain_chain.invoke(inputs)
            kill_chain = [
                KillChainPhase(
                    phase=p.phase, description=p.description, evidence=p.evidence
                )
                for p in kc_result.phases
            ]
        except Exception as e:
            logger.warning(f"Kill Chain analysis failed: {e}")
            kill_chain = []

        # Intelligence Assessment
        print("   Assessing intelligence confidence...")
        try:
            ia_result = self.assessment_chain.invoke({
                **inputs,
                "source_count": str(len(all_sources)),
                "source_types": source_types,
            })
            assessment = IntelAssessment(
                overall_confidence=ia_result.overall_confidence,
                source_reliability=ia_result.source_reliability,
                information_credibility=ia_result.information_credibility,
                key_judgments=ia_result.key_judgments,
                intelligence_gaps=ia_result.intelligence_gaps,
                collection_priorities=ia_result.collection_priorities,
            )
        except Exception as e:
            logger.warning(f"Intelligence assessment failed: {e}")
            assessment = IntelAssessment()

        return FrameworkAnalysis(
            diamond_model=diamond,
            kill_chain=kill_chain,
            assessment=assessment,
        )
