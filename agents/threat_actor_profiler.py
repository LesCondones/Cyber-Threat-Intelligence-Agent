"""
Threat Actor Profiling Agent

Identifies and profiles threat actor groups mentioned in research findings.
Produces structured profiles similar to CrowdStrike/Mandiant intelligence briefs.

Uses LangChain structured output for reliable, validated JSON from the LLM.
"""

import logging
from typing import List, Optional

from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate

from config import get_llm

logger = logging.getLogger(__name__)


# ── Pydantic Models ──

class ActorListOutput(BaseModel):
    """List of identified threat actors."""
    actors: List[str] = Field(
        description="List of threat actor/APT group names found in the analysis. Empty list if none."
    )


class ThreatActorProfileOutput(BaseModel):
    """Structured threat actor intelligence profile."""
    name: str = Field(description="Official name of the threat actor")
    aliases: List[str] = Field(description="Other names this actor is known by")
    motivation: str = Field(description="Financial, Espionage, Hacktivism, Destruction, or Unknown")
    sophistication: str = Field(description="Low, Medium, High, or Advanced")
    primary_targets: List[str] = Field(description="Targeted industries/sectors")
    target_regions: List[str] = Field(description="Targeted geographic regions")
    techniques: List[str] = Field(description="Known attack techniques")
    malware_used: List[str] = Field(description="Malware families and tools used")
    first_seen: str = Field(description="Approximate year or date first observed")
    description: str = Field(description="2-3 sentence overview of the group")
    associated_campaigns: List[str] = Field(description="Named campaigns or operations")


# ── Data Class ──

class ThreatActorProfile:
    """Threat actor profile for use throughout the system."""

    def __init__(self, **kwargs):
        self.name = kwargs.get("name", "Unknown")
        self.aliases = kwargs.get("aliases", [])
        self.motivation = kwargs.get("motivation", "Unknown")
        self.sophistication = kwargs.get("sophistication", "Unknown")
        self.primary_targets = kwargs.get("primary_targets", [])
        self.target_regions = kwargs.get("target_regions", [])
        self.techniques = kwargs.get("techniques", [])
        self.malware_used = kwargs.get("malware_used", [])
        self.first_seen = kwargs.get("first_seen", "Unknown")
        self.description = kwargs.get("description", "")
        self.associated_campaigns = kwargs.get("associated_campaigns", [])

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "aliases": self.aliases,
            "motivation": self.motivation,
            "sophistication": self.sophistication,
            "primary_targets": self.primary_targets,
            "target_regions": self.target_regions,
            "techniques": self.techniques,
            "malware_used": self.malware_used,
            "first_seen": self.first_seen,
            "description": self.description,
            "associated_campaigns": self.associated_campaigns,
        }


class ThreatActorProfiler:
    """
    Identifies and profiles threat actors using structured output chains.

    Two-step process:
    1. Identify actors mentioned in findings (structured output → ActorListOutput)
    2. Profile each unique actor (structured output → ThreatActorProfileOutput)
    """

    def __init__(self, llm=None):
        self.llm = llm or get_llm()

        # Chain 1: Identify actors
        self.identify_chain = (
            ChatPromptTemplate.from_messages([
                ("system", (
                    "You are a cyber threat intelligence analyst. "
                    "Identify specific threat actor groups, APT groups, or "
                    "cybercriminal organizations mentioned in the analysis. "
                    "Only include groups explicitly named in the text."
                )),
                ("human", (
                    "Identify all threat actors mentioned in this analysis:\n\n"
                    "{analysis}\n\n"
                    "Return the list of actor names. Return empty list if none are found."
                )),
            ])
            | self.llm.with_structured_output(ActorListOutput)
        )

        # Chain 2: Profile a single actor
        self.profile_chain = (
            ChatPromptTemplate.from_messages([
                ("system", (
                    "You are a senior threat intelligence analyst creating a threat actor profile. "
                    "Base your profile on the research context provided and your knowledge. "
                    "Be accurate — do NOT confuse different threat groups or attribute wrong aliases. "
                    "Each group has its own identity. For example, CL0P is NOT the same as "
                    "LockBit or Ragnar Locker."
                )),
                ("human", (
                    "Create a detailed profile for: {actor_name}\n\n"
                    "Research Context:\n{context}\n\n"
                    "Provide accurate attribution — only list aliases that truly belong "
                    "to this actor, not other groups."
                )),
            ])
            | self.llm.with_structured_output(ThreatActorProfileOutput)
        )

    def identify_actors(self, analysis_text: str) -> List[str]:
        """Identify threat actor names mentioned in analysis text."""
        try:
            result = self.identify_chain.invoke({"analysis": analysis_text})
            return [a for a in result.actors if a.strip()]
        except Exception as e:
            logger.warning(f"Actor identification failed: {e}")
            return []

    def profile_actor(
        self, actor_name: str, context: str
    ) -> Optional[ThreatActorProfile]:
        """Generate a structured profile for a specific threat actor."""
        try:
            result = self.profile_chain.invoke({
                "actor_name": actor_name,
                "context": context,
            })
            return ThreatActorProfile(
                name=result.name,
                aliases=result.aliases,
                motivation=result.motivation,
                sophistication=result.sophistication,
                primary_targets=result.primary_targets,
                target_regions=result.target_regions,
                techniques=result.techniques,
                malware_used=result.malware_used,
                first_seen=result.first_seen,
                description=result.description,
                associated_campaigns=result.associated_campaigns,
            )
        except Exception as e:
            logger.warning(f"Profile generation failed for {actor_name}: {e}")
            return None

    def profile_from_findings(self, findings: list) -> List[ThreatActorProfile]:
        """
        Identify and profile all threat actors across findings.
        Deduplicates by name (case-insensitive).
        """
        all_analysis = "\n\n".join(f.analysis for f in findings)

        actor_names = self.identify_actors(all_analysis)
        if not actor_names:
            return []

        # Deduplicate (case-insensitive)
        seen = set()
        unique_actors = []
        for name in actor_names:
            if name.lower() not in seen:
                seen.add(name.lower())
                unique_actors.append(name)

        profiles = []
        for actor_name in unique_actors:
            print(f"   Profiling threat actor: {actor_name}")
            profile = self.profile_actor(actor_name, all_analysis)
            if profile:
                profiles.append(profile)

        return profiles
