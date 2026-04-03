"""
Research SubAgent

Conducts focused research on a single subtopic using web search,
then produces source-grounded analysis with key findings attributed
to specific sources.

Uses:
- LCEL chains (prompt | llm | parser) for composable pipelines
- Pydantic models + with_structured_output() for reliable structured data
- StrOutputParser for free-form text analysis
"""

from dataclasses import dataclass, field
from typing import List, Optional

from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

from agents.searcher import WebSearcher, SearchResult
from agents.ioc_extractor import IOCExtractor, IOCResults
from config import get_llm


# ── Pydantic Models for Structured Output ──

class KeyFindingModel(BaseModel):
    """A specific intelligence finding attributed to a source."""
    finding: str = Field(description="Specific factual finding with data points from the source")
    source_index: int = Field(description="1-based index of the source this finding comes from")
    confidence: str = Field(description="High, Moderate, or Low confidence level")


class KeyFindingsOutput(BaseModel):
    """Extracted key findings from search results."""
    findings: List[KeyFindingModel] = Field(description="3-7 key factual findings with source attribution")


class SeverityOutput(BaseModel):
    """Severity assessment for a threat."""
    severity: str = Field(description="Critical, High, Medium, or Low")
    justification: str = Field(description="One sentence citing specific evidence")


# ── Data Classes for Research Results ──

@dataclass
class Citation:
    """Source citation."""
    title: str
    url: str


@dataclass
class KeyFinding:
    """A specific intelligence finding attributed to a source."""
    finding: str
    source_title: str
    source_url: str
    confidence: str = "Moderate"


@dataclass
class SourceContent:
    """Preserved raw source content for downstream framework analysis."""
    title: str
    url: str
    content: str


@dataclass
class ResearchFinding:
    """Research result with source-grounded analysis."""
    topic: str
    analysis: str
    sources: List[Citation]
    severity: str = "Unknown"
    iocs: IOCResults = field(default_factory=IOCResults)
    key_findings: List[KeyFinding] = field(default_factory=list)
    raw_sources: List[SourceContent] = field(default_factory=list)


# ── SubAgent ──

class SubAgent:
    """
    Focused research agent that produces source-grounded analysis.

    Uses LCEL chains for each step:
    - analysis_chain: prompt | llm | StrOutputParser (free-form text)
    - key_findings_chain: prompt | llm.with_structured_output (Pydantic model)
    - severity_chain: prompt | llm.with_structured_output (Pydantic model)
    """

    def __init__(self, llm=None, topic: str = ""):
        self.llm = llm or get_llm()
        self.topic = topic
        self.searcher = WebSearcher()
        self.ioc_extractor = IOCExtractor()

        # Chain 1: Source-grounded analysis (free-form text)
        self.analysis_chain = (
            ChatPromptTemplate.from_messages([
                ("system", (
                    "You are a cyber threat intelligence analyst. "
                    "You MUST ground every claim in the source material provided. "
                    "Reference sources as [Source N] throughout your analysis. "
                    "Do NOT write generic knowledge — only report what the sources say."
                )),
                ("human", (
                    "Analyze these search results about: {topic}\n\n"
                    "{search_results}\n\n"
                    "Write a detailed analysis with this structure:\n\n"
                    "SITUATION OVERVIEW: What is happening based on the sources? Include specific "
                    "dates, names, numbers, and facts reported.\n\n"
                    "THREAT DETAILS: Specific threats, CVEs, malware, tools, and techniques "
                    "described in the sources.\n\n"
                    "IMPACT ASSESSMENT: Reported impact — organizations affected, data volumes, "
                    "financial figures, operational disruptions from the sources.\n\n"
                    "RECOMMENDED ACTIONS: Specific mitigations and tools recommended by the sources.\n\n"
                    "RULES:\n"
                    "- Every paragraph MUST cite at least one source as [Source N]\n"
                    "- Include specific numbers, dates, and names from sources\n"
                    "- If sources contradict, note the disagreement\n"
                    "- Write in plain text only — no markdown formatting"
                )),
            ])
            | self.llm
            | StrOutputParser()
        )

        # Chain 2: Key findings extraction (structured output)
        self.key_findings_chain = (
            ChatPromptTemplate.from_messages([
                ("system", (
                    "You extract key intelligence findings from search results. "
                    "Each finding must be a specific, verifiable fact from a source — "
                    "not opinions or generic statements."
                )),
                ("human", (
                    "Extract 3-7 KEY FINDINGS from these results about: {topic}\n\n"
                    "{search_results}\n\n"
                    "Good: 'CL0P exploited CVE-2023-34362 in MOVEit Transfer, breaching "
                    "600+ organizations [Source 4]'\n"
                    "Bad: 'Ransomware attacks are increasing' (too generic)\n\n"
                    "Each finding needs: the specific fact, which source (by index), "
                    "and your confidence level."
                )),
            ])
            | self.llm.with_structured_output(KeyFindingsOutput)
        )

        # Chain 3: Severity assessment (structured output)
        self.severity_chain = (
            ChatPromptTemplate.from_messages([
                ("system", "You are a threat severity assessor."),
                ("human", (
                    "Rate the severity of this threat based on the analysis:\n\n"
                    "Topic: {topic}\n"
                    "Analysis: {analysis}\n\n"
                    "Consider:\n"
                    "- Impact: What damage can this cause? Are there reported incidents?\n"
                    "- Exploitability: Are exploits actively used in the wild?\n"
                    "- Scope: How many systems/organizations affected?\n\n"
                    "Provide severity (Critical/High/Medium/Low) with evidence-based justification."
                )),
            ])
            | self.llm.with_structured_output(SeverityOutput)
        )

    def _build_source_text(
        self, sources: List[Citation], search_content: List[str]
    ) -> str:
        """Build numbered source list for LLM prompts."""
        return "\n\n".join(
            f"[Source {i+1}: {sources[i].title}]\n{content}"
            for i, content in enumerate(search_content)
            if i < len(sources)
        )

    def _extract_key_findings(
        self, formatted_results: str, sources: List[Citation]
    ) -> List[KeyFinding]:
        """Extract source-attributed key findings using structured output chain."""
        try:
            result = self.key_findings_chain.invoke({
                "topic": self.topic,
                "search_results": formatted_results,
            })
            findings = []
            for item in result.findings:
                idx = item.source_index - 1  # Convert to 0-based
                if 0 <= idx < len(sources):
                    src = sources[idx]
                elif sources:
                    src = sources[0]
                else:
                    continue
                findings.append(KeyFinding(
                    finding=item.finding,
                    source_title=src.title,
                    source_url=src.url,
                    confidence=item.confidence,
                ))
            return findings
        except Exception as e:
            # Structured output can fail with some models — degrade gracefully
            import logging
            logging.getLogger(__name__).warning(
                f"Key findings extraction failed, falling back: {e}"
            )
            return []

    def _assess_severity(self, analysis: str) -> str:
        """Assess threat severity using structured output chain."""
        try:
            result = self.severity_chain.invoke({
                "topic": self.topic,
                "analysis": analysis,
            })
            return result.severity
        except Exception:
            return "Unknown"

    def research(self, queries: List[str]) -> ResearchFinding:
        """
        Conduct focused, source-grounded research on the topic.

        Pipeline:
        1. Search with Tavily (full content via include_raw_content)
        2. Analyze findings with source citations (LCEL chain)
        3. Extract key findings with source attribution (structured output)
        4. Extract IOCs from raw content (regex)
        5. Assess severity (structured output)
        """
        all_sources: List[Citation] = []
        search_content: List[str] = []
        raw_text_for_iocs: List[str] = []
        raw_sources: List[SourceContent] = []

        for query in queries:
            results = self.searcher.search(query, max_results=3)
            for result in results:
                all_sources.append(Citation(title=result.title, url=result.url))
                # Prefer raw_content (full article) over content (snippet)
                best_content = result.raw_content if result.raw_content else result.content
                # Cap individual source content to avoid token overflow
                if len(best_content) > 4000:
                    best_content = best_content[:4000] + "\n[...]"
                search_content.append(best_content)
                # Cap content for IOC extraction — article body (where real
                # IOCs live) comes first in Tavily markdown; page chrome
                # (navbars, footers, sidebars) is appended after.
                ioc_content = result.raw_content or result.content
                if len(ioc_content) > 8000:
                    ioc_content = ioc_content[:8000]
                raw_text_for_iocs.append(ioc_content)
                raw_sources.append(SourceContent(
                    title=result.title, url=result.url,
                    content=best_content,
                ))

        # Build numbered source text for LLM
        formatted_results = self._build_source_text(all_sources, search_content)

        # Step 1: Source-grounded analysis (LCEL chain)
        analysis = self.analysis_chain.invoke({
            "topic": self.topic,
            "search_results": formatted_results,
        })

        # Step 2: Key findings with source attribution (structured output)
        key_findings = self._extract_key_findings(formatted_results, all_sources)

        # Step 3: IOC extraction from raw content (regex — no LLM needed)
        iocs = self.ioc_extractor.extract("\n".join(raw_text_for_iocs))

        # Step 4: Severity assessment (structured output)
        severity = self._assess_severity(analysis)

        return ResearchFinding(
            topic=self.topic,
            analysis=analysis,
            sources=all_sources,
            severity=severity,
            iocs=iocs,
            key_findings=key_findings,
            raw_sources=raw_sources,
        )
