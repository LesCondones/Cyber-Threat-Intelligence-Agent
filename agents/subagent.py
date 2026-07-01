"""
Research SubAgent

Conducts focused research on a single subtopic using web search,
then produces source-grounded analysis with key findings attributed
to specific sources.

A single structured-output call returns analysis, key findings, and
severity together — instead of three separate calls re-sending the
same source context — to keep token cost in check.
"""

from dataclasses import dataclass, field
from typing import List

from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate

from agents.searcher import WebSearcher
from agents.ioc_extractor import IOCExtractor, IOCResults
from config import get_llm


# Per-source content cap (chars). Lower = fewer input tokens per LLM call.
# 2500 chars ≈ 600 tokens; with ~9 sources that's ~5.5k tokens of source
# context — enough for grounded analysis without re-billing huge bodies
# across multiple calls.
SOURCE_CONTENT_CAP = 2500
IOC_CONTENT_CAP = 8000


# ── Pydantic Models for Structured Output ──

class KeyFindingModel(BaseModel):
    """A specific intelligence finding attributed to a source."""
    finding: str = Field(description="Specific factual finding with data points from the source")
    source_index: int = Field(description="1-based index of the source this finding comes from")
    confidence: str = Field(description="High, Moderate, or Low confidence level")


class ResearchOutput(BaseModel):
    """
    Combined research output produced in a single LLM call.

    The analysis field carries the long source-grounded text; the structured
    fields carry the extracted facts and severity. Producing all three in
    one call avoids re-sending the same source bodies to the LLM 3x.
    """
    analysis: str = Field(description=(
        "Detailed source-grounded analysis (plain text, no markdown). "
        "Every paragraph must cite at least one source as [Source N]. "
        "Cover: SITUATION OVERVIEW, THREAT DETAILS, IMPACT ASSESSMENT, "
        "RECOMMENDED ACTIONS — using specific dates, names, numbers from sources."
    ))
    key_findings: List[KeyFindingModel] = Field(description=(
        "3-7 specific, verifiable facts extracted from the sources with "
        "source attribution."
    ))
    severity: str = Field(description="Critical, High, Medium, or Low")
    severity_justification: str = Field(description=(
        "One sentence citing specific evidence for the severity rating."
    ))


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

    Pipeline:
    1. Search with Tavily (cached locally)
    2. ONE structured-output LLM call returning analysis + findings + severity
    3. Regex IOC extraction (no LLM)
    """

    def __init__(self, llm=None, topic: str = ""):
        self.llm = llm or get_llm()
        self.topic = topic
        self.searcher = WebSearcher()
        self.ioc_extractor = IOCExtractor()

        self.research_chain = (
            ChatPromptTemplate.from_messages([
                ("system", (
                    "You are a cyber threat intelligence analyst. "
                    "Ground every claim in the source material provided — "
                    "reference sources as [Source N] throughout the analysis. "
                    "Do NOT write generic knowledge — only report what the sources say. "
                    "Plain text only, no markdown formatting."
                )),
                ("human", (
                    "Analyze these search results about: {topic}\n\n"
                    "{search_results}\n\n"
                    "Produce a single combined output containing:\n"
                    "1. ANALYSIS: detailed source-grounded write-up with sections "
                    "SITUATION OVERVIEW / THREAT DETAILS / IMPACT ASSESSMENT / "
                    "RECOMMENDED ACTIONS. Every paragraph cites at least one "
                    "[Source N]. Include specific dates, names, numbers.\n"
                    "2. KEY FINDINGS: 3-7 specific verifiable facts with source "
                    "index and confidence (High/Moderate/Low). "
                    "Good: 'CL0P exploited CVE-2023-34362 in MOVEit, breaching "
                    "600+ organizations [Source 4]'. Bad: 'Ransomware is rising' "
                    "(too generic).\n"
                    "3. SEVERITY: Critical/High/Medium/Low based on impact, "
                    "exploitability, and scope, with one-sentence evidence-based "
                    "justification."
                )),
            ])
            | self.llm.with_structured_output(ResearchOutput)
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

    def _map_findings(
        self, raw_findings: List[KeyFindingModel], sources: List[Citation]
    ) -> List[KeyFinding]:
        """Map structured findings back to concrete source citations."""
        out: List[KeyFinding] = []
        for item in raw_findings:
            idx = item.source_index - 1
            if 0 <= idx < len(sources):
                src = sources[idx]
            elif sources:
                src = sources[0]
            else:
                continue
            out.append(KeyFinding(
                finding=item.finding,
                source_title=src.title,
                source_url=src.url,
                confidence=item.confidence,
            ))
        return out

    def research(self, queries: List[str]) -> ResearchFinding:
        """
        Conduct focused, source-grounded research on the topic.

        Pipeline:
        1. Search with Tavily (full content via include_raw_content, cached)
        2. Single LLM call → analysis + key findings + severity
        3. IOC extraction from raw content (regex)
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
                if len(best_content) > SOURCE_CONTENT_CAP:
                    best_content = best_content[:SOURCE_CONTENT_CAP] + "\n[...]"
                search_content.append(best_content)
                # IOC extraction uses a larger window: article body (where real
                # IOCs live) comes first in Tavily markdown; page chrome
                # (navbars, footers, sidebars) is appended after.
                ioc_content = result.raw_content or result.content
                if len(ioc_content) > IOC_CONTENT_CAP:
                    ioc_content = ioc_content[:IOC_CONTENT_CAP]
                raw_text_for_iocs.append(ioc_content)
                raw_sources.append(SourceContent(
                    title=result.title, url=result.url,
                    content=best_content,
                ))

        formatted_results = self._build_source_text(all_sources, search_content)

        # Single LLM call → analysis + key findings + severity
        try:
            result = self.research_chain.invoke({
                "topic": self.topic,
                "search_results": formatted_results,
            })
            analysis = result.analysis
            key_findings = self._map_findings(result.key_findings, all_sources)
            severity = result.severity or "Unknown"
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(
                f"Research structured output failed for '{self.topic}': {e}"
            )
            analysis = ""
            key_findings = []
            severity = "Unknown"

        # IOC extraction from raw content (regex — no LLM needed)
        iocs = self.ioc_extractor.extract("\n".join(raw_text_for_iocs))

        return ResearchFinding(
            topic=self.topic,
            analysis=analysis,
            sources=all_sources,
            severity=severity,
            iocs=iocs,
            key_findings=key_findings,
            raw_sources=raw_sources,
        )
