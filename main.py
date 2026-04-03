"""
CTI Coordinator — LangGraph Investigation Workflow

Orchestrates the full threat intelligence investigation as a state machine:

    plan → research → mitre_map → profile_actors → enrich_iocs
         → framework_analysis → executive_summary → generate_report

Each node is a self-contained step that reads from and writes to the
shared InvestigationState. LangGraph handles the flow, making it easy
to add conditional branches, checkpoints, or human-in-the-loop later.
"""

import asyncio
from datetime import datetime
from typing import Any, List, Optional, TypedDict

from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langgraph.graph import StateGraph, END

from agents.subagent import SubAgent, ResearchFinding
from agents.mitre_mapper import MITREMapper, MITREMapping
from agents.enrichment_agent import EnrichmentAgent, EnrichmentSummary
from agents.threat_actor_profiler import ThreatActorProfiler
from agents.framework_analyst import FrameworkAnalyst
from agents.feed_monitor import FeedMonitor
from agents.ioc_extractor import IOCResults
from reports.generator import ReportGenerator
from database.ioc_store import IOCStore
from config import get_llm, settings


# ── Pydantic Models for Structured Output ──

class InvestigationPlan(BaseModel):
    """Planning output: subtopics and targeted queries."""
    subtopics: List[str] = Field(description="3-5 focused, topic-specific subtopics for investigation")
    queries: dict[str, List[str]] = Field(
        description="For each subtopic, 3 targeted search queries"
    )


# ── LangGraph State ──

class InvestigationState(TypedDict):
    research_topic: str
    subtopics: list[str]
    queries: dict[str, list[str]]
    findings: list  # List[ResearchFinding]
    all_sources: list  # List[(title, url, content)]
    mitre_mappings: list  # List[MITREMapping]
    actor_profiles: list  # List[ThreatActorProfile]
    enrichment_summary: Any  # EnrichmentSummary
    framework_analysis: Any  # FrameworkAnalysis
    executive_summary: str
    report_path: str


# ── Shared Agent Instances ──
# Created once, reused across nodes to avoid re-initialization

_llm = None
_mitre_mapper = None
_enrichment_agent = None
_threat_actor_profiler = None
_framework_analyst = None
_report_generator = None
_ioc_store = None
_feed_monitor = None


def _init_agents():
    """Initialize all agents (called once at startup)."""
    global _llm, _mitre_mapper, _enrichment_agent, _threat_actor_profiler
    global _framework_analyst, _report_generator, _ioc_store, _feed_monitor

    _llm = get_llm()
    _mitre_mapper = MITREMapper(_llm)
    _enrichment_agent = EnrichmentAgent(
        virustotal_api_key=settings.virustotal_api_key,
        shodan_api_key=settings.shodan_api_key,
        abuseipdb_api_key=settings.abuseipdb_api_key,
    )
    _threat_actor_profiler = ThreatActorProfiler(_llm)
    _framework_analyst = FrameworkAnalyst(_llm)
    _report_generator = ReportGenerator()
    _ioc_store = IOCStore()
    _feed_monitor = FeedMonitor()


# ── Graph Nodes ──

def plan_node(state: InvestigationState) -> dict:
    """
    Break the research topic into focused subtopics with targeted queries.

    Uses structured output to get a plan with specific, topic-relevant
    subtopics — not generic categories like "ransomware attack vectors".
    """
    topic = state["research_topic"]
    print(f"\n[Plan] Planning investigation: '{topic}'")

    plan_chain = (
        ChatPromptTemplate.from_messages([
            ("system", (
                "You are a cyber threat intelligence coordinator planning an investigation. "
                "Today's date is {today}. "
                "Generate SPECIFIC subtopics that directly relate to the research topic. "
                "Do NOT generate generic categories like 'ransomware attack vectors' or "
                "'phishing techniques'. Instead, generate subtopics that investigate "
                "what actually happened, who was involved, and what the impact was."
            )),
            ("human", (
                "Plan an investigation into: {research_topic}\n\n"
                "Generate 3-5 subtopics that are SPECIFIC to this topic. "
                "For each subtopic, provide 3 targeted search queries that will find "
                "relevant, current information.\n\n"
                "Example for 'SolarWinds supply chain attack':\n"
                "- Subtopic: 'SolarWinds Orion compromise timeline and discovery'\n"
                "  Queries: ['SolarWinds Orion SUNBURST malware discovery timeline', "
                "'SolarWinds breach FireEye detection December 2020', "
                "'SolarWinds Orion update trojanized build process']\n"
                "- Subtopic: 'APT29 attribution and Russian intelligence connection'\n"
                "  Queries: ['APT29 Cozy Bear SolarWinds attribution evidence', ...]\n\n"
                "Now plan for: {research_topic}"
            )),
        ])
        | _llm.with_structured_output(InvestigationPlan)
    )

    try:
        plan = plan_chain.invoke({
            "research_topic": topic,
            "today": datetime.now().strftime("%Y-%m-%d"),
        })
        subtopics = plan.subtopics
        queries = plan.queries
    except Exception as e:
        # Fallback: use the topic itself
        print(f"   Plan structured output failed ({e}), using fallback")
        subtopics = [topic]
        queries = {topic: [
            f"{topic} cyber threat intelligence 2025 2026",
            f"{topic} attack details timeline",
            f"{topic} impact response mitigation",
        ]}

    print(f"[Plan] {len(subtopics)} subtopics: {subtopics}")
    return {"subtopics": subtopics, "queries": queries}


def research_node(state: InvestigationState) -> dict:
    """
    Research all subtopics concurrently using SubAgents.

    Each SubAgent:
    1. Searches with targeted queries (Tavily with full content)
    2. Produces source-grounded analysis (LCEL chain)
    3. Extracts key findings with source attribution (structured output)
    4. Extracts IOCs (regex)
    5. Assesses severity (structured output)
    """
    subtopics = state["subtopics"]
    queries = state["queries"]

    async def _research_all():
        tasks = []
        for idx, subtopic in enumerate(subtopics, 1):
            print(f"\n  SubAgent {idx}/{len(subtopics)}: {subtopic}")
            sub_queries = queries.get(subtopic, [
                f"{subtopic} cyber threat intelligence",
                f"{subtopic} latest attacks 2025 2026",
                f"{subtopic} impact analysis",
            ])

            async def _run(st=subtopic, sq=sub_queries):
                def _sync():
                    agent = SubAgent(llm=_llm, topic=st)
                    print(f"   Searching with {len(sq)} queries...")
                    result = agent.research(sq)
                    print(f"   {st}: {len(result.sources)} sources, severity={result.severity}")
                    return result
                return await asyncio.to_thread(_sync)

            tasks.append(_run())

        return await asyncio.gather(*tasks)

    findings = list(asyncio.run(_research_all()))

    # Deduplicate sources across findings
    seen_urls = set()
    for finding in findings:
        unique = []
        for source in finding.sources:
            if source.url not in seen_urls:
                seen_urls.add(source.url)
                unique.append(source)
        finding.sources = unique

    # Collect all source content for framework analysis
    all_sources = []
    for f in findings:
        for src in f.raw_sources:
            all_sources.append((src.title, src.url, src.content))

    return {"findings": findings, "all_sources": all_sources}


def mitre_node(state: InvestigationState) -> dict:
    """Map findings to MITRE ATT&CK using real technique data."""
    print(f"\n[MITRE] Mapping to MITRE ATT&CK framework...")
    all_mitre: List[MITREMapping] = []
    for finding in state["findings"]:
        mappings = _mitre_mapper.map_techniques(finding.analysis)
        all_mitre.extend(mappings)

    # Global dedup across findings
    seen = set()
    deduped = []
    for m in all_mitre:
        key = (m.tactic, m.technique_id)
        if key not in seen:
            seen.add(key)
            deduped.append(m)

    print(f"   {len(deduped)} unique technique mappings")
    return {"mitre_mappings": deduped}


def actor_node(state: InvestigationState) -> dict:
    """Identify and profile threat actors."""
    print(f"\n[Profiler] Identifying threat actors...")
    profiles = _threat_actor_profiler.profile_from_findings(state["findings"])
    if profiles:
        print(f"   Found {len(profiles)} actor(s): {[p.name for p in profiles]}")
    else:
        print("   No specific threat actors identified")
    return {"actor_profiles": profiles}


def enrich_node(state: InvestigationState) -> dict:
    """Enrich IOCs with external threat intelligence."""
    print(f"\n[Enrichment] Checking IOC reputation...")
    findings = state["findings"]

    has_keys = any([
        settings.virustotal_api_key,
        settings.shodan_api_key,
        settings.abuseipdb_api_key,
    ])
    if not has_keys:
        print("   No enrichment API keys configured, skipping")
        return {"enrichment_summary": EnrichmentSummary()}

    merged = IOCResults()
    for f in findings:
        merged.ipv4_addresses = list(set(merged.ipv4_addresses + f.iocs.ipv4_addresses))
        merged.domains = list(set(merged.domains + f.iocs.domains))
        merged.md5_hashes = list(set(merged.md5_hashes + f.iocs.md5_hashes))
        merged.sha256_hashes = list(set(merged.sha256_hashes + f.iocs.sha256_hashes))

    total = (len(merged.ipv4_addresses) + len(merged.domains) +
             len(merged.md5_hashes) + len(merged.sha256_hashes))

    if total == 0:
        return {"enrichment_summary": EnrichmentSummary()}

    print(f"   Enriching {total} unique IOCs...")
    summary = _enrichment_agent.enrich_all(merged)
    if summary.results:
        print(f"   {len(summary.results)} enriched, {summary.malicious_count} malicious")
    return {"enrichment_summary": summary}


def framework_node(state: InvestigationState) -> dict:
    """Apply CTI frameworks: Diamond Model, Kill Chain, confidence assessment."""
    print(f"\n[Frameworks] Applying CTI analysis frameworks...")
    analysis = _framework_analyst.full_analysis(
        state["research_topic"],
        state["findings"],
        state["all_sources"],
    )
    return {"framework_analysis": analysis}


def summary_node(state: InvestigationState) -> dict:
    """Generate an executive summary grounded in the findings."""
    print(f"\n[Summary] Generating executive summary...")

    # Build key findings text for the summary
    all_key_findings = []
    for f in state["findings"]:
        for kf in f.key_findings:
            all_key_findings.append(f"- {kf.finding} (Source: {kf.source_title})")
    key_findings_text = "\n".join(all_key_findings[:15]) if all_key_findings else "None extracted"

    # Build findings overview
    findings_text = "\n\n".join(
        f"[{f.topic}] (Severity: {f.severity})\n{f.analysis[:800]}"
        for f in state["findings"]
    )

    # Assessment context
    assessment = state.get("framework_analysis")
    confidence_text = ""
    if assessment and hasattr(assessment, "assessment"):
        a = assessment.assessment
        confidence_text = (
            f"\nIntelligence Confidence: {a.overall_confidence}"
            f"\nSource Reliability: {a.source_reliability}"
        )

    summary_chain = (
        ChatPromptTemplate.from_messages([
            ("system", (
                "You are a senior threat intelligence analyst writing an executive summary. "
                "Ground your summary in the specific findings and key facts below. "
                "Do NOT write generic cybersecurity advice. "
                "Write in plain text — no markdown formatting."
            )),
            ("human", (
                "Write a concise executive summary (3-5 paragraphs) for:\n\n"
                "Research Topic: {research_topic}\n"
                "{confidence_text}\n\n"
                "Key Intelligence Findings:\n{key_findings_text}\n\n"
                "Detailed Findings:\n{findings_text}\n\n"
                "The summary must:\n"
                "1. Open with the most critical specific finding (with data)\n"
                "2. Cover the key facts discovered across all subtopics\n"
                "3. Note the confidence level and any intelligence gaps\n"
                "4. Close with prioritized, specific recommendations\n\n"
                "Use specific names, dates, and numbers from the findings. "
                "Do NOT generalize."
            )),
        ])
        | _llm
        | StrOutputParser()
    )

    summary = summary_chain.invoke({
        "research_topic": state["research_topic"],
        "key_findings_text": key_findings_text,
        "findings_text": findings_text,
        "confidence_text": confidence_text,
    })

    return {"executive_summary": summary}


def report_node(state: InvestigationState) -> dict:
    """Generate the PDF report and persist to database."""
    print(f"\n[Report] Generating PDF report...")

    # Persist to database
    investigation_id = _ioc_store.create_investigation(
        topic=state["research_topic"],
        executive_summary=state["executive_summary"],
    )
    for finding in state["findings"]:
        _ioc_store.store_finding(investigation_id, finding)
    if state["mitre_mappings"]:
        _ioc_store.store_mitre_mappings(investigation_id, state["mitre_mappings"])
    for profile in state["actor_profiles"]:
        _ioc_store.store_threat_actor(profile)
        _ioc_store.build_relationships_from_profile(profile, investigation_id)
    for result in state.get("enrichment_summary", EnrichmentSummary()).results:
        _ioc_store.store_ioc(
            value=result.ioc_value, ioc_type=result.ioc_type,
            risk_score=result.risk_score, enrichment_data=result.sources,
        )

    # Generate PDF
    enrichment = state.get("enrichment_summary", EnrichmentSummary())
    report_path = _report_generator.create_report(
        title=f"Threat Intelligence: {state['research_topic']}",
        findings=state["findings"],
        executive_summary=state["executive_summary"],
        mitre_mappings=state["mitre_mappings"],
        threat_actor_profiles=state["actor_profiles"] or None,
        enrichment_summary=enrichment if enrichment.results else None,
        framework_analysis=state.get("framework_analysis"),
    )

    # Update investigation with report path
    _ioc_store.create_investigation(
        topic=state["research_topic"], report_path=report_path
    )

    stats = _ioc_store.get_graph_summary()
    print(f"\n[Database] Knowledge graph: {stats['total_iocs']} IOCs, "
          f"{stats['total_threat_actors']} actors, "
          f"{stats['total_relationships']} relationships")
    print(f"\n[Done] Report saved: {report_path}")

    return {"report_path": report_path}


# ── Build the LangGraph ──

def build_investigation_graph() -> StateGraph:
    """
    Construct the investigation workflow as a LangGraph state machine.

    Flow:
        plan → research → mitre_map → profile_actors → enrich_iocs
             → framework_analysis → executive_summary → generate_report → END
    """
    graph = StateGraph(InvestigationState)

    graph.add_node("plan", plan_node)
    graph.add_node("research", research_node)
    graph.add_node("mitre_map", mitre_node)
    graph.add_node("profile_actors", actor_node)
    graph.add_node("enrich_iocs", enrich_node)
    graph.add_node("framework_analysis", framework_node)
    graph.add_node("executive_summary", summary_node)
    graph.add_node("generate_report", report_node)

    graph.set_entry_point("plan")
    graph.add_edge("plan", "research")
    graph.add_edge("research", "mitre_map")
    graph.add_edge("mitre_map", "profile_actors")
    graph.add_edge("profile_actors", "enrich_iocs")
    graph.add_edge("enrich_iocs", "framework_analysis")
    graph.add_edge("framework_analysis", "executive_summary")
    graph.add_edge("executive_summary", "generate_report")
    graph.add_edge("generate_report", END)

    return graph


# ── Public API ──

class CoordinatorAgent:
    """
    Main interface for running CTI investigations.

    Wraps the LangGraph workflow for backward compatibility with the CLI.
    """

    def __init__(self):
        _init_agents()
        self.graph = build_investigation_graph().compile()

    def investigate(self, research_topic: str) -> str:
        """Run a full investigation and return the report path."""
        result = self.graph.invoke({
            "research_topic": research_topic,
            "subtopics": [],
            "queries": {},
            "findings": [],
            "all_sources": [],
            "mitre_mappings": [],
            "actor_profiles": [],
            "enrichment_summary": EnrichmentSummary(),
            "framework_analysis": None,
            "executive_summary": "",
            "report_path": "",
        })
        return result["report_path"]

    def check_feeds(self, keyword: Optional[str] = None) -> dict:
        """Check threat intel feeds for recent alerts and CVEs."""
        print("\n[Feed Monitor] Checking threat intelligence feeds...")
        alerts = _feed_monitor.check_all_feeds(max_per_feed=5)
        print(f"   Found {len(alerts)} alerts from RSS feeds")
        cves = _feed_monitor.check_cve_feed(keyword=keyword, days_back=7)
        print(f"   Found {len(cves)} recent CVEs" +
              (f" matching '{keyword}'" if keyword else ""))
        return {"alerts": alerts, "cves": cves}

    def export_stix(self, findings: List[ResearchFinding]) -> dict:
        """Export all IOCs from findings as a STIX 2.1 bundle."""
        merged = IOCResults()
        for f in findings:
            merged.ipv4_addresses = list(set(merged.ipv4_addresses + f.iocs.ipv4_addresses))
            merged.domains = list(set(merged.domains + f.iocs.domains))
            merged.md5_hashes = list(set(merged.md5_hashes + f.iocs.md5_hashes))
            merged.sha256_hashes = list(set(merged.sha256_hashes + f.iocs.sha256_hashes))
            merged.cve_ids = list(set(merged.cve_ids + f.iocs.cve_ids))
            merged.urls = list(set(merged.urls + f.iocs.urls))
            merged.malware_names = list(set(merged.malware_names + f.iocs.malware_names))
        return merged.to_stix_bundle()


def main():
    """CLI entry point."""
    coordinator = CoordinatorAgent()

    print("\n CTI Research System")
    print("=" * 50)
    print("Commands:")
    print("  [topic]     - Investigate a research topic")
    print("  feeds       - Check threat intel feeds")
    print("  feeds:word  - Check feeds filtered by keyword")
    print("  stats       - Show knowledge graph stats")
    print("  exit        - Quit")
    print("=" * 50)

    while True:
        user_input = input("\nEnter command: ").strip()

        if not user_input:
            continue

        if user_input.lower() in ['exit', 'quit']:
            print("Exiting. Goodbye!")
            break

        if user_input.lower() == 'stats':
            stats = _ioc_store.get_graph_summary()
            print("\n Knowledge Graph Statistics:")
            for key, value in stats.items():
                print(f"  {key.replace('_', ' ').title()}: {value}")
            continue

        if user_input.lower().startswith('feeds'):
            keyword = None
            if ':' in user_input:
                keyword = user_input.split(':', 1)[1].strip()
            result = coordinator.check_feeds(keyword=keyword)
            print(f"\n Feed Alerts ({len(result['alerts'])}):")
            for alert in result['alerts'][:10]:
                print(f"  [{alert.source}] {alert.title}")
            print(f"\n Recent CVEs ({len(result['cves'])}):")
            for cve in result['cves'][:10]:
                print(f"  {cve.cve_id} (CVSS: {cve.cvss_score}) - {cve.description[:80]}...")
            continue

        report_path = coordinator.investigate(user_input)
        print(f"\n Investigation complete! Report: {report_path}")


if __name__ == "__main__":
    main()
