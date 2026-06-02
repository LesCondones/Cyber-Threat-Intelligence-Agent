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
from langgraph.graph import StateGraph, END

from agents.subagent import SubAgent, ResearchFinding
from agents.mitre_mapper import MITREMapper
from agents.enrichment_agent import EnrichmentAgent, EnrichmentSummary
from agents.threat_actor_profiler import ThreatActorProfiler
from agents.framework_analyst import FrameworkAnalyst
from agents.feed_monitor import FeedMonitor
from agents.ioc_extractor import IOCResults
from agents.recommendations_generator import RecommendationsGenerator, Recommendation
from agents.detection_logic_generator import DetectionLogicGenerator, DetectionLogic
from reports.generator import ReportGenerator
from database.ioc_store import IOCStore
from database.vector_store import VectorStore, SearchHit
from config import get_llm, settings


# ── Pydantic Models for Structured Output ──

class InvestigationPlan(BaseModel):
    """Planning output: subtopics and targeted queries."""
    subtopics: List[str] = Field(description="3-5 focused, topic-specific subtopics for investigation")
    queries: dict[str, List[str]] = Field(
        description="For each subtopic, 3 targeted search queries"
    )


class ExecutiveSummaryOutput(BaseModel):
    """Structured executive summary with TL;DR + threat status alongside prose."""
    tldr_bullets: List[str] = Field(
        description="2-4 sharp, executive-facing TL;DR bullets covering "
                    "the most critical specific findings with concrete data."
    )
    threat_status: str = Field(
        description="One of: Active, Historical, Anticipated. "
                    "Active = ongoing campaign/exploitation; Historical = past "
                    "incident with current relevance; Anticipated = emerging risk "
                    "not yet observed in the wild."
    )
    executive_summary: str = Field(
        description="3-5 paragraph plain-text executive summary grounded in the "
                    "specific findings. Open with the most critical finding; cover "
                    "key facts; note confidence level; close with prioritized "
                    "recommendations. No markdown, no generic advice."
    )


# ── LangGraph State ──

class InvestigationState(TypedDict):
    research_topic: str
    subtopics: list[str]
    queries: dict[str, list[str]]
    findings: list  # List[ResearchFinding]
    all_sources: list  # List[(title, url, content)]
    mitre_mappings: list
    actor_profiles: list  # List[ThreatActorProfile]
    enrichment_summary: Any  # EnrichmentSummary
    framework_analysis: Any  # FrameworkAnalysis
    executive_summary: str
    tldr_bullets: list[str]
    threat_status: str
    recommendations: list  # List[Recommendation]
    detection_logic: Any  # DetectionLogic
    report_path: str


# ── Shared Agent Instances ──
# Created once, reused across nodes to avoid re-initialization

_llm = None
_mitre_mapper = None
_enrichment_agent = None
_threat_actor_profiler = None
_framework_analyst = None
_recommendations_generator = None
_detection_logic_generator = None
_report_generator = None
_ioc_store = None
_vector_store = None
_feed_monitor = None


def _init_agents():
    """Initialize all agents (called once at startup)."""
    global _llm, _mitre_mapper, _enrichment_agent, _threat_actor_profiler
    global _framework_analyst, _recommendations_generator, _detection_logic_generator
    global _report_generator, _ioc_store, _vector_store, _feed_monitor

    _llm = get_llm()
    _mitre_mapper = MITREMapper(_llm)
    _enrichment_agent = EnrichmentAgent(
        virustotal_api_key=settings.virustotal_api_key,
        shodan_api_key=settings.shodan_api_key,
        abuseipdb_api_key=settings.abuseipdb_api_key,
    )
    _threat_actor_profiler = ThreatActorProfiler(_llm)
    _framework_analyst = FrameworkAnalyst(_llm)
    _recommendations_generator = RecommendationsGenerator(_llm)
    _detection_logic_generator = DetectionLogicGenerator(_llm)
    _report_generator = ReportGenerator()
    _ioc_store = IOCStore()
    try:
        _vector_store = VectorStore(
            persist_dir=settings.vector_db_path,
            model_name=settings.embedding_model,
        )
    except Exception as e:
        print(f"[Vector] init failed (semantic search disabled): {e}")
        _vector_store = None
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
    """Map findings to MITRE ATT&CK using real technique data.

    Combines all findings into a single analysis string and runs the
    mapper once — one LLM call instead of one-per-finding. The mapper
    already deduplicates its own output.
    """
    print(f"\n[MITRE] Mapping to MITRE ATT&CK framework...")
    combined_analysis = "\n\n".join(
        f"[{f.topic}]\n{f.analysis}" for f in state["findings"] if f.analysis
    )

    if not combined_analysis:
        print("   No analysis content to map")
        return {"mitre_mappings": []}

    mappings = _mitre_mapper.map_techniques(combined_analysis)
    print(f"   {len(mappings)} unique technique mappings")
    return {"mitre_mappings": mappings}


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
    """Generate executive summary + TL;DR bullets + threat status in one call."""
    print(f"\n[Summary] Generating executive summary, TL;DR, threat status...")

    all_key_findings = []
    for f in state["findings"]:
        for kf in f.key_findings:
            all_key_findings.append(f"- {kf.finding} (Source: {kf.source_title})")
    key_findings_text = "\n".join(all_key_findings[:15]) if all_key_findings else "None extracted"

    findings_text = "\n\n".join(
        f"[{f.topic}] (Severity: {f.severity})\n{f.analysis[:800]}"
        for f in state["findings"]
    )

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
                "You are a senior threat intelligence analyst writing the "
                "audience-aligned opener for a CTI report. Ground every output "
                "in the specific findings below. No generic cybersecurity "
                "advice. No markdown formatting in the prose summary."
            )),
            ("human", (
                "For this investigation, produce a structured output with three parts.\n\n"
                "Research Topic: {research_topic}\n"
                "{confidence_text}\n\n"
                "Key Intelligence Findings:\n{key_findings_text}\n\n"
                "Detailed Findings:\n{findings_text}\n\n"
                "Part 1 — TL;DR Bullets (executive-facing): 2-4 sharp bullets, "
                "each ONE sentence, opening with the most critical finding and "
                "including specific data (CVE IDs, organization counts, dates, "
                "actor names). No filler.\n\n"
                "Part 2 — Threat Status: classify as Active (ongoing campaign or "
                "exploitation), Historical (past incident with current relevance "
                "to defenders), or Anticipated (emerging risk, not yet observed "
                "in the wild).\n\n"
                "Part 3 — Executive Summary: 3-5 paragraphs of plain text. Open "
                "with the most critical specific finding; cover key facts across "
                "subtopics; note confidence level and intelligence gaps; close "
                "with prioritized recommendations. Use specific names, dates, "
                "and numbers from the findings."
            )),
        ])
        | _llm.with_structured_output(ExecutiveSummaryOutput)
    )

    try:
        result = summary_chain.invoke({
            "research_topic": state["research_topic"],
            "key_findings_text": key_findings_text,
            "findings_text": findings_text,
            "confidence_text": confidence_text,
        })
        return {
            "executive_summary": result.executive_summary,
            "tldr_bullets": result.tldr_bullets,
            "threat_status": result.threat_status,
        }
    except Exception as e:
        print(f"   Summary structured output failed ({e}), using fallback")
        return {
            "executive_summary": "",
            "tldr_bullets": [],
            "threat_status": "Unknown",
        }


def recommendations_node(state: InvestigationState) -> dict:
    """Generate prioritized, actionable recommendations."""
    print(f"\n[Recommendations] Generating prioritized recommendations...")
    recs = _recommendations_generator.generate(
        research_topic=state["research_topic"],
        findings=state["findings"],
        mitre_mappings=state.get("mitre_mappings"),
        enrichment_summary=state.get("enrichment_summary"),
    )
    print(f"   {len(recs)} recommendations generated")
    return {"recommendations": recs}


def detection_logic_node(state: InvestigationState) -> dict:
    """Generate Sigma rules, YARA rules, and SIEM hunt queries."""
    print(f"\n[Detection] Generating detection logic (Sigma / YARA / SIEM)...")

    # Merge IOCs across findings for the detection generator
    merged = IOCResults()
    for f in state["findings"]:
        merged.ipv4_addresses = list(set(merged.ipv4_addresses + f.iocs.ipv4_addresses))
        merged.domains = list(set(merged.domains + f.iocs.domains))
        merged.md5_hashes = list(set(merged.md5_hashes + f.iocs.md5_hashes))
        merged.sha256_hashes = list(set(merged.sha256_hashes + f.iocs.sha256_hashes))
        merged.cve_ids = list(set(merged.cve_ids + f.iocs.cve_ids))
        merged.urls = list(set(merged.urls + f.iocs.urls))
        merged.malware_names = list(set(merged.malware_names + f.iocs.malware_names))

    detection = _detection_logic_generator.generate(
        research_topic=state["research_topic"],
        mitre_mappings=state.get("mitre_mappings"),
        iocs=merged,
        threat_actor_profiles=state.get("actor_profiles"),
    )
    counts = (
        f"sigma={len(detection.sigma_rules)} "
        f"yara={len(detection.yara_rules)} "
        f"splunk={len(detection.splunk_queries)} "
        f"kql={len(detection.kql_queries)}"
    )
    print(f"   {counts}")
    return {"detection_logic": detection}


def report_node(state: InvestigationState) -> dict:
    """Generate the PDF report and persist findings to the database."""
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

    # Vector indexing — index long-form text for semantic search.
    # Failures must never block the PDF report.
    if _vector_store is not None:
        try:
            topic = state["research_topic"]
            indexed = 0
            if state.get("executive_summary"):
                _vector_store.upsert_executive_summary(
                    investigation_id, topic, state["executive_summary"]
                )
                indexed += 1
            for i, finding in enumerate(state["findings"]):
                _vector_store.upsert_finding(investigation_id, topic, finding, i)
                indexed += 1
            for profile in state["actor_profiles"]:
                _vector_store.upsert_threat_actor(profile)
                indexed += 1
            for i, rec in enumerate(state.get("recommendations") or []):
                _vector_store.upsert_recommendation(investigation_id, topic, rec, i)
                indexed += 1
            detection = state.get("detection_logic")
            if detection:
                for i, rule in enumerate(getattr(detection, "sigma_rules", []) or []):
                    _vector_store.upsert_detection_rule(investigation_id, topic, "sigma", rule, i)
                    indexed += 1
                for i, rule in enumerate(getattr(detection, "yara_rules", []) or []):
                    _vector_store.upsert_detection_rule(investigation_id, topic, "yara", rule, i)
                    indexed += 1
                for i, rule in enumerate(getattr(detection, "splunk_queries", []) or []):
                    _vector_store.upsert_detection_rule(investigation_id, topic, "splunk", rule, i)
                    indexed += 1
                for i, rule in enumerate(getattr(detection, "kql_queries", []) or []):
                    _vector_store.upsert_detection_rule(investigation_id, topic, "kql", rule, i)
                    indexed += 1
            print(f"[Vector] indexed {indexed} docs (total in store: {_vector_store.count()})")
        except Exception as e:
            print(f"[Vector] indexing failed (continuing): {e}")

    enrichment = state.get("enrichment_summary", EnrichmentSummary())
    report_path = _report_generator.create_report(
        title=f"Threat Intelligence: {state['research_topic']}",
        findings=state["findings"],
        executive_summary=state["executive_summary"],
        mitre_mappings=state["mitre_mappings"],
        threat_actor_profiles=state["actor_profiles"] or None,
        enrichment_summary=enrichment if enrichment.results else None,
        framework_analysis=state.get("framework_analysis"),
        tldr_bullets=state.get("tldr_bullets"),
        threat_status=state.get("threat_status"),
        recommendations=state.get("recommendations"),
        detection_logic=state.get("detection_logic"),
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
             → framework_analysis → recommendations → detection_logic
             → executive_summary → generate_report → END
    """
    graph = StateGraph(InvestigationState)

    graph.add_node("plan", plan_node)
    graph.add_node("research", research_node)
    graph.add_node("mitre_map", mitre_node)
    graph.add_node("profile_actors", actor_node)
    graph.add_node("enrich_iocs", enrich_node)
    graph.add_node("framework_analysis", framework_node)
    graph.add_node("recommendations", recommendations_node)
    graph.add_node("detection_logic", detection_logic_node)
    graph.add_node("executive_summary", summary_node)
    graph.add_node("generate_report", report_node)

    graph.set_entry_point("plan")
    graph.add_edge("plan", "research")
    graph.add_edge("research", "mitre_map")
    graph.add_edge("mitre_map", "profile_actors")
    graph.add_edge("profile_actors", "enrich_iocs")
    graph.add_edge("enrich_iocs", "framework_analysis")
    graph.add_edge("framework_analysis", "recommendations")
    graph.add_edge("recommendations", "detection_logic")
    graph.add_edge("detection_logic", "executive_summary")
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
            "tldr_bullets": [],
            "threat_status": "Unknown",
            "recommendations": [],
            "detection_logic": None,
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

    def semantic_search(
        self,
        query: str,
        k: int = 10,
        types: Optional[List[str]] = None,
    ) -> List[SearchHit]:
        """Semantic search across indexed CTI artifacts.

        ``types`` optionally restricts results to one or more of:
        finding, summary, actor, recommendation, detection.
        Returns an empty list if the vector store failed to initialize.
        """
        if _vector_store is None:
            return []
        return _vector_store.search(query, k=k, types=types)


def main():
    """CLI entry point."""
    coordinator = CoordinatorAgent()

    print("\n CTI Research System")
    print("=" * 50)
    print("Commands:")
    print("  [topic]          - Investigate a research topic")
    print("  feeds            - Check threat intel feeds")
    print("  feeds:word       - Check feeds filtered by keyword")
    print("  search <query>   - Semantic search of stored intel")
    print("                     (optional --type=finding|summary|actor|")
    print("                      recommendation|detection)")
    print("  stats            - Show knowledge graph stats")
    print("  exit             - Quit")
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

        if user_input.lower().startswith('search '):
            # Parse: search <query...> [--type=<t>]
            raw = user_input[len('search '):].strip()
            type_filter: Optional[List[str]] = None
            tokens = []
            for tok in raw.split():
                if tok.startswith('--type='):
                    type_filter = [tok.split('=', 1)[1].strip()]
                else:
                    tokens.append(tok)
            query = ' '.join(tokens).strip()
            if not query:
                print("Usage: search <query> [--type=finding|summary|actor|recommendation|detection]")
                continue
            hits = coordinator.semantic_search(query, k=10, types=type_filter)
            if not hits:
                print(f"\n No results for '{query}'.")
                continue
            print(f"\n {len(hits)} hits for '{query}':")
            for hit in hits:
                topic = hit.metadata.get('topic') or hit.metadata.get('actor_name') or ''
                snippet = hit.text.replace('\n', ' ')[:160]
                print(f"  [{hit.type:13s}] score={hit.score:.3f}  {topic}")
                print(f"                  {snippet}{'...' if len(hit.text) > 160 else ''}")
            continue

        report_path = coordinator.investigate(user_input)
        print(f"\n Investigation complete! Report: {report_path}")


if __name__ == "__main__":
    main()
