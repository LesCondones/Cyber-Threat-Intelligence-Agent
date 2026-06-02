"""
Streamlit Frontend for CTI Agent

Web interface for running investigations, monitoring threat feeds,
and browsing the knowledge base. Launch with: streamlit run app.py
"""

import io
import json
import os
import sys
import time
import threading
from datetime import datetime
from pathlib import Path

import streamlit as st

# ── Page Config (must be first Streamlit call) ──
st.set_page_config(
    page_title="CTI Agent",
    page_icon="\U0001f6e1\ufe0f",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ── Resource Caching ──

@st.cache_resource
def get_coordinator():
    """Initialize CoordinatorAgent once across all sessions."""
    from main import CoordinatorAgent
    return CoordinatorAgent()


@st.cache_resource
def get_ioc_store():
    """Initialize IOCStore once across all sessions."""
    from database.ioc_store import IOCStore
    return IOCStore()


@st.cache_resource
def get_vector_store():
    """Initialize VectorStore once across all sessions. Returns None if unavailable."""
    try:
        from database.vector_store import VectorStore
        from config import settings
        return VectorStore(
            persist_dir=settings.vector_db_path,
            model_name=settings.embedding_model,
        )
    except Exception as e:
        # Vector store is optional — page should still render without it
        print(f"[Vector] Streamlit init failed: {e}")
        return None


# ── Thread-Safe Log Capture ──

class ThreadSafeLogCapture(io.StringIO):
    """Captures stdout in the worker thread, appending lines to a shared list."""

    def __init__(self, log_lines: list):
        super().__init__()
        self._log_lines = log_lines
        self._original_stdout = sys.stdout

    def write(self, text: str):
        self._original_stdout.write(text)
        if text.strip():
            self._log_lines.append(text.strip())
        return len(text)

    def flush(self):
        self._original_stdout.flush()


def _detect_stage(log_lines: list) -> tuple[str, float]:
    """Parse log lines to determine investigation stage and progress."""
    stages = [
        ("[Plan]", "Planning investigation...", 0.05),
        ("SubAgent", "Researching subtopics...", 0.15),
        ("Searching with", "Running search queries...", 0.25),
        ("severity=", "Analyzing findings...", 0.35),
        ("[MITRE]", "Mapping to MITRE ATT&CK...", 0.50),
        ("[Profiler]", "Profiling threat actors...", 0.60),
        ("[Enrichment]", "Enriching IOCs...", 0.70),
        ("[Frameworks]", "Applying CTI frameworks...", 0.80),
        ("[Summary]", "Generating executive summary...", 0.90),
        ("[Report]", "Generating PDF report...", 0.95),
        ("[Done]", "Investigation complete!", 1.0),
    ]
    current_label = "Starting..."
    current_progress = 0.0
    for line in log_lines:
        for prefix, label, progress in stages:
            if prefix in line:
                current_label = label
                current_progress = progress
    return current_label, current_progress


def run_investigation_thread(topic: str, coordinator, shared: dict):
    """Run investigation in a background thread.

    Uses a plain dict (not st.session_state) because Streamlit's session
    state proxy requires a ScriptRunContext that doesn't exist in
    background threads.
    """
    log_lines = shared["log_lines"]
    capture = ThreadSafeLogCapture(log_lines)
    old_stdout = sys.stdout
    try:
        sys.stdout = capture
        report_path = coordinator.investigate(topic)
        shared["investigation_result"] = report_path
    except Exception as e:
        shared["investigation_error"] = str(e)
    finally:
        sys.stdout = old_stdout
        shared["investigation_running"] = False


# ── Session State Init ──

def _init_session_state():
    defaults = {
        "log_lines": [],
        "investigation_running": False,
        "investigation_result": None,
        "investigation_error": None,
        "shared_investigation": None,
        "feed_results": None,
        "feed_loading": False,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


_init_session_state()


# ── Sidebar ──

def render_sidebar():
    with st.sidebar:
        st.title("\U0001f6e1\ufe0f CTI Agent")
        page = st.radio(
            "Navigation",
            ["Investigation", "Feed Monitor", "Knowledge Base"],
            label_visibility="collapsed",
        )

        st.divider()

        # LLM Config Display
        from config import settings
        st.caption("LLM Configuration")
        st.text("Provider: ANTHROPIC")
        st.text(f"Model: {settings.anthropic_model}")

        st.divider()

        # API Key Status
        st.caption("API Keys")
        keys = {
            "Tavily": bool(settings.tavily_api_key),
            "Anthropic": bool(settings.anthropic_api_key),
            "VirusTotal": bool(settings.virustotal_api_key),
            "Shodan": bool(settings.shodan_api_key),
            "AbuseIPDB": bool(settings.abuseipdb_api_key),
        }
        for name, configured in keys.items():
            icon = "\u2705" if configured else "\u274c"
            st.text(f"{icon} {name}")

        st.divider()

        # Database Stats
        st.caption("Knowledge Base")
        try:
            store = get_ioc_store()
            stats = store.get_graph_summary()
            st.text(f"Investigations: {stats['total_investigations']}")
            st.text(f"IOCs: {stats['total_iocs']}")
            st.text(f"Threat Actors: {stats['total_threat_actors']}")
        except Exception:
            st.text("Database unavailable")

    return page


# ── Page 1: Investigation ──

def page_investigation():
    st.header("Threat Intelligence Investigation")
    st.caption("Enter a topic to run a full CTI investigation pipeline")

    topic = st.text_input(
        "Research Topic",
        placeholder="e.g., APT groups targeting financial institutions",
        disabled=st.session_state.investigation_running,
    )

    col1, col2 = st.columns([1, 5])
    with col1:
        run_btn = st.button(
            "Run Investigation",
            type="primary",
            disabled=st.session_state.investigation_running or not topic,
        )
    with col2:
        if st.session_state.investigation_running:
            st.info("Investigation in progress...")

    # Start investigation
    if run_btn and topic:
        # Plain dict shared with the background thread (avoids
        # Streamlit's ScriptRunContext requirement).
        shared = {
            "log_lines": [],
            "investigation_running": True,
            "investigation_result": None,
            "investigation_error": None,
        }
        st.session_state.shared_investigation = shared
        st.session_state.log_lines = shared["log_lines"]
        st.session_state.investigation_running = True
        st.session_state.investigation_result = None
        st.session_state.investigation_error = None

        coordinator = get_coordinator()
        thread = threading.Thread(
            target=run_investigation_thread,
            args=(topic, coordinator, shared),
            daemon=True,
        )
        thread.start()
        st.rerun()

    # Sync shared dict back into session_state each rerun
    shared = st.session_state.get("shared_investigation")
    if shared is not None:
        st.session_state.log_lines = shared["log_lines"]
        st.session_state.investigation_running = shared["investigation_running"]
        if shared["investigation_result"] is not None:
            st.session_state.investigation_result = shared["investigation_result"]
        if shared["investigation_error"] is not None:
            st.session_state.investigation_error = shared["investigation_error"]
        # Clean up shared dict once investigation is done
        if not shared["investigation_running"]:
            del st.session_state.shared_investigation

    # Progress display while running
    if st.session_state.investigation_running:
        log_lines = st.session_state.log_lines
        stage_label, progress = _detect_stage(log_lines)

        st.progress(progress, text=stage_label)

        with st.status("Investigation Logs", expanded=True):
            # Show last 30 log lines
            for line in log_lines[-30:]:
                st.text(line)

        # Poll for completion
        time.sleep(2)
        st.rerun()

    # Show result
    if st.session_state.investigation_result:
        report_path = st.session_state.investigation_result
        st.success(f"Investigation complete! Report: {report_path}")

        # Show last logs
        with st.expander("Investigation Logs", expanded=False):
            for line in st.session_state.log_lines:
                st.text(line)

        # Download button
        report_file = Path(report_path)
        if report_file.exists():
            with open(report_file, "rb") as f:
                st.download_button(
                    label="Download Report (PDF)",
                    data=f.read(),
                    file_name=report_file.name,
                    mime="application/pdf",
                )

    # Show error
    if st.session_state.investigation_error:
        st.error(f"Investigation failed: {st.session_state.investigation_error}")
        with st.expander("Investigation Logs", expanded=True):
            for line in st.session_state.log_lines:
                st.text(line)


# ── Page 2: Feed Monitor ──

def page_feed_monitor():
    st.header("Threat Intelligence Feed Monitor")
    st.caption("Check live threat feeds and recent CVEs")

    col1, col2 = st.columns([3, 1])
    with col1:
        keyword = st.text_input(
            "Keyword Filter (optional)",
            placeholder="e.g., ransomware, apache, zero-day",
        )
    with col2:
        st.write("")  # spacing
        st.write("")
        check_btn = st.button("Check Feeds", type="primary")

    if check_btn:
        with st.spinner("Fetching threat intelligence feeds..."):
            coordinator = get_coordinator()
            kw = keyword.strip() if keyword.strip() else None
            results = coordinator.check_feeds(keyword=kw)
            st.session_state.feed_results = results

    results = st.session_state.feed_results
    if results is None:
        st.info("Click 'Check Feeds' to fetch the latest threat intelligence.")
        return

    alerts = results.get("alerts", [])
    cves = results.get("cves", [])

    col_alerts, col_cves = st.columns(2)

    # Feed Alerts
    with col_alerts:
        st.subheader(f"Feed Alerts ({len(alerts)})")
        if not alerts:
            st.info("No alerts found.")
        for alert in alerts:
            severity_color = {
                "CRITICAL": "red", "HIGH": "orange",
                "MEDIUM": "blue", "LOW": "green",
            }.get(alert.severity.upper(), "gray")

            with st.expander(f"[{alert.source}] {alert.title[:80]}"):
                if alert.severity != "Unknown":
                    st.markdown(f"**Severity:** :{severity_color}[{alert.severity}]")
                st.markdown(f"**Source:** {alert.source}")
                if alert.published:
                    st.markdown(f"**Published:** {alert.published}")
                st.markdown(alert.description[:500])
                if alert.link:
                    st.markdown(f"[Read more]({alert.link})")
                if alert.cve_ids:
                    st.markdown(f"**CVEs:** {', '.join(alert.cve_ids)}")

    # CVEs
    with col_cves:
        st.subheader(f"Recent CVEs ({len(cves)})")
        if not cves:
            st.info("No CVEs found.")
        for cve in cves:
            score = cve.cvss_score
            if score >= 9.0:
                sev_color = "red"
            elif score >= 7.0:
                sev_color = "orange"
            elif score >= 4.0:
                sev_color = "blue"
            else:
                sev_color = "green"

            with st.expander(f"{cve.cve_id} (CVSS: {score})"):
                st.markdown(f"**Severity:** :{sev_color}[{cve.severity}] | **CVSS:** {score}")
                if cve.published:
                    st.markdown(f"**Published:** {cve.published}")
                st.markdown(cve.description[:500])
                if cve.affected_products:
                    st.markdown(f"**Affected:** {', '.join(cve.affected_products[:5])}")
                if cve.references:
                    st.markdown("**References:**")
                    for ref in cve.references[:3]:
                        st.markdown(f"- {ref}")


# ── Page 3: Knowledge Base ──

def page_knowledge_base():
    st.header("Knowledge Base")
    st.caption("Browse stored investigations, threat actors, and IOCs")

    store = get_ioc_store()
    stats = store.get_graph_summary()
    vstore = get_vector_store()

    # Metric cards
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Investigations", stats["total_investigations"])
    m2.metric("IOCs", stats["total_iocs"])
    m3.metric("Threat Actors", stats["total_threat_actors"])
    m4.metric("Relationships", stats["total_relationships"])

    # ── Semantic Search ──
    st.subheader("Semantic Search")
    if vstore is None:
        st.warning(
            "Vector store unavailable — install dependencies with `uv sync` "
            "to enable semantic search."
        )
    else:
        total = vstore.count()
        st.caption(f"{total} indexed documents (findings, summaries, actors, "
                   "recommendations, detection rules)")
        sc1, sc2 = st.columns([4, 1])
        with sc1:
            query = st.text_input(
                "Search stored intelligence",
                placeholder="e.g., ransomware affiliates targeting healthcare",
                key="semantic_query",
            )
        with sc2:
            type_filter = st.selectbox(
                "Type",
                ["All", "finding", "summary", "actor", "recommendation", "detection"],
                key="semantic_type_filter",
            )

        if query and query.strip():
            types = None if type_filter == "All" else [type_filter]
            hits = vstore.search(query, k=10, types=types)
            if not hits:
                st.info("No matching documents.")
            else:
                for hit in hits:
                    topic = hit.metadata.get("topic") or hit.metadata.get("actor_name") or ""
                    label = f"[{hit.type}] {topic} — score {hit.score:.3f}"
                    with st.expander(label):
                        st.markdown(f"**ID:** `{hit.id}`")
                        meta_pairs = [
                            f"**{k}:** {v}" for k, v in hit.metadata.items()
                            if k not in ("topic", "actor_name")
                        ]
                        if meta_pairs:
                            st.caption(" | ".join(meta_pairs))
                        st.markdown(hit.text[:2000])

    st.divider()

    # Tabs
    tab_inv, tab_actors, tab_iocs = st.tabs([
        "Investigations", "Threat Actors", "High-Risk IOCs"
    ])

    # ── Investigations Tab ──
    with tab_inv:
        investigations = store.get_investigations(limit=20)
        if not investigations:
            st.info("No investigations yet. Run one from the Investigation page.")
        else:
            for inv in investigations:
                with st.expander(
                    f"{inv['topic']} — {inv['created_at'][:10]}"
                ):
                    if inv.get("executive_summary"):
                        st.markdown(inv["executive_summary"][:1000])
                    if inv.get("report_path") and Path(inv["report_path"]).exists():
                        with open(inv["report_path"], "rb") as f:
                            st.download_button(
                                label="Download Report",
                                data=f.read(),
                                file_name=Path(inv["report_path"]).name,
                                mime="application/pdf",
                                key=f"dl_inv_{inv['id']}",
                            )

    # ── Threat Actors Tab ──
    with tab_actors:
        actors = store.get_threat_actors()
        if not actors:
            st.info("No threat actors profiled yet.")
        else:
            for actor in actors:
                with st.expander(f"{actor['name']}"):
                    cols = st.columns(2)
                    with cols[0]:
                        st.markdown(f"**Motivation:** {actor.get('motivation', 'Unknown')}")
                        st.markdown(f"**Sophistication:** {actor.get('sophistication', 'Unknown')}")
                        if actor.get("first_seen"):
                            st.markdown(f"**First Seen:** {actor['first_seen']}")
                    with cols[1]:
                        aliases = actor.get("aliases", [])
                        if aliases:
                            st.markdown(f"**Aliases:** {', '.join(aliases)}")
                        targets = actor.get("primary_targets", [])
                        if targets:
                            st.markdown(f"**Targets:** {', '.join(targets)}")
                        regions = actor.get("target_regions", [])
                        if regions:
                            st.markdown(f"**Regions:** {', '.join(regions)}")

                    if actor.get("description"):
                        st.markdown("---")
                        st.markdown(actor["description"][:1000])

                    techniques = actor.get("techniques", [])
                    if techniques:
                        st.markdown(f"**Techniques:** {', '.join(techniques)}")
                    malware = actor.get("malware_used", [])
                    if malware:
                        st.markdown(f"**Malware:** {', '.join(malware)}")
                    campaigns = actor.get("associated_campaigns", [])
                    if campaigns:
                        st.markdown(f"**Campaigns:** {', '.join(campaigns)}")

    # ── High-Risk IOCs Tab ──
    with tab_iocs:
        min_score = st.slider(
            "Minimum Risk Score", 0, 100, 50, step=5
        )
        iocs = store.get_high_risk_iocs(min_score=min_score)
        if not iocs:
            st.info(f"No IOCs with risk score >= {min_score}.")
        else:
            st.markdown(f"**{len(iocs)} IOCs** with risk score >= {min_score}")
            # Build table data
            table_data = []
            for ioc in iocs:
                table_data.append({
                    "Value": ioc["value"],
                    "Type": ioc["type"],
                    "Risk Score": ioc["risk_score"],
                    "First Seen": ioc.get("first_seen", ""),
                    "Last Seen": ioc.get("last_seen", ""),
                })
            st.dataframe(table_data, use_container_width=True)

            # Detailed view
            for ioc in iocs[:20]:
                enrichment = ioc.get("enrichment_data")
                if enrichment:
                    with st.expander(f"{ioc['value']} ({ioc['type']}) — Score: {ioc['risk_score']}"):
                        if isinstance(enrichment, str):
                            try:
                                enrichment = json.loads(enrichment)
                            except json.JSONDecodeError:
                                pass
                        st.json(enrichment)


# ── Main ──

def main():
    page = render_sidebar()
    if page == "Investigation":
        page_investigation()
    elif page == "Feed Monitor":
        page_feed_monitor()
    elif page == "Knowledge Base":
        page_knowledge_base()


if __name__ == "__main__":
    main()
