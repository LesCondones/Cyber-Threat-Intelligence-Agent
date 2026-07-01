# Deep Agents: Cyber Threat Intelligence

A multi-agent system built on **LangGraph** that researches a threat topic end to end and produces a single, self-contained PDF intelligence report. It runs concurrent source-grounded research, extracts and enriches IOCs, profiles threat actors, maps findings to MITRE ATT&CK, applies classic CTI frameworks (Diamond Model, Cyber Kill Chain, Admiralty grading), generates prioritized recommendations and deployable detection logic, and persists everything to a SQLite knowledge graph plus a local Chroma vector store for semantic recall.

## Architecture

```
User Input (Research Topic)
    |
CoordinatorAgent.investigate()
    |
    LangGraph State Machine:
    |
    plan ──► research ──► mitre_map ──► profile_actors ──► enrich_iocs
                                                                |
                                                       framework_analysis
                                                                |
    generate_report ◄── executive_summary ◄── detection_logic ◄── recommendations
         |
         +── IOCStore.persist()        ──► SQLite knowledge graph
         +── VectorStore.upsert()       ──► Chroma (semantic search index)
         +── ReportGenerator.create_report() ──► PDF (single deliverable)
```

The PDF is the **only** report artifact — there are no STIX/CSV/rule side files. All
rendered detection content and consolidated IOCs live inside the PDF so it is
self-contained. Structured data is additionally persisted to SQLite (source of truth)
and embedded into Chroma (semantic search).

### Graph Nodes

| Node | Function | Description |
|------|----------|-------------|
| `plan` | `plan_node` | LLM breaks the topic into 3–5 specific subtopics with targeted queries |
| `research` | `research_node` | Concurrent SubAgent execution per subtopic (one merged LLM call per subtopic) |
| `mitre_map` | `mitre_node` | Maps combined findings to MITRE ATT&CK techniques in one call |
| `profile_actors` | `actor_node` | Identifies and profiles threat actor groups |
| `enrich_iocs` | `enrich_node` | VirusTotal / Shodan / AbuseIPDB reputation lookups |
| `framework_analysis` | `framework_node` | Diamond Model, Cyber Kill Chain, Admiralty confidence assessment |
| `recommendations` | `recommendations_node` | Prioritized, actionable recommendations with owner + rationale |
| `detection_logic` | `detection_logic_node` | Sigma rules, YARA rules, Splunk SPL and Microsoft KQL hunt queries |
| `executive_summary` | `summary_node` | TL;DR bullets + threat status + source-grounded executive summary |
| `generate_report` | `report_node` | PDF generation + SQLite persistence + Chroma indexing |

### Agent Components

| Agent | File | Purpose |
|-------|------|---------|
| **Coordinator** | `main.py` | LangGraph orchestration, CLI, public API |
| **SubAgent** | `agents/subagent.py` | Source-grounded research with key-findings extraction |
| **Web Searcher** | `agents/searcher.py` | Tavily API integration (with SQLite result cache) |
| **Web Scraper** | `agents/scraper.py` | LangChain WebBaseLoader for direct URL fetching |
| **IOC Extractor** | `agents/ioc_extractor.py` | Regex extraction of IPs, domains, URLs, hashes, CVEs, malware |
| **MITRE Mapper** | `agents/mitre_mapper.py` | LLM-based ATT&CK technique mapping with deduplication |
| **Enrichment Agent** | `agents/enrichment_agent.py` | VirusTotal, Shodan, AbuseIPDB lookups |
| **Threat Actor Profiler** | `agents/threat_actor_profiler.py` | LLM-based structured threat actor profiles |
| **Framework Analyst** | `agents/framework_analyst.py` | Diamond Model, Cyber Kill Chain, Admiralty confidence assessment |
| **Recommendations Generator** | `agents/recommendations_generator.py` | Prioritized, ticket-ready recommendations |
| **Detection Logic Generator** | `agents/detection_logic_generator.py` | Sigma / YARA / Splunk SPL / KQL detection content |
| **Source Classifier** | `agents/source_classifier.py` | Deterministic source-type tagging (Gov / Vendor / Research / News / Blog) |
| **Feed Monitor** | `agents/feed_monitor.py` | RSS / CVE feed ingestion |
| **IOC Store** | `database/ioc_store.py` | SQLite knowledge graph |
| **Vector Store** | `database/vector_store.py` | Chroma + sentence-transformers semantic search index |
| **Report Generator** | `reports/generator.py` | PDF report with charts, tables, framework sections |

## Setup

1. **Install dependencies**:
```bash
uv sync
```

2. **Configure environment**:
```bash
cp .env.example .env
```

3. **Add your API keys** to `.env`:
```env
TAVILY_SEARCH_API_KEY=your_key_here
ANTHROPIC_API_KEY=your_key_here

# Anthropic model (defaults to claude-sonnet-4-6)
ANTHROPIC_MODEL=claude-sonnet-4-6

# Optional enrichment keys (enrichment is skipped if not set)
VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
ABUSEIPDB_API_KEY=

# Optional semantic-search settings (safe defaults; no API key needed)
EMBEDDING_MODEL=all-MiniLM-L6-v2
VECTOR_DB_PATH=database/chroma
```

Only `TAVILY_SEARCH_API_KEY` and `ANTHROPIC_API_KEY` are required. Enrichment keys are
optional — enrichment is skipped for any provider whose key is absent. Semantic-search
embeddings run locally and need no key.

## Usage

### Run the CLI
```bash
uv run python main.py
```

Available commands:
- **[topic]** — Investigate any research topic (produces a PDF report)
- **feeds** — Check all threat intel feeds
- **feeds:ransomware** — Check feeds filtered by keyword
- **search \<query\>** — Semantic search across stored findings, summaries, threat actors, recommendations, and detection rules. Add `--type=finding|summary|actor|recommendation|detection` to filter by content type.
- **stats** — Show knowledge graph statistics
- **exit** — Quit

### Streamlit UI
```bash
uv run streamlit run app.py
```
Provides an investigation runner and a Knowledge Base page with a semantic search box.
`.streamlit/config.toml` disables Streamlit's file watcher — the local embedding model
pulls in modules that would otherwise flood the console with harmless `torchvision`
warnings. (Restart the app to pick up code changes.)

### Programmatic Usage

```python
from main import CoordinatorAgent

coordinator = CoordinatorAgent()

# Full investigation — returns the path to the generated PDF report
report_path = coordinator.investigate("Ransomware trends 2024")

# Check threat feeds
result = coordinator.check_feeds(keyword="ransomware")
# result = {"alerts": [...], "cves": [...]}

# Query the knowledge graph (SQLite)
stats = coordinator.ioc_store.get_graph_summary()
high_risk = coordinator.ioc_store.get_high_risk_iocs(min_score=60)
relationships = coordinator.ioc_store.get_relationships("LockBit")

# Semantic search across stored intel (Chroma vector store)
hits = coordinator.semantic_search("ransomware affiliates targeting healthcare", k=10)
actor_hits = coordinator.semantic_search("APT29 phishing", k=5, types=["actor"])
```

### Change the Claude model

Edit `.env`:
```env
ANTHROPIC_MODEL=claude-sonnet-4-6
```

## How It Works

1. **Plan** — LLM generates specific subtopics and targeted search queries for the topic.
2. **Research** — SubAgents run concurrently: search, analyze with source grounding, extract IOCs, assess severity.
3. **MITRE Mapping** — Maps findings to ATT&CK techniques/tactics with deduplication.
4. **Threat Actor Profiling** — Identifies and profiles threat actor groups from findings.
5. **IOC Enrichment** — Checks IPs, domains, and hashes against VirusTotal, Shodan, AbuseIPDB.
6. **Framework Analysis** — Applies Diamond Model, Cyber Kill Chain, and Admiralty confidence grading.
7. **Recommendations** — Produces prioritized, ticket-ready actions with owner and rationale.
8. **Detection Logic** — Generates Sigma, YARA, Splunk SPL, and KQL detection content from the observed TTPs and IOCs.
9. **Executive Summary** — Source-grounded summary with TL;DR bullets, threat status, confidence, and gaps.
10. **Report + Persistence** — PDF report generated; structured data persisted to SQLite; text artifacts embedded into Chroma.

## Output

### PDF Report (single deliverable)
The report is BLUF-oriented — executive material first, raw data last — and deliberately
avoids restating the same intelligence in multiple places. Sections:

- **TL;DR card** (executive-facing 2–4 bullets)
- **Timeliness header** (intelligence-collected timestamp + threat status: Active / Historical / Anticipated)
- **Intelligence Assessment** (Admiralty confidence + reliability on one line, intelligence gaps, collection priorities)
- **Executive Summary** (source-grounded prose)
- **Prioritized Recommendations** (action / owner / rationale, color-coded by priority)
- **Detection Logic** (full Sigma / YARA / Splunk SPL / KQL rule bodies in preformatted code blocks)
- **Threat Severity Overview** (table + bar chart)
- **Diamond Model Analysis**
- **Cyber Kill Chain** (flow diagram of observed vs. unobserved phases + one compact line per observed phase)
- **Detailed Findings** with analysis, IOCs, and source citations (each source tagged Gov / Vendor / Research / News / Blog)
- **Threat Actor Profiles** (motivation, targets, techniques, malware, campaigns)
- **IOC Enrichment Results** (risk scores, detection counts, high-risk detail)
- **MITRE ATT&CK Technique Mappings**
- **Consolidated Indicators of Compromise** (deduplicated, copy-paste-ready)

> Note: The pipeline used to emit `.stix.json`, `.iocs.csv`, `.sigma.yml`, and `.yara`
> side files. Those were removed in favor of a single self-contained PDF — all rendered
> detection content and consolidated IOCs now live inside the report.

### Knowledge Graph (SQLite)
Persistent storage tracks:
- Investigations and findings
- IOCs with enrichment data and risk scores
- Threat actor profiles
- MITRE ATT&CK mappings
- Entity relationships (actor → uses → malware → communicates_with → domain)

### Semantic Search (Chroma)
Local vector store sitting alongside SQLite. After every investigation, the following
content is embedded with a local `sentence-transformers` model (default
`all-MiniLM-L6-v2`) and persisted to `database/chroma/`:
- Finding analyses (per subtopic) with severity and topic metadata
- Executive summaries (per investigation)
- Threat actor profiles (description, targets, techniques, malware)
- Recommendations (action + rationale + references)
- Detection rules (Sigma, YARA, Splunk SPL, KQL — title + description + body)

Document IDs are deterministic (e.g. `inv:42:finding:0`, `actor:lockbit`) so re-running
an investigation upserts cleanly instead of duplicating entries. No API key is required —
embeddings run locally and offline. Override the model or path with `EMBEDDING_MODEL` and
`VECTOR_DB_PATH` in `.env`.

## Feed Monitoring

Built-in RSS feeds:
- CISA Alerts and Known Exploited Vulnerabilities
- NVD CVE Database (API)
- Krebs on Security
- The Hacker News
- BleepingComputer
- Dark Reading

## Project Structure

```
/
├── .env                           # API keys & config
├── .env.example                   # Config template
├── .streamlit/config.toml         # Streamlit settings (file watcher disabled)
├── main.py                        # LangGraph coordinator + CLI + public API
├── app.py                         # Streamlit UI (investigation runner + knowledge base)
├── config.py                      # Settings (Anthropic model, keys, embedding model, vector path)
├── agents/
│   ├── searcher.py                    # Tavily web search (with SQLite cache)
│   ├── scraper.py                     # WebBaseLoader URL scraper
│   ├── subagent.py                    # Source-grounded research subagent
│   ├── ioc_extractor.py               # IOC extraction
│   ├── mitre_mapper.py                # MITRE ATT&CK mapping
│   ├── enrichment_agent.py            # VirusTotal/Shodan/AbuseIPDB
│   ├── threat_actor_profiler.py       # Threat actor profiling
│   ├── framework_analyst.py           # Diamond Model, Kill Chain, confidence
│   ├── recommendations_generator.py   # Prioritized actionable recommendations
│   ├── detection_logic_generator.py   # Sigma/YARA/SPL/KQL detection content
│   ├── source_classifier.py           # Deterministic source-type tagging
│   └── feed_monitor.py                # RSS/CVE feed monitoring
├── database/
│   ├── ioc_store.py                   # SQLite knowledge graph
│   ├── vector_store.py                # Chroma semantic search index
│   └── search_cache.py                # Tavily search-result cache
├── reports/
│   └── generator.py                   # PDF report generator
└── pyproject.toml                 # Dependencies
```

## API Key Sources

| Service | URL | Free Tier |
|---------|-----|-----------|
| Tavily | https://app.tavily.com | 1,000 searches/month |
| Anthropic | https://console.anthropic.com | Pay-per-use |
| VirusTotal | https://www.virustotal.com | 4 requests/minute |
| Shodan | https://account.shodan.io | Limited queries |
| AbuseIPDB | https://www.abuseipdb.com | 1,000 checks/day |

## Example Topics

- "APT groups targeting financial institutions"
- "Zero-day vulnerabilities in cloud infrastructure"
- "Ransomware trends 2024"
- "Supply chain attacks in software development"
- "Phishing campaigns targeting healthcare"
