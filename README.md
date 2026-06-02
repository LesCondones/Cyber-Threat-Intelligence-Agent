# Deep Agents: Cyber Threat Intelligence

Multi-agent system using LangGraph for cyber threat intelligence research with Tavily search, IOC enrichment, threat actor profiling, MITRE ATT&CK mapping, CTI framework analysis, and PDF reporting.

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
         +── IOCStore.persist() ──► SQLite knowledge graph
         +── VectorStore.upsert() ──► Chroma (semantic search index)
         +── ReportGenerator.create_report() ──► PDF
         +── STIX 2.1 bundle + IOCs CSV + Sigma + YARA side files
```

### Graph Nodes

| Node | Function | Description |
|------|----------|-------------|
| `plan` | `plan_node` | LLM breaks topic into 3-5 specific subtopics with targeted queries |
| `research` | `research_node` | Concurrent SubAgent execution per subtopic (single merged LLM call per subtopic) |
| `mitre_map` | `mitre_node` | Maps combined findings to MITRE ATT&CK techniques in one call |
| `profile_actors` | `actor_node` | Identifies and profiles threat actor groups |
| `enrich_iocs` | `enrich_node` | VirusTotal/Shodan/AbuseIPDB reputation lookups |
| `framework_analysis` | `framework_node` | Diamond Model, Kill Chain, confidence assessment |
| `recommendations` | `recommendations_node` | Prioritized, actionable recommendations with owner + rationale |
| `detection_logic` | `detection_logic_node` | Sigma rules, YARA rules, Splunk SPL and KQL hunt queries |
| `executive_summary` | `summary_node` | TL;DR bullets + threat status + source-grounded executive summary |
| `generate_report` | `report_node` | PDF generation + STIX/CSV/Sigma/YARA side files + SQLite persistence |

### Agent Components

| Agent | File | Purpose |
|-------|------|---------|
| **Coordinator** | `main.py` | LangGraph orchestration, CLI, public API |
| **SubAgent** | `agents/subagent.py` | Source-grounded research with key findings extraction |
| **Web Searcher** | `agents/searcher.py` | Tavily API integration |
| **Web Scraper** | `agents/scraper.py` | LangChain WebBaseLoader for direct URL fetching |
| **IOC Extractor** | `agents/ioc_extractor.py` | Regex extraction of IPs, domains, URLs, hashes, CVEs, malware; STIX 2.1 export |
| **MITRE Mapper** | `agents/mitre_mapper.py` | LLM-based ATT&CK technique mapping with deduplication |
| **Enrichment Agent** | `agents/enrichment_agent.py` | VirusTotal, Shodan, AbuseIPDB lookups |
| **Threat Actor Profiler** | `agents/threat_actor_profiler.py` | LLM-based structured threat actor profiles |
| **Framework Analyst** | `agents/framework_analyst.py` | Diamond Model, Cyber Kill Chain, Admiralty confidence assessment |
| **Feed Monitor** | `agents/feed_monitor.py` | RSS/CVE feed ingestion |
| **IOC Store** | `database/ioc_store.py` | SQLite knowledge graph |
| **Vector Store** | `database/vector_store.py` | Chroma + sentence-transformers semantic search index |
| **Report Generator** | `reports/generator.py` | PDF reports with charts, tables, framework sections |

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
```

## Usage

### Run the CLI
```bash
uv run python main.py
```

Available commands:
- **[topic]** - Investigate any research topic
- **feeds** - Check all threat intel feeds
- **feeds:ransomware** - Check feeds filtered by keyword
- **search \<query\>** - Semantic search across stored findings, summaries, threat actors, recommendations, and detection rules. Add `--type=finding|summary|actor|recommendation|detection` to filter by content type.
- **stats** - Show knowledge graph statistics
- **exit** - Quit

### Programmatic Usage

```python
from main import CoordinatorAgent

coordinator = CoordinatorAgent()

# Full investigation — returns path to PDF report
report_path = coordinator.investigate("Ransomware trends 2024")

# Check threat feeds
result = coordinator.check_feeds(keyword="ransomware")
# result = {"alerts": [...], "cves": [...]}

# Export IOCs as STIX 2.1
stix_bundle = coordinator.export_stix(findings)

# Query knowledge graph
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

1. **Plan**: LLM generates specific subtopics and targeted search queries for the topic
2. **Research**: SubAgents run concurrently — search, analyze with source grounding, extract IOCs, assess severity
3. **MITRE Mapping**: Maps findings to ATT&CK techniques/tactics with deduplication
4. **Threat Actor Profiling**: Identifies and profiles threat actor groups from findings
5. **IOC Enrichment**: Checks IPs, domains, and hashes against VirusTotal, Shodan, AbuseIPDB
6. **Framework Analysis**: Applies Diamond Model, Cyber Kill Chain, and Admiralty confidence grading
7. **Executive Summary**: Source-grounded summary with specific facts, confidence level, and gaps
8. **Report + Database**: PDF report generated; all data persisted to SQLite knowledge graph

## Output

### PDF Report Sections
- **TL;DR card** (executive-facing 2-4 bullets)
- **Timeliness header** (intelligence-collected timestamp + threat status: Active / Historical / Anticipated)
- **Intelligence Assessment** (Admiralty confidence + reliability + key judgments + intelligence gaps)
- **Executive Summary** (source-grounded prose)
- **Prioritized Recommendations** (action / owner / rationale, color-coded by priority)
- **Detection Logic** (Sigma rules, YARA rules, Splunk SPL and KQL hunt queries — Preformatted code blocks)
- **Threat Severity Overview** (table + bar chart)
- **Diamond Model Analysis**
- **Cyber Kill Chain** (horizontal flow diagram showing observed vs. unobserved phases)
- **Detailed Findings** with key facts and source citations (each source tagged Gov / Vendor / Research / News / Blog)
- **Threat Actor Profiles** (motivation, targets, techniques, malware)
- **IOC Enrichment Results** (risk scores, detection counts)
- **MITRE ATT&CK Technique Mappings**
- **Consolidated Indicators of Compromise**

### Machine-Readable Side Files
Written alongside the PDF for direct ingestion into SIEM / EDR / TIP:
- `<report>.stix.json` — STIX 2.1 bundle
- `<report>.iocs.csv` — Flat CSV (type, value, risk_score, risk_level)
- `<report>.sigma.yml` — Sigma rules (multi-document YAML)
- `<report>.yara` — YARA rules

### Knowledge Graph (SQLite)
Persistent storage tracks:
- Investigations and findings
- IOCs with enrichment data and risk scores
- Threat actor profiles
- MITRE ATT&CK mappings
- Entity relationships (actor → uses → malware → communicates_with → domain)

### Semantic Search (Chroma)
Local vector store sitting alongside SQLite. After every investigation, the following content is embedded with a local `sentence-transformers` model (default `all-MiniLM-L6-v2`) and persisted to `database/chroma/`:
- Finding analyses (per subtopic) with severity and topic metadata
- Executive summaries (per investigation)
- Threat actor profiles (description, targets, techniques, malware)
- Recommendations (action + rationale + references)
- Detection rules (Sigma, YARA, Splunk SPL, KQL — title + description + body)

Document IDs are deterministic (e.g. `inv:42:finding:0`, `actor:lockbit`) so re-running an investigation upserts cleanly instead of duplicating entries. No API key is required — embeddings run locally. Override the model or path with `EMBEDDING_MODEL` and `VECTOR_DB_PATH` in `.env`.

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
├── main.py                        # LangGraph coordinator + CLI
├── config.py                      # Anthropic Claude configuration
├── agents/
│   ├── searcher.py                    # Tavily web search (with SQLite cache)
│   ├── scraper.py                     # WebBaseLoader URL scraper
│   ├── subagent.py                    # Source-grounded research subagent
│   ├── ioc_extractor.py               # IOC extraction + STIX 2.1 export
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
│   └── search_cache.py                # Tavily search-result cache (7-day TTL)
├── reports/
│   └── generator.py                   # PDF report + side files
├── tasks/
│   └── todo.md                   # Development roadmap
└── pyproject.toml                # Dependencies
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
