<div align="center">

# ThreatTrace

### Adaptive Cybersecurity Threat Detection & Analytics

**Upload security log. It works out what every column means, finds the threats, and explains itself.**

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.6-F7931E?logo=scikitlearn&logoColor=white)](https://scikit-learn.org/)
[![Tests](https://img.shields.io/badge/tests-48%20passing-0ca30c)](#testing)
[![LLM calls](https://img.shields.io/badge/LLM%20API%20calls-0-8b7bf0)](#why-no-llm)

</div>

---

## The problem

Every security tool names the same field differently. A SIEM pipeline normally needs a
hand-written mapping per data source, and it breaks the moment a vendor renames a column.

```
Dataset A   source_ip   destination_ip   failed_attempts        timestamp
Dataset B   src_addr    dst_host         login_fail             event_time
Dataset C   client_ip   server_ip        authentication_errors  created_at
```

Three schemas, zero shared column names, identical meaning. ThreatTrace resolves them
**semantically** - no config, no per-source mapping file.

```mermaid
flowchart TD
    subgraph SRC["Three unrelated log sources"]
        direction LR
        A["Dataset A<br/>source_ip · failed_attempts · timestamp"]
        B["Dataset B<br/>src_addr · login_fail · event_time"]
        C["Dataset C<br/>client_ip · authentication_errors · created_at"]
    end

    A --> M{{"Semantic<br/>schema mapper"}}
    B --> M
    C --> M

    M --> CANON["Canonical event schema<br/>source_ip · failed_attempts · timestamp · 10 more"]
    CANON --> D["Detection engines"]
    CANON -.->|"columns with no match,<br/>preserved verbatim"| X["extra_fields JSON"]

    style M fill:#8b7bf0,stroke:#5b46d9,color:#fff
    style CANON fill:#199e70,stroke:#0f7a55,color:#fff
    style X fill:#33333f,stroke:#8a8a99,color:#fff
```

---

## Architecture

```mermaid
flowchart LR
    U(["CSV / JSON<br/>upload"])

    subgraph ING["Ingestion"]
        direction TB
        L["loader<br/>CSV · JSON · NDJSON<br/>nested wrappers"]
        P["semantic_analyzer<br/>profile each column"]
        SM["schema_mapper<br/>embed + cosine match"]
        N["normalizer<br/>canonical frame"]
        L --> P --> SM --> N
    end

    subgraph DET["Detection"]
        direction TB
        R1["brute_force"]
        R2["credential_spray"]
        R3["port_scan"]
        R4["endpoint_probe"]
        ML["anomaly_detector<br/>Isolation Forest"]
    end

    subgraph INT["Intelligence"]
        direction TB
        RE["risk_engine<br/>0-100 weighted score"]
        TE["threat_explainer<br/>evidence templates"]
        RE --> TE
    end

    DB[("PostgreSQL<br/>SQLite in dev")]
    API["FastAPI"]
    UI["React dashboard"]

    U --> ING --> DET --> INT --> DB
    ING --> DB
    DB <--> API <--> UI
    UI -.->|"correct a mapping"| API
    API -.->|"re-run pipeline"| ING

    style ING fill:#14141c,stroke:#8b7bf0,color:#fff
    style DET fill:#14141c,stroke:#d55181,color:#fff
    style INT fill:#14141c,stroke:#199e70,color:#fff
    style API fill:#3987e5,stroke:#2a78d6,color:#fff
    style UI fill:#8b7bf0,stroke:#5b46d9,color:#fff
```

---

## How a column gets understood

Column names alone are unreliable, so each column is judged on **name + inferred type +
observed values**.

```mermaid
flowchart TD
    START(["Raw column"]) --> PROF["<b>1. Profile</b><br/>infer dtype from real values<br/>summarise the value shape"]
    PROF --> DESC["Descriptor sentence<br/><i>Column named 'usr_fail_cnt'.<br/>Inferred type: integer.<br/>Values 0 to 47, mean 2.10.</i>"]
    DESC --> EMB["<b>2. Embed + match</b><br/>cosine similarity against<br/>13 ontology concepts"]

    EMB --> BONUS["name-hint bonus +0.08<br/>dtype match bonus +0.05<br/><b>dtype mismatch -0.10</b>"]
    BONUS --> SOFT["<b>3. Calibrate</b><br/>per-column softmax<br/>to a 0-1 confidence"]
    SOFT --> ASSIGN["<b>4. Assign</b><br/>greedy highest-first<br/>one column per concept"]

    ASSIGN --> Q{"confidence<br/>above 0.35?"}
    Q -->|yes| MAP["Mapped to canonical field"]
    Q -->|no| KEEP["<b>5. Preserved</b><br/>kept verbatim in extra_fields<br/>never discarded"]

    MAP --> Q2{"confidence<br/>above 0.60?"}
    Q2 -->|yes| TRUST["Trustworthy"]
    Q2 -->|no| REVIEW["Flagged <i>Check this</i><br/>in the Schema view"]
    REVIEW -.->|"analyst corrects it"| FORCE["Pinned at 100%<br/>full re-analysis"]

    style PROF fill:#14141c,stroke:#3987e5,color:#fff
    style EMB fill:#14141c,stroke:#3987e5,color:#fff
    style SOFT fill:#14141c,stroke:#3987e5,color:#fff
    style ASSIGN fill:#14141c,stroke:#3987e5,color:#fff
    style TRUST fill:#0ca30c,stroke:#0a850a,color:#fff
    style REVIEW fill:#fab219,stroke:#d99a12,color:#000
    style FORCE fill:#8b7bf0,stroke:#5b46d9,color:#fff
    style KEEP fill:#33333f,stroke:#8a8a99,color:#fff
```

The **dtype-mismatch penalty** is what stops a string `cost_centre_code` from being read as
the integer `status_code` concept just because both contain the word "code".

### Two interchangeable embedding backends

| Backend | When | Trade-off |
|---|---|---|
| `sentence-transformers` (all-MiniLM-L6-v2) | installed via `requirements-ml.txt` | true paraphrase understanding, ~2 GB of torch |
| TF-IDF + cosine (scikit-learn only) | automatic fallback | no heavy dependency, weaker on synonyms |

Both are tested to map every sample column correctly, so the fallback is a real option and
not a degraded mode. Check which is live with `GET /api/health`.

---

## Detection engines

Four explainable rules plus unsupervised ML, all grouped per source IP over **densest
sliding windows** - a two-pointer scan finds the busiest window of a given size, so a burst
is never split across two fixed buckets.

```mermaid
flowchart TD
    CANON["Canonical events"] --> GRP["Group by source_ip<br/>densest sliding window"]

    GRP --> BF["<b>Brute force</b><br/>8+ failures, same user<br/>10 min window"]
    GRP --> CS["<b>Credential spraying</b><br/>8+ distinct users<br/>low attempts per user"]
    GRP --> PS["<b>Port scanning</b><br/>15+ distinct ports<br/>5 min window"]
    GRP --> EP["<b>Endpoint probing</b><br/>10+ paths, 50%+ errors<br/>or 5 sensitive-path hits"]
    GRP --> IF["<b>Isolation Forest</b><br/>8 per-IP features<br/>needs 8+ IPs to train"]

    BF --> AGG["Per-IP findings"]
    CS --> AGG
    PS --> AGG
    EP --> AGG
    IF --> AGG
    IF -->|"anomaly above 0.70<br/>and no rule matched"| UNK["Unclassified anomaly<br/><i>the unknown-threat case</i>"]
    UNK --> AGG

    AGG --> RISK["Risk engine"]

    style BF fill:#3987e5,stroke:#2a78d6,color:#fff
    style CS fill:#d95926,stroke:#b8461d,color:#fff
    style PS fill:#199e70,stroke:#0f7a55,color:#fff
    style EP fill:#c98500,stroke:#a66d00,color:#fff
    style IF fill:#d55181,stroke:#b53d68,color:#fff
    style UNK fill:#14141c,stroke:#d55181,color:#fff
```

### The Isolation Forest does two jobs

1. It supplies the **behaviour-anomaly term of every risk score** (30% of the total).
2. It independently flags IPs that are statistically abnormal but matched **no rule at all**
   - the unknown-threat case a pure rule engine cannot reach.

Features: request rate, failure ratio, distinct ports / destinations / paths / usernames,
mean payload size, off-hours ratio.

### Detectors degrade honestly

```mermaid
flowchart LR
    D{"Does the log have<br/>the fields this<br/>detector needs?"}
    D -->|yes| RUN["Run and report"]
    D -->|no| STAND["Stand down<br/><i>not observable here</i>"]
    STAND --> HONEST["Reported as<br/>0 detections,<br/>never guessed"]

    style RUN fill:#0ca30c,stroke:#0a850a,color:#fff
    style STAND fill:#33333f,stroke:#8a8a99,color:#fff
    style HONEST fill:#14141c,stroke:#0ca30c,color:#fff
```

A log with no `username` column genuinely cannot reveal credential spraying, so that
detector stands down instead of inventing a finding. A 4-column dataset fires two of the
five, and says so.

---

## Risk scoring

Deterministic, weighted, reproducible - an analyst can always explain why a score is what
it is.

```
risk = 100 × ( 0.40 × threat_severity      ← strongest rule hit
             + 0.30 × behaviour_anomaly    ← Isolation Forest score
             + 0.15 × frequency            ← log-scaled event volume
             + 0.15 × confidence )         ← evidence volume × mapping confidence
```

```mermaid
pie showData
    title Risk score composition
    "Threat severity" : 40
    "Behaviour anomaly" : 30
    "Frequency" : 15
    "Mapping confidence" : 15
```

| Band | Score | Meaning |
|---|---|---|
| 🟢 **Low** | 0-39 | Background noise |
| 🟡 **Medium** | 40-59 | Worth a look |
| 🟠 **High** | 60-79 | Investigate |
| 🔴 **Critical** | 80-100 | Act now |

Note that **mapping confidence feeds the score**. A finding built on a shaky column
interpretation scores lower than the same finding built on a confident one.

---

## Explanations

Every finding is explained from a template filled with measured evidence.

> **🔴 Critical 95.6 - Possible credential spraying attack**
> `36.82.21.229` · China · 67 events
>
> **Evidence**
> - Contacted **45 distinct user accounts** with 67 failed attempts (1.49 attempts/user on average) within 10 minutes
> - Activity differs from the dataset's normal baseline, notably in: distinct usernames, off-hours ratio, distinct destinations
>
> **Recommended actions**
> 1. Block the source IP temporarily
> 2. Review all targeted accounts for signs of compromise
> 3. Enforce multi-factor authentication on affected accounts

### Why no LLM

No language-model call anywhere in the pipeline. That is a deliberate engineering choice,
not a missing feature:

| Property | Why it matters |
|---|---|
| **Reproducible** | the same log always yields the same verdict |
| **Auditable** | every number traces to a row in the data |
| **Offline** | runs air-gapped, which many SOCs require |
| **Free** | no per-token cost on a 100k-row log |

A finding that has to hold up in an incident review cannot come from a black box.

---

## The honest limitation, and the fix

Semantic matching has a real failure mode: **a wrong mapping produces a wrong finding
rather than no finding.** Confident matches (above ~0.7) are reliable; low-confidence ones
are frequently wrong, and similarity has no way to know that `LogonType` is not a failure
count.

So the fix is to make it **visible and correctable** rather than pretend it doesn't happen.

```mermaid
sequenceDiagram
    actor Analyst
    participant UI as Schema View
    participant API as FastAPI
    participant Pipeline
    participant DB as Database

    Analyst->>UI: Open Schema
    UI->>API: GET dataset schema
    API-->>UI: Columns, types, samples, confidence
    UI-->>Analyst: Flag low confidence mappings

    Note over Analyst,UI: request_count mapped incorrectly\nstatus contains the real signal

    Analyst->>UI: Correct field mappings
    UI->>API: Update schema mapping
    API->>DB: Remove old analysis
    API->>Pipeline: Re-run analysis
    Pipeline->>DB: Store rebuilt results
    API-->>UI: Updated mapping
    UI-->>Analyst: Re-analysis complete

    Note over Analyst,DB: Evidence changes from false positives\nto actual failed attempts
```

Two clicks, and every detection, score, and explanation is rebuilt from the corrected
mapping - never a mix of two.

### Dataset lifecycle

```mermaid
stateDiagram-v2
    [*] --> Uploaded: CSV / JSON received
    Uploaded --> Analyzed: infer, detect, score, explain
    Analyzed --> UnderReview: analyst opens Schema view
    UnderReview --> Analyzed: mapping accepted
    UnderReview --> Corrected: mapping reassigned
    Corrected --> Analyzed: full re-run on retained file
    Analyzed --> [*]

    note right of Corrected
        Old events, detections and alerts
        are deleted before the re-run, so
        results never mix two mappings
    end note
```

---

## Will it work on my data?

Column **names** genuinely don't matter. Column **structure** does. Four hard
requirements - all four, or the analysis honestly returns nothing.

```mermaid
flowchart TD
    F(["Your log file"]) --> R1{"Already parsed<br/>into columns?"}
    R1 -->|"no - raw syslog text"| N1["0 columns mapped<br/><i>no free-text parser</i>"]
    R1 -->|yes| R2{"One row<br/>per event?"}
    R2 -->|"no - pre-aggregated"| N2["0 detections<br/><i>windows count rows</i>"]
    R2 -->|yes| R3{"Has a<br/>source IP column?"}
    R3 -->|no| N3["0 detections<br/><i>findings attach to an IP</i>"]
    R3 -->|yes| R4{"Has a<br/>timestamp column?"}
    R4 -->|no| N4["0 detections<br/><i>every rule is windowed</i>"]
    R4 -->|yes| YES["It works<br/>whatever the columns are called"]

    style YES fill:#0ca30c,stroke:#0a850a,color:#fff
    style N1 fill:#d03b3b,stroke:#b02f2f,color:#fff
    style N2 fill:#d03b3b,stroke:#b02f2f,color:#fff
    style N3 fill:#d03b3b,stroke:#b02f2f,color:#fff
    style N4 fill:#d03b3b,stroke:#b02f2f,color:#fff
```

Each of those failure paths is **verified in the test suite**, not assumed.

### Log sources by fit

| ✅ Works well | 🟡 Partially | ❌ Won't work |
|---|---|---|
| SSH / auth logs | IDS / IPS alerts | Raw unstructured syslog |
| Windows Security (4624/4625) | Proxy logs | EDR / process telemetry |
| nginx, Apache, ALB, CloudFront | LB logs without paths | File-integrity monitoring |
| WAF logs | | DNS without client IP |
| Firewall, netflow, Zeek `conn.log` | | Packet captures (pcap) |
| VPN, RADIUS | | Application error logs |
| Okta, Azure AD, CloudTrail sign-ins | | Anything pre-aggregated |

### Field requirements per detector

| Detector | Source IP | Timestamp | Also needs |
|---|---|---|---|
| Brute force | required | required | username · failure signal |
| Credential spraying | required | required | username · failure signal |
| Port scanning | required | required | port |
| Endpoint probing | required | required | request path (status code helps) |
| Behavioural anomaly | required | required | nothing - uses whatever exists |

---

## Quick start

### Local development

```bash
# ── backend ──────────────────────────────────────────
cd backend
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt      # Windows
# source .venv/bin/activate && pip install -r requirements.txt  # macOS / Linux

python -m synthetic.generate_datasets      # writes data/samples/
python -m uvicorn main:app --reload        # :8000

# ── frontend (second terminal) ───────────────────────
cd frontend
npm install
npm run dev                                # :5173
```

Defaults to SQLite, so there is no database to set up. Point `DATABASE_URL` at Postgres
(`postgresql+psycopg://...`) when you want persistence - that is what docker-compose does.

Optional, for the stronger embedding backend:

```bash
pip install -r backend/requirements-ml.txt
```

---

## Using it

```mermaid
flowchart LR
    U["<b>1 Upload</b><br/>drag a log in"] --> S["<b>2 Schema</b><br/>check the mapping,<br/>correct anything<br/>marked <i>Check this</i>"]
    S --> O["<b>3 Overview</b><br/>peak risk, KPIs,<br/>severity spread"]
    O --> T["<b>4 Timeline</b><br/>volume and detections<br/>over time"]
    T --> I["<b>5 Investigation</b><br/>pick an IP card,<br/>read the evidence"]
    I --> A["<b>6 Analytics</b><br/>top offenders,<br/>categories, geography"]

    style U fill:#8b7bf0,stroke:#5b46d9,color:#fff
    style S fill:#3987e5,stroke:#2a78d6,color:#fff
    style O fill:#199e70,stroke:#0f7a55,color:#fff
    style T fill:#c98500,stroke:#a66d00,color:#fff
    style I fill:#d55181,stroke:#b53d68,color:#fff
    style A fill:#d95926,stroke:#b8461d,color:#fff
```

Start with `data/samples/web_logs_b.json` - 11 deliberately renamed columns, and all five
detectors fire on it.

---

## Data model

```mermaid
erDiagram
    DATASET ||--o{ EVENT : normalises_to
    DATASET ||--o{ DETECTION : produces
    DATASET ||--o{ ALERT : produces

    DATASET {
        int id PK
        string filename
        datetime uploaded_at
        int row_count
        json mapping_summary "per-column match + confidence"
        json unmapped_columns
        string source_path "retained upload, enables re-run"
        json overrides "analyst corrections"
    }
    EVENT {
        int id PK
        string source_ip
        datetime timestamp
        string username
        float failed_attempts
        float port
        string request_path
        text extra_fields "unmapped columns, verbatim"
    }
    DETECTION {
        int id PK
        string detection_type
        string source_ip
        datetime window_start
        float severity
        json evidence
    }
    ALERT {
        int id PK
        string source_ip
        float risk_score
        string classification
        json components "the four weighted terms"
        json evidence
        json recommendation
    }
```

---

## API

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | status + which embedding backend is live |
| `GET` | `/api/ontology` | the 13 canonical fields |
| `POST` | `/api/datasets` | upload and analyse a log |
| `GET` | `/api/datasets` | list analysed datasets |
| `GET` | `/api/datasets/{id}/schema` | per-column mapping, dtype, samples, confidence |
| `PUT` | `/api/datasets/{id}/schema` | **correct the mapping and re-run** |
| `GET` | `/api/datasets/{id}/overview` | KPIs and distributions |
| `GET` | `/api/datasets/{id}/timeline` | bucketed volume and detections |
| `GET` | `/api/datasets/{id}/alerts` | scored alerts, highest risk first |
| `GET` | `/api/datasets/{id}/ips/{ip}` | full investigation for one IP |
| `GET` | `/api/datasets/{id}/analytics` | offenders, categories, geography |

Interactive docs at `/docs`.

---

## Testing

```bash
cd backend
.venv/Scripts/python -m pytest tests/ -v      # 48 tests
```

```mermaid
flowchart LR
    subgraph T["48 tests"]
        direction TB
        A["<b>Schema mapping</b><br/>same concept across 3 schemas,<br/>on both embedding backends"]
        B["<b>Overrides</b><br/>pinning, concept re-matching,<br/>duplicate rejection, re-run"]
        C["<b>Detection ground truth</b><br/>labelled synthetic attacks,<br/>right IP and right type"]
        D["<b>Foreign formats</b><br/>Zeek, Windows, ECS, NDJSON,<br/>non-security, tiny, empty"]
        E["<b>API</b><br/>every endpoint, ordering,<br/>404s, bad file types"]
    end

    style A fill:#14141c,stroke:#3987e5,color:#fff
    style B fill:#14141c,stroke:#8b7bf0,color:#fff
    style C fill:#14141c,stroke:#199e70,color:#fff
    style D fill:#14141c,stroke:#c98500,color:#fff
    style E fill:#14141c,stroke:#d55181,color:#fff
```

The **foreign-format** suite matters most: the sample data was written alongside the
ingestion layer, so passing on it proves less than it looks. Those tests use shapes the
system was never designed around - and four of them crashed the app before they existed.

The dashboard is also verified end-to-end in headless Chromium: upload, every page, zero
console errors.

---

## Project layout

```
backend/
  ingestion/      ontology · semantic_analyzer · schema_mapper · normalizer · loader
  detection/      brute_force · credential_spray · port_scan · endpoint_probe
                  anomaly_detector · windowing
  intelligence/   risk_engine · threat_explainer
  geoip/          bundled offline IP-to-country table
  synthetic/      dataset generator + labelled attack scenarios
  db/             SQLAlchemy models · session
  api/            routes/ · pipeline · schemas
  tests/          48 tests
frontend/src/     pages/ · components/ · theme.js · api.js
docs/             landing page (GitHub Pages source)
docker/           Dockerfiles · nginx config
data/samples/     generated sample datasets + ground truth
```

**Stack** - Python 3.12 · FastAPI · pandas · scikit-learn · SQLAlchemy 2 · Pydantic v2 ·
PostgreSQL · sentence-transformers · React 18 · Vite · Tailwind CSS · Recharts · Docker
Compose · pytest


---



<div align="center">

**Built to be honest about what it knows.**

</div>
