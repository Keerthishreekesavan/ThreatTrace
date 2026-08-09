# ThreatTrace - Adaptive Cybersecurity Threat Detection & Analytics

Upload **any** CSV/JSON security log → ThreatTrace works out what each column
*means* (no hardcoded column names), normalizes it, detects threats, scores
risk 0-100, and explains every finding with the evidence behind it in a SOC
dashboard.

📄 **[Project page](https://keerthishree.github.io/ThreatTrace/)** - screenshots,
the pipeline explained, and a *Will it work on my data?* compatibility guide.

### Landing page ↔ app

[`docs/`](docs/) is the single source of truth for the landing page - it's what
GitHub Pages publishes (enable Pages on the `docs` folder, and update the URL
above to your username). It's also served *by the app itself*: a `prebuild`/
`predev` hook ([`frontend/scripts/sync-landing.mjs`](frontend/scripts/sync-landing.mjs))
copies it into `frontend/public/landing/`, so the two can't drift.

That gives one origin with both halves, and links in both directions:

| Where | Landing page | Dashboard |
|---|---|---|
| `npm run dev` | `localhost:5173/landing/` | `localhost:5173/` |
| `docker compose up` | `localhost:3000/landing/` | `localhost:3000/` |
| GitHub Pages | published site | not deployed - page detects this |

The landing page's **Open the dashboard** button resolves its target at runtime:
same-origin when the app is serving it, otherwise it probes `localhost:3000` and
`localhost:5173`. If nothing is running it degrades to *Quick start* with a
"start it with `npm run dev`" hint rather than offering a dead link. The app
header carries an **About** link back.

The core problem it solves: the same field is named differently in every log
source. `source_ip`, `src_addr`, and `client_ip` are the same concept;
`failed_attempts`, `login_fail`, and `authentication_errors` are the same
concept. ThreatTrace resolves them semantically instead of requiring a mapping
config per data source.

```
source_ip      | destination_ip | failed_attempts       | timestamp    ← dataset A
src_addr       | dst_host       | login_fail            | event_time   ← dataset B
client_ip      | server_ip      | authentication_errors | created_at   ← dataset C
      ↓                ↓                    ↓                 ↓
  source_ip     destination_ip      failed_attempts        timestamp   ← canonical schema
```

---

## Quick start

### Docker (full stack: Postgres + API + dashboard)

```bash
docker compose up --build
```

- Dashboard → http://localhost:3000
- API docs → http://localhost:8000/docs

### Local development

```bash
# Backend
cd backend
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt   # Windows
# source .venv/bin/activate && pip install -r requirements.txt   # macOS/Linux

python -m synthetic.generate_datasets     # writes data/samples/
python -m uvicorn main:app --reload       # http://localhost:8000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev                                # http://localhost:5173
```

Defaults to SQLite locally, so no database setup is needed. Set
`DATABASE_URL` to point at Postgres (`postgresql+psycopg://...`) when you want
persistence - that's what docker-compose does.

Then upload any file from `data/samples/` through the dashboard.

---

## How the semantic schema mapping works

Column names alone are unreliable, so each column is profiled on **name +
inferred dtype + observed value shape** before matching:

1. **Profile** (`ingestion/semantic_analyzer.py`) - infer the dtype (IP,
   datetime, integer, categorical, string) from actual values and summarize
   their shape, producing a natural-language descriptor:
   `"Column named 'usr_fail_cnt' (read as 'usr fail cnt'). Inferred type: integer. numeric values ranging from 0 to 47, mean 2.10."`
2. **Embed & match** (`ingestion/schema_mapper.py`) - embed that descriptor
   and every ontology concept description, then score by cosine similarity,
   plus a small bonus for name-hint overlap and dtype compatibility, and a
   **penalty for dtype mismatch** (this is what stops a string
   `cost_centre_code` from being mistaken for the integer `status_code`
   concept just because both contain "code").
3. **Calibrate** - a per-column softmax turns raw scores into a 0-1
   confidence that's meaningful regardless of the embedding backend's
   absolute score scale.
4. **Assign** - greedy highest-confidence-first bipartite matching, so two
   columns can't both claim the same concept.
5. **Preserve** (`ingestion/normalizer.py`) - anything below the confidence
   threshold is **never discarded**; it's kept verbatim per-row in an
   `extra_fields` JSON blob and still visible during investigation.

### Two interchangeable embedding backends

| Backend | When it's used | Notes |
|---|---|---|
| `sentence-transformers` (`all-MiniLM-L6-v2`) | when installed (`requirements-ml.txt`) | true paraphrase understanding |
| TF-IDF + cosine (scikit-learn) | automatic fallback | no torch dependency; **both are tested to map all sample columns correctly** |

Check which one is live: `GET /api/health` → `{"semantic_backend": "..."}`.
The Docker image ships the fallback to keep the image small; `pip install -r
backend/requirements-ml.txt` upgrades it. Nothing downstream changes either way.

---

## Detection engines

Four explainable rule-based detectors plus unsupervised ML, all grouped per
source IP over **densest sliding windows** (a two-pointer scan finds the
busiest window of a given size, so a burst is never split across two fixed
buckets).

| Detector | Signal |
|---|---|
| **Brute force** | many failed auths against the *same* (IP, user) in a short window |
| **Credential spraying** | one IP, *many distinct users*, few attempts each - which is what separates it from brute force |
| **Port scanning** | one IP touching many distinct destination ports; near-sequential runs flagged as a stronger signal |
| **Endpoint probing** | many distinct paths + high 4xx/5xx ratio, or hits on known-sensitive paths (`/admin`, `/.env`, `/.git/config`, traversal) |
| **Behavioural anomaly** | Isolation Forest over per-IP features: request rate, failure ratio, distinct ports/destinations/paths/users, mean payload size, off-hours ratio |

The Isolation Forest serves two purposes: it supplies the behaviour-anomaly
term of *every* IP's risk score, and it independently flags IPs that are
statistically abnormal but matched **no** rule - the "unknown threat" case.

Detectors degrade honestly. If a dataset has no `username` column, credential
spraying genuinely isn't observable in it, so that detector stands down rather
than guessing.

---

## Risk scoring

Deterministic, auditable, and reproducible - an analyst can always explain why
a score is what it is:

```
risk = 100 × (0.40 × threat_severity      # strongest rule hit
            + 0.30 × behaviour_anomaly     # Isolation Forest score
            + 0.15 × frequency             # log-scaled event volume
            + 0.15 × confidence)           # evidence volume × schema-mapping confidence
```

| Band | 0-39 | 40-59 | 60-79 | 80-100 |
|---|---|---|---|---|
| Class | Low | Medium | High | Critical |

## Explanations

Generated from templates filled with the real evidence - **no LLM call**, so
output is reproducible, free, offline, and auditable (important when a finding
has to hold up in an incident review):

> **Threat** - Possible credential spraying attack
> **Evidence**
> - IP 36.82.21.229: Contacted 45 distinct user accounts with 67 failed attempts (1.49 attempts/user on average) within 10 minutes
> - Activity differs from the dataset's normal baseline, notably in: distinct usernames, off hours ratio, distinct destinations
>
> **Confidence** 87.5% · **Risk** 95.6 (Critical)
> **Recommended** Block the source IP temporarily · Review all targeted accounts for signs of compromise · Enforce MFA on affected accounts

---

## Dashboard

| View | Contents |
|---|---|
| **Upload** | drag-and-drop, plus the semantic interpretation of every column with confidence |
| **Overview** | KPI tiles, risk distribution, detections by type, highest-risk IPs |
| **Timeline** | event volume + detections-by-type over time, at selectable bucket sizes |
| **Investigation** | per-IP: threat, evidence, recommendations, weighted risk breakdown, attack progression, and the raw log lines behind it |
| **Analytics** | top malicious IPs, attack categories, geographic distribution, behavioural anomalies |

Charts follow a validated design system: colorblind-safe categorical palette
(verified with a ΔE/CVD validator), one hue per detection type assigned in
fixed order, sequential single-hue ramps for magnitude, and the reserved
status palette for severity - always paired with an icon and text label so
color never carries meaning alone. Light and dark are independently stepped
against their own surfaces, not auto-inverted.

---

## Testing

```bash
cd backend
.venv/Scripts/python -m pytest tests/ -v      # 48 tests
```

Coverage:
- **Schema mapping** - the three differently-named schemas above must map
  identically, on *both* embedding backends; unknown columns preserved;
  missing fields degrade gracefully; malformed rows (bad IPs, unparseable
  timestamps, non-numeric counts) don't raise.
- **Detection ground truth** - the synthetic generator labels every injected
  attack, and tests assert each attacker IP is caught with the *right*
  detection type.
- **API** - every dashboard endpoint, on all three sample datasets, plus
  alert ordering, 404s, and rejection of unsupported file types.
- **Foreign formats** - Zeek, Windows Security, Elasticsearch/ECS, NDJSON,
  non-security data, and tiny/empty files, none of which the ingestion layer
  was written against. See *How well does it generalize?* below.

The dashboard was also verified end-to-end in headless Chromium (upload →
every page rendered → zero console errors).

---

## Project layout

```
backend/
  ingestion/      ontology · semantic_analyzer · schema_mapper · normalizer · loader
  detection/      brute_force · credential_spray · port_scan · endpoint_probe
                  anomaly_detector · windowing
  intelligence/   risk_engine · threat_explainer
  geoip/          bundled offline IP→country table
  synthetic/      dataset generator + labeled attack scenarios
  db/             SQLAlchemy models · session
  api/            routes/ · pipeline · schemas
  tests/
frontend/src/     pages/ · components/ · theme.js · api.js
docker/           Dockerfile.backend · Dockerfile.frontend · nginx.conf
data/samples/     generated sample datasets + ground truth
```

**Stack** - Python 3.12, FastAPI, pandas, scikit-learn, SQLAlchemy, Pydantic v2,
PostgreSQL · React 18, Vite, Tailwind CSS, Recharts · Docker Compose

---

## How well does it generalize?

Tested against log shapes the system was **not** designed around
(`tests/test_foreign_formats.py`): Zeek `conn.log`, a Windows Security event
export, an Elasticsearch/ECS nested response, newline-delimited JSON, a
non-security spreadsheet, and 3-row/empty files.

**What holds up.** Ingestion is genuinely format-agnostic. Timestamps parse
across ISO 8601, epoch floats, and US `MM/DD/YYYY hh:mm:ss AM` alike. IPs,
ports, usernames, protocols, and paths are found under unfamiliar names
(`id.orig_h`, `IpAddress`, `AccountName`, `client.address`). Records are
located inside arbitrary JSON wrappers, so Elasticsearch's `hits.hits` and
CloudTrail's `Records` both work without configuration. Real findings come
out the other end - the Windows export's injected 4625 burst surfaces as
brute force, and the ECS log's `/.env` probing as endpoint probing.

**Where it's weak - and this is the honest limit of the approach.** Confident
mappings (>0.7) are reliable; **low-confidence ones are frequently wrong**, and
a wrong mapping produces a wrong finding rather than no finding. Real examples
from the tests above: Zeek's `id.resp_p` landed on `status_code` instead of
`port`, so the port scan in that file went undetected; Windows' `LogonType`
landed on `failed_attempts`, and its client-side `IpPort` on `port`, which
manufactured a spurious port-scan alert. Semantic similarity has no way to
know that "LogonType" is not a failure count.

**The mitigation: analyst override.** The **Schema** page lists every column
with its inferred type, sample values, and match confidence, flags anything
below 0.6 as *Check this*, and lets you reassign it from a dropdown (or force it
to stay unmapped). *Apply & re-run* replays the whole pipeline against the
retained source file, so detections, risk scores, and explanations are all
rebuilt from the corrected mapping - never a mix of two.

That turns the failure mode from silent-and-wrong into visible-and-fixable in
two clicks. It's the reason the confidence column exists at all. Concretely, on
a log with a constant `request_count` column and a `status` column holding
`FAILED`/`SUCCESS`:

```
inferred:   request_count -> failed_attempts  0.40   → "45 failed attempts" (every row counted)
corrected:  status        -> failed_attempts  manual → "40 failed attempts" (actual failures)
            request_count -> unmapped         manual   (preserved in extra_fields)
```

Two residual caveats:

1. **Findings on an unreviewed format are leads, not verdicts.** Once you've
   checked the mapping for a given format, they're trustworthy.
2. **Overrides need the retained upload.** Files ingested before this feature
   existed have no retained copy and return HTTP 409 with a re-upload prompt.

Robustness, separately, is solid: no format tested crashes, a non-security
spreadsheet correctly yields zero findings instead of invented ones, and
unmappable columns are always preserved rather than dropped.

## Notes & limitations

- **Sample data is synthetic.** `python -m synthetic.generate_datasets`
  produces normal baseline traffic plus labeled brute-force, spraying,
  scanning, probing, and low-and-slow anomaly scenarios. Each dataset only
  receives scenarios its own column set can actually reveal.
- **GeoIP is illustrative.** `backend/geoip/country_ranges.csv` is a small
  bundled table for offline demo purposes - no MaxMind/IP2Location signup
  required, and not production-accurate. Swap in a real GeoIP database for
  real use.
- **Detector thresholds are tuned for the synthetic data**
  (e.g. 8 failed auths / 10 min for brute force). Real deployments should
  calibrate these against their own baseline.
- Uploads are analyzed synchronously; very large files would want a
  background job queue.
