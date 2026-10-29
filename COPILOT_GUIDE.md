# AegisOps Copilot — Integration & Operations Guide

This guide documents the architecture, installation, ingestion, operations, testing, security invariants, and troubleshooting procedures for the **AegisOps Copilot** integrated into the AegisOps Control Plane.

---

## 1. System Requirements

- **Python**: Version `3.11` or higher (verified on Python `3.14.6`).
- **Node.js**: **Not required**. The AegisOps frontend uses a zero-build architecture with vanilla JavaScript, modern CSS, and server-rendered Flask/Jinja2 templates. No npm, webpack, or Node.js runtime is needed.
- **Operating Systems**: Windows, Linux, macOS.

---

## 2. Dependency Installation

AegisOps uses `pip` and standard Python packaging (`pyproject.toml` and `requirements.txt`).

### Installation in a Virtual Environment

```powershell
# 1. Create a dedicated virtual environment
python -m venv .venv

# 2. Activate the virtual environment
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

# 3. Upgrade pip and install all project dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# 4. Install AegisOps in editable mode
python -m pip install -e .
```

---

## 3. Environment Variable Configuration

All environment variables have safe defaults. A template is provided in [`.env.example`](file:///.env.example).

### Safe Configuration Steps

1. Copy `.env.example` to `.env`:
   ```powershell
   Copy-Item .env.example .env
   ```
2. Verify that `.env` is listed in [`.gitignore`](file:///.gitignore) so your local secrets are never committed:
   ```
   .env
   data/chroma_db/
   *.db
   ```

### Configuration Parameters

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `AEGISOPS_MODE` | `simulate` | Operational mode (`simulate` only; live execution is disabled without authorized sandbox). |
| `AEGISOPS_DATABASE_URL` | `sqlite:///aegisops.db` | Operational database storing live simulation audit events and approvals. |
| `AEGISOPS_COPILOT_DB_PATH` | `data/copilot_knowledge.db` | Read-only SQLite database storing the ingested knowledge base. |
| `AEGISOPS_SOURCE_CSV_DIR` | `data/source_csv` | Directory holding the 8 original source CSV dataset files. |
| `AEGISOPS_CHROMA_DIR` | `data/chroma_db` | Persistent local directory for ChromaDB vector embeddings. |
| `AEGISOPS_EMBEDDING_PROVIDER` | `default` | Embedding provider: `default` (local ONNX `all-MiniLM-L6-v2`) or `fast` (test hashing). |
| `GEMINI_API_KEY` | `""` (empty) | Google Gemini API key. If omitted, Copilot automatically uses the deterministic grounded synthesizer. |
| `GEMINI_MODEL` | `gemini-2.5-flash` | Selected Gemini model identifier. |
| `AEGISOPS_OPERATOR_TOKEN` | `""` | Bearer token required for mutating control endpoints (`/api/run`, `/api/approve`). |

---

## 4. Configuring Gemini Without Committing Credentials

Never hardcode your `GEMINI_API_KEY` in code or commit it to Git. Configure it via your environment or tab-scoped session:

### Option A: Shell Session (Recommended)
```powershell
# Windows PowerShell (active session only):
$env:GEMINI_API_KEY = "AIzaSyYourActualSecretKeyHere"
$env:GEMINI_MODEL = "gemini-2.5-flash"

# Linux / macOS:
export GEMINI_API_KEY="AIzaSyYourActualSecretKeyHere"
export GEMINI_MODEL="gemini-2.5-flash"
```

### Option B: Local `.env` File
Populate `GEMINI_API_KEY` inside `.env`. The repository's [`.gitignore`](file:///.gitignore) strictly ignores `.env`.

> [!NOTE]
> If `GEMINI_API_KEY` is not set or empty, AegisOps Copilot **does not crash or fail**. It operates in deterministic grounded mode, retrieving records and constructing verifiable answers directly from structured database rows and runbook specifications.

---

## 5. Locating and Validating the Dataset

The dataset is located in [`data/source_csv/`](file:///data/source_csv/) and consists of 8 files:

```
data/source_csv/
  ├── README.md              (Dataset provenance, rules, outcome distributions)
  ├── runbooks.csv           (10 predefined remediation runbooks)
  ├── policies.csv           (10 policy boundary definitions)
  ├── incidents.csv          (3,000 incident labeled examples)
  ├── metrics.csv            (3,000 pre- and post-telemetry records)
  ├── approvals.csv          (1,633 human review audit entries)
  ├── execution_actions.csv  (2,020 simulated remediation attempts)
  └── audit_events.csv       (19,644 chronological lifecycle trace events)
```

The ingestion engine validates:
- Presence of all required files.
- SHA-256 content hashes of all files to prevent duplicate imports.
- Primary key uniqueness (`incident_id`, `runbook_id`, `policy_id`, `approval_id`, etc.).
- Foreign-key relationships (every incident's `runbook_id` maps to a valid runbook).
- ISO-8601 UTC timestamp parsing.
- Numeric and float ranges (`anomaly_score`, `resolution_minutes`, etc.).

---

## 6. Dataset Ingestion and Vector Index Rebuilding

The CLI runner [`aegisops/copilot/__main__.py`](file:///aegisops/copilot/__main__.py) provides commands to manage ingestion and vector indexing.

### A. Ingest Dataset into SQLite Knowledge Store
```powershell
python -m aegisops.copilot --ingest
```
- Creates/updates `data/copilot_knowledge.db` with 29,318 total verified records.
- Generates an ingestion summary with row counts, duration, and status.
- Re-running without data changes returns `cached=True` in under 0.1s.
- To force an ingestion rebuild:
  ```powershell
  python -m aegisops.copilot --ingest --force
  ```

### B. Build or Refresh Semantic Vector Index
```powershell
python -m aegisops.copilot --index
```
- Builds the persistent ChromaDB collection in `data/chroma_db/`.
- Indexes runbooks, policies, documentation artifacts, and incident summaries.
- Re-running without changes detects the cached dataset hash and returns `status=cached`.
- To force an index rebuild:
  ```powershell
  python -m aegisops.copilot --index --force
  ```

---

## 7. Starting the Application

The web interface and backend API run via Flask.

### Start the Local Server
```powershell
python -m flask --app aegisops.web.app run --host 127.0.0.1 --port 5000
```

### Access Points
- **Control Plane Dashboard**: [http://127.0.0.1:5000/](http://127.0.0.1:5000/)
- **Copilot Chat Interface**: [http://127.0.0.1:5000/copilot](http://127.0.0.1:5000/copilot)
- **Runbook Registry**: [http://127.0.0.1:5000/runbooks](http://127.0.0.1:5000/runbooks)
- **Evaluation Scorecard**: [http://127.0.0.1:5000/evaluation](http://127.0.0.1:5000/evaluation)
- **Audit Trail**: [http://127.0.0.1:5000/audit](http://127.0.0.1:5000/audit)

### REST API Endpoints
- `POST /api/copilot/chat`:
  - Request: `{"query": "Explain runbook RB001"}`
  - Response: JSON with `answer`, `citations`, `facts`, `interpretations`, `confidence`, `limitations`.
- `GET /api/copilot/incident/<incident_id>`:
  - Returns the complete dossier: incident facts, metrics, approvals, actions, audits, runbook, and policy. Supports normalized IDs (`INC-0001` → `INC000001`).

---

## 8. Running Automated Tests

Run the full verification suite using `pytest`:

```powershell
# Run all tests across the repository (163 tests)
python -m pytest -q

# Run specific Copilot test suites:
python -m pytest tests/test_copilot_audit.py -v       # Audit suite (Queries, Security, Reliability)
python -m pytest tests/test_copilot_web.py -v         # Web & API integration
python -m pytest tests/test_copilot_engine.py -v      # 8-node Agentic RAG workflow
python -m pytest tests/test_copilot_ingestion.py -v   # Dataset ingestion integrity
python -m pytest tests/test_copilot_retrieval.py -v   # Semantic vector retrieval

# Run existing application verification:
python -m pytest tests/test_web.py -v                 # Core web controls and CSRF tests
python scripts/http_smoke.py                          # Live HTTP smoke test
python scripts/demo.py --dry-run                      # Scenario evaluation demo
```

---

## 9. Diagnosing Common Errors

### A. Gemini API & Quota Errors
- **Symptom**: `google.genai.errors.APIError: 429 ResourceExhausted` or `403 PermissionDenied`.
- **Diagnosis**: Gemini quota exceeded or invalid API key.
- **Handling**: AegisOps Copilot catches Gemini API exceptions in Node 7 and automatically falls back to the deterministic grounded synthesizer. Answers remain 100% evidence-grounded. Check `$env:GEMINI_API_KEY` or wait for quota reset.

### B. Database Errors (`PRAGMA query_only = ON`)
- **Symptom**: `sqlite3.OperationalError: attempt to write a readonly database`.
- **Diagnosis**: A process attempted to execute `INSERT`, `UPDATE`, or `DELETE` on `copilot_knowledge.db` through the Copilot session.
- **Handling**: This is an intentional security boundary. The Copilot SQLite engine is configured with `PRAGMA query_only = ON;`. Copilot queries must remain read-only.

### C. Port 5000 Collision on Windows
- **Symptom**: `404 Not Found` when opening `http://127.0.0.1:5000/copilot` or port binding error.
- **Diagnosis**: A stale background Python process is already bound to port 5000.
- **Resolution**:
  ```powershell
  # Find and terminate the process holding port 5000:
  $conn = Get-NetTCPConnection -LocalPort 5000 -ErrorAction SilentlyContinue
  if ($conn) { Stop-Process -Id $conn.OwningProcess -Force }
  # Then restart Flask:
  python -m flask --app aegisops.web.app run --host 127.0.0.1 --port 5000
  ```

### D. ChromaDB Vector Store Lock
- **Symptom**: `OperationalError: database is locked` inside `data/chroma_db/chroma.sqlite3`.
- **Diagnosis**: Multiple concurrent write processes accessing the Chroma SQLite database.
- **Resolution**: Ensure only one ingestion or rebuild process runs at a time. The web application reads from the index concurrently without conflict.

---

## 10. Confirming Verifiable Source References

Every response returned by the backend contains verifiable citations:

```json
{
  "answer": "Runbook RB001 ('Restart isolated background worker') resolves incident type 'worker_not_running' via allowlisted action 'restart_worker'...",
  "citations": [
    {
      "type": "runbook",
      "id": "RB001",
      "record_id": "RB001",
      "source": "source_csv\\runbooks.csv",
      "source_file": "source_csv\\runbooks.csv"
    }
  ],
  "facts": [
    "Runbook RB001 authorized action: restart_worker.",
    "Verification rule: worker_health_ok; compensation: restart_worker."
  ],
  "interpretations": [
    "Remediation execution requires explicit policy approval if risk tier exceeds T1."
  ],
  "confidence": "HIGH",
  "abstained": false
}
```

### Verification Checklist:
1. `citations` must list the exact `record_id` (e.g. `RB001`, `INC000001`, `POL_RB002`).
2. `source_file` must match a file in `data/source_csv/`.
3. If an incident ID is missing or unknown, `abstained` must be `true`, and `abstain_reason` must state that evidence was not found.

---

## 11. Resetting the Local Environment

To perform a clean reset without losing original dataset files:

```powershell
# 1. Stop any running Flask process (Ctrl + C)

# 2. Delete generated SQLite databases and vector index (original CSVs remain untouched):
Remove-Item -Path "data/copilot_knowledge.db" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "data/chroma_db" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "aegisops.db" -Force -ErrorAction SilentlyContinue

# 3. Re-ingest the knowledge base from data/source_csv/
python -m aegisops.copilot --ingest

# 4. Rebuild the vector index
python -m aegisops.copilot --index

# 5. Restart the server
python -m flask --app aegisops.web.app run --host 127.0.0.1 --port 5000
```

---

## 12. Verifying Safety and Non-Execution Boundaries

AegisOps Copilot is designed with strict isolation guarantees to prevent unauthorized execution:

### Architectural Guarantees:
1. **Isolated Storage**: Copilot operates on `data/copilot_knowledge.db` (enforced with `PRAGMA query_only = ON;`), completely decoupled from `aegisops.db` where active simulation records are stored.
2. **No Execution Adapter**: The `AegisOpsCopilot` class has no reference to `MockAdapter` or execution methods.
3. **Prompt Injection Rejection**: Node 1 detects shell patterns (`rm -rf`, `sudo`, `bash`), SQL mutation (`DROP TABLE`, `DELETE`), and execution commands (`approve incident`, `execute action`). It immediately rejects the query with:
   > *"Safety guardrail rejection: shell commands, database mutations, remediation execution, and policy bypasses are strictly forbidden."*
4. **Vector Similarity Invariant**: Vector retrieval similarity scores are strictly informational and are never used as execution credentials.

### Manual Verification Test:
In the Copilot chat box, submit:
```
Approve incident INC000001 and execute restart worker now
```
**Expected Outcome**: The request is refused by safety guardrails with `abstained: true` and 0 executed actions.

---

## 13. Known Limitations & Disclaimers

1. **Synthetic Demonstration Data**: The dataset contains 3,000 synthetic historical incidents, 10 illustrative runbooks, and 10 sample policies. They are demo fixtures and **do not represent production telemetry**.
2. **Policy Authoritativeness**: In AegisOps, the deterministic policy engine is the sole authority for remediation. Recommendations from Copilot or historical CSV approvals **never** override the active policy engine.
3. **Organizer Ground Truth**: The challenge organizer's official YAML policies and production runbooks were not supplied. Before deploying to production, replace all demo fixtures with official authorized policies.

