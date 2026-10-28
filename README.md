# TRACE-X — AI-Powered Cyber Investigation Assistant

TRACE-X is a Django-based cybersecurity investigation platform that turns raw
evidence (logs, emails, IDS alerts, netflow) into **traceable conclusions**:

- **Evidence fingerprints** — every upload is hashed with SHA-256 at arrival.
- **Tamper-evident ledger** — blockchain-style append-only hash chain
  (`block_hash = SHA-256(height | timestamp | prev_hash | payload_hash)`) over
  evidence, timeline events and findings. Any unauthorized modification of
  investigation data or the ledger itself is detected.
- **Deterministic AI analysis** — parsers + detection rules + correlation
  engine reconstruct a chronological attack timeline and emit findings
  (brute force, compromise after failures, phishing, malware, C2 beaconing,
  recon scans, exfiltration, privilege escalation, cross-source IP links).
- **Evidence-to-Conclusion traceability** — every finding stores the exact
  supporting evidence, excerpts and rationale; the finding page shows the
  full trail (Finding → Evidence → raw excerpt).
- **JSON API** — `/api/investigations/`, per-case detail with traceability,
  `/analyze`, `/integrity`, plus `/api/health`.

## Quick start

```bash
pip install -r requirements.txt
python manage.py migrate
python manage.py seed_demo        # demo case TRX-0001
python manage.py runserver
```

Open http://127.0.0.1:8000/ and sign in with credentials created by `seed_demo`.

Demo evidence files live in `demo/evidence/` and are loaded by `seed_demo`
(fallback content is embedded in the command if the folder is missing).

## Tests

```bash
python manage.py test
```

67 tests cover hashing, the integrity chain and tamper detection, all
parsers, detection rules, correlation, timeline ordering, finding
traceability, evidence upload & validation, UI views, the JSON API and the
complete create → upload → hash → analyze → verify → report workflow.

## Security notes

- Uploaded files are treated as untrusted data — never executed.
- Upload size limit (25 MB), safe storage filenames, login-protected views.
- Runs fully locally; no evidence leaves the machine.
- Uploaded evidence is re-hashed from disk during verification, so post-acquisition file tampering is detected.
- Cases are owner-scoped (or superuser-scoped), API endpoints require authentication, and evidence downloads are protected.
- Duplicate evidence hashes are rejected per case.
- Re-analysis rebuilds the derived ledger instead of accumulating stale blocks.
- Audit trail records views, uploads, analysis, verification, exports and workflow changes.
- HTML forensic report and IOC CSV export are available per case.
- Use `.env.example` for deployment configuration; never commit secrets or private evidence.

## TRACE-X Sentinel AI

TRACE-X includes a case-scoped AI investigator assistant. Configure `GEMINI_API_KEY` in the server environment (or `.env` loaded by your deployment) and optionally set `GEMINI_MODEL`. The browser never receives the key; Django sends requests to the Gemini API server-side using the `x-goog-api-key` header. The assistant receives a bounded case context containing case metadata, evidence metadata/hashes, findings, and timeline events.

Do not commit `.env` or API keys. If a key is ever pasted into chat, a repository, terminal log, or public issue, revoke/rotate it immediately.
