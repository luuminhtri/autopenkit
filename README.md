# AutoPenKit

**AutoPenKit** is a Python CLI-based automated pentesting framework with AI-assisted analysis.

The project is designed for learning, automation, and authorized security testing only.

---

## Purpose

AutoPenKit helps automate selected parts of an authorized security testing workflow, including:

* Target validation
* Reconnaissance
* Vulnerability scanning
* Result normalization
* AI-assisted analysis
* Report generation

---

## Legal Notice

This tool is intended for **educational purposes** and **authorized security testing only**.

Allowed use cases include:

* Local labs
* OWASP Juice Shop
* DVWA
* Intentionally vulnerable applications
* Targets with explicit written permission

Do **not** use this tool on unauthorized systems.

---

## Current Status

**Phase 4 — AI-assisted Analysis**

The project currently validates authorized targets, builds a basic asset list, runs Nuclei against the live URLs discovered in recon, stores raw JSON Lines output, normalizes scanner findings into a unified JSON schema, and can generate AI-assisted analysis for each normalized finding.

---

## Planned Pipeline

```text
Target Validation
        ↓
Recon
        ↓
Scanner
        ↓
Normalizer
        ↓
AI Analysis
        ↓
Merger
        ↓
Reporter
```

---

## Project Structure

```text
autopenkit/
├── main.py
├── config/
├── src/
│   └── autopenkit/
├── templates/
├── outputs/
├── examples/
├── tests/
└── docs/
```

---

## Roadmap

| Phase | Goal |
|---|---|
| Phase 1 | Project skeleton |
| Phase 2 | Scanner integration |
| Phase 3 | Result normalization |
| Phase 4 | AI-assisted analysis |
| Phase 5 | Result merger and report generation |
| Phase 6 | Testing, documentation, and demo |

---

## Implemented MVP Flow

AutoPenKit can currently:

* Run from the command line
* Validate a target URL
* Check whether the target is authorized
* Create a unique output folder for each scan
* Generate basic scan metadata
* Generate an initial asset list
* Run Nuclei against the live URLs from recon using a safe profile
* Save raw scanner output under `outputs/<scan_id>/raw/`
* Parse Nuclei JSON Lines output
* Normalize raw scanner findings into `normalized_findings.json`
* Deduplicate findings
* Sort findings by severity
* Preserve partial findings if Nuclei times out after writing results
* Generate AI-assisted analysis into `ai_analysis.json`
* Ask AI to assess evidence quality, confidence rationale, validation status, remediation owner, and safe follow-up scan focus
* Generate step-by-step verification and remediation guidance for authorized site owners
* Generate an AI executive action plan in Markdown and HTML reports
* Skip or safely fall back when an AI API key is not configured

---

## Full Scan Command

```bash
python main.py --target http://localhost:3000 --profile safe
```

Example authorized public lab target:

```bash
python main.py --target https://demo.testfire.net/ --profile safe
```

The `safe` profile limits Nuclei by severity and tags to keep scans suitable for MVP use:

```yaml
nuclei_severity: "info,low,medium"
nuclei_tags: "exposure,misconfig,headers"
timeout: 300
rate_limit: 5
```

---

## Normalize Existing Output

If a scan already produced `raw/nuclei.jsonl`, AutoPenKit can normalize it without running Nuclei again:

```bash
python main.py --normalize-output-dir outputs/<scan_id>
```

This is useful when reviewing existing scan output or regenerating `normalized_findings.json`.

---

## AI Analysis

AutoPenKit currently supports Gemini for AI-assisted finding analysis.

Create a local `.env` file from `.env.example` and set:

```env
GEMINI_API_KEY=your_gemini_api_key_here
```

Do not commit `.env` or paste API keys into source files.

To run AI analysis for an existing scan output directory:

```bash
python main.py --analyze-output-dir outputs/<scan_id>
```

To skip real AI calls while keeping pipeline output files consistent:

```bash
python main.py --target http://localhost:3000 --profile safe --skip-ai
```

When no API key is configured, AutoPenKit uses a safe placeholder analysis instead of failing the whole pipeline.

AI analysis uses `normalized_findings.json` and can batch multiple findings per Gemini request. Configure `ai.batch_size` in `config/settings.yaml` to reduce daily request usage; the default is 5 findings per request. If a batch fails, AutoPenKit falls back to single-finding analysis before writing placeholders.

For each finding, AI output includes safe owner-focused guidance such as:

* Evidence quality and confidence reason
* Defensive validation status
* Affected location and step-by-step verification
* Business impact and priority rationale
* Likely remediation owner and technology context
* Owner remediation steps, defensive config examples, and fix validation steps
* Safe follow-up scan recommendations for an authorized retest

---

## Expected Output

```text
outputs/<scan_id>/
├── validated_target.json
├── scan_metadata.json
├── assets.json
├── raw/
│   ├── targets.txt
│   └── nuclei.jsonl
├── normalized_findings.json
├── ai_analysis.json
└── reports/
```

`scan_metadata.json` includes `scan_status`. Possible current values include:

* `completed`
* `timeout_partial`

When `scan_status` is `timeout_partial`, Nuclei reached the configured timeout, but AutoPenKit still keeps any raw findings already written to `raw/nuclei.jsonl` and continues normalization.

---

## Safety Principle

AutoPenKit follows a **safety-first** design.

By default, only local lab targets should be allowed, such as:

* `localhost`
* `127.0.0.1`

Any external target must be explicitly added to the authorized scope in the configuration file.

---

## Future Work

Possible future improvements include:

* PDF export for generated reports
* Stronger AI summary generation across larger result sets
* Stronger scan profiles such as `medium` and `deep`
* Nmap reconnaissance
* Nikto scanner support
* Shodan integration
* Web dashboard
* Database for scan history

---

## Disclaimer

All scan results generated by AutoPenKit require human validation.

AutoPenKit does **not** replace professional penetration testers.  
It is a learning and automation tool for authorized security testing only.
