# SOC Log Analyzer

A small, dependency-free Python tool that reads authentication logs (CSV), detects **suspicious
login patterns**, explains every alert, and writes JSON, CSV and Markdown reports.
It is a **learning and portfolio project** that shows how a SOC analyst turns raw logs into
something reviewable.

> **Not production-ready.** It does not detect every attack, and an alert is a lead for human
> review, never proof of an attack or a compromised account. All sample data is **synthetic**.

## Table of contents
1. [Objectives and learning outcomes](#objectives-and-learning-outcomes)
2. [Features](#features)
3. [Architecture and workflow](#architecture-and-workflow)
4. [Prerequisites](#prerequisites)
5. [Installation (Windows PowerShell)](#installation-windows-powershell)
6. [Usage](#usage)
7. [Example output](#example-output)
8. [Detection rules and thresholds](#detection-rules-and-thresholds)
9. [Testing](#testing)
10. [Docker](#docker)
11. [GitHub Actions](#github-actions)
12. [Known limitations](#known-limitations)
13. [Roadmap and future improvements](#roadmap-and-future-improvements)
14. [Ethical and legal considerations](#ethical-and-legal-considerations)
15. [شرح بالعربية (Arabic explanation)](#شرح-بالعربية-arabic-explanation)

## Objectives and learning outcomes

* Understand what authentication events look like and which patterns analysts care about
  (brute force, password spraying, success-after-failure, off-hours access).
* Practise **detection engineering**: thresholds, time windows, severity, and false positives.
* Practise clean Python: type hints, separation of parsing / detection / reporting, validation of untrusted input.
* Practise testing (pytest, boundary conditions), containers (Docker) and CI (GitHub Actions).
* Learn to communicate findings carefully: *what was observed* versus *what is proven*.

## Features

* **Log ingestion** from CSV with column validation, UTC normalisation of timestamps, and graceful handling of malformed rows (skipped, counted, and listed with line numbers).
* **Five configurable detection rules** (thresholds and windows in `config/detection_rules.json`).
* **Severity** LOW / MEDIUM / HIGH / CRITICAL with documented rules and a plain-English explanation per alert.
* **IP handling** with Python's `ipaddress` module: validation and type (private, public, documentation, loopback, ...). No lookups, no reputation scoring.
* **Reports:** JSON (alerts + supporting events), CSV (alerts), Markdown (readable summary), each with the analysis timestamp and input filename; summary counts; recommended defensive actions per alert type.
* **CLI** with meaningful exit codes, Docker image, and CI workflow.
* Read-only and offline: no network code at all.

## Architecture and workflow

```
CSV log --> log_parser --> events --> detectors (+ config) --> alerts --> reporter --> JSON / CSV / Markdown
              |                                                               ^
              +--------------- malformed rows + counts -----------------------+
```

| Module | Role |
|---|---|
| `src/log_parser.py` | Validates and normalises input. Knows nothing about rules. |
| `src/config.py` | Loads and validates thresholds and business hours. |
| `src/detectors.py` | Pure detection logic and severity rules. No file access. |
| `src/reporter.py` | Builds and writes the three reports. |
| `src/main.py` | Command-line interface and exit codes. |

More detail: [docs/architecture.md](docs/architecture.md).

## Prerequisites

* Python **3.11 or newer** (`py --version` in PowerShell)
* Git (to clone / publish)
* Optional: Docker Desktop for the container workflow

The analyzer needs **no third-party packages**. `pytest` is only needed to run the tests.

## Installation (Windows PowerShell)

```powershell
git clone https://github.com/<your-username>/soc-log-analyzer.git
cd soc-log-analyzer

# Create and activate a virtual environment
py -3.11 -m venv .venv          # use "py -m venv .venv" if you have a newer Python
.\.venv\Scripts\Activate.ps1

# If activation is blocked by execution policy, allow it for this window only:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Usage

Run all commands from the repository root.

```powershell
# Check a log file without analysing it
python -m src.main validate --input logs\sample_auth.csv

# Analyse and write reports into .\reports
python -m src.main analyze --input logs\sample_auth.csv --output reports

# Override the failed-login threshold of rules 1 and 2
python -m src.main analyze --input logs\sample_auth.csv --output reports --threshold 5

# Use your own rules file
python -m src.main analyze --input logs\sample_auth.csv --output reports --config config\detection_rules.json
```

Reports written: `soc_report.json`, `soc_alerts.csv`, `soc_summary.md`.

**Exit codes:** `0` success - `2` invalid input (missing/empty file, wrong columns, bad config/arguments;
`validate` also returns 2 when malformed rows exist) - `3` processing error (e.g. output folder not writable).
Check the code in PowerShell with `$LASTEXITCODE`.

**Input format:** header `timestamp,username,source_ip,event_type`; ISO 8601 timestamps
(no timezone = UTC); event types `login_success` / `login_failure`. Lines starting with `#` before the
header are comments. Extra columns are ignored.

> `validate` returns exit code 2 for the sample file on purpose: it contains six deliberately malformed rows.

## Example output

Real output from the bundled synthetic sample (`analysis timestamp` in the reports changes on every run):

```text
Warning: 6 malformed row(s) skipped:
  - Line 52: invalid timestamp 'not-a-timestamp' (expected ISO 8601, e.g. 2026-03-02T09:15:00Z)
  - Line 53: invalid IP address '999.999.1.1'
  - Line 54: missing value(s) for: username
  - Line 55: unknown event type 'login_maybe' (expected login_success or login_failure)
  - Line 56: missing value(s) for: source_ip
  - Line 57: expected at most 4 fields but found 5
SOC Log Analyzer 0.1.0
Input file       : sample_auth.csv
Events analysed  : 58 (failed: 28, successful: 30, malformed rows skipped: 6)
Alerts generated : 8 (CRITICAL: 1, HIGH: 3, MEDIUM: 2, LOW: 2)
Reports written  :
  - reports\soc_report.json
  - reports\soc_alerts.csv
  - reports\soc_summary.md
```

An alert in `soc_summary.md`:

```markdown
### ALERT-0005 - CRITICAL - Successful login after multiple failures

- Subject: `dave`
- First seen: 2026-03-03T02:10:05+00:00
- Events: 4
- Why this alert was generated: A successful login for 'dave' from the same IP address followed 3 failed
  attempts within 15 minutes (threshold: 3). The successful login was outside business hours. This sequence
  can mean a password was guessed, but it can equally be a legitimate user who mistyped their password.
  Verify with the account owner before drawing conclusions.
```

A guided walk-through of all alerts: [docs/sample_investigation.md](docs/sample_investigation.md).

## Detection rules and thresholds

| # | Rule | Default | Severity |
|---|---|---|---|
| 1 | Repeated failed logins from one IP | 5 in 10 min | MEDIUM at threshold, HIGH at 2x |
| 2 | Repeated failed logins against one username | 5 in 10 min | MEDIUM at threshold, HIGH at 2x |
| 3 | Successful login after multiple failures | 3 failures in 15 min | HIGH; CRITICAL if failures >= 2x or success is off-hours |
| 4 | Activity outside business hours | Mon-Fri 08:00-18:00 | LOW; MEDIUM if failures included |
| 5 | Multiple accounts targeted from one IP | 3 users in 10 min | MEDIUM at threshold, HIGH at 2x |

Volume alone never produces CRITICAL. Full details, edge cases and configuration keys:
[docs/detection_rules.md](docs/detection_rules.md).

## Testing

```powershell
python -m pytest
```

The suite uses only synthetic, deterministic data and covers: valid CSV, missing columns, malformed
timestamps, invalid IPs, repeated-failure detection, success-after-failures, severity classification,
empty files, report generation, boundary conditions at thresholds and window edges, configuration
validation, and CLI exit codes.

## Docker

The image runs as a non-root user and needs no network. Windows PowerShell, from the repository root:

```powershell
# Build
docker build -t soc-log-analyzer .

# Make sure the output folder exists
New-Item -ItemType Directory -Force reports | Out-Null

# Run: log folder mounted read-only, reports written to .\reports, no network
docker run --rm --network none `
  -v "${PWD}\logs:/data:ro" `
  -v "${PWD}\reports:/reports" `
  soc-log-analyzer analyze --input /data/sample_auth.csv --output /reports

# Validate only
docker run --rm --network none -v "${PWD}\logs:/data:ro" soc-log-analyzer validate --input /data/sample_auth.csv
```

## GitHub Actions

`.github/workflows/tests.yml` runs on every push and pull request. It checks out the code, installs
Python 3.11 and 3.12 on Ubuntu and Windows, installs `requirements.txt`, runs `pytest`, and then runs a
smoke test of the CLI. It has read-only permissions and uses no secrets or paid services.
Failures show as a red check with the failing test output in the job log.

## Known limitations

* Detects only the five patterns above; slow attacks below the thresholds are invisible.
* Works on CSV in one fixed layout. No syslog, Windows Event Log, or cloud log parsers yet.
* Thresholds are generic; real environments need tuning to reduce false positives.
* Batch analysis of a file: no real-time monitoring and no memory-efficient streaming for very large files.
* IP *type* only: no geolocation, ASN, or threat-intelligence enrichment (deliberately).
* Business hours use one fixed UTC offset (no daylight-saving or per-user schedules).
* Development testing was done on Linux with Python 3.12. Windows, Python 3.11, Docker and the GitHub Actions
  workflow are written to work but were not run by the author of this code before publication; verify them yourself.

## Roadmap and future improvements

- [ ] More input formats (Linux `auth.log`, Windows Security events)
- [ ] Per-user baselines (typical hours and source IPs) instead of one global schedule
- [ ] Impossible-travel style checks using **your own** user-supplied location data
- [ ] Optional allow-list for known scanners / VPN / office addresses
- [ ] Streaming parser for large files and an HTML report
- [ ] Mapping alerts to MITRE ATT&CK techniques (documentation only)
- [ ] Coverage reporting in CI

## Ethical and legal considerations

* Analyse only logs you own or are **authorised** to analyse. Logs contain personal data (usernames, IPs).
* The tool is passive and read-only: no scanning, no probing, no exploitation, no external lookups.
* Do not label a person or an IP address as an attacker based on an alert alone; attribution needs far more evidence.
* Never commit real logs, credentials or tokens to Git. `.gitignore` blocks everything in `logs/` except the synthetic sample.
* Sample data is entirely fictional and uses documentation-reserved IP ranges (RFC 5737).

## شرح بالعربية (Arabic explanation)

**فكرة المشروع:** أداة بلغة بايثون تقرأ سجلات تسجيل الدخول، وتبحث عن أنماط مشبوهة (مثل تخمين كلمات المرور)،
وتكتب تقارير يمكن لمحلل أمني مراجعتها. التنبيه هو **مؤشر يحتاج إلى مراجعة** وليس دليلًا على اختراق.

* **`log_parser.py` (قارئ السجلات):** يقرأ ملف CSV، ويتحقق من الأعمدة والتواريخ وعناوين IP، ويحوّل كل الأوقات إلى UTC.
  الصفوف المعطوبة لا توقف البرنامج، بل تُسجَّل مع رقم السطر.
* **`config.py` (الإعدادات):** يقرأ الحدود (عدد المحاولات) والنوافذ الزمنية وساعات العمل من ملف JSON ويتحقق منها.
* **`detectors.py` (قواعد الكشف):** خمس قواعد: محاولات فاشلة كثيرة من نفس العنوان، أو ضد نفس المستخدم،
  أو دخول ناجح بعد عدة محاولات فاشلة، أو نشاط خارج ساعات العمل، أو استهداف عدة حسابات من نفس العنوان.
  كل تنبيه له درجة خطورة (LOW / MEDIUM / HIGH / CRITICAL) وشرح لسبب ظهوره.
* **`reporter.py` (التقارير):** ينتج تقرير JSON وتقرير CSV وملخصًا بصيغة Markdown، مع وقت التحليل واسم الملف
  وإجراءات الحماية المقترحة.
* **`main.py` (سطر الأوامر):** الأوامر `analyze` و`validate` ورموز الخروج (0 نجاح، 2 مدخلات غير صالحة، 3 خطأ في المعالجة).
* **الاختبارات (`tests/`):** اختبارات pytest ببيانات وهمية تتحقق من الحالات الحدّية، لنطمئن أن التعديلات لا تكسر شيئًا.
* **Docker:** يشغّل الأداة داخل حاوية معزولة، مع قراءة السجلات للقراءة فقط وبدون إنترنت.
* **GitHub Actions:** يشغّل الاختبارات تلقائيًا عند كل `push` و`pull request`.

كل البيانات في المشروع **وهمية**، والمشروع تعليمي وليس جاهزًا للإنتاج.

## License

MIT - see [LICENSE](LICENSE). Replace `[Your Name]` in the license file with your name.
