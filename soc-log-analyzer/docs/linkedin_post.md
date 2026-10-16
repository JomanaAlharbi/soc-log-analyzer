# LinkedIn Portfolio Package

Replace every `[placeholder]`. Do not add results you have not actually achieved.

## Main post

I just finished **SOC Log Analyzer**, a Python project I built to learn how security analysts turn raw
authentication logs into something they can investigate.

What it does:
- Reads login logs (CSV), validates them, and safely skips malformed rows
- Applies 5 configurable detection rules: repeated failures from one IP or against one account, a successful
  login after several failures, off-hours activity, and one IP targeting multiple accounts
- Assigns LOW to CRITICAL severity and explains *why* each alert fired, without claiming it proves an attack
- Writes JSON, CSV and Markdown reports with recommended defensive actions

Built with the Python standard library, tested with pytest (including threshold and time-window edge cases),
packaged with Docker, and checked by GitHub Actions CI.

The biggest lesson: detection is about trade-offs. A lower threshold catches more, but also flags more
innocent users who simply mistyped a password. That is why every alert is worded as a lead to review, not a verdict.

All data in the repo is synthetic. It is a learning project and not a production tool.

Code and documentation: [GitHub link]
I'd welcome feedback from anyone working in SOC or detection engineering: [specific question you want to ask].

#CyberSecurity #SOC #BlueTeam #Python #DetectionEngineering #InfoSec #GitHub #Docker #Pytest #LearningInPublic

## Shorter alternative

Built **SOC Log Analyzer**, a Python tool that finds suspicious login patterns (brute force, password spraying,
success-after-failures, off-hours access) and writes explained JSON/CSV/Markdown reports.
Standard library only, pytest-tested, Docker + GitHub Actions. Synthetic data, built for learning.
[GitHub link]

#CyberSecurity #SOC #Python #BlueTeam #InfoSec

## CV project description

**SOC Log Analyzer** (Python, pytest, Docker, GitHub Actions) - Personal project. Command-line tool that parses
authentication logs, applies five configurable detection rules, classifies alert severity, and generates JSON, CSV
and Markdown incident-style reports. [GitHub link]

## Technical achievements (CV bullets)

* Designed a modular Python tool that separates log parsing, detection logic and reporting, with five detection rules whose thresholds and time windows are configurable via a validated JSON file.
* Wrote a pytest suite covering malformed input, empty files, severity classification and threshold/time-window boundary conditions, and added a GitHub Actions workflow that runs it automatically on every push and pull request.
* Hardened the tool for untrusted input: strict validation with the `ipaddress` module, UTC timestamp normalisation, spreadsheet-formula neutralisation in CSV output, and a Docker image that runs as non-root with read-only log mounting.

Add measurable results only if they are true, for example: "Tested on [N] log files / [N] events" or "[N] tests passing" (run `python -m pytest` and use the real number).

## Interview questions and sample answers

**1. Why did you build this project, and what problem does it solve?**
I wanted to understand how a SOC analyst moves from raw logs to an actionable alert. The tool takes authentication
logs, finds a few well-known suspicious patterns, and explains each one, so I could practise detection logic,
severity decisions and report writing. It is a learning project, not a replacement for a SIEM.

**2. How do you decide the thresholds, and how do you handle false positives?**
The defaults (for example 5 failures in 10 minutes) are reasonable starting points, not universal truths, so they
live in a config file. In a real environment I would tune them against normal behaviour. To limit false-positive
harm, each alert explains the innocent alternatives (a mistyped password, a shared NAT address) and nothing is
labelled "malicious" from an IP alone.

**3. How does the "successful login after failures" rule work, and why does it matter?**
For each username, the detector tracks recent failures. When a success arrives, it counts failures in the previous
time window; if there are at least three, it raises an alert and then resets the count. It matters because a
success after guessing is the point where a password attack might have worked. It is HIGH by default, and CRITICAL
if there were many failures or the login was outside business hours. It still needs human confirmation.

**4. How did you test it, and what edge cases did you consider?**
I used pytest with synthetic, deterministic data. I tested the boundaries explicitly: one event below the threshold
(no alert), exactly at the threshold (alert), exactly at the window edge (inclusive), and one second beyond it (no
alert). I also tested malformed timestamps, invalid IPs, missing columns, empty files, and report generation.
Honest limitation: tests prove the logic works on the cases I thought of, not that it catches every attack.

**5. What are the limitations, and what would you improve next?**
It only covers five patterns and one CSV format, uses global thresholds, and cannot see slow attacks or successful
first-try logins with stolen credentials. Next I would add more log formats such as Linux `auth.log`, per-user
baselines, an allow-list for known scanners and VPNs, and mapping alerts to MITRE ATT&CK in the documentation.

## Short Arabic explanation for interviews / شرح مختصر بالعربية

"مشروعي اسمه SOC Log Analyzer، وهو أداة بلغة بايثون تقرأ سجلات تسجيل الدخول وتبحث عن أنماط مشبوهة مثل كثرة
المحاولات الفاشلة من نفس العنوان، أو دخول ناجح بعد عدة محاولات فاشلة، أو نشاط خارج ساعات العمل. تعطي كل تنبيه
درجة خطورة وشرحًا لسببه، وتنتج تقارير JSON وCSV وMarkdown. لا أدّعي أن التنبيه يثبت وجود هجوم، بل هو مؤشر يحتاج
إلى مراجعة المحلل. كتبت اختبارات تلقائية بـ pytest، وجهّزت Docker وGitHub Actions. البيانات كلها وهمية، والمشروع
تعليمي وليس جاهزًا للإنتاج. تعلمت منه كيف أوازن بين اكتشاف أكثر عدد من التهديدات وتقليل الإنذارات الكاذبة."
