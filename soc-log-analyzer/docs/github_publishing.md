# Publishing to GitHub (Windows PowerShell)

Nothing in this project has been pushed anywhere. These steps publish it from your own machine.

## 0. Before you publish

* Replace `[Your Name]` in `LICENSE` and the placeholders in `docs/linkedin_post.md`.
* Confirm there is nothing private: `git status` should list only project files; `reports/` and real logs are ignored.
* Run `python -m pytest` and make sure it passes.

## 1. Initialise Git and make the first commit

```powershell
cd path\to\soc-log-analyzer
git init -b main
git config user.name  "Your Name"
git config user.email "you@example.com"     # or your GitHub noreply address

git add .
git status                                   # review the list before committing
git commit -m "feat: add SOC log analyzer with CSV ingestion, five detection rules and reports"
```

## 2a. Create the repository with GitHub CLI (easiest)

```powershell
winget install --id GitHub.cli                # once, then reopen PowerShell
gh auth login
gh repo create soc-log-analyzer --public --source=. --remote=origin --push `
  --description "Educational SOC tool: detect suspicious authentication activity in CSV logs"
```

## 2b. Or create it in the browser

1. On github.com choose **New repository**, name it `soc-log-analyzer`, leave it **empty** (no README/license).
2. Then:

```powershell
git remote add origin https://github.com/<your-username>/soc-log-analyzer.git
git push -u origin main
```

## 3. After pushing

* Open the **Actions** tab and confirm the *Tests* workflow is green (this is its first real run).
* Add topics: `cybersecurity`, `soc`, `log-analysis`, `python`, `blue-team`.
* Pin the repository on your profile and link it from LinkedIn.

## Suggested commit messages

Use short, imperative messages with a type prefix:

```text
feat: add CSV log parser with row-level validation
feat: add failed-login-by-IP and by-username detectors
feat: add success-after-failures detection with severity escalation
feat: add off-hours and multi-account detection rules
feat: add JSON, CSV and Markdown report generation
feat: add command-line interface with exit codes
test: add boundary tests for thresholds and time windows
ci: add GitHub Actions workflow running pytest
build: add Dockerfile and .dockerignore
docs: add README, detection rules and sample investigation
chore: add MIT license and .gitignore
```

If you want a history like this, make several commits instead of one (`git add <files>` then `git commit`).
