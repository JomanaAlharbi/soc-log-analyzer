# Sample Investigation (synthetic data)

This walkthrough shows how an analyst might triage the alerts produced from
`logs/sample_auth.csv`. All data is **synthetic**; IPs are from documentation ranges (RFC 5737).
Run it yourself:

```powershell
python -m src.main analyze --input logs\sample_auth.csv --output reports
```

The run produces 8 alerts from 58 valid events (6 malformed rows are skipped and listed).
The IDs below are stable for this file and configuration.

## Triage order

Start with the highest severity, then ask the same questions for each alert:
*What exactly happened? Is there an innocent explanation? What else does the log show? What action is justified?*

### 1. ALERT-0005 - CRITICAL - Successful login after multiple failures (`dave`)

* **Observed:** on 2026-03-03, three failures at 02:10:05, 02:10:50 and 02:11:30 UTC from `192.0.2.44`,
  then a success at 02:12:15 from the same IP, outside business hours (hence CRITICAL).
* **Innocent explanations:** `dave` mistyped a password on a night shift or on-call task.
* **Checks:** Does `dave` normally work at night (ALERT-0004 is the related off-hours alert for the same events)?
  Does the same IP appear elsewhere in the log? (Not in this file.)
* **Reasonable actions:** ask `dave` to confirm; if he cannot, reset the password, revoke sessions, and review
  what the account did after 02:12.
* **What we cannot conclude:** that the account was compromised. The log only shows the sequence.

### 2. ALERT-0001 and ALERT-0002 - HIGH - 12 failures from `203.0.113.50` against `admin`

* **Observed:** 12 failures in about 4.5 minutes (10:00:00-10:04:35 UTC on 2026-03-02) from one IP against one
  username. Rule 1 (by IP) and rule 2 (by user) both fire on the same events; they are two views of one incident.
* **Checks:** Did `admin` log in successfully afterwards? (No success for `admin` appears in this file.)
  Does the account `admin` even exist on the system? Is the IP a known scanner or an internal tool?
* **Reasonable actions:** confirm throttling/lockout works, consider blocking the IP at the firewall once confirmed
  unauthorized, make sure `admin` has MFA or is disabled.

### 3. ALERT-0003 - HIGH - Success after 4 failures (`carol`)

* **Observed:** four failures from `198.51.100.23` (11:20:05-11:22:40), then a success from the same IP at 11:24:10 during business hours.
* **Why not CRITICAL:** 4 < 2 x 3 failures and the success was inside business hours.
* **Checks:** is `198.51.100.23` where `carol` usually connects from? Do earlier `carol` logins use `10.0.0.13` (private
  address)? In this file they do, so a login from a different address deserves a conversation with her.

### 4. ALERT-0006 - MEDIUM - Multiple accounts from `192.0.2.99`

* **Observed:** failures against `alice`, `bob`, `carol` and `erin` within about 2 minutes from one IP, one attempt each.
  Spreading attempts across accounts is a common way to stay under per-account lockout limits ("password spraying").
* **Checks:** did any of those four accounts have a *successful* login from `192.0.2.99`? (No.)

### 5. ALERT-0004, ALERT-0007, ALERT-0008 - off-hours activity

* `dave` (MEDIUM: includes failures), `grace` (LOW: one login at 21:37 UTC) and `svc_backup` (LOW: Saturday login).
* A service account logging in on a weekend may be a scheduled backup; confirm against the job schedule before escalating.

## Malformed rows

Six rows are skipped (bad timestamp, invalid IP, missing username, unknown event type, missing IP, extra field).
In real work you would find out *why*: a broken log source can hide the events you most need to see.

## What a real investigation adds

Correlating with other data (VPN, endpoint and application logs), asking account owners, checking change tickets,
and recording your reasoning. This tool automates only the first step: surfacing patterns worth a look.
