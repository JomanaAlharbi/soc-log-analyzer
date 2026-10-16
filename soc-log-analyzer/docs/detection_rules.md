# Detection Rules

All thresholds and windows live in [`config/detection_rules.json`](../config/detection_rules.json).
You can point to another file with `--config`, and override the failed-login
threshold of rules 1 and 2 with `--threshold N`.

> Alerts are **leads for a human to review**. None of these rules proves an attack or a compromise.

## The five rules

| # | Rule ID | What it looks for | Config section | Defaults |
|---|---|---|---|---|
| 1 | `failed_logins_by_ip` | N or more **failed** logins from the **same IP** inside a time window | `failed_login_by_ip` | 5 in 10 min |
| 2 | `failed_logins_by_user` | N or more **failed** logins against the **same username** inside a time window | `failed_login_by_user` | 5 in 10 min |
| 3 | `success_after_failures` | A **successful** login for a username that had N or more failures just before it | `success_after_failures` | 3 in 15 min |
| 4 | `off_hours_activity` | Any login event outside business hours or on a non-business day | `business_hours` | Mon-Fri 08:00-18:00 |
| 5 | `multiple_accounts_from_ip` | Failed logins from one IP against N or more **different** usernames inside a window | `multiple_accounts_from_ip` | 3 users in 10 min |

### Business hours (rule 4)
`start_hour` is inclusive, `end_hour` is exclusive, `business_days` uses Monday=0 … Sunday=6,
and `utc_offset_hours` converts the UTC timestamps in the log to your local time before checking
(for example `2` for UTC+2). With the defaults, 08:00 is inside and 18:00 is outside.
Events are grouped into **one alert per username per local day** to avoid noise.

## Severity rules

| Rule | LOW | MEDIUM | HIGH | CRITICAL |
|---|---|---|---|---|
| 1, 2, 5 (volume rules) | - | count >= threshold | count >= 2 x threshold | never (volume alone is not enough) |
| 3 Success after failures | - | - | default | failures >= 2 x threshold, **or** the successful login was outside business hours |
| 4 Off-hours activity | only successful logins | the day includes at least one failed login | - | - |

For rule 5 the "count" is the number of **distinct usernames**.
Severity is deliberately based only on what is in the log (counts, timing). It is **not** based on
IP reputation or geolocation.

## How matching works

* **Sliding window, inclusive.** Starting from an event, every event within the window
  (including one exactly `window` minutes later) belongs to the group. 5 failures whose first and last events are exactly
  10 minutes apart trigger the default rule; 10 minutes and 1 second apart does not.
* **One burst, one alert.** After a group triggers, scanning resumes *after* that group, so a long
  burst does not create many overlapping alerts. A new burst later creates a new alert.
* **Rule 3** counts failures for the username in the window before the success. Any earlier success
  for that username resets the count. Failures may come from different IPs; the explanation says so.
* Usernames are compared **case-insensitively** (`Alice` = `alice`); the first spelling seen is displayed.
* All timestamps are converted to **UTC** (timestamps without a timezone are assumed to be UTC).
* Input order does not matter; events are sorted before analysis.

## IP address handling

IPs are validated with Python's `ipaddress` module and described as one of:
`documentation`, `private`, `loopback`, `link_local`, `multicast`, `reserved`, `public`.
This describes the *type* of address only. The tool never looks addresses up, never contacts them,
and never labels an address "malicious".

## What the rules cannot see

* Attacks that stay below your thresholds (slow, "low and slow" guessing).
* Stolen credentials used successfully on the first attempt.
* Anything not in the log: the log must be complete and have trustworthy timestamps.
* Events from many different IPs that together target one account (rule 2 catches the volume against
  the account, but not the distributed origin).
