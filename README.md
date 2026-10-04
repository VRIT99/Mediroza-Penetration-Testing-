# Mediroza-Penetration-Testing-
Black-box penetration test on a simulated hospital web app (Networkwalks) — critical SQL injection → auth bypass, exposed DB backup, weak PDF encryption cracked via offline attacks, and IDOR. Full writeup with PoCs, remediation, and a professional pentest report included.

# 🏥 Mediroza General Hospital — Black-Box Penetration Test Writeup

> **Training Engagement** — Networkwalks Academy, Batch B083, Week 4
> **Target:** `medirozahospital.com` (simulated hospital web application)
> **Test Type:** Black-Box Penetration Test
> **Duration:** 5 Days
> **Tester:** Sahil Hiwale

---

## ⚠️ Disclaimer

This assessment was conducted in a **controlled training environment** provided by Networkwalks Academy, with **explicit written authorization** to test the target. All techniques, payloads, and findings documented below were used strictly within that authorized scope.

**None of this should be applied to any system without explicit, written permission from its owner.** Unauthorized testing of systems you do not own or have permission to test is illegal.

---

## 📋 Table of Contents

- [Project Overview](#-project-overview)
- [Scope & Rules of Engagement](#-scope--rules-of-engagement)
- [Tools Used](#-tools-used)
- [Methodology](#-methodology)
- [Recon & Information Gathering](#1-recon--information-gathering)
- [Finding 1: SQL Injection → Authentication Bypass](#finding-1-sql-injection--authentication-bypass-critical)
- [Finding 2: Exposed Database Backup](#finding-2-sensitive-database-backup-publicly-exposed-critical)
- [Finding 3: Directory Listing Enabled](#finding-3-directory-listing-enabled-medium)
- [Finding 4: Weak PDF Encryption](#finding-4-weak-pdf-encryption-on-patient-reports-high)
- [Finding 5: IDOR in Report Download](#finding-5-insecure-direct-object-reference-idor-low)
- [What Didn't Work (and why that matters)](#-what-didnt-work-and-why-that-matters)
- [Risk Summary](#-risk-summary)
- [Lessons Learned](#-lessons-learned)

---

## 🎯 Project Overview

Mediroza General Hospital is a simulated client built by Networkwalks Academy for a black-box pentest training exercise. The brief was simple on paper, hard in practice: no source code, no credentials, no hints beyond four milestones —

1. Gain unauthorized access to the site and retrieve 3 confidential patient PDF lab reports
2. Crack the encryption on all 3 retrieved files
3. Find a further critical data exposure on the server (staff salaries + shareholder details)
4. Write a professional penetration testing report

This writeup documents the full attack chain — from the first `robots.txt` request to full compromise of patient medical data and internal HR/financial records.

---

## 🔍 Scope & Rules of Engagement

| | |
|---|---|
| **Target** | `https://medirozahospital.com` |
| **Test Type** | Full black-box penetration test |
| **Authorization** | Written authorization provided by Networkwalks for this training engagement |
| **Rules** | Testing limited to the target domain only. No social engineering. No DoS. No testing outside agreed scope. |

---

## 🛠 Tools Used

| Category | Tools |
|---|---|
| Reconnaissance | `subfinder`, Wappalyzer, Google dorking, Wayback Machine |
| Directory/Content Discovery | `gobuster`, `ffuf`, manual browsing |
| Interception & Manipulation | Burp Suite (Proxy, Repeater) |
| SQL Injection Testing | Manual payloads, `sqlmap` |
| Password Cracking | John the Ripper (`pdf2john`), `pdfcrack`, `rockyou.txt` / SecLists wordlists |
| Command Line | `curl` |

---

## 🧭 Methodology

The engagement followed a standard black-box flow: **Recon → Attack Surface Mapping → Vulnerability Identification → Exploitation → Impact Validation → Reporting.**

### 1. Recon & Information Gathering

Started completely passive before touching the app directly:

```bash
subfinder -d medirozahospital.com
```
Only one subdomain surfaced (`www`), so the attack surface was effectively the main application itself.

Next, the basics that most people skip — but shouldn't:

```
https://medirozahospital.com/robots.txt
https://medirozahospital.com/sitemap.xml
```

**`sitemap.xml`** revealed only public marketing pages (`index.html`, `about.html`, `doctors.html`, `contact.html`) — nothing interesting.

**`robots.txt`** told a completely different story:

```
User-agent: *
Disallow: /patient/
Disallow: /staff/
Disallow: /old/
```

This is the classic rookie mistake — `robots.txt` only tells well-behaved search engine crawlers *not to index* a path. It enforces **zero actual access control**. In practice, it's a roadmap for an attacker: *"here are the three folders we don't want you to look in."* So naturally, that's exactly where the investigation went next.

A Wappalyzer scan also confirmed the stack: **pure PHP backend**, **LiteSpeed web server**, no CMS detected — meaning this was custom-coded, not running on a hardened off-the-shelf platform like WordPress.

---

## Finding 1: SQL Injection → Authentication Bypass (CRITICAL)

**Endpoint:** `POST /patient/login.php`
**Parameter:** `username`
**CWE-89**

### Discovery

Manually browsing the disallowed paths from `robots.txt` revealed that `/patient/`, `/staff/`, and `/old/` all had **directory listing enabled** — another server misconfiguration stacking on top of the first one. Inside `/patient/` sat `login.php`, `portal.php`, `download.php`, `logout.php`, and a 244KB `error_log`.

The patient login page's HTML was unremarkable — a standard `username` / `password` POST form. But testing input sanitization immediately paid off. Submitting a single quote (`'`) in the username field returned:

```
Warning: mysqli_query(): You have an error in your SQL syntax; check the 
manual that corresponds to your MySQL server version for the right syntax 
to use near ''' at line 1
```

Raw SQL error, straight to the browser. Classic sign of string concatenation instead of parameterized queries.

### Exploitation

```
Username: admin'-- -
Password: (anything)
```

This closes the string literal and comments out everything after it — including the password check. The backend query effectively collapses to:

```sql
SELECT * FROM users WHERE username='admin'-- -' AND password='whatever'
```

Everything after `--` is ignored by MySQL. **Result: authenticated as the first matching account, with zero valid credentials.**

> Interesting detail: payloads like `' OR '1'='1'-- -` (quote *at the start*, no prefix text) consistently triggered the same SQL error instead of bypassing login — but `admin'-- -` worked cleanly. The app seems to behave differently depending on whether the quote is prefixed with literal text, which is a useful fingerprinting detail for understanding exactly how the query is built.

### Proof of Access

Logging in with `admin'-- -` dropped straight into the patient portal's **"My lab reports"** dashboard, listing three password-protected pathology reports belonging to real (simulated) patients.

### Impact

Full unauthenticated bypass of the patient authentication system. This was the initial foothold for the entire rest of the engagement — every other patient-side finding flows from this one.

### Remediation

- Use parameterized queries / prepared statements (`mysqli` or PDO with bound parameters) — never concatenate user input into SQL.
- Apply least-privilege to the DB account the app connects with.
- Add WAF coverage — notably, the **staff login on this same app was properly protected** (see [What Didn't Work](#-what-didnt-work-and-why-that-matters)), proving the dev team *can* do this correctly, just not consistently.

---

## Finding 2: Sensitive Database Backup Publicly Exposed (CRITICAL)

**Path:** `/old/mediroza_db_backup_2019.sql`
**CWE-538**

### Discovery

Remember that `robots.txt` entry for `/old/`? Browsing there directly (directory listing enabled, same issue as above) revealed exactly one file:

```
mediroza_db_backup_2019.sql
```

No authentication, no access token — just a direct, unauthenticated download.

### What Was Inside

A full MySQL dump of the `mediroza_hr` database, containing two tables:

**`staff`** — 30 full records including:
- Full name, job title, department
- Email, phone number
- **National ID number**
- **Exact monthly salary (ZAR)**
- Date joined

**`shareholders`** — equity/ownership data:
- Shareholder name
- Shares held
- Equity percentage
- Share class

### Impact

This is a textbook unauthenticated data breach. Staff PII (including government ID numbers) and complete salary data for every employee, plus confidential ownership records — all retrievable with a single unauthenticated GET request. Legally and reputationally, this is arguably **worse** than the SQL injection, because it required zero exploitation skill — just knowing where to look.

### Remediation

- Never leave backup files in a web-accessible directory. Store them outside the web root in access-controlled storage.
- Disable directory indexing at the web server level.
- Don't rely on `robots.txt` as a security control — it is explicitly *not* one.

---

## Finding 3: Directory Listing Enabled (MEDIUM)

**Paths:** `/patient/`, `/staff/`, `/old/`
**CWE-548**

All three paths flagged in `robots.txt` had directory listing enabled at the web server level, turning every folder into a browsable file index. This exposed:

- Application source files (`login.php`, `download.php`, `portal.php`, `logout.php`)
- A 244KB `error_log` (potential info leak of internal paths/stack traces — not deeply analyzed in this engagement but flagged for follow-up)
- The database backup from Finding 2

This single misconfiguration was a force-multiplier for everything else in this report — it's the reason the `.sql` backup was even discoverable.

**Fix:** Disable directory indexing globally (`Options -Indexes` on Apache; equivalent on LiteSpeed/OpenResty).

---

## Finding 4: Weak PDF Encryption on Patient Reports (HIGH)

**CWE-521**

After bypassing login (Finding 1), three password-protected pathology reports were downloaded via `/patient/download.php?id=1/2/3`:

| Patient | Lab Ref | Status |
|---|---|---|
| S. Dlamini | LR-2024-1187 | 🔓 Cracked |
| P. Reddy | LR-2024-1192 | 🔓 Cracked |
| E. Thompson | LR-2024-1205 | 🔓 Cracked |

### Cracking Process

Hash extraction:

```bash
perl /usr/share/john/pdf2john.pl patient_report_1.pdf > hash1.txt
```

John the Ripper initially refused to load the hash (`No password hashes loaded`) despite the format being valid and registered (`john --list=formats | grep -i pdf` confirmed `PDF` was supported). Rather than burn more time debugging John's loader, pivoted to a more reliable, purpose-built tool:

```bash
pdfcrack -f patient_report_1.pdf -w /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
```

All three cracked via straightforward dictionary attack against `rockyou.txt`. The passwords recovered speak for themselves:

- `123456`
- `password`
- `!@#$%^&`

Two out of three are literally on every "worst passwords of all time" list. Even the third, while not a dictionary word, was still a trivially weak keyboard-pattern string.

### Impact

Encryption is only as strong as the password protecting it. These PDFs contained full pathology lab results — patient name, DOB, patient ID, referring doctor, detailed test results and flagged abnormal values — "protected" by passwords an attacker can crack in minutes with a free wordlist.

### Remediation

- Never use static/dictionary-guessable passwords for medical document encryption.
- Generate strong, unique, randomly-generated passwords per document, delivered via a verified out-of-band channel (e.g. SMS OTP), not a predictable scheme.

---

## Finding 5: Insecure Direct Object Reference / IDOR (LOW)

**Endpoint:** `GET /patient/download.php?id=`
**CWE-639**

The `id` parameter on the report download endpoint is a small sequential integer with no visible ownership check tying it to the authenticated session.

### Testing

Systematically walked the parameter after authenticating:

```
?id=0   → no result
?id=1   → S. Dlamini's report
?id=2   → P. Reddy's report
?id=3   → E. Thompson's report
?id=4   → no result
?id=-1  → no result
?id=100 → no result
```

In this specific training environment, only 3 patient records exist, which naturally capped the real impact — there was nothing beyond `id=3` to find.

### Why It Still Matters

The *underlying* problem isn't "no extra records exist" — it's that the application appears to validate that you're *logged in*, but not that the record you're requesting actually *belongs to you*. In a real deployment with hundreds or thousands of patients, this exact same code path would let any authenticated (or, combined with Finding 1, *unauthenticated*) user enumerate and download arbitrary patients' confidential lab reports just by changing a number in the URL.

### Remediation

- Enforce server-side ownership checks on every object reference.
- Prefer unguessable identifiers (UUIDs) over small sequential integers for anything referenced in a URL.

---

## 🛡 What Didn't Work (and why that matters)

A good pentest writeup isn't just a list of wins — knowing what's *actually secure* is just as valuable, and it's worth documenting the negative testing as thoroughly as the positive findings.

### Staff Login — Held Up

The staff portal (`/staff/login.php`) got the exact same treatment as the patient login, and then some:

- Manual SQLi payloads (quote injection, `OR 1=1`, comment-based bypass, case-mixing, `/**/` comment-splitting, `/*!...*/` MySQL-specific comments)
- Time-based blind SQLi (`admin' AND SLEEP(5)-- -`) — triggered an **immediate HTTP 403**, not a 5-second delay, indicating active WAF/filtering rather than a vulnerable, slow backend
- Common/default credential guessing against known staff identities pulled from the leaked DB backup
- A full automated `sqlmap` run:

```bash
sqlmap -u "https://medirozahospital.com/staff/login.php" \
  --data="username=admin&password=test" --batch --level=1 --risk=1
```

Final verdict from sqlmap itself:

```
[CRITICAL] all tested parameters do not appear to be injectable.
HTTP error codes detected during run:
400 (Bad Request) - 198 times, 403 (Forbidden) - 15 times
```

**Takeaway:** same application, same developer team, two completely different security postures on two login forms. This is a great illustration of *inconsistent* security practice rather than *absent* security practice — and it's a strong argument in the final report for extending whatever protection exists on `/staff/` to `/patient/` as well.

### Path Traversal — Blocked

Attempted to read `/etc/passwd` via the download endpoint:

```
download.php?id=../../../../etc/passwd
download.php?id=..%2f..%2f..%2f..%2fetc%2fpasswd
download.php?id=....//....//....//....//etc/passwd
```

Every variant — tested via direct browser requests, `curl`, and Burp Suite Repeater with manipulated headers (`X-Forwarded-For`, `X-Original-URL`, method switching) — was blocked at the CDN/WAF layer, either with a hard `403` or a JavaScript-based bot-verification challenge page. No bypass found.

### Reflected XSS — Not Applicable

The app's entire user-input surface is two login forms plus a static (formless) contact page. Script payloads in both login forms were never reflected back in the response — just a fixed, generic error message — so there was no injection point for reflected XSS to exploit.

---

## 📊 Risk Summary

| ID | Finding | Likelihood | Impact | Overall Risk |
|---|---|---|---|---|
| F-01 | SQL Injection → Auth Bypass | High | Critical | 🔴 **Critical** |
| F-02 | Database Backup Exposed | High | Critical | 🔴 **Critical** |
| F-04 | Weak PDF Passwords | High | High | 🟠 **High** |
| F-03 | Directory Listing Enabled | High | Medium | 🟡 **Medium** |
| F-05 | IDOR in Report Download | Medium | Low (in test env.) | 🟢 **Low** |

---

## 🎓 Lessons Learned

A few things from this engagement that'll stick with me:

1. **`robots.txt` is a map, not a wall.** The very first file I checked ended up pointing directly at every sensitive path in the app. Developers need to understand that "hidden" and "secured" are not the same thing.
2. **Stack multiple small misconfigs and you get a breach.** No single finding here was individually catastrophic in isolation except the SQLi — but directory listing + an old backup file + no access control turned into a full HR/financial data leak.
3. **Negative results are still results.** Thoroughly testing the staff login and *confirming* it was secure (rather than assuming and moving on) made the final report far more credible — and gave a clear, evidence-backed recommendation: "whatever you did here, do it there too."
4. **Tool quirks are normal — don't get stuck.** John the Ripper refusing a technically-valid hash file cost some time; switching to `pdfcrack` unblocked progress immediately. Knowing multiple tools for the same job matters.
5. **Weak passwords undermine strong encryption.** The PDF encryption algorithm itself wasn't broken — the *passwords* were. A reminder that crypto is only as strong as its weakest human-chosen input.

---

## 📎 Deliverables

- Full professional PDF penetration testing report (Executive Summary, Scope, Findings, Risk Ratings, Recommendations)
- This technical writeup
- Evidence screenshots for every finding

---

*This project was completed as part of Networkwalks Academy's hands-on VAPT training program (Batch B083). All testing was performed against a training environment built and authorized specifically for this exercise.*
