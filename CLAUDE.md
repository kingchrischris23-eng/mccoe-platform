# CLAUDE.md — MCCoE Platform Briefing
> Read this first. This file brings you fully up to speed on the MCCoE Cybersecurity Apprenticeship Platform.

---

## WHO YOU ARE WORKING WITH

**Chris King** — Director, Missouri Cybersecurity Center of Excellence (MCCoE)
- Email: cking@mccoe.org
- Role: Runs a 9-week cybersecurity apprenticeship cohort for students
- Also pursuing GRC certifications: Security+ ✅ → CRISC (target Dec 2026) → CISA → CISM → CISSP
- NSF Grant application in progress (NSF-25-515, deadline 2026-09-28)

---

## WHAT THIS PLATFORM IS

A fully custom cybersecurity apprenticeship platform built in plain HTML/JS/CSS, hosted on GitHub Pages, with Firebase Realtime Database as the backend. No frameworks, no build tools — just files.

**Live URL:** https://kingchrischris23-eng.github.io/mccoe-platform/
**GitHub Repo:** https://github.com/kingchrischris23-eng/mccoe-platform
**Local folder:** C:\Users\ChrisKing\Desktop\mccoe-platform

The cohort runs 9 weeks, Mon–Thu, covering cybersecurity fundamentals through incident analysis and ethical hacking. Current cohort started Mon Aug 31, 2026 at 9AM.

---

## PLATFORM ARCHITECTURE — 5 PILLARS + HUB

### MCCoE_Hub.html — Landing Page
The entry point. Students log in here with name + password. Hub SSO passes `?name=...&id=...` as URL params to all pillar pages so students stay identified across the platform.

- 5-pillar grid layout
- "This Week" checklist panel — auto-detects current week, week dropdown with ◄ Current Week indicator
- Hub SSO: `hubLoginSuccess()` stores name/id in localStorage, passes via URL params
- Admin login: separate path, goes to tracker

### MCCoE_Student_Platform.html — Pillar 1
- Student registration (invite code: MCCoE2026) → admin approval required
- Student IDs auto-assigned: MCCoE-001, MCCoE-002, etc.
- 9-week quiz system (SY0-701 scenario-based, 90 questions)
- XP system: 6 levels, 15 badges, streak tracking, leaderboard
- SY0-701 Acronym Drill: 292 acronyms across all 9 weeks
- SOC Ticket Board: 15 Cedar Creek Industries mock tickets (3 tiers), Kanban triage
- Daily Survey + Weekly Check-In → Firebase mccoe_checkins
- 8 Project submission system → Firebase mccoe_submissions
- Inline curriculum downloads (9 project doc buttons)
- HTB (Hack The Box) score tracking card

### CyberSec_Academy.html — Pillar 2
- 8 curriculum modules (0-based index for ?cur=N deep-linking)
- 150 quiz questions across 15 categories
- SOC Simulator (3 scenarios), Password Checker, Phishing Spotter
- Scores saved to Firebase mccoe_academy
- Deep-link: ?cur=N jumps directly to module N (0=Foundations, 1=Network, 2=Threat, 3=Human Factors, 4=Kali Basics, 5=Nmap/Recon, 6=Secure Dev, 7=Pentest)

### MCCoE_Curriculum.html / Project Docs — Pillar 3
- 8 projects across 4 incidents: Target (1-2), Colonial Pipeline (3-4), SolarWinds (5-6), Equifax (7-8)
- Part 1 = Deep Dive (50 pts), Part 2 = Frameworks & Writing (100 pts) = 600 pts total
- PDF project docs hosted on GitHub Pages
- Key file: Week2_Colonial_Pipeline_2021.docx (Project 3) at C:\Users\ChrisKing\Desktop\
  - Has MITRE ATT&CK Table 6 (6 techniques), Kill Chain Table 5, NIST CSF Table 7
  - Teaching scaffold added to Executive Summary Section 4 (T1078 worked example + 5 scaffold rows)
  - Source doc links in References section (CISA AA21-131A, CEO Senate Testimony, CISA 2-year reflection)

### Pillar4_EthicalHacking.html — Pillar 4
- HTB Pwnbox based (no Docker/admin required)
- Covers 5 pentesting phases
- Links to HTB Academy: Nmap, Service Enumeration
- IppSec YouTube walkthroughs linked

### Pillar5_BlueTeam.html — Pillar 5
- Blue Team Lab: 5 phases of defense
- CTF Challenges: 12 flags across 4 scenarios
- Certificate generation, Live Scoreboard
- Job Readiness Score

### MCCoE_Student_Tracker.html — Admin Only
Password: (ask Chris — stored in tracker HTML)
Admin users: jharbour, cking, cdaniels

**Nav sections and views:**
- Dashboard, Pending Approvals, Students, Attendance
- Surveys (dual format: Daily Survey = rating/confidence/topic; Weekly Check-In = mood/learned/goal)
- Employer Profile, Student Submissions (8 projects, grading)
- Library, Course Documents, Academy Scores, Acronym Scores
- Pentest Lab, HTB Scores, Blue Team Lab, CTF Scores
- SOC Tickets (SLA tracking P1=4h/P2=8h/P3=24h/P4=72h)
- **🗺️ MITRE Mapping** — student MITRE ATT&CK worksheet submissions
- Exec Summary Rubric (digital grader), Cheat Sheet, CTF Answer Key
- Due Dates, Admin Tools

### MITRE_Attack_Map.html — Interactive Learning Tool
- 4-tab tool: Framework / Attack Story / Technique Breakdown / Student Worksheet
- Colonial Pipeline mapped to 7 ATT&CK techniques (T1078, T1133, T1021, T1048, T1490, T1486, T1489)
- Tab 4 is a submittable student worksheet — saves to Firebase mccoe_mitre
- Hub button in header passes name/ID back to Hub
- Linked from Hub Week 3 + Week 4 checklists

### Other HTML files
- MCCoE_CTF.html — CTF challenges
- MCCoE_Scoreboard.html — Live leaderboard
- OSI_CIA_Phases_Framework.html — Interactive diagram (OSI, CIA Triad, 5 Pentest Phases)

---

## FIREBASE

**Project:** mccoe-platform-a9710
**Config:**
```javascript
{
  apiKey: "AIzaSyBpK8uLCD0_m83a1xFiOQVaS1PKWSGcEc8",
  authDomain: "mccoe-platform-a9710.firebaseapp.com",
  databaseURL: "https://mccoe-platform-a9710-default-rtdb.firebaseio.com",
  projectId: "mccoe-platform-a9710"
}
```

**Firebase Paths (all have .read: true, .write: true):**
| Path | What it stores |
|---|---|
| mccoe_registry | Student registrations (name, cohort, assignedId, approved) |
| mccoe_progress | Quiz scores, XP, badges, streak per student |
| mccoe_submissions | 8 project submissions + instructor grades |
| mccoe_logins | Login timestamps per student |
| mccoe_xp | XP and level data |
| mccoe_academy | CyberSec Academy quiz/SOC/phish scores |
| mccoe_checkins | Daily surveys + weekly check-ins |
| mccoe_feedback | Student feedback |
| mccoe_tickets | SOC Ticket Board (Cedar Creek Industries) |
| mccoe_hours | Automated hours tracking |
| mccoe_htb | HTB scores |
| mccoe_blueteam | Blue Team Lab scores |
| mccoe_ctf | CTF challenge scores |
| mccoe_pentest | Pentest lab scores |
| mccoe_schedule | Due dates |
| mccoe_rubric | Executive Summary rubric grades |
| mccoe_acronyms | Acronym drill scores |
| mccoe_library | Resource library |
| mccoe_tracker_students | Tracker-side student data |
| mccoe_mitre | MITRE ATT&CK mapping worksheet submissions |

---

## HUB WEEK CHECKLIST — WEEK → PILLAR MAPPING

```
Week 1: P2 cur:0 (Foundations),    P3 proj:1 (Target Deep Dive)
Week 2: P2 cur:1 (Network),        P3 proj:2 (Target Frameworks)
Week 3: P2 cur:2 (Threat),         P3 proj:3 (Colonial Deep Dive) + MITRE tool + 3 source docs
Week 4: P2 cur:4 (Kali Basics),    P3 proj:4 (Colonial Frameworks) + MITRE reference
Week 5: P2 cur:5 (Nmap/Recon),     P3 proj:5 (SolarWinds Deep Dive)
Week 6: P2 cur:3 (Human Factors),  P3 proj:6 (SolarWinds Frameworks)
Week 7: P2 cur:6 (Secure Dev),     P3 proj:7 (Equifax Deep Dive)
Week 8: P2 cur:7 (Pentest),        P3 proj:8 (Equifax Frameworks)
Week 9: P2 general,                 CTF Challenges
```

**Hub item types in WEEK_TASKS:**
- `p:'p1'` — Student Platform (appends ?name=&id=&week=N)
- `p:'p2-cur'` — Academy with cur:N deep-link
- `p:'p2'` — Academy general
- `p:'p3'` — Opens project submit modal (proj:N)
- `p:'p4'` — Pillar 4 Ethical Hacking
- `p:'p5'` — Pillar 5 Blue Team
- `p:'ctf'` — CTF page
- `p:'tool'` — Internal tool page (appends name/id params), url:field
- `p:'ext'` — External URL, opens as-is in new tab, url:field

---

## KEY CODE PATTERNS

**Hub SSO URL params:** `?name=ENCODED_NAME&id=ENCODED_ID`
All pillar pages read: `new URLSearchParams(window.location.search).get('name')`
localStorage backup: `hub_name`, `hub_id`

**Firebase init pattern (all files):**
```javascript
var _fbDb = null;
try {
  if (!firebase.apps.length) firebase.initializeApp(FIREBASE_CONFIG);
  _fbDb = firebase.database();
} catch(e) {}
```

**Student temp ID (registry key):** generated at registration, stored as `tempId` in localStorage
**Assigned MCCoE ID:** MCCoE-001 format, stored in mccoe_registry/{tempId}/assignedId

**Survey dual format detection:**
- Daily Survey: has `c.rating` field → labeled "📋 Daily Survey — DATE" (green)
- Weekly Check-In: has `c.mood` field → labeled "Week N" (blue)

---

## CURRICULUM DOCUMENTS

All at: C:\Users\ChrisKing\Desktop\ (working copies)
Published PDFs: on GitHub Pages in /mccoe-platform/ folder

| File | Project | Points |
|---|---|---|
| Week1_Target_Breach_2013.docx | Project 1 | 50 |
| Week1b_Target_Breach_Frameworks.docx | Project 2 | 100 |
| Week2_Colonial_Pipeline_2021.docx | Project 3 | 50 |
| Week2b_Colonial_Pipeline_Frameworks.docx | Project 4 | 100 |
| Week3_SolarWinds_2020.docx | Project 5 | 50 |
| Week3b_SolarWinds_Frameworks.docx | Project 6 | 100 |
| Week4_Equifax_2017.docx | Project 7 | 50 |
| Week4b_Equifax_Frameworks.docx | Project 8 | 100 |

Teacher Answer Key DOCX: C:\Users\ChrisKing\Desktop\ (covers all 8 projects)

---

## GIT WORKFLOW

```bash
cd C:\Users\ChrisKing\Desktop\mccoe-platform
git add <files>
git commit -m "description"
git push origin main
```
GitHub Pages auto-deploys on push. No build step needed.
`.nojekyll` file exists in repo root (required for GitHub Pages to serve all files).

---

## IMPORTANT PREFERENCES

- Chris calls the session done with "save and zip it up" → zip mccoe-platform folder to Desktop
- Always update memory (MEMORY.md + session summary file) at end of session
- No comments in code unless absolutely necessary
- No emojis unless Chris asks
- Use python-docx for all Word document edits (Python 3.13 + python-docx installed)
- PowerShell is primary shell on this Windows 11 machine
- When pushing to GitHub, always use `git add <specific files>` not `git add .`
- Pricing context: platform worth $25-35/month self-paced, $75-150/month with instructor cohort, $499-799 one-time cohort fee

---

## BACKUPS

- GitHub: always up to date (push after every session)
- Local zips on Desktop: mccoe_platform_backup_YYYYMMDD.zip
- Claude memory: C:\Users\ChrisKing\.claude\projects\C--Users-ChrisKing\memory\
  - Copy the entire .claude folder to any new machine to restore full context
