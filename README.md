# GCIH Lab — Gamified SOC Training Terminal

A gamified GIAC Certified Incident Handler (GCIH) prep app built with **React, Tailwind CSS, and Lucide icons** on Vite. All progress is saved to `localStorage`.

## Run it

```bash
npm install
npm run dev      # http://localhost:5173
npm run build    # production build in dist/
```

## Features

- **Dashboard**: rank/XP HUD, daily streak, per-domain readiness bars, "Drill Weakest Domain", and a 10-question "Quick Triage" drill.
- **Flashcards**: 3D flip cards. `Space` flips, `1`/`2`/`3` rate *Needs Review* / *Familiar* / *Mastered* with spaced-repetition requeueing. Filter by domain and tag.
- **Exam Bank (200 MCQs)**: filter by domain, difficulty, unanswered or missed. *Study Mode* explains the answer and the distractors instantly. *Exam Simulation* is timed, supports flagging, and ends with a per-domain score breakdown.
- **Incident Labs (30)**: split-pane SOC workstation with ticket and evidence on the left and a 5-step investigation on the right. Hints cost 25 XP, and every step has a walkthrough.
- **Bulk Import**: paste or upload JSON, a JS array, or a JS module (`export const x = [...]`) of questions, flashcards, or labs. Items are validated against the schemas below and duplicates (by `id`) are skipped.

### XP and ranks

| Action | XP |
| --- | --- |
| Flashcard rated Mastered (first time) | +20 |
| Correct MCQ | +50 |
| Every 5 correct in a row | +25 bonus |
| Incident Lab closed (first time) | +250 |
| Lab hint | −25 |

Ranks: Tier 1 Triage (0) → Tier 2 Responder (1,500) → Tier 3 Threat Hunter (4,500) → Incident Commander (9,000).

## Content and schemas

| File | Contents |
| --- | --- |
| `src/data/questions_d1.js` | 40 MCQs: IR, PICERL, order of volatility, tcpdump/tshark BPF, Volatility, AI-assisted triage |
| `src/data/questions_d2.js` | 40 MCQs: Nmap signatures, SMB enumeration, Snort/Suricata, Netcat/Socat, covert channels |
| `src/data/questions_d3.js` | 40 MCQs: Kerberoasting, NTLM, spraying, AWS CloudTrail/IAM, Entra ID/M365 IR |
| `src/data/questions_d4.js` | 40 MCQs: SQLi, XSS, SSRF, IDOR, command injection, Apache/Nginx log forensics |
| `src/data/questions_d5.js` | 40 MCQs: Windows/Linux persistence, pivoting, anti-forensics, prompt injection and LLM security |
| `src/data/flashcards.js` | 40 flashcards |
| `src/data/labs.js` | 30 five-step labs |

```js
// Flashcard
{ id, domain, tag, front, back }
// MCQ
{ id, domain, difficulty, scenarioLog, question, options: [4 strings], correctIndex, explanation }
// Lab
{ id, title, domain, difficulty, xpReward: 250, briefing,
  steps: [{ stepNumber, objective, evidence, question, options: [4 strings], correctIndex, hint, walkthrough }] }
```

`domain` is a number from 1 to 5. Not affiliated with GIAC or SANS.
