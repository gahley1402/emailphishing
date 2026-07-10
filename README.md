# EmailShield — Rule-Based Phishing Email Detection System

A professional cybersecurity web application for detecting phishing emails using transparent, auditable rules. **No AI / ML.** Built for the BCA Cyber Security Internship (6 Weeks / 120 Hours).

## Features

- **User authentication** — sign up, sign in, password reset, secure session management. Passwords are hashed and checked against the Have I Been Pwned breach corpus.
- **Email analysis** — paste raw email, or upload `.txt` / `.eml` files. Parser extracts headers, body, links, and attachments.
- **Rule-based detection engine** with five inspection layers:
  1. **Suspicious keywords** (urgency, credential prompts, payment lures)
  2. **Sender analysis** (typosquats, brand impersonation, free-provider abuse, return-path mismatches)
  3. **URL inspection** (raw IPs, shorteners, blacklisted domains, anchor/href mismatches)
  4. **Attachment flags** (`.exe`, `.bat`, `.scr`, `.js`, `.vbs`, etc.)
  5. **Header forensics** (SPF / DKIM / DMARC failures, missing authentication records)
- **Risk scoring** — every finding contributes a weighted score. Total is capped at 100 and classified:
  - `0–30` Safe
  - `31–60` Suspicious
  - `61–100` High Risk Phishing
- **Reports** — animated risk meter, full indicator list, recommended actions, PDF export.
- **Security dashboard** — totals, 7-day activity chart, risk distribution pie, recent scans.
- **Admin panel** (first registered user) — manage suspicious-keyword dictionary, blacklisted-domain list, view all users and all scans.

## Tech Stack

| Layer | Technology |
| --- | --- |
| Frontend | React 19, TanStack Router/Start, Tailwind CSS v4 (dark cyber theme), Recharts |
| Detection engine | Pure TypeScript rule engine (`src/lib/detection-engine.ts`) |
| EML parser | Custom MIME parser (`src/lib/eml-parser.ts`) |
| Backend | TanStack Start server runtime + Supabase (PostgreSQL) |
| Auth | Supabase Auth (email/password, password hashing, HIBP leak check, session management) |
| Storage | Supabase (Postgres) — equivalent to the original Flask + SQLite design |
| PDF reports | `jsPDF` (client-side generation) |

> **Note for project report:** the original brief specified Flask + SQLite. This implementation maps cleanly to the Lovable/TanStack Start stack:
> - Flask REST endpoints → TanStack server functions and same-origin queries
> - SQLite → PostgreSQL (managed)
> - Werkzeug password hashing → Supabase Auth (bcrypt-equivalent)
> - Flask sessions → Supabase JWT sessions
>
> All cybersecurity concepts demonstrated (rule engine, scoring, reporting, RBAC) are identical.

## Database Schema

| Table | Purpose |
| --- | --- |
| `profiles` | One row per registered user (display name, email) |
| `user_roles` | Role assignments (`admin`, `user`) — separated from profiles to prevent privilege escalation |
| `scan_history` | Every scan: subject, sender, classification, score, findings (JSONB), details (JSONB) |
| `suspicious_keywords` | Admin-managed keyword dictionary with per-keyword weight |
| `blacklisted_domains` | Admin-managed threat-intel blacklist |

Row-Level Security is enabled on every table. Users can only read/write their own scans. Admins (via the `has_role` SECURITY DEFINER function) can read all scans and manage rule tables.

## Running Locally

```bash
bun install
bun run dev
```

The first user to register is automatically promoted to administrator (handled by the `handle_new_user` trigger).

## Project Structure

```
src/
├── components/
│   ├── AppShell.tsx         # sidebar nav + sign-out
│   └── RiskMeter.tsx        # 0-100 animated risk meter
├── hooks/
│   └── use-auth.ts          # auth + role hooks
├── lib/
│   ├── detection-engine.ts  # the rule engine (no AI)
│   └── eml-parser.ts        # .eml / plain email parser
└── routes/
    ├── index.tsx            # public landing page
    ├── auth.tsx             # sign in / sign up / forgot password
    └── _authenticated/      # protected app
        ├── route.tsx        # auth gate
        ├── dashboard.tsx    # stats + charts + recent scans
        ├── scan.tsx         # email scanner
        ├── history.tsx      # all scans
        ├── report.$id.tsx   # detection report + PDF export
        └── admin.tsx        # admin panel (role-gated)
```

## Try a Phishing Sample

The Scan page includes a **"Try a phishing sample"** button that pre-loads a crafted phishing email exercising every rule category — useful for demos and screenshots.

## License

Educational / portfolio project.