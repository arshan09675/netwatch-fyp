# NetWatch — AI-Powered Network Monitoring System

NetWatch is a real-time network monitoring and security dashboard built as a
Final Year Project. It captures live traffic on the local machine, discovers
devices on the LAN, detects anomalies and threats, and visualizes everything
through a web dashboard. Monitoring data and user accounts are stored in
**Supabase (cloud PostgreSQL)**, with a **local SQLite** fallback for offline
demos.

> **Note:** Packet capture, device scanning, and ARP-based blocking run
> **locally** and require Administrator privileges + Npcap. Only the data
> storage layer is in the cloud.

---

## Features

- **Live traffic monitoring** — per-adapter and total throughput, CPU / memory /
  disk metrics, active connection counts.
- **LAN device discovery** — ARP/ping-based scanning with vendor (OUI) lookup.
- **Anomaly & threat detection** — traffic anomaly detection, DDoS detection,
  dark-web / threat-intel checks, GeoIP lookups.
- **Device blocking** — ARP-spoofing-based block/unblock of LAN devices.
- **Alerts** — severity-rated alerts with acknowledge / resolve workflow.
- **AI predictions** — short-term bandwidth forecasting.
- **Authentication** — JWT login, sessions, OTP, brute-force protection,
  activity logging.
- **Dual storage backend** — Supabase/PostgreSQL (cloud) or SQLite (offline),
  switchable with a single environment flag.

## Tech Stack

- **Backend:** Python, FastAPI, Uvicorn
- **Capture / networking:** Scapy, psutil (requires Npcap + Administrator)
- **Database:** Supabase (PostgreSQL via psycopg2) / SQLite
- **ML:** scikit-learn, NumPy, pandas
- **Frontend:** vanilla HTML / CSS / JavaScript dashboard

---

## Setup

### Prerequisites

- Python 3.10+
- **[Npcap](https://npcap.com/)** installed (required for Scapy packet capture)
- A **Supabase** project (free tier is fine) — only needed for cloud mode
- Windows: ability to run as **Administrator** (required for packet capture,
  scanning, and blocking)

### 1. Install dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Configure environment

Copy the template and fill in your own values:

```bash
# from the backend/ folder
copy .env.example .env        # Windows
# cp .env.example .env        # macOS/Linux
```

Open `backend/.env` and set your Supabase pooler credentials. Paste the
password **exactly as-is** — special characters such as `@` are handled
automatically (no URL-encoding needed):

```ini
USE_SUPABASE=true
SUPABASE_DB_HOST=aws-1-ap-southeast-1.pooler.supabase.com
SUPABASE_DB_PORT=6543
SUPABASE_DB_USER=postgres.<your-project-ref>
SUPABASE_DB_NAME=postgres
SUPABASE_DB_PASSWORD=<your-database-password>
```

> The real `.env` is gitignored and must **never** be committed. Only
> `.env.example` belongs in the repo.
>
> For an **offline demo**, set `USE_SUPABASE=false` — the app will use a local
> SQLite database (`backend/data/netwatch.db`) and create the tables
> automatically, no Supabase required.

### 3. Create the database schema (Supabase mode only)

In the **Supabase dashboard → SQL Editor → New query**, paste the entire
contents of [`supabase_setup.sql`](supabase_setup.sql) and click **Run**. This
creates all tables and indexes. It is safe to run more than once.

### 4. Run the application (as Administrator)

Open your terminal **as Administrator** (packet capture / scanning / blocking
will not work otherwise), then:

```bash
cd backend
python main.py
```

The server starts on **http://localhost:8000**. Open that address in your
browser and log in.

**Default admin (first run):**

| Username | Password    |
| -------- | ----------- |
| `admin`  | `Admin@123` |

> Change this immediately. You can override it before first run by setting
> `ADMIN_USERNAME` / `ADMIN_PASSWORD` / `ADMIN_EMAIL` in `.env`.

---

## Configuration reference

| Variable               | Description                                            |
| ---------------------- | ------------------------------------------------------ |
| `USE_SUPABASE`         | `true` = cloud PostgreSQL, `false` = local SQLite      |
| `SUPABASE_DB_HOST`     | Supabase pooler host (IPv4)                            |
| `SUPABASE_DB_PORT`     | Pooler port (e.g. `6543`)                              |
| `SUPABASE_DB_USER`     | Database user (`postgres.<project-ref>`)               |
| `SUPABASE_DB_NAME`     | Database name (usually `postgres`)                     |
| `SUPABASE_DB_PASSWORD` | Database password (raw — no encoding needed)           |
| `DATABASE_URL`         | Optional single connection string (overrides the above; password must be URL-encoded) |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` / `ADMIN_EMAIL` | Optional default admin override |

---

## Security notes

- Never commit `backend/.env`, the local database (`*.db`), or packet captures
  (`*.pcap`) — these are excluded via `.gitignore`.
- Capture, scanning, and blocking modify/observe live network traffic; only use
  them on networks you own or are authorized to test.

## License

Academic / educational use (Final Year Project).
