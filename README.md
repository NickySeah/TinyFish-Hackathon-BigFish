# TinyPhish

AI-powered phishing detection that scans suspicious URLs in a real browser, analyzes content with OpenAI, and checks reputation with VirusTotal — all in seconds.

Built for the [TinyFish Hackathon](https://agent.tinyfish.ai).

## How It Works

1. **Paste a suspicious link** — enter any URL and select where you found it
2. **Live browser scan** — TinyFish opens the page in a sandboxed browser and extracts all visible content (streamed live to the UI)
3. **AI + reputation analysis** — OpenAI analyzes the scraped content for phishing indicators while VirusTotal checks domain reputation, both in parallel
4. **Instant verdict** — get a confidence score, detailed explanation, and specific phishing indicators detected

All scan results are persisted to Supabase and accessible via the history dropdown.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 19, TypeScript, Vite, Tailwind CSS 4, shadcn/ui, Framer Motion |
| Backend | FastAPI, Python 3.12, Pydantic |
| Database | Supabase (PostgreSQL) |
| AI | OpenAI (phishing analysis) |
| Browser Automation | TinyFish Agent API (SSE streaming) |
| Threat Intelligence | VirusTotal API |

## Project Structure

```
├── backend/          # FastAPI server — orchestrates all services
│   ├── api.py        # All API endpoints
│   ├── config.py     # Environment/settings management
│   ├── schemas.py    # Pydantic models for scans
│   ├── supabase_client.py
│   └── services/     # Scan persistence service
├── frontend/         # React SPA
│   └── src/
│       ├── pages/    # HomePage (scan form) + ResultsPage
│       ├── components/  # UI components (gauge, risk cards, history)
│       └── lib/      # API client, types, utilities
└── schema/           # Supabase SQL schema
```

## Setup

### Prerequisites

- Python 3.12+
- Node.js 18+
- A [Supabase](https://supabase.com) project
- API keys for: [TinyFish](https://agent.tinyfish.ai/api-keys), [VirusTotal](https://www.virustotal.com/gui/my-apikey), [OpenAI](https://platform.openai.com/api-keys)

### Database

Run the SQL in `schema/schema.sql` in your Supabase SQL editor to create the `scans` and `url_sources` tables.

### Backend

```bash
cd backend
python -m venv .venv
.venv/Scripts/activate  # Windows — use source .venv/bin/activate on Linux/Mac
pip install -r requirements.txt
```

Create `backend/.env`:

```env
VIRUSTOTAL_API_KEY=your_key
OPENAI_API_KEY=your_key
TINYFISH_API_KEY=your_key
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your_service_key
SUPABASE_ANON_KEY=your_anon_key
DATABASE_URL=postgresql://postgres:password@db.your-project.supabase.co:5432/postgres
```

Start the server:

```bash
uvicorn api:app --reload --port 8000
```

API docs available at [http://localhost:8000/docs](http://localhost:8000/docs).

### Frontend

```bash
cd frontend
npm install
```

Create `frontend/.env`:

```env
VITE_API_URL=http://localhost:8000
```

Start the dev server:

```bash
npm run dev
```

Open [http://localhost:5173](http://localhost:5173).

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health check |
| `GET` | `/health/db` | Database connectivity check |
| `POST` | `/tinyfish` | SSE-streamed browser scan |
| `POST` | `/virustotal` | VirusTotal URL reputation |
| `POST` | `/openai` | OpenAI phishing analysis |
| `POST` | `/scans/save` | Persist scan results |
| `GET` | `/scans/history` | Recent scan history |
| `GET` | `/scans/{id}` | Get scan by ID |
| `POST` | `/analyze` | Submit URL for analysis |

## Team

**BigFish** — TinyFish Hackathon