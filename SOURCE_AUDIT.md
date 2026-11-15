# BugHawk AI 2.0 — Source Audit

Audit date: 2026-11-15  
Project root: `C:\Users\Bhanu\Downloads\BugHawAi`  
Method: read-only file inspection. No terminal commands were run. Nothing was installed, started, or tested. Statuses below are based on what the source actually does, not on filenames.

## 1. Project root

The extracted root is `C:\Users\Bhanu\Downloads\BugHawAi`.

```
BugHawAi/
  .env.example
  .gitignore
  docker-compose.yml
  backend/
    Dockerfile
    requirements.txt
    pytest.ini
    alembic.ini
    alembic/env.py
    alembic/script.py.mako
    app/                 FastAPI application
    tests/test_scope_guard.py
    venv/                machine-specific Python 3.11.9 venv (pip + setuptools only)
  frontend/
    Dockerfile
    nginx.conf
    package.json
    vite.config.ts
    src/                 React application
    public/favicon.svg
    venv/                Python venv placed inside the React app by mistake
```

There is no `README.md`. There is no `package-lock.json` or `pnpm-lock.yaml`. There is no `.env` in the tree (only `.env.example`). There is no `backend/alembic/versions/` revision. There is no `app/workers`, `app/agents`, or scanner package.

The virtualenvs were created on another machine (`C:\Users\babaj\Desktop\react\BugHawAi`, Python 3.11.9). They are gitignored and are not a usable install of this project’s dependencies.

## 2. Feature implementation matrix

| Feature | Status | Evidence |
| --- | --- | --- |
| React + TypeScript + Vite UI shell | IMPLEMENTED | `frontend/src` routes, Tailwind theme, Vite proxy to port 8000. Not executed. |
| Page set (overview, assets, scans, findings, analyst, attack paths, remediation, reports, agents, scope, settings) | PARTIALLY IMPLEMENTED | Routes exist. Most pages call the API with a hardcoded `demo-project-id`. Attack paths and agent activity never call the API. |
| Axios API client | IMPLEMENTED | `frontend/src/lib/api.ts` matches the backend paths that exist. |
| Recharts dashboard | PARTIALLY IMPLEMENTED | Overview renders charts from API stats, then substitutes hardcoded numbers when the request fails. |
| React Flow attack paths | MOCK IMPLEMENTATION | `AttackPaths.tsx` renders `DEMO_NODES` / `DEMO_EDGES` only. `AttackPath` table has no API. |
| FastAPI application | IMPLEMENTED | `backend/app/main.py` mounts health, projects, scopes, assets, scans, findings, agents, reports, remediation. Docs are at `/api/docs`, not `/docs`. Not started. |
| Pydantic schemas | IMPLEMENTED | `backend/app/schemas/__init__.py` covers the live routes plus unused auth schemas. |
| SQLAlchemy models | IMPLEMENTED | Users, projects, scopes, assets, scans, findings, evidence, agent executions, attack paths, remediation, reports, audit logs. |
| Alembic migrations | NOT IMPLEMENTED | `env.py` and `script.py.mako` exist. No revision files. Startup does not call `create_all`. |
| PostgreSQL connectivity code | PARTIALLY IMPLEMENTED | Sync engine in `database/session.py`. Health runs `SELECT 1`. No schema is created. |
| Redis | NOT IMPLEMENTED | URL is configured. No application code connects to Redis. |
| Celery worker | BROKEN | Compose runs `celery -A app.workers.celery_app`. That module does not exist. |
| Authentication (JWT, login, roles) | NOT IMPLEMENTED | `core/security.py` and auth schemas exist. No auth router, no `get_current_user`, no route uses them. |
| Project CRUD | PARTIALLY IMPLEMENTED | Create, list, get, patch exist. Create always sets `owner_id="demo-user-id"`, which has no user row and will violate the foreign key once tables exist. No delete. |
| Scope management | IMPLEMENTED | Add, list, deactivate, and validate. Validation uses `ScopeGuardian`. |
| Scope Guardian | IMPLEMENTED | Deterministic host/wildcard/IP checks in `core/scope_guard.py`, with unit tests. Not executed in this audit. |
| Asset import and list | PARTIALLY IMPLEMENTED | List and batch import exist and check scope. There is no single-asset create route. Out-of-scope hosts are still stored. |
| Scan job creation | PARTIALLY IMPLEMENTED | Create validates modules and scope, then stores a `pending` job. Nothing runs the job. |
| Subfinder / httpx / Nuclei / Semgrep / ZAP execution | NOT IMPLEMENTED | Names appear as enums, allowed module strings, and env paths. No subprocess, JSON parser, or normalizer exists. |
| Finding import | PARTIALLY IMPLEMENTED | JSON import stores findings and skips identical hashes. It does not parse scanner output, link assets, set `is_demo`, or mark duplicates as `duplicate`. |
| Duplicate detection | PARTIALLY IMPLEMENTED | Import-time SHA-256 skip only. Dashboard “duplicates” counts `validation_status == duplicate`, which nothing sets. |
| Risk prioritization | NOT IMPLEMENTED | `risk_score` and `risk_factors` columns exist. No code writes them. |
| AI / LangGraph agents | MOCK IMPLEMENTATION | `agents.py` returns canned chat and analysis when `settings.is_demo` is true (the default). Non-demo mode returns HTTP 503. LangGraph is a dependency only. |
| Human-in-the-loop approval | NOT IMPLEMENTED | `AgentStatus.WAITING_HUMAN` exists. No approval endpoint or workflow. |
| Remediation recommendations | PARTIALLY IMPLEMENTED | Read and status update only. Nothing creates a `RemediationSuggestion`. |
| Report generation | PARTIALLY IMPLEMENTED | JSON report is stored in the database and can be downloaded. PDF/HTML formats are named only. `reportlab` is unused. `include_remediation` is ignored. |
| Demo mode labeling | PARTIALLY IMPLEMENTED | Agent responses set `is_demo`. Report text says “SYNTHETIC DEMO DATA” only when `project.is_demo` is true, and nothing sets that flag. Assets page falls back to client mock rows labeled `is_demo: true`. Overview fallback numbers are not individually marked. Agent Activity and Attack Paths are unlabeled synthetic UI. |
| Audit logging | NOT IMPLEMENTED | `AuditLog` model exists. Scope decisions stay in process memory and are not written to the database. |
| Rate limiting | NOT IMPLEMENTED | Settings exist. No middleware uses them. |
| Automated tests | PARTIALLY IMPLEMENTED | `tests/test_scope_guard.py` covers the guardian. No API, database, or frontend tests. Pytest was not run. |
| Docker Compose stack | BROKEN | Compose file is present. Frontend image build requires a missing lockfile. Celery command imports a missing module. Backend image would start an API with no schema. |
| Production deployment docs | NOT IMPLEMENTED | No README, no production compose file, no secret-injection guide beyond `.env.example`. |

## 3. What is actually implemented

### Backend

- FastAPI app with CORS from `ALLOWED_ORIGINS`, a validation error handler, and a generic 500 handler.
- OpenAPI at `/api/docs`, ReDoc at `/api/redoc`, schema at `/api/openapi.json`. Root JSON points at `/api/health`.
- Health check reports version, environment, a database `SELECT 1` result, and demo mode. HTTP status stays 200 even when the database string is an error.
- Project, scope, asset, scan, finding, report, and remediation routes as described in the matrix.
- Scope checks before scan creation and during asset import.
- Structured logging via structlog.
- Password hashing and JWT helpers that no route calls.

### Frontend

- Vite dev server on port 5173, proxying `/api` to `http://localhost:8000`.
- Tailwind theme, layout, sidebar, and a header health probe.
- Live API calls from Overview, Assets, Scans, Findings, Analyst, Remediation, Reports, and Scope.
- Every one of those pages sends `project_id=demo-project-id`. There is no project switcher and no login screen.
- Assets falls back to five synthetic hosts (`*.demo-target.com`) when the API call fails, with `is_demo: true`.
- Overview falls back to fixed counts when the API call fails, under a page banner that says the app is a demo.
- Settings toggles are local React state. Save does not write `.env` or call the API. The banner that says otherwise is incorrect.

### Tests

`backend/tests/test_scope_guard.py` exercises normalization, exact versus wildcard matching, suffix-bypass rejection, and explicit IP allow-listing. It does not need a database. It was not executed.

## 4. Mock and demo behavior

`Settings.is_demo` is true when `LLM_PROVIDER=demo` **or** `DEMO_MODE=true`. Both default to demo. Setting a real provider while leaving `DEMO_MODE=true` still serves mock AI responses.

Demo chat is keyword matching over a few canned paragraphs. Demo analysis matches finding titles containing “Missing Security Headers” or “SQL Injection Indicator”. Other titles get a short placeholder. The SQL-injection demo text includes active verification steps. That conflicts with a passive-only assessment policy and should be rewritten before this text is shown to users.

Nothing seeds a demo user, demo project, demo assets, or demo findings. The UI id `demo-project-id` is not created anywhere in the backend.

## 5. Missing implementations

- LangGraph graph, prompts, structured outputs, and provider clients.
- Scanner runners and JSON normalizers for Subfinder, httpx, Nuclei, Semgrep, and ZAP.
- Celery app, tasks, and result handling.
- Redis client usage.
- Auth routes and route protection.
- Database revision and seed.
- Risk scoring.
- Remediation generation.
- PDF and HTML reports.
- Attack-path API.
- Persisted audit log.
- Rate limiting.
- File upload handling (`uploads/` is created in the image and never used).
- README and local setup docs.

## 6. Broken integrations and startup blockers

1. **No schema.** `alembic upgrade head` has no revisions. The API imports models but never creates tables. The first database write will fail.
2. **Project create cannot succeed after tables exist.** `owner_id="demo-user-id"` references `users.id`, and no user is inserted.
3. **Celery service cannot start.** `app.workers.celery_app` is absent, so `docker compose up` fails on `celery_worker` even if the API image builds.
4. **Frontend image cannot build.** `frontend/Dockerfile` runs `pnpm install --frozen-lockfile` and copies `pnpm-lock.yaml*`. No lockfile is in the tree, so `--frozen-lockfile` fails. `nginx.conf` does exist and is otherwise a reasonable SPA plus `/api` proxy to the Compose service name `backend`.
5. **IP scopes do not authorize IPs.** `ScopeGuardian` allows an IP only through `authorized_ips`. The scopes API never passes stored IP rules into that set, so an authorized IP scope still denies that IP.
6. **Scan jobs never leave `pending`.** Creating a scan does not enqueue work.
7. **`.env` lookup is the process working directory.** `Settings` uses `env_file=".env"`. A server started from `backend/` will not read a `.env` at the repo root unless the variables are already in the environment. Compose injects the root `.env`, so this matters for local uvicorn, not for Compose.
8. **Docs URL differs from the usual FastAPI default.** Use `http://localhost:8000/api/docs`.

## 7. Dependencies

### Frontend (`frontend/package.json`, version 2.0.0)

Declared and used: React 18, React Router 6, Axios, Recharts, `reactflow` 11, Lucide, Tailwind, PostCSS, Autoprefixer, Vite 5, TypeScript 5.6.

Also declared: `clsx`, `date-fns`. `clsx` is used. `date-fns` was not imported by `src/`.

`eslint` 9 is a devDependency and `npm run lint` is `eslint . --ext ts,tsx`. ESLint 9 ignores eslintrc-style flags unless a flat `eslint.config.js` exists. That file is missing, so the lint script is not usable.

No `engines` field. The frontend Dockerfile uses `node:20-slim`. Vite 5 expects Node 18 or newer. Exact installed Node was not checked.

No lockfile, so installs are not reproducible.

`tsconfig.json` has `noEmit: true` while `npm run build` is `tsc && vite build`. `tsc` still typechecks. This was not run.

### Backend (`backend/requirements.txt`)

Pinned and used by the running API surface: FastAPI 0.115.5, Uvicorn 0.32.1, SQLAlchemy 2.0.36, Alembic 1.14.0, psycopg2-binary 2.9.10, Pydantic 2.10.1, pydantic-settings 2.6.1, python-jose, passlib, structlog, python-dotenv.

Declared and unused by application code: Redis, Celery, asyncpg, LangChain, LangGraph, langchain-openai, langchain-anthropic, langchain-google-genai, openai, anthropic, aiohttp, reportlab, jinja2, tenacity, shortuuid, orjson, factory-boy, ruff. `httpx==0.27.2` is the Python HTTP library, not ProjectDiscovery httpx. The security tool `httpx` is not a Python dependency.

AI packages use `>=` ranges. A future install can resolve incompatible LangChain and LangGraph versions. That conflict is not proven until an install is allowed.

`asyncpg` is imported nowhere. `session.py` imports async SQLAlchemy symbols and never uses them. The live engine is synchronous psycopg2.

Python requirement in comments and the backend Dockerfile: 3.11. The unused venv metadata says 3.11.9. The interpreter on this machine was not invoked.

### Compose images

| Service | Image / build | Host port |
| --- | --- | --- |
| PostgreSQL | `postgres:15-alpine` | 5432 |
| Redis | `redis:7-alpine` | 6379 |
| Backend | `backend/Dockerfile` (`python:3.11-slim`) | 8000 |
| Celery | same image, missing module | none |
| Frontend | `frontend/Dockerfile` (`node:20-slim` then `nginx:alpine`) | 5173 mapped to container port 80 |

Compose file format `3.9`. Docker Engine was not checked.

## 8. Environment variables

`.env.example` is the only env file. It contains placeholders, not live credentials. Do not copy its demo password or default database password into production.

| Variable | Required to boot API | Notes |
| --- | --- | --- |
| `DATABASE_URL` | Yes, for any DB call | Default in code matches the example: local Postgres database `bughawk_db`. |
| `APP_SECRET_KEY`, `JWT_SECRET_KEY` | Not for current routes | Code defaults are the string `INSECURE_DEFAULT_CHANGE_IN_PRODUCTION`. |
| `ALLOWED_ORIGINS` | No | Defaults include `http://localhost:5173` and `:3000`. |
| `APP_ENV`, `APP_DEBUG` | No | Example sets debug true. Code default for debug is false. |
| `REDIS_URL`, `CELERY_*` | No, until workers exist | |
| `LLM_PROVIDER`, `DEMO_MODE`, provider API keys | No | Demo path needs no key. A real provider needs its key **and** `DEMO_MODE=false`, and there is still no LangGraph code to call. |
| `SUBFINDER_PATH`, `NUCLEI_PATH`, `SEMGREP_PATH`, `ZAP_API_URL`, `ZAP_API_KEY` | No | Nothing executes these tools. |
| `RATE_LIMIT_*` | No | Unused. |
| `DEMO_ADMIN_EMAIL`, `DEMO_ADMIN_PASSWORD` | No | Unused. No login route. |

External tools required today: none. They become required only after a scanner runner is written. Default scan posture in that future work should stay passive and scope-checked immediately before execution.

## 9. Security weaknesses

These are properties of the current source, not a scan of a running system.

- Every API route is unauthenticated. Anyone who can reach the port can create projects, scopes, scans, and findings.
- Default JWT and app secrets are hardcoded fallbacks.
- `alembic.ini` contains the same development database URL as `.env.example`, including the development password.
- CORS allows credentials for the configured origins. Development origins must not be copied into production.
- Health does not check Redis and does not fail the process when Postgres is down.
- The generic `Exception` handler is broad. Whether it swallows `HTTPException` was not verified at runtime.
- Finding import accepts arbitrary JSON evidence with no size limit.
- Scope validation is enforced at scan-job creation and asset import. There is no second check at execution time because nothing executes. A future worker must validate again immediately before any tool runs.
- Demo analysis text for one canned finding recommends active confirmation steps. That should not ship as user guidance.
- Settings UI implies it can change server secrets. It cannot, which is the safer behavior, but the copy is misleading.
- `frontend/venv` and `backend/venv` are local environments from another user path. They should stay gitignored and should not be treated as the project runtime.

No live API keys were found in source. `.env` is gitignored and is not present.

## 10. Deployment blockers

Do not deploy this tree.

- Frontend Docker build fails without a lockfile.
- Celery container command fails on import.
- Database has no migration, so the API cannot persist data.
- Project creation is wired to a missing user.
- Authentication is absent.
- Debug and demo defaults are on in `.env.example`.
- AI, scanners, and workers are not implemented, so a deployed UI would show empty API data or client-side demo fallbacks.
- No production compose file, HTTPS termination, backup job, or healthcheck on the backend/frontend services (Postgres and Redis do have healthchecks).

## 11. Commands and tests

No commands were executed. No test results exist from this audit. `pytest tests/test_scope_guard.py` is the only automated test suite and remains unverified.

## 12. Milestone 1 conclusion

The repository is a structured skeleton with a real FastAPI surface, a real scope validator, and a React console. Persistence, auth, background work, scanners, and LLM orchestration are not in a runnable state. The next milestone should be environment and dependency validation only: document required Node, Python, Postgres 15, and Redis 7 versions, and list the commands for you to run. No packages should be installed until you approve those commands.
