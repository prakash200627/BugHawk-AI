# BugHawk AI 2.0

BugHawk AI is a web application for authorized security assessment work. It stores projects, scopes, assets, scan jobs, findings, remediation notes, and reports, and it keeps each signed-in user inside their own projects.

This repository is the current source. It is not a finished scanner platform. Sections below separate what the code does today from what is only demonstrated, stored, or planned.

## Problem

Security assessment output is scattered across tools, spreadsheets, and chat logs. A reviewer needs one place to record an authorized scope, keep imported results, and see which findings belong to which project. BugHawk is that record, with a login boundary so one account cannot read or change another account’s projects.

## Key features

| Area | What the running code does |
| --- | --- |
| Accounts | Email and password login for a user that already exists. No public registration. |
| Projects | Create, list, read, and update projects owned by the signed-in user. |
| Scope | Store scope rules and check a target with the deterministic Scope Guardian. |
| Assets and findings | Import and list records for an owned project. |
| Scan jobs | Store a job after a scope check. The worker runs Subfinder, httpx, Nuclei, Semgrep, or ZAP when the module list is exactly that tool. Any other list is failed. |
| Reports | Build a JSON report from stored rows and download that JSON. |
| Remediation | Read suggestions and update a suggestion status when a row already exists. |
| Analyst | In demo mode, return canned explanations. Otherwise return HTTP 503. |

## Implementation status

**Implemented**

- React interface with login, a project picker, and pages that call the API for the selected project.
- FastAPI routes for health, login, projects, scopes, assets, scans, findings, reports, remediation, and the analyst endpoints.
- JWT access tokens and per-project ownership checks.
- PostgreSQL models and one Alembic revision, `0001_initial`. Startup does not apply it.
- An interactive command, `python -m app.cli.create_admin`, that hashes a password with the same bcrypt helper as login. It is not run on startup.
- Production startup checks: secrets of at least 32 characters, a non-local `ALLOWED_ORIGINS` list, debug forced off, and interactive API docs disabled.

**Demo or illustrative**

- Analyst chat and analysis when `DEMO_MODE=true`. The text is written in the API module. It is not a model response.
- Attack Paths and Agent Activity. Both pages say they are illustrations and do not load account data.
- The Settings screen. It does not read or write server configuration.

**Stored only**

- A job runs only when its module list is exactly one of `subfinder`, `httpx`, `nuclei`, `semgrep`, or `zap`. Any other list is failed by the worker. Nuclei uses five reviewed header templates. Semgrep uses three reviewed static rules and does not scan until a source archive exists. ZAP runs a passive baseline on HTTPX-verified origins.
- JSON reports are stored and downloaded. PDF and HTML requests are rejected.
- Remediation, attack-path, agent-execution, and audit-log tables exist. The API does not generate those rows, except agent-execution rows written by the demo analyst path.

**Planned, not present**

- A source-upload or authorized repository connection for Semgrep. The scanner interface is present and jobs fail with that missing prerequisite.
- Any worker other than `python -m app.workers.scan_worker`. That process runs Subfinder, httpx, Nuclei, Semgrep, and ZAP.
- A live LangGraph or provider call. Those libraries are listed in `backend/requirements.txt` and are not imported by the application.
- Redis use. The URL is configuration only.
- PDF or HTML rendering.
- Risk scores, duplicate workflow, and durable scope audit rows.

Nothing in this repository was executed as part of writing this file. Test files exist. A green test run is not claimed here.

## Technology stack

| Layer | Choice |
| --- | --- |
| Interface | React 18, TypeScript, Vite 5, Tailwind, Axios, Recharts, React Flow |
| API | FastAPI, Pydantic v2, Uvicorn |
| Data | SQLAlchemy 2, Alembic, PostgreSQL, psycopg2 |
| Auth | bcrypt passwords, HS256 JWT |
| Interface host | Vercel |
| API host | Render, using `backend/Dockerfile` (`python:3.11-slim`) |

## Repository structure

```
README.md
docker-compose.yml          optional local Compose definition; not required to deploy
backend/
  Dockerfile                Render image
  requirements.txt
  alembic/                  revision 0001_initial
  app/                      FastAPI application, including cli/create_admin.py
  tests/                    scope and auth unit tests
frontend/
  Dockerfile                optional nginx image; Vercel does not use it
  package.json
  package-lock.json
  vercel.json               SPA fallback only
  src/                      React application
```

## Architecture

The browser talks to the API with Axios. When `VITE_API_BASE_URL` is set, requests go to `{origin}/api`. When it is unset, requests stay on `/api`, and the Vite dev server proxies that prefix to `http://localhost:8000`. Production on Vercel does not use that proxy. Set `VITE_API_BASE_URL` to the Render origin, without a trailing slash and without `/api`.

Render runs the backend container. The process listens on `$PORT`, or on 8000 when `PORT` is absent. Health is `GET /api/health`. A failed database check returns 503 and does not put the exception text in the response.

PostgreSQL is required for any route that opens a session. The schema comes from Alembic, not from process startup. Redis and a worker are not part of the running API.

```
Browser (Vercel static files)
        |  HTTPS, VITE_API_BASE_URL
        v
FastAPI on Render
        |  SQLAlchemy session
        v
Managed PostgreSQL
```

## Authentication and project isolation

`POST /api/auth/login` and `GET /api/health` are public. Every other route requires `Authorization: Bearer <token>`. A missing or invalid token returns 401.

Project lists are filtered by `owner_id`. A missing project returns 404. A project owned by someone else returns 403. The same check covers scopes, assets, scans, findings, reports, remediation, and analyst calls.

There is no registration route and no default administrator password. The first account is created only when an operator runs `python -m app.cli.create_admin` in an interactive shell after the migration. The password is prompted and is not accepted as an argument. `seed_demo.py` is a manual script, is not called on startup, and refuses `APP_ENV=production`.

Roles are stored. The API does not yet treat a viewer as read-only.

## Environment variables

Copy `.env.example` to `.env` for local API configuration. Do not commit `.env`. Placeholders in the example are not production secrets.

| Name | Role |
| --- | --- |
| `APP_ENV` | `development` or `production`. Production enables the secret, CORS, debug, and docs rules. |
| `APP_DEBUG` | SQL echo outside production. Production forces this off. |
| `APP_SECRET_KEY` | Application secret. Production requires at least 32 characters. |
| `JWT_SECRET_KEY` | Signing key. Production requires at least 32 characters. Login returns 503 when it is empty. |
| `JWT_ALGORITHM` | Default `HS256`. |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | Access-token lifetime. Default 60. |
| `ALLOWED_ORIGINS` | Comma-separated browser origins. Production rejects an empty list and any origin containing `localhost` or `127.0.0.1`. |
| `DATABASE_URL` | `postgresql://` URL. Alembic reads this and escapes `%` for its config parser. |
| `DEMO_MODE` | Canned analyst responses. Defaults to false. Outside production, `LLM_PROVIDER=demo` also enables them. |
| `LLM_PROVIDER`, `LLM_MODEL`, provider API keys | Reserved. No provider client is called. |
| `REDIS_URL`, `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND` | Unused by the application. |
| `SUBFINDER_PATH`, `HTTPX_PATH`, `NUCLEI_PATH`, `SEMGREP_PATH`, `ZAP_PATH` | Program names for the scan worker. The API does not accept a path, rule, or template from a request. `ZAP_API_URL` is not used to reach a public ZAP. |
| `RATE_LIMIT_REQUESTS`, `RATE_LIMIT_WINDOW_SECONDS` | Unused. No limiter is installed. |
| `DEMO_ADMIN_EMAIL`, `DEMO_ADMIN_PASSWORD` | Used only by the manual `seed_demo.py` script. |
| `VITE_API_BASE_URL` | Frontend build setting, in the Vercel project or `frontend/.env`. Not a Python setting. |

`POSTGRES_USER`, `POSTGRES_PASSWORD`, and `POSTGRES_DB` are Compose settings. They are not read by FastAPI.

## Setup for a future developer

These steps are documentation. They are not required to read the source, and this change set does not run them.

Backend, from `backend/`, on Python 3.11:

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Use a disposable database in `DATABASE_URL`. Do not point that URL at a production instance. After the migration, create an account with `python -m app.cli.create_admin` in a terminal that can prompt.

Frontend, from `frontend/`:

```bash
npm ci
npm run dev
```

Leave `VITE_API_BASE_URL` unset so the Vite proxy is used. `npm run build` is `tsc && vite build` and writes `dist`. `npm run lint` runs ESLint 9 with `eslint.config.js`. That config uses the JavaScript support already installed with ESLint. It does not parse `.ts` or `.tsx`. TypeScript is checked by `tsc` during `npm run build`. Adding a TypeScript parser would require new packages and a lockfile update, which this phase does not include.

## Testing strategy

`.github/workflows/ci.yml` runs on pull requests to `main` and on pushes to `main`. It uses Ubuntu, Python 3.11, and Node.js 22. Backend installs `backend/requirements.txt`, runs Ruff, then pytest. The job sets `DATABASE_URL` to a localhost test URL and does not start PostgreSQL, because the current tests do not open a database. A test process refuses a non-local database host. Frontend runs `npm ci`, `npx tsc --noEmit`, `npm run lint`, and `npm run build`. The workflow does not deploy and does not read repository secrets.

- `pytest` for `backend/tests`. The current tests cover Scope Guardian behavior and a few auth and health cases with a stand-in database session. They do not need the production database.
- A later job may start an empty Postgres service and apply `0001_initial`. That database must be created by the job and destroyed with the job.
- `npm ci`, `npx tsc --noEmit`, `npm run lint`, and `npm run build` for the frontend.

Do not describe those commands as passed until a run has recorded a result.

## Scanner worker

The API stores a scan job and returns. It does not run Subfinder, httpx, Nuclei, Semgrep, or ZAP. A second process, `python -m app.workers.scan_worker`, polls the same database. It claims a pending row with a conditional update from `pending` to `running`, so two workers cannot take the same job. A running job older than that tool's timeout, plus 30 seconds, is marked `failed`. A module list that is not exactly one supported tool is marked `failed` with an explicit message.

| Module | What the worker does |
| --- | --- |
| `subfinder` | Passive name lookup for one in-scope domain. |
| `httpx` | HTTP and HTTPS on ports 80 and 443 for stored assets under that domain. |
| `nuclei` | Five reviewed header templates against HTTPX-verified origins. Results stay unconfirmed. |
| `semgrep` | Reviewed static rules. The job fails until a source archive or authorized repository exists. It does not read arbitrary disk paths or clone a URL. |
| `zap` | Passive baseline of HTTPX-verified origins. The process listens on `127.0.0.1` only. Active scan, spider, and fuzzer actions are not requested. |

When `ZAP_PATH` points at an installed `zap.sh`, the worker starts `java -jar` for the ZAP jar beside that script so the process stays in the foreground and can be stopped. A bare `zap.sh -daemon` call would background itself and leave the worker unable to stop it.

## Deployment architecture

| Piece | Setting |
| --- | --- |
| Render API | Docker web service, root directory `backend`, Dockerfile `Dockerfile`, empty start command so the image uses `$PORT`, health check `/api/health` |
| Render worker | Second service, not a public web service. Dockerfile `backend/Dockerfile.worker`, start command `python -m app.workers.scan_worker`, same `DATABASE_URL` as the API, no published port |
| Database | The existing managed Postgres database. Do not create a second one from the application. |
| Vercel | Root `frontend`, install `npm ci`, build `npm run build`, output `dist` |
| Routing | `frontend/vercel.json` rewrites application paths to `/index.html`. It does not proxy `/api`. |

Render names to set on both services, not in git: `APP_ENV`, `APP_DEBUG`, `APP_SECRET_KEY`, `JWT_SECRET_KEY`, `JWT_ALGORITHM`, `ALLOWED_ORIGINS`, `DATABASE_URL`, `DEMO_MODE`, `LLM_PROVIDER`. The worker also reads `SUBFINDER_PATH`, `HTTPX_PATH`, `NUCLEI_PATH`, `SEMGREP_PATH`, and `ZAP_PATH`. The image sets those paths. `ZAP_API_URL` is not used to reach ZAP. `ALLOWED_ORIGINS` must list the Vercel origin. Production rejects an empty list and any origin containing `localhost`.

Apply the schema only with an approved `alembic upgrade head` against the intended database. Confirm the database name and that `alembic_version` is absent before the first upgrade. Do not run `alembic downgrade` on a database that holds real rows. The downgrade drops the tables.

Create the first administrator only after that upgrade, with `python -m app.cli.create_admin`.

## Access control

Access tokens are HS256 JWTs. Each token has `sub`, `iat`, `exp`, and `type=access`. The default lifetime is `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` (60). The API loads the user row for that `sub` and uses the role stored on the row. A role claim inside the token does not change permissions.

| Role | What the API allows |
| --- | --- |
| Viewer | Read owned projects and run a scope check. Create, update, delete, import, report generation, remediation status changes, and analyst calls return HTTP 403. |
| Analyst | Those writes, only for projects owned by that user. |
| Admin | The same writes as an analyst, only for projects that admin owns. Admin does not skip ownership checks. There is no HTTP API to create users, change roles, or list another account’s projects. The first admin is created with `python -m app.cli.create_admin`. |

Login failures are counted in memory in the current process: 5 per email and 30 per client address inside 15 minutes, then HTTP 429. Another worker or another machine has its own counters. This is not a shared rate limit. Successful sign-in does not add to the counter.

The browser still keeps the access token in `localStorage` and sends `Authorization: Bearer`. HttpOnly cookies were not added. The intended hosts are a Vercel site and a Render API, which are different sites. A cookie that the browser would send requires `SameSite=None` and `Secure`, plus a CSRF token on every state-changing request, plus a frontend that stops storing the bearer token. Shipping the cookie without that CSRF check, or accepting both a cookie and the current localStorage token, would leave a hole. The bearer flow stays until that whole change can be made together.

`alembic.ini` does not contain a database URL. `alembic/env.py` reads `DATABASE_URL` and stops if that variable is missing. It does not print the URL. Health and unhandled-error logs redact connection URLs.

## Current limitations

- Subfinder, httpx, Nuclei, Semgrep, and ZAP run only in `python -m app.workers.scan_worker`, and only when the module list is exactly one of those names. The API request stores the job and does not run the tool. Semgrep reports that no source archive or authorized repository is stored, and it does not scan the server disk. ZAP is a passive baseline of HTTPX-verified origins and binds to 127.0.0.1 inside the worker. Its results stay unconfirmed.
- The worker image is `backend/Dockerfile.worker`. It installs Subfinder 2.17.0, httpx 1.12.0, Nuclei 3.11.1, Semgrep 1.186.0, and ZAP 2.16.0, and uses the same `DATABASE_URL` as the API. The API image does not include those programs. ZAP's port is not published.
- Non-demo analyst calls return 503.
- PDF and HTML reports are rejected. JSON reports are stored and downloaded.
- Access tokens are kept in `localStorage`. A cookie session is not implemented.
- Login limiting applies only inside one process.
- The viewer role is enforced on the API. The interface still shows write controls; those requests return 403.
- On this Windows machine, `npm run build` stops when Application Control blocks `rollup.win32-x64-msvc.node`. The lockfile already includes `@rollup/rollup-linux-x64-gnu` for Ubuntu CI. That policy was not changed.
- The API and worker images have not been built in this tree. The worker image does not publish a ZAP port.

## Roadmap

1. Repository foundation: this documentation, the lint config, and Compose that matches the code.
2. Backend correctness: enum values, scan ownership on import, IP scope rules, and safer error bodies.
3. Frontend quality: label controls and pages that do not change server state.
4. GitHub Actions for Python tests, Ruff, TypeScript, lint, and the production build.
5. One real scanner and a real analyst path, behind the existing scope check.
6. Deployment of the Render service and the Vercel site, including the approved migration and the first administrator.

## Security reporting

Report a vulnerability privately through [GitHub security advisories](https://github.com/prakash200627/BugHawk-AI/security/advisories/new) for this repository. Include the affected path, the impact, and a minimal way to reproduce it. Do not open a public issue for an unfixed authentication, authorization, or data-exposure bug. Do not include live passwords, tokens, or database URLs in the report.
