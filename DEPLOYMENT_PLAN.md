# BugHawk AI 2.0 — Deployment Plan

Date: 2026-11-15  
Status: plan only. Nothing was installed, started, committed, pushed, or deployed.  
`ENVIRONMENT_AUDIT.md` is not in the repository. This plan uses `SOURCE_AUDIT.md` and the current source.

Confirmed facts come from files in the tree. Assumptions and missing information are labeled. No secret values are included.

## Architecture

| Piece | Target | Required for the current API |
| --- | --- | --- |
| Frontend | Vercel | Yes |
| Backend | Render web service | Yes |
| Database | Managed PostgreSQL | Yes for any route that opens a session, including health |
| Redis | Deferred | No application code connects to Redis |
| Celery | Deferred | `app.workers.celery_app` does not exist. Do not create a worker service |

The browser app calls `baseURL: '/api'` (`frontend/src/lib/api.ts`). The Vite proxy to `http://localhost:8000` runs only under `vite dev`. A Vercel static build does not use that proxy. The only production `/api` proxy in the repo is `frontend/nginx.conf`, and it targets the Docker hostname `backend:8000`. Vercel does not read that file.

So a Vercel site and a Render API stay disconnected until one of these exists:

1. A Vercel rewrite from `/api/:path*` to the Render origin, keeping the frontend on relative `/api` (same-origin in the browser).
2. A frontend change to an absolute API base URL.

Neither exists today. Option 1 is the smaller change and does not require editing React code. It still needs a new `frontend/vercel.json`, which is not in the repo. Do not add it until this plan is approved.

## Repository structure and service roots

Repository root: the directory that contains `frontend/`, `backend/`, `docker-compose.yml`, and `.env.example`.

| Service | Root directory | Why |
| --- | --- | --- |
| Vercel | `frontend` | `package.json`, `vite.config.ts`, and `index.html` live here |
| Render | `backend` | `requirements.txt`, `Dockerfile`, and `app/main.py` live here |
| PostgreSQL | managed instance, not a directory | The app reads `DATABASE_URL` |

Do not set either service root to the repository root. Do not deploy `frontend/venv` or `backend/venv`. Both are machine-specific, gitignored, and are not the runtime.

There is no `vercel.json`, `render.yaml`, `Procfile`, `runtime.txt`, `.python-version`, or `.dockerignore`.

## Frontend deployment settings

Confirmed from `frontend/package.json` and `frontend/vite.config.ts`:

| Setting | Value |
| --- | --- |
| Root directory | `frontend` |
| Install command | `npm install` |
| Build command | `npm run build`, which is `tsc && vite build` |
| Output directory | `dist` |
| Dev server port | `5173` (local only) |
| Framework | Vite. Vercel preset: Vite |

`vite.config.ts` does not set `build.outDir`. Vite’s default output is `dist`. The frontend Dockerfile copies `/app/dist`, which matches that default.

Do not use the frontend Dockerfile on Vercel. That Dockerfile runs `pnpm install --frozen-lockfile`, and the repo has no `pnpm-lock.yaml` or `package-lock.json`.

Node.js: `package.json` has no `engines` field. The frontend Dockerfile uses `node:20-slim`. Vite 5.4 supports Node 18+.

**Assumption:** set the Vercel Node.js version to 20 so it matches the Dockerfile. That pin is not in `package.json`.

**Missing:** the production Vercel hostname. It does not exist until the project is created. CORS and any rewrite destination depend on it.

### Frontend config that must be added before a working deploy

Not in the repo. Approval required before creating it.

`frontend/vercel.json` needs two behaviors the current Vite build does not provide:

1. Rewrite `/api/:path*` to `https://<render-service-host>/api/:path*`, so the existing Axios client keeps working.
2. Rewrite other paths to `/index.html`, so React Router routes such as `/findings` and `/scans` load on a direct request. `nginx.conf` does this with `try_files`. Vercel will not.

There is no `VITE_*` API variable. Do not invent one unless the rewrite approach is rejected.

## Backend deployment settings

Confirmed from `backend/Dockerfile`, `backend/requirements.txt`, and `backend/app/main.py`:

| Setting | Value |
| --- | --- |
| Root directory | `backend` |
| Language | Python |
| Version pin that exists in repo | `python:3.11-slim` in the Dockerfile. Requirements comment says `Python 3.11+`. No `runtime.txt` |
| Dependency install | `pip install -r requirements.txt` |
| Application module | `app.main:app` |
| Start command in the Dockerfile | `uvicorn app.main:app --host 0.0.0.0 --port 8000` |
| Container port declared | `8000` |
| Health URL | `GET /api/health` |
| API docs | `GET /api/docs` |
| ReDoc | `GET /api/redoc` |
| OpenAPI | `GET /api/openapi.json` |
| Service info | `GET /` |

**Recommended Render mode:** Docker, using `backend/Dockerfile`, because that is the only start command and Python version pin in the repo.

**Missing for a non-Docker Render service:** the Dockerfile binds port `8000`. A native Render Python service must listen on the platform `PORT` value. This repo has no start command that reads `PORT`. Use Docker, or approve a start-command change before using a native build.

**Unverified build risk:** `requirements.txt` installs LangChain, LangGraph, provider SDKs, Celery, Redis, and ReportLab. None of those are imported by `backend/app`. The install is large and may fail or time out on a small Render instance. Removing packages would be a source change and is not part of this plan.

**Unverified startup risk:** `Settings` sets `env_file=".env"`. Render supplies real environment variables and the image should not contain a `.env`. Whether a missing `.env` file aborts process start was not executed.

**Docker context:** there is no `.dockerignore`. `COPY . .` in `backend/Dockerfile` would include `backend/venv` if that directory is present in the build context. The venv is a Windows tree and is not the Linux runtime. Exclude it before a Docker build. That requires a new `.dockerignore`, which is not approved yet.

## PostgreSQL setup

Confirmed:

- The app uses synchronous SQLAlchemy with `psycopg2` (`backend/app/database/session.py`).
- The engine reads `settings.database_url`.
- Local Compose uses `postgres:15-alpine`, database name `bughawk_db`, user `bughawk`.
- Alembic’s `env.py` replaces `sqlalchemy.url` when `DATABASE_URL` is set.
- `alembic.ini` still contains a localhost development URL. Do not rely on that file in production.
- Startup (`lifespan` in `app/main.py`) does not create tables and does not run migrations.
- `backend/alembic/versions/` has no revision files.

**Assumption:** choose managed PostgreSQL 15 so the major version matches Compose. The application code does not pin a server version.

**Missing:** the managed hostname, database name, username, and password. Render’s PostgreSQL service provides these. Copy the connection URL into the web service as `DATABASE_URL`. Do not paste it into git, this document, or chat.

If the provider URL starts with `postgres://`, store the `postgresql://` form. The engine URL in this repo is a `postgresql://` URL. A `postgres://` scheme was not tested.

The engine pool is `pool_size=10` and `max_overflow=20`. Confirm the managed plan allows that many connections. A small plan can refuse new connections. No code change is proposed here.

## Environment variable table

Set these on the Render web service. Do not commit them. Do not paste `.env.example` into Render: that file sets `APP_ENV=development`, `APP_DEBUG=true`, and `DEMO_MODE=true`, and it contains development database credentials.

Generate `APP_SECRET_KEY` and `JWT_SECRET_KEY` in the host’s secret store. They must be long random values. This plan does not supply them.

| Variable | Production value | Required now | Source |
| --- | --- | --- | --- |
| `APP_ENV` | `production` | Yes | Code default is `development`. Production logging uses JSON only when this is `production` |
| `APP_DEBUG` | `false` | Yes | Code default is already `false`. Example file sets `true`. `true` turns on SQL echo |
| `APP_SECRET_KEY` | new random secret, host only | Yes | Code default is an insecure placeholder |
| `JWT_SECRET_KEY` | different new random secret, host only | Yes | Same placeholder class. No login route uses it yet |
| `JWT_ALGORITHM` | `HS256` | No | This is the code default |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | No | This is the code default. Unused until auth exists |
| `ALLOWED_ORIGINS` | `https://<vercel-hostname>` | Yes, once the hostname exists | Code default is `http://localhost:5173,http://localhost:3000`. No trailing slash. One origin, or comma-separated origins with no spaces required (spaces are stripped) |
| `DATABASE_URL` | managed `postgresql://` URL | Yes | Code default is a localhost development URL. Replace it |
| `LLM_PROVIDER` | `demo` | Yes for current behavior | Code default is `demo`. Any other value with `DEMO_MODE=false` makes `/api/agents/*` return HTTP 503. There is no LangGraph client |
| `DEMO_MODE` | `true` | Yes for current behavior | Code default is `true`. `is_demo` is true if this is true **or** `LLM_PROVIDER` is `demo` |
| `LLM_MODEL` | leave unset | No | Unused by current agent code |
| `OPENAI_API_KEY` | leave unset | No | Do not place a live key. Nothing calls OpenAI |
| `ANTHROPIC_API_KEY` | leave unset | No | Nothing calls Anthropic |
| `GOOGLE_API_KEY` | leave unset | No | Nothing calls Gemini |
| `REDIS_URL` | leave unset | No | Nothing connects. Code default is localhost and is harmless only because it is unused |
| `CELERY_BROKER_URL` | leave unset | No | No worker |
| `CELERY_RESULT_BACKEND` | leave unset | No | No worker |
| `SUBFINDER_PATH` | leave unset | No | No scanner runner |
| `NUCLEI_PATH` | leave unset | No | No scanner runner |
| `SEMGREP_PATH` | leave unset | No | No scanner runner |
| `ZAP_API_URL` | leave unset | No | No scanner runner |
| `ZAP_API_KEY` | leave unset | No | Do not set a live key |
| `RATE_LIMIT_REQUESTS` | leave unset | No | No middleware reads it |
| `RATE_LIMIT_WINDOW_SECONDS` | leave unset | No | No middleware reads it |
| `DEMO_ADMIN_EMAIL` | leave unset | No | No login route |
| `DEMO_ADMIN_PASSWORD` | leave unset | No | Do not copy the example file’s password |
| `POSTGRES_USER` | leave unset on the web service | No | Compose only. The managed URL already contains the user |
| `POSTGRES_PASSWORD` | leave unset on the web service | No | Compose only |
| `POSTGRES_DB` | leave unset on the web service | No | Compose only |

Vercel needs no environment variables for the current frontend, because the API base URL is hardcoded to `/api` and there is no `import.meta.env` usage in `src/`.

## Database initialization

Safest path with the code that exists today: **do not let production startup create tables.** It does not, and it should stay that way until a reviewed migration exists.

`alembic upgrade head` cannot create the schema. `backend/alembic/` contains `env.py` and `script.py.mako` only.

Tables defined on `Base.metadata`, from `backend/app/models/__init__.py`:

`users`, `projects`, `authorized_scopes`, `assets`, `scan_jobs`, `security_findings`, `finding_evidence`, `agent_executions`, `attack_paths`, `remediation_suggestions`, `security_reports`, `audit_logs`.

### Approved sequence, after you allow the migration file

1. From `backend/`, against a disposable local or staging database, generate one initial revision: `alembic revision --autogenerate -m "initial schema"`.
2. Read the generated file. Confirm it creates only those tables and does not connect to production.
3. Commit that file under `backend/alembic/versions/`. This plan does not create it.
4. On Render, after `DATABASE_URL` is set and before users are sent to the site, run a one-off command from the `backend` root: `alembic upgrade head`.
5. Confirm the tables exist in the managed database.
6. Only then keep the web service running.

`env.py` reads `DATABASE_URL` from the environment. The one-off shell must have that variable. Do not use the URL inside `alembic.ini`.

**Known follow-on failure after tables exist:** `POST /api/projects` sets `owner_id` to `demo-user-id`. Nothing inserts that user. The insert will violate the `projects.owner_id` foreign key. Health and read endpoints can still succeed on an empty database. Seeding a user is a code or data change and is not approved.

**Do not** point the managed database at the localhost URL in `alembic.ini`.  
**Do not** run scanners as part of initialization.  
**Watch for:** an Alembic config error if the managed password contains a `%` character. `env.py` passes the URL through Alembic’s config object, which uses interpolation. That failure mode was not executed.

## CORS

Confirmed in `backend/app/main.py`:

- `allow_origins` is the split `ALLOWED_ORIGINS` list.
- `allow_credentials` is `True`.
- `allow_methods` and `allow_headers` are `*`.
- The origin list is not `*`. With credentials enabled, an allow-all origin would be invalid. Keep an explicit list.

Production `ALLOWED_ORIGINS` must be the real Vercel origin, for example `https://<project>.vercel.app`, with scheme, host, and no path or trailing slash. Add a custom domain only after it exists. Do not leave `http://localhost:5173` in the production value.

If the Vercel rewrite is used, the browser talks to the Vercel origin and Vercel calls Render. Those browser calls are same-origin, so CORS is not what connects the UI to the API. Set `ALLOWED_ORIGINS` anyway so a direct browser call to Render is limited to the Vercel site, and so production does not keep the localhost default.

A rewrite does not exist yet. Until it does, the deployed UI will request `/api` on the Vercel host and receive the SPA or a 404, not the Render API.

## Deployment blockers

These block a correct first deploy. Hosting accounts and a git remote were not checked, because no terminal commands were run.

1. **No API route from Vercel to Render.** Axios uses `/api`. Production Vite output has no proxy. `vercel.json` is absent.
2. **No SPA fallback on Vercel.** Direct loads of client routes need an index rewrite. Only `nginx.conf` has that behavior, and Vercel will not use it.
3. **No database revision.** Tables are not created on startup. `alembic upgrade head` has nothing to apply.
4. **Project create cannot succeed after tables exist** until a real `users` row matches `demo-user-id`.
5. **Every API route is unauthenticated.** A public Render URL is an open write API. That is the current source. Deploying it publishes that behavior.
6. **Python port pin exists only in Docker.** A native Render start command that listens on `$PORT` is not in the repo.
7. **No lockfile.** `npm install` on Vercel is not reproducible. The frontend Docker build is not a fallback; frozen pnpm install fails.
8. **`npm run build` runs `tsc` first.** TypeScript errors fail the Vercel build. The build was not run.
9. **Demo AI is the only AI path that returns 200.** Setting a provider key does not enable LangGraph. Setting `DEMO_MODE=false` and a non-demo provider returns 503.
10. **UI data pages send `project_id=demo-project-id`.** Nothing seeds that project. Overview and Assets substitute client-side numbers when the API fails. Those numbers are not production data.
11. **Public docs.** `/api/docs` is enabled with no auth. Decide whether the first deploy leaves that public.
12. **No `.dockerignore`.** A Docker build from a workspace that contains `backend/venv` uploads that tree.

Redis and Celery are not blockers. Leave them undeployed.

## Deployment sequence

Stop after each step until the expected result is confirmed. Do not run this sequence until you approve it.

1. **Approve the file changes this plan still needs.** At minimum: `frontend/vercel.json` (API rewrite and SPA fallback) and `backend/alembic/versions/<initial>.py` after you allow generation. Optional: `backend/.dockerignore` excluding `venv`. No application behavior edits are included unless you approve them separately.
2. **Put the repository where Vercel and Render can read it.** This plan does not push.
3. **Create managed PostgreSQL.** Use a PostgreSQL 15 plan whose connection limit can cover pool size 10 plus overflow 20, or accept that the pool settings may be too large for the plan. Copy the `postgresql://` URL into a password manager. Do not send it in chat.
4. **Create the Render web service.** Root `backend`. Environment Docker. Dockerfile path `backend/Dockerfile` relative to the repo, with root directory `backend` (Render then uses `Dockerfile` inside that root). Instance port `8000`. Health check path `/api/health`. Add the environment variables from the table. Do not add Redis or a worker.
5. **Generate and review the initial migration locally, then run `alembic upgrade head` once** in a Render shell that has `DATABASE_URL`. Confirm the twelve tables exist.
6. **Deploy the Render service.** Expected: `GET /` returns the platform JSON. `GET /api/health` returns `"database": "connected"`. A database error string inside a 200 body means the URL or network rule is wrong.
7. **Create the Vercel project.** Root `frontend`. Install `npm install`. Build `npm run build`. Output `dist`. Node 20. Add `vercel.json` before this deploy if step 1 was approved. The rewrite destination is the Render HTTPS origin from step 6, with no trailing slash.
8. **Set Render `ALLOWED_ORIGINS` to the exact Vercel origin** from step 7. Redeploy or restart Render so the process reloads settings (`get_settings` is cached for the process lifetime).
9. **Run the post-deployment checks below.** Do not announce success from a green Vercel build alone.

## Minimum post-deployment checks

| Check | Expected result | Failure means |
| --- | --- | --- |
| `GET https://<render-host>/` | JSON with `"docs": "/api/docs"` and `"health": "/api/health"` | Process did not start |
| `GET https://<render-host>/api/health` | `"status": "ok"` and `"database": "connected"` | `DATABASE_URL`, SSL, or network |
| `GET https://<render-host>/api/docs` | OpenAPI page loads, if you left docs public | Routing or startup |
| Vercel site `/` | The BugHawk shell renders | Build output or SPA fallback |
| Browser request for `/api/health` on the Vercel origin | Same health JSON as Render, not `index.html` | Rewrite missing or pointed at the wrong host |
| Direct load of `/findings` on Vercel | The findings page, not a platform 404 | SPA fallback missing |
| `GET /api/projects` | `[]` or a list, not a database-programming error | Tables were not created |
| `POST /api/projects` with a name | **Expected to fail** with a server error until a user row exists | This is a known source defect, not proof the database is down |
| `POST /api/agents/chat` with a message | HTTP 200 and `"is_demo": true` | Provider was switched off demo without an agent implementation |
| Overview numbers after a failed API call | Treat as synthetic. The page states it is a demo | Do not record those counts as live findings |
| Render service list | No Redis and no Celery worker | Extra services are out of scope |
| Logs | No stack trace on `/api/health`. SQL echo is off | `APP_DEBUG` was left true |

Do not run Subfinder, Nuclei, Semgrep, ZAP, or any scan against a real target as a deployment check. Creating a scan row only inserts a `pending` job. It does not execute tools, and it still requires a project and an authorized scope.

## Rollback

| Layer | Action |
| --- | --- |
| Vercel | In the Vercel deployment list, promote the previous successful deployment. If this is the first deployment, disable or delete the project. The static site holds no database |
| Render web | Roll back to the previous image in the Render deploy history, or suspend the service. Suspending stops the public API immediately |
| Environment | Changing a variable does not rewrite git. Remove the bad variable and restart. Settings load at process start |
| PostgreSQL | If `alembic upgrade head` was the first migration and the data is disposable, downgrade with `alembic downgrade base` from the backend root **only after** the revision file has a `downgrade()` and you have confirmed the target is the managed database. If no migration was applied, there is nothing to roll back |
| Secrets | Rotating `APP_SECRET_KEY` or `JWT_SECRET_KEY` invalidates any future tokens. No tokens are issued today. Do not put the old or new value in git |

Do not drop the managed database as a routine rollback. Do not reuse the development password from `.env.example` or `alembic.ini` while restoring.

## What this deploy will not provide

Even after the blockers above are cleared, the running system still has no login, no scanner execution, no LangGraph analysis, no risk scores, no generated remediation rows, no PDF reports, and no seeded demo project. AI responses in demo mode are canned and must be treated as demo data. Attack Paths and Agent Activity are hardcoded in the frontend and will look populated on Vercel with the API disconnected.
