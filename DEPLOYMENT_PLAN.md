# BugHawk AI 2.0 — Deployment notes

Revised: 2026-11-22, from commit `9039e9c`.  
This is a plan. Nothing in this revision was deployed, and no database migration was run. Claims below come from the current files. Commands listed here were not executed for this revision.

## Targets

| Piece | Where | Required by the current API |
| --- | --- | --- |
| Frontend | Vercel, root `frontend` | Yes |
| API | Render Docker service, root `backend` | Yes |
| PostgreSQL | Existing managed database | Yes |
| Redis | Not deployed | No application code connects |
| Worker | Not deployed | `app.workers` does not exist |

The browser uses `VITE_API_BASE_URL` when that build variable is set (`frontend/src/lib/api.ts`). Vercel must set it to the Render origin, with no trailing slash and no `/api` suffix. `frontend/vercel.json` only rewrites routes to `/index.html`. It does not proxy `/api`.

`frontend/nginx.conf` proxies `/api` to the Compose hostname `backend`. Vercel does not read that file.

## Render

| Setting | Value in the repo |
| --- | --- |
| Root directory | `backend` |
| Dockerfile | `backend/Dockerfile` |
| Image | `python:3.11-slim` |
| Start | Leave empty. The image runs `uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}` |
| Health | `GET /api/health` |
| Docs | Disabled when `APP_ENV=production` |

`backend/.dockerignore` excludes virtualenvs and `.env` files. The SQLAlchemy pool is 2 connections plus 2 overflow.

Set these names on the service, not in git: `APP_ENV=production`, `APP_DEBUG=false`, `APP_SECRET_KEY`, `JWT_SECRET_KEY`, `JWT_ALGORITHM`, `ALLOWED_ORIGINS`, `DATABASE_URL`, `DEMO_MODE`, `LLM_PROVIDER`.

Production startup rejects short secrets and a localhost `ALLOWED_ORIGINS`. It forces debug off. `DEMO_MODE` defaults to false, so canned analyst responses are off unless that variable is explicitly true. A non-demo analyst call returns 503 because no provider client exists.

Do not create a new database from the app. Attach the existing managed database. Do not print its URL.

`alembic upgrade head` applies revision `0001_initial`. Startup does not run it. `env.py` reads `DATABASE_URL` and escapes `%`. Do not rely on the localhost URL in `alembic.ini`. Do not run `alembic downgrade` against a database that should keep its rows.

After an approved upgrade, the first account is `python -m app.cli.create_admin` in an interactive shell. There is no public registration.

## Vercel

| Setting | Value |
| --- | --- |
| Root | `frontend` |
| Install | `npm ci` |
| Build | `npm run build` (`tsc && vite build`) |
| Output | `dist` |
| Environment | `VITE_API_BASE_URL` at build time |

`npm run build` has not been recorded as passing in this revision. A TypeScript error fails the Vercel build.

## Compose

`docker-compose.yml` can start Postgres, an unused Redis service, the API, and the nginx frontend. It does not start a worker. The frontend image uses `npm ci` and `package-lock.json`. This plan does not run Compose.

## What a deploy still will not do

Scanning, live model analysis, PDF generation, Redis, and background jobs stay unimplemented. Attack Paths and Agent Activity stay labeled illustrations.

## Checks after a future deploy

| Check | Expected |
| --- | --- |
| `GET /api/health` | 200 and `database` connected, or 503 when the check fails |
| `GET /api/docs` | 404 when `APP_ENV=production` |
| `GET /api/projects` without a token | 401 |
| Vercel route reload, such as `/login` | The SPA, not a platform 404 |
| Browser API calls | The Render origin, not the Vercel host |

Do not treat a green host build as proof of those checks. Do not run scanners against a real target as a deployment test.
