# BugHawk AI 2.0 — Source status

Revised: 2026-11-22, from commit `9039e9c` on `main`.  
The 2026-11-15 snapshot described a tree without login, without a migration, and without a lockfile. Those statements are no longer true. This file replaces that snapshot.

Method: file inspection. Tests in `backend/tests` were not executed for this revision. Do not treat their presence as a passing run.

## Feature status

| Feature | Status | Evidence |
| --- | --- | --- |
| Login and project ownership | Implemented | `backend/app/api/auth.py`, `backend/app/api/deps.py`. Login and health are public. Other routes require a bearer token. |
| First administrator | Manual command | `python -m app.cli.create_admin`. Not called on startup. No public registration. |
| React app | Implemented | Login, session, project picker, and API pages under `frontend/src`. |
| Attack Paths and Agent Activity | Illustrative | Pages state they are not account data. |
| Settings page | Display only | Does not read or write server configuration. |
| Alembic revision | Present, not applied by startup | `backend/alembic/versions/20261115_0001_initial_schema.py`, revision `0001_initial`. |
| Health | Implemented | `GET /api/health` returns 503 when the database check fails. |
| Scope Guardian | Implemented | Hostname rules and an exact IP scope. Neighboring IPs stay denied. |
| Scanners | Not implemented | Module names are stored on a pending scan job. |
| Worker, Redis, Celery | Not implemented | No `app.workers` module. Compose no longer starts a Celery command. |
| Live AI | Not implemented | Demo mode returns canned text. Any other mode returns 503. Libraries in `requirements.txt` are not imported by `backend/app`. |
| Reports | JSON only | Download returns stored JSON even when the row is labeled PDF. |
| Tests | Present, not run for this revision | `backend/tests/test_scope_guard.py`, `backend/tests/test_auth_guards.py`. No GitHub Actions workflow. |

## Known source gaps

Phase 2 maps API enum strings onto the migration’s member names, authorizes an exact IP scope, checks finding scan ownership, omits request bodies from validation errors, and rejects PDF reports. Those behaviors were not executed in this revision.

- `backend/alembic.ini` still has a localhost SQLAlchemy URL. `env.py` replaces it when `DATABASE_URL` is set.
- Access tokens are stored in browser `localStorage`.
- Login has no rate limit. Viewer role is stored and not enforced as read-only.
