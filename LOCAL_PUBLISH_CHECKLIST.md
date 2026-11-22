# BugHawk AI 2.0 — Publish checklist

Revised: 2026-11-22.

The 2026-11-15 checklist described a folder that was not yet a git repository and a GitHub project with no commits. That is no longer the case.

Remote: https://github.com/prakash200627/BugHawk-AI  
Branch: `main`

Published commits include:

- `394b51d` Initial commit: BugHawk AI 2.0
- `43fb209` Add initial PostgreSQL schema migration
- `9039e9c` Prepare BugHawk AI for restricted production demo

Do not run `git init` again. Do not force-push. This revision does not create a commit.

## Keep out of git

| Path | Why |
| --- | --- |
| `.env` and other untracked env files | Ignored. `.env.example` and `frontend/.env.example` are templates with placeholders. |
| `backend/venv/`, `backend/.venv/`, `frontend/venv/`, `frontend/node_modules/` | Local environments. Ignored. |
| `__pycache__/`, `dist/`, pytest cache | Generated. Ignored. |

`backend/alembic.ini` is already published and still contains a localhost SQLAlchemy URL. Do not replace it with a production URL. Alembic uses `DATABASE_URL` when that variable is set.

## Before a later commit

Review `git status` and `git diff`. Confirm no env file, virtualenv, or `node_modules` is staged. Do not commit a database URL, token, or password. Do not claim tests passed unless a recorded run passed.
