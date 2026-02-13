# DucksRow Backend (Dynamic Outing Planner)

Go backend: Fiber, GORM, PostgreSQL (PostGIS), JWT.

## Prerequisites

- Go 1.21+
- PostgreSQL with [PostGIS](https://postgis.net/install/) extension available

## Environment

| Variable         | Description              | Default     |
|-----------------|--------------------------|-------------|
| `PORT`          | HTTP port                | `8080`      |
| `DATABASE_URL`  | Full Postgres DSN        | (see below) |
| `DB_HOST`       | DB host                  | `localhost` |
| `DB_PORT`       | DB port                  | `5432`      |
| `DB_USER`       | DB user                  | `postgres`  |
| `DB_PASSWORD`   | DB password              | `postgres`  |
| `DB_NAME`       | DB name                  | `ducksrow`  |
| `DB_SSLMODE`    | SSL mode                 | `disable`   |
| `JWT_SECRET`    | Secret for signing JWTs  | (insecure default) |
| `ADMIN_EMAIL`   | Email for super-admin seed (optional) | — |
| `ADMIN_PASSWORD`| Password for super-admin seed (optional) | — |

If `DATABASE_URL` is set, it overrides the `DB_*` variables.

**Super Admin seed:** Set `ADMIN_EMAIL` and `ADMIN_PASSWORD` in `.env` to create an admin user on first startup (only if no admin with that email exists). Use a strong password. To run seed once without starting the server: `go run ./cmd/server -seed-admin`.

## Run

```bash
# From backend/
go run ./cmd/server
```

Create the DB and enable PostGIS first, for example:

```sql
CREATE DATABASE ducksrow;
\c ducksrow
CREATE EXTENSION IF NOT EXISTS postgis;
```

## API (see Postman)

- **Health:** `GET /health`
- **Auth:** `POST /auth/register`, `POST /auth/login`, `POST /auth/logout`
- **Places:** `POST /api/places` (requires `Authorization: Bearer <token>`)
- **Admin:** `GET /admin/stats` (requires JWT with role `admin`; returns `{"message": "Welcome Admin"}`)

Import **`postman/DucksRow Backend.postman_collection.json`** into Postman. Run Login to set the collection variable `token`, then use Create Place to test JSONB payloads.

## Project layout

- `cmd/server` – entrypoint
- `database` – connection, PostGIS extension, migration
- `models` – GORM models (User, PlaceType, Place, Plan, PlanItem) with JSONB and PostGIS
- `handlers` – HTTP handlers (auth, places)
- `routes` – route registration
- `middleware` – JWT protected middleware
- `FUTURE.md` – planned features (social, reviews, media, notifications, payments, etc.)
