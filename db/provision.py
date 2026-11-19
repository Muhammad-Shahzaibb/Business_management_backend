"""Applies the SQL schemas stored in ``database/*.sql``.

* the **superadmin** schema is applied automatically on backend startup;
* the **tenant** schema is applied when the superadmin creates an
  organization (and again via the "reprovision" endpoint).

All statements are idempotent, so applying them repeatedly is safe.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import asyncpg

from db.pools import create_pool
from db.util import redact

SQL_DIR = Path(__file__).resolve().parent.parent / "database"

TENANT_TABLES = ("users", "categories", "inventory", "sales", "expenses")


def _read_sql(filename: str) -> str:
    path = SQL_DIR / filename
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - packaging problem
        raise RuntimeError(f"could not read SQL file {path}: {exc}") from exc


def superadmin_ddl() -> str:
    return _read_sql("superadmin_schema.sql")


def tenant_ddl() -> str:
    return _read_sql("tenant_schema.sql")


async def apply_superadmin_schema(pool: asyncpg.Pool) -> None:
    await pool.execute(superadmin_ddl())


async def apply_tenant_schema(pool: asyncpg.Pool) -> None:
    await pool.execute(tenant_ddl())


async def tenant_schema_status(pool: asyncpg.Pool) -> dict[str, Any]:
    """Report which tenant objects already exist in a database."""
    records = await pool.fetch(
        """
        SELECT tablename
        FROM pg_tables
        WHERE schemaname = 'public' AND tablename = ANY($1::text[])
        """,
        list(TENANT_TABLES),
    )
    found = {record["tablename"] for record in records}
    tables = {table: table in found for table in TENANT_TABLES}
    sequence = await pool.fetchval("SELECT to_regclass('invoice_seq') IS NOT NULL")
    return {
        "tables": tables,
        "sequence": bool(sequence),
        "ready": all(tables.values()) and bool(sequence),
    }


async def test_database_connection(database_url: str) -> dict[str, Any]:
    """Open a throwaway connection and report latency + schema readiness."""
    started = time.perf_counter()
    pool = None
    try:
        pool = await create_pool(database_url)
        await pool.fetchval("SELECT 1")
        latency_ms = round((time.perf_counter() - started) * 1000, 1)
        status = await tenant_schema_status(pool)
        return {
            "ok": True,
            "message": "Connected successfully"
            + ("" if status["ready"] else " (application schema not applied yet)"),
            "latency_ms": latency_ms,
            "schema_ready": status["ready"],
            "schema_status": status,
        }
    except Exception as exc:
        return {
            "ok": False,
            "message": f"Connection failed: {redact(str(exc))}",
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            "schema_ready": False,
            "schema_status": None,
        }
    finally:
        if pool is not None:
            try:
                await pool.close()
            except Exception:  # pragma: no cover - best effort
                pass
