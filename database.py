"""Public database facade - the rest of the app imports from here.

The database is **Supabase Postgres** (no Prisma):

* ``connect_db()``      connects the central *superadmin* pool (its connection
                        string is the only DB credential in .env) and applies
                        ``database/superadmin_schema.sql``;
* ``get_db()``          returns a query client for the organization that owns
                        the current request (set from the JWT by the auth
                        dependencies);
* ``superadmin_store()`` returns the helper used for the organization
                        registry / login directory / superadmin accounts.

Organization pools are created lazily from the Supabase credentials stored in
the superadmin database (see db.pools.ensure_org_pool).
"""

from __future__ import annotations

from typing import Optional

from config import settings
from db import pools as pool_manager
from db.client import Client
from db.pools import OrgContext
from db.provision import apply_superadmin_schema
from db.schema import SUPERADMIN_TABLES, TENANT_TABLES
from db.store import SuperadminStore


def _superadmin_client() -> Client:
    return Client(pool_manager.superadmin_pool, SUPERADMIN_TABLES)


def _tenant_client(org_id: int) -> Client:
    return Client(lambda: pool_manager.org_pool(org_id), TENANT_TABLES)


_store: Optional[SuperadminStore] = None


async def connect_db() -> Client:
    """Connect to the central superadmin database and ensure its schema."""
    global _store
    pool = await pool_manager.connect_superadmin(settings.SUPERADMIN_DATABASE_URL)
    await apply_superadmin_schema(pool)
    _store = SuperadminStore(pool_manager.superadmin_pool)
    return _superadmin_client()


async def disconnect_db() -> None:
    """Close every pool (superadmin + all organizations)."""
    global _store
    await pool_manager.close_all_pools()
    _store = None


async def ensure_connected() -> None:
    """Make sure the central superadmin pool is up (reconnect if needed)."""
    if not pool_manager.superadmin_connected():
        await connect_db()


def superadmin_store() -> SuperadminStore:
    """Access point for the central database (orgs, directory, superadmins)."""
    if _store is None:
        raise RuntimeError("superadmin database is not connected - call connect_db() first")
    return _store


def superadmin_client() -> Client:
    """Raw query client for the central superadmin database."""
    return _superadmin_client()


def get_db() -> Client:
    """Query client for the organization that owns the current request.

    Must be called from within a request whose auth dependency has resolved
    the organization (``set_current_org``). Raises otherwise, which surfaces
    as a clear 500 instead of silently hitting the wrong database.
    """
    context = pool_manager.get_current_org()
    if context is None:
        raise RuntimeError(
            "no organization in request context - this endpoint must depend on "
            "get_current_user/get_current_admin"
        )
    return _tenant_client(context.org_id)


def get_org_client(org_id: int) -> Client:
    """Explicit client for one organization (pool must already exist)."""
    return _tenant_client(org_id)


async def ensure_org_pool(org_id: int, database_url: str) -> None:
    """Create/refresh the connection pool of an organization."""
    await pool_manager.ensure_org_pool(org_id, database_url)


def set_current_org(org_id: int, database_url: str) -> None:
    """Bind the current request to an organization's database."""
    pool_manager.set_current_org(org_id, database_url)


def get_current_org() -> Optional[OrgContext]:
    """Organization bound to the current request (or None)."""
    return pool_manager.get_current_org()


async def close_org_pool(org_id: int) -> None:
    """Drop the pool of an organization (used when credentials change)."""
    await pool_manager.close_org_pool(org_id)
