"""Connection pool management.

Two kinds of pools exist:

* one **central superadmin pool** - the Supabase project whose connection
  string lives in ``SUPERADMIN_DATABASE_URL`` (the only DB credential in
  the repository's .env);
* one **pool per organization** - created lazily from the Supabase
  credentials stored for that organization in the superadmin database.

The organization that owns the current request is kept in a ContextVar so
``database.get_db()`` (a synchronous call used everywhere in the API) can
return the right tenant client.
"""

from __future__ import annotations

import asyncio
import ssl
from contextvars import ContextVar
from typing import NamedTuple, Optional
from urllib.parse import parse_qs, urlunparse, urlparse

import asyncpg

from db.util import redact_url

# Supabase free tier allows plenty of direct connections per project; each
# organization has its own project so a small per-tenant pool is enough.
POOL_MIN_SIZE = 1
POOL_MAX_SIZE = 5
COMMAND_TIMEOUT = 60.0
IDLE_CONNECTION_LIFETIME = 300.0
APPLICATION_NAME = "hisaab-backend"


class OrgContext(NamedTuple):
    """Which organization database the current request should use."""

    org_id: int
    database_url: str


_org_context: ContextVar[Optional[OrgContext]] = ContextVar("org_context", default=None)

_superadmin_pool: Optional[asyncpg.Pool] = None
_org_pools: dict[int, asyncpg.Pool] = {}
_org_urls: dict[int, str] = {}
_pool_lock = asyncio.Lock()


# ---------------------------------------------------------------------------
# URL / SSL handling
# ---------------------------------------------------------------------------
def prepare_dsn(database_url: str) -> tuple[str, Optional[ssl.SSLContext]]:
    """Validate a Supabase connection string and build the SSL context.

    Returns ``(dsn_without_query, ssl_context)``.

    ``sslmode`` semantics follow libpq:
        disable            -> no SSL
        require/allow/prefer (and unset) -> encrypt, do not verify the cert
        verify-ca/verify-full           -> encrypt and verify
    Supabase uses valid certificates, so verification works out of the box;
    the default is deliberately "encrypt without verify" so the backend also
    works against any Postgres that uses a private CA.
    """
    if not database_url or not database_url.strip():
        raise ValueError("Database connection string is empty")

    raw = database_url.strip()
    parsed = urlparse(raw)
    if parsed.scheme not in ("postgresql", "postgres"):
        raise ValueError("Connection string must start with postgresql:// or postgres://")
    if not parsed.hostname:
        raise ValueError("Connection string has no host")

    query = parse_qs(parsed.query)
    sslmode = (query.get("sslmode") or ["require"])[0].lower()

    # Drop the query string: asyncpg does not understand sslmode/other params.
    clean = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

    if sslmode == "disable":
        return clean, None

    if sslmode in ("verify-ca", "verify-full"):
        context = ssl.create_default_context()
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2

    return clean, context


async def create_pool(database_url: str) -> asyncpg.Pool:
    """Create a new pool for a Supabase connection string."""
    dsn, ssl_context = prepare_dsn(database_url)
    try:
        return await asyncpg.create_pool(
            dsn=dsn,
            ssl=ssl_context,
            min_size=POOL_MIN_SIZE,
            max_size=POOL_MAX_SIZE,
            command_timeout=COMMAND_TIMEOUT,
            max_inactive_connection_lifetime=IDLE_CONNECTION_LIFETIME,
            server_settings={"application_name": APPLICATION_NAME},
        )
    except Exception as exc:
        raise RuntimeError(f"could not connect to {redact_url(database_url)}: {exc}") from exc


# ---------------------------------------------------------------------------
# Central superadmin pool
# ---------------------------------------------------------------------------
async def connect_superadmin(database_url: str) -> asyncpg.Pool:
    global _superadmin_pool
    if _superadmin_pool is not None and not _superadmin_pool.is_closing():
        return _superadmin_pool
    _superadmin_pool = await create_pool(database_url)
    return _superadmin_pool


def superadmin_pool() -> asyncpg.Pool:
    if _superadmin_pool is None or _superadmin_pool.is_closing():
        raise RuntimeError("superadmin database is not connected")
    return _superadmin_pool


def superadmin_connected() -> bool:
    return _superadmin_pool is not None and not _superadmin_pool.is_closing()


async def close_superadmin() -> None:
    global _superadmin_pool
    if _superadmin_pool is not None and not _superadmin_pool.is_closing():
        await _superadmin_pool.close()
    _superadmin_pool = None


# ---------------------------------------------------------------------------
# Organization pools
# ---------------------------------------------------------------------------
async def ensure_org_pool(org_id: int, database_url: str) -> asyncpg.Pool:
    """Return the pool for an organization, creating/refreshing it as needed.

    If the stored credentials changed, the old pool is closed and replaced.
    """
    existing = _org_pools.get(org_id)
    if (
        existing is not None
        and not existing.is_closing()
        and _org_urls.get(org_id) == database_url
    ):
        return existing

    async with _pool_lock:
        existing = _org_pools.get(org_id)
        if (
            existing is not None
            and not existing.is_closing()
            and _org_urls.get(org_id) == database_url
        ):
            return existing

        if existing is not None:
            try:
                await existing.close()
            except Exception:  # pragma: no cover - best effort
                pass

        pool = await create_pool(database_url)
        _org_pools[org_id] = pool
        _org_urls[org_id] = database_url
        return pool


def org_pool(org_id: int) -> asyncpg.Pool:
    pool = _org_pools.get(org_id)
    if pool is None or pool.is_closing():
        raise RuntimeError(f"no connection pool for organization {org_id}")
    return pool


async def close_org_pool(org_id: int) -> None:
    pool = _org_pools.pop(org_id, None)
    _org_urls.pop(org_id, None)
    if pool is not None and not pool.is_closing():
        try:
            await pool.close()
        except Exception:  # pragma: no cover - best effort
            pass


async def close_all_pools() -> None:
    for org_id in list(_org_pools.keys()):
        await close_org_pool(org_id)
    await close_superadmin()


# ---------------------------------------------------------------------------
# Current-request organization
# ---------------------------------------------------------------------------
def set_current_org(org_id: int, database_url: str) -> None:
    _org_context.set(OrgContext(org_id=org_id, database_url=database_url))


def get_current_org() -> Optional[OrgContext]:
    return _org_context.get()


def clear_current_org() -> None:
    _org_context.set(None)
