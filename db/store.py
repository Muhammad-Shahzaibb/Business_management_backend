"""Queries against the central superadmin database.

The superadmin database holds the organization registry, the email->organization
directory used at login, and the superadmin portal accounts themselves.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

import asyncpg

from db.client import Client, Row
from db.schema import SUPERADMIN_TABLES


class SuperadminStore:
    """Data-access helper bound to the central superadmin pool."""

    def __init__(self, pool_getter: Callable[[], asyncpg.Pool]):
        self._pool_getter = pool_getter
        self.client = Client(pool_getter, SUPERADMIN_TABLES)

    @property
    def _pool(self) -> asyncpg.Pool:
        pool = self._pool_getter()
        if pool is None:
            raise RuntimeError("superadmin database is not connected")
        return pool

    # ------------------------------------------------------------------
    # Organizations
    # ------------------------------------------------------------------
    async def get_org(self, org_id: int) -> Optional[Row]:
        return await self.client.organizations.find_unique(where={"id": org_id})

    async def get_org_by_slug(self, slug: str) -> Optional[Row]:
        return await self.client.organizations.find_unique(where={"slug": slug})

    async def list_orgs(self) -> list[Row]:
        return await self.client.organizations.find_many(order={"id": "desc"})

    # ------------------------------------------------------------------
    # Email -> organization directory
    # ------------------------------------------------------------------
    async def find_orgs_for_email(self, email: str) -> list[dict[str, Any]]:
        """All (org, role) pairs registered for an email address."""
        records = await self._pool.fetch(
            """
            SELECT o.id, o.name, o.slug, o.database_url, o.status, d.role_id
            FROM org_directory d
            JOIN organizations o ON o.id = d.org_id
            WHERE d.email = $1
            ORDER BY d.org_id
            """,
            email,
        )
        return [dict(record) for record in records]

    async def email_registered(self, email: str) -> bool:
        record = await self._pool.fetchrow(
            "SELECT 1 AS one FROM org_directory WHERE email = $1 LIMIT 1", email
        )
        return record is not None

    async def email_registered_to_other_org(self, email: str, org_id: int) -> bool:
        record = await self._pool.fetchrow(
            "SELECT 1 AS one FROM org_directory WHERE email = $1 AND org_id <> $2 LIMIT 1",
            email,
            org_id,
        )
        return record is not None

    async def add_directory(self, email: str, org_id: int, role_id: int) -> None:
        await self._pool.execute(
            """
            INSERT INTO org_directory (email, org_id, role_id)
            VALUES ($1, $2, $3)
            ON CONFLICT (email, org_id) DO UPDATE SET role_id = EXCLUDED.role_id
            """,
            email,
            org_id,
            role_id,
        )

    async def remove_directory(self, email: str, org_id: int) -> None:
        await self._pool.execute(
            "DELETE FROM org_directory WHERE email = $1 AND org_id = $2", email, org_id
        )

    async def remove_directory_by_org(self, org_id: int) -> None:
        await self._pool.execute("DELETE FROM org_directory WHERE org_id = $1", org_id)

    # ------------------------------------------------------------------
    # Superadmin portal accounts
    # ------------------------------------------------------------------
    async def get_superadmin(self, superadmin_id: int) -> Optional[Row]:
        return await self.client.superadmins.find_unique(where={"id": superadmin_id})

    async def get_superadmin_by_email(self, email: str) -> Optional[Row]:
        return await self.client.superadmins.find_unique(where={"email": email})

    async def count_superadmins(self) -> int:
        return await self.client.superadmins.count()

    async def upsert_superadmin(self, name: str, email: str, password_hash: str) -> Row:
        existing = await self.get_superadmin_by_email(email)
        if existing:
            updated = await self.client.superadmins.update(
                where={"id": existing.id},
                data={"name": name, "password": password_hash},
            )
            return updated or existing
        created = await self.client.superadmins.create(
            data={"name": name, "email": email, "password": password_hash}
        )
        if created is None:  # pragma: no cover - insert always returns a row
            raise RuntimeError("failed to create superadmin")
        return created

    async def set_superadmin_password(self, email: str, password_hash: str) -> None:
        await self.client.superadmins.update(
            where={"email": email}, data={"password": password_hash}
        )
