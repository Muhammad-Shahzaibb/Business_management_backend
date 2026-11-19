"""Prisma-compatible query surface backed by asyncpg.

The rest of the application was written against Prisma's Python client:

    db = get_db()
    rows  = await db.users.find_many(where={...}, order={...})
    row   = await db.users.find_unique(where={"id": 1})
    row   = await db.users.create(data={...})
    rows  = await db.query_raw("SELECT nextval('invoice_seq') as next_val")

This module keeps that exact surface (and the attribute-style row access the
code relies on: ``row.cost_price``) but executes plain SQL against Supabase's
Postgres instead.
"""

from __future__ import annotations

from typing import Any, Callable, Optional, Sequence

import asyncpg

from db.schema import TABLES
from db.translate import compile_insert, compile_order, compile_set, compile_where, coerce_value


class Row:
    """A single result row with attribute access (``row.column_name``)."""

    def __init__(self, data: Any):
        # dict(Record) / dict(dict) -> plain dict
        self._data = dict(data)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        try:
            return self._data[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def keys(self):
        return self._data.keys()

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"Row({self._data!r})"


class Model:
    """Query helper for one table."""

    def __init__(self, table: str, pool_getter: Callable[[], asyncpg.Pool]):
        if table not in TABLES:
            raise ValueError(f"unknown table {table!r}")
        self.table = table
        self.columns = TABLES[table]
        self._pool_getter = pool_getter

    @property
    def _pool(self) -> asyncpg.Pool:
        pool = self._pool_getter()
        if pool is None:
            raise RuntimeError(
                f"no database connection available for table {self.table!r} "
                "(was the organization pool initialised?)"
            )
        return pool

    async def find_many(
        self,
        where: Optional[dict[str, Any]] = None,
        order: Optional[dict[str, Any]] = None,
    ) -> list[Row]:
        params: list[Any] = []
        sql = f'SELECT * FROM "{self.table}"'
        if where:
            sql += " WHERE " + compile_where(self.table, where, params)
        sql += compile_order(self.table, order)
        records = await self._pool.fetch(sql, *params)
        return [Row(record) for record in records]

    async def find_unique(self, where: Optional[dict[str, Any]] = None) -> Optional[Row]:
        rows = await self.find_many(where=where)
        return rows[0] if rows else None

    async def find_first(
        self,
        where: Optional[dict[str, Any]] = None,
        order: Optional[dict[str, Any]] = None,
    ) -> Optional[Row]:
        rows = await self.find_many(where=where, order=order)
        return rows[0] if rows else None

    async def create(self, data: dict[str, Any]) -> Optional[Row]:
        params: list[Any] = []
        columns_sql, values_sql = compile_insert(self.table, data, params)
        sql = f'INSERT INTO "{self.table}" ({columns_sql}) VALUES ({values_sql}) RETURNING *'
        record = await self._pool.fetchrow(sql, *params)
        return Row(record) if record else None

    async def update(
        self,
        where: Optional[dict[str, Any]] = None,
        data: Optional[dict[str, Any]] = None,
    ) -> Optional[Row]:
        params: list[Any] = []
        set_sql = compile_set(self.table, data or {}, params)
        sql = f'UPDATE "{self.table}" SET {set_sql} WHERE '
        sql += compile_where(self.table, where, params)
        sql += " RETURNING *"
        record = await self._pool.fetchrow(sql, *params)
        return Row(record) if record else None

    async def delete(self, where: Optional[dict[str, Any]] = None) -> Optional[Row]:
        params: list[Any] = []
        sql = f'DELETE FROM "{self.table}" WHERE '
        sql += compile_where(self.table, where, params)
        sql += " RETURNING *"
        record = await self._pool.fetchrow(sql, *params)
        return Row(record) if record else None

    async def count(self, where: Optional[dict[str, Any]] = None) -> int:
        params: list[Any] = []
        sql = f'SELECT count(*) AS c FROM "{self.table}"'
        if where:
            sql += " WHERE " + compile_where(self.table, where, params)
        value = await self._pool.fetchval(sql, *params)
        return int(value or 0)


class Client:
    """A database client bound to one connection pool.

    ``pool_getter`` is a callable returning the asyncpg pool to use. For
    tenant requests that is the pool of the organization found in the JWT;
    for the superadmin it is the central pool.
    """

    def __init__(self, pool_getter: Callable[[], asyncpg.Pool], tables: Sequence[str]):
        self._pool_getter = pool_getter
        for table in tables:
            setattr(self, table, Model(table, pool_getter))

    @property
    def _pool(self) -> asyncpg.Pool:
        pool = self._pool_getter()
        if pool is None:
            raise RuntimeError("no database connection available")
        return pool

    @property
    def pool(self) -> asyncpg.Pool:
        """The underlying pool (for DDL / low-level operations)."""
        return self._pool

    async def query_raw(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        """Run raw SQL; returns a list of dicts (used for nextval lookups)."""
        records = await self._pool.fetch(sql, *args)
        return [dict(record) for record in records]

    async def execute_raw(self, sql: str, *args: Any) -> str:
        """Run raw SQL (DDL / multi-statement when called without args)."""
        return await self._pool.execute(sql, *args)
