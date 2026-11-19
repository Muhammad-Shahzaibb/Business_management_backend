"""Translate the small query dialect used by the API into parameterised SQL.

The API layer uses a Prisma-like surface:

    where={"email": "a@b.c", "role_id": 1}
    where={"id": {"in": [1, 2, 3]}}
    where={"created_at": {"gte": d1, "lt": d2}}
    order={"created_at": "desc"}

This module turns those dicts into a SQL fragment plus a positional
parameter list. Column names are always taken from ``db.schema.TABLES``
(whitelisted) and values are always sent as bound parameters, so user input
can never become executable SQL.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

from db.schema import TABLES

_COMPARISON_OPS = {"gte": ">=", "gt": ">", "lte": "<=", "lt": "<"}


def _quote(identifier: str) -> str:
    # Identifiers only ever come from TABLES (our own schema), never from input.
    return f'"{identifier}"'


def coerce_value(column_type: str, value: Any) -> Any:
    """Convert a Python value to the type asyncpg expects for this column."""
    if value is None:
        return None

    if column_type == "numeric":
        if isinstance(value, Decimal):
            return value
        if isinstance(value, bool):
            raise TypeError("boolean is not a valid numeric value")
        try:
            # str() first so float artifacts (0.1 + 0.2) don't leak into money.
            return Decimal(str(value))
        except (InvalidOperation, ValueError) as exc:
            raise TypeError(f"cannot convert {value!r} to numeric") from exc

    if column_type in ("int", "smallint"):
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            return int(value)
        if isinstance(value, float):
            return int(value)
        raise TypeError(f"cannot convert {value!r} to integer")

    if column_type == "bool":
        if isinstance(value, bool):
            return value
        raise TypeError(f"cannot convert {value!r} to boolean")

    if column_type == "timestamp":
        if isinstance(value, datetime):
            dt = value
        elif isinstance(value, str):
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            raise TypeError(f"cannot convert {value!r} to datetime")
        if dt.tzinfo is not None:
            # Columns are `timestamp without time zone`; store UTC wall time.
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt

    # text (and anything unknown that already is a string)
    if isinstance(value, str):
        return value
    return str(value)


def compile_where(table: str, where: dict[str, Any] | None, params: list[Any]) -> str:
    """Build a WHERE fragment. Appends bound values to ``params``."""
    if not where:
        return "TRUE"

    columns = TABLES.get(table)
    if columns is None:
        raise ValueError(f"unknown table {table!r}")

    clauses: list[str] = []
    for key, value in where.items():
        if key not in columns:
            raise ValueError(f"unknown column {key!r} for table {table!r}")
        column_type = columns[key]
        quoted = _quote(key)

        if isinstance(value, dict):
            for op, op_value in value.items():
                if op == "in":
                    items = list(op_value or [])
                    if not items:
                        clauses.append("FALSE")
                        continue
                    placeholders = []
                    for item in items:
                        params.append(coerce_value(column_type, item))
                        placeholders.append(f"${len(params)}")
                    clauses.append(f"{quoted} IN ({', '.join(placeholders)})")
                elif op in _COMPARISON_OPS:
                    params.append(coerce_value(column_type, op_value))
                    clauses.append(f"{quoted} {_COMPARISON_OPS[op]} ${len(params)}")
                elif op == "not":
                    if op_value is None:
                        clauses.append(f"{quoted} IS NOT NULL")
                    else:
                        params.append(coerce_value(column_type, op_value))
                        clauses.append(f"{quoted} <> ${len(params)}")
                else:
                    raise ValueError(f"unsupported operator {op!r} for column {key!r}")
        elif value is None:
            clauses.append(f"{quoted} IS NULL")
        else:
            params.append(coerce_value(column_type, value))
            clauses.append(f"{quoted} = ${len(params)}")

    return " AND ".join(clauses) if clauses else "TRUE"


def compile_order(table: str, order: dict[str, Any] | None) -> str:
    """Build an ORDER BY fragment (empty string when no ordering requested)."""
    if not order:
        return ""

    columns = TABLES.get(table)
    if columns is None:
        raise ValueError(f"unknown table {table!r}")

    parts: list[str] = []
    for key, direction in order.items():
        if key not in columns:
            raise ValueError(f"unknown column {key!r} for table {table!r}")
        direction = str(direction).lower()
        if direction not in ("asc", "desc"):
            raise ValueError(f"invalid sort direction {direction!r} for column {key!r}")
        parts.append(f"{_quote(key)} {direction.upper()}")

    return " ORDER BY " + ", ".join(parts) if parts else ""


def compile_set(table: str, data: dict[str, Any], params: list[Any]) -> str:
    """Build the SET fragment of an UPDATE. Appends bound values to ``params``."""
    columns = TABLES.get(table)
    if columns is None:
        raise ValueError(f"unknown table {table!r}")
    if not data:
        raise ValueError("update data cannot be empty")

    assignments: list[str] = []
    for key, value in data.items():
        if key not in columns:
            raise ValueError(f"unknown column {key!r} for table {table!r}")
        params.append(coerce_value(columns[key], value))
        assignments.append(f"{_quote(key)} = ${len(params)}")
    return ", ".join(assignments)


def compile_insert(table: str, data: dict[str, Any], params: list[Any]) -> tuple[str, str]:
    """Build the column list and VALUES fragment of an INSERT.

    Returns ``(columns_sql, values_sql)``; bound values are appended to
    ``params``.
    """
    columns = TABLES.get(table)
    if columns is None:
        raise ValueError(f"unknown table {table!r}")
    if not data:
        raise ValueError("insert data cannot be empty")

    names: list[str] = []
    placeholders: list[str] = []
    for key, value in data.items():
        if key not in columns:
            raise ValueError(f"unknown column {key!r} for table {table!r}")
        params.append(coerce_value(columns[key], value))
        names.append(_quote(key))
        placeholders.append(f"${len(params)}")

    return ", ".join(names), ", ".join(placeholders)
