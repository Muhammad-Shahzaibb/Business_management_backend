"""Table/column metadata for every table the backend touches.

``TABLES`` is the single source of truth used to:

* whitelist column names in queries (SQL-injection safety - unknown columns
  raise instead of being interpolated), and
* coerce Python values to the right Postgres types before they are sent as
  query parameters (asyncpg is strict: a ``float`` cannot be bound to a
  ``numeric`` column, an aware ``datetime`` cannot be bound to a
  ``timestamp`` column, ...).

The DDL itself lives in ``database/*.sql`` and is applied automatically:
superadmin schema on startup, tenant schema when an organization is created.

Logical types used below:
    text, int, smallint, numeric, bool, timestamp
"""

from __future__ import annotations

# Table name -> {column name: logical type}
TABLES: dict[str, dict[str, str]] = {
    # ---- tenant tables (one database per organization) ----
    "users": {
        "id": "int",
        "name": "text",
        "email": "text",
        "password": "text",
        "role_id": "smallint",
        "created_at": "timestamp",
    },
    "categories": {
        "category_id": "int",
        "category_name": "text",
        "created_at": "timestamp",
    },
    "inventory": {
        "id": "int",
        "invoice_no": "text",
        "category": "text",
        "product_name": "text",
        "cost_price": "numeric",
        "quantity": "int",
        "advance_amount": "numeric",
        "added_by": "text",
        "created_at": "timestamp",
        "entry_date": "timestamp",
        "edited": "bool",
    },
    "sales": {
        "id": "int",
        "invoice_no": "text",
        "customer_name": "text",
        "customer_address": "text",
        "customer_phone": "text",
        "category": "text",
        "product_name": "text",
        "quantity": "int",
        "cost_price": "numeric",
        "sale_price": "numeric",
        "payment_type": "text",
        "advance_amount": "numeric",
        "sold_by": "text",
        "created_at": "timestamp",
        "entry_date": "timestamp",
        "edited": "bool",
    },
    "expenses": {
        "id": "int",
        "invoice_no": "text",
        "material_name": "text",
        "amount": "numeric",
        "payment_method": "text",
        "advance_amount": "numeric",
        "used": "bool",
        "added_by": "text",
        "created_at": "timestamp",
        "entry_date": "timestamp",
        "description": "text",
        "edited": "bool",
        "total_amount": "numeric",
        "amount_taken": "numeric",
        "remaining_amount": "numeric",
        "payment_history": "text",
    },
    # ---- central superadmin tables ----
    "superadmins": {
        "id": "int",
        "name": "text",
        "email": "text",
        "password": "text",
        "created_at": "timestamp",
    },
    "organizations": {
        "id": "int",
        "name": "text",
        "slug": "text",
        "database_url": "text",
        "supabase_url": "text",
        "service_role_key": "text",
        "project_ref": "text",
        "status": "text",
        "created_at": "timestamp",
        "updated_at": "timestamp",
    },
    "org_directory": {
        "email": "text",
        "org_id": "int",
        "role_id": "smallint",
        "created_at": "timestamp",
    },
}

# Tables belonging to an organization database (a "tenant client").
TENANT_TABLES: tuple[str, ...] = ("users", "categories", "inventory", "sales", "expenses")

# Tables belonging to the central superadmin database.
SUPERADMIN_TABLES: tuple[str, ...] = ("superadmins", "organizations", "org_directory")
