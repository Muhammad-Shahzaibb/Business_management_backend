"""Supabase/Postgres data layer for the Hisaab backend.

This package replaces Prisma. It talks directly to Supabase's Postgres
(using asyncpg) and exposes a small Prisma-compatible query surface
(find_many / find_unique / find_first / create / update / delete / count)
so the existing API code keeps working unchanged.

Layout:
    db.schema      - table/column metadata (used to whitelist + coerce values)
    db.translate   - where/order clauses -> parameterised SQL
    db.client      - Row / Model / Client (the Prisma-like query surface)
    db.pools       - connection pools (central superadmin + one per organization)
    db.store       - queries against the central superadmin database
    db.provision   - applies the SQL schemas (database/*.sql)
    db.util        - URL parsing / secret redaction helpers
"""
