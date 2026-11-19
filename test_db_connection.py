#!/usr/bin/env python3
"""
Test database connectivity for the Supabase multi-tenant setup.

Run:
    python test_db_connection.py                 # central superadmin database
    python test_db_connection.py --org my-org    # a specific organization DB

The central connection string comes from SUPERADMIN_DATABASE_URL in .env;
organization credentials are read from the superadmin database itself.
"""

import argparse
import asyncio
import os
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import settings
from database import connect_db, disconnect_db, superadmin_store
from db.provision import test_database_connection
from db.util import redact, redact_url


async def test_superadmin_database() -> bool:
    """Test the central superadmin database (org registry + portal accounts)."""
    print("=" * 60)
    print("Testing central SUPERADMIN Supabase database")
    print("=" * 60)
    print()

    # Test 1: environment
    print("1. Checking environment variables...")
    try:
        print(f"   ✓ SUPERADMIN_DATABASE_URL: {redact_url(settings.SUPERADMIN_DATABASE_URL)}")
    except Exception as e:
        print(f"   ✗ Error loading environment variables: {str(e)}")
        return False
    print()

    # Test 2: connect + auto-apply schema
    print("2. Connecting to the superadmin database...")
    try:
        await connect_db()
        print("   ✓ Connected (schema applied automatically)")
    except Exception as e:
        print(f"   ✗ Error connecting to database: {redact(str(e))}")
        return False
    print()

    # Test 3: tables
    print("3. Checking superadmin tables...")
    try:
        store = superadmin_store()
        superadmin_count = await store.client.superadmins.count()
        org_count = await store.client.organizations.count()
        directory_count = await store.client.org_directory.count()
        print(f"   ✓ superadmins table: {superadmin_count} account(s)")
        print(f"   ✓ organizations table: {org_count} organization(s)")
        print(f"   ✓ org_directory table: {directory_count} entry(ies)")
        if superadmin_count == 0:
            print("   ⚠ No superadmin account yet - create one with:")
            print("     python create_superadmin.py --name \"Your Name\" --email you@example.com")
    except Exception as e:
        print(f"   ✗ Error checking tables: {redact(str(e))}")
        return False
    print()

    # Test 4: list organizations
    print("4. Registered organizations...")
    try:
        store = superadmin_store()
        orgs = await store.list_orgs()
        if orgs:
            for org in orgs:
                print(f"   • {org.name} [{org.slug}] - {org.status} - {redact_url(org.database_url)}")
        else:
            print("   (none yet - create one from the superadmin portal)")
    except Exception as e:
        print(f"   ✗ Error listing organizations: {redact(str(e))}")
        return False
    print()

    return True


async def test_org_database(slug: str) -> bool:
    """Test one organization's Supabase database."""
    print("=" * 60)
    print(f"Testing organization database: {slug}")
    print("=" * 60)
    print()

    store = superadmin_store()
    org = await store.get_org_by_slug(slug)
    if not org:
        print(f"   ✗ No organization with slug '{slug}'")
        return False

    print(f"   ✓ Organization: {org.name} ({org.status})")
    print(f"   ✓ URL: {redact_url(org.database_url)}")
    print()

    print("1. Testing connection...")
    result = await test_database_connection(org.database_url)
    if not result["ok"]:
        print(f"   ✗ {result['message']}")
        return False
    print(f"   ✓ Connected in {result['latency_ms']} ms")
    print()

    print("2. Checking application schema...")
    if result["schema_ready"]:
        print("   ✓ All tables present (users, categories, inventory, sales, expenses)")
        print("   ✓ invoice_seq sequence present")
    else:
        print("   ⚠ Schema incomplete - run reprovision from the portal, or:")
        print("     POST /api/superadmin/organizations/{id}/reprovision")
    print()

    print("3. Counting rows...")
    try:
        from database import ensure_org_pool, get_org_client

        await ensure_org_pool(org.id, org.database_url)
        tenant = get_org_client(org.id)
        print(f"   ✓ users: {await tenant.users.count()}")
        print(f"   ✓ categories: {await tenant.categories.count()}")
        print(f"   ✓ inventory: {await tenant.inventory.count()}")
        print(f"   ✓ sales: {await tenant.sales.count()}")
        print(f"   ✓ expenses: {await tenant.expenses.count()}")
    except Exception as e:
        print(f"   ✗ Error counting rows: {redact(str(e))}")
        return False
    print()

    return True


async def main() -> bool:
    parser = argparse.ArgumentParser(description="Test Supabase database connectivity")
    parser.add_argument("--org", help="slug of a registered organization to test")
    args = parser.parse_args()

    ok = await test_superadmin_database()
    if ok and args.org:
        ok = await test_org_database(args.org)

    await disconnect_db()

    print("=" * 60)
    if ok:
        print("✓ All database connection tests passed!")
    else:
        print("✗ Database connection tests failed")
    print("=" * 60)
    return ok


if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        import traceback
        print(f"\n\n✗ Unexpected error: {str(e)}")
        print(traceback.format_exc())
        sys.exit(1)
