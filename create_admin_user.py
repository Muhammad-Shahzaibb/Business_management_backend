#!/usr/bin/env python3
"""Create (or reset) a user inside an organization. The password is stored as
a bcrypt hash in that organization's own Supabase database, and the central
login directory is updated so the account can log in.

Usage:
    python create_admin_user.py --org my-org --name "Owner" --email owner@example.com
    python create_admin_user.py --org my-org --name "Staff" --email staff@example.com --role staff
    (you will be prompted for the password; it is never stored in code or .env)

Use create_superadmin.py for the superadmin portal account instead.
"""
import argparse
import asyncio
import getpass
import sys

from database import connect_db, disconnect_db, ensure_org_pool, get_org_client, superadmin_store
from services.passwords import hash_password, validate_password_strength

ROLE_IDS = {"admin": 1, "staff": 2}


async def create_user(org_slug: str, name: str, email: str, password: str, role: str) -> None:
    await connect_db()
    try:
        store = superadmin_store()
        org = await store.get_org_by_slug(org_slug)
        if not org:
            print(f"No organization with slug '{org_slug}'.", file=sys.stderr)
            print("Registered organizations:", file=sys.stderr)
            for registered in await store.list_orgs():
                print(f"  - {registered.slug} ({registered.name})", file=sys.stderr)
            sys.exit(1)

        if await store.email_registered_to_other_org(email, org.id):
            print(f"{email} is already registered to a different organization.", file=sys.stderr)
            sys.exit(1)

        await ensure_org_pool(org.id, org.database_url)
        db = get_org_client(org.id)
        role_id = ROLE_IDS[role]

        existing = await db.users.find_first(where={"email": email})
        if existing:
            await db.users.update(
                where={"id": existing.id},
                data={"name": name, "password": hash_password(password), "role_id": role_id},
            )
            print(f"Updated existing user {email} as {role} in {org.name}.")
        else:
            await db.users.create(
                data={
                    "name": name,
                    "email": email,
                    "password": hash_password(password),
                    "role_id": role_id,
                }
            )
            print(f"Created {role} {email} in {org.name}.")

        await store.add_directory(email, org.id, role_id)
        print("Login directory updated - the user can now sign in.")
    finally:
        await disconnect_db()


def main() -> int:
    parser = argparse.ArgumentParser(description="Create or reset an organization user")
    parser.add_argument("--org", required=True, help="organization slug")
    parser.add_argument("--name", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--role", choices=sorted(ROLE_IDS), default="admin")
    args = parser.parse_args()

    password = getpass.getpass(f"{args.role.capitalize()} password: ")
    if password != getpass.getpass("Confirm password: "):
        print("Passwords do not match.", file=sys.stderr)
        return 1
    try:
        validate_password_strength(password)
    except ValueError as e:
        print(e, file=sys.stderr)
        return 1

    asyncio.run(create_user(args.org.strip(), args.name, args.email.strip(), password, args.role))
    return 0


if __name__ == "__main__":
    sys.exit(main())
