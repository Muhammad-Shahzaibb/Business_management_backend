#!/usr/bin/env python3
"""Create (or reset) a SUPERADMIN portal account in the central database.

This is the account that opens the superadmin portal - it is NOT tied to any
organization. Its credentials live only in the central superadmin Supabase
database (whose connection string is SUPERADMIN_DATABASE_URL in .env).

Usage:
    python create_superadmin.py --name "Root Admin" --email root@example.com
    (you will be prompted for the password; it is never stored in code or .env)
"""
import argparse
import asyncio
import getpass
import sys

from database import connect_db, disconnect_db, superadmin_store
from services.passwords import hash_password, validate_password_strength


async def create_superadmin(name: str, email: str, password: str) -> None:
    await connect_db()
    try:
        store = superadmin_store()
        existing = await store.get_superadmin_by_email(email)
        if existing:
            print(f"Updating existing superadmin {email}.")
        else:
            print(f"Creating superadmin {email}.")
        await store.upsert_superadmin(name=name, email=email, password_hash=hash_password(password))
        total = await store.count_superadmins()
        print(f"Done. Superadmin accounts in central database: {total}.")
    finally:
        await disconnect_db()


def main() -> int:
    parser = argparse.ArgumentParser(description="Create or reset a superadmin account")
    parser.add_argument("--name", required=True)
    parser.add_argument("--email", required=True)
    args = parser.parse_args()

    password = getpass.getpass("Superadmin password: ")
    if password != getpass.getpass("Confirm password: "):
        print("Passwords do not match.", file=sys.stderr)
        return 1
    try:
        validate_password_strength(password)
    except ValueError as e:
        print(e, file=sys.stderr)
        return 1

    asyncio.run(create_superadmin(args.name, args.email.strip(), password))
    return 0


if __name__ == "__main__":
    sys.exit(main())
