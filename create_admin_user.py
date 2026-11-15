#!/usr/bin/env python3
"""Create (or reset) an admin user. The password is stored as a bcrypt hash.

Usage:
    python create_admin_user.py --name "Owner" --email owner@example.com
    (you will be prompted for the password; it is never stored in code or .env)
"""
import argparse
import asyncio
import getpass
import sys

from database import connect_db, disconnect_db, get_db
from services.passwords import hash_password, validate_password_strength

ADMIN_ROLE_ID = 1


async def create_admin(name: str, email: str, password: str) -> None:
    await connect_db()
    try:
        db = get_db()
        existing = await db.users.find_first(where={"email": email})
        if existing:
            await db.users.update(
                where={"id": existing.id},
                data={"name": name, "password": hash_password(password), "role_id": ADMIN_ROLE_ID},
            )
            print(f"Updated existing user {email} as admin.")
        else:
            await db.users.create(
                data={"name": name, "email": email, "password": hash_password(password), "role_id": ADMIN_ROLE_ID}
            )
            print(f"Created admin {email}.")
    finally:
        await disconnect_db()


def main() -> int:
    parser = argparse.ArgumentParser(description="Create or reset an admin user")
    parser.add_argument("--name", required=True)
    parser.add_argument("--email", required=True)
    args = parser.parse_args()

    password = getpass.getpass("Admin password: ")
    if password != getpass.getpass("Confirm password: "):
        print("Passwords do not match.", file=sys.stderr)
        return 1
    try:
        validate_password_strength(password)
    except ValueError as e:
        print(e, file=sys.stderr)
        return 1

    asyncio.run(create_admin(args.name, args.email.strip(), password))
    return 0


if __name__ == "__main__":
    sys.exit(main())
