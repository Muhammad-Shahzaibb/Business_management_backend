"""Superadmin portal business logic.

The superadmin portal manages the multi-tenant layout:

* accounts that can open the portal (stored in the central superadmin DB);
* organizations - each one pointing at its OWN free Supabase project, whose
  credentials are entered through the portal and stored in the central DB;
* provisioning - when an organization is created the backend connects to the
  fresh Supabase database, applies the application schema and creates the
  organization's first administrator.

Only the central superadmin database connection lives in .env; every
organization's credentials come from this layer (never from the environment).
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Optional, Tuple

from fastapi import HTTPException, status
from jose import JWTError, jwt

from config import settings
from database import (
    close_org_pool,
    ensure_connected,
    ensure_org_pool,
    get_org_client,
    superadmin_store,
)
from db.pools import prepare_dsn
from db.provision import apply_tenant_schema, test_database_connection
from db.util import parse_database_url, redact
from errors import server_error
from models.schemas import (
    OrgUserCreateRequest,
    OrganizationCreateRequest,
    OrganizationResponse,
    OrganizationUpdateRequest,
    TestConnectionResponse,
    UserResponse,
)
from services.passwords import hash_password, verify_password

SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
VALID_STATUSES = ("active", "inactive")
VALID_ROLES = ("admin", "staff")

ROLE_ID = {"admin": 1, "staff": 2}
ROLE_NAME = {1: "admin", 2: "staff"}


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = re.sub(r"-{2,}", "-", value).strip("-")
    return value[:100]


class SuperadminService:
    # ------------------------------------------------------------------
    # Portal authentication
    # ------------------------------------------------------------------
    def _create_token(self, superadmin_id: int, email: str) -> str:
        expire = datetime.utcnow() + timedelta(hours=settings.JWT_ACCESS_TOKEN_EXPIRE_HOURS)
        payload = {
            "sub": str(superadmin_id),
            "email": email,
            "role": "superadmin",
            "portal": "superadmin",
            "exp": expire,
        }
        return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

    def _decode_token(self, token: str) -> dict:
        try:
            return jwt.decode(
                token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
            )
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
            )

    @staticmethod
    def _to_user(superadmin_row) -> UserResponse:
        return UserResponse(
            id=str(superadmin_row.id),
            name=superadmin_row.name,
            email=superadmin_row.email,
            role="superadmin",
            created_at=superadmin_row.created_at,
        )

    async def login(self, email: str, password: str) -> Tuple[dict, UserResponse]:
        await ensure_connected()
        store = superadmin_store()
        account = await store.get_superadmin_by_email(email)
        if not account or not verify_password(password, account.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )
        auth_data = {
            "access_token": self._create_token(account.id, account.email),
            "token_type": "bearer",
            "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_HOURS * 3600,
        }
        return auth_data, self._to_user(account)

    async def get_current(self, token: str) -> UserResponse:
        await ensure_connected()
        payload = self._decode_token(token)
        if payload.get("portal") != "superadmin":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
            )
        try:
            superadmin_id = int(payload.get("sub"))
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
            )
        account = await superadmin_store().get_superadmin(superadmin_id)
        if not account:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
            )
        return self._to_user(account)

    async def change_password(self, token: str, current_password: str, new_password: str) -> bool:
        user = await self.get_current(token)
        await ensure_connected()
        store = superadmin_store()
        account = await store.get_superadmin_by_email(user.email)
        if not account:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
            )
        if not verify_password(current_password, account.password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect",
            )
        await store.set_superadmin_password(user.email, hash_password(new_password))
        return True

    # ------------------------------------------------------------------
    # Organization helpers
    # ------------------------------------------------------------------
    async def _get_org_or_404(self, org_id: int):
        org = await superadmin_store().get_org(org_id)
        if not org:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found",
            )
        return org

    async def _to_org_response(self, org) -> OrganizationResponse:
        parts = parse_database_url(org.database_url)
        store = superadmin_store()
        admin_count = await store.client.org_directory.count(
            where={"org_id": org.id, "role_id": 1}
        )
        return OrganizationResponse(
            id=org.id,
            name=org.name,
            slug=org.slug,
            status=org.status,
            project_ref=org.project_ref,
            supabase_url=org.supabase_url,
            database_host=parts["host"],
            database_name=parts["database"],
            database_user=parts["user"],
            service_role_key_set=bool(org.service_role_key),
            admin_count=admin_count,
            created_at=org.created_at,
            updated_at=org.updated_at,
        )

    @staticmethod
    def _validate_slug(slug: str) -> str:
        slug = slug.strip().lower()
        if not SLUG_RE.match(slug) or len(slug) > 100:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Slug must be 1-100 characters: lowercase letters, numbers and single dashes",
            )
        return slug

    @staticmethod
    def _validate_database_url(database_url: str) -> str:
        try:
            prepare_dsn(database_url)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            )
        return database_url.strip()

    async def _unique_slug(self, base: str, exclude_org_id: Optional[int] = None) -> str:
        store = superadmin_store()
        candidate = base
        counter = 2
        while True:
            existing = await store.get_org_by_slug(candidate)
            if existing is None or (exclude_org_id and existing.id == exclude_org_id):
                return candidate
            candidate = f"{base}-{counter}"
            counter += 1
            if counter > 1000:  # pragma: no cover - defensive
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Could not generate a unique slug; please provide one",
                )

    # ------------------------------------------------------------------
    # Organization listing / reading
    # ------------------------------------------------------------------
    async def list_organizations(self) -> list[OrganizationResponse]:
        await ensure_connected()
        orgs = await superadmin_store().list_orgs()
        return [await self._to_org_response(org) for org in orgs]

    async def get_organization(self, org_id: int) -> OrganizationResponse:
        await ensure_connected()
        org = await self._get_org_or_404(org_id)
        return await self._to_org_response(org)

    # ------------------------------------------------------------------
    # Create organization (fresh Supabase credentials + first admin)
    # ------------------------------------------------------------------
    async def create_organization(self, request: OrganizationCreateRequest) -> OrganizationResponse:
        await ensure_connected()
        store = superadmin_store()

        name = request.name.strip()
        if not name:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Organization name is required",
            )

        requested_slug = request.slug.strip().lower() if request.slug else slugify(name)
        if not requested_slug:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Could not derive a slug from the name; please provide one",
            )
        slug = self._validate_slug(requested_slug)
        if request.slug and await store.get_org_by_slug(slug):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Slug already in use",
            )
        slug = await self._unique_slug(slug)

        admin = request.admin
        if await store.email_registered(admin.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This email is already registered to an organization",
            )

        database_url = self._validate_database_url(request.database_url)

        # 1) Record the organization first so it has an id (the pool and the
        #    directory row are keyed by it).
        org = await store.client.organizations.create(
            data={
                "name": name,
                "slug": slug,
                "database_url": database_url,
                "supabase_url": request.supabase_url.strip() if request.supabase_url else None,
                "service_role_key": (
                    request.service_role_key.strip() if request.service_role_key else None
                ),
                "project_ref": request.project_ref.strip() if request.project_ref else None,
                "status": "active",
            }
        )
        if org is None:  # pragma: no cover - insert always returns a row
            raise server_error("Failed to create organization")
        org_id = org.id

        # 2) Provision the organization's Supabase database.
        try:
            await ensure_org_pool(org_id, database_url)
            await apply_tenant_schema(get_org_client(org_id).pool)

            tenant = get_org_client(org_id)
            existing_user = await tenant.users.find_first(where={"email": admin.email})
            if existing_user:
                await tenant.users.update(
                    where={"id": existing_user.id},
                    data={
                        "name": admin.name,
                        "password": hash_password(admin.password),
                        "role_id": 1,
                    },
                )
            else:
                await tenant.users.create(
                    data={
                        "name": admin.name,
                        "email": admin.email,
                        "password": hash_password(admin.password),
                        "role_id": 1,
                    }
                )

            await store.add_directory(admin.email, org_id, 1)
        except HTTPException:
            await self._rollback_organization(org_id)
            raise
        except Exception as exc:
            await self._rollback_organization(org_id)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Could not provision the organization database: {redact(str(exc))}",
            )

        created = await store.get_org(org_id)
        return await self._to_org_response(created)

    async def _rollback_organization(self, org_id: int) -> None:
        """Best-effort undo when provisioning fails."""
        try:
            store = superadmin_store()
            await store.remove_directory_by_org(org_id)
            await store.client.organizations.delete(where={"id": org_id})
        except Exception:  # pragma: no cover - best effort
            pass
        try:
            await close_org_pool(org_id)
        except Exception:  # pragma: no cover - best effort
            pass

    # ------------------------------------------------------------------
    # Update organization
    # ------------------------------------------------------------------
    async def update_organization(
        self, org_id: int, request: OrganizationUpdateRequest
    ) -> OrganizationResponse:
        await ensure_connected()
        org = await self._get_org_or_404(org_id)
        store = superadmin_store()

        data: dict = {}

        if request.name is not None:
            name = request.name.strip()
            if not name:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Organization name cannot be empty",
                )
            data["name"] = name

        if request.slug is not None:
            slug = self._validate_slug(request.slug)
            existing = await store.get_org_by_slug(slug)
            if existing and existing.id != org_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Slug already in use",
                )
            data["slug"] = slug

        if request.status is not None:
            status_value = request.status.strip().lower()
            if status_value not in VALID_STATUSES:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Status must be 'active' or 'inactive'",
                )
            data["status"] = status_value

        if request.supabase_url is not None:
            data["supabase_url"] = request.supabase_url.strip() or None
        if request.service_role_key is not None:
            data["service_role_key"] = request.service_role_key.strip() or None
        if request.project_ref is not None:
            data["project_ref"] = request.project_ref.strip() or None

        new_database_url = None
        if request.database_url is not None:
            new_database_url = self._validate_database_url(request.database_url)
            if new_database_url != org.database_url:
                # Test the new credentials before swapping them in.
                result = await test_database_connection(new_database_url)
                if not result["ok"]:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=result["message"],
                    )
                data["database_url"] = new_database_url
            else:
                new_database_url = None

        if not data:
            return await self._to_org_response(org)

        data["updated_at"] = datetime.utcnow()
        updated = await store.client.organizations.update(where={"id": org_id}, data=data)
        if updated is None:  # pragma: no cover - row was just read
            raise server_error("Failed to update organization")

        if new_database_url:
            # Drop the old pool; the next request creates one for the new URL.
            await close_org_pool(org_id)

        return await self._to_org_response(updated)

    async def delete_organization(self, org_id: int) -> None:
        await ensure_connected()
        org = await self._get_org_or_404(org_id)
        store = superadmin_store()
        # org_directory cascades; the organization's own Supabase database is
        # intentionally left untouched (it belongs to the customer).
        await store.client.organizations.delete(where={"id": org_id})
        await close_org_pool(org_id)

    # ------------------------------------------------------------------
    # Connection testing / reprovisioning
    # ------------------------------------------------------------------
    async def test_database(self, database_url: str) -> TestConnectionResponse:
        await ensure_connected()
        try:
            self._validate_database_url(database_url)
        except HTTPException as exc:
            return TestConnectionResponse(ok=False, message=exc.detail)
        result = await test_database_connection(database_url)
        return TestConnectionResponse(
            ok=result["ok"],
            message=result["message"],
            latency_ms=result["latency_ms"],
            schema_ready=result["schema_ready"],
        )

    async def test_organization_connection(self, org_id: int) -> TestConnectionResponse:
        await ensure_connected()
        org = await self._get_org_or_404(org_id)
        return await self.test_database(org.database_url)

    async def reprovision(self, org_id: int) -> str:
        """(Re)apply the application schema to an organization's database."""
        await ensure_connected()
        org = await self._get_org_or_404(org_id)
        try:
            await ensure_org_pool(org.id, org.database_url)
            await apply_tenant_schema(get_org_client(org.id).pool)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Could not apply schema: {redact(str(exc))}",
            )
        return "Organization schema applied successfully"

    # ------------------------------------------------------------------
    # Users inside an organization
    # ------------------------------------------------------------------
    async def _tenant_client_for(self, org_id: int, database_url: str):
        await ensure_org_pool(org_id, database_url)
        return get_org_client(org_id)

    async def list_org_users(self, org_id: int) -> list[UserResponse]:
        await ensure_connected()
        org = await self._get_org_or_404(org_id)
        tenant = await self._tenant_client_for(org.id, org.database_url)
        users = await tenant.users.find_many(order={"created_at": "desc"})
        return [
            UserResponse(
                id=str(user.id),
                name=user.name,
                email=user.email,
                role=ROLE_NAME.get(user.role_id, "staff"),
                created_at=user.created_at,
            )
            for user in users
        ]

    async def create_org_user(self, org_id: int, request: OrgUserCreateRequest) -> UserResponse:
        await ensure_connected()
        org = await self._get_org_or_404(org_id)
        store = superadmin_store()

        if request.role not in VALID_ROLES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Role must be 'admin' or 'staff'",
            )

        if await store.email_registered_to_other_org(request.email, org_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered to another organization",
            )

        role_id = ROLE_ID[request.role]
        tenant = await self._tenant_client_for(org.id, org.database_url)

        try:
            existing = await tenant.users.find_first(where={"email": request.email})
            if existing:
                user_row = await tenant.users.update(
                    where={"id": existing.id},
                    data={
                        "name": request.name,
                        "password": hash_password(request.password),
                        "role_id": role_id,
                    },
                )
            else:
                user_row = await tenant.users.create(
                    data={
                        "name": request.name,
                        "email": request.email,
                        "password": hash_password(request.password),
                        "role_id": role_id,
                    }
                )
        except Exception as exc:
            error_str = str(exc).lower()
            if "duplicate" in error_str or "unique" in error_str:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already registered",
                )
            raise server_error(f"Failed to create user: {redact(str(exc))}")

        if user_row is None:  # pragma: no cover - insert/update returns a row
            raise server_error("Failed to create user")

        await store.add_directory(request.email, org_id, role_id)

        return UserResponse(
            id=str(user_row.id),
            name=user_row.name,
            email=user_row.email,
            role=ROLE_NAME.get(user_row.role_id, "staff"),
            created_at=user_row.created_at,
        )


superadmin_service = SuperadminService()
