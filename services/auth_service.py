"""Authentication for the organization-facing app (admin & staff portals).

Multi-tenancy: every organization has its own Supabase database with its own
``users`` table. At login the organization is resolved from the central
``org_directory`` (email -> organization), the credentials are verified in
that organization's database, and the issued JWT carries ``org_id`` so every
subsequent request knows which database to use. The login API therefore stays
email+password - no change required in the existing frontend.
"""

from database import (
    ensure_connected,
    ensure_org_pool,
    get_current_org,
    get_db,
    set_current_org,
    superadmin_store,
)
from config import settings
from models.schemas import UserResponse
from typing import Optional, Tuple
from fastapi import HTTPException, status
from jose import JWTError, jwt
from datetime import datetime, timedelta
from services.passwords import hash_password, verify_password
from errors import server_error


class AuthService:
    def _verify_password(self, plain_password: str, stored_password: str) -> bool:
        """Check a password against the stored bcrypt hash"""
        return verify_password(plain_password, stored_password)

    def _create_access_token(
        self, user_id: str, email: str, role: str, org_id: Optional[int] = None
    ) -> str:
        """Create JWT access token.

        ``org_id`` routes the request to the right tenant database; ``portal``
        keeps app tokens and superadmin tokens from being interchangeable.
        """
        expire = datetime.utcnow() + timedelta(hours=settings.JWT_ACCESS_TOKEN_EXPIRE_HOURS)
        to_encode = {
            "sub": user_id,
            "email": email,
            "role": role,
            "portal": "app",
            "exp": expire,
        }
        if org_id is not None:
            to_encode["org_id"] = org_id
        encoded_jwt = jwt.encode(
            to_encode,
            settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM
        )
        return encoded_jwt

    def _decode_token(self, token: str) -> dict:
        """Decode and verify JWT token"""
        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM]
            )
            return payload
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token"
            )

    def _role_id_to_string(self, role_id: int) -> str:
        """Convert role_id (1=Admin, 2=Staff) to string"""
        return "admin" if role_id == 1 else "staff"

    def _role_string_to_id(self, role: str) -> int:
        """Convert role string (admin/staff) to role_id (1/2)"""
        return 1 if role == "admin" else 2

    ADMIN_ROLE_ID = 1
    STAFF_ROLE_ID = 2

    async def _resolve_org_for_login(
        self, email: str, role_id: int, org_slug: Optional[str]
    ) -> dict:
        """Find the organization an email belongs to (central directory)."""
        store = superadmin_store()
        candidates = await store.find_orgs_for_email(email)

        matches = [
            row for row in candidates
            if row["role_id"] == role_id and row["status"] == "active"
        ]
        if org_slug:
            matches = [row for row in matches if row["slug"] == org_slug.strip().lower()]

        if not matches:
            # Generic error: never reveal whether the email exists.
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )
        if len(matches) > 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This email belongs to several organizations; please specify the organization",
            )
        return matches[0]

    async def _login(
        self,
        email: str,
        password: str,
        role_id: int,
        org_slug: Optional[str] = None,
    ) -> Tuple[dict, UserResponse]:
        """Authenticate a user for one specific portal (admin or staff).

        The same generic error is returned whether the email is unknown, the
        password is wrong, or the account belongs to the other portal.
        """
        await ensure_connected()
        try:
            org = await self._resolve_org_for_login(email, role_id, org_slug)

            # Bind this request to the organization's Supabase database.
            await ensure_org_pool(org["id"], org["database_url"])
            set_current_org(org["id"], org["database_url"])
            db = get_db()

            user_data_db = await db.users.find_first(
                where={"email": email, "role_id": role_id}
            )
            if not user_data_db or not self._verify_password(password, user_data_db.password):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid email or password"
                )

            role = self._role_id_to_string(user_data_db.role_id)
            access_token = self._create_access_token(
                user_id=str(user_data_db.id),
                email=user_data_db.email,
                role=role,
                org_id=org["id"],
            )
            user_data = UserResponse(
                id=str(user_data_db.id),
                name=user_data_db.name,
                email=user_data_db.email,
                role=role,
                created_at=user_data_db.created_at
            )
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_HOURS * 3600
            }, user_data

        except HTTPException:
            raise
        except Exception:
            raise server_error("Authentication failed")

    async def admin_login(
        self, email: str, password: str, org_slug: Optional[str] = None
    ) -> Tuple[dict, UserResponse]:
        """Admin portal login - only role_id 1"""
        return await self._login(email, password, self.ADMIN_ROLE_ID, org_slug)

    async def staff_login(
        self, email: str, password: str, org_slug: Optional[str] = None
    ) -> Tuple[dict, UserResponse]:
        """Staff portal login - only role_id 2"""
        return await self._login(email, password, self.STAFF_ROLE_ID, org_slug)

    async def get_current_user(self, token: str) -> UserResponse:
        """Get current user from JWT token (and bind the request to its org)."""
        await ensure_connected()
        try:
            payload = self._decode_token(token)

            # Superadmin tokens must not be usable on organization endpoints.
            if payload.get("portal") == "superadmin":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired token"
                )

            org_id = payload.get("org_id")
            user_id = payload.get("sub")
            if not org_id or not user_id:
                # Token issued before the multi-tenant upgrade -> re-login.
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session expired. Please log in again."
                )

            store = superadmin_store()
            org = await store.get_org(int(org_id))
            if not org or org.status != "active":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Organization is not active. Please contact support."
                )

            await ensure_org_pool(org.id, org.database_url)
            set_current_org(org.id, org.database_url)

            db = get_db()
            user_data_db = await db.users.find_unique(where={"id": int(user_id)})

            if not user_data_db:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found"
                )

            role = self._role_id_to_string(user_data_db.role_id)

            return UserResponse(
                id=str(user_data_db.id),
                name=user_data_db.name,
                email=user_data_db.email,
                role=role,
                created_at=user_data_db.created_at
            )

        except HTTPException:
            raise
        except Exception:
            raise server_error("Invalid or expired token", status.HTTP_401_UNAUTHORIZED)

    async def change_password(self, token: str, current_password: str, new_password: str) -> bool:
        """Change user password (the request is already bound to its org)."""
        try:
            payload = self._decode_token(token)
            user_id = payload.get("sub")

            db = get_db()
            user_data_db = await db.users.find_unique(where={"id": int(user_id)})

            if not user_data_db:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found"
                )

            # Verify current password (column is 'password', not 'password_hash')
            if not self._verify_password(current_password, user_data_db.password):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Current password is incorrect"
                )

            # Store only the bcrypt hash of the new password
            await db.users.update(
                where={"id": int(user_id)},
                data={"password": hash_password(new_password)}
            )

            return True

        except HTTPException:
            raise
        except Exception:
            raise server_error("Failed to change password")

    async def create_user(self, name: str, email: str, password: str, role: str) -> UserResponse:
        """
        Create a new user (admin or staff) - Admin only
        """
        try:
            if role not in ["admin", "staff"]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Role must be 'admin' or 'staff'"
                )

            context = get_current_org()
            if context is None:
                raise server_error("No organization in request context")

            store = superadmin_store()

            # An email may only belong to one organization, otherwise login
            # could not tell the databases apart.
            if await store.email_registered_to_other_org(email, context.org_id):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already registered to another organization"
                )

            role_id = self._role_string_to_id(role)

            # Insert user into database (password stored as bcrypt hash)
            db = get_db()
            user_data_db = await db.users.create(
                data={
                    "email": email,
                    "password": hash_password(password),
                    "name": name,
                    "role_id": role_id  # 1=Admin, 2=Staff
                }
            )

            if not user_data_db:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to create user"
                )

            # Keep the central login directory in sync so this user can log in.
            try:
                await store.add_directory(email, context.org_id, role_id)
            except Exception:
                # Tenant user exists but the directory row failed - surface a
                # clear message rather than a half-created account.
                raise server_error("Failed to register user in the login directory")

            role_str = self._role_id_to_string(user_data_db.role_id)

            return UserResponse(
                id=str(user_data_db.id),
                name=user_data_db.name,
                email=user_data_db.email,
                role=role_str,
                created_at=user_data_db.created_at
            )

        except HTTPException:
            raise
        except Exception as e:
            error_str = str(e).lower()
            if "duplicate" in error_str or "unique" in error_str or "already exists" in error_str:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already registered"
                )
            raise server_error("Failed to create user")

    async def logout(self, user_id: str) -> bool:
        """
        Logout user (JWT tokens are stateless, so we just return success)
        """
        # Since we're using JWT, logout is handled client-side by removing the token
        # This endpoint is here for API consistency
        return True


# Create singleton instance
auth_service = AuthService()
