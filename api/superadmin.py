"""Superadmin portal endpoints (central database + organization registry)."""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from dependencies import get_current_superadmin
from models.schemas import (
    ChangePasswordRequest,
    MessageResponse,
    OrgUserCreateRequest,
    OrganizationCreateRequest,
    OrganizationResponse,
    OrganizationUpdateRequest,
    SuperadminLoginRequest,
    TestConnectionResponse,
    TestDatabaseRequest,
    TokenResponse,
    UserResponse,
)
from services.login_limiter import login_key, login_limiter
from services.superadmin_service import superadmin_service

security = HTTPBearer()

router = APIRouter(prefix="/superadmin", tags=["Superadmin"])


@router.post("/login", response_model=TokenResponse)
async def superadmin_login(body: SuperadminLoginRequest, request: Request):
    """Superadmin portal login (central database only)."""
    key = login_key(request, "superadmin", body.email)
    login_limiter.check(key)
    try:
        auth_data, user = await superadmin_service.login(body.email, body.password)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            login_limiter.record_failure(key)
        raise
    login_limiter.reset(key)
    return TokenResponse(
        access_token=auth_data["access_token"],
        token_type="bearer",
        user=user,
    )


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: UserResponse = Depends(get_current_superadmin)):
    """Get the authenticated superadmin."""
    return current_user


@router.post("/change-password", response_model=MessageResponse)
async def change_password(
    body: ChangePasswordRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    current_user: UserResponse = Depends(get_current_superadmin),
):
    """Change the superadmin password."""
    await superadmin_service.change_password(
        token=credentials.credentials,
        current_password=body.current_password,
        new_password=body.new_password,
    )
    return MessageResponse(message="Password changed successfully")


# ---------------------------------------------------------------------------
# Organizations
# ---------------------------------------------------------------------------
@router.get("/organizations", response_model=List[OrganizationResponse])
async def list_organizations(
    current_user: UserResponse = Depends(get_current_superadmin),
):
    """List every organization (secrets are never returned)."""
    return await superadmin_service.list_organizations()


@router.post(
    "/organizations",
    response_model=OrganizationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_organization(
    body: OrganizationCreateRequest,
    current_user: UserResponse = Depends(get_current_superadmin),
):
    """Create an organization from fresh Supabase credentials.

    Provisions the application schema in the new database and creates the
    organization's first administrator.
    """
    return await superadmin_service.create_organization(body)


@router.get("/organizations/{org_id}", response_model=OrganizationResponse)
async def get_organization(
    org_id: int,
    current_user: UserResponse = Depends(get_current_superadmin),
):
    """Get one organization."""
    return await superadmin_service.get_organization(org_id)


@router.put("/organizations/{org_id}", response_model=OrganizationResponse)
async def update_organization(
    org_id: int,
    body: OrganizationUpdateRequest,
    current_user: UserResponse = Depends(get_current_superadmin),
):
    """Update an organization (name, status, Supabase credentials, ...)."""
    return await superadmin_service.update_organization(org_id, body)


@router.delete(
    "/organizations/{org_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_organization(
    org_id: int,
    current_user: UserResponse = Depends(get_current_superadmin),
):
    """Remove an organization from the registry.

    The organization's own Supabase database is left untouched.
    """
    await superadmin_service.delete_organization(org_id)
    return None


@router.post("/organizations/{org_id}/test-connection", response_model=TestConnectionResponse)
async def test_organization_connection(
    org_id: int,
    current_user: UserResponse = Depends(get_current_superadmin),
):
    """Verify the stored Supabase credentials still work."""
    return await superadmin_service.test_organization_connection(org_id)


@router.post("/organizations/{org_id}/reprovision", response_model=MessageResponse)
async def reprovision_organization(
    org_id: int,
    current_user: UserResponse = Depends(get_current_superadmin),
):
    """(Re)apply the application schema to the organization's database."""
    message = await superadmin_service.reprovision(org_id)
    return MessageResponse(message=message)


# ---------------------------------------------------------------------------
# Users inside an organization
# ---------------------------------------------------------------------------
@router.get("/organizations/{org_id}/users", response_model=List[UserResponse])
async def list_organization_users(
    org_id: int,
    current_user: UserResponse = Depends(get_current_superadmin),
):
    """List the admins/staff of an organization (read-only)."""
    return await superadmin_service.list_org_users(org_id)


@router.post(
    "/organizations/{org_id}/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_organization_user(
    org_id: int,
    body: OrgUserCreateRequest,
    current_user: UserResponse = Depends(get_current_superadmin),
):
    """Create (or reset) a user inside an organization from the portal."""
    return await superadmin_service.create_org_user(org_id, body)


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------
@router.post("/test-database", response_model=TestConnectionResponse)
async def test_database(
    body: TestDatabaseRequest,
    current_user: UserResponse = Depends(get_current_superadmin),
):
    """Test a Supabase connection string before saving a new organization."""
    return await superadmin_service.test_database(body.database_url)
