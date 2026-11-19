from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from models.schemas import (
    AdminLoginRequest,
    StaffLoginRequest,
    ChangePasswordRequest,
    CreateUserRequest,
    TokenResponse,
    UserResponse,
    MessageResponse
)
from services.auth_service import auth_service
from services.login_limiter import login_limiter, login_key
from dependencies import get_current_user, get_current_admin

security = HTTPBearer()

router = APIRouter(prefix="/auth", tags=["Authentication"])


async def _rate_limited_login(request: Request, portal: str, body, login_fn) -> TokenResponse:
    """Run a login, blocking the email+IP after too many failed attempts."""
    key = login_key(request, portal, body.email)
    login_limiter.check(key)
    try:
        auth_data, user = await login_fn(
            email=body.email,
            password=body.password,
            org_slug=getattr(body, "org_slug", None),
        )
    except HTTPException as e:
        if e.status_code == status.HTTP_401_UNAUTHORIZED:
            login_limiter.record_failure(key)
        raise
    login_limiter.reset(key)
    return TokenResponse(
        access_token=auth_data["access_token"],
        token_type="bearer",
        user=user
    )


@router.post("/admin/login", response_model=TokenResponse)
async def admin_login(body: AdminLoginRequest, request: Request):
    """
    Admin login endpoint
    """
    return await _rate_limited_login(request, "admin", body, auth_service.admin_login)


@router.post("/staff/login", response_model=TokenResponse)
async def staff_login(body: StaffLoginRequest, request: Request):
    """
    Staff login endpoint
    """
    return await _rate_limited_login(request, "staff", body, auth_service.staff_login)

@router.post("/logout", response_model=MessageResponse)
async def logout(
    current_user: UserResponse = Depends(get_current_user)
):
    """
    Logout endpoint
    """
    # Note: For JWT tokens, logout is typically handled client-side
    # by removing the token. This endpoint can be used for server-side
    # token blacklisting if needed.
    await auth_service.logout(current_user.id)
    return MessageResponse(message="Logged out successfully")


@router.get("/me", response_model=UserResponse)
async def get_me(
    current_user: UserResponse = Depends(get_current_user)
):
    """
    Get current authenticated user
    """
    return current_user


@router.post("/change-password", response_model=MessageResponse)
async def change_password(
    request: ChangePasswordRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    current_user: UserResponse = Depends(get_current_user)
):
    """
    Change user password
    """
    token = credentials.credentials
    await auth_service.change_password(
        token=token,
        current_password=request.current_password,
        new_password=request.new_password
    )
    return MessageResponse(message="Password changed successfully")


@router.post("/create-user", response_model=UserResponse)
async def create_user(
    request: CreateUserRequest,
    current_admin: UserResponse = Depends(get_current_admin)
):
    """
    Create a new user (admin or staff) - Admin only
    """
    user = await auth_service.create_user(
        name=request.name,
        email=request.email,
        password=request.password,
        role=request.role
    )
    return user

