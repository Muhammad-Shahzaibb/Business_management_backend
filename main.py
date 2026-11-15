from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config import settings
from api.auth import router as auth_router
from api.inventory import router as inventory_router
from api.sales import router as sales_router
from api.expenses import router as expenses_router
from api.categories import router as categories_router
from api.dashboard import router as dashboard_router
from api.users import router as users_router
from api.reports import router as reports_router
from database import connect_db, disconnect_db

app = FastAPI(
    title="Hisaab API",
    description="Hisaab - Business Management System API",
    version="1.0.0",
    # API docs are only served when ENABLE_API_DOCS=true (e.g. local development)
    docs_url="/docs" if settings.ENABLE_API_DOCS else None,
    redoc_url="/redoc" if settings.ENABLE_API_DOCS else None,
    openapi_url="/openapi.json" if settings.ENABLE_API_DOCS else None,
)


@app.on_event("startup")
async def startup():
    """Connect to database on startup"""
    await connect_db()


@app.on_event("shutdown")
async def shutdown():
    """Disconnect from database on shutdown"""
    await disconnect_db()

# CORS Middleware - must be added before routers
# Allowed origins come from the CORS_ORIGINS env var (comma-separated).
_allow_all_origins = "*" in settings.CORS_ORIGINS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=not _allow_all_origins,  # Credentials can't be combined with "*"
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)

# Include routers
app.include_router(auth_router, prefix="/api")
app.include_router(inventory_router, prefix="/api")
app.include_router(sales_router, prefix="/api")
app.include_router(expenses_router, prefix="/api")
app.include_router(categories_router, prefix="/api")
app.include_router(dashboard_router, prefix="/api")
app.include_router(users_router, prefix="/api")
app.include_router(reports_router, prefix="/api/reports", tags=["reports"])


@app.get("/")
async def root():
    return {
        "message": "Hisaab API",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy"}

