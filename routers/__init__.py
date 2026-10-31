"""
routers
=======
Modular API routers for ShadowMem.
Assembles versioned /api/v1 routes and backward-compatible unversioned routes.
"""

from fastapi import APIRouter
from core.config import settings
from routers.forensics import router as forensics_v1_router, compat_router as forensics_compat_router
from routers.containment import router as containment_v1_router, compat_router as containment_compat_router
from routers.alerts import router as alerts_v1_router, compat_router as alerts_compat_router
from routers.sandbox import router as sandbox_v1_router, compat_router as sandbox_compat_router
from routers.supply_chain import router as supply_chain_v1_router, compat_router as supply_chain_compat_router

# Versioned API router (/api/v1)
v1_router = APIRouter(prefix=settings.api_prefix)
v1_router.include_router(forensics_v1_router)
v1_router.include_router(containment_v1_router)
v1_router.include_router(alerts_v1_router)
v1_router.include_router(sandbox_v1_router)
v1_router.include_router(supply_chain_v1_router)

# Compatibility router (legacy unversioned paths)
compat_router = APIRouter()
compat_router.include_router(forensics_compat_router)
compat_router.include_router(containment_compat_router)
compat_router.include_router(alerts_compat_router)
compat_router.include_router(sandbox_compat_router)
compat_router.include_router(supply_chain_compat_router)

__all__ = [
    "v1_router",
    "compat_router",
    "forensics_v1_router",
    "forensics_compat_router",
    "containment_v1_router",
    "containment_compat_router",
    "alerts_v1_router",
    "alerts_compat_router",
    "sandbox_v1_router",
    "sandbox_compat_router",
    "supply_chain_v1_router",
    "supply_chain_compat_router",
]
