from typing import List
from fastapi import APIRouter, Depends, Response
from api.domain.enum.feature import Feature as FeatureEnum
from api.domain.enum.permission import Permission
from api.interfaces.security.role_checker import check_permissions_for_current_role

router = APIRouter(prefix="/features")
router.tags = ["Features"]

@router.get("/", response_model=List[FeatureEnum], description="List all available features. Requires HOST_MANAGE_TENANTS permission.")
def list_features(
    response: Response,
    _bool: bool = Depends(check_permissions_for_current_role(required_permissions=[Permission.HOST_MANAGE_TENANTS]))
):
    # The catalogue is static, but the endpoint is permission-gated
    # (HOST_MANAGE_TENANTS), so it must not be served from a browser
    # or proxy cache: a cached 200 could show the gated catalogue to
    # a different user after an account switch on a shared machine —
    # the same no-store hardening as the other GET endpoints.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return [feature for feature in FeatureEnum]


