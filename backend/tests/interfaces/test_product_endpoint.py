import pytest
from httpx import AsyncClient

from api import app
from api.common.enums.gender import Gender
from api.domain.dtos.auth_dto import MeResponseDto
from api.domain.dtos.role_dto import RoleDto
from api.infrastructure.security.current_user import get_current_user


@pytest.mark.asyncio
async def test_get_products_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The products area had no interface test file at all, so
    deleting the products router from api/__init__.py — or dropping
    the central ApiBaseException no-store lines or the
    security-headers middleware registration — would previously
    have gone uncaught here even though every other interface
    area locks its headers in. The products router is feature-gated
    at the router level (Feature.STRIPE), in front of every
    handler, so the success path is not asserted here: it
    needs a Stripe account with products plus the
    MANAGE_PRODUCTS_AND_PRICING permission, neither of which
    the shared conftest client provides. The error path below
    is deterministic instead, and it reuses the per-test
    MeResponseDto override pattern from the AI/prices tests: the
    products router also carries a permission dependency
    (MANAGE_PRODUCTS_AND_PRICING) after the feature gate, but
    the gate runs first, and with a role carrying no
    permissions and no tenant the host-scope branch of
    check_feature_access raises
    FeatureNotEnabledException("stripe") before the permission
    check or the handler runs — so no Stripe service is ever
    reached and no live external call is made. The shared
    conftest mock cannot be used directly: it is a plain
    UserDto with no role attribute, so the gate would fail
    with an AttributeError 500 instead of the deterministic
    403. In production that cannot happen: get_current_user
    builds a MeResponseDto (role is a required field) and
    raises RoleNotFoundException before any feature check
    when the role row is missing. The original override is
    restored in finally, so no other test's mock is affected.
    That 403 must still carry the error-response headers: a
    cached 403 could otherwise be served to a different user
    after an account switch on a shared machine, and the product
    list is account-visible catalog configuration.
    """
    async def override_get_current_user_with_role():
        return MeResponseDto(
            first_name="Admin",
            last_name="User",
            id="68c302ef6bf7a039b7e9b385",
            email="admin@example.com",
            gender=Gender.OTHER,
            is_active=True,
            role_id="68c302ef6bf7a039b7e9b386",
            created_at="2024-10-01T00:00:00Z",
            updated_at="2024-10-01T00:00:00Z",
            role=RoleDto(
                id="68c302ef6bf7a039b7e9b386",
                name="No permissions",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_with_role
    try:
        response = await client.get("/products/")
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 403
    body = response.json()
    assert body["code"] == 403
    assert "stripe" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the prices test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the products 403 must carry the same headers
    # as the authenticated GETs, including the exception-handler
    # responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the prices lock, using substring checks so later additions
    # to the list do not break this test. The full value lives in
    # _SECURITY_HEADERS. Each directive is safe to lock here for
    # the same reasons as on the other routes: the SPA has no
    # camera, microphone, geolocation, payment, clipboard-read,
    # display-capture, fullscreen, motion-sensor, compass, XR, or
    # idle-detection flow (verified by grep in the earlier sweeps
    # and re-verified fresh this run: zero IdleDetector/
    # requestIdleCallback matches and zero case-insensitive idle
    # matches across frontend/app/src, and the remaining flows
    # verified absent).
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    assert "accelerometer=()" in permissions_policy
    assert "gyroscope=()" in permissions_policy
    assert "magnetometer=()" in permissions_policy
    assert "xr-spatial-tracking=()" in permissions_policy
    assert "idle-detection=()" in permissions_policy
