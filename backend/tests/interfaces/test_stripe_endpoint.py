import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_stripe_webhook_without_signature_returns_bad_request_with_security_headers(client: AsyncClient):
    """
        The Stripe webhook POST without a signature header:
    """
    # The Stripe area had no interface test file at all, so deleting
    # the webhook router from api/__init__.py — or dropping the
    # security-headers middleware registration — would previously
    # have gone uncaught here even though every other interface area
    # locks its headers in. This POST needs no new fixture, no
    # authenticated user, and no live Stripe service: the webhook
    # router deliberately carries no auth dependencies (Stripe's
    # server-to-server POSTs carry no Bearer token; signature
    # verification inside the handler is its authentication), and
    # the request carries no X-Tenant-ID, so the tenant middleware
    # resolves host scope (the "test" host is neither the main
    # domain nor a subdomain of it, and no tenant record matches
    # it). On the host branch the secret comes from settings — a
    # required Settings field, so any environment that can import
    # the app has one — and verification then runs before any
    # service call or event dispatch. With no stripe-signature
    # header, stripe's verify_header raises
    # SignatureVerificationError before parsing the payload, and
    # the handler maps it to HTTPException 400 "Invalid signature".
    # That error path is therefore deterministic regardless of the
    # payload or the configured secret value.
    response = await client.post("/configurations/stripe/webhooks", content=b"{}")
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid signature"
    # Same security-headers lock as the other interface tests: the
    # pure-ASGI middleware stamps every HTTP response with no path
    # exclusions, so this unauthenticated webhook 400 must carry the
    # same headers as the authenticated GETs. Cache-Control:
    # no-store is now asserted too: the central HTTPException
    # handler in api/__init__.py stamps it (mirroring the
    # ApiBaseException handler), closing the gap this test
    # previously recorded — HTTPException responses used to carry
    # no cache headers at all.
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the other interface locks, using substring checks so later
    # additions to the list do not break this test. The full value
    # lives in _SECURITY_HEADERS. Each directive is safe to lock
    # here for the same reasons as on the other routes: the SPA has
    # no camera, microphone, geolocation, payment, clipboard-read,
    # display-capture, fullscreen, motion-sensor, compass, XR, or
    # idle-detection flow (verified by grep in the earlier sweeps).
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


@pytest.mark.asyncio
async def test_get_stripe_settings_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The Stripe settings GET:
    """
    # The Stripe settings GET was untested: the stripe test file
    # only locked the unauthenticated webhook POST, so deleting
    # the settings router from api/__init__.py — or dropping the
    # central ApiBaseException no-store lines or the
    # security-headers middleware registration — would previously
    # have gone uncaught here even though every other interface
    # area locks its headers in. The success path is not asserted
    # here: the GET is permission-gated (MANAGE_PAYMENTS_SETTINGS
    # via a router-level dependency) and feature-gated
    # (Feature.STRIPE), so it needs a DB role lookup and a Stripe
    # settings service, and the shared conftest client seeds no
    # role — the SSO/branding tests document the same exclusion
    # for their endpoints. The error path below is deterministic
    # instead, with one ordering difference from the invoice and
    # checkout locks to note: on this router the permission
    # dependency is listed BEFORE the feature gate
    # (stripe_endpoint.py), so the permission check runs first.
    # The mocked host user's role_id points at no row in the
    # fresh test database (Role is in the conftest model set), so
    # the permission dependency raises RoleNotFoundException
    # before the feature gate, the read-scope guard, and the
    # handler run — so no Stripe settings service is ever reached,
    # no stored secret key is read, and no live external call is
    # made. That 404 must still carry the error-response headers:
    # Stripe settings are sensitive payment configuration, so a
    # cached 404 could otherwise be served to a different admin
    # after an account switch on a shared machine.
    response = await client.get("/configurations/stripe")
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the webhook test in this file:
    # the pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so this authenticated settings 404 must
    # carry the same headers as the other interface locks.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the webhook lock, using substring checks so later additions
    # to the list do not break this test. The full value lives in
    # _SECURITY_HEADERS. Each directive is safe to lock here for
    # the same reasons as on the other routes: the SPA has no
    # camera, microphone, geolocation, payment, clipboard-read,
    # display-capture, fullscreen, motion-sensor, compass, XR, or
    # idle-detection flow (verified by grep in the earlier sweeps
    # and re-verified fresh this run: zero case-insensitive idle
    # matches and zero IdleDetector/requestIdleCallback matches
    # across frontend/app/src, and the remaining flows verified
    # absent).
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
