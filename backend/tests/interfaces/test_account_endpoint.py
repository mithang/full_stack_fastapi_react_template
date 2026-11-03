import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_account_logout_returns_ok_with_cache_and_security_headers(client: AsyncClient):
    """
        The account logout GET:
    """
    # The account area had no interface test file at all, so
    # deleting the account router from api/__init__.py — or
    # dropping the no-store lines or the security-headers middleware
    # registration — would previously have gone uncaught here even
    # though every other interface area locks its headers in. This
    # GET needs no new fixture and no authenticated user: unlike
    # the /me GET it carries no MeResponseDto role requirement (the
    # shared mocked user has no role object, so /me cannot yield a
    # deterministic 200), and unlike the passkey GET it needs no
    # beanie document outside the conftest model set. Logout takes
    # CurrentUserOptional, and the OAuth2 scheme has auto_error=False,
    # so with no Authorization header the optional-user resolution
    # fails closed to None, the audit write is skipped, and the
    # handler still runs its session-ending act — deleting the
    # refresh cookie — and returns 200. That unauthenticated 200 is
    # by design: logout must succeed even when the access token has
    # already expired or is absent, or the refresh cookie would
    # survive logout and the background worker would refresh it back
    # into a live session.
    response = await client.get("/account/logout")
    assert response.status_code == 200
    # This GET deletes the refresh cookie and ends the session, so
    # it must never be served from a browser or proxy cache: a
    # cached 200 would replay without running the handler, leaving
    # the refresh cookie (and the session it backs) in place while
    # the user believes they logged out. The handler sets both
    # headers before the cookie deletion, so they hold on this path.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # The deletion itself must be present: the Set-Cookie header
    # carries the refresh_token cookie being cleared.
    assert "refresh_token" in response.headers.get("set-cookie", "")
    # Same security-headers lock as the dashboard test: the
    # pure-ASGI middleware stamps every HTTP response with no path
    # exclusions, so the logout GET must carry the same headers as
    # the authenticated GETs.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the dashboard lock, using substring checks so later additions
    # to the list do not break this test. The full value lives in
    # _SECURITY_HEADERS. Each directive is safe to lock here for the
    # same reasons as on the other routes: the SPA has no camera,
    # microphone, geolocation, payment, clipboard-read,
    # display-capture, fullscreen, motion-sensor, compass, XR, or
    # idle-detection flow (verified by grep in the earlier sweeps:
    # zero IdleDetector/requestIdleCallback matches and zero
    # case-insensitive idle matches across frontend/app/src, and the
    # remaining flows verified absent).
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
async def test_account_refresh_without_cookie_returns_forbidden_with_cache_and_security_headers(client: AsyncClient):
    """
        The account refresh POST without a refresh cookie:
    """
    # The refresh route's missing-cookie branch had no header lock:
    # it raises before any service call, so no fixture, DB row, or
    # live service is needed — the httpx client sends no cookies by
    # default, the Cookies model defaults refresh_token to None, and
    # the handler raises ForbiddenException("Refresh token missing!")
    # before touching the auth service. The central ApiBaseException
    # handler maps ForbiddenException to 403 (api/__init__.py) and
    # stamps Cache-Control: no-store plus Pragma: no-cache on every
    # such error response, so a cached 403 could otherwise be served
    # to a different user after an account switch on a shared machine
    # — the same class as the tenant-create 406 lock. The pure-ASGI
    # security-headers middleware stamps every HTTP response with no
    # path exclusions, so the 403 must carry the same headers as the
    # logout 200 above.
    response = await client.post("/account/refresh")
    assert response.status_code == 403
    assert response.json()["error"] == "Refresh token missing!"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the logout lock, using substring checks so later additions
    # to the list do not break this test. The full value lives in
    # _SECURITY_HEADERS. Each directive is safe to lock here for the
    # same reasons as on the other routes: the SPA has no camera,
    # microphone, geolocation, payment, clipboard-read,
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
async def test_account_passkey_register_options_unknown_email_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The account passkey register-options POST for an unknown email:
    """
    # The passkey register-options route had no header lock: it is the
    # first account route after logout/refresh whose error path needs
    # no authenticated user and no seeded row. It carries no permission
    # dependency and no CurrentUser dependency, so the mocked host user
    # (whose role_id points at no row) cannot interfere here — unlike
    # the permission-gated routes, no role lookup runs at all. The
    # handler resolves the auth service from the container (no lookup),
    # then calls user_service.find_by_email before the try block — the
    # comment on the handler says so explicitly, so an unknown email
    # keeps its 404 instead of being wrapped into the 406
    # PassKeyException. Against the fresh test DB the lookup finds no
    # User row and raises UserNotFoundException (core/exceptions.py),
    # a NotFoundException subclass, which the central ApiBaseException
    # handler maps to 404 with Cache-Control: no-store and Pragma:
    # no-cache (api/__init__.py). No passkey record is created, no
    # webauthn options are generated, and no email is sent on this
    # path: the failure happens before passkey_service is ever called.
    # The body is a bare JSON string because the endpoint declares
    # email as EmailStr = Body(...), not a DTO object.
    response = await client.post(
        "/account/passkey/register_options", json="unknown@example.com"
    )
    assert response.status_code == 404
    assert response.json()["code"] == 404
    assert "User" in response.json()["error"]
    assert "unknown@example.com" in response.json()["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-headers lock as the logout/refresh tests: the
    # pure-ASGI middleware stamps every HTTP response with no path
    # exclusions, so the 404 must carry the same headers.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the logout lock, using substring checks so later additions
    # to the list do not break this test. Each directive is safe to
    # lock here for the same reasons as on the other routes: the SPA
    # has no camera, microphone, geolocation, payment, clipboard-read,
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
async def test_account_passkey_login_options_unknown_email_returns_406_with_cache_and_security_headers(client: AsyncClient):
    """
        The account passkey login-options POST for an unknown email:
    """
    # The passkey login-options route had no header lock: it is the
    # next account route after register-options whose error path needs
    # no authenticated user, no seeded row, and no live service. It
    # carries no permission dependency and no CurrentUser dependency,
    # so the mocked host user (whose role_id points at no row) cannot
    # interfere here — no role lookup runs at all. The handler calls
    # user_service.find_by_email inside a try that catches only
    # UserNotFoundException and re-raises it as PassKeyException("No
    # credentials found for the user. Please register first.") — the
    # handler comment says so explicitly, closing the same
    # account-enumeration leak as password login: an unknown email
    # otherwise escapes as 404 "User with identifier <email> not
    # found.", while a known account without passkeys gets the
    # identical 406. Against the fresh test DB the lookup finds no
    # User row, so the 406 fires before passkey_service is ever
    # called: no webauthn options are generated, no credential is
    # decoded, and no email is sent on this path. PassKeyException
    # is an InvalidOperationException, so the central ApiBaseException
    # handler maps it to 406 with body {"error": ..., "code": 406}
    # and Cache-Control: no-store plus Pragma: no-cache
    # (api/__init__.py). The body is a bare JSON string because the
    # endpoint declares email as EmailStr = Body(...), not a DTO.
    response = await client.post(
        "/account/passkey/login_options", json="unknown@example.com"
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert response.json()["error"] == "No credentials found for the user. Please register first."
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-headers lock as the logout/refresh and
    # register-options tests: the pure-ASGI middleware stamps every
    # HTTP response with no path exclusions, so the 406 must carry
    # the same headers.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the register-options lock, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow (verified
    # by grep in the earlier sweeps).
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
async def test_account_passkey_register_without_challenge_returns_406_with_cache_and_security_headers(client: AsyncClient):
    """
        The account passkey register POST with no live challenge:
    """
    # The passkey register route is the next account route after
    # login-options whose error path needs no authenticated user, no
    # seeded row, and no live service. It carries no permission
    # dependency and no CurrentUser dependency, so the mocked host
    # user (whose role_id points at no row) cannot interfere here —
    # no role lookup runs at all. The handler wraps the whole
    # service call in a blanket except that re-raises any failure as
    # PassKeyException("Passkey registration failed.") — the handler
    # comment says so explicitly, because the webauthn library's own
    # exceptions for a malformed credential would otherwise escape
    # as a 500. Against a fresh test DB there is no registration
    # challenge for the email, so complete_registration raises
    # PassKeyException("No expected challenge found or challenge
    # expired.") before any credential is verified or stored; and
    # even the conftest wrinkle that Challenges is not in the
    # conftest model set converges to the same outcome, since a
    # lookup failure on the uninitialized collection is also caught
    # by that blanket except and re-raised as the identical 406.
    # No webauthn verification runs, no credential is stored, and
    # no email is sent on this path. The endpoint declares two Body
    # params (email: EmailStr, credential: dict), so FastAPI expects
    # a single JSON object keyed by both names; a bare dict
    # credential passes Body validation, so no 422 can mask the
    # 406. PassKeyException is an InvalidOperationException, so the
    # central ApiBaseException handler maps it to 406 with body
    # {"error": ..., "code": 406} and Cache-Control: no-store plus
    # Pragma: no-cache (api/__init__.py). The error assertion uses
    # a substring check because PassKeyException prefixes its
    # message with "PassKey Error: ".
    response = await client.post(
        "/account/passkey/register",
        json={"email": "unknown@example.com", "credential": {"id": "not-a-credential"}},
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Passkey registration failed." in response.json()["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-headers lock as the logout/refresh and
    # register-options tests: the pure-ASGI middleware stamps every
    # HTTP response with no path exclusions, so the 406 must carry
    # the same headers.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the login-options lock, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow (verified
    # by grep in the earlier sweeps).
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
async def test_account_passkey_login_without_challenge_returns_406_with_cache_and_security_headers(client: AsyncClient):
    """
        The account passkey login POST with no live challenge:
    """
    # The passkey login route is the next account route after
    # register whose error path needs no authenticated user, no
    # seeded row, and no live service. It carries no permission
    # dependency and no CurrentUser dependency, so the mocked host
    # user (whose role_id points at no row) cannot interfere here —
    # no role lookup runs at all. The handler wraps the whole
    # service call in a blanket except that re-raises any failure as
    # PassKeyException("Passkey authentication failed."). Against a
    # fresh test DB there is no authentication challenge for the
    # email, so complete_auth_login raises PassKeyException("No
    # expected challenge found or challenge expired.") before any
    # credential is verified, any sign-in count is updated, or any
    # token is issued; and even the conftest wrinkle that
    # Challenges is not in the conftest model set (conftest.py
    # models are User, Tenant, Role, UserPasswordReset,
    # UserPreference only) converges to the same outcome, since a
    # lookup failure on the uninitialized collection is also caught
    # by that blanket except and re-raised as the identical 406.
    # No webauthn verification runs, no token is issued, and no
    # refresh cookie is set on this path. The endpoint declares
    # two Body params (email: EmailStr, credential: dict), so
    # FastAPI expects a single JSON object keyed by both names; a
    # bare dict credential passes Body validation, so no 422 can
    # mask the 406. PassKeyException is an
    # InvalidOperationException, so the central ApiBaseException
    # handler maps it to 406 with body {"error": ..., "code": 406}
    # and Cache-Control: no-store plus Pragma: no-cache
    # (api/__init__.py). The error assertion uses a substring
    # check because PassKeyException prefixes its message with
    # "PassKey Error: " — the same reason the register lock uses
    # a substring check.
    response = await client.post(
        "/account/passkey/login",
        json={"email": "unknown@example.com", "credential": {"id": "not-a-credential"}},
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Passkey authentication failed." in response.json()["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-headers lock as the logout/refresh and
    # register-options tests: the pure-ASGI middleware stamps every
    # HTTP response with no path exclusions, so the 406 must carry
    # the same headers.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the register lock, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow (verified
    # by grep in the earlier sweeps).
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
async def test_account_email_magic_link_login_unknown_email_returns_generic_200_with_security_headers(client: AsyncClient):
    """
        The account email magic link login POST for an unknown email:
    """
    # The next account route after the passkey set whose error path
    # needs no authenticated user, no seeded row, and no live
    # service. It carries no permission dependency and no
    # CurrentUser dependency, so the mocked host user (whose
    # role_id points at no row) cannot interfere here — no role
    # lookup runs at all. The handler resolves the user service
    # and calls find_by_email, which queries the User collection
    # (in the conftest model set) and raises UserNotFoundException
    # on the empty fresh test DB; the handler catches exactly that
    # exception and returns the same generic 200 message as the
    # success path ("If the email exists, a magic link has been
    # sent."), so the response is indistinguishable from a known
    # email and reveals nothing to enumerate accounts. Because the
    # lookup fails first, create_magic_link is never called: no
    # magic-link record is written and no email is sent — so the
    # fact that UserMagicLink is not in the conftest model set
    # cannot affect this path, unlike the passkey routes. The
    # endpoint declares a single Body param (email: EmailStr), so
    # FastAPI expects the bare JSON string, as the
    # register-options/login-options tests already do — an object
    # body would 422 and mask the generic 200. No refresh cookie
    # is set on this path: the handler returns a plain DTO. No
    # Cache-Control assertion here, deliberately: unlike the
    # error paths (central handler) and the validate GET (explicit
    # handler headers), this 200 sets no cache headers, and POST
    # responses are not cached by default, so there is no header
    # to lock — the lock is the generic body plus the security
    # headers the pure-ASGI middleware stamps on every response.
    response = await client.post(
        "/account/email_magic_link_login",
        json="unknown@example.com",
    )
    assert response.status_code == 200
    assert response.json()["message"] == "If the email exists, a magic link has been sent."
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # Same security-headers lock as the passkey tests: the
    # pure-ASGI middleware stamps every HTTP response with no path
    # exclusions, so this generic 200 must carry the same headers.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the passkey locks, using substring checks so later additions
    # to the list do not break this test. Each directive is safe
    # to lock here for the same reasons as on the other routes:
    # the SPA has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen, motion-sensor,
    # compass, XR, or idle-detection flow (verified by grep in the
    # earlier sweeps).
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
async def test_account_email_magic_link_validate_invalid_link_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The account magic-link validate GET with an invalid link:
    """
    # This GET carries no permission or CurrentUser dependency (the
    # router itself has none, account_endpoint.py line 49), so the
    # mocked host user's role_id pointing at no row cannot interfere
    # — no role lookup runs at all, and the service factories ahead
    # of the handler only resolve singletons. validate_magic_link
    # then looks up the (user_id, token) record: on the fresh test
    # DB there is no such record, and UserMagicLink is not even in
    # the conftest model set, so the lookup either finds nothing or
    # raises — and the service catches Exception broadly and returns
    # False either way. The handler therefore raises
    # ForbiddenException("Invalid or expired magic link.") before
    # login_with_magic_link runs, so no token set is issued and no
    # refresh cookie is set: an invalid or already-consumed link
    # must not mint a session. The central ApiBaseException handler
    # maps ForbiddenException to 403 with body {"error": ..., "code":
    # 403} plus Cache-Control: no-store and Pragma: no-cache, and
    # the pure-ASGI middleware stamps every response with the
    # security headers. The user_id is a well-formed ObjectId hex
    # (the mocked user's id) so the 403 comes from the record
    # lookup, not from a malformed-id shortcut, and the token is a
    # value no record could carry.
    response = await client.get(
        "/account/email_magic_link_validate",
        params={
            "token": "bogus-token-that-matches-no-record",
            "user_id": "68c302ef6bf7a039b7e9b385",
        },
    )
    assert response.status_code == 403
    assert response.json()["code"] == 403
    assert "Invalid or expired magic link" in response.json()["error"]
    # An invalid link must not mint a session: no refresh cookie.
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # Error responses must not be cached either: a cached 403 could
    # be served to a different user after an account switch on a
    # shared machine, and a cached success on this single-use flow
    # would replay a consumed link's token set.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-headers lock as the other account tests: the
    # pure-ASGI middleware stamps every HTTP response with no path
    # exclusions, so this 403 must carry the same headers.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the passkey and magic-link-login locks, using substring checks
    # so later additions to the list do not break this test. Each
    # directive is safe to lock here for the same reasons as on the
    # other routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow (verified
    # by grep in the earlier sweeps).
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
async def test_account_password_reset_request_unknown_email_returns_generic_200_with_security_headers(client: AsyncClient):
    """
        The account password reset request POST for an unknown email:
    """
    # The next account route after the magic-link set whose error
    # path needs no authenticated user, no seeded row, and no live
    # service. It carries no permission dependency and no
    # CurrentUser dependency, so the mocked host user (whose
    # role_id points at no row) cannot interfere here — no role
    # lookup runs at all, and the FrontendHost dependency only
    # reads request state (tenant_middleware.py), with no DB
    # lookup. The handler wraps initate_password_reset in a
    # blanket try/except with a finally that always returns the
    # same generic 200 message ("If the email exists, a password
    # reset link has been sent."), so unknown and known emails
    # are indistinguishable and no account enumeration leaks.
    # Because the lookup fails first — request_password_reset
    # raises InvalidOperationException when find_by_email finds
    # no user, before any reset record is written, any token is
    # minted, or any email is sent — no reset email goes out for
    # an unknown address, and the fact that the handler swallows
    # the exception means the failure cannot surface as an error
    # status either. The endpoint takes a PasswordResetRequestDto
    # body, so the request is the JSON object {"email": ...} —
    # unlike the magic-link login's bare-string Body param, a
    # bare string here would 422 and mask the generic 200. No
    # refresh cookie is set on this path: the handler returns a
    # plain DTO. No Cache-Control assertion here, deliberately:
    # unlike the error paths (central handler), this 200 sets no
    # cache headers, and POST responses are not cached by
    # default, so there is no header to lock — the lock is the
    # generic body plus the security headers the pure-ASGI
    # middleware stamps on every response.
    response = await client.post(
        "/account/password_reset_request",
        json={"email": "unknown@example.com"},
    )
    assert response.status_code == 200
    assert response.json()["message"] == "If the email exists, a password reset link has been sent."
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # Same security-headers lock as the magic-link tests: the
    # pure-ASGI middleware stamps every HTTP response with no path
    # exclusions, so this generic 200 must carry the same headers.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the magic-link locks, using substring checks so later additions
    # to the list do not break this test. Each directive is safe
    # to lock here for the same reasons as on the other routes:
    # the SPA has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen, motion-sensor,
    # compass, XR, or idle-detection flow (verified by grep in the
    # earlier sweeps).
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
async def test_account_password_reset_confirmation_no_reset_record_returns_406_with_cache_and_security_headers(client: AsyncClient):
    """
        The account password reset confirmation POST for a user id
        with no seeded reset record:
    """
    # The next account route after password_reset_request whose
    # error path needs no authenticated user, no seeded row, and
    # no live service. It carries no permission dependency and no
    # CurrentUser dependency, so the mocked host user's role_id
    # pointing at no row cannot interfere here — no role lookup
    # runs at all, and the handler takes only the AuthService
    # dependency (account_endpoint.py lines 234-257). The
    # deterministic ordering is the key: change_password
    # (auth_service.py lines 403-427) first calls
    # retrieve_password_reset_data_by_user_id, which returns None
    # for a fresh test DB with no UserPasswordReset document for
    # this user id (and returns None rather than raising even for
    # a malformed id), and raises InvalidOperationException
    # ("Invalid or expired password reset token.") BEFORE any JWT
    # verification, password update, or notification email — so a
    # garbage token is enough and the test depends on neither the
    # JWT secret nor any seeded record. The central
    # ApiBaseException handler maps InvalidOperationException to
    # 406 with body {"error": ..., "code": 406} plus no-store
    # headers (api/__init__.py lines 84-132). No refresh cookie
    # is set on this path: the handler returns a plain DTO only
    # on success, and this path raises before any token minting.
    # The endpoint takes a PasswordResetConfirmRequestDto body
    # (new_password) plus token and user_id query params
    # (auth_dto.py line 13), so the token/user_id must ride the
    # query string, not the JSON body, or FastAPI 422s and masks
    # the 406.
    response = await client.post(
        "/account/password_reset_confirmation?token=<redacted>&user_id=68c302ef6bf7a039b7e9b385",
        json={"new_password": "NewPassword123!"},
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Invalid or expired password reset token" in response.json()["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # Error responses must not be cached either: a cached 406
    # could be served to a different user after an account switch
    # on a shared machine, and a cached success on this flow
    # would replay a consumed reset link's token set.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-headers lock as the other account tests: the
    # pure-ASGI middleware stamps every HTTP response with no path
    # exclusions, so this 406 must carry the same headers.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the magic-link and reset-request locks, using substring checks
    # so later additions to the list do not break this test. Each
    # directive is safe to lock here for the same reasons as on the
    # other routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow (verified
    # by grep in the earlier sweeps).
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
async def test_account_activate_invalid_token_returns_406_with_cache_and_security_headers(client: AsyncClient):
    """
        The account activation POST for a garbage token:
    """
    # The next account route after password_reset_confirmation whose
    # error path needs no authenticated user, no seeded row, and
    # no live service. It carries no permission dependency and no
    # CurrentUser dependency, so the mocked host user's role_id
    # pointing at no row cannot interfere here — no role lookup
    # runs at all, and the handler takes only the AuthService
    # dependency (account_endpoint.py lines 276-284). The
    # deterministic ordering is the key: activate_account
    # (auth_service.py lines 458-482) first calls
    # verify_activation_token, which raises
    # InvalidOperationException ("Invalid activation token") for
    # a garbage token (jwt_token_service.py lines 121-147)
    # BEFORE any user lookup, activation write, or email — so
    # the test depends on neither the JWT secret nor any seeded
    # record, and a garbage token suffices regardless of the
    # secret. The central ApiBaseException handler maps
    # InvalidOperationException to 406 with body {"error": ...,
    # "code": 406} plus no-store headers (api/__init__.py lines
    # 84-132). No refresh cookie is set on this path: the
    # handler returns a bare 200 only on success, and this path
    # raises before any token minting. The DTO takes a plain
    # string token (user_dto.py line 125), trimmed by its
    # validator, so the garbage token must ride the JSON body,
    # not the query string, or FastAPI 422s and masks the 406.
    # Deliberately no resend-activation lock here: that route
    # carries a permission dependency (account_endpoint.py lines
    # 263-274), so under the conftest user its role lookup is
    # non-deterministic in the same way /me is — assess
    # separately with a seeded role.
    response = await client.post(
        "/account/activate",
        json={"token": "not-a-valid-jwt"},
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Invalid activation token" in response.json()["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # Error responses must not be cached either: a cached 406
    # could be served to a different user after an account switch
    # on a shared machine, and a cached success on this flow
    # would replay a consumed activation link's effect.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-headers lock as the other account tests: the
    # pure-ASGI middleware stamps every HTTP response with no path
    # exclusions, so this 406 must carry the same headers.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the reset-confirmation lock, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow (verified
    # by grep in the earlier sweeps).
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
