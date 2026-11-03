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


@pytest.mark.asyncio
async def test_account_login_unknown_email_returns_401_with_cache_and_security_headers(client: AsyncClient):
    """
        The account login POST for an unknown email:
    """
    # The next account route after activate whose error path needs
    # no authenticated user, no seeded row, and no live service. It
    # carries no permission dependency and no CurrentUser dependency,
    # so the mocked host user's role_id pointing at no row cannot
    # interfere here — no role lookup runs at all, and the handler
    # takes only the AuthService dependency plus the optional
    # X-Tenant-ID (account_endpoint.py lines 51-60). The
    # deterministic ordering is the key: login (auth_service.py
    # lines 176-194) first calls find_by_email, which raises
    # UserNotFoundException on the empty fresh test DB (User is in
    # the conftest model set), runs one dummy pbkdf2 verify so the
    # path takes about as long as a wrong-password attempt, and
    # raises UnauthorizedException ("Authentication failed. Please
    # check your credentials.") — the exact same generic 401 as a
    # wrong password, so unknown and wrong-password attempts are
    # indistinguishable and no account enumeration leaks. The
    # central ApiBaseException handler maps UnauthorizedException
    # to 401 with body {"error": ..., "code": 401} plus no-store
    # headers (api/__init__.py lines 84-132). The endpoint takes
    # an OAuth2PasswordRequestForm, so the credentials must ride
    # form fields (username/password), not a JSON body, or FastAPI
    # 422s and masks the 401. No refresh cookie is set on this
    # path: the handler raises before minting any token set.
    response = await client.post(
        "/account/login",
        data={"username": "unknown@example.com", "password": "WrongPassword123!"},
    )
    assert response.status_code == 401
    assert response.json()["code"] == 401
    assert "Authentication failed. Please check your credentials." in response.json()["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # Error responses must not be cached either: a cached 401
    # could be served to a different user after an account switch
    # on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-headers lock as the other account tests: the
    # pure-ASGI middleware stamps every HTTP response with no path
    # exclusions, so this 401 must carry the same headers.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the activate lock, using substring checks so later additions
    # to the list do not break this test. Each directive is safe to
    # lock here for the same reasons as on the other routes: the
    # SPA has no camera, microphone, geolocation, payment,
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
async def test_account_sso_login_unknown_provider_returns_422_with_security_headers(client: AsyncClient):
    """
        The account SSO login GET for an unknown provider name:
    """
    # The next account route after login whose error path needs
    # no authenticated user, no seeded row, and no live service.
    # It carries no permission dependency and no CurrentUser
    # dependency, so the mocked host user's role_id pointing at
    # no row cannot interfere here — and, crucially, no service
    # call runs at all. provider_name is typed SSOProvider, a
    # Literal of the ten supported providers (sso_settings.py
    # line 8: google, github, discord, microsoft, linkedin, x,
    # notion, gitlab, bitbucket, facebook), so FastAPI validates
    # the path parameter before any dependency resolves and a
    # name outside that Literal 422s. That ordering is what makes
    # this lock deterministic where the valid-provider path is
    # not: a valid provider would reach SSOAuthProvider.login,
    # which lists SSOSettings rows — but SSOSettings is NOT in
    # the conftest model set (User, Tenant, Role,
    # UserPasswordReset, UserPreference only), so that lookup's
    # outcome on the uninitialized collection is not reasoned
    # here, and a live provider redirect is not asserted either.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, and locking
    # cache headers here would assert behaviour no code promises.
    # The security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    response = await client.get("/account/sso/not-a-provider/login")
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "provider_name" in [str(part) for part in err.get("loc", [])]
        for err in detail
    )
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the login lock, using substring checks so later
    # additions to the list do not break this test.
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
async def test_account_sso_callback_unknown_provider_returns_422_with_security_headers(client: AsyncClient):
    """
        The account SSO callback GET for an unknown provider name:
    """
    # The callback is the SSO login's sibling route and its
    # unknown-provider path is lockable on exactly the same
    # reasoning, verified fresh this run, not assumed. It
    # carries no permission dependency and no CurrentUser
    # dependency, so the mocked host user's role_id pointing at
    # no row cannot interfere — and no service call runs at
    # all. provider_name is typed SSOProvider, a Literal of
    # the ten supported providers (sso_settings.py line 8:
    # google, github, discord, microsoft, linkedin, x, notion,
    # gitlab, bitbucket, facebook), so a name outside that
    # Literal 422s with detail loc containing provider_name
    # before the handler exchanges any provider code or sets
    # any refresh cookie. The callback's extra tenant
    # dependency is harmless to that outcome: get_tenant_id
    # only reads request.state.tenant_id and returns None when
    # unset (tenant_middleware.py lines 138-139), so it cannot
    # fail or redirect on this path. Deliberately NOT locked:
    # the valid-provider path, which would reach
    # SSOAuthProvider.callback and then login_with_sso —
    # SSOSettings is NOT in the conftest model set (User,
    # Tenant, Role, UserPasswordReset, UserPreference only),
    # so that lookup's outcome on the uninitialized
    # collection is not reasoned here, and no live provider
    # redirect or cookie is asserted either. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, and the
    # callback handler's own no-store lines run only after a
    # successful exchange. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    response = await client.get("/account/sso/not-a-provider/callback")
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "provider_name" in [str(part) for part in err.get("loc", [])]
        for err in detail
    )
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the SSO login lock, using substring checks so
    # later additions to the list do not break this test.
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
async def test_account_change_email_request_same_email_returns_406_with_cache_and_security_headers(client: AsyncClient):
    """
        The account change-email-request PATCH for the caller's own
        current email address:
    """
    # The change-email-request route had no header lock, and its
    # same-email branch is lockable without any seeded row, live
    # service, or sent email, verified fresh this run, not assumed.
    # The handler takes CurrentUser, which conftest overrides to
    # the mocked user admin@example.com (conftest.py), so PATCHing
    # with new_email equal to that address hits the service's
    # first check — current_email == new_email — and raises
    # InvalidOperationException("The new email address must be
    # different from the current email address.") before
    # check_email_exists, find_by_email, or any email send runs,
    # so no DB row and no SMTP call can affect the outcome. The
    # central ApiBaseException handler maps
    # InvalidOperationException to 406 with body {"error": ...,
    # "code": 406} and Cache-Control: no-store plus Pragma:
    # no-cache (api/__init__.py lines 84-132), and the pure-ASGI
    # security-headers middleware stamps every HTTP response
    # with no path exclusions. Deliberately NOT locked: a
    # different new_email, which would reach the user lookup and
    # the email send, and change_email_confirmation, whose token
    # lookup needs its own fresh verification.
    response = await client.patch(
        "/account/change_email_request",
        json={"new_email": "admin@example.com"},
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert (
        response.json()["error"]
        == "The new email address must be different from the current email address."
    )
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the SSO callback lock, using substring checks so
    # later additions to the list do not break this test.
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
async def test_account_change_email_confirmation_invalid_token_returns_400_with_cache_and_security_headers(client: AsyncClient):
    """
        The account change-email-confirmation PATCH with a token
        that is not a valid JWT:
    """
    # The change-email-confirmation route had no header lock, and
    # its invalid-token branch is lockable without any seeded row,
    # live service, or sent email, verified fresh this run, not
    # assumed. The endpoint carries no permission dependency and
    # no FrontendHost dependency; it takes CurrentUser, which
    # conftest overrides to the mocked user admin@example.com,
    # and a ChangeEmailConfirmRequestDto whose only field is the
    # token string (trimmed by its model validator, so a plain
    # garbage token still reaches verification). The service
    # verifies the JWT first — verify_change_email_token raises
    # InvalidOperationException("Invalid change email token") for
    # a non-JWT before any user lookup, email-existence check,
    # email update, or notification email — and the endpoint
    # catches InvalidOperationException and re-raises
    # HTTPException 400 with the generic detail "Email change
    # confirmation failed.", so the failure reveals nothing about
    # the token's shape or any account. The Starlette
    # HTTPException handler returns body {"detail": ...} with
    # Cache-Control: no-store plus Pragma: no-cache
    # (api/__init__.py), and the pure-ASGI security-headers
    # middleware stamps every HTTP response with no path
    # exclusions. Deliberately NOT locked: a valid token for
    # another user (needs a minted JWT, assessed separately)
    # and the success path (needs a minted token plus a seeded
    # user row). Note the body shape differs from the central
    # ApiBaseException error shape: this endpoint converts the
    # service error to a plain HTTPException, so the lock asserts
    # "detail", not "error"/"code".
    response = await client.patch(
        "/account/change_email_confirmation",
        json={"token": "not-a-jwt"},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Email change confirmation failed."
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the change-email-request lock, using substring
    # checks so later additions to the list do not break this test.
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
async def test_account_resend_activation_email_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The account resend-activation-email POST had no header lock,
        and its permission-gate branch is lockable without any seeded
        row, live service, or sent email, verified fresh this run,
        not assumed. The endpoint is permission-gated
        (USER_READ_AND_WRITE_ONLY or FULL_ACCESS), so it needs a DB
        role lookup, and the shared conftest client seeds no role:
        the mocked host user's role_id points at no row in the fresh
        test database (Role is in the conftest model set), so the
        permission dependency's get_role_by_id raises
        RoleNotFoundException before the service's find_by_email,
        is_active check, token minting, or any email send — no side
        effect. The DTO body passes validation (a valid email, an id
        string, and a first name), so no 422 can mask the 404, and
        the FrontendHost dependency only reads request state with
        no DB lookup. The central ApiBaseException handler maps the
        NotFound subclass to 404 with body {"error": ..., "code":
        404} and Cache-Control: no-store plus Pragma: no-cache
        (api/__init__.py lines 84-132), and the pure-ASGI
        security-headers middleware stamps every HTTP response
        with no path exclusions. Deliberately NOT locked: the 202
        success path, which needs a seeded role with the required
        permission plus an inactive seeded user row and an SMTP
        send, and the already-active 406 branch, which needs the
        same seeding. The error assertion uses a substring check
        for "Role", mirroring the role-list permission-gate lock,
        rather than the full constructed message.
    """
    response = await client.post(
        "/account/resend_activation_email",
        json={
            "email": "inactive@example.com",
            "id": "68c302ef6bf7a039b7e9b385",
            "first_name": "Inactive",
        },
    )
    assert response.status_code == 404
    assert response.json()["code"] == 404
    assert "Role" in response.json()["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the change-email-confirmation lock, using substring
    # checks so later additions to the list do not break this test.
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
async def test_account_change_email_confirmation_other_user_token_returns_400_with_cache_and_security_headers(client: AsyncClient):
    """
        The account change-email-confirmation PATCH for a token
        issued to another user:
    """
    # The valid-token-for-another-user branch was deliberately NOT
    # locked in iteration 2363 (it needs a minted JWT) and is locked
    # here, verified fresh this run, not assumed. The token is
    # minted inside the test with the app's own signing constants
    # (imported, never hardcoded): payload user_id differs from the
    # conftest mocked user (admin@example.com, id
    # 68c302ef6bf7a039b7e9b385), type is
    # "change_email_confirmation", and exp is one hour in the
    # future, so verify_change_email_token accepts it. The service
    # then compares payload.user_id against the authenticated
    # caller's id BEFORE any user lookup, email-existence check,
    # email update, or notification email, and raises
    # InvalidOperationException on the mismatch — so no seeded row
    # and no live service is needed, and no side effect occurs.
    # The endpoint catches InvalidOperationException and re-raises
    # HTTPException 400 with the generic detail "Email change
    # confirmation failed.", so the failure reveals nothing about
    # the token's owner or any account. The Starlette HTTPException
    # handler returns body {"detail": ...} with Cache-Control:
    # no-store plus Pragma: no-cache (api/__init__.py), and the
    # pure-ASGI security-headers middleware stamps every HTTP
    # response with no path exclusions. Deliberately NOT locked:
    # the success path (needs a token for the caller plus a seeded
    # user row and an SMTP send) and the already-in-use branch
    # (needs the same seeding). Note the body shape differs from
    # the central ApiBaseException error shape: this endpoint
    # converts the service error to a plain HTTPException, so the
    # lock asserts "detail", not "error"/"code", mirroring the
    # invalid-token lock.
    import jwt
    from datetime import datetime, timedelta, timezone

    from api.common.security import ALGORITHM, JWT_SECRET

    token = jwt.encode(
        {
            "user_id": "68c302ef6bf7a039b7e9b387",
            "email": "new@example.com",
            "type": "change_email_confirmation",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        },
        JWT_SECRET,
        algorithm=ALGORITHM,
    )
    response = await client.patch(
        "/account/change_email_confirmation",
        json={"token": token},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Email change confirmation failed."
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the resend-activation-email lock, using substring
    # checks so later additions to the list do not break this test.
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
async def test_account_register_missing_guest_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The account register POST when the GUEST role is absent:
    """
    # The register route had no header lock, and its missing-role
    # branch is lockable without any seeded row, live service, or
    # sent email, verified fresh this run, not assumed. The handler
    # first resolves the GUEST role (RoleType.GUEST, "guest") via
    # role_service.find_by_name, before assigning role_id, before
    # any tenant branching, and before AuthService.register runs
    # (password validation, user creation, and the post-tenant
    # worker payload all happen after this lookup). The shared
    # conftest client seeds no role and Role is in the conftest
    # model set, so the lookup on the fresh test database raises
    # RoleNotFoundException before any creation or email send — no
    # side effect. The DTO body passes validation (non-blank names,
    # a valid email, a gender value, and a password string), so no
    # 422 can mask the 404, and no X-Tenant-ID header is sent, so
    # the tenant-context branch cannot run first. The central
    # ApiBaseException handler maps the NotFound subclass to 404
    # with body {"error": ..., "code": 404} and Cache-Control:
    # no-store plus Pragma: no-cache (api/__init__.py), and the
    # pure-ASGI security-headers middleware stamps every HTTP
    # response with no path exclusions. Deliberately NOT locked:
    # the 201 success path (needs a seeded GUEST role plus tenant
    # creation or a direct user creation and an activation email)
    # and the taken-subdomain branch. The error assertion uses a
    # substring check for "Role", mirroring the
    # resend-activation-email lock, rather than the full
    # constructed message.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 404
    assert response.json()["code"] == 404
    assert "Role" in response.json()["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the change-email-confirmation lock, using substring
    # checks so later additions to the list do not break this test.
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
async def test_account_refresh_invalid_cookie_returns_401_with_cache_and_security_headers(client: AsyncClient):
    """
        The account refresh POST with an invalid refresh cookie:
    """
    # The refresh route's invalid-token branch had no header lock, and
    # it is lockable without any seeded row, live service, or valid
    # secret, verified fresh this run, not assumed. The handler only
    # checks that a cookie is present (the missing-cookie 403 lock
    # covers the absent case), then passes the raw cookie value
    # through the plain-str TokenRefreshRequestDto to
    # AuthService.refresh_token, which decodes it first, before any
    # user or role lookup (auth_service.py lines 351-360). A
    # non-JWT string fails decoding under any secret — decode_token
    # catches InvalidTokenError and returns None (jwt_token_service.py
    # lines 107-112) — so the service raises
    # UnauthorizedException("Invalid refresh token") with no DB
    # lookup, no token minting, and no new cookie. The central
    # ApiBaseException handler maps UnauthorizedException to 401 with
    # body {"error": ..., "code": 401} and Cache-Control: no-store
    # plus Pragma: no-cache (api/__init__.py lines 84-132), and the
    # pure-ASGI security-headers middleware stamps every HTTP response
    # with no path exclusions. Deliberately NOT locked: an expired but
    # otherwise well-formed refresh token (same 401 via the expired
    # branch, but minting one needs the refresh secret) and the 200
    # success path (needs a minted token plus a seeded user and role).
    response = await client.post(
        "/account/refresh",
        cookies={"refresh_token": "not-a-jwt"},
    )
    assert response.status_code == 401
    assert response.json()["code"] == 401
    assert response.json()["error"] == "Invalid refresh token"
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the register lock, using substring checks so later
    # additions to the list do not break this test.
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
async def test_account_refresh_expired_cookie_returns_401_with_cache_and_security_headers(client: AsyncClient):
    """
        The account refresh POST with an expired refresh cookie:
    """
    # The refresh route's expired-token branch had no header lock,
    # and it is lockable without any seeded row, live service, or
    # sent email, verified fresh this run, not assumed. The handler
    # only checks cookie presence (the missing-cookie 403 lock
    # covers absence), then passes the raw value to
    # AuthService.refresh_token, which decodes it FIRST, before
    # any user or role lookup (auth_service.py lines 351-360).
    # The token is minted inside the test with the app's own
    # refresh signing constants (imported, never hardcoded):
    # payload sub is a valid ObjectId, tenant_id is None, type
    # is "refresh" matching get_refresh_token, and exp is one
    # hour in the past, so decode_token's refresh branch raises
    # ExpiredSignatureError and returns None (jwt_token_service.py
    # lines 107-112) — a different decode branch from the
    # invalid-cookie lock's InvalidTokenError, but the same
    # downstream outcome — so the service raises
    # UnauthorizedException("Invalid refresh token") with no DB
    # lookup, no token minting, and no new cookie. The central
    # ApiBaseException handler maps UnauthorizedException to 401
    # with body {"error": ..., "code": 401} and Cache-Control:
    # no-store plus Pragma: no-cache (api/__init__.py lines
    # 84-132), and the pure-ASGI security-headers middleware
    # stamps every HTTP response with no path exclusions.
    # Deliberately NOT locked: the 200 success path (needs a
    # live, unexpired token plus seeded user and role rows after
    # decode) and the wrong-type token branch (an access token
    # presented as a refresh token, which needs a minted access
    # token and shares the same 401 outcome).
    import jwt
    from datetime import datetime, timedelta, timezone

    from api.common.security import REFRESH_ALGORITHM, REFRESH_TOKEN_SECRET

    token = jwt.encode(
        {
            "sub": "68c302ef6bf7a039b7e9b385",
            "tenant_id": None,
            "type": "refresh",
            "exp": datetime.now(timezone.utc) - timedelta(hours=1),
        },
        REFRESH_TOKEN_SECRET,
        algorithm=REFRESH_ALGORITHM,
    )
    response = await client.post(
        "/account/refresh",
        cookies={"refresh_token": token},
    )
    assert response.status_code == 401
    assert response.json()["code"] == 401
    assert response.json()["error"] == "Invalid refresh token"
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the refresh-invalid-cookie lock, using substring
    # checks so later additions to the list do not break this test.
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
async def test_account_refresh_wrong_type_token_returns_401_with_cache_and_security_headers(client: AsyncClient):
    """
        The account refresh POST with a live access token presented
        as the refresh cookie:
    """
    # The refresh route's wrong-type-token branch had no header lock,
    # and it is lockable without any seeded row, live service, or
    # sent email, verified fresh this run, not assumed. The handler
    # only checks cookie presence (the missing-cookie 403 lock
    # covers absence), then passes the raw value to
    # AuthService.refresh_token, which decodes it FIRST, before
    # any user or role lookup (auth_service.py lines 351-360).
    # The token is minted inside the test as a genuine access
    # token, with the app's own access signing constants
    # (imported, never hardcoded): sub is the conftest mocked
    # user id, email is admin@example.com, is_active is True,
    # no "type" claim (get_access_token adds none), and exp is
    # one hour in the future. Access tokens are signed HS256
    # (settings.algorithm default) while the refresh decode
    # branch only accepts HS512 (settings.refresh_algorithm
    # default), so PyJWT rejects the algorithm before any
    # signature or type check, and decode_token returns None
    # (jwt_token_service.py lines 92-112) — so this branch is
    # deterministic even if the two secrets ever coincided, and
    # it is distinct from the invalid-cookie lock (signature
    # failure) and the expired-cookie lock (expiry failure):
    # the service raises UnauthorizedException("Invalid refresh
    # token") with no DB lookup, no token minting, and no new
    # cookie. The central ApiBaseException handler maps
    # UnauthorizedException to 401 with body {"error": ...,
    # "code": 401} and Cache-Control: no-store plus Pragma:
    # no-cache (api/__init__.py lines 84-132), and the pure-ASGI
    # security-headers middleware stamps every HTTP response
    # with no path exclusions. Deliberately NOT locked: the 200
    # success path (needs a live, unexpired refresh token plus
    # seeded user and role rows after decode).
    import jwt
    from datetime import datetime, timedelta, timezone

    from api.common.security import ALGORITHM, JWT_SECRET

    token = jwt.encode(
        {
            "sub": "68c302ef6bf7a039b7e9b385",
            "email": "admin@example.com",
            "is_active": True,
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        },
        JWT_SECRET,
        algorithm=ALGORITHM,
    )
    response = await client.post(
        "/account/refresh",
        cookies={"refresh_token": token},
    )
    assert response.status_code == 401
    assert response.json()["code"] == 401
    assert response.json()["error"] == "Invalid refresh token"
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the refresh-expired-cookie lock, using substring
    # checks so later additions to the list do not break this test.
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
async def test_account_login_missing_password_returns_422_with_security_headers(client: AsyncClient):
    """
        The account login POST with the password form field omitted:
    """
    # The next account route after the refresh wrong-type lock
    # whose error path needs no seeded row, no live service, and
    # no authenticated user, verified fresh this run, not
    # assumed. The handler takes OAuth2PasswordRequestForm
    # (account_endpoint.py lines 51-60), whose username and
    # password fields are both required form fields, so FastAPI
    # validates the form BEFORE the handler body runs: the
    # LoginRequestDto construction and the AuthService.login
    # call (which would do the find_by_email lookup) never
    # execute, and no token is minted and no refresh cookie is
    # set. This is distinct from the login unknown-email 401
    # lock (a valid form reaching the service) and from a
    # malformed-email submission, which is deliberately NOT
    # locked here: a malformed username passes form validation
    # and only fails later inside the handler's LoginRequestDto
    # construction, whose error handling is not reasoned here.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the SSO unknown-provider 422 locks. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    response = await client.post(
        "/account/login",
        data={"username": "admin@example.com"},
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "password" in [str(part) for part in err.get("loc", [])]
        for err in detail
    )
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the refresh wrong-type lock, using substring
    # checks so later additions to the list do not break this test.
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
async def test_account_login_malformed_email_returns_422_with_security_headers(client: AsyncClient):
    """
        The account login POST with a malformed username (not an email):
    """
    # The follow-up to the missing-password 422 lock (iteration 2370):
    # a malformed username passes OAuth2PasswordRequestForm validation
    # (username is a free-form string) and only fails inside the
    # handler's LoginRequestDto construction, whose EmailStr field
    # raises a pydantic ValidationError. No exception handler in
    # api/__init__.py covers ValidationError (only ApiBaseException
    # and StarletteHTTPException), so before this run's fix the
    # caller got a bare 500 and no AuthService.login lookup ever ran
    # — the unknown-email 401 lock does not cover this path, because
    # that lock's valid email reaches the service. The fix maps the
    # ValidationError to HTTPException 422, so the central
    # StarletteHTTPException handler stamps Cache-Control no-store
    # and Pragma no-cache on the error response, unlike the FastAPI
    # request-validation 422s (missing password, unknown SSO
    # provider), which carry no cache headers. The security headers
    # ARE locked: the pure-ASGI middleware stamps every HTTP
    # response, including error responses, with no path exclusions.
    # Deliberately NOT locked: the login wrong-password 401 (needs
    # a seeded user row) and any token minting — no token is minted
    # and no refresh cookie is set on this path.
    response = await client.post(
        "/account/login",
        data={"username": "not-an-email", "password": "whatever123"},
    )
    assert response.status_code == 422
    assert "Invalid email format" in str(response.json()["detail"])
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the missing-password 422 lock, using substring
    # checks so later additions to the list do not break this test.
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
async def test_account_login_wrong_password_returns_401_with_cache_and_security_headers(client: AsyncClient):
    """
        The account login POST with a valid email but a wrong password:
    """
    # The follow-up to the unknown-email 401 lock and the malformed-email
    # 422 lock (iterations 2370-2371): those locks cover an email with
    # no row and a username that never reaches the service, but neither
    # exercises the found-user branch of AuthService.login
    # (auth_service.py lines 176-194), where find_by_email returns a
    # row and verify_password returns False. That branch must yield
    # the exact same generic 401 as the unknown-email path, or the two
    # outcomes become distinguishable and account enumeration leaks.
    # Seeding is done directly through the User document
    # (doc.insert(), the same call BaseRepository.create uses), not
    # through POST /users: that API route carries the permission
    # dependency whose role lookup 404s on the fresh test DB (the
    # mocked host user's role_id points at no row), so API creation
    # cannot seed here. No role row is needed on this path: login
    # raises UnauthorizedException before _get_token_set runs, so no
    # role lookup and no audit-log write ever happen (the AuditLog
    # model is not in the conftest model set, which is why the 200
    # success path stays unlocked). The seeded password is hashed
    # with the app's own hash_it, never stored in plaintext, and the
    # conftest fixture drops the test DB after the test, so the row
    # cannot leak into other tests. No X-Tenant-ID header is sent,
    # so both the seed and the login read the host test DB.
    from api.common.enums.gender import Gender
    from api.common.security import hash_it
    from api.domain.entities.user import User

    await User(
        first_name="Wrong",
        last_name="Password",
        email="wrongpass@example.com",
        gender=Gender.OTHER,
        is_active=True,
        password=hash_it("CorrectPassword123!"),
    ).insert()
    response = await client.post(
        "/account/login",
        data={"username": "wrongpass@example.com", "password": "WrongPassword123!"},
    )
    assert response.status_code == 401
    assert response.json()["code"] == 401
    assert "Authentication failed. Please check your credentials." in response.json()["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # Error responses must not be cached either: a cached 401
    # could be served to a different user after an account switch
    # on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-headers lock as the other account tests: the
    # pure-ASGI middleware stamps every HTTP response with no path
    # exclusions, so this 401 must carry the same headers.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the unknown-email 401 lock, using substring checks
    # so later additions to the list do not break this test.
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
async def test_account_change_email_confirmation_email_in_use_returns_400_with_cache_and_security_headers(client: AsyncClient):
    """
        The account change-email-confirmation PATCH when the new
        email is already in use by another account:
    """
    # The already-in-use branch was deliberately NOT locked in
    # iteration 2365 (it needs a caller-owned token plus seeded
    # rows) and is locked here, verified fresh this run, not
    # assumed. The token is minted inside the test with the app's
    # own signing constants (imported, never hardcoded): payload
    # user_id IS the conftest mocked user (admin@example.com, id
    # 68c302ef6bf7a039b7e9b385), type is
    # "change_email_confirmation", and exp is one hour in the
    # future, so verify_change_email_token accepts it and the
    # service's caller-ownership check passes. The service then
    # looks the caller up by id (auth_service.py
    # change_email_confirmation): the caller row is seeded with
    # that exact id via Beanie's explicit-id document insert, so
    # the lookup succeeds instead of 404ing, and
    # check_email_exists finds the second seeded row whose email
    # equals the token's new email, so the service raises
    # InvalidOperationException BEFORE any email update or
    # notification email — no side effect occurs. The endpoint
    # catches InvalidOperationException and re-raises HTTPException
    # 400 with the generic detail "Email change confirmation
    # failed.", so the failure reveals neither which account owns
    # the taken email nor the caller's current email. Seeding is
    # done directly through the User document (doc.insert(), the
    # same call BaseRepository.create uses), not through POST
    # /users, whose permission dependency 404s on the fresh test
    # DB (the standing role-list tension); no role row is needed
    # on this path because no role lookup runs before the raise,
    # and the conftest fixture drops the test DB after the test,
    # so the rows cannot leak into other tests. No X-Tenant-ID
    # header is sent, so the seeds and the service reads all use
    # the host test DB, and the service's get_user_by_id call
    # passes no tenant id, so the host caller may access any
    # record. Deliberately NOT locked: the success path (the
    # same seeding plus an SMTP send, which the test environment
    # does not stub), and any assertion about the caller's email
    # staying unchanged (that would need a post-request read of a
    # row the endpoint never returns). Note the body shape: this
    # endpoint converts the service error to a plain
    # HTTPException, so the lock asserts "detail", not
    # "error"/"code", mirroring the other-user-token lock.
    import jwt
    from datetime import datetime, timedelta, timezone

    from beanie import PydanticObjectId

    from api.common.enums.gender import Gender
    from api.common.security import ALGORITHM, JWT_SECRET, hash_it
    from api.domain.entities.user import User

    await User(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b385"),
        first_name="Admin",
        last_name="User",
        email="admin@example.com",
        gender=Gender.OTHER,
        is_active=True,
        password=hash_it("SeededPassword123!"),
    ).insert()
    await User(
        first_name="Taken",
        last_name="Email",
        email="taken@example.com",
        gender=Gender.OTHER,
        is_active=True,
        password=hash_it("SeededPassword123!"),
    ).insert()
    token = jwt.encode(
        {
            "user_id": "68c302ef6bf7a039b7e9b385",
            "email": "taken@example.com",
            "type": "change_email_confirmation",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        },
        JWT_SECRET,
        algorithm=ALGORITHM,
    )
    response = await client.patch(
        "/account/change_email_confirmation",
        json={"token": token},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Email change confirmation failed."
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the other-user-token lock, using substring
    # checks so later additions to the list do not break this test.
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
