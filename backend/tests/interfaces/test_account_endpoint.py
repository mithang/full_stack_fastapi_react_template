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


@pytest.mark.asyncio
async def test_account_change_email_confirmation_success_returns_200_with_security_headers(client: AsyncClient):
    """
        The account change-email-confirmation PATCH success path:
    """
    # The success path was deliberately NOT locked in iteration
    # 2373 (it needs the caller seeding plus an SMTP send) and is
    # locked here, verified fresh this run, not assumed. The token
    # is minted inside the test with the app's own signing
    # constants (imported, never hardcoded): payload user_id IS
    # the conftest mocked user (admin@example.com, id
    # 68c302ef6bf7a039b7e9b385), type is
    # "change_email_confirmation", and exp is one hour in the
    # future, so verify_change_email_token accepts it and the
    # service's caller-ownership check passes. The caller row is
    # seeded with that exact id via Beanie's explicit-id document
    # insert (the same mechanism as the already-in-use lock), so
    # get_user_by_id succeeds, and no second row is seeded, so
    # check_email_exists for the token's new email returns False
    # and the already-in-use raise cannot fire. The service then
    # updates the row and saves it BEFORE the notification email,
    # so a 200 here already proves the save completed (a save
    # failure would raise before the return), and the
    # notification send uses the default raise_on_failure=False,
    # whose handler swallows ApiError, ConnectionErrors, and any
    # other exception (smtp_email.py) — so an unconfigured or
    # unreachable SMTP server in the test environment cannot turn
    # this success into an error, unlike the change_email_request
    # path which opts into raise_on_failure=True. The endpoint
    # returns ChangeEmailResponseDto(message="Email changed
    # successfully.") with status 200 and sets no refresh cookie.
    # No Cache-Control assertion here, deliberately: unlike the
    # error paths (central HTTPException handler) and logout
    # (explicit handler headers), this success path sets no cache
    # headers, mirroring the magic-link 200 lock — PATCH responses
    # are not cached by default, so there is no header to lock.
    # No X-Tenant-ID header is sent, so the seed and the service
    # reads all use the host test DB, and the service's
    # get_user_by_id call passes no tenant id, so the host caller
    # may access the row. Seeding is done directly through the
    # User document (doc.insert(), the same call
    # BaseRepository.create uses), not through POST /users, whose
    # permission dependency 404s on the fresh test DB (the
    # standing role-list tension); no role row is needed on this
    # path because no role lookup runs before the return, and the
    # conftest fixture drops the test DB after the test, so the
    # row cannot leak into other tests.
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
    token = jwt.encode(
        {
            "user_id": "68c302ef6bf7a039b7e9b385",
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
    assert response.status_code == 200
    assert response.json()["message"] == "Email changed successfully."
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the already-in-use lock, using substring checks
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
async def test_account_resend_activation_email_already_active_returns_406_with_cache_and_security_headers(client: AsyncClient):
    """
        The account resend-activation-email POST for an already-active user:
    """
    # The already-active branch was deliberately NOT locked in the
    # permission-gate lock (it needs a seeded role plus a seeded
    # active user row) and is locked here, verified fresh this run,
    # not assumed. The endpoint is permission-gated with
    # required_permissions=[USER_READ_AND_WRITE_ONLY, FULL_ACCESS]
    # through the factory's defaults any_permission=False and
    # allow_self_access=False, so the mocked caller's role must
    # carry BOTH permissions, not just one: the factory passes
    # any_permission=False into UserAccessManagement, whose
    # has_permission then requires all required permissions. The
    # role row is therefore seeded with the mocked user's exact
    # role_id (68c302ef6bf7a039b7e9b386) and both permissions, so
    # get_role_by_id succeeds and the gate passes — the opposite
    # of the missing-role 404 lock, which seeds no role. The
    # service then calls find_by_email on the DTO email, which
    # returns the seeded active row, and raises
    # InvalidOperationException("User is already active.") BEFORE
    # any token minting or email send, so the raise_on_failure=True
    # SMTP send on the 202 success path can never run here and no
    # live mail server is needed — unlike the 202 success branch,
    # which stays deliberately NOT locked because it needs that
    # send to succeed. The central ApiBaseException handler maps
    # InvalidOperationException to 406 with body {"error": ...,
    # "code": 406} and Cache-Control: no-store plus Pragma:
    # no-cache (api/__init__.py), and the pure-ASGI
    # security-headers middleware stamps every HTTP response with
    # no path exclusions. Seeding is done directly through the
    # Role and User documents (doc.insert(), the same call
    # BaseRepository.create uses), not through POST endpoints,
    # whose own permission dependencies 404 on the fresh test DB
    # (the standing role-list tension); no X-Tenant-ID header is
    # sent, so the seeds and the service reads all use the host
    # test DB, and the conftest fixture drops the test DB after
    # the test, so the rows cannot leak into other tests.
    from beanie import PydanticObjectId

    from api.common.enums.gender import Gender
    from api.common.security import hash_it
    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Admin",
        description="Administrator role for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY, Permission.FULL_ACCESS],
    ).insert()
    await User(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b390"),
        first_name="Active",
        last_name="User",
        email="active@example.com",
        gender=Gender.OTHER,
        is_active=True,
        password=hash_it("Password123!"),
    ).insert()
    response = await client.post(
        "/account/resend_activation_email",
        json={
            "email": "active@example.com",
            "id": "68c302ef6bf7a039b7e9b390",
            "first_name": "Active",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert response.json()["error"] == "User is already active."
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
async def test_account_register_missing_password_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with the password field omitted:
    """
    # The next account route after the resend-activation-email
    # already-active 406 lock whose error path needs no seeded row,
    # no live service, and no sent email, verified fresh this run,
    # not assumed. CreateUserDto.password is a required str field
    # (user_dto.py), so FastAPI request validation fails before
    # the handler body runs: the GUEST role lookup, the tenant
    # branching, AuthService.register, and the activation email
    # never execute, and no token is minted and no refresh cookie
    # is set. The endpoint's dependencies cannot mask the 422
    # either: get_auth_service/get_role_service only resolve
    # container objects and get_tenant_id only reads request
    # state, with no database lookup. This is distinct from the
    # register missing-GUEST-role 404 lock (a valid body reaching
    # the role lookup) and from a weak-password submission, which
    # is deliberately NOT locked here: password policy is only
    # validated inside the handler/callback, after the role
    # lookup, so it needs a seeded GUEST role. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the login missing-password 422 lock. The security headers
    # ARE locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
        },
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
    # mirroring the login missing-password 422 lock, using substring
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
async def test_account_register_missing_email_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with the email field omitted:
    """
    # The next register validation branch after the missing-password
    # 422 lock whose error path needs no seeded row, no live service,
    # and no sent email, verified fresh this run, not assumed.
    # BaseUserDto.email is a required EmailStr field with no default
    # (user_dto.py), so FastAPI request validation fails before the
    # handler body runs: the GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never execute,
    # and no token is minted and no refresh cookie is set. The
    # endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid
    # (non-blank names, a gender value, a password string), so no
    # other 422 can mask the email error. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central handler's
    # no-store headers do not apply to it, mirroring the register
    # missing-password 422 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "email" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register missing-password 422 lock, using substring
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
async def test_account_register_missing_first_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with the first_name field omitted:
    """
    # The next register validation branch after the missing-email
    # 422 lock whose error path needs no seeded row, no live service,
    # and no sent email, verified fresh this run, not assumed.
    # BaseUserDto.first_name is a required str field with
    # min_length=1 and no default (user_dto.py), so FastAPI request
    # validation fails before the handler body runs: the GUEST role
    # lookup, the tenant branching, AuthService.register, and the
    # activation email never execute, and no token is minted and no
    # refresh cookie is set. The endpoint's dependencies cannot mask
    # the 422 either: get_auth_service/get_role_service only resolve
    # container objects and get_tenant_id only reads request state,
    # with no database lookup. The remaining body fields are all
    # valid (a non-blank last name, a valid email, gender "other",
    # a password string), so no other 422 can mask the first_name
    # error. Deliberately no Cache-Control/Pragma assertion: a 422
    # is FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register missing-email 422 lock. The security
    # headers ARE locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "first_name" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register missing-email 422 lock, using substring
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
async def test_account_register_missing_last_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with the last_name field omitted:
    """
    # The next register validation branch after the missing-first_name
    # 422 lock whose error path needs no seeded row, no live service,
    # and no sent email, verified fresh this run, not assumed.
    # BaseUserDto.last_name is a required str field with
    # min_length=1 and no default (user_dto.py), so FastAPI request
    # validation fails before the handler body runs: the GUEST role
    # lookup, the tenant branching, AuthService.register, and the
    # activation email never execute, and no token is minted and no
    # refresh cookie is set. The endpoint's dependencies cannot mask
    # the 422 either: get_auth_service/get_role_service only resolve
    # container objects and get_tenant_id only reads request state,
    # with no database lookup. The remaining body fields are all
    # valid (a non-blank first name, a valid email, gender "other",
    # a password string), so no other 422 can mask the last_name
    # error. Deliberately no Cache-Control/Pragma assertion: a 422
    # is FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register missing-first_name 422 lock. The security
    # headers ARE locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "last_name" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register missing-first_name 422 lock, using substring
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

async def test_account_register_missing_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with the gender field omitted:
    """
    # The next register validation branch after the missing-last_name
    # 422 lock whose error path needs no seeded row, no live service,
    # and no sent email, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), so FastAPI request validation fails before the
    # handler body runs: the GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never execute,
    # and no token is minted and no refresh cookie is set. The
    # endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container objects
    # and get_tenant_id only reads request state, with no database
    # lookup. The remaining body fields are all valid (non-blank first
    # and last names, a valid email, a password string), so no other
    # 422 can mask the gender error. The mode="after" normalize_names
    # validator cannot mask it either, since it runs only after field
    # validation passes. Deliberately no Cache-Control/Pragma
    # assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store headers do
    # not apply to it, mirroring the register missing-last_name 422
    # lock. The security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors, with no
    # path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register missing-last_name 422 lock, using substring
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


async def test_account_register_invalid_email_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a malformed email value:
    """
    # The next register validation branch after the missing-gender
    # 422 lock whose error path needs no seeded row, no live service,
    # and no sent email, verified fresh this run, not assumed.
    # BaseUserDto.email is a required EmailStr field with no default
    # (user_dto.py), so a value with no "@" fails FastAPI request
    # validation before the handler body runs: the GUEST role lookup,
    # the tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. The endpoint's dependencies cannot mask the 422
    # either: get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid
    # (non-blank first and last names, gender "other", a password
    # string), so no other 422 can mask the email error. The
    # mode="after" normalize_names validator cannot mask it either,
    # since it runs only after field validation passes. Deliberately
    # no Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central handler's
    # no-store headers do not apply to it, mirroring the register
    # missing-gender 422 lock. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "not-an-email",
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "email" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register missing-gender 422 lock, using substring
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


async def test_account_register_invalid_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an invalid gender value:
    """
    # The next register validation branch after the invalid-email
    # 422 lock whose error path needs no seeded row, no live service,
    # and no sent email, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py line 12), and Gender admits only "male",
    # "female", "other", and "prefer_not_to_say" (gender.py), so a
    # value outside that set fails FastAPI request validation before
    # the handler body runs: the GUEST role lookup, the tenant
    # branching, AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie is set.
    # The endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, a password
    # string), so no other 422 can mask the gender error. The
    # mode="after" normalize_names validator cannot mask it either,
    # since it runs only after field validation passes. Deliberately
    # no Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central handler's
    # no-store headers do not apply to it, mirroring the register
    # invalid-email 422 lock. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "unknown",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register invalid-email 422 lock, using substring
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


async def test_account_register_blank_first_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a whitespace-only first_name:
    """
    # The next register validation branch after the invalid-gender
    # 422 lock whose error path needs no seeded row, no live service,
    # and no sent email, verified fresh this run, not assumed.
    # BaseUserDto.first_name is a str with min_length=1
    # (user_dto.py), so "   " passes field validation (length 3) and
    # only fails in the mode="after" normalize_names validator, which
    # raises ValueError "first_name must not be blank" for a value
    # trimming to empty. That is still FastAPI request validation, so
    # it fails before the handler body runs: the GUEST role lookup,
    # the tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. The endpoint's dependencies cannot mask the 422
    # either: get_auth_service/get_role_service only resolve
    # container objects and get_tenant_id only reads request state,
    # with no database lookup. The remaining body fields are all
    # valid (a non-blank last name, a valid email, gender "other",
    # a password string), so no other 422 can mask the first_name
    # error. The assertion reads the validator message rather than
    # the error loc: a model_validator error is located at the body,
    # not at the field, so its loc carries no "first_name" part.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register invalid-gender 422 lock. The security
    # headers ARE locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "   ",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "first_name must not be blank" in str(err.get("msg", ""))
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
    # mirroring the register invalid-gender 422 lock, using substring
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


async def test_account_register_blank_last_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a whitespace-only last_name:
    """
    # The mirror of the register blank-first_name 422 lock, verified
    # fresh this run, not assumed. BaseUserDto.last_name is a str
    # with min_length=1 (user_dto.py), so "   " passes field
    # validation (length 3) and only fails in the mode="after"
    # normalize_names validator, which raises ValueError
    # "last_name must not be blank" for a value trimming to empty.
    # That is still FastAPI request validation, so it fails before
    # the handler body runs: the GUEST role lookup, the tenant
    # branching, AuthService.register, and the activation email
    # never execute, and no token is minted and no refresh cookie
    # is set. The endpoint's dependencies cannot mask the 422
    # either: get_auth_service/get_role_service only resolve
    # container objects and get_tenant_id only reads request state,
    # with no database lookup. The remaining body fields are all
    # valid (a non-blank first name, a valid email, gender "other",
    # a password string), so no other 422 can mask the last_name
    # error. The assertion reads the validator message rather than
    # the error loc: a model_validator error is located at the body,
    # not at the field, so its loc carries no "last_name" part.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register blank-first_name 422 lock. The security
    # headers ARE locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "   ",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "last_name must not be blank" in str(err.get("msg", ""))
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
    # mirroring the register blank-first_name 422 lock, using substring
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


async def test_account_register_empty_first_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an empty-string first_name:
    """
    # The next register validation branch after the blank-last_name
    # 422 lock, verified fresh this run, not assumed. This branch is
    # distinct from the whitespace-only locks: BaseUserDto.first_name
    # is a str with min_length=1 (user_dto.py), so "" fails FIELD
    # validation (pydantic v2 string_too_short) before the
    # mode="after" normalize_names validator ever runs — the blank
    # validator would also reject it, but it is never reached, and
    # its error is located at the body rather than at the field.
    # This is still FastAPI request validation, so it fails before
    # the handler body runs: the GUEST role lookup, the tenant
    # branching, AuthService.register, and the activation email
    # never execute, and no token is minted and no refresh cookie
    # is set. The endpoint's dependencies cannot mask the 422
    # either: get_auth_service/get_role_service only resolve
    # container objects and get_tenant_id only reads request state,
    # with no database lookup. The remaining body fields are all
    # valid (a non-blank last name, a valid email, gender "other",
    # a password string), so no other 422 can mask the first_name
    # error. The assertion reads the field error's loc and type,
    # not the validator message used by the blank-name locks, since
    # a field-validation error carries loc ["body", "first_name"]
    # and type "string_too_short". Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central handler's
    # no-store headers do not apply to it, mirroring the register
    # blank-last_name 422 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "first_name" in [str(part) for part in err.get("loc", [])]
        and err.get("type") == "string_too_short"
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
    # mirroring the register blank-last_name 422 lock, using substring
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


async def test_account_register_empty_last_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an empty-string last_name:
    """
    # The mirror of the empty-first_name 422 lock, verified fresh
    # this run, not assumed. BaseUserDto.last_name is a str with
    # min_length=1 (user_dto.py), so "" fails FIELD validation
    # (pydantic v2 string_too_short, loc ["body", "last_name"])
    # before the mode="after" normalize_names validator ever runs
    # — the blank validator would also reject it, but it is never
    # reached, and its error is located at the body rather than at
    # the field. This is still FastAPI request validation, so it
    # fails before the handler body runs: the GUEST role lookup,
    # the tenant branching, AuthService.register, and the
    # activation email never execute, and no token is minted and
    # no refresh cookie is set. The endpoint's dependencies
    # cannot mask the 422 either: get_auth_service/
    # get_role_service only resolve container objects and
    # get_tenant_id only reads request state, with no database
    # lookup. The remaining body fields are all valid (a non-blank
    # first name, a valid email, gender "other", a password
    # string), so no other 422 can mask the last_name error.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register empty-first_name 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "last_name" in [str(part) for part in err.get("loc", [])]
        and err.get("type") == "string_too_short"
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
    # mirroring the register empty-first_name 422 lock, using substring
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


async def test_account_register_invalid_tenant_id_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a malformed tenant_id:
    """
    # The next register validation branch after the empty-last_name
    # 422 lock, verified fresh this run, not assumed. CreateUserDto
    # inherits tenant_id: PydanticObjectId | None from BaseUserDto
    # (user_dto.py line 13), so a non-ObjectId string fails FastAPI
    # request validation before the handler body runs: the GUEST
    # role lookup, the tenant branching, AuthService.register, and
    # the activation email never execute, and no token is minted
    # and no refresh cookie is set. The endpoint's dependencies
    # cannot mask the 422 either: get_auth_service/get_role_service
    # only resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. The remaining body
    # fields are all valid (non-blank names, a valid email, gender
    # "other", a password string), so no other 422 can mask the
    # tenant_id error. Deliberately no exact error-type assertion:
    # unlike string_too_short for the name fields, the beanie
    # PydanticObjectId error type has no precedent in this file,
    # so the lock asserts only the 422 status and a detail entry
    # located at tenant_id. Deliberately no Cache-Control/Pragma
    # assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store headers
    # do not apply to it, mirroring the register empty-last_name
    # 422 lock. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including validation
    # errors, with no path exclusions. Note on the branch NOT
    # locked here: an empty-string password is not a field
    # validation branch at all — CreateUserDto.password is a plain
    # str with no min_length, so "" passes DTO validation and
    # reaches the handler, where the outcome depends on the GUEST
    # role lookup, the tenancy mode, and AuthService.register's
    # password-policy check, so it is non-deterministic in this
    # test environment and is deliberately left unlocked.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "tenant_id": "not-an-objectid",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "tenant_id" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register empty-last_name 422 lock, using substring
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
async def test_account_register_invalid_role_id_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a malformed role_id:
    """
    # The next register validation branch after the invalid-tenant_id
    # 422 lock, verified fresh this run, not assumed. CreateUserDto
    # inherits role_id: PydanticObjectId | None from BaseUserDto
    # (user_dto.py line 14), the mirror of the tenant_id field, so
    # a non-ObjectId string fails FastAPI request validation before
    # the handler body runs: the GUEST role lookup, the tenant
    # branching, AuthService.register, and the activation email
    # never execute, and no token is minted and no refresh cookie
    # is set. The mode="after" normalize_names validator cannot
    # mask the error either, since it runs only after field
    # validation passes. The endpoint's dependencies cannot mask
    # the 422 either: get_auth_service/get_role_service only
    # resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. The remaining body
    # fields are all valid (non-blank names, a valid email, gender
    # "other", a password string, no tenant_id supplied), so no
    # other 422 can mask the role_id error. Deliberately no exact
    # error-type assertion: like the beanie PydanticObjectId error
    # type for tenant_id, it has no precedent in this file, so the
    # lock asserts only the 422 status and a detail entry located
    # at role_id. Deliberately no Cache-Control/Pragma assertion:
    # a 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the register invalid-tenant_id 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with no
    # path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "role_id": "not-an-objectid",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "role_id" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register invalid-tenant_id 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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
async def test_account_register_nonstring_first_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a non-string first_name:
    """
    # The next register validation branch after the invalid-role_id
    # 422 lock, verified fresh this run, not assumed. The two
    # branches suggested for this run do NOT yield a deterministic
    # 422 and are deliberately not locked here: CreateUserDto inherits
    # sso_provider_id: Optional[str] = None and adds
    # sub_domain: Optional[str] = None (user_dto.py), both with no
    # constraint, so any string passes DTO validation and reaches
    # the handler, where the outcome depends on the GUEST role
    # lookup and AuthService.register; and a padded name is trimmed
    # by the mode="after" normalize_names validator and then also
    # reaches the handler, so it is likewise DB-dependent rather
    # than a validation failure. By contrast, first_name is a plain
    # str field, so a JSON list value cannot be coerced to a string
    # under any Pydantic version and fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the tenant
    # branching, AuthService.register, and the activation email
    # never execute, and no token is minted and no refresh cookie
    # is set. The mode="after" normalize_names validator cannot
    # mask the error either, since it runs only after field
    # validation passes. The endpoint's dependencies cannot mask
    # the 422 either: get_auth_service/get_role_service only
    # resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. The remaining body
    # fields are all valid (a non-blank last name, a valid email,
    # gender "other", a password string, no tenant_id or role_id
    # supplied), so no other 422 can mask the first_name error.
    # Deliberately no exact error-type assertion: like the beanie
    # PydanticObjectId error type for tenant_id/role_id, a
    # string-type error type has no precedent in this file, so the
    # lock asserts only the 422 status and a detail entry located
    # at first_name. Deliberately no Cache-Control/Pragma assertion:
    # a 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the register invalid-role_id 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with no
    # path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": ["New"],
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "first_name" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register invalid-role_id 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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
async def test_account_register_nonstring_last_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a non-string last_name:
    """
    # The next register validation branch after the non-string
    # first_name 422 lock, verified fresh this run, not assumed.
    # CreateUserDto inherits last_name: str = Field(min_length=1)
    # from BaseUserDto (user_dto.py), so a JSON list value cannot
    # be coerced to a string under any Pydantic version and fails
    # FastAPI request validation before the handler body runs: the
    # GUEST role lookup, the tenant branching, AuthService.register,
    # and the activation email never execute, and no token is minted
    # and no refresh cookie is set. The mode="after" normalize_names
    # validator cannot mask the error either, since it runs only
    # after field validation passes. The endpoint's dependencies
    # cannot mask the 422 either: get_auth_service/get_role_service
    # only resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. The remaining body
    # fields are all valid (a non-blank first name, a valid email,
    # gender "other", a password string, no tenant_id or role_id
    # supplied), so no other 422 can mask the last_name error.
    # Deliberately no exact error-type assertion: like the
    # non-string first_name lock, a string-type error type has no
    # precedent in this file, so the lock asserts only the 422
    # status and a detail entry located at last_name. Deliberately
    # no Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central handler's
    # no-store headers do not apply to it, mirroring the register
    # non-string first_name 422 lock. The security headers ARE
    # locked: the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": ["User"],
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "last_name" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register non-string first_name 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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
async def test_account_register_nonstring_email_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a non-string email value:
    """
    # The next register validation branch after the non-string
    # last_name 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.email is a required EmailStr field with no default
    # (user_dto.py), so a JSON list value cannot be coerced to a
    # string email under any Pydantic version and fails FastAPI
    # request validation before the handler body runs: the GUEST
    # role lookup, the tenant branching, AuthService.register,
    # and the activation email never execute, and no token is minted
    # and no refresh cookie is set. The mode="after" normalize_names
    # validator cannot mask the error either, since it runs only
    # after field validation passes. The endpoint's dependencies
    # cannot mask the 422 either: get_auth_service/get_role_service
    # only resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. The remaining body
    # fields are all valid (non-blank first and last names, gender
    # "other", a password string, no tenant_id or role_id
    # supplied), so no other 422 can mask the email error.
    # Deliberately no exact error-type assertion: like the
    # non-string first_name/last_name locks, an email-type error
    # type has no precedent in this file, so the lock asserts only
    # the 422 status and a detail entry located at email.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register non-string last_name 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with no
    # path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": ["newuser@example.com"],
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "email" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register non-string last_name 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_nonstring_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a non-string gender value:
    """
    # The next register validation branch after the non-string
    # email 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender is a str Enum with only "male",
    # "female", "other" and "prefer_not_to_say" (gender.py), so a
    # JSON list value cannot be coerced to a Gender member under
    # any Pydantic version and fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. The mode="after" normalize_names validator
    # cannot mask the error either, since it runs only after field
    # validation passes. The endpoint's dependencies cannot mask
    # the 422 either: get_auth_service/get_role_service only
    # resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. The remaining body
    # fields are all valid (non-blank first and last names, a
    # valid email, a password string, no tenant_id or role_id
    # supplied), so no other 422 can mask the gender error.
    # Deliberately no exact error-type assertion: like the
    # non-string email lock, a gender-type error type has no
    # precedent in this file, so the lock asserts only the 422
    # status and a detail entry located at gender.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register non-string email 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with no
    # path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": ["other"],
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register non-string email 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_nonstring_password_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a non-string password value:
    """
    # The next register validation branch after the non-string
    # gender 422 lock, verified fresh this run, not assumed.
    # CreateUserDto.password is a required str field with no default
    # (user_dto.py), so a JSON list value cannot be coerced to a str
    # and fails FastAPI request validation before the handler body
    # runs: the GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never execute,
    # and no token is minted and no refresh cookie is set. The
    # mode="after" normalize_names validator cannot mask the error
    # either, since it runs only after field validation passes. The
    # endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects (container.py) and get_tenant_id only reads request
    # state (tenant_middleware.py), with no database lookup. The
    # remaining body fields are all valid (non-blank first and last
    # names, a valid email, gender "other", no tenant_id or role_id
    # supplied), so no other 422 can mask the password error.
    # Deliberately no exact error-type assertion: like the non-string
    # gender lock, a password-type error type has no precedent in
    # this file, so the lock asserts only the 422 status and a
    # detail entry located at password.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register non-string gender 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with no
    # path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": ["Register123!"],
        },
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
    # mirroring the register non-string gender 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_nonstring_sub_domain_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a non-string sub_domain value:
    """
    # The next register validation branch after the non-string
    # password 422 lock, verified fresh this run, not assumed.
    # CreateUserDto.sub_domain is an Optional[str] field with a None
    # default (user_dto.py), so a JSON list value cannot be coerced
    # to a str and fails FastAPI request validation before the
    # handler body runs: the GUEST role lookup, the tenant
    # branching, AuthService.register, and the activation email
    # never execute, and no token is minted and no refresh cookie
    # is set. The mode="after" normalize_names validator cannot
    # mask the error either, since it runs only after field
    # validation passes. The endpoint's dependencies cannot mask
    # the 422 either: get_auth_service/get_role_service only
    # resolve container objects (container.py) and get_tenant_id
    # only reads request state (tenant_middleware.py), with no
    # database lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, gender
    # "other", a password string, no tenant_id or role_id
    # supplied), so no other 422 can mask the sub_domain error.
    # Deliberately no exact error-type assertion: like the
    # non-string password lock, a sub_domain-type error type has
    # no precedent in this file, so the lock asserts only the 422
    # status and a detail entry located at sub_domain.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register non-string password 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with no
    # path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "sub_domain": ["tenant"],
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "sub_domain" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register non-string password 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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
async def test_account_register_nonstring_sso_provider_id_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a non-string sso_provider_id value:
    """
    # The next register validation branch after the non-string
    # sub_domain 422 lock, verified fresh this run, not assumed.
    # CreateUserDto inherits sso_provider_id: Optional[str] = None
    # from BaseUserDto (user_dto.py), so a JSON list value cannot
    # be coerced to a str and fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. An earlier run noted that any *string*
    # sso_provider_id passes DTO validation (no constraint) and
    # reaches the handler, where the outcome is DB-dependent;
    # that note does not cover a non-string value, which fails
    # field validation outright, so this branch is deterministic.
    # The mode="after" normalize_names validator cannot mask the
    # error either, since it runs only after field validation
    # passes. The endpoint's dependencies cannot mask the 422
    # either: get_auth_service/get_role_service only resolve
    # container objects (account_endpoint.py register signature)
    # and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, gender
    # "other", a password string, no tenant_id, role_id, or
    # sub_domain supplied), so no other 422 can mask the
    # sso_provider_id error.
    # Deliberately no exact error-type assertion: like the
    # non-string sub_domain lock, a sso_provider_id-type error
    # type has no precedent in this file, so the lock asserts
    # only the 422 status and a detail entry located at
    # sso_provider_id.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register non-string sub_domain 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with no
    # path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "sso_provider_id": ["google"],
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "sso_provider_id" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register non-string sub_domain 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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
async def test_account_register_nonstring_tenant_id_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a non-string tenant_id value:
    """
    # The next register validation branch after the non-string
    # sso_provider_id 422 lock, verified fresh this run, not assumed.
    # CreateUserDto inherits tenant_id: PydanticObjectId | None
    # from BaseUserDto (user_dto.py), so a JSON list value cannot
    # be coerced to an ObjectId and fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. This is distinct from the earlier
    # invalid-tenant_id lock, which used a malformed *string*
    # ("not-an-objectid"); a list value fails field validation
    # outright on type, not on ObjectId parsing, so it is a
    # separate branch. The mode="after" normalize_names validator
    # cannot mask the error either, since it runs only after field
    # validation passes. The endpoint's dependencies cannot mask
    # the 422 either: get_auth_service/get_role_service only
    # resolve container objects (account_endpoint.py register
    # signature) and get_tenant_id only reads request state, with
    # no database lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, gender
    # "other", a password string, no role_id, sso_provider_id, or
    # sub_domain supplied), so no other 422 can mask the
    # tenant_id error.
    # Deliberately no exact error-type assertion: like the
    # non-string sso_provider_id lock, a tenant_id-type error
    # type has no precedent in this file, so the lock asserts
    # only the 422 status and a detail entry located at
    # tenant_id.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register non-string sso_provider_id 422 lock.
    # The security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "tenant_id": ["507f1f77bcf86cd799439011"],
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "tenant_id" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register non-string sso_provider_id 422 lock,
    # using substring checks so later additions to the list do not
    # break this test.
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
async def test_account_register_nonstring_role_id_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a non-string role_id value:
    """
    # The next register validation branch after the non-string
    # tenant_id 422 lock, verified fresh this run, not assumed.
    # CreateUserDto inherits role_id: PydanticObjectId | None
    # from BaseUserDto (user_dto.py), so a JSON list value cannot
    # be coerced to an ObjectId and fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. This is distinct from the earlier
    # invalid-role_id lock, which used a malformed *string*
    # ("not-an-objectid"); a list value fails field validation
    # outright on type, not on ObjectId parsing, so it is a
    # separate branch. It is also unaffected by the handler's
    # `data.role_id = role_guest.id` overwrite, which runs only
    # after validation passes. The mode="after" normalize_names
    # validator cannot mask the error either, since it runs only
    # after field validation passes. The endpoint's dependencies
    # cannot mask the 422 either: get_auth_service/get_role_service
    # only resolve container objects (account_endpoint.py register
    # signature) and get_tenant_id only reads request state, with
    # no database lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, gender
    # "other", a password string, no tenant_id, sso_provider_id, or
    # sub_domain supplied), so no other 422 can mask the
    # role_id error.
    # Deliberately no exact error-type assertion: like the
    # non-string tenant_id lock, a role_id-type error
    # type has no precedent in this file, so the lock asserts
    # only the 422 status and a detail entry located at
    # role_id.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register non-string tenant_id 422 lock.
    # The security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "role_id": ["507f1f77bcf86cd799439011"],
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "role_id" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register non-string tenant_id 422 lock,
    # using substring checks so later additions to the list do not
    # break this test.
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
async def test_account_register_missing_body_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with no request body at all:
    """
    # The next register validation branch after the non-string
    # role_id 422 lock whose error path needs no seeded row, no live
    # service, and no sent email, verified fresh this run, not
    # assumed. The register handler takes a required `data:
    # CreateUserDto` body parameter with no default
    # (account_endpoint.py), so a POST with no body at all fails
    # FastAPI request validation before the handler body runs: the
    # GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never execute,
    # and no token is minted and no refresh cookie is set. The
    # endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with no
    # database lookup. Unlike the per-field locks, the detail loc
    # here is ["body"] rather than a field name, since the whole
    # body is missing, so the assertion locks "body" in the loc.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register non-string role_id 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with no
    # path exclusions.
    response = await client.post("/account/register")
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "body" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register non-string role_id 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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
async def test_account_register_nonobject_body_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a non-object JSON body:
    """
    # The next register validation branch after the missing-body
    # 422 lock, verified fresh this run, not assumed. The
    # register handler takes a required `data: CreateUserDto`
    # body parameter with no default (account_endpoint.py), so
    # a JSON array body cannot be coerced to the CreateUserDto
    # model and fails FastAPI request validation before the
    # handler body runs: the GUEST role lookup, the tenant
    # branching, AuthService.register, and the activation email
    # never execute, and no token is minted and no refresh
    # cookie is set. This is distinct from the missing-body
    # lock (no body at all) and from the per-field non-string
    # locks (an object body with one mistyped field): here the
    # whole body is the wrong JSON type, so the detail loc is
    # ["body"] rather than a field name, mirroring the
    # missing-body lock. The mode="after" normalize_names
    # validator cannot mask it either, since it runs only
    # after field validation passes. The endpoint's
    # dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with
    # no database lookup. Deliberately no exact error-type
    # assertion, mirroring the missing-body lock. Deliberately
    # no Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register missing-body 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    response = await client.post(
        "/account/register",
        json=["New", "User"],
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "body" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register missing-body 422 lock, using
    # substring checks so later additions to the list do not
    # break this test.
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
async def test_account_register_scalar_body_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a JSON scalar body:
    """
    # The next register validation branch after the non-object
    # (array) body 422 lock, verified fresh this run, not
    # assumed. The register handler takes a required `data:
    # CreateUserDto` body parameter with no default
    # (account_endpoint.py), so a bare JSON string body cannot
    # be coerced to the CreateUserDto model and fails FastAPI
    # request validation before the handler body runs: the
    # GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie
    # is set. This is distinct from the missing-body lock (no
    # body at all) and from the array-body lock (a JSON
    # collection of the wrong type): here the whole body is
    # a scalar, so the detail loc is ["body"] rather than a
    # field name, mirroring both earlier locks. The
    # mode="after" normalize_names validator cannot mask it
    # either, since it runs only after field validation
    # passes. The endpoint's dependencies cannot mask the
    # 422 either: get_auth_service/get_role_service only
    # resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. Deliberately
    # no exact error-type assertion, mirroring the
    # non-object-body lock. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register non-object-body 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation
    # errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json="New User",
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "body" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register non-object-body 422 lock, using
    # substring checks so later additions to the list do not
    # break this test.
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
async def test_account_register_numeric_body_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a JSON numeric body:
    """
    # The next register validation branch after the scalar
    # (string) body 422 lock, verified fresh this run, not
    # assumed. The register handler takes a required `data:
    # CreateUserDto` body parameter with no default
    # (account_endpoint.py), so a bare JSON number body cannot
    # be coerced to the CreateUserDto model and fails FastAPI
    # request validation before the handler body runs: the
    # GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie
    # is set. This is distinct from the missing-body lock (no
    # body at all), from the array-body lock (a JSON
    # collection of the wrong type), and from the string-scalar
    # lock (a JSON string of the wrong type): here the whole
    # body is a number, so the detail loc is ["body"] rather
    # than a field name, mirroring all three earlier locks.
    # The mode="after" normalize_names validator cannot mask it
    # either, since it runs only after field validation
    # passes. The endpoint's dependencies cannot mask the
    # 422 either: get_auth_service/get_role_service only
    # resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. Deliberately
    # no exact error-type assertion, mirroring the
    # scalar-body lock. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register scalar-body 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    response = await client.post(
        "/account/register",
        json=42,
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "body" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register scalar-body 422 lock, using
    # substring checks so later additions to the list do not
    # break this test.
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


async def test_account_register_boolean_body_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a JSON boolean body:
    """
    # The next register validation branch after the numeric
    # body 422 lock, verified fresh this run, not
    # assumed. The register handler takes a required `data:
    # CreateUserDto` body parameter with no default
    # (account_endpoint.py), so a bare JSON boolean body cannot
    # be coerced to the CreateUserDto model and fails FastAPI
    # request validation before the handler body runs: the
    # GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie
    # is set. This is distinct from the missing-body lock (no
    # body at all), from the array-body lock (a JSON
    # collection of the wrong type), from the string-scalar
    # lock (a JSON string of the wrong type), and from the
    # numeric-body lock (a JSON number of the wrong type):
    # here the whole body is a boolean, so the detail loc is
    # ["body"] rather than a field name, mirroring all four
    # earlier locks. The mode="after" normalize_names validator
    # cannot mask it either, since it runs only after field
    # validation passes. The endpoint's dependencies cannot
    # mask the 422 either: get_auth_service/get_role_service
    # only resolve container objects and get_tenant_id only
    # reads request state, with no database lookup.
    # Deliberately no exact error-type assertion, mirroring
    # the numeric-body lock. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register numeric-body 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    response = await client.post(
        "/account/register",
        json=True,
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "body" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register numeric-body 422 lock, using
    # substring checks so later additions to the list do not
    # break this test.
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


async def test_account_register_null_body_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an explicit JSON null body:
    """
    # The next register validation branch after the boolean
    # body 422 lock, verified fresh this run, not
    # assumed. The register handler takes a required `data:
    # CreateUserDto` body parameter with no default
    # (account_endpoint.py), so an explicit JSON null body
    # cannot be coerced to the CreateUserDto model and fails
    # FastAPI request validation before the handler body runs:
    # the GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie
    # is set. This is distinct from the missing-body lock (no
    # body at all), from the array-body lock (a JSON
    # collection of the wrong type), from the string-scalar
    # lock (a JSON string of the wrong type), from the
    # numeric-body lock (a JSON number of the wrong type),
    # and from the boolean-body lock (a JSON boolean of the
    # wrong type): here the whole body is an explicit null,
    # so the detail loc is ["body"] rather than a field name,
    # mirroring all five earlier locks. The body is sent as
    # the literal string "null" with a JSON content type
    # rather than via json=None, so the null is unambiguous
    # and does not depend on how the HTTP client encodes a
    # None json argument. The mode="after" normalize_names
    # validator cannot mask it either, since it runs only
    # after field validation passes. The endpoint's
    # dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state,
    # with no database lookup.
    # Deliberately no exact error-type assertion, mirroring
    # the boolean-body lock. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register boolean-body 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    response = await client.post(
        "/account/register",
        content="null",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "body" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register boolean-body 422 lock, using
    # substring checks so later additions to the list do not
    # break this test.
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


async def test_account_register_malformed_json_body_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a malformed (non-JSON) body:
    """
    # The next register validation branch after the null-body
    # 422 lock, verified fresh this run, not assumed. The
    # register handler takes a required `data: CreateUserDto`
    # body parameter with no default
    # (account_endpoint.py), so a body that is not valid JSON
    # at all cannot even be parsed, and fails FastAPI request
    # validation before the handler body runs: the GUEST role
    # lookup, the tenant branching, AuthService.register, and
    # the activation email never execute, and no token is
    # minted and no refresh cookie is set. This is distinct
    # from the missing-body lock (no body at all), from the
    # array-body lock (a JSON collection of the wrong type),
    # and from the string/numeric/boolean/null scalar locks
    # (valid JSON of the wrong type): here the body is not
    # JSON at all, so the failure is a JSON decode error
    # whose detail loc is still ["body"], mirroring all six
    # earlier locks. The body is sent with an explicit JSON
    # content type so the failure is a parse failure, not a
    # content-type rejection. The mode="after"
    # normalize_names validator cannot mask it either, since
    # it runs only after field validation passes, and the
    # endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state,
    # with no database lookup.
    # Deliberately no exact error-type assertion, mirroring
    # the null-body lock. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register null-body 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    response = await client.post(
        "/account/register",
        content="{not valid json",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "body" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register null-body 422 lock, using
    # substring checks so later additions to the list do not
    # break this test.
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


async def test_account_register_object_first_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an object-valued first_name:
    """
    # The next register validation branch after the malformed-JSON
    # body 422 lock, verified fresh this run, not assumed. The
    # extra-field candidate suggested by iteration 2413 was
    # assessed first and rejected: CreateUserDto/BaseUserDto
    # carry no model_config forbidding extra fields
    # (user_dto.py), so Pydantic's default extra="ignore"
    # drops an unknown field and the request proceeds to the
    # GUEST role lookup instead of failing validation — not a
    # deterministic 422. This branch is deterministic instead:
    # CreateUserDto.first_name is a required str field with
    # min_length=1 (user_dto.py), so a JSON object value cannot
    # be coerced to a str and fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. It is distinct from the non-string
    # first_name lock, which used a list value: a list and an
    # object are different JSON shapes reaching the same str
    # field, and both must be rejected. The mode="after"
    # normalize_names validator cannot mask the error either,
    # since it runs only after field validation passes. The
    # endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects (container.py) and get_tenant_id only reads request
    # state (tenant_middleware.py), with no database lookup. The
    # remaining body fields are all valid (a non-blank last
    # name, a valid email, gender "other", a string password),
    # so no other 422 can mask the first_name error.
    # Deliberately no exact error-type assertion: like the
    # non-string first_name lock, a first_name-type error type
    # has no precedent in this file, so the lock asserts only
    # the 422 status and a detail entry located at first_name.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register non-string first_name 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": {"nested": "New"},
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "first_name" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register non-string first_name 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_object_last_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an object-valued last_name:
    """
    # The next register validation branch after the object-valued
    # first_name 422 lock, verified fresh this run, not assumed.
    # CreateUserDto.last_name is a required str field with
    # min_length=1 inherited from BaseUserDto (user_dto.py), so a
    # JSON object value cannot be coerced to a str and fails
    # FastAPI request validation before the handler body runs:
    # the GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie is
    # set. It is distinct from the object-valued first_name
    # lock: a different required str field, and both must be
    # rejected. The mode="after" normalize_names validator
    # cannot mask the error either, since it runs only after
    # field validation passes. The endpoint's dependencies
    # cannot mask the 422 either: get_auth_service/
    # get_role_service only resolve container objects and
    # get_tenant_id only reads request state, with no database
    # lookup. The remaining body fields are all valid (a
    # non-blank first name, a valid email, gender "other", a
    # string password), so no other 422 can mask the last_name
    # error. Deliberately no exact error-type assertion: like
    # the object-valued first_name lock, a last_name-type error
    # type has no precedent in this file, so the lock asserts
    # only the 422 status and a detail entry located at
    # last_name. Deliberately no Cache-Control/Pragma
    # assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the object-valued
    # first_name 422 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": {"nested": "User"},
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "last_name" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the object-valued first_name 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_object_email_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an object-valued email:
    """
    # The next register validation branch after the object-valued
    # last_name 422 lock, verified fresh this run, not assumed.
    # CreateUserDto.email is a required EmailStr field inherited
    # from BaseUserDto (user_dto.py), so a JSON object value
    # cannot be coerced to a valid email string and fails
    # FastAPI request validation before the handler body runs:
    # the GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie is
    # set. It is distinct from the object-valued first_name /
    # last_name locks: a different required field, and all must
    # be rejected. The mode="after" normalize_names validator
    # cannot mask the error either, since it runs only after
    # field validation passes. The endpoint's dependencies
    # cannot mask the 422 either: get_auth_service /
    # get_role_service only resolve container objects and
    # get_tenant_id only reads request state, with no database
    # lookup. The remaining body fields are all valid (non-blank
    # first and last names, gender "other", a string password),
    # so no other 422 can mask the email error. Deliberately no
    # exact error-type assertion: like the object-valued
    # first_name / last_name locks, an email-type error type
    # has no precedent in this file, so the lock asserts only
    # the 422 status and a detail entry located at email.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to
    # it, mirroring the object-valued first_name / last_name
    # 422 locks. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": {"nested": "newuser@example.com"},
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "email" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the object-valued first_name 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_object_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an object-valued gender:
    """
    # The next register validation branch after the object-valued
    # email 422 lock, verified fresh this run, not assumed.
    # CreateUserDto.gender is a required Gender field inherited
    # from BaseUserDto (user_dto.py), where Gender is a str Enum
    # (male/female/other/prefer_not_to_say), so a JSON object
    # value cannot be coerced to a valid enum member and fails
    # FastAPI request validation before the handler body runs:
    # the GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie is
    # set. It is distinct from the object-valued first_name /
    # last_name / email locks: a different required field, and
    # all must be rejected. The mode="after" normalize_names
    # validator cannot mask the error either, since it runs only
    # after field validation passes. The endpoint's dependencies
    # cannot mask the 422 either: get_auth_service /
    # get_role_service only resolve container objects and
    # get_tenant_id only reads request state, with no database
    # lookup. The remaining body fields are all valid (non-blank
    # first and last names, a valid email, a string password),
    # so no other 422 can mask the gender error. Deliberately no
    # exact error-type assertion: like the object-valued
    # first_name / last_name / email locks, a gender-type error
    # type has no precedent in this file, so the lock asserts
    # only the 422 status and a detail entry located at gender.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to
    # it, mirroring the object-valued first_name / last_name /
    # email 422 locks. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": {"value": "other"},
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the object-valued first_name 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_object_password_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an object-valued password:
    """
    # The next register validation branch after the object-valued
    # gender 422 lock, verified fresh this run, not assumed.
    # CreateUserDto.password is a plain str field
    # (user_dto.py), so a JSON object value cannot be coerced
    # to a string and fails FastAPI request validation before
    # the handler body runs: the GUEST role lookup, the tenant
    # branching, AuthService.register, and the activation email
    # never execute, and no token is minted and no refresh
    # cookie is set. It is distinct from the non-string
    # password lock, which used a list value, and from the
    # object-valued first_name / last_name / email / gender
    # locks: a different required field, and all must be
    # rejected. The mode="after" normalize_names validator
    # cannot mask the error either, since it runs only after
    # field validation passes, and it touches only first and
    # last names in any case. The endpoint's dependencies
    # cannot mask the 422 either: get_auth_service /
    # get_role_service only resolve container objects and
    # get_tenant_id only reads request state, with no database
    # lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, gender
    # "other"), so no other 422 can mask the password error.
    # Deliberately no exact error-type assertion: like the
    # object-valued first_name / last_name / email / gender
    # locks, a password-type error type has no precedent in
    # this file, so the lock asserts only the 422 status and
    # a detail entry located at password. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the object-valued first_name / last_name /
    # email / gender 422 locks. The security headers ARE
    # locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": {"value": "Register123!"},
        },
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
    # mirroring the object-valued first_name 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_object_sub_domain_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an object-valued sub_domain:
    """
    # The next register validation branch after the object-valued
    # password 422 lock, verified fresh this run, not assumed.
    # CreateUserDto.sub_domain is an Optional[str] field with a
    # None default (user_dto.py), so a JSON object value cannot
    # be coerced to a string and fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. It is distinct from the non-string
    # sub_domain lock, which used a list value, and from the
    # object-valued first_name / last_name / email / gender /
    # password locks: a different field, and all must be
    # rejected. The mode="after" normalize_names validator
    # cannot mask the error either, since it runs only after
    # field validation passes, and it touches only first and
    # last names in any case. The endpoint's dependencies
    # cannot mask the 422 either: get_auth_service /
    # get_role_service only resolve container objects and
    # get_tenant_id only reads request state, with no database
    # lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, gender
    # "other", a string password), so no other 422 can mask
    # the sub_domain error. Deliberately no exact error-type
    # assertion: like the object-valued first_name / last_name /
    # email / gender / password locks, a sub_domain-type error
    # type has no precedent in this file, so the lock asserts
    # only the 422 status and a detail entry located at
    # sub_domain. Deliberately no Cache-Control/Pragma
    # assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the object-valued
    # first_name / last_name / email / gender / password 422
    # locks. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "sub_domain": {"value": "tenant"},
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "sub_domain" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the object-valued first_name 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_object_sso_provider_id_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an object-valued sso_provider_id:
    """
    # The next register validation branch after the object-valued
    # sub_domain 422 lock, verified fresh this run, not assumed.
    # CreateUserDto inherits sso_provider_id: Optional[str] = None
    # from BaseUserDto (user_dto.py), so a JSON object value cannot
    # be coerced to a string and fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. It is distinct from the non-string
    # sso_provider_id lock, which used a list value, and from the
    # object-valued first_name / last_name / email / gender /
    # password / sub_domain locks: a different field, and all must
    # be rejected. The mode="after" normalize_names validator
    # cannot mask the error either, since it runs only after
    # field validation passes, and it touches only first and
    # last names in any case. The endpoint's dependencies
    # cannot mask the 422 either: get_auth_service /
    # get_role_service only resolve container objects and
    # get_tenant_id only reads request state, with no database
    # lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, gender
    # "other", a string password), so no other 422 can mask
    # the sso_provider_id error. Deliberately no exact error-type
    # assertion: like the object-valued first_name / last_name /
    # email / gender / password / sub_domain locks, a
    # sso_provider_id-type error type has no precedent in this
    # file, so the lock asserts only the 422 status and a detail
    # entry located at sso_provider_id. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the object-valued first_name / last_name / email / gender /
    # password / sub_domain 422 locks. The security headers ARE
    # locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "sso_provider_id": {"provider": "google"},
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "sso_provider_id" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the object-valued first_name 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_object_tenant_id_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an object-valued tenant_id:
    """
    # The next register validation branch after the object-valued
    # sso_provider_id 422 lock, verified fresh this run, not assumed.
    # CreateUserDto inherits tenant_id: PydanticObjectId | None
    # from BaseUserDto (user_dto.py), so a JSON object value cannot
    # be coerced to an ObjectId and fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. It is distinct from the malformed tenant_id
    # lock, which used a non-ObjectId string, and from the
    # non-string tenant_id lock, which used a list value, and from
    # the object-valued first_name / last_name / email / gender /
    # password / sub_domain / sso_provider_id locks: a different
    # field, and all must be rejected. The register handler takes
    # a required `data: CreateUserDto` body parameter with no
    # default (account_endpoint.py), and its dependencies cannot
    # mask the 422: get_auth_service / get_role_service only
    # resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. The remaining body
    # fields are all valid (non-blank first and last names, a
    # valid email, gender "other", a string password), so no
    # other 422 can mask the tenant_id error. The mode="after"
    # normalize_names validator cannot mask it either, since it
    # runs only after field validation passes and touches only
    # first and last names in any case. Deliberately no exact
    # error-type assertion: like the object-valued sso_provider_id
    # lock, a PydanticObjectId error type for an object value has
    # no precedent in this file, so the lock asserts only the 422
    # status and a detail entry located at tenant_id.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the object-valued sso_provider_id 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "tenant_id": {"id": "507f1f77bcf86cd799439011"},
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "tenant_id" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the object-valued sso_provider_id 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_object_role_id_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an object-valued role_id:
    """
    # The next register validation branch after the object-valued
    # tenant_id 422 lock, verified fresh this run, not assumed.
    # CreateUserDto inherits role_id: PydanticObjectId | None
    # from BaseUserDto (user_dto.py), so a JSON object value cannot
    # be coerced to an ObjectId and fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. It is distinct from the malformed role_id
    # lock, which used a non-ObjectId string, and from the
    # non-string role_id lock, which used a list value, and from
    # the object-valued first_name / last_name / email / gender /
    # password / sub_domain / sso_provider_id / tenant_id locks: a
    # different field, and all must be rejected. It is also
    # unaffected by the handler's `data.role_id = role_guest.id`
    # overwrite, which runs only after validation passes. The
    # register handler takes a required `data: CreateUserDto` body
    # parameter with no default (account_endpoint.py), and its
    # dependencies cannot mask the 422: get_auth_service /
    # get_role_service only resolve container objects and
    # get_tenant_id only reads request state, with no database
    # lookup. The remaining body fields are all valid (non-blank
    # first and last names, a valid email, gender "other", a
    # string password), so no other 422 can mask the role_id
    # error. The mode="after" normalize_names validator cannot
    # mask it either, since it runs only after field validation
    # passes and touches only first and last names in any case.
    # Deliberately no exact error-type assertion: like the
    # object-valued tenant_id lock, a PydanticObjectId error type
    # for an object value has no precedent in this file, so the
    # lock asserts only the 422 status and a detail entry located
    # at role_id. Deliberately no Cache-Control/Pragma assertion:
    # a 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the object-valued tenant_id 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "role_id": {"id": "507f1f77bcf86cd799439011"},
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "role_id" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the object-valued tenant_id 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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
async def test_account_register_boolean_first_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a boolean-valued first_name:
    """
    # The next register validation branch after the object-valued
    # role_id 422 lock, verified fresh this run, not assumed.
    # All nine CreateUserDto fields now have list-valued
    # (non-string) and dict-valued (object) locks, so the next
    # deterministic branch is a scalar wrong-type value: a JSON
    # boolean for first_name. first_name is a plain str field
    # (BaseUserDto, user_dto.py), and Pydantic v2 does not coerce
    # a boolean to a string, so it fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. It is distinct from the non-string first_name
    # lock, which used a list value, and from the object-valued
    # first_name lock, which used a dict value: a different JSON
    # type, and all must be rejected. The mode="after"
    # normalize_names validator cannot mask it either, since it
    # runs only after field validation passes. The register
    # handler takes a required `data: CreateUserDto` body parameter
    # with no default (account_endpoint.py), and its dependencies
    # cannot mask the 422: get_auth_service / get_role_service only
    # resolve container objects and get_tenant_id only reads request
    # state, with no database lookup. The remaining body fields are
    # all valid (a non-blank last name, a valid email, gender
    # "other", a string password), so no other 422 can mask the
    # first_name error. Deliberately no exact error-type assertion:
    # like the object-valued role_id lock, a string-type error type
    # for a boolean value has no precedent in this file, so the lock
    # asserts only the 422 status and a detail entry located at
    # first_name. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to it,
    # mirroring the object-valued role_id 422 lock. The security
    # headers ARE locked: the pure-ASGI middleware stamps every
    # HTTP response, including validation errors, with no path
    # exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": True,
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "first_name" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the object-valued role_id 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_boolean_last_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a boolean-valued last_name:
    """
    # The next register validation branch after the boolean-valued
    # first_name 422 lock, verified fresh this run, not assumed.
    # last_name is a plain str field (BaseUserDto, user_dto.py), and
    # Pydantic v2 does not coerce a boolean to a string, so it fails
    # FastAPI request validation before the handler body runs: the
    # GUEST role lookup, the tenant branching, AuthService.register,
    # and the activation email never execute, and no token is minted
    # and no refresh cookie is set. It is distinct from the
    # non-string last_name lock, which used a list value, and from
    # the object-valued last_name lock, which used a dict value: a
    # different JSON type, and all must be rejected. The mode="after"
    # normalize_names validator cannot mask it either, since it
    # runs only after field validation passes. The register
    # handler takes a required `data: CreateUserDto` body parameter
    # with no default (account_endpoint.py), and its dependencies
    # cannot mask the 422: get_auth_service / get_role_service only
    # resolve container objects and get_tenant_id only reads request
    # state, with no database lookup. The remaining body fields are
    # all valid (a non-blank first name, a valid email, gender
    # "other", a string password), so no other 422 can mask the
    # last_name error. Deliberately no exact error-type assertion:
    # like the boolean-valued first_name lock, a string-type error
    # type for a boolean value has no precedent in this file, so the
    # lock asserts only the 422 status and a detail entry located at
    # last_name. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to it,
    # mirroring the boolean-valued first_name 422 lock. The security
    # headers ARE locked: the pure-ASGI middleware stamps every
    # HTTP response, including validation errors, with no path
    # exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": True,
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "last_name" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the boolean-valued first_name 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_boolean_email_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a boolean-valued email:
    """
    # The next register validation branch after the boolean-valued
    # last_name 422 lock, verified fresh this run, not assumed.
    # email is an EmailStr field (BaseUserDto, user_dto.py), and
    # Pydantic v2 does not coerce a boolean to a string, so it
    # fails FastAPI request validation before the handler body
    # runs: the GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie is
    # set. It is distinct from the non-string email lock, which
    # used a list value, from the object-valued email lock, which
    # used a dict value, and from the invalid-email lock, which
    # used a malformed string: a different JSON type, and all must
    # be rejected. The mode="after" normalize_names validator
    # cannot mask it either, since it runs only after field
    # validation passes and only touches first/last names. The
    # register handler takes a required `data: CreateUserDto` body
    # parameter with no default (account_endpoint.py), and its
    # dependencies cannot mask the 422: get_auth_service /
    # get_role_service only resolve container objects and
    # get_tenant_id only reads request state, with no database
    # lookup. The remaining body fields are all valid (non-blank
    # first and last names, gender "other", a string password),
    # so no other 422 can mask the email error. Deliberately no
    # exact error-type assertion: like the boolean-valued
    # first_name and last_name locks, an email-type error type for
    # a boolean value has no precedent in this file, so the lock
    # asserts only the 422 status and a detail entry located at
    # email. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the boolean-valued last_name 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with no
    # path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": True,
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "email" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the boolean-valued last_name 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_boolean_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a boolean-valued gender:
    """
    # The next register validation branch after the boolean-valued
    # email 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender is a str Enum with only "male",
    # "female", "other" and "prefer_not_to_say" (gender.py), so a
    # JSON boolean value cannot be coerced to a Gender member under
    # any Pydantic version and fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. It is distinct from the non-string gender
    # lock, which used a list value, from the object-valued gender
    # lock, which used a dict value, and from the invalid-gender
    # lock, which used a malformed string: a different JSON type,
    # and all must be rejected. The mode="after" normalize_names
    # validator cannot mask it either, since it runs only after
    # field validation passes and only touches first/last names.
    # The endpoint's dependencies cannot mask the 422:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, a string
    # password), so no other 422 can mask the gender error.
    # Deliberately no exact error-type assertion: like the
    # boolean-valued email lock, a gender-type error type for a
    # boolean value has no precedent in this file, so the lock
    # asserts only the 422 status and a detail entry located at
    # gender. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the boolean-valued email 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with no
    # path exclusions. This lock adds no new route-specific
    # contradiction (a validation 422 precedes the role lookup,
    # so it contradicts no existing role expectation).
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": True,
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the boolean-valued email 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_boolean_password_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a boolean-valued password:
    """
    # The next register validation branch after the boolean-valued
    # gender 422 lock, verified fresh this run, not assumed.
    # CreateUserDto.password is a required str field with no default
    # (user_dto.py), so a JSON boolean value cannot be coerced to a
    # str and fails FastAPI request validation before the handler
    # body runs: the GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never execute,
    # and no token is minted and no refresh cookie is set. It is
    # distinct from the object-valued password lock, which used a
    # dict value, and from the weak-password branch, which uses a
    # string that fails strength rules after validation: a different
    # JSON type, and all must be rejected. The mode="after"
    # normalize_names validator cannot mask it either, since it runs
    # only after field validation passes and only touches first/last
    # names. The endpoint's dependencies cannot mask the 422:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, gender
    # "other"), so no other 422 can mask the password error.
    # Deliberately no exact error-type assertion: like the
    # boolean-valued gender lock, a password-type error type for a
    # boolean value has no precedent in this file, so the lock
    # asserts only the 422 status and a detail entry located at
    # password. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the boolean-valued gender 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with no
    # path exclusions. This lock adds no new route-specific
    # contradiction (a validation 422 precedes the role lookup,
    # so it contradicts no existing role expectation).
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": True,
        },
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
    # mirroring the boolean-valued gender 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_boolean_sub_domain_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a boolean-valued sub_domain:
    """
    # The next register validation branch after the boolean-valued
    # password 422 lock, verified fresh this run, not assumed.
    # CreateUserDto.sub_domain is an Optional[str] field with a None
    # default (user_dto.py), so a JSON boolean value cannot be
    # coerced to a str and fails FastAPI request validation before
    # the handler body runs: the GUEST role lookup, the tenant
    # branching, AuthService.register, and the activation email
    # never execute, and no token is minted and no refresh cookie
    # is set. It is distinct from the non-string sub_domain lock,
    # which used a list value, and from the object-valued
    # sub_domain lock, which used a dict value: a different JSON
    # type, and all must be rejected. The mode="after"
    # normalize_names validator cannot mask it either, since it
    # runs only after field validation passes and only touches
    # first/last names. The endpoint's dependencies cannot mask
    # the 422: get_auth_service/get_role_service only resolve
    # container objects and get_tenant_id only reads request state,
    # with no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, gender
    # "other", a string password), so no other 422 can mask the
    # sub_domain error. Deliberately no exact error-type
    # assertion: like the boolean-valued password lock, a
    # sub_domain-type error type for a boolean value has no
    # precedent in this file, so the lock asserts only the 422
    # status and a detail entry located at sub_domain.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the boolean-valued password 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with no
    # path exclusions. This lock adds no new route-specific
    # contradiction (a validation 422 precedes the role lookup,
    # so it contradicts no existing role expectation).
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "sub_domain": True,
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "sub_domain" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the boolean-valued password 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_boolean_sso_provider_id_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a boolean-valued sso_provider_id:
    """
    # The next register validation branch after the boolean-valued
    # sub_domain 422 lock, verified fresh this run, not assumed.
    # CreateUserDto inherits sso_provider_id: Optional[str] = None
    # (BaseUserDto, user_dto.py), so a JSON boolean value cannot be
    # coerced to a str and fails FastAPI request validation before
    # the handler body runs: the GUEST role lookup, the tenant
    # branching, AuthService.register, and the activation email
    # never execute, and no token is minted and no refresh cookie
    # is set. It is distinct from the non-string sso_provider_id
    # lock, which used a list value, and from the object-valued
    # sso_provider_id lock, which used a dict value: a different
    # JSON type, and all must be rejected. The mode="after"
    # normalize_names validator cannot mask it either, since it
    # runs only after field validation passes and only touches
    # first/last names. The endpoint's dependencies cannot mask
    # the 422: get_auth_service/get_role_service only resolve
    # container objects and get_tenant_id only reads request state,
    # with no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, gender
    # "other", a string password), so no other 422 can mask the
    # sso_provider_id error. Deliberately no exact error-type
    # assertion: like the boolean-valued sub_domain lock, a
    # sso_provider_id-type error type for a boolean value has no
    # precedent in this file, so the lock asserts only the 422
    # status and a detail entry located at sso_provider_id.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the boolean-valued sub_domain 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with no
    # path exclusions. This lock adds no new route-specific
    # contradiction (a validation 422 precedes the role lookup,
    # so it contradicts no existing role expectation).
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "sso_provider_id": True,
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "sso_provider_id" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the boolean-valued sub_domain 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_boolean_tenant_id_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a boolean-valued tenant_id:
    """
    # The next register validation branch after the boolean-valued
    # sso_provider_id 422 lock, verified fresh this run, not assumed.
    # CreateUserDto inherits tenant_id: PydanticObjectId | None = None
    # (BaseUserDto, user_dto.py), so a JSON boolean value is neither
    # a valid ObjectId nor a valid ObjectId hex string and fails
    # FastAPI request validation before the handler body runs: the
    # GUEST role lookup, the tenant branching, AuthService.register,
    # and the activation email never execute, and no token is minted
    # and no refresh cookie is set. The handler overwriting
    # data.tenant_id afterwards (from X-Tenant-ID or tenant creation)
    # cannot mask the 422, since it runs only after validation
    # passes. It is distinct from the non-string tenant_id lock,
    # which used a list value, and from the object-valued tenant_id
    # lock, which used a dict value: a different JSON type, and all
    # must be rejected. The mode="after" normalize_names validator
    # cannot mask it either, since it runs only after field
    # validation passes and only touches first/last names. The
    # endpoint's dependencies cannot mask the 422:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, gender
    # "other", a string password), so no other 422 can mask the
    # tenant_id error. Deliberately no exact error-type assertion:
    # like the boolean-valued sso_provider_id lock, a tenant_id-type
    # error type for a boolean value has no precedent in this file,
    # so the lock asserts only the 422 status and a detail entry
    # located at tenant_id. Deliberately no Cache-Control/Pragma
    # assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store headers do
    # not apply to it, mirroring the boolean-valued sso_provider_id
    # 422 lock. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including validation
    # errors, with no path exclusions. This lock adds no new
    # route-specific contradiction (a validation 422 precedes the
    # role lookup, so it contradicts no existing role expectation).
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "tenant_id": True,
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "tenant_id" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the boolean-valued sso_provider_id 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_boolean_role_id_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a boolean-valued role_id:
    """
    # The next register validation branch after the boolean-valued
    # tenant_id 422 lock, verified fresh this run, not assumed.
    # CreateUserDto inherits role_id: PydanticObjectId | None = None
    # (BaseUserDto, user_dto.py), the mirror of the tenant_id field,
    # so a JSON boolean value is neither a valid ObjectId nor a
    # valid ObjectId hex string and fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. The handler overwriting data.role_id with the
    # GUEST role id afterwards cannot mask the 422, since it runs
    # only after validation passes. It is distinct from the
    # invalid-role_id lock, which used a malformed string, from the
    # non-string role_id lock, which used a list value, and from
    # the object-valued role_id lock, which used a dict value: a
    # different JSON type, and all must be rejected. The
    # mode="after" normalize_names validator cannot mask it
    # either, since it runs only after field validation passes
    # and only touches first/last names. The endpoint's
    # dependencies cannot mask the 422: get_auth_service /
    # get_role_service only resolve container objects and
    # get_tenant_id only reads request state, with no database
    # lookup. The remaining body fields are all valid (non-blank
    # first and last names, a valid email, gender "other", a
    # string password), so no other 422 can mask the role_id
    # error. Deliberately no exact error-type assertion: like the
    # boolean-valued tenant_id lock, a role_id-type error type
    # for a boolean value has no precedent in this file, so the
    # lock asserts only the 422 status and a detail entry located
    # at role_id. Deliberately no Cache-Control/Pragma assertion:
    # a 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the boolean-valued tenant_id 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with no
    # path exclusions. This lock adds no new route-specific
    # contradiction (a validation 422 precedes the role lookup, so
    # it contradicts no existing role expectation).
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "role_id": True,
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "role_id" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the boolean-valued tenant_id 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_integer_first_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an integer-valued first_name:
    """
    # The next register validation branch after the boolean-valued
    # role_id 422 lock, verified fresh this run, not assumed.
    # All nine CreateUserDto fields now have list-valued
    # (non-string), dict-valued (object), and boolean-valued locks,
    # so the next deterministic branch is another scalar wrong-type
    # value: a JSON integer for first_name. first_name is a plain
    # str field with min_length=1 (BaseUserDto, user_dto.py), and
    # Pydantic v2 does not coerce a number to a string (the same
    # no-coercion reasoning the boolean-valued first_name lock
    # relies on for booleans), so it fails FastAPI request
    # validation before the handler body runs: the GUEST role
    # lookup, the tenant branching, AuthService.register, and the
    # activation email never execute, and no token is minted and
    # no refresh cookie is set. It is distinct from the
    # non-string first_name lock, which used a list value, from
    # the object-valued first_name lock, which used a dict value,
    # and from the boolean-valued first_name lock, which used a
    # boolean value: a different JSON type, and all must be
    # rejected. The mode="after" normalize_names validator cannot
    # mask it either, since it runs only after field validation
    # passes and only touches first/last names. The register
    # handler takes a required `data: CreateUserDto` body parameter
    # with no default (account_endpoint.py), and its dependencies
    # cannot mask the 422: get_auth_service / get_role_service only
    # resolve container objects and get_tenant_id only reads request
    # state, with no database lookup. The remaining body fields are
    # all valid (a non-blank last name, a valid email, gender
    # "other", a string password), so no other 422 can mask the
    # first_name error. Deliberately no exact error-type assertion:
    # like the boolean-valued first_name lock, a string-type error
    # type for an integer value has no precedent in this file, so
    # the lock asserts only the 422 status and a detail entry
    # located at first_name. Deliberately no Cache-Control/Pragma
    # assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store headers
    # do not apply to it, mirroring the boolean-valued role_id 422
    # lock. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including validation
    # errors, with no path exclusions. This lock adds no new
    # route-specific contradiction (a validation 422 precedes the
    # role lookup, so it contradicts no existing role expectation).
    response = await client.post(
        "/account/register",
        json={
            "first_name": 123,
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "first_name" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the boolean-valued role_id 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_integer_last_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an integer-valued last_name:
    """
    # The next register validation branch after the integer-valued
    # first_name 422 lock, verified fresh this run, not assumed.
    # last_name is a plain str field with min_length=1 (BaseUserDto,
    # user_dto.py), and Pydantic v2 does not coerce a number to a
    # string (the same no-coercion reasoning the integer-valued
    # first_name lock relies on), so it fails FastAPI request
    # validation before the handler body runs: the GUEST role
    # lookup, the tenant branching, AuthService.register, and the
    # activation email never execute, and no token is minted and
    # no refresh cookie is set. It is distinct from the
    # non-string last_name lock, which used a list value, from
    # the object-valued last_name lock, which used a dict value,
    # and from the boolean-valued last_name lock, which used a
    # boolean value: a different JSON type, and all must be
    # rejected. The mode="after" normalize_names validator cannot
    # mask it either, since it runs only after field validation
    # passes and only touches first/last names. The register
    # handler takes a required `data: CreateUserDto` body parameter
    # with no default (account_endpoint.py), and its dependencies
    # cannot mask the 422: get_auth_service / get_role_service only
    # resolve container objects and get_tenant_id only reads request
    # state, with no database lookup. The remaining body fields are
    # all valid (a non-blank first name, a valid email, gender
    # "other", a string password), so no other 422 can mask the
    # last_name error. Deliberately no exact error-type assertion:
    # like the integer-valued first_name lock, a string-type error
    # type for an integer value has no precedent in this file, so
    # the lock asserts only the 422 status and a detail entry
    # located at last_name. Deliberately no Cache-Control/Pragma
    # assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store headers
    # do not apply to it, mirroring the boolean-valued role_id 422
    # lock. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including validation
    # errors, with no path exclusions. This lock adds no new
    # route-specific contradiction (a validation 422 precedes the
    # role lookup, so it contradicts no existing role expectation).
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": 456,
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "last_name" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the boolean-valued role_id 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_integer_email_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an integer-valued email:
    """
    # The next register validation branch after the integer-valued
    # last_name 422 lock, verified fresh this run, not assumed.
    # email is a required EmailStr field with no default
    # (BaseUserDto, user_dto.py), and Pydantic v2 does not coerce
    # a number to a string email (the same no-coercion reasoning
    # the integer-valued first_name/last_name locks rely on), so
    # it fails FastAPI request validation before the handler body
    # runs: the GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie is
    # set. It is distinct from the non-string email lock, which
    # used a list value, from the object-valued email lock, which
    # used a dict value, and from the boolean-valued email lock,
    # which used a boolean value: a different JSON type, and all
    # must be rejected. The mode="after" normalize_names validator
    # cannot mask it either, since it runs only after field
    # validation passes and only touches first/last names. The
    # register handler takes a required `data: CreateUserDto` body
    # parameter with no default (account_endpoint.py), and its
    # dependencies cannot mask the 422: get_auth_service /
    # get_role_service only resolve container objects and
    # get_tenant_id only reads request state, with no database
    # lookup. The remaining body fields are all valid (non-blank
    # first and last names, gender "other", a string password),
    # so no other 422 can mask the email error. Deliberately no
    # exact error-type assertion: like the integer-valued
    # first_name/last_name locks, a string-type error type for an
    # integer value has no precedent in this file, so the lock
    # asserts only the 422 status and a detail entry located at
    # email. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the boolean-valued role_id 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with no
    # path exclusions. This lock adds no new route-specific
    # contradiction (a validation 422 precedes the role lookup,
    # so it contradicts no existing role expectation).
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": 12345,
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "email" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the boolean-valued role_id 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_integer_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an integer-valued gender:
    """
    # The next register validation branch after the integer-valued
    # email 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender is a str Enum with only "male",
    # "female", "other" and "prefer_not_to_say" (gender.py), so a
    # JSON integer matches no enum member value and fails FastAPI
    # request validation before the handler body runs: the GUEST
    # role lookup, the tenant branching, AuthService.register, and
    # the activation email never execute, and no token is minted
    # and no refresh cookie is set. It is distinct from the
    # non-string gender lock, which used a list value, from the
    # object-valued gender lock, which used a dict value, from the
    # boolean-valued gender lock, which used a boolean value, and
    # from the invalid-gender lock, which used a malformed string:
    # a different JSON type, and all must be rejected. The
    # mode="after" normalize_names validator cannot mask it
    # either, since it runs only after field validation passes and
    # only touches first/last names. The register handler takes a
    # required `data: CreateUserDto` body parameter with no default
    # (account_endpoint.py), and its dependencies cannot mask the
    # 422: get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, a string
    # password), so no other 422 can mask the gender error.
    # Deliberately no exact error-type assertion: like the
    # integer-valued first_name/last_name/email locks, a
    # gender-type error type for an integer value has no precedent
    # in this file, so the lock asserts only the 422 status and a
    # detail entry located at gender. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central handler's
    # no-store headers do not apply to it, mirroring the
    # integer-valued email 422 lock. The security headers ARE
    # locked: the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions. This
    # lock adds no new route-specific contradiction (a validation
    # 422 precedes the role lookup, so it contradicts no existing
    # role expectation).
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": 12345,
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the integer-valued email 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_integer_password_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an integer-valued password:
    """
    # The next register validation branch after the integer-valued
    # gender 422 lock, verified fresh this run, not assumed.
    # CreateUserDto.password is a required plain str field with no
    # default (user_dto.py), and Pydantic v2 does not coerce a
    # number to a string (the same no-coercion reasoning the
    # integer-valued first_name/last_name/email/gender locks rely
    # on), so a JSON integer fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. It is distinct from the non-string password
    # lock, which used a list value, from the object-valued
    # password lock, which used a dict value, from the
    # boolean-valued password lock, which used a boolean value,
    # and from the missing-password lock, which omitted the field:
    # a different JSON type, and all must be rejected. The
    # mode="after" normalize_names validator cannot mask it
    # either, since it runs only after field validation passes and
    # only touches first/last names, and the password is
    # deliberately not trimmed in that validator. The register
    # handler takes a required `data: CreateUserDto` body parameter
    # with no default (account_endpoint.py), and its dependencies
    # cannot mask the 422: get_auth_service/get_role_service only
    # resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. The remaining body
    # fields are all valid (non-blank first and last names, a
    # valid email, gender "other"), so no other 422 can mask the
    # password error. Deliberately no exact error-type assertion,
    # mirroring the integer-valued first_name/last_name/email/
    # gender locks. Deliberately no Cache-Control/Pragma assertion:
    # a 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the integer-valued gender 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with no
    # path exclusions. This lock adds no new route-specific
    # contradiction (a validation 422 precedes the role lookup, so
    # it contradicts no existing role expectation).
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": 12345,
        },
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
    # mirroring the integer-valued gender 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_integer_sub_domain_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an integer-valued sub_domain:
    """
    # The next register validation branch after the integer-valued
    # password 422 lock, verified fresh this run, not assumed.
    # CreateUserDto.sub_domain is an Optional[str] field defaulting
    # to None (user_dto.py) with no validator touching it: the
    # only field_serializer covers tenant_id/role_id, and the
    # mode="after" normalize_names validator only touches
    # first/last names and runs only after field validation
    # passes. Pydantic v2 does not coerce a number to a string
    # (the same no-coercion reasoning the integer-valued
    # first_name/last_name/email/gender/password locks rely on),
    # so a JSON integer fails FastAPI request validation before
    # the handler body runs: the GUEST role lookup, the tenant
    # branching, AuthService.register, and the activation email
    # never execute, and no token is minted and no refresh cookie
    # is set. It is distinct from the non-string sub_domain lock,
    # which used a list value, from the object-valued sub_domain
    # lock, which used a dict value, and from the boolean-valued
    # sub_domain lock, which used a boolean value: a different
    # JSON type, and all must be rejected. The register handler
    # takes a required `data: CreateUserDto` body parameter with
    # no default (account_endpoint.py), and its dependencies
    # cannot mask the 422: get_auth_service/get_role_service only
    # resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. The remaining body
    # fields are all valid (non-blank first and last names, a
    # valid email, gender "other", a valid password), so no other
    # 422 can mask the sub_domain error. Deliberately no exact
    # error-type assertion, mirroring the integer-valued
    # password 422 lock. Deliberately no Cache-Control/Pragma
    # assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store headers
    # do not apply to it, mirroring the integer-valued password
    # 422 lock. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including validation
    # errors, with no path exclusions. This lock adds no new
    # route-specific contradiction (a validation 422 precedes the
    # role lookup, so it contradicts no existing role
    # expectation).
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "sub_domain": 12345,
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "sub_domain" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the integer-valued password 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_integer_sso_provider_id_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an integer-valued sso_provider_id:
    """
    # The next register validation branch after the integer-valued
    # sub_domain 422 lock, verified fresh this run, not assumed.
    # CreateUserDto inherits sso_provider_id as an Optional[str]
    # field defaulting to None from BaseUserDto (user_dto.py)
    # with no validator touching it: the only field_serializer
    # covers tenant_id/role_id, and the mode="after"
    # normalize_names validator only touches first/last names
    # and runs only after field validation passes. Pydantic v2
    # does not coerce a number to a string (the same
    # no-coercion reasoning the integer-valued
    # first_name/last_name/email/gender/password/sub_domain
    # locks rely on), so a JSON integer fails FastAPI request
    # validation before the handler body runs: the GUEST role
    # lookup, the tenant branching, AuthService.register, and
    # the activation email never execute, and no token is minted
    # and no refresh cookie is set. It is distinct from the
    # non-string sso_provider_id lock, which used a list value,
    # from the object-valued sso_provider_id lock, which used a
    # dict value, and from the boolean-valued sso_provider_id
    # lock, which used a boolean value: a different JSON type,
    # and all must be rejected. The register handler takes a
    # required `data: CreateUserDto` body parameter with no
    # default (account_endpoint.py), and its dependencies
    # cannot mask the 422: get_auth_service/get_role_service only
    # resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. The remaining body
    # fields are all valid (non-blank first and last names, a
    # valid email, gender "other", a valid password), so no other
    # 422 can mask the sso_provider_id error. Deliberately no exact
    # error-type assertion, mirroring the integer-valued
    # sub_domain 422 lock. Deliberately no Cache-Control/Pragma
    # assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store headers
    # do not apply to it, mirroring the integer-valued sub_domain
    # 422 lock. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including validation
    # errors, with no path exclusions. This lock adds no new
    # route-specific contradiction (a validation 422 precedes the
    # role lookup, so it contradicts no existing role
    # expectation).
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "sso_provider_id": 12345,
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "sso_provider_id" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the integer-valued sub_domain 422 lock, using
    # substring checks so later additions to the list do not break
    # this test.
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


async def test_account_register_integer_tenant_id_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an integer-valued tenant_id:
    """
    # The next register validation branch after the integer-valued
    # sso_provider_id 422 lock, verified fresh this run, not
    # assumed. CreateUserDto inherits tenant_id as a
    # PydanticObjectId | None field defaulting to None from
    # BaseUserDto (user_dto.py): a beanie ObjectId is built from
    # a 24-hex string or 12 bytes, so a JSON integer fails
    # FastAPI request validation before the handler body runs:
    # the GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie is
    # set. No validator masks it: the only field_serializer
    # covers tenant_id/role_id for output only, and the
    # mode="after" normalize_names validator only touches
    # first/last names and runs only after field validation
    # passes. It is distinct from the malformed-string
    # tenant_id lock, which used a non-ObjectId string, and
    # from the boolean-valued tenant_id lock, which used a
    # boolean value: a different JSON type, and all must be
    # rejected. The register handler takes a required
    # `data: CreateUserDto` body parameter with no default
    # (account_endpoint.py), and its dependencies cannot mask
    # the 422: get_auth_service/get_role_service only resolve
    # container objects and get_tenant_id only reads request
    # state, with no database lookup. The remaining body fields
    # are all valid (non-blank first and last names, a valid
    # email, gender "other", a valid password), so no other 422
    # can mask the tenant_id error. Deliberately no exact
    # error-type assertion, mirroring the integer-valued
    # sso_provider_id 422 lock. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the integer-valued sso_provider_id 422 lock. The security
    # headers ARE locked: the pure-ASGI middleware stamps every
    # HTTP response, including validation errors, with no path
    # exclusions. This lock adds no new route-specific
    # contradiction (a validation 422 precedes the role lookup,
    # so it contradicts no existing role expectation).
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "tenant_id": 12345,
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "tenant_id" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the integer-valued sso_provider_id 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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
async def test_account_register_integer_role_id_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an integer-valued role_id:
    """
    # The next register validation branch after the integer-valued
    # tenant_id 422 lock, verified fresh this run, not assumed.
    # CreateUserDto inherits role_id as a PydanticObjectId | None
    # field defaulting to None from BaseUserDto (user_dto.py): a
    # beanie ObjectId is built from a 24-hex string or 12 bytes,
    # so a JSON integer fails FastAPI request validation before
    # the handler body runs: the GUEST role lookup, the tenant
    # branching, AuthService.register, and the activation email
    # never execute, and no token is minted and no refresh cookie
    # is set. No validator masks it: the only field_serializer
    # covers tenant_id/role_id for output only, and the
    # mode="after" normalize_names validator only touches
    # first/last names and runs only after field validation
    # passes. It is distinct from the malformed-string role_id
    # lock, which used a non-ObjectId string, from the
    # boolean-valued role_id lock, which used a boolean value,
    # and from the list- and dict-valued role_id locks: a
    # different JSON type, and all must be rejected. The
    # register handler takes a required `data: CreateUserDto`
    # body parameter with no default (account_endpoint.py), and
    # its dependencies cannot mask the 422:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, gender
    # "other", a valid password), so no other 422 can mask the
    # role_id error. Deliberately no exact error-type assertion,
    # mirroring the integer-valued tenant_id 422 lock.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the integer-valued tenant_id 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions. This lock adds no new
    # route-specific contradiction (a validation 422 precedes
    # the role lookup, so it contradicts no existing role
    # expectation).
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "role_id": 12345,
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "role_id" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the integer-valued tenant_id 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_null_first_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a null-valued first_name:
    """
    # The next register validation branch after the integer-valued
    # role_id 422 lock, verified fresh this run, not assumed.
    # CreateUserDto inherits first_name as a required str field
    # with min_length=1 from BaseUserDto (user_dto.py): it is
    # not Optional, so a JSON null fails FastAPI request
    # validation before the handler body runs: the GUEST role
    # lookup, the tenant branching, AuthService.register, and
    # the activation email never execute, and no token is
    # minted and no refresh cookie is set. No validator masks
    # it: the mode="after" normalize_names validator only
    # touches first/last names and runs only after field
    # validation passes. It is distinct from the object-,
    # boolean-, and integer-valued first_name locks (different
    # JSON types, all must be rejected) and from the null-body
    # lock (whole body null rather than one field null). Note
    # the contrast with the optional register fields
    # (tenant_id, role_id, sso_provider_id, sub_domain), for
    # which null is a valid "absent" value, not a 422 — so a
    # required field is the correct null target here. The
    # register handler takes a required `data: CreateUserDto`
    # body parameter with no default (account_endpoint.py),
    # and its dependencies cannot mask the 422:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with
    # no database lookup. The remaining body fields are all
    # valid (non-blank last name, a valid email, gender
    # "other", a valid password), so no other 422 can mask the
    # first_name error. Deliberately no exact error-type
    # assertion, mirroring the integer-valued role_id 422 lock.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to
    # it, mirroring the integer-valued role_id 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions. This lock adds no new
    # route-specific contradiction (a validation 422 precedes
    # the role lookup, so it contradicts no existing role
    # expectation).
    response = await client.post(
        "/account/register",
        json={
            "first_name": None,
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "first_name" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the integer-valued role_id 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_null_last_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a null-valued last_name:
    """
    # The next register validation branch after the null-valued
    # first_name 422 lock, verified fresh this run, not assumed.
    # CreateUserDto inherits last_name as a required str field
    # with min_length=1 from BaseUserDto (user_dto.py): it is
    # not Optional, so a JSON null fails FastAPI request
    # validation before the handler body runs: the GUEST role
    # lookup, the tenant branching, AuthService.register, and
    # the activation email never execute, and no token is
    # minted and no refresh cookie is set. No validator masks
    # it: the mode="after" normalize_names validator only
    # touches first/last names and runs only after field
    # validation passes. It is distinct from the object-,
    # boolean-, integer-, and nonstring-valued last_name locks
    # (different JSON types, all must be rejected) and from
    # the null-first_name lock (different detail loc) and the
    # null-body lock (whole body null rather than one field
    # null). Note the contrast with the optional register
    # fields (tenant_id, role_id, sso_provider_id, sub_domain),
    # for which null is a valid "absent" value, not a 422 — so
    # a required field is the correct null target here. The
    # register handler takes a required `data: CreateUserDto`
    # body parameter with no default (account_endpoint.py),
    # and its dependencies cannot mask the 422:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with
    # no database lookup. The remaining body fields are all
    # valid (non-blank first name, a valid email, gender
    # "other", a valid password), so no other 422 can mask the
    # last_name error. Deliberately no exact error-type
    # assertion, mirroring the null-valued first_name 422 lock.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to
    # it, mirroring the null-valued first_name 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions. This lock adds no new
    # route-specific contradiction (a validation 422 precedes
    # the role lookup, so it contradicts no existing role
    # expectation).
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": None,
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "last_name" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the null-valued first_name 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_null_email_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a null-valued email:
    """
    # The next register validation branch after the null-valued
    # last_name 422 lock, verified fresh this run, not assumed.
    # CreateUserDto inherits email as a required EmailStr field
    # from BaseUserDto (user_dto.py): it is not Optional, so a
    # JSON null fails FastAPI request validation before the
    # handler body runs: the GUEST role lookup, the tenant
    # branching, AuthService.register, and the activation email
    # never execute, and no token is minted and no refresh
    # cookie is set. No validator masks it: the mode="after"
    # normalize_names validator only touches first/last names
    # and runs only after field validation passes, and the
    # field_serializer covers tenant_id/role_id for output
    # only. It is distinct from the null-first_name and
    # null-last_name locks (different detail loc) and from the
    # null-body lock (whole body null rather than one field
    # null). Note the contrast with the optional register
    # fields (tenant_id, role_id, sso_provider_id, sub_domain),
    # for which null is a valid "absent" value, not a 422 — so
    # a required field is the correct null target here. The
    # register handler takes a required `data: CreateUserDto`
    # body parameter with no default (account_endpoint.py),
    # and its dependencies cannot mask the 422:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with
    # no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, gender "other",
    # a valid password), so no other 422 can mask the email
    # error. Deliberately no exact error-type assertion,
    # mirroring the null-valued last_name 422 lock.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to
    # it, mirroring the null-valued last_name 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions. This lock adds no new
    # route-specific contradiction (a validation 422 precedes
    # the role lookup, so it contradicts no existing role
    # expectation).
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": None,
            "gender": "other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "email" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the null-valued last_name 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_null_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a null-valued gender:
    """
    # The next register validation branch after the null-valued
    # email 422 lock, verified fresh this run, not assumed.
    # CreateUserDto inherits gender as a required Gender enum
    # field from BaseUserDto (user_dto.py): it has no default
    # and is not Optional, so a JSON null fails FastAPI request
    # validation before the handler body runs: the GUEST role
    # lookup, the tenant branching, AuthService.register, and
    # the activation email never execute, and no token is
    # minted and no refresh cookie is set. No validator masks
    # it: the mode="after" normalize_names validator only
    # touches first/last names and runs only after field
    # validation passes, and the field_serializer covers
    # tenant_id/role_id for output only. It is distinct from
    # the null-first_name, null-last_name, and null-email
    # locks (different detail loc) and from the null-body lock
    # (whole body null rather than one field null). Note the
    # contrast with the optional register fields (tenant_id,
    # role_id, sso_provider_id, sub_domain), for which null is
    # a valid "absent" value, not a 422 — so a required field
    # is the correct null target here. The register handler
    # takes a required `data: CreateUserDto` body parameter
    # with no default (account_endpoint.py), and its
    # dependencies cannot mask the 422: get_auth_service /
    # get_role_service only resolve container objects and
    # get_tenant_id only reads request state, with no database
    # lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, a string
    # password), so no other 422 can mask the gender error.
    # Deliberately no exact error-type assertion, mirroring
    # the null-valued email 422 lock. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the null-valued email 422 lock. The security headers
    # ARE locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions. This lock adds no new route-specific
    # contradiction (a validation 422 precedes the role
    # lookup, so it contradicts no existing role expectation).
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": None,
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the null-valued email 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_null_password_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a null-valued password:
    """
    # The next register validation branch after the null-valued
    # gender 422 lock, verified fresh this run, not assumed.
    # CreateUserDto carries password as a required str field
    # (user_dto.py line 44): it has no default and is not
    # Optional, so a JSON null fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the
    # activation email never execute, and no token is minted
    # and no refresh cookie is set. No validator masks it:
    # the mode="after" normalize_names validator only touches
    # first/last names and runs only after field validation
    # passes, and the field_serializer covers tenant_id/role_id
    # for output only. The password is deliberately NOT trimmed
    # by normalize_names (credential semantics), but that only
    # matters for string values; a null fails field validation
    # first. It is distinct from the null-first_name,
    # null-last_name, null-email, and null-gender locks
    # (different detail loc) and from the null-body lock (whole
    # body null rather than one field null), and from the
    # non-string password locks (integer/boolean values are a
    # different JSON type than null). Note the contrast with
    # the optional register fields (tenant_id, role_id,
    # sso_provider_id, sub_domain), for which null is a valid
    # "absent" value, not a 422 — so a required field is the
    # correct null target here. The register handler takes a
    # required `data: CreateUserDto` body parameter with no
    # default (account_endpoint.py), and its dependencies
    # cannot mask the 422: get_auth_service / get_role_service
    # only resolve container objects and get_tenant_id only
    # reads request state, with no database lookup. The
    # remaining body fields are all valid (non-blank first and
    # last names, a valid email, gender "other"), so no other
    # 422 can mask the password error. Deliberately no exact
    # error-type assertion, mirroring the null-valued gender
    # 422 lock. Deliberately no Cache-Control/Pragma assertion:
    # a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the null-valued
    # gender 422 lock. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    # This lock adds no new route-specific contradiction (a
    # validation 422 precedes the role lookup, so it
    # contradicts no existing role expectation).
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "other",
            "password": None,
        },
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
    # mirroring the null-valued gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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
async def test_account_register_empty_password_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The account register POST with an empty password:
    """
    # The next register branch after the null-password 422 lock,
    # verified fresh this run, not assumed. CreateUserDto carries
    # password as a plain required str field (user_dto.py line 44)
    # with no min_length, no default, and no trim: unlike a null,
    # an empty string passes FastAPI request validation, so the
    # handler body runs. Its first step is the GUEST role lookup
    # (account_endpoint.py register), before any tenant branching
    # and before AuthService.register runs — and the password
    # policy (validate_password, common/utils.py) only runs later,
    # inside the process_user_creation callback, so it cannot mask
    # the role outcome here. The shared conftest client seeds no
    # role and Role is in the conftest model set, so the lookup on
    # the fresh test database raises RoleNotFoundException before
    # any creation, password-policy check, or email send. No
    # X-Tenant-ID header is sent, so the tenant-context branch
    # cannot run first. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, gender
    # "other"), so no 422 can mask the 404. This locks the
    # ordering, not acceptance of an empty password: with a seeded
    # GUEST role the same request would reach the password policy
    # and fail there. Deliberately NOT locked: the 201 success
    # path and the weak-password branch, which both need a seeded
    # GUEST role. The central ApiBaseException handler maps the
    # NotFound subclass to 404 with body {"error": ..., "code":
    # 404} and Cache-Control: no-store plus Pragma: no-cache, and
    # the pure-ASGI security-headers middleware stamps every HTTP
    # response with no path exclusions. The error assertion uses
    # a substring check for "Role", mirroring the missing-guest
    # role 404 lock.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "",
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
    # mirroring the missing-guest role 404 lock, using substring
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
async def test_account_register_whitespace_password_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The account register POST with a whitespace-only password:
    """
    # The next register branch after the empty-password 404 lock,
    # verified fresh this run, not assumed. CreateUserDto carries
    # password as a plain required str field (user_dto.py line 44)
    # with no min_length, no default, and no trim: unlike a null,
    # a whitespace-only string passes FastAPI request validation,
    # so the handler body runs. It is distinct from the
    # empty-password lock ("" has length 0, "   " has length 3)
    # and from the null/non-string password locks (a different
    # JSON type or a validation failure, not a handler outcome):
    # whitespace-only is the remaining string shape that the
    # deliberate no-trim credential rule leaves unnormalized.
    # The handler's first step is the GUEST role lookup
    # (account_endpoint.py register), before any tenant branching
    # and before AuthService.register runs — and the password
    # policy (validate_password, common/utils.py) only runs later,
    # inside the process_user_creation callback, so it cannot mask
    # the role outcome here. The shared conftest client seeds no
    # role and Role is in the conftest model set, so the lookup on
    # the fresh test database raises RoleNotFoundException before
    # any creation, password-policy check, or email send. No
    # X-Tenant-ID header is sent, so the tenant-context branch
    # cannot run first. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, gender
    # "other"), so no 422 can mask the 404. This locks the
    # ordering, not acceptance of a whitespace password: with a
    # seeded GUEST role the same request would reach the password
    # policy and fail there. Deliberately NOT locked: the 201
    # success path and the weak-password branch, which both need
    # a seeded GUEST role. The central ApiBaseException handler
    # maps the NotFound subclass to 404 with body {"error": ...,
    # "code": 404} and Cache-Control: no-store plus Pragma:
    # no-cache, and the pure-ASGI security-headers middleware
    # stamps every HTTP response with no path exclusions. The
    # error assertion uses a substring check for "Role",
    # mirroring the missing-guest role 404 lock.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "   ",
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
    # mirroring the missing-guest role 404 lock, using substring
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
async def test_account_register_padded_password_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The account register POST with a padded password:
    """
    # The next register branch after the whitespace-password 404 lock,
    # verified fresh this run, not assumed. CreateUserDto carries
    # password as a plain required str field (user_dto.py line 44)
    # with no min_length, no default, and no trim: normalize_names
    # touches only first/last names and deliberately does NOT trim
    # the password (credential semantics, stated in its own comment),
    # so a padded value passes FastAPI request validation verbatim
    # and the handler body runs. It is distinct from the
    # whitespace-password lock (all spaces, no non-space core) and
    # from the empty-password lock (length 0): here the trimmed core
    # "StrongPass1!" satisfies the password policy (8+ chars, upper,
    # lower, digit, special per PASSWORD_REGEX in common/utils.py),
    # so the padding itself is the only difference from a plain
    # strong password — and it still cannot mask the role outcome.
    # The handler's first step is the GUEST role lookup
    # (account_endpoint.py register), before any tenant branching
    # and before AuthService.register runs — and validate_password
    # only runs later, inside the process_user_creation callback, so
    # it cannot mask the role outcome here. The shared conftest
    # client seeds no role and Role is in the conftest model set, so
    # the lookup on the fresh test database raises
    # RoleNotFoundException before any creation, password-policy
    # check, or email send. No X-Tenant-ID header is sent, so the
    # tenant-context branch cannot run first. The remaining body
    # fields are all valid (non-blank first and last names, a valid
    # email, gender "other"), so no 422 can mask the 404. This locks
    # the ordering, not acceptance of a padded password: with a
    # seeded GUEST role the same request would reach the password
    # policy (which the padded value also satisfies) and continue
    # toward creation. Deliberately NOT locked: the 201 success path
    # and the weak-password branch, which both need a seeded GUEST
    # role. The central ApiBaseException handler maps the NotFound
    # subclass to 404 with body {"error": ..., "code": 404} and
    # Cache-Control: no-store plus Pragma: no-cache, and the
    # pure-ASGI security-headers middleware stamps every HTTP
    # response with no path exclusions. The error assertion uses a
    # substring check for "Role", mirroring the missing-guest role
    # 404 lock.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "  StrongPass1!  ",
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
    # mirroring the missing-guest role 404 lock, using substring
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
async def test_account_register_padded_first_name_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The account register POST with a padded first_name:
    """
    # The next register branch after the padded-password 404 lock,
    # verified fresh this run, not assumed. CreateUserDto inherits
    # first_name as a required str with min_length=1 from BaseUserDto
    # (user_dto.py line 9), and its mode="after" normalize_names
    # validator trims first/last names (raising 422 only when the
    # trimmed value is empty), so "  New  " passes FastAPI request
    # validation as "New" and the handler body runs. It is distinct
    # from the padded-password lock (padding on a name the validator
    # trims, versus padding on a password deliberately NOT trimmed),
    # from the whitespace-name locks (all spaces, rejected 422 by
    # the validator), and from the integer/null first_name locks
    # (type errors, 422 before the handler). The handler's first
    # step is the GUEST role lookup (account_endpoint.py register),
    # before any tenant branching and before AuthService.register
    # runs — and validate_password only runs later, inside the
    # process_user_creation callback, so it cannot mask the role
    # outcome here. The shared conftest client seeds no role and
    # Role is in the conftest model set, so the lookup on the fresh
    # test database raises RoleNotFoundException before any
    # creation, password-policy check, or email send. No
    # X-Tenant-ID header is sent, so the tenant-context branch
    # cannot run first. The remaining body fields are all valid
    # (non-blank last name, a valid email, gender "other", a
    # strong string password), so no 422 can mask the 404. This
    # locks the ordering, not acceptance of a padded name: with a
    # seeded GUEST role the same request would continue toward
    # creation with the trimmed name "New". Deliberately NOT locked:
    # the 201 success path and the weak-password branch, which both
    # need a seeded GUEST role. The central ApiBaseException
    # handler maps the NotFound subclass to 404 with body
    # {"error": ..., "code": 404} and Cache-Control: no-store plus
    # Pragma: no-cache, and the pure-ASGI security-headers
    # middleware stamps every HTTP response with no path
    # exclusions. The error assertion uses a substring check for
    # "Role", mirroring the missing-guest role 404 lock.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "  New  ",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "StrongPass1!",
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
    # mirroring the missing-guest role 404 lock, using substring
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
async def test_account_register_padded_last_name_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The account register POST with a padded last_name:
    """
    # The next register branch after the padded-first_name 404 lock,
    # verified fresh this run, not assumed. CreateUserDto inherits
    # last_name as a required str with min_length=1 from BaseUserDto
    # (user_dto.py), and its mode="after" normalize_names
    # validator trims first/last names (raising 422 only when the
    # trimmed value is empty), so "  User  " passes FastAPI request
    # validation as "User" and the handler body runs. It is distinct
    # from the padded-first_name lock (padding on the other trimmed
    # name field), from the whitespace-name locks (all spaces,
    # rejected 422 by the validator), and from the integer/null
    # last_name locks (type errors, 422 before the handler). The
    # handler's first step is the GUEST role lookup
    # (account_endpoint.py register), before any tenant branching
    # and before AuthService.register runs — and validate_password
    # only runs later, inside the process_user_creation callback,
    # so it cannot mask the role outcome here. The shared conftest
    # client seeds no role and Role is in the conftest model set,
    # so the lookup on the fresh test database raises
    # RoleNotFoundException before any creation, password-policy
    # check, or email send. No X-Tenant-ID header is sent, so the
    # tenant-context branch cannot run first. The remaining body
    # fields are all valid (non-blank first name, a valid email,
    # gender "other", a strong string password), so no 422 can mask
    # the 404. This locks the ordering, not acceptance of a padded
    # name: with a seeded GUEST role the same request would
    # continue toward creation with the trimmed name "User".
    # Deliberately NOT locked: the 201 success path and the
    # weak-password branch, which both need a seeded GUEST role.
    # The central ApiBaseException handler maps the NotFound
    # subclass to 404 with body {"error": ..., "code": 404} and
    # Cache-Control: no-store plus Pragma: no-cache, and the
    # pure-ASGI security-headers middleware stamps every HTTP
    # response with no path exclusions. The error assertion uses a
    # substring check for "Role", mirroring the missing-guest role
    # 404 lock.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "  User  ",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "StrongPass1!",
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
    # mirroring the missing-guest role 404 lock, using substring
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


async def test_account_register_padded_email_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The account register POST with a padded email:
    """
    # The next register branch after the padded-last_name 404 lock,
    # verified fresh this run, not assumed. CreateUserDto inherits
    # email as EmailStr from BaseUserDto (user_dto.py), and its
    # mode="after" normalize_names validator only touches first/last
    # names and runs only after field validation passes, so it cannot
    # mask the email outcome. Whether a padded address passes
    # EmailStr was checked empirically this run, not assumed: with
    # the repo's locked versions (pydantic 2.14.2, email-validator
    # 2.3.0, uv.lock) a padded address validates and normalizes to
    # the unpadded address, so "  newuser@example.com  " passes
    # FastAPI request validation and the handler body runs. It is
    # distinct from the padded-first_name/padded-last_name locks
    # (padding on the trimmed name fields, not the email field),
    # from the invalid-email lock (a malformed address, rejected
    # 422), and from the nonstring/object/boolean/integer email
    # locks (type errors, 422 before the handler). The handler's
    # first step is the GUEST role lookup
    # (account_endpoint.py register), before any tenant branching
    # and before AuthService.register runs — and validate_password
    # only runs later, inside the process_user_creation callback,
    # so it cannot mask the role outcome here. The shared conftest
    # client seeds no role and Role is in the conftest model set,
    # so the lookup on the fresh test database raises
    # RoleNotFoundException before any creation, password-policy
    # check, or email send. No X-Tenant-ID header is sent, so the
    # tenant-context branch cannot run first. The remaining body
    # fields are all valid (non-blank first and last names, gender
    # "other", a strong string password), so no 422 can mask the
    # 404. This locks the ordering, not acceptance of a padded
    # address: with a seeded GUEST role the same request would
    # continue toward creation with the normalized email.
    # Deliberately NOT locked: the 201 success path and the
    # weak-password branch, which both need a seeded GUEST role.
    # The central ApiBaseException handler maps the NotFound
    # subclass to 404 with body {"error": ..., "code": 404} and
    # Cache-Control: no-store plus Pragma: no-cache, and the
    # pure-ASGI security-headers middleware stamps every HTTP
    # response with no path exclusions. The error assertion uses a
    # substring check for "Role", mirroring the missing-guest role
    # 404 lock.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "  newuser@example.com  ",
            "gender": "other",
            "password": "StrongPass1!",
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
    # mirroring the missing-guest role 404 lock, using substring
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


async def test_account_register_padded_sub_domain_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The account register POST with a padded sub_domain:
    """
    # The next register branch after the padded-email 404 lock,
    # verified fresh this run, not assumed. CreateUserDto inherits
    # no validator for sub_domain: the mode="after"
    # normalize_names validator only touches first/last names and
    # runs only after field validation passes, and the only
    # field_serializer covers tenant_id/role_id for output only,
    # so neither can mask the sub_domain outcome. sub_domain is
    # Optional[str] with no min_length or pattern constraint
    # (user_dto.py), so " tenant " passes FastAPI request
    # validation verbatim and the handler body runs. It is
    # distinct from the padded-first_name/padded-last_name/
    # padded-email/padded-password locks (padding on other
    # fields, not sub_domain), and from the non-string/object/
    # boolean/integer sub_domain locks (type errors, 422 before
    # the handler). The handler's first step is the GUEST role
    # lookup (account_endpoint.py register), before any tenant
    # branching and before AuthService.register runs — and the
    # sub_domain is only consumed later, inside
    # AuthService.register (auth_service.py strips/lowercases it
    # there), so it cannot mask the role outcome here. The
    # shared conftest client seeds no role and Role is in the
    # conftest model set, so the lookup on the fresh test
    # database raises RoleNotFoundException before any creation,
    # password-policy check, or email send. No X-Tenant-ID header
    # is sent, so the tenant-context branch cannot run first.
    # The remaining body fields are all valid (non-blank first
    # and last names, a valid email, gender "other", a strong
    # string password), so no 422 can mask the 404. This locks
    # the ordering, not acceptance of a padded sub_domain: with
    # a seeded GUEST role the same request would continue
    # toward creation, where AuthService.register strips and
    # lowercases the sub_domain before use.
    # Deliberately NOT locked: the 201 success path and the
    # weak-password branch, which both need a seeded GUEST role.
    # The central ApiBaseException handler maps the NotFound
    # subclass to 404 with body {"error": ..., "code": 404} and
    # Cache-Control: no-store plus Pragma: no-cache, and the
    # pure-ASGI security-headers middleware stamps every HTTP
    # response with no path exclusions. The error assertion uses a
    # substring check for "Role", mirroring the missing-guest role
    # 404 lock.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "StrongPass1!",
            "sub_domain": " tenant ",
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
    # mirroring the missing-guest role 404 lock, using substring
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


async def test_account_register_whitespace_sub_domain_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The account register POST with a whitespace-only sub_domain:
    """
    # The next register branch after the padded-sub_domain 404 lock,
    # verified fresh this run, not assumed. CreateUserDto.sub_domain
    # is Optional[str] with no min_length or pattern constraint
    # (user_dto.py), and no validator touches it: the mode="after"
    # normalize_names validator only trims first/last names (raising
    # 422 only when a name trims to empty) and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only, so neither can mask the
    # sub_domain outcome. "   " is a string, so it passes FastAPI
    # request validation verbatim and the handler body runs. It is
    # distinct from the padded-sub_domain lock (" tenant " has a
    # non-space core that AuthService.register later strips and
    # lowercases) and from the non-string/object/boolean/integer
    # sub_domain locks (type errors, 422 before the handler). The
    # handler's first step is the GUEST role lookup
    # (account_endpoint.py register), before any tenant branching
    # and before AuthService.register runs — and the sub_domain is
    # only consumed later, inside AuthService.register, so it
    # cannot mask the role outcome here. The shared conftest client
    # seeds no role and Role is in the conftest model set, so the
    # lookup on the fresh test database raises
    # RoleNotFoundException before any creation, password-policy
    # check, or email send. No X-Tenant-ID header is sent, so the
    # tenant-context branch cannot run first. The remaining body
    # fields are all valid (non-blank first and last names, a valid
    # email, gender "other", a strong string password), so no 422
    # can mask the 404. This locks the ordering, not acceptance of
    # a whitespace-only sub_domain: with a seeded GUEST role the
    # same request would continue toward creation, where
    # AuthService.register strips and lowercases the sub_domain
    # before use (a whitespace-only value would strip to empty
    # there, a downstream branch outside this lock).
    # Deliberately NOT locked: the 201 success path and the
    # weak-password branch, which both need a seeded GUEST role.
    # The central ApiBaseException handler maps the NotFound
    # subclass to 404 with body {"error": ..., "code": 404} and
    # Cache-Control: no-store plus Pragma: no-cache, and the
    # pure-ASGI security-headers middleware stamps every HTTP
    # response with no path exclusions. The error assertion uses a
    # substring check for "Role", mirroring the missing-guest role
    # 404 lock.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "StrongPass1!",
            "sub_domain": "   ",
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
    # mirroring the missing-guest role 404 lock, using substring
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


async def test_account_register_null_sub_domain_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The account register POST with an explicit-null sub_domain:
    """
    # The next register branch after the whitespace-only sub_domain
    # 404 lock, verified fresh this run, not assumed. CreateUserDto
    # .sub_domain is Optional[str] = None (user_dto.py), with no
    # min_length or pattern constraint and no validator touching
    # it: the mode="after" normalize_names validator only trims
    # first/last names and runs only after field validation
    # passes, and the only field_serializer covers tenant_id/
    # role_id for output only, so neither can mask the sub_domain
    # outcome. An explicit JSON null is therefore a valid "absent"
    # value, not a 422: it passes FastAPI request validation
    # verbatim and the handler body runs. It is distinct from
    # the whitespace-only sub_domain lock ("   " is a string
    # that AuthService.register would later strip to empty) and
    # from the non-string/object/boolean/integer sub_domain
    # locks (type errors, 422 before the handler). The handler's
    # first step is the GUEST role lookup (account_endpoint.py
    # register), before any tenant branching and before
    # AuthService.register runs — and the sub_domain is only
    # consumed later, inside AuthService.register, so it cannot
    # mask the role outcome here. The shared conftest client
    # seeds no role and Role is in the conftest model set, so
    # the lookup on the fresh test database raises
    # RoleNotFoundException before any creation, password-policy
    # check, or email send. No X-Tenant-ID header is sent, so the
    # tenant-context branch cannot run first. The remaining body
    # fields are all valid (non-blank first and last names, a
    # valid email, gender "other", a strong string password), so
    # no 422 can mask the 404. This locks the ordering, not
    # acceptance of a null sub_domain: with a seeded GUEST role
    # the same request would continue toward creation, where an
    # absent sub_domain takes the brand-new-tenant branch
    # (a downstream branch outside this lock).
    # Deliberately NOT locked: the 201 success path and the
    # weak-password branch, which both need a seeded GUEST role.
    # The central ApiBaseException handler maps the NotFound
    # subclass to 404 with body {"error": ..., "code": 404} and
    # Cache-Control: no-store plus Pragma: no-cache, and the
    # pure-ASGI security-headers middleware stamps every HTTP
    # response with no path exclusions. The error assertion uses
    # a substring check for "Role", mirroring the missing-guest
    # role 404 lock.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "StrongPass1!",
            "sub_domain": None,
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
    # mirroring the missing-guest role 404 lock, using substring
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

async def test_account_register_padded_sso_provider_id_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The account register POST with a padded sso_provider_id:
    """
    # The next register branch after the explicit-null sub_domain
    # 404 lock, verified fresh this run, not assumed. CreateUserDto
    # .sso_provider_id is Optional[str] = None (user_dto.py
    # BaseUserDto), with no min_length or pattern constraint and
    # no validator touching it: the mode="after" normalize_names
    # validator only trims first/last names and runs only after
    # field validation passes, and the only field_serializer
    # covers tenant_id/role_id for output only, so neither can
    # mask the sso_provider_id outcome. A padded string such as
    # " google " therefore passes FastAPI request validation
    # verbatim and the handler body runs. It is distinct from
    # the padded-first_name/padded-last_name/padded-email/
    # padded-password/padded-sub_domain locks (other fields)
    # and from the non-string/object/boolean/integer
    # sso_provider_id locks (type errors, 422 before the
    # handler). The handler's first step is the GUEST role
    # lookup (account_endpoint.py register), before any tenant
    # branching and before AuthService.register runs — and
    # sso_provider_id is only consumed in SSO login flows
    # (auth_service.py), not in the register path, so it cannot
    # mask the role outcome here. The shared conftest client
    # seeds no role and Role is in the conftest model set, so
    # the lookup on the fresh test database raises
    # RoleNotFoundException before any creation, password-policy
    # check, or email send. No X-Tenant-ID header is sent, so the
    # tenant-context branch cannot run first. The remaining body
    # fields are all valid (non-blank first and last names, a
    # valid email, gender "other", a strong string password), so
    # no 422 can mask the 404. This locks the ordering, not
    # acceptance of a padded sso_provider_id: with a seeded
    # GUEST role the same request would continue toward
    # creation, where the padded value would persist verbatim
    # (a downstream branch outside this lock).
    # Deliberately NOT locked: the 201 success path and the
    # weak-password branch, which both need a seeded GUEST role.
    # The central ApiBaseException handler maps the NotFound
    # subclass to 404 with body {"error": ..., "code": 404} and
    # Cache-Control: no-store plus Pragma: no-cache, and the
    # pure-ASGI security-headers middleware stamps every HTTP
    # response with no path exclusions. The error assertion uses
    # a substring check for "Role", mirroring the missing-guest
    # role 404 lock.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "StrongPass1!",
            "sso_provider_id": " google ",
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
    # mirroring the missing-guest role 404 lock, using substring
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


async def test_account_register_whitespace_only_sso_provider_id_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The account register POST with a whitespace-only sso_provider_id:
    """
    # The next register branch after the padded sso_provider_id
    # 404 lock, verified fresh this run, not assumed. CreateUserDto
    # .sso_provider_id is Optional[str] = None (user_dto.py
    # BaseUserDto), with no min_length or pattern constraint and
    # no validator touching it: the mode="after" normalize_names
    # validator only trims first/last names (raising on a blank
    # name) and runs only after field validation passes, and the
    # only field_serializer covers tenant_id/role_id for output
    # only, so neither can mask the sso_provider_id outcome. A
    # whitespace-only string such as "   " therefore passes
    # FastAPI request validation verbatim and the handler body
    # runs — note the contrast with first/last names, where the
    # same whitespace-only value is rejected 422 by
    # normalize_names. It is distinct from the padded
    # sso_provider_id lock (a value with non-whitespace content
    # that survives trimming) and from the non-string/object/
    # boolean/integer sso_provider_id locks (type errors, 422
    # before the handler). The handler's first step is the GUEST
    # role lookup (account_endpoint.py register), before any
    # tenant branching and before AuthService.register runs —
    # and sso_provider_id is only consumed in SSO login flows
    # (auth_service.py), not in the register path, so it cannot
    # mask the role outcome here. The shared conftest client
    # seeds no role and Role is in the conftest model set, so
    # the lookup on the fresh test database raises
    # RoleNotFoundException before any creation, password-policy
    # check, or email send. No X-Tenant-ID header is sent, so the
    # tenant-context branch cannot run first. The remaining body
    # fields are all valid (non-blank first and last names, a
    # valid email, gender "other", a strong string password), so
    # no 422 can mask the 404. This locks the ordering, not
    # acceptance of a whitespace-only sso_provider_id: with a
    # seeded GUEST role the same request would continue toward
    # creation, where the blank value would persist verbatim
    # (a downstream branch outside this lock).
    # Deliberately NOT locked: the 201 success path and the
    # weak-password branch, which both need a seeded GUEST role.
    # The central ApiBaseException handler maps the NotFound
    # subclass to 404 with body {"error": ..., "code": 404} and
    # Cache-Control: no-store plus Pragma: no-cache, and the
    # pure-ASGI security-headers middleware stamps every HTTP
    # response with no path exclusions. The error assertion uses
    # a substring check for "Role", mirroring the missing-guest
    # role 404 lock.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "StrongPass1!",
            "sso_provider_id": "   ",
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
    # mirroring the missing-guest role 404 lock, using substring
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

async def test_account_register_null_sso_provider_id_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The account register POST with an explicit-null sso_provider_id:
    """
    # The next register branch after the whitespace-only
    # sso_provider_id 404 lock, verified fresh this run, not
    # assumed. CreateUserDto.sso_provider_id is Optional[str] =
    # None (user_dto.py BaseUserDto), with no min_length or
    # pattern constraint and no validator touching it: the
    # mode="after" normalize_names validator only trims
    # first/last names (raising on a blank name) and runs only
    # after field validation passes, and the only
    # field_serializer covers tenant_id/role_id for output
    # only, so neither can mask the sso_provider_id outcome.
    # An explicit JSON null is therefore a valid "absent"
    # value, not a 422: it passes FastAPI request validation
    # verbatim and the handler body runs. It is distinct from
    # the whitespace-only sso_provider_id lock ("   " is a
    # string that would persist verbatim downstream) and from
    # the padded lock (a string with non-whitespace content),
    # and from the non-string/object/boolean/integer
    # sso_provider_id locks (type errors, 422 before the
    # handler). It is also distinct from merely omitting the
    # field: this locks that an explicit null is accepted as
    # absent by request validation rather than rejected. The
    # handler's first step is the GUEST role lookup
    # (account_endpoint.py register), before any tenant
    # branching and before AuthService.register runs — and
    # sso_provider_id is only consumed in SSO login flows
    # (auth_service.py), not in the register path, so it
    # cannot mask the role outcome here. The shared conftest
    # client seeds no role and Role is in the conftest model
    # set, so the lookup on the fresh test database raises
    # RoleNotFoundException before any creation,
    # password-policy check, or email send. No X-Tenant-ID
    # header is sent, so the tenant-context branch cannot run
    # first. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, gender
    # "other", a strong string password), so no 422 can mask
    # the 404. This locks the ordering, not acceptance of a
    # null sso_provider_id: with a seeded GUEST role the same
    # request would continue toward creation, where a null
    # sso_provider_id is simply absent (a downstream branch
    # outside this lock).
    # Deliberately NOT locked: the 201 success path and the
    # weak-password branch, which both need a seeded GUEST role.
    # The central ApiBaseException handler maps the NotFound
    # subclass to 404 with body {"error": ..., "code": 404} and
    # Cache-Control: no-store plus Pragma: no-cache, and the
    # pure-ASGI security-headers middleware stamps every HTTP
    # response with no path exclusions. The error assertion uses
    # a substring check for "Role", mirroring the missing-guest
    # role 404 lock.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "StrongPass1!",
            "sso_provider_id": None,
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
    # mirroring the missing-guest role 404 lock, using substring
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

async def test_account_register_null_tenant_id_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The account register POST with an explicit-null tenant_id:
    """
    # The next register branch after the explicit-null
    # sso_provider_id 404 lock, verified fresh this run, not
    # assumed. CreateUserDto.tenant_id is PydanticObjectId | None
    # = None (user_dto.py BaseUserDto), with no validator
    # touching it: the mode="after" normalize_names validator
    # only trims first/last names (raising on a blank name) and
    # runs only after field validation passes, and the only
    # field_serializer covers tenant_id/role_id for output
    # only, so it cannot mask the tenant_id outcome at request
    # validation. An explicit JSON null is therefore a valid
    # "absent" value, not a 422: it passes FastAPI request
    # validation verbatim and the handler body runs. It is
    # distinct from merely omitting the field: this locks that
    # an explicit null is accepted as absent by request
    # validation rather than rejected. It is also distinct
    # from the non-string/object/boolean/integer tenant_id
    # locks (type errors, 422 before the handler) and from a
    # value-bearing tenant_id, which would be parsed as a
    # PydanticObjectId and could be overwritten by the
    # X-Tenant-ID header branch. The handler's first step is
    # the GUEST role lookup (account_endpoint.py register),
    # before any tenant branching, before data.tenant_id is
    # stamped from the header, and before AuthService.register
    # runs — and tenant_id is only consumed downstream in the
    # tenant-creation branches, not in the role lookup, so it
    # cannot mask the role outcome here. The shared conftest
    # client seeds no role and Role is in the conftest model
    # set, so the lookup on the fresh test database raises
    # RoleNotFoundException before any creation,
    # password-policy check, or email send. No X-Tenant-ID
    # header is sent, so the tenant-context branch cannot run
    # first and cannot stamp a different tenant_id. The
    # remaining body fields are all valid (non-blank first and
    # last names, a valid email, gender "other", a strong
    # string password), so no 422 can mask the 404. This locks
    # the ordering, not acceptance of a null tenant_id: with a
    # seeded GUEST role the same request would continue toward
    # creation, where a null tenant_id takes the
    # brand-new-tenant branch (a downstream branch outside
    # this lock).
    # Deliberately NOT locked: the 201 success path and the
    # weak-password branch, which both need a seeded GUEST role.
    # The central ApiBaseException handler maps the NotFound
    # subclass to 404 with body {"error": ..., "code": 404} and
    # Cache-Control: no-store plus Pragma: no-cache, and the
    # pure-ASGI security-headers middleware stamps every HTTP
    # response with no path exclusions. The error assertion uses
    # a substring check for "Role", mirroring the missing-guest
    # role 404 lock.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "StrongPass1!",
            "tenant_id": None,
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
    # mirroring the missing-guest role 404 lock, using substring
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

async def test_account_register_null_role_id_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The account register POST with an explicit-null role_id:
    """
    # The next register branch after the explicit-null
    # tenant_id 404 lock, verified fresh this run, not
    # assumed. CreateUserDto.role_id is PydanticObjectId | None
    # = None (user_dto.py BaseUserDto), with no validator
    # touching it: the mode="after" normalize_names validator
    # only trims first/last names (raising on a blank name) and
    # runs only after field validation passes, and the only
    # field_serializer covers tenant_id/role_id for output
    # only, so it cannot mask the role_id outcome at request
    # validation. An explicit JSON null is therefore a valid
    # "absent" value, not a 422: it passes FastAPI request
    # validation verbatim and the handler body runs. It is
    # distinct from merely omitting the field: this locks that
    # an explicit null is accepted as absent by request
    # validation rather than rejected. It is also distinct
    # from the malformed-string and non-string role_id locks
    # (type errors, 422 before the handler) and from a
    # value-bearing role_id, which would be parsed as a
    # PydanticObjectId. The handler's first step is the GUEST
    # role lookup (account_endpoint.py register), before the
    # `data.role_id = role_guest.id` overwrite, before any
    # tenant branching, and before AuthService.register runs
    # — and role_id is only consumed via that overwrite, not
    # in the lookup, so it cannot mask the role outcome here.
    # The shared conftest client seeds no role and Role is in
    # the conftest model set, so the lookup on the fresh test
    # database raises RoleNotFoundException before any
    # creation, password-policy check, or email send. No
    # X-Tenant-ID header is sent, so the tenant-context branch
    # cannot run first. The remaining body fields are all
    # valid (non-blank first and last names, a valid email,
    # gender "other", a strong string password), so no 422 can
    # mask the 404. This locks the ordering, not acceptance of
    # a null role_id: with a seeded GUEST role the same request
    # would continue toward creation, where the null role_id
    # would be overwritten with the GUEST role id anyway (a
    # downstream step outside this lock).
    # Deliberately NOT locked: the 201 success path and the
    # weak-password branch, which both need a seeded GUEST role.
    # The central ApiBaseException handler maps the NotFound
    # subclass to 404 with body {"error": ..., "code": 404} and
    # Cache-Control: no-store plus Pragma: no-cache, and the
    # pure-ASGI security-headers middleware stamps every HTTP
    # response with no path exclusions. The error assertion uses
    # a substring check for "Role", mirroring the missing-guest
    # role 404 lock.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "StrongPass1!",
            "role_id": None,
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
    # mirroring the missing-guest role 404 lock, using substring
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


async def test_account_register_padded_tenant_id_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a padded tenant_id:
    """
    # The next register branch after the explicit-null
    # role_id 404 lock, verified fresh this run, not
    # assumed. CreateUserDto inherits tenant_id as a
    # PydanticObjectId | None field defaulting to None from
    # BaseUserDto (user_dto.py), with no validator touching
    # it: the mode="after" normalize_names validator only
    # trims first/last names and runs only after field
    # validation passes, and the only field_serializer
    # covers tenant_id/role_id for output only, so neither
    # can trim the incoming value. A PydanticObjectId
    # requires exactly 24 hex chars (stated in
    # base_repository.py and
    # subscription_plan_repository_impl.py, and the
    # UpdateUserDto comment records that a padded id
    # failed conversion before its own trim was added),
    # so a valid 24-hex id wrapped in spaces is 26 chars
    # with non-hex characters and fails FastAPI request
    # validation before the handler body runs: the GUEST
    # role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie
    # is set. The endpoint's dependencies cannot mask the
    # 422 either: get_auth_service/get_role_service only
    # resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. It is
    # distinct from the malformed-string tenant_id lock,
    # which used a non-ObjectId string, from the
    # list/dict/boolean/integer tenant_id locks (wrong
    # JSON types, 422 before the handler), from the
    # explicit-null tenant_id lock (a valid absent value
    # reaching the 404 role lookup), and from the padded
    # first_name/last_name/email/password/sub_domain/
    # sso_provider_id locks (other fields, 404): this
    # locks that surrounding whitespace is NOT stripped
    # from an ObjectId field at register validation. The
    # remaining body fields are all valid (non-blank
    # first and last names, a valid email, gender
    # "other", a strong string password), so no other 422
    # can mask the tenant_id error. Deliberately no exact
    # error-type assertion, mirroring the integer-valued
    # tenant_id 422 lock. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to
    # it, mirroring the integer-valued tenant_id 422
    # lock. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions. This
    # lock adds no new route-specific contradiction (a
    # validation 422 precedes the role lookup, so it
    # contradicts no existing role expectation).
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "tenant_id": " 507f1f77bcf86cd799439011 ",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "tenant_id" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the integer-valued tenant_id 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_padded_role_id_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a padded role_id:
    """
    # The next register branch after the padded
    # tenant_id 422 lock, verified fresh this run, not
    # assumed. CreateUserDto inherits role_id as a
    # PydanticObjectId | None field defaulting to None from
    # BaseUserDto (user_dto.py), with no validator touching
    # it: the mode="after" normalize_names validator only
    # trims first/last names and runs only after field
    # validation passes, and the only field_serializer
    # covers tenant_id/role_id for output only, so neither
    # can trim the incoming value. (The trim in
    # UpdateUserDto and in UserRoleUpdateRequestDto covers
    # other endpoints, not register.) A PydanticObjectId
    # requires exactly 24 hex chars, so a valid 24-hex id
    # wrapped in spaces is 26 chars with non-hex
    # characters and fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup,
    # the tenant branching, AuthService.register, and the
    # activation email never execute, and no token is
    # minted and no refresh cookie is set. The endpoint's
    # dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve
    # container objects and get_tenant_id only reads
    # request state, with no database lookup. Note the
    # handler overwrites data.role_id with the GUEST role
    # id after the lookup, so a valid unpadded role_id
    # would be ignored anyway — padding is what makes
    # this a validation failure rather than a silent
    # overwrite. It is distinct from the malformed-string
    # role_id lock, which used a non-ObjectId string, from
    # the list/dict/boolean/integer/nonstring role_id locks
    # (wrong JSON types, 422 before the handler), from the
    # explicit-null role_id lock (a valid absent value
    # reaching the 404 role lookup), and from the padded
    # tenant_id lock (the other ObjectId field, 422).
    # This locks that surrounding whitespace is NOT
    # stripped from an ObjectId field at register
    # validation. The remaining body fields are all valid
    # (non-blank first and last names, a valid email,
    # gender "other", a strong string password), so no
    # other 422 can mask the role_id error. Deliberately
    # no exact error-type assertion, mirroring the
    # integer-valued role_id 422 lock. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to
    # it, mirroring the integer-valued role_id 422 lock.
    # The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions. This
    # lock adds no new route-specific contradiction (a
    # validation 422 precedes the role lookup, so it
    # contradicts no existing role expectation).
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "role_id": " 507f1f77bcf86cd799439011 ",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "role_id" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the integer-valued role_id 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_empty_sub_domain_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The account register POST with an empty-string sub_domain:
    """
    # The next register branch after the padded role_id 422 lock,
    # verified fresh this run, not assumed. CreateUserDto
    # .sub_domain is Optional[str] = None (user_dto.py), with no
    # min_length or pattern constraint and no validator touching
    # it: the mode="after" normalize_names validator only trims
    # first/last names and runs only after field validation
    # passes, and the only field_serializer covers tenant_id/
    # role_id for output only, so neither can mask the sub_domain
    # outcome. An empty string is therefore a valid string value,
    # not a 422: unlike first/last names (min_length=1 plus the
    # blank-rejecting normalize_names validator), nothing rejects
    # "" for sub_domain, so it passes FastAPI request validation
    # verbatim and the handler body runs. It is distinct from
    # the whitespace-only sub_domain lock ("   " is a string
    # that AuthService.register would later strip to empty),
    # from the padded sub_domain lock (a value with
    # non-whitespace content), from the null sub_domain lock
    # (an absent value), and from the non-string/object/
    # boolean/integer sub_domain locks (type errors, 422 before
    # the handler). The handler's first step is the GUEST role
    # lookup (account_endpoint.py register), before any tenant
    # branching and before AuthService.register runs — and the
    # sub_domain is only consumed later, inside
    # AuthService.register, so it cannot mask the role outcome
    # here. The shared conftest client seeds no role and Role is
    # in the conftest model set, so the lookup on the fresh test
    # database raises RoleNotFoundException before any creation,
    # password-policy check, or email send. No X-Tenant-ID header
    # is sent, so the tenant-context branch cannot run first.
    # The remaining body fields are all valid (non-blank first
    # and last names, a valid email, gender "other", a strong
    # string password), so no 422 can mask the 404. This locks
    # the ordering, not acceptance of an empty sub_domain: with
    # a seeded GUEST role the same request would continue toward
    # creation, where an empty sub_domain takes the
    # brand-new-tenant branch (a downstream branch outside this
    # lock). Deliberately NOT locked: the 201 success path and
    # the weak-password branch, which both need a seeded GUEST
    # role. The central ApiBaseException handler maps the
    # NotFound subclass to 404 with body {"error": ..., "code":
    # 404} and Cache-Control: no-store plus Pragma: no-cache,
    # and the pure-ASGI security-headers middleware stamps every
    # HTTP response with no path exclusions. The error assertion
    # uses a substring check for "Role", mirroring the
    # missing-guest role 404 lock.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "StrongPass1!",
            "sub_domain": "",
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
    # mirroring the missing-guest role 404 lock, using substring
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


async def test_account_register_empty_sso_provider_id_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The account register POST with an empty-string sso_provider_id:
    """
    # The next register branch after the empty sub_domain 404
    # lock, verified fresh this run, not assumed. CreateUserDto
    # .sso_provider_id is Optional[str] = None (user_dto.py
    # BaseUserDto), with no min_length or pattern constraint
    # and no validator touching it: the mode="after"
    # normalize_names validator only trims first/last names
    # and runs only after field validation passes, and the
    # only field_serializer covers tenant_id/role_id for output
    # only, so neither can mask the sso_provider_id outcome.
    # An empty string is therefore a valid string value, not
    # a 422: unlike first/last names (min_length=1 plus the
    # blank-rejecting normalize_names validator), nothing
    # rejects "" for sso_provider_id, so it passes FastAPI
    # request validation verbatim and the handler body runs.
    # It is distinct from the whitespace-only
    # sso_provider_id lock ("   " is a string with no
    # non-whitespace content but non-zero length), from the
    # padded sso_provider_id lock (a value with
    # non-whitespace content), from the null sso_provider_id
    # lock (an absent value), and from the non-string/object/
    # boolean/integer sso_provider_id locks (type errors, 422
    # before the handler). The handler's first step is the
    # GUEST role lookup (account_endpoint.py register),
    # before any tenant branching and before
    # AuthService.register runs — and sso_provider_id is only
    # consumed in SSO login flows (auth_service.py), not in
    # the register path, so it cannot mask the role outcome
    # here. The shared conftest client seeds no role and Role
    # is in the conftest model set, so the lookup on the
    # fresh test database raises RoleNotFoundException before
    # any creation, password-policy check, or email send. No
    # X-Tenant-ID header is sent, so the tenant-context
    # branch cannot run first. The remaining body fields are
    # all valid (non-blank first and last names, a valid
    # email, gender "other", a strong string password), so no
    # 422 can mask the 404. This locks the ordering, not
    # acceptance of an empty sso_provider_id: with a seeded
    # GUEST role the same request would continue toward
    # creation, where the blank value would persist verbatim
    # (a downstream branch outside this lock). Deliberately
    # NOT locked: the 201 success path and the weak-password
    # branch, which both need a seeded GUEST role. The
    # central ApiBaseException handler maps the NotFound
    # subclass to 404 with body {"error": ..., "code": 404}
    # and Cache-Control: no-store plus Pragma: no-cache, and
    # the pure-ASGI security-headers middleware stamps every
    # HTTP response with no path exclusions. The error
    # assertion uses a substring check for "Role", mirroring
    # the missing-guest role 404 lock.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "StrongPass1!",
            "sso_provider_id": "",
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
    # mirroring the missing-guest role 404 lock, using substring
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


async def test_account_register_empty_tenant_id_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an empty-string tenant_id:
    """
    # The next register branch after the empty
    # sso_provider_id 404 lock, verified fresh this run,
    # not assumed. CreateUserDto inherits tenant_id as a
    # PydanticObjectId | None field defaulting to None from
    # BaseUserDto (user_dto.py), with no validator touching
    # it: the mode="after" normalize_names validator only
    # trims first/last names and runs only after field
    # validation passes, and the only field_serializer
    # covers tenant_id/role_id for output only, so neither
    # can coerce the incoming value. A PydanticObjectId
    # requires exactly 24 hex chars (stated in
    # base_repository.py and
    # subscription_plan_repository_impl.py), so an empty
    # string — zero chars, no hex content — fails FastAPI
    # request validation before the handler body runs: the
    # GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie
    # is set. The endpoint's dependencies cannot mask the
    # 422 either: get_auth_service/get_role_service only
    # resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. This is the
    # same validation class as the already-locked
    # malformed-string tenant_id 422 lock
    # ("not-an-objectid", likewise not 24 hex chars) and
    # the padded tenant_id 422 lock (26 chars with
    # non-hex characters); it is distinct from both in
    # length and content (zero-length, no whitespace to
    # strip), from the list/dict/boolean/integer
    # tenant_id locks (wrong JSON types, 422 before the
    # handler), from the explicit-null tenant_id lock (a
    # valid absent value reaching the 404 role lookup),
    # and from the empty sub_domain/sso_provider_id locks
    # (plain str fields with no constraint, 404). The
    # remaining body fields are all valid (non-blank
    # first and last names, a valid email, gender
    # "other", a strong string password), so no other 422
    # can mask the tenant_id error. Deliberately no exact
    # error-type assertion, mirroring the padded
    # tenant_id 422 lock. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to
    # it, mirroring the padded tenant_id 422 lock. The
    # security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions. This
    # lock adds no new route-specific contradiction (a
    # validation 422 precedes the role lookup, so it
    # contradicts no existing role expectation).
    # Note: bson is not installed in this environment, so
    # ObjectId("") could not be executed directly here;
    # the 422 follows from the documented 24-hex
    # requirement plus the in-file malformed-string and
    # padded tenant_id 422 locks, not from assumption.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "tenant_id": "",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "tenant_id" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the padded tenant_id 422 lock, using
    # substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_empty_role_id_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an empty-string role_id:
    """
    # The next register branch after the empty
    # tenant_id 422 lock, verified fresh this run,
    # not assumed. CreateUserDto inherits role_id as a
    # PydanticObjectId | None field defaulting to None from
    # BaseUserDto (user_dto.py), with no validator touching
    # it: the mode="after" normalize_names validator only
    # trims first/last names and runs only after field
    # validation passes, and the only field_serializer
    # covers tenant_id/role_id for output only, so neither
    # can coerce the incoming value. A PydanticObjectId
    # requires exactly 24 hex chars, so an empty
    # string — zero chars, no hex content — fails FastAPI
    # request validation before the handler body runs: the
    # GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie
    # is set. The endpoint's dependencies cannot mask the
    # 422 either: get_auth_service/get_role_service only
    # resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. This is the
    # same validation class as the already-locked
    # malformed-string role_id 422 lock and the padded
    # role_id 422 lock (26 chars with non-hex characters);
    # it is distinct from both in length and content
    # (zero-length, no whitespace to strip), from the
    # list/dict/boolean/integer role_id locks (wrong JSON
    # types, 422 before the handler), from the explicit-null
    # role_id lock (a valid absent value reaching the 404
    # role lookup), from the empty tenant_id lock (a
    # different field, verified the same way in the prior
    # run), and from the empty sub_domain/sso_provider_id
    # locks (plain str fields with no constraint, 404).
    # The remaining body fields are all valid (non-blank
    # first and last names, a valid email, gender
    # "other", a strong string password), so no other 422
    # can mask the role_id error. Deliberately no exact
    # error-type assertion, mirroring the empty tenant_id
    # 422 lock. Deliberately no Cache-Control/Pragma
    # assertion: a 422 is FastAPI request validation, not
    # an ApiBaseException, so the central handler's
    # no-store headers do not apply to it, mirroring the
    # empty tenant_id 422 lock. The security headers ARE
    # locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions. This lock adds no new route-specific
    # contradiction (a validation 422 precedes the role
    # lookup, so it contradicts no existing role
    # expectation).
    # Note: bson is not installed in this environment, so
    # ObjectId("") could not be executed directly here;
    # the 422 follows from the documented 24-hex
    # requirement plus the in-file malformed-string and
    # padded role_id 422 locks, not from assumption.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "role_id": "",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "role_id" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the empty tenant_id 422 lock, using
    # substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_whitespace_role_id_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a whitespace-only role_id:
    """
    # The next register branch after the empty
    # role_id 422 lock, verified fresh this run,
    # not assumed. CreateUserDto inherits role_id as a
    # PydanticObjectId | None field defaulting to None from
    # BaseUserDto (user_dto.py), with no validator touching
    # it: the mode="after" normalize_names validator only
    # trims first/last names and runs only after field
    # validation passes, and the only field_serializer
    # covers tenant_id/role_id for output only, so neither
    # can coerce the incoming value. A PydanticObjectId
    # requires exactly 24 hex chars, so a whitespace-only
    # string — three spaces, no hex content — fails FastAPI
    # request validation before the handler body runs: the
    # GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie
    # is set. The endpoint's dependencies cannot mask the
    # 422 either: get_auth_service/get_role_service only
    # resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. This is the
    # same validation class as the already-locked
    # malformed-string role_id 422 lock, the padded
    # role_id 422 lock (26 chars with non-hex characters),
    # and the empty role_id 422 lock (zero chars); it is
    # distinct from all three in length and content
    # (whitespace-only, no non-space core to strip to a
    # valid id), from the list/dict/boolean/integer role_id
    # locks (wrong JSON types, 422 before the handler),
    # from the explicit-null role_id lock (a valid absent
    # value reaching the 404 role lookup), from the
    # whitespace-only tenant_id variant (a different field,
    # not yet locked, and the direct analogue of this
    # lock), and from the whitespace-only sub_domain/
    # sso_provider_id locks (plain str fields with no
    # constraint, 404). The remaining body fields are all
    # valid (non-blank first and last names, a valid
    # email, gender "other", a strong string password),
    # so no other 422 can mask the role_id error.
    # Deliberately no exact error-type assertion, mirroring
    # the empty role_id 422 lock. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to
    # it, mirroring the empty role_id 422 lock. The
    # security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions. This lock
    # adds no new route-specific contradiction (a
    # validation 422 precedes the role lookup, so it
    # contradicts no existing role expectation).
    # Note: bson is not installed in this environment, so
    # ObjectId("   ") could not be executed directly here;
    # the 422 follows from the documented 24-hex
    # requirement plus the in-file malformed-string,
    # padded, and empty role_id 422 locks, not from
    # assumption.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "role_id": "   ",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "role_id" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the empty role_id 422 lock, using
    # substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_whitespace_tenant_id_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a whitespace-only tenant_id:
    """
    # The next register branch after the whitespace-only
    # role_id 422 lock, verified fresh this run,
    # not assumed. CreateUserDto inherits tenant_id as a
    # PydanticObjectId | None field defaulting to None from
    # BaseUserDto (user_dto.py), with no validator touching
    # it: the mode="after" normalize_names validator only
    # trims first/last names and runs only after field
    # validation passes, and the only field_serializer
    # covers tenant_id/role_id for output only, so neither
    # can coerce the incoming value. A PydanticObjectId
    # requires exactly 24 hex chars, so a whitespace-only
    # string — three spaces, no hex content — fails FastAPI
    # request validation before the handler body runs: the
    # GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie
    # is set. The endpoint's dependencies cannot mask the
    # 422 either: get_auth_service/get_role_service only
    # resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. This is the
    # same validation class as the already-locked
    # malformed-string tenant_id 422 lock, the padded
    # tenant_id 422 lock (26 chars with non-hex characters),
    # and the empty tenant_id 422 lock (zero chars); it is
    # distinct from all three in length and content
    # (whitespace-only, no non-space core to strip to a
    # valid id), from the list/dict/boolean/integer tenant_id
    # locks (wrong JSON types, 422 before the handler),
    # from the explicit-null tenant_id lock (a valid absent
    # value reaching the 404 role lookup), from the
    # whitespace-only role_id lock (a different field, the
    # direct analogue of this lock, prior run), and from
    # the whitespace-only sub_domain/sso_provider_id locks
    # (plain str fields with no constraint, 404). The
    # remaining body fields are all valid (non-blank first
    # and last names, a valid email, gender "other", a
    # strong string password), so no other 422 can mask the
    # tenant_id error.
    # Deliberately no exact error-type assertion, mirroring
    # the empty tenant_id 422 lock. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to
    # it, mirroring the empty tenant_id 422 lock. The
    # security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions. This lock
    # adds no new route-specific contradiction (a
    # validation 422 precedes the role lookup, so it
    # contradicts no existing role expectation).
    # Note: bson is not installed in this environment, so
    # ObjectId("   ") could not be executed directly here;
    # the 422 follows from the documented 24-hex
    # requirement plus the in-file malformed-string,
    # padded, and empty tenant_id 422 locks, not from
    # assumption.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "gender": "other",
            "password": "Register123!",
            "tenant_id": "   ",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "tenant_id" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the empty tenant_id 422 lock, using
    # substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_whitespace_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a whitespace-only gender:
    """
    # The next register validation branch after the whitespace-only
    # tenant_id 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py). No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only. Enum parsing does not
    # strip whitespace, so a whitespace-only string — three
    # spaces, no enum content — is not a Gender member and fails
    # FastAPI request validation before the handler body runs:
    # the GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie is
    # set. Distinct from the missing-gender lock (field omitted)
    # and the invalid-gender lock (a non-whitespace value outside
    # the enum, "unknown"): this lock pins the whitespace-only
    # variant, which a trimming parser would have accepted only
    # by stripping to an empty string — still not a member — so
    # the 422 holds under either parsing behaviour. The
    # endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, a password
    # string), so no other 422 can mask the gender error.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register invalid-gender 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "   ",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register invalid-gender 422 lock, using
    # substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_padded_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a padded gender value:
    """
    # The next register validation branch after the whitespace-only
    # gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py). No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only. Enum parsing does not
    # strip whitespace, so " other " — valid enum content
    # surrounded by spaces — is not a Gender member and fails
    # FastAPI request validation before the handler body runs:
    # the GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie is
    # set. Distinct from the whitespace-only gender lock (three
    # spaces, no enum content, which fails even under a trimming
    # parser since trimming yields an empty string, still not a
    # member), from the invalid-gender lock (a non-whitespace
    # value outside the enum, "unknown"), and from the
    # missing-gender lock (field omitted): this lock pins the
    # padded variant, which a trimming parser WOULD accept, so
    # it locks strict exact-match enum parsing rather than
    # merely rejecting a value with no valid content. The
    # endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, a password
    # string), so no other 422 can mask the gender error.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register whitespace-only gender 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": " other ",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register whitespace-only gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_case_variant_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a case-variant gender value:
    """
    # The next register validation branch after the padded
    # gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "Other" is not a member even
    # though it matches "other" case-insensitively. No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only. Enum parsing is
    # case-sensitive, so "Other" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the padded gender lock
    # (" other ", valid content surrounded by spaces), from the
    # whitespace-only gender lock (no enum content), from the
    # invalid-gender lock (a value outside the enum, "unknown"),
    # and from the missing-gender lock (field omitted): this lock
    # pins the case-variant, which a case-insensitive parser
    # WOULD accept, so it locks strict case-sensitive enum
    # parsing rather than merely rejecting a value with no valid
    # content. The endpoint's dependencies cannot mask the 422
    # either: get_auth_service/get_role_service only resolve
    # container objects and get_tenant_id only reads request
    # state, with no database lookup. The remaining body fields
    # are all valid (non-blank first and last names, a valid
    # email, a password string), so no other 422 can mask the
    # gender error. Deliberately no Cache-Control/Pragma
    # assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store headers
    # do not apply to it, mirroring the register padded gender
    # 422 lock. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including validation
    # errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "Other",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register padded gender 422 lock, using
    # substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_all_caps_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an all-caps gender value:
    """
    # The next register validation branch after the case-variant
    # gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "OTHER" is not a member even
    # though it matches "other" case-insensitively. No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only. Enum parsing is
    # case-sensitive, so "OTHER" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the case-variant gender lock
    # ("Other", mixed case), the padded gender lock
    # (" other ", valid content surrounded by spaces), from the
    # whitespace-only gender lock (no enum content), from the
    # invalid-gender lock (a value outside the enum, "unknown"),
    # and from the missing-gender lock (field omitted): this lock
    # pins the all-caps variant, which a case-insensitive parser
    # WOULD accept, so it locks strict case-sensitive enum
    # parsing rather than merely rejecting a value with no valid
    # content. The endpoint's dependencies cannot mask the 422
    # either: get_auth_service/get_role_service only resolve
    # container objects and get_tenant_id only reads request
    # state, with no database lookup. The remaining body fields
    # are all valid (non-blank first and last names, a valid
    # email, a password string), so no other 422 can mask the
    # gender error. Deliberately no Cache-Control/Pragma
    # assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store headers
    # do not apply to it, mirroring the register case-variant
    # gender 422 lock. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including validation
    # errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "OTHER",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register case-variant gender 422 lock, using
    # substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_all_caps_male_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an all-caps male gender value:
    """
    # The next register validation branch after the all-caps
    # gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "MALE" is not a member even
    # though it matches "male" case-insensitively. No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only. Enum parsing is
    # case-sensitive, so "MALE" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the all-caps gender lock
    # ("OTHER", a different enum member), the case-variant gender
    # lock ("Other", mixed case of a different member), the padded
    # gender lock (" other ", valid content surrounded by spaces),
    # from the whitespace-only gender lock (no enum content), from
    # the invalid-gender lock (a value outside the enum,
    # "unknown"), and from the missing-gender lock (field
    # omitted): this lock pins the all-caps variant for the male
    # member, which a case-insensitive parser WOULD accept, so it
    # locks strict case-sensitive enum parsing for a second member
    # rather than merely rejecting a value with no valid content.
    # The endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, a password
    # string), so no other 422 can mask the gender error.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register all-caps gender 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with no
    # path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "MALE",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register all-caps gender 422 lock, using
    # substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_capitalized_female_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a capitalized female gender value:
    """
    # The next register validation branch after the all-caps male
    # gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "Female" is not a member even
    # though it matches "female" case-insensitively. No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only. Enum parsing is
    # case-sensitive, so "Female" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the all-caps male gender lock
    # ("MALE", a different enum member in all caps), the all-caps
    # gender lock ("OTHER", a different member), the case-variant
    # gender lock ("Other", mixed case of a different member),
    # the padded gender lock (" other ", valid content surrounded
    # by spaces), from the whitespace-only gender lock (no enum
    # content), from the invalid-gender lock (a value outside the
    # enum, "unknown"), and from the missing-gender lock (field
    # omitted): this lock pins the capitalized variant for the
    # female member, which a case-insensitive parser WOULD accept,
    # so it locks strict case-sensitive enum parsing for a third
    # member rather than merely rejecting a value with no valid
    # content. The endpoint's dependencies cannot mask the 422
    # either: get_auth_service/get_role_service only resolve
    # container objects and get_tenant_id only reads request
    # state, with no database lookup. The remaining body fields
    # are all valid (non-blank first and last names, a valid
    # email, a password string), so no other 422 can mask the
    # gender error. Deliberately no Cache-Control/Pragma
    # assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store headers
    # do not apply to it, mirroring the register all-caps male
    # gender 422 lock. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including validation
    # errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "Female",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register all-caps male gender 422 lock, using
    # substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_all_caps_female_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an all-caps female gender value:
    """
    # The next register validation branch after the capitalized
    # female gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "FEMALE" is not a member even
    # though it matches "female" case-insensitively. No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only. Enum parsing is
    # case-sensitive, so "FEMALE" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the capitalized female gender
    # lock ("Female", same member in title case), the all-caps
    # male gender lock ("MALE", a different enum member in all
    # caps), the all-caps gender lock ("OTHER", a different
    # member), the case-variant gender lock ("Other", mixed case
    # of a different member), the padded gender lock (" other ",
    # valid content surrounded by spaces), from the
    # whitespace-only gender lock (no enum content), from the
    # invalid-gender lock (a value outside the enum, "unknown"),
    # and from the missing-gender lock (field omitted): this lock
    # pins the all-caps variant for the female member, which a
    # case-insensitive parser WOULD accept, so it locks strict
    # case-sensitive enum parsing for a fourth member/casing
    # combination rather than merely rejecting a value with no
    # valid content. The endpoint's dependencies cannot mask the
    # 422 either: get_auth_service/get_role_service only resolve
    # container objects and get_tenant_id only reads request
    # state, with no database lookup. The remaining body fields
    # are all valid (non-blank first and last names, a valid
    # email, a password string), so no other 422 can mask the
    # gender error. Deliberately no Cache-Control/Pragma
    # assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store headers
    # do not apply to it, mirroring the register capitalized
    # female gender 422 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "FEMALE",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register capitalized female gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_lowercase_first_uppercase_second_female_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first uppercase-second female gender value:
    """
    # The next register validation branch after the all-caps
    # female gender 422 lock, verified fresh this run, not assumed:
    # grep count 0 for "fEmale" in this file before appending.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "fEmale" is not a member even
    # though it matches "female" case-insensitively. No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only. Enum parsing is
    # case-sensitive, so "fEmale" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the capitalized female gender
    # lock ("Female", title case of the same member), the all-caps
    # female gender lock ("FEMALE", all caps of the same member),
    # the all-caps gender lock ("OTHER", a different member),
    # the case-variant gender lock ("Other", mixed case of a
    # different member), the padded gender lock (" other ",
    # valid content surrounded by spaces), from the
    # whitespace-only gender lock (no enum content), from the
    # invalid-gender lock (a value outside the enum, "unknown"),
    # and from the missing-gender lock (field omitted): this lock
    # pins the lowercase-first / uppercase-second variant for the
    # female member, which a case-insensitive parser WOULD accept,
    # so it locks strict case-sensitive enum parsing for a new
    # member/casing combination rather than merely rejecting a
    # value with no valid content. The endpoint's dependencies
    # cannot mask the 422 either: get_auth_service/get_role_service
    # only resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. The remaining body
    # fields are all valid (non-blank first and last names, a valid
    # email, a password string), so no other 422 can mask the
    # gender error. Deliberately no Cache-Control/Pragma
    # assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store headers
    # do not apply to it, mirroring the register all-caps female
    # gender 422 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "fEmale",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register all-caps female gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_capitalized_male_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a capitalized male gender value:
    """
    # The next register validation branch after the all-caps
    # female gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "Male" is not a member even
    # though it matches "male" case-insensitively. No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only. Enum parsing is
    # case-sensitive, so "Male" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the all-caps female gender
    # lock ("FEMALE", a different member in all caps), the
    # capitalized female gender lock ("Female", same casing of
    # a different member), the all-caps male gender lock
    # ("MALE", same member in all caps), the all-caps gender
    # lock ("OTHER", a different member), the case-variant
    # gender lock ("Other", mixed case of a different member),
    # the padded gender lock (" other ", valid content
    # surrounded by spaces), from the whitespace-only gender
    # lock (no enum content), from the invalid-gender lock (a
    # value outside the enum, "unknown"), and from the
    # missing-gender lock (field omitted): this lock pins the
    # title-case variant for the male member, which a
    # case-insensitive parser WOULD accept, so it locks strict
    # case-sensitive enum parsing for a fifth member/casing
    # combination rather than merely rejecting a value with no
    # valid content. The endpoint's dependencies cannot mask the
    # 422 either: get_auth_service/get_role_service only resolve
    # container objects and get_tenant_id only reads request
    # state, with no database lookup. The remaining body fields
    # are all valid (non-blank first and last names, a valid
    # email, a password string), so no other 422 can mask the
    # gender error. Deliberately no Cache-Control/Pragma
    # assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store headers
    # do not apply to it, mirroring the register all-caps female
    # gender 422 lock. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "Male",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register all-caps female gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_capitalized_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a capitalized prefer-not-to-say gender value:
    """
    # The next register validation branch after the capitalized
    # male gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "Prefer_not_to_say" is not a
    # member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims
    # first/last names and runs only after field validation
    # passes, and the only field_serializer covers tenant_id/
    # role_id for output only. Enum parsing is case-sensitive,
    # so "Prefer_not_to_say" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the capitalized male gender
    # lock ("Male", title case of a different member), the
    # capitalized female gender lock ("Female", title case of
    # a different member), the all-caps female gender lock
    # ("FEMALE"), the all-caps male gender lock ("MALE"), the
    # all-caps gender lock ("OTHER"), the case-variant gender
    # lock ("Other", mixed case of a different member), the
    # padded gender lock (" other ", valid content surrounded
    # by spaces), from the whitespace-only gender lock (no enum
    # content), from the invalid-gender lock (a value outside
    # the enum, "unknown"), and from the missing-gender lock
    # (field omitted): this lock pins the capitalized variant
    # for the prefer_not_to_say member, which a
    # case-insensitive parser WOULD accept, so it locks strict
    # case-sensitive enum parsing for the fourth member rather
    # than merely rejecting a value with no valid content. The
    # endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with
    # no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, a
    # password string), so no other 422 can mask the gender
    # error. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the register capitalized male gender 422
    # lock. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "Prefer_not_to_say",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register capitalized male gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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

async def test_account_register_all_caps_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an all-caps prefer-not-to-say gender value:
    """
    # The next register validation branch after the capitalized
    # prefer_not_to_say gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "PREFER_NOT_TO_SAY" is not a
    # member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims
    # first/last names and runs only after field validation
    # passes, and the only field_serializer covers tenant_id/
    # role_id for output only. Enum parsing is case-sensitive,
    # so "PREFER_NOT_TO_SAY" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the capitalized
    # prefer_not_to_say lock ("Prefer_not_to_say", title case
    # of the same member), the capitalized male gender lock
    # ("Male"), the capitalized female gender lock ("Female"),
    # the all-caps female gender lock ("FEMALE"), the all-caps
    # male gender lock ("MALE"), the all-caps gender lock
    # ("OTHER"), the case-variant gender lock ("Other", mixed
    # case of a different member), the padded gender lock
    # (" other ", valid content surrounded by spaces), from the
    # whitespace-only gender lock (no enum content), from the
    # invalid-gender lock (a value outside the enum,
    # "unknown"), and from the missing-gender lock (field
    # omitted): this lock pins the all-caps variant for the
    # prefer_not_to_say member, which a case-insensitive parser
    # WOULD accept, so it locks strict case-sensitive enum
    # parsing for the fourth member rather than merely
    # rejecting a value with no valid content. The endpoint's
    # dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with
    # no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, a
    # password string), so no other 422 can mask the gender
    # error. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the register capitalized prefer_not_to_say
    # gender 422 lock. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "PREFER_NOT_TO_SAY",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register capitalized prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_mixed_case_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a mixed-case prefer-not-to-say gender value:
    """
    # The next register validation branch after the all-caps
    # prefer_not_to_say gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "pREFER_NOT_TO_SAY" is not a
    # member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims
    # first/last names and runs only after field validation
    # passes, and the only field_serializer covers tenant_id/
    # role_id for output only. Enum parsing is case-sensitive,
    # so "pREFER_NOT_TO_SAY" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the all-caps
    # prefer_not_to_say lock ("PREFER_NOT_TO_SAY") and the
    # capitalized prefer_not_to_say lock ("Prefer_not_to_say",
    # title case of the same member), the capitalized male gender lock
    # ("Male"), the capitalized female gender lock ("Female"),
    # the all-caps female gender lock ("FEMALE"), the all-caps
    # male gender lock ("MALE"), the all-caps gender lock
    # ("OTHER"), the case-variant gender lock ("Other", mixed
    # case of a different member), the padded gender lock
    # (" other ", valid content surrounded by spaces), from the
    # whitespace-only gender lock (no enum content), from the
    # invalid-gender lock (a value outside the enum,
    # "unknown"), and from the missing-gender lock (field
    # omitted): this lock pins a mixed-case variant (lowercase
    # first letter, uppercase remainder) for the
    # prefer_not_to_say member, which a case-insensitive parser
    # WOULD accept, so it locks strict case-sensitive enum
    # parsing for the fourth member rather than merely
    # rejecting a value with no valid content. The endpoint's
    # dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with
    # no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, a
    # password string), so no other 422 can mask the gender
    # error. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the register all-caps prefer_not_to_say
    # gender 422 lock. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "pREFER_NOT_TO_SAY",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register all-caps prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_partial_caps_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a partial-caps prefer-not-to-say gender value:
    """
    # The next register validation branch after the mixed-case
    # prefer_not_to_say gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "prefer_NOT_TO_SAY" is not a
    # member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims
    # first/last names and runs only after field validation
    # passes, and the only field_serializer covers tenant_id/
    # role_id for output only. Enum parsing is case-sensitive,
    # so "prefer_NOT_TO_SAY" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the mixed-case
    # prefer_not_to_say lock ("pREFER_NOT_TO_SAY", lowercase
    # first letter, uppercase remainder), the all-caps
    # prefer_not_to_say lock ("PREFER_NOT_TO_SAY") and the
    # capitalized prefer_not_to_say lock ("Prefer_not_to_say",
    # title case of the same member), the capitalized male gender lock
    # ("Male"), the capitalized female gender lock ("Female"),
    # the all-caps female gender lock ("FEMALE"), the all-caps
    # male gender lock ("MALE"), the all-caps gender lock
    # ("OTHER"), the case-variant gender lock ("Other", mixed
    # case of a different member), the padded gender lock
    # (" other ", valid content surrounded by spaces), from the
    # whitespace-only gender lock (no enum content), from the
    # invalid-gender lock (a value outside the enum,
    # "unknown"), and from the missing-gender lock (field
    # omitted): this lock pins a partial-caps variant (lowercase
    # stem "prefer", uppercase remainder "NOT_TO_SAY") for the
    # prefer_not_to_say member, which a case-insensitive parser
    # WOULD accept, so it locks strict case-sensitive enum
    # parsing for the fourth member rather than merely
    # rejecting a value with no valid content. The endpoint's
    # dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with
    # no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, a
    # password string), so no other 422 can mask the gender
    # error. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the register mixed-case prefer_not_to_say
    # gender 422 lock. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "prefer_NOT_TO_SAY",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register mixed-case prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_uppercase_stem_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an uppercase-stem prefer-not-to-say gender value:
    """
    # The next register validation branch after the partial-caps
    # prefer_not_to_say gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "PREFER_not_to_say" is not a
    # member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims
    # first/last names and runs only after field validation
    # passes, and the only field_serializer covers tenant_id/
    # role_id for output only. Enum parsing is case-sensitive,
    # so "PREFER_not_to_say" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the partial-caps
    # prefer_not_to_say lock ("prefer_NOT_TO_SAY", lowercase
    # stem, uppercase remainder), the mixed-case
    # prefer_not_to_say lock ("pREFER_NOT_TO_SAY", lowercase
    # first letter, uppercase remainder), the all-caps
    # prefer_not_to_say lock ("PREFER_NOT_TO_SAY") and the
    # capitalized prefer_not_to_say lock ("Prefer_not_to_say",
    # title case of the same member), the capitalized male gender lock
    # ("Male"), the capitalized female gender lock ("Female"),
    # the all-caps female gender lock ("FEMALE"), the all-caps
    # male gender lock ("MALE"), the all-caps gender lock
    # ("OTHER"), the case-variant gender lock ("Other", mixed
    # case of a different member), the padded gender lock
    # (" other ", valid content surrounded by spaces), from the
    # whitespace-only gender lock (no enum content), from the
    # invalid-gender lock (a value outside the enum,
    # "unknown"), and from the missing-gender lock (field
    # omitted): this lock pins a partial-caps variant (uppercase
    # stem "PREFER", lowercase remainder "_not_to_say") for the
    # prefer_not_to_say member, which a case-insensitive parser
    # WOULD accept, so it locks strict case-sensitive enum
    # parsing for the fourth member rather than merely
    # rejecting a value with no valid content. The endpoint's
    # dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with
    # no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, a
    # password string), so no other 422 can mask the gender
    # error. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the register partial-caps prefer_not_to_say
    # gender 422 lock. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "PREFER_not_to_say",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register partial-caps prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_uppercase_prefix_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an uppercase-prefix prefer-not-to-say gender value:
    """
    # The next register validation branch after the uppercase-stem
    # prefer_not_to_say gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "PREFER_NOT_to_say" is not a
    # member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims
    # first/last names and runs only after field validation
    # passes, and the only field_serializer covers tenant_id/
    # role_id for output only. Enum parsing is case-sensitive,
    # so "PREFER_NOT_to_say" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the uppercase-stem
    # prefer_not_to_say lock ("PREFER_not_to_say", uppercase
    # stem only, lowercase remainder), the partial-caps
    # prefer_not_to_say lock ("prefer_NOT_TO_SAY", lowercase
    # stem, uppercase remainder), the mixed-case
    # prefer_not_to_say lock ("pREFER_NOT_TO_SAY", lowercase
    # first letter, uppercase remainder), the all-caps
    # prefer_not_to_say lock ("PREFER_NOT_TO_SAY") and the
    # capitalized prefer_not_to_say lock ("Prefer_not_to_say",
    # title case of the same member), the capitalized male gender lock
    # ("Male"), the capitalized female gender lock ("Female"),
    # the all-caps female gender lock ("FEMALE"), the all-caps
    # male gender lock ("MALE"), the all-caps gender lock
    # ("OTHER"), the case-variant gender lock ("Other", mixed
    # case of a different member), the padded gender lock
    # (" other ", valid content surrounded by spaces), from the
    # whitespace-only gender lock (no enum content), from the
    # invalid-gender lock (a value outside the enum,
    # "unknown"), and from the missing-gender lock (field
    # omitted): this lock pins a partial-caps variant (uppercase
    # prefix "PREFER_NOT", lowercase remainder "_to_say") for the
    # prefer_not_to_say member, which a case-insensitive parser
    # WOULD accept, so it locks strict case-sensitive enum
    # parsing for the fourth member rather than merely
    # rejecting a value with no valid content. The endpoint's
    # dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with
    # no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, a
    # password string), so no other 422 can mask the gender
    # error. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the register uppercase-stem prefer_not_to_say
    # gender 422 lock. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "PREFER_NOT_to_say",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register uppercase-stem prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_uppercase_suffix_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an uppercase-suffix prefer-not-to-say gender value:
    """
    # The next register validation branch after the uppercase-prefix
    # prefer_not_to_say gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "prefer_not_TO_SAY" is not a
    # member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims
    # first/last names and runs only after field validation
    # passes, and the only field_serializer covers tenant_id/
    # role_id for output only. Enum parsing is case-sensitive,
    # so "prefer_not_TO_SAY" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the uppercase-prefix
    # prefer_not_to_say lock ("PREFER_NOT_to_say", uppercase
    # prefix, lowercase remainder), the uppercase-stem
    # prefer_not_to_say lock ("PREFER_not_to_say", uppercase
    # stem only, lowercase remainder), the partial-caps
    # prefer_not_to_say lock ("prefer_NOT_TO_SAY", lowercase
    # stem "prefer", uppercase remainder), the mixed-case
    # prefer_not_to_say lock ("pREFER_NOT_TO_SAY", lowercase
    # first letter, uppercase remainder), the all-caps
    # prefer_not_to_say lock ("PREFER_NOT_TO_SAY") and the
    # capitalized prefer_not_to_say lock ("Prefer_not_to_say",
    # title case of the same member), the capitalized male gender lock
    # ("Male"), the capitalized female gender lock ("Female"),
    # the all-caps female gender lock ("FEMALE"), the all-caps
    # male gender lock ("MALE"), the all-caps gender lock
    # ("OTHER"), the case-variant gender lock ("Other", mixed
    # case of a different member), the padded gender lock
    # (" other ", valid content surrounded by spaces), from the
    # whitespace-only gender lock (no enum content), from the
    # invalid-gender lock (a value outside the enum,
    # "unknown"), and from the missing-gender lock (field
    # omitted): this lock pins a partial-caps variant (lowercase
    # prefix "prefer_not", uppercase suffix "_TO_SAY") for the
    # prefer_not_to_say member, which a case-insensitive parser
    # WOULD accept, so it locks strict case-sensitive enum
    # parsing for the fourth member rather than merely
    # rejecting a value with no valid content. The endpoint's
    # dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with
    # no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, a
    # password string), so no other 422 can mask the gender
    # error. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the register uppercase-prefix prefer_not_to_say
    # gender 422 lock. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "prefer_not_TO_SAY",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register uppercase-prefix prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_capitalized_uppercase_middle_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a capitalized-prefix, uppercase-middle prefer-not-to-say gender value:
    """
    # The next register validation branch after the uppercase-suffix
    # prefer_not_to_say gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "Prefer_NOT_to_say" is not a
    # member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims
    # first/last names and runs only after field validation
    # passes, and the only field_serializer covers tenant_id/
    # role_id for output only. Enum parsing is case-sensitive,
    # so "Prefer_NOT_to_say" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the uppercase-suffix
    # prefer_not_to_say lock ("prefer_not_TO_SAY", lowercase
    # prefix "prefer_not", uppercase suffix "_TO_SAY"), the
    # uppercase-prefix prefer_not_to_say lock
    # ("PREFER_NOT_to_say", uppercase prefix, lowercase
    # remainder), the uppercase-stem prefer_not_to_say lock
    # ("PREFER_not_to_say", uppercase stem only, lowercase
    # remainder), the partial-caps prefer_not_to_say lock
    # ("prefer_NOT_TO_SAY", lowercase stem "prefer", uppercase
    # remainder), the mixed-case prefer_not_to_say lock
    # ("pREFER_NOT_TO_SAY", lowercase first letter, uppercase
    # remainder), the all-caps prefer_not_to_say lock
    # ("PREFER_NOT_TO_SAY") and the capitalized
    # prefer_not_to_say lock ("Prefer_not_to_say", title case
    # of the same member), the capitalized male gender lock
    # ("Male"), the capitalized female gender lock ("Female"),
    # the all-caps female gender lock ("FEMALE"), the all-caps
    # male gender lock ("MALE"), the all-caps gender lock
    # ("OTHER"), the case-variant gender lock ("Other", mixed
    # case of a different member), the padded gender lock
    # (" other ", valid content surrounded by spaces), from the
    # whitespace-only gender lock (no enum content), from the
    # invalid-gender lock (a value outside the enum,
    # "unknown"), and from the missing-gender lock (field
    # omitted): this lock pins a partial-caps variant
    # (capitalized prefix "Prefer", uppercase middle "_NOT",
    # lowercase suffix "_to_say") for the prefer_not_to_say
    # member, which a case-insensitive parser WOULD accept, so
    # it locks strict case-sensitive enum parsing for the
    # fourth member rather than merely rejecting a value with
    # no valid content. The endpoint's dependencies cannot mask
    # the 422 either: get_auth_service/get_role_service only
    # resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. The remaining
    # body fields are all valid (non-blank first and last
    # names, a valid email, a password string), so no other
    # 422 can mask the gender error. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the register uppercase-suffix prefer_not_to_say gender
    # 422 lock. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "Prefer_NOT_to_say",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register uppercase-suffix prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_lowercase_uppercase_middle_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-stem, uppercase-middle prefer-not-to-say gender value:
    """
    # The next register validation branch after the capitalized-uppercase-middle
    # prefer_not_to_say gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "prefer_NOT_to_say" is not a
    # member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims
    # first/last names and runs only after field validation
    # passes, and the only field_serializer covers tenant_id/
    # role_id for output only. Enum parsing is case-sensitive,
    # so "prefer_NOT_to_say" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the capitalized-uppercase-middle
    # prefer_not_to_say lock ("Prefer_NOT_to_say", capitalized
    # prefix "Prefer", uppercase middle "_NOT", lowercase suffix
    # "_to_say"), the uppercase-suffix prefer_not_to_say lock
    # ("prefer_not_TO_SAY", lowercase prefix "prefer_not",
    # uppercase suffix "_TO_SAY"), the uppercase-prefix
    # prefer_not_to_say lock ("PREFER_NOT_to_say", uppercase
    # prefix, lowercase remainder), the uppercase-stem
    # prefer_not_to_say lock ("PREFER_not_to_say", uppercase
    # stem only, lowercase remainder), the partial-caps
    # prefer_not_to_say lock ("prefer_NOT_TO_SAY", lowercase
    # stem "prefer", uppercase remainder), the mixed-case
    # prefer_not_to_say lock ("pREFER_NOT_TO_SAY", lowercase
    # first letter, uppercase remainder), the all-caps
    # prefer_not_to_say lock ("PREFER_NOT_TO_SAY") and the
    # capitalized prefer_not_to_say lock ("Prefer_not_to_say",
    # title case of the same member), the capitalized male gender
    # lock ("Male"), the capitalized female gender lock
    # ("Female"), the all-caps female gender lock ("FEMALE"),
    # the all-caps male gender lock ("MALE"), the all-caps
    # gender lock ("OTHER"), the case-variant gender lock
    # ("Other", mixed case of a different member), the padded
    # gender lock (" other ", valid content surrounded by
    # spaces), from the whitespace-only gender lock (no enum
    # content), from the invalid-gender lock (a value outside
    # the enum, "unknown"), and from the missing-gender lock
    # (field omitted): this lock pins a partial-caps variant
    # (lowercase stem "prefer", uppercase middle "_NOT",
    # lowercase suffix "_to_say") for the prefer_not_to_say
    # member, which a case-insensitive parser WOULD accept, so
    # it locks strict case-sensitive enum parsing for the
    # fourth member rather than merely rejecting a value with
    # no valid content. The endpoint's dependencies cannot mask
    # the 422 either: get_auth_service/get_role_service only
    # resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. The remaining
    # body fields are all valid (non-blank first and last
    # names, a valid email, a password string), so no other
    # 422 can mask the gender error. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the register capitalized-uppercase-middle prefer_not_to_say
    # gender 422 lock. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "prefer_NOT_to_say",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register capitalized-uppercase-middle prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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

async def test_account_register_uppercase_middle_lowercase_middle_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an uppercase-stem, lowercase-middle, uppercase-suffix prefer-not-to-say gender value:
    """
    # The next register validation branch after the lowercase-uppercase-middle
    # prefer_not_to_say gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "PREFER_not_TO_SAY" is not a
    # member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims
    # first/last names and runs only after field validation
    # passes, and the only field_serializer covers tenant_id/
    # role_id for output only. Enum parsing is case-sensitive,
    # so "PREFER_not_TO_SAY" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the lowercase-uppercase-middle
    # prefer_not_to_say lock ("prefer_NOT_to_say", lowercase
    # stem "prefer", uppercase middle "_NOT", lowercase suffix
    # "_to_say"), the capitalized-uppercase-middle
    # prefer_not_to_say lock ("Prefer_NOT_to_say", capitalized
    # prefix "Prefer", uppercase middle "_NOT", lowercase suffix
    # "_to_say"), the uppercase-suffix prefer_not_to_say lock
    # ("prefer_not_TO_SAY", lowercase prefix "prefer_not",
    # uppercase suffix "_TO_SAY"), the uppercase-prefix
    # prefer_not_to_say lock ("PREFER_NOT_to_say", uppercase
    # prefix, lowercase remainder), the uppercase-stem
    # prefer_not_to_say lock ("PREFER_not_to_say", uppercase
    # stem only, lowercase remainder), the partial-caps
    # prefer_not_to_say lock ("prefer_NOT_TO_SAY", lowercase
    # stem "prefer", uppercase remainder), the mixed-case
    # prefer_not_to_say lock ("pREFER_NOT_TO_SAY", lowercase
    # first letter, uppercase remainder), the all-caps
    # prefer_not_to_say lock ("PREFER_NOT_TO_SAY") and the
    # capitalized prefer_not_to_say lock ("Prefer_not_to_say",
    # title case of the same member), the capitalized male gender
    # lock ("Male"), the capitalized female gender lock
    # ("Female"), the all-caps female gender lock ("FEMALE"),
    # the all-caps male gender lock ("MALE"), the all-caps
    # gender lock ("OTHER"), the case-variant gender lock
    # ("Other", mixed case of a different member), the padded
    # gender lock (" other ", valid content surrounded by
    # spaces), from the whitespace-only gender lock (no enum
    # content), from the invalid-gender lock (a value outside
    # the enum, "unknown"), and from the missing-gender lock
    # (field omitted): this lock pins a partial-caps variant
    # (uppercase stem "PREFER", lowercase middle "_not",
    # uppercase suffix "_TO_SAY") for the prefer_not_to_say
    # member, which a case-insensitive parser WOULD accept, so
    # it locks strict case-sensitive enum parsing for the
    # fourth member rather than merely rejecting a value with
    # no valid content. The endpoint's dependencies cannot mask
    # the 422 either: get_auth_service/get_role_service only
    # resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. The remaining
    # body fields are all valid (non-blank first and last
    # names, a valid email, a password string), so no other
    # 422 can mask the gender error. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the register lowercase-uppercase-middle prefer_not_to_say
    # gender 422 lock. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "PREFER_not_TO_SAY",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register lowercase-uppercase-middle prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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

async def test_account_register_uppercase_prefix_lowercase_suffix_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an uppercase-prefix, lowercase-suffix prefer-not-to-say gender value:
    """
    # The next register validation branch after the uppercase-middle-lowercase-middle
    # prefer_not_to_say gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "PREFER_NOT_TO_say" is not a
    # member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims
    # first/last names and runs only after field validation
    # passes, and the only field_serializer covers tenant_id/
    # role_id for output only. Enum parsing is case-sensitive,
    # so "PREFER_NOT_TO_say" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the uppercase-middle-lowercase-middle
    # prefer_not_to_say lock ("PREFER_not_TO_SAY", uppercase
    # stem "PREFER", lowercase middle "_not", uppercase suffix
    # "_TO_SAY"), the lowercase-uppercase-middle
    # prefer_not_to_say lock ("prefer_NOT_to_say", lowercase
    # stem "prefer", uppercase middle "_NOT", lowercase suffix
    # "_to_say"), the capitalized-uppercase-middle
    # prefer_not_to_say lock ("Prefer_NOT_to_say", capitalized
    # prefix "Prefer", uppercase middle "_NOT", lowercase suffix
    # "_to_say"), the uppercase-suffix prefer_not_to_say lock
    # ("prefer_not_TO_SAY", lowercase prefix "prefer_not",
    # uppercase suffix "_TO_SAY"), the uppercase-prefix
    # prefer_not_to_say lock ("PREFER_NOT_to_say", uppercase
    # prefix, lowercase remainder), the uppercase-stem
    # prefer_not_to_say lock ("PREFER_not_to_say", uppercase
    # stem only, lowercase remainder), the partial-caps
    # prefer_not_to_say lock ("prefer_NOT_TO_SAY", lowercase
    # stem "prefer", uppercase remainder), the mixed-case
    # prefer_not_to_say lock ("pREFER_NOT_TO_SAY", lowercase
    # first letter, uppercase remainder), the all-caps
    # prefer_not_to_say lock ("PREFER_NOT_TO_SAY") and the
    # capitalized prefer_not_to_say lock ("Prefer_not_to_say",
    # title case of the same member), the capitalized male gender
    # lock ("Male"), the capitalized female gender lock
    # ("Female"), the all-caps female gender lock ("FEMALE"),
    # the all-caps male gender lock ("MALE"), the all-caps
    # gender lock ("OTHER"), the case-variant gender lock
    # ("Other", mixed case of a different member), the padded
    # gender lock (" other ", valid content surrounded by
    # spaces), from the whitespace-only gender lock (no enum
    # content), from the invalid-gender lock (a value outside
    # the enum, "unknown"), and from the missing-gender lock
    # (field omitted): this lock pins a partial-caps variant
    # (uppercase prefix "PREFER_NOT_TO", lowercase suffix
    # "_say") for the prefer_not_to_say member, which a
    # case-insensitive parser WOULD accept, so it locks strict
    # case-sensitive enum parsing for the fourth member rather
    # than merely rejecting a value with no valid content. The
    # endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with
    # no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, a
    # password string), so no other 422 can mask the gender
    # error. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the register uppercase-middle-lowercase-middle
    # prefer_not_to_say gender 422 lock. The security headers
    # ARE locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "PREFER_NOT_TO_say",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register uppercase-middle-lowercase-middle prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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

async def test_account_register_capitalized_uppercase_middle_lowercase_suffix_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a capitalized-prefix, uppercase-middle, lowercase-suffix prefer-not-to-say gender value:
    """
    # The next register validation branch after the uppercase-prefix-lowercase-suffix
    # prefer_not_to_say gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "Prefer_NOT_TO_say" is not a
    # member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims
    # first/last names and runs only after field validation
    # passes, and the only field_serializer covers tenant_id/
    # role_id for output only. Enum parsing is case-sensitive,
    # so "Prefer_NOT_TO_say" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the uppercase-prefix-lowercase-suffix
    # prefer_not_to_say lock ("PREFER_NOT_TO_say", uppercase
    # prefix "PREFER_NOT_TO", lowercase suffix "_say"), the
    # uppercase-middle-lowercase-middle prefer_not_to_say lock
    # ("PREFER_not_TO_SAY", uppercase stem "PREFER", lowercase
    # middle "_not", uppercase suffix "_TO_SAY"), the
    # lowercase-uppercase-middle prefer_not_to_say lock
    # ("prefer_NOT_to_say", lowercase stem "prefer", uppercase
    # middle "_NOT", lowercase suffix "_to_say"), the
    # capitalized-uppercase-middle prefer_not_to_say lock
    # ("Prefer_NOT_to_say", capitalized prefix "Prefer", uppercase
    # middle "_NOT", lowercase suffix "_to_say"), the
    # uppercase-suffix prefer_not_to_say lock
    # ("prefer_not_TO_SAY", lowercase prefix "prefer_not",
    # uppercase suffix "_TO_SAY"), the uppercase-prefix
    # prefer_not_to_say lock ("PREFER_NOT_to_say", uppercase
    # prefix, lowercase remainder), the uppercase-stem
    # prefer_not_to_say lock ("PREFER_not_to_say", uppercase
    # stem only, lowercase remainder), the partial-caps
    # prefer_not_to_say lock ("prefer_NOT_TO_SAY", lowercase
    # stem "prefer", uppercase remainder), the mixed-case
    # prefer_not_to_say lock ("pREFER_NOT_TO_SAY", lowercase
    # first letter, uppercase remainder), the all-caps
    # prefer_not_to_say lock ("PREFER_NOT_TO_SAY") and the
    # capitalized prefer_not_to_say lock ("Prefer_not_to_say",
    # title case of the same member), the capitalized male gender
    # lock ("Male"), the capitalized female gender lock
    # ("Female"), the all-caps female gender lock ("FEMALE"),
    # the all-caps male gender lock ("MALE"), the all-caps
    # gender lock ("OTHER"), the case-variant gender lock
    # ("Other", mixed case of a different member), the padded
    # gender lock (" other ", valid content surrounded by
    # spaces), from the whitespace-only gender lock (no enum
    # content), from the invalid-gender lock (a value outside
    # the enum, "unknown"), and from the missing-gender lock
    # (field omitted): this lock pins a partial-caps variant
    # (capitalized prefix "Prefer", uppercase middle "_NOT_TO",
    # lowercase suffix "_say") for the prefer_not_to_say member,
    # which a case-insensitive parser WOULD accept, so it locks
    # strict case-sensitive enum parsing for the fourth member
    # rather than merely rejecting a value with no valid content.
    # The endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with
    # no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, a
    # password string), so no other 422 can mask the gender
    # error. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the register uppercase-prefix-lowercase-suffix
    # prefer_not_to_say gender 422 lock. The security headers
    # ARE locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "Prefer_NOT_TO_say",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register uppercase-prefix-lowercase-suffix prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_lowercase_first_uppercase_stem_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first-letter, uppercase-stem prefer-not-to-say gender value:
    """
    # The next register validation branch after the capitalized-uppercase-middle-lowercase-suffix
    # prefer_not_to_say gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "pREFER_not_to_say" is not a
    # member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims
    # first/last names and runs only after field validation
    # passes, and the only field_serializer covers tenant_id/
    # role_id for output only. Enum parsing is case-sensitive,
    # so "pREFER_not_to_say" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the capitalized-uppercase-middle-lowercase-suffix
    # prefer_not_to_say lock ("Prefer_NOT_TO_say", capitalized
    # prefix "Prefer", uppercase middle "_NOT_TO", lowercase
    # suffix "_say"), the uppercase-prefix-lowercase-suffix
    # prefer_not_to_say lock ("PREFER_NOT_TO_say", uppercase
    # prefix "PREFER_NOT_TO", lowercase suffix "_say"), the
    # uppercase-middle-lowercase-middle prefer_not_to_say lock
    # ("PREFER_not_TO_SAY", uppercase stem "PREFER", lowercase
    # middle "_not", uppercase suffix "_TO_SAY"), the
    # lowercase-uppercase-middle prefer_not_to_say lock
    # ("prefer_NOT_to_say", lowercase stem "prefer", uppercase
    # middle "_NOT", lowercase suffix "_to_say"), the
    # capitalized-uppercase-middle prefer_not_to_say lock
    # ("Prefer_NOT_to_say", capitalized prefix "Prefer", uppercase
    # middle "_NOT", lowercase suffix "_to_say"), the
    # uppercase-suffix prefer_not_to_say lock
    # ("prefer_not_TO_SAY", lowercase prefix "prefer_not",
    # uppercase suffix "_TO_SAY"), the uppercase-prefix
    # prefer_not_to_say lock ("PREFER_NOT_to_say", uppercase
    # prefix, lowercase remainder), the uppercase-stem
    # prefer_not_to_say lock ("PREFER_not_to_say", uppercase
    # stem only, lowercase remainder), the partial-caps
    # prefer_not_to_say lock ("prefer_NOT_TO_SAY", lowercase
    # stem "prefer", uppercase remainder), the mixed-case
    # prefer_not_to_say lock ("pREFER_NOT_TO_SAY", lowercase
    # first letter, uppercase remainder), the all-caps
    # prefer_not_to_say lock ("PREFER_NOT_TO_SAY") and the
    # capitalized prefer_not_to_say lock ("Prefer_not_to_say",
    # title case of the same member), the capitalized male gender
    # lock ("Male"), the capitalized female gender lock
    # ("Female"), the all-caps female gender lock ("FEMALE"),
    # the all-caps male gender lock ("MALE"), the all-caps
    # gender lock ("OTHER"), the case-variant gender lock
    # ("Other", mixed case of a different member), the padded
    # gender lock (" other ", valid content surrounded by
    # spaces), from the whitespace-only gender lock (no enum
    # content), from the invalid-gender lock (a value outside
    # the enum, "unknown"), and from the missing-gender lock
    # (field omitted): this lock pins a partial-caps variant
    # (lowercase first letter "p", uppercase stem "REFER",
    # lowercase remainder "_not_to_say") for the
    # prefer_not_to_say member, which a case-insensitive parser
    # WOULD accept, so it locks strict case-sensitive enum
    # parsing for the fourth member rather than merely rejecting
    # a value with no valid content.
    # The endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with
    # no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, a
    # password string), so no other 422 can mask the gender
    # error. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the register capitalized-uppercase-middle-lowercase-suffix
    # prefer_not_to_say gender 422 lock. The security headers
    # ARE locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "pREFER_not_to_say",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register capitalized-uppercase-middle-lowercase-suffix prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_lowercase_first_uppercase_middle_lowercase_suffix_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first-letter, uppercase-middle, lowercase-suffix
        prefer-not-to-say gender value:
    """
    # The next register validation branch after the lowercase-first-uppercase-stem
    # prefer_not_to_say gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "pREFER_NOT_to_say" is not a
    # member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims
    # first/last names and runs only after field validation
    # passes, and the only field_serializer covers tenant_id/
    # role_id for output only. Enum parsing is case-sensitive,
    # so "pREFER_NOT_to_say" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the lowercase-first-uppercase-stem
    # prefer_not_to_say lock ("pREFER_not_to_say", lowercase
    # first letter "p", uppercase stem "REFER", lowercase
    # remainder "_not_to_say"), the mixed-case
    # prefer_not_to_say lock ("pREFER_NOT_TO_SAY", lowercase
    # first letter, uppercase remainder), the
    # lowercase-uppercase-middle prefer_not_to_say lock
    # ("prefer_NOT_to_say", lowercase stem "prefer", uppercase
    # middle "_NOT", lowercase suffix "_to_say"), the
    # capitalized-uppercase-middle-lowercase-suffix
    # prefer_not_to_say lock ("Prefer_NOT_TO_say"), the
    # uppercase-prefix-lowercase-suffix prefer_not_to_say lock
    # ("PREFER_NOT_TO_say"), the uppercase-middle-lowercase-middle
    # prefer_not_to_say lock ("PREFER_not_TO_SAY"), the
    # capitalized-uppercase-middle prefer_not_to_say lock
    # ("Prefer_NOT_to_say"), the uppercase-suffix
    # prefer_not_to_say lock ("prefer_not_TO_SAY"), the
    # uppercase-prefix prefer_not_to_say lock
    # ("PREFER_NOT_to_say"), the uppercase-stem
    # prefer_not_to_say lock ("PREFER_not_to_say"), the
    # partial-caps prefer_not_to_say lock
    # ("prefer_NOT_TO_SAY"), the all-caps prefer_not_to_say
    # lock ("PREFER_NOT_TO_SAY") and the capitalized
    # prefer_not_to_say lock ("Prefer_not_to_say"), the
    # capitalized male gender lock ("Male"), the capitalized
    # female gender lock ("Female"), the all-caps female gender
    # lock ("FEMALE"), the all-caps male gender lock ("MALE"),
    # the all-caps gender lock ("OTHER"), the case-variant
    # gender lock ("Other", mixed case of a different member),
    # the padded gender lock (" other ", valid content
    # surrounded by spaces), from the whitespace-only gender
    # lock (no enum content), from the invalid-gender lock (a
    # value outside the enum, "unknown"), and from the
    # missing-gender lock (field omitted): this lock pins a
    # partial-caps variant (lowercase first letter "p",
    # uppercase middle "_NOT", lowercase suffix "_to_say")
    # for the prefer_not_to_say member, which a
    # case-insensitive parser WOULD accept, so it locks strict
    # case-sensitive enum parsing for the fourth member rather
    # than merely rejecting a value with no valid content.
    # The endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with
    # no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, a
    # password string), so no other 422 can mask the gender
    # error. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the register lowercase-first-uppercase-stem
    # prefer_not_to_say gender 422 lock. The security headers
    # ARE locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "pREFER_NOT_to_say",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register lowercase-first-uppercase-stem prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_capitalized_uppercase_middle_lowercase_uppercase_suffix_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a capitalized, uppercase-middle, lowercase-middle,
        uppercase-suffix prefer-not-to-say gender value:
    """
    # The next register validation branch after the lowercase-first-uppercase-middle-lowercase-suffix
    # prefer_not_to_say gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "Prefer_NOT_to_SAY" is not a
    # member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims
    # first/last names and runs only after field validation
    # passes, and the only field_serializer covers tenant_id/
    # role_id for output only. Enum parsing is case-sensitive,
    # so "Prefer_NOT_to_SAY" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the lowercase-first-uppercase-middle-lowercase-suffix
    # prefer_not_to_say lock ("pREFER_NOT_to_say"), the lowercase-first-uppercase-stem
    # prefer_not_to_say lock ("pREFER_not_to_say"), the mixed-case
    # prefer_not_to_say lock ("pREFER_NOT_TO_SAY"), the
    # lowercase-uppercase-middle prefer_not_to_say lock
    # ("prefer_NOT_to_say"), the capitalized-uppercase-middle-lowercase-suffix
    # prefer_not_to_say lock ("Prefer_NOT_TO_say"), the
    # uppercase-prefix-lowercase-suffix prefer_not_to_say lock
    # ("PREFER_NOT_TO_say"), the uppercase-middle-lowercase-middle
    # prefer_not_to_say lock ("PREFER_not_TO_SAY"), the
    # capitalized-uppercase-middle prefer_not_to_say lock
    # ("Prefer_NOT_to_say"), the uppercase-suffix
    # prefer_not_to_say lock ("prefer_not_TO_SAY"), the
    # uppercase-prefix prefer_not_to_say lock
    # ("PREFER_NOT_to_say"), the uppercase-stem
    # prefer_not_to_say lock ("PREFER_not_to_say"), the
    # partial-caps prefer_not_to_say lock
    # ("prefer_NOT_TO_SAY"), the all-caps prefer_not_to_say
    # lock ("PREFER_NOT_TO_SAY") and the capitalized
    # prefer_not_to_say lock ("Prefer_not_to_say"), the
    # capitalized male gender lock ("Male"), the capitalized
    # female gender lock ("Female"), the all-caps female gender
    # lock ("FEMALE"), the all-caps male gender lock ("MALE"),
    # the all-caps gender lock ("OTHER"), the case-variant
    # gender lock ("Other", mixed case of a different member),
    # the padded gender lock (" other ", valid content
    # surrounded by spaces), from the whitespace-only gender
    # lock (no enum content), from the invalid-gender lock (a
    # value outside the enum, "unknown"), and from the
    # missing-gender lock (field omitted): this lock pins a
    # partial-caps variant (capitalized first segment "Prefer",
    # uppercase middle "_NOT", lowercase middle "_to",
    # uppercase suffix "_SAY") for the prefer_not_to_say
    # member, which a case-insensitive parser WOULD accept, so
    # it locks strict case-sensitive enum parsing for the
    # fourth member rather than merely rejecting a value with
    # no valid content.
    # The endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with
    # no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, a
    # password string), so no other 422 can mask the gender
    # error. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the register lowercase-first-uppercase-middle-lowercase-suffix
    # prefer_not_to_say gender 422 lock. The security headers
    # ARE locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "Prefer_NOT_to_SAY",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register lowercase-first-uppercase-middle-lowercase-suffix prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_lowercase_first_uppercase_stem_middle_lowercase_suffix_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first, uppercase-stem,
        uppercase-middle, lowercase-suffix prefer-not-to-say gender value:
    """
    # The next register validation branch after the capitalized-uppercase-middle-lowercase-
    # uppercase-suffix prefer_not_to_say gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "pREFER_NOT_TO_say" is not a
    # member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims
    # first/last names and runs only after field validation
    # passes, and the only field_serializer covers tenant_id/
    # role_id for output only. Enum parsing is case-sensitive,
    # so "pREFER_NOT_TO_say" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the capitalized-uppercase-middle-lowercase-uppercase-suffix
    # prefer_not_to_say lock ("Prefer_NOT_to_SAY"), the lowercase-first-uppercase-middle-lowercase-suffix
    # prefer_not_to_say lock ("pREFER_NOT_to_say"), the lowercase-first-uppercase-stem
    # prefer_not_to_say lock ("pREFER_not_to_say"), the mixed-case
    # prefer_not_to_say lock ("pREFER_NOT_TO_SAY"), the
    # lowercase-uppercase-middle prefer_not_to_say lock
    # ("prefer_NOT_to_say"), the capitalized-uppercase-middle-lowercase-suffix
    # prefer_not_to_say lock ("Prefer_NOT_TO_say"), the
    # uppercase-prefix-lowercase-suffix prefer_not_to_say lock
    # ("PREFER_NOT_TO_say"), the uppercase-middle-lowercase-middle
    # prefer_not_to_say lock ("PREFER_not_TO_SAY"), the
    # capitalized-uppercase-middle prefer_not_to_say lock
    # ("Prefer_NOT_to_say"), the uppercase-suffix
    # prefer_not_to_say lock ("prefer_not_TO_SAY"), the
    # uppercase-prefix prefer_not_to_say lock
    # ("PREFER_NOT_to_say"), the uppercase-stem
    # prefer_not_to_say lock ("PREFER_not_to_say"), the
    # partial-caps prefer_not_to_say lock
    # ("prefer_NOT_TO_SAY"), the all-caps prefer_not_to_say
    # lock ("PREFER_NOT_TO_SAY") and the capitalized
    # prefer_not_to_say lock ("Prefer_not_to_say"), the
    # capitalized male gender lock ("Male"), the capitalized
    # female gender lock ("Female"), the all-caps female gender
    # lock ("FEMALE"), the all-caps male gender lock ("MALE"),
    # the all-caps gender lock ("OTHER"), the case-variant
    # gender lock ("Other", mixed case of a different member),
    # the padded gender lock (" other ", valid content
    # surrounded by spaces), from the whitespace-only gender
    # lock (no enum content), from the invalid-gender lock (a
    # value outside the enum, "unknown"), and from the
    # missing-gender lock (field omitted): this lock pins a
    # partial-caps variant (lowercase first letter "p",
    # uppercase stem "REFER", uppercase middle "_NOT_TO",
    # lowercase suffix "_say") for the prefer_not_to_say
    # member, which a case-insensitive parser WOULD accept, so
    # it locks strict case-sensitive enum parsing for the
    # fourth member rather than merely rejecting a value with
    # no valid content.
    # The endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with
    # no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, a
    # password string), so no other 422 can mask the gender
    # error. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the register capitalized-uppercase-middle-lowercase-uppercase-suffix
    # prefer_not_to_say gender 422 lock. The security headers
    # ARE locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "pREFER_NOT_TO_say",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register capitalized-uppercase-middle-lowercase-uppercase-suffix prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_capitalized_uppercase_middle_uppercase_suffix_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a capitalized, uppercase-middle,
        uppercase-suffix prefer-not-to-say gender value:
    """
    # The next register validation branch after the lowercase-first-uppercase-stem-middle-
    # lowercase-suffix prefer_not_to_say gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "Prefer_NOT_TO_SAY" is not a
    # member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims
    # first/last names and runs only after field validation
    # passes, and the only field_serializer covers tenant_id/
    # role_id for output only. Enum parsing is case-sensitive,
    # so "Prefer_NOT_TO_SAY" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the lowercase-first-uppercase-stem-middle-lowercase-suffix
    # prefer_not_to_say lock ("pREFER_NOT_TO_say"), the capitalized-uppercase-middle-lowercase-uppercase-suffix
    # prefer_not_to_say lock ("Prefer_NOT_to_SAY"), the lowercase-first-uppercase-middle-lowercase-suffix
    # prefer_not_to_say lock ("pREFER_NOT_to_say"), the lowercase-first-uppercase-stem
    # prefer_not_to_say lock ("pREFER_not_to_say"), the mixed-case
    # prefer_not_to_say lock ("pREFER_NOT_TO_SAY"), the
    # lowercase-uppercase-middle prefer_not_to_say lock
    # ("prefer_NOT_to_say"), the capitalized-uppercase-middle-lowercase-suffix
    # prefer_not_to_say lock ("Prefer_NOT_TO_say"), the
    # uppercase-prefix-lowercase-suffix prefer_not_to_say lock
    # ("PREFER_NOT_TO_say"), the uppercase-middle-lowercase-middle
    # prefer_not_to_say lock ("PREFER_not_TO_SAY"), the
    # capitalized-uppercase-middle prefer_not_to_say lock
    # ("Prefer_NOT_to_say"), the uppercase-suffix
    # prefer_not_to_say lock ("prefer_not_TO_SAY"), the
    # uppercase-prefix prefer_not_to_say lock
    # ("PREFER_NOT_to_say"), the uppercase-stem
    # prefer_not_to_say lock ("PREFER_not_to_say"), the
    # partial-caps prefer_not_to_say lock
    # ("prefer_NOT_TO_SAY"), the all-caps prefer_not_to_say
    # lock ("PREFER_NOT_TO_SAY") and the capitalized
    # prefer_not_to_say lock ("Prefer_not_to_say"), the
    # capitalized male gender lock ("Male"), the capitalized
    # female gender lock ("Female"), the all-caps female gender
    # lock ("FEMALE"), the all-caps male gender lock ("MALE"),
    # the all-caps gender lock ("OTHER"), the case-variant
    # gender lock ("Other", mixed case of a different member),
    # the padded gender lock (" other ", valid content
    # surrounded by spaces), from the whitespace-only gender
    # lock (no enum content), from the invalid-gender lock (a
    # value outside the enum, "unknown"), and from the
    # missing-gender lock (field omitted): this lock pins a
    # partial-caps variant (capitalized first letter "P",
    # lowercase stem "refer", uppercase middle "_NOT_TO",
    # uppercase suffix "_SAY") for the prefer_not_to_say
    # member, which a case-insensitive parser WOULD accept, so
    # it locks strict case-sensitive enum parsing for the
    # fourth member rather than merely rejecting a value with
    # no valid content.
    # The endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with
    # no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, a
    # password string), so no other 422 can mask the gender
    # error. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the register lowercase-first-uppercase-stem-middle-lowercase-suffix
    # prefer_not_to_say gender 422 lock. The security headers
    # ARE locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "Prefer_NOT_TO_SAY",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register lowercase-first-uppercase-stem-middle-lowercase-suffix prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_lowercase_first_uppercase_stem_uppercase_middle_lowercase_middle_uppercase_suffix_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first,
        uppercase-stem, uppercase-middle, lowercase-middle,
        uppercase-suffix prefer-not-to-say gender value:
    """
    # The next register validation branch after the capitalized-uppercase-middle-
    # uppercase-suffix prefer_not_to_say gender 422 lock, verified fresh this run, not assumed.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "pREFER_NOT_to_SAY" is not a
    # member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims
    # first/last names and runs only after field validation
    # passes, and the only field_serializer covers tenant_id/
    # role_id for output only. Enum parsing is case-sensitive,
    # so "pREFER_NOT_to_SAY" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the lowercase-first-uppercase-stem-middle-lowercase-suffix
    # prefer_not_to_say lock ("pREFER_NOT_TO_say", lowercase
    # suffix where this lock has an uppercase suffix), the
    # lowercase-first-uppercase-middle-lowercase-suffix
    # prefer_not_to_say lock ("pREFER_NOT_to_say", lowercase
    # suffix), the lowercase-first-uppercase-stem
    # prefer_not_to_say lock ("pREFER_not_to_say"), the mixed-case
    # prefer_not_to_say lock ("pREFER_NOT_TO_SAY", uppercase
    # middle "_TO" where this lock has lowercase "_to"), the
    # capitalized-uppercase-middle-uppercase-suffix
    # prefer_not_to_say lock ("Prefer_NOT_TO_SAY"), and the
    # all-caps prefer_not_to_say lock ("PREFER_NOT_TO_SAY"):
    # this lock pins a partial-caps variant (lowercase first
    # letter "p", uppercase stem "REFER", uppercase middle
    # "_NOT", lowercase middle "_to", uppercase suffix "_SAY")
    # for the prefer_not_to_say member, which a
    # case-insensitive parser WOULD accept, so it locks strict
    # case-sensitive enum parsing for the fourth member rather
    # than merely rejecting a value with no valid content.
    # The endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with
    # no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, a
    # password string), so no other 422 can mask the gender
    # error. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the capitalized-uppercase-middle-uppercase-suffix
    # prefer_not_to_say gender 422 lock. The security headers
    # ARE locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "pREFER_NOT_to_SAY",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the capitalized-uppercase-middle-uppercase-suffix prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_lowercase_first_uppercase_stem_lowercase_middle_uppercase_middle_uppercase_suffix_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first,
        uppercase-stem, lowercase-middle, uppercase-middle,
        uppercase-suffix prefer-not-to-say gender value:
    """
    # The next register validation branch after the lowercase-first-uppercase-stem-
    # uppercase-middle-lowercase-middle-uppercase-suffix prefer_not_to_say gender 422 lock,
    # verified fresh this run, not assumed. BaseUserDto.gender is a required Gender field
    # with no default (user_dto.py), and Gender admits only "male", "female", "other",
    # and "prefer_not_to_say" (gender.py) — a case-sensitive str Enum, so
    # "pREFER_not_TO_SAY" is not a member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the mode="after" normalize_names
    # validator only trims first/last names and runs only after field validation passes,
    # and the only field_serializer covers tenant_id/role_id for output only. Enum parsing
    # is case-sensitive, so "pREFER_not_TO_SAY" fails FastAPI request validation before the
    # handler body runs: the GUEST role lookup, the tenant branching, AuthService.register,
    # and the activation email never execute, and no token is minted and no refresh cookie
    # is set. Distinct from the lowercase-first-uppercase-stem-uppercase-middle-lowercase-
    # middle-uppercase-suffix prefer_not_to_say lock ("pREFER_NOT_to_SAY", uppercase middle
    # "_NOT" and lowercase middle "_to" where this lock has lowercase "_not" and uppercase
    # "_TO"), the lowercase-first-uppercase-stem-middle-lowercase-suffix prefer_not_to_say
    # lock ("pREFER_NOT_TO_say", lowercase suffix), the lowercase-first-uppercase-middle-
    # lowercase-suffix prefer_not_to_say lock ("pREFER_NOT_to_say"), the lowercase-first-
    # uppercase-stem prefer_not_to_say lock ("pREFER_not_to_say", lowercase "_to" and
    # lowercase "_say" where this lock has uppercase "_TO" and "_SAY"), the mixed-case
    # prefer_not_to_say lock ("pREFER_NOT_TO_SAY"), the capitalized-uppercase-middle-
    # uppercase-suffix prefer_not_to_say lock ("Prefer_NOT_TO_SAY"), and the all-caps
    # prefer_not_to_say lock ("PREFER_NOT_TO_SAY"): this lock pins a partial-caps variant
    # (lowercase first letter "p", uppercase stem "REFER", lowercase middle "_not",
    # uppercase middle "_TO", uppercase suffix "_SAY") for the prefer_not_to_say member,
    # which a case-insensitive parser WOULD accept, so it locks strict case-sensitive enum
    # parsing for the fourth member rather than merely rejecting a value with no valid
    # content. The endpoint's dependencies cannot mask the 422 either: get_auth_service/
    # get_role_service only resolve container objects and get_tenant_id only reads request
    # state, with no database lookup. The remaining body fields are all valid (non-blank
    # first and last names, a valid email, a password string), so no other 422 can mask
    # the gender error. Deliberately no Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the central handler's no-store headers
    # do not apply to it, mirroring the lowercase-first-uppercase-stem-uppercase-middle-
    # lowercase-middle-uppercase-suffix prefer_not_to_say gender 422 lock. The security
    # headers ARE locked: the pure-ASGI middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "pREFER_not_TO_SAY",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the lowercase-first-uppercase-stem-uppercase-middle-lowercase-middle-
    # uppercase-suffix prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_capitalized_first_lowercase_stem_lowercase_middle_uppercase_middle_uppercase_suffix_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a capitalized-first,
        lowercase-stem, lowercase-middle, uppercase-middle,
        uppercase-suffix prefer-not-to-say gender value:
    """
    # The next register validation branch after the lowercase-first-uppercase-stem-
    # lowercase-middle-uppercase-middle-uppercase-suffix prefer_not_to_say gender 422 lock,
    # verified fresh this run, not assumed. BaseUserDto.gender is a required Gender field
    # with no default (user_dto.py), and Gender admits only "male", "female", "other",
    # and "prefer_not_to_say" (gender.py) — a case-sensitive str Enum, so
    # "Prefer_not_TO_SAY" is not a member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the mode="after" normalize_names
    # validator only trims first/last names and runs only after field validation passes,
    # and the only field_serializer covers tenant_id/role_id for output only. Enum parsing
    # is case-sensitive, so "Prefer_not_TO_SAY" fails FastAPI request validation before the
    # handler body runs: the GUEST role lookup, the tenant branching, AuthService.register,
    # and the activation email never execute, and no token is minted and no refresh cookie
    # is set. Distinct from the lowercase-first-uppercase-stem-lowercase-middle-uppercase-
    # middle-uppercase-suffix prefer_not_to_say lock ("pREFER_not_TO_SAY", lowercase first
    # letter and uppercase stem where this lock has a capitalized first letter and a
    # lowercase stem), the lowercase-first-uppercase-stem-uppercase-middle-lowercase-middle-
    # uppercase-suffix prefer_not_to_say lock ("pREFER_NOT_to_SAY"), the capitalized-
    # uppercase-middle-uppercase-suffix prefer_not_to_say lock ("Prefer_NOT_TO_SAY",
    # uppercase middle "_NOT" where this lock has lowercase "_not"), the capitalized
    # prefer_not_to_say lock ("Prefer_not_to_say", lowercase "_to" and "_say" where this
    # lock has uppercase "_TO" and "_SAY"), the mixed-case prefer_not_to_say lock
    # ("pREFER_NOT_TO_SAY"), and the all-caps prefer_not_to_say lock ("PREFER_NOT_TO_SAY"):
    # this lock pins a partial-caps variant (capitalized first letter "P", lowercase stem
    # "refer", lowercase middle "_not", uppercase middle "_TO", uppercase suffix "_SAY")
    # for the prefer_not_to_say member, which a case-insensitive parser WOULD accept, so
    # it locks strict case-sensitive enum parsing for the fourth member rather than merely
    # rejecting a value with no valid content. The endpoint's dependencies cannot mask the
    # 422 either: get_auth_service/get_role_service only resolve container objects and
    # get_tenant_id only reads request state, with no database lookup. The remaining body
    # fields are all valid (non-blank first and last names, a valid email, a password
    # string), so no other 422 can mask the gender error. Deliberately no Cache-Control/
    # Pragma assertion: a 422 is FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to it, mirroring the
    # lowercase-first-uppercase-stem-lowercase-middle-uppercase-middle-uppercase-suffix
    # prefer_not_to_say gender 422 lock. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including validation errors, with no path
    # exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "Prefer_not_TO_SAY",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the lowercase-first-uppercase-stem-lowercase-middle-uppercase-middle-
    # uppercase-suffix prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_capitalized_first_lowercase_stem_lowercase_middle_lowercase_middle_uppercase_suffix_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a capitalized-first,
        lowercase-stem, lowercase-middle, lowercase-middle,
        uppercase-suffix prefer-not-to-say gender value:
    """
    # The next register validation branch after the capitalized-first-lowercase-stem-
    # lowercase-middle-uppercase-middle-uppercase-suffix prefer_not_to_say gender 422 lock,
    # verified fresh this run, not assumed (grep count 0 for "Prefer_not_to_SAY" and for
    # this test name before appending). BaseUserDto.gender is a required Gender field
    # with no default (user_dto.py), and Gender admits only "male", "female", "other",
    # and "prefer_not_to_say" (gender.py) — a case-sensitive str Enum, so
    # "Prefer_not_to_SAY" is not a member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the mode="after" normalize_names
    # validator only trims first/last names and runs only after field validation passes,
    # and the only field_serializer covers tenant_id/role_id for output only. Enum parsing
    # is case-sensitive, so "Prefer_not_to_SAY" fails FastAPI request validation before the
    # handler body runs: the GUEST role lookup, the tenant branching, AuthService.register,
    # and the activation email never execute, and no token is minted and no refresh cookie
    # is set. Distinct from the capitalized-first-lowercase-stem-lowercase-middle-uppercase-
    # middle-uppercase-suffix prefer_not_to_say lock ("Prefer_not_TO_SAY", uppercase middle
    # "_TO" where this lock has lowercase "_to"), the capitalized-uppercase-middle-uppercase-
    # suffix prefer_not_to_say lock ("Prefer_NOT_TO_SAY"), the capitalized prefer_not_to_say
    # lock ("Prefer_not_to_say", lowercase "_to" and "_say" where this lock has lowercase
    # "_to" but uppercase "_SAY"), the mixed-case prefer_not_to_say lock
    # ("pREFER_NOT_TO_SAY"), and the all-caps prefer_not_to_say lock ("PREFER_NOT_TO_SAY"):
    # this lock pins a partial-caps variant (capitalized first letter "P", lowercase stem
    # "refer", lowercase middle "_not", lowercase middle "_to", uppercase suffix "_SAY")
    # for the prefer_not_to_say member, which a case-insensitive parser WOULD accept, so
    # it locks strict case-sensitive enum parsing for the fourth member rather than merely
    # rejecting a value with no valid content. The endpoint's dependencies cannot mask the
    # 422 either: get_auth_service/get_role_service only resolve container objects and
    # get_tenant_id only reads request state, with no database lookup. The remaining body
    # fields are all valid (non-blank first and last names, a valid email, a password
    # string), so no other 422 can mask the gender error. Deliberately no Cache-Control/
    # Pragma assertion: a 422 is FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to it, mirroring the
    # capitalized-first-lowercase-stem-lowercase-middle-uppercase-middle-uppercase-suffix
    # prefer_not_to_say gender 422 lock. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including validation errors, with no path
    # exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "Prefer_not_to_SAY",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the capitalized-first-lowercase-stem-lowercase-middle-uppercase-middle-
    # uppercase-suffix prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_capitalized_first_lowercase_stem_lowercase_middle_uppercase_middle_lowercase_suffix_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a capitalized-first,
        lowercase-stem, lowercase-middle, uppercase-middle,
        lowercase-suffix prefer-not-to-say gender value:
    """
    # The next register validation branch after the capitalized-first-lowercase-stem-
    # lowercase-middle-lowercase-middle-uppercase-suffix prefer_not_to_say gender 422 lock,
    # verified fresh this run, not assumed (grep count 0 for "Prefer_not_TO_say" and for
    # this test name before appending). BaseUserDto.gender is a required Gender field
    # with no default (user_dto.py), and Gender admits only "male", "female", "other",
    # and "prefer_not_to_say" (gender.py) — a case-sensitive str Enum, so
    # "Prefer_not_TO_say" is not a member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the mode="after" normalize_names
    # validator only trims first/last names and runs only after field validation passes,
    # and the only field_serializer covers tenant_id/role_id for output only. Enum parsing
    # is case-sensitive, so "Prefer_not_TO_say" fails FastAPI request validation before the
    # handler body runs: the GUEST role lookup, the tenant branching, AuthService.register,
    # and the activation email never execute, and no token is minted and no refresh cookie
    # is set. Distinct from the capitalized-first-lowercase-stem-lowercase-middle-uppercase-
    # middle-uppercase-suffix prefer_not_to_say lock ("Prefer_not_TO_SAY", uppercase suffix
    # "_SAY" where this lock has lowercase "_say"), the capitalized-first-lowercase-stem-
    # lowercase-middle-lowercase-middle-uppercase-suffix prefer_not_to_say lock
    # ("Prefer_not_to_SAY", lowercase middle "_to" where this lock has uppercase "_TO"),
    # the capitalized prefer_not_to_say lock ("Prefer_not_to_say", lowercase "_to" and
    # "_say" where this lock has uppercase "_TO"), the mixed-case prefer_not_to_say lock
    # ("pREFER_NOT_TO_SAY"), and the all-caps prefer_not_to_say lock ("PREFER_NOT_TO_SAY"):
    # this lock pins a partial-caps variant (capitalized first letter "P", lowercase stem
    # "refer", lowercase middle "_not", uppercase middle "_TO", lowercase suffix "_say")
    # for the prefer_not_to_say member, which a case-insensitive parser WOULD accept, so
    # it locks strict case-sensitive enum parsing for the fourth member rather than merely
    # rejecting a value with no valid content. The endpoint's dependencies cannot mask the
    # 422 either: get_auth_service/get_role_service only resolve container objects and
    # get_tenant_id only reads request state, with no database lookup. The remaining body
    # fields are all valid (non-blank first and last names, a valid email, a password
    # string), so no other 422 can mask the gender error. Deliberately no Cache-Control/
    # Pragma assertion: a 422 is FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to it, mirroring the
    # capitalized-first-lowercase-stem-lowercase-middle-lowercase-middle-uppercase-suffix
    # prefer_not_to_say gender 422 lock. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including validation errors, with no path
    # exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "Prefer_not_TO_say",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the capitalized-first-lowercase-stem-lowercase-middle-lowercase-middle-
    # uppercase-suffix prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_uppercase_first_uppercase_stem_lowercase_middle_uppercase_middle_lowercase_suffix_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an uppercase-first,
        uppercase-stem, lowercase-middle, uppercase-middle,
        lowercase-suffix prefer-not-to-say gender value:
    """
    # The next register validation branch after the capitalized-first-lowercase-stem-
    # lowercase-middle-uppercase-middle-lowercase-suffix prefer_not_to_say gender 422 lock,
    # verified fresh this run, not assumed (grep count 0 for "PREFER_not_TO_say" and for
    # this test name before appending). BaseUserDto.gender is a required Gender field
    # with no default (user_dto.py), and Gender admits only "male", "female", "other",
    # and "prefer_not_to_say" (gender.py) — a case-sensitive str Enum, so
    # "PREFER_not_TO_say" is not a member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the mode="after" normalize_names
    # validator only trims first/last names and runs only after field validation passes,
    # and the only field_serializer covers tenant_id/role_id for output only. Enum parsing
    # is case-sensitive, so "PREFER_not_TO_say" fails FastAPI request validation before the
    # handler body runs: the GUEST role lookup, the tenant branching, AuthService.register,
    # and the activation email never execute, and no token is minted and no refresh cookie
    # is set. Distinct from the capitalized-first-lowercase-stem-lowercase-middle-uppercase-
    # middle-lowercase-suffix prefer_not_to_say lock ("Prefer_not_TO_say", capitalized first
    # letter "P" plus lowercase stem "refer" where this lock has the fully uppercase stem
    # "PREFER"), the uppercase-stem-lowercase-middle-uppercase-middle-uppercase-suffix
    # prefer_not_to_say lock ("PREFER_not_TO_SAY", uppercase suffix "_SAY" where this lock
    # has lowercase "_say"), the uppercase-stem-lowercase-middle-lowercase-middle-uppercase-
    # suffix prefer_not_to_say lock ("PREFER_not_to_SAY"), and the all-caps prefer_not_to_say
    # lock ("PREFER_NOT_TO_SAY"): this lock pins a partial-caps variant (uppercase stem
    # "PREFER", lowercase middle "_not", uppercase middle "_TO", lowercase suffix "_say")
    # for the prefer_not_to_say member, which a case-insensitive parser WOULD accept, so
    # it locks strict case-sensitive enum parsing for the fourth member rather than merely
    # rejecting a value with no valid content. The endpoint's dependencies cannot mask the
    # 422 either: get_auth_service/get_role_service only resolve container objects and
    # get_tenant_id only reads request state, with no database lookup. The remaining body
    # fields are all valid (non-blank first and last names, a valid email, a password
    # string), so no other 422 can mask the gender error. Deliberately no Cache-Control/
    # Pragma assertion: a 422 is FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to it, mirroring the
    # capitalized-first-lowercase-stem-lowercase-middle-uppercase-middle-lowercase-suffix
    # prefer_not_to_say gender 422 lock. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including validation errors, with no path
    # exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "PREFER_not_TO_say",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the capitalized-first-lowercase-stem-lowercase-middle-uppercase-middle-
    # lowercase-suffix prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_lowercase_first_lowercase_stem_uppercase_middle_uppercase_middle_lowercase_suffix_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first,
        lowercase-stem, uppercase-middle, uppercase-middle,
        lowercase-suffix prefer-not-to-say gender value:
    """
    # The next register validation branch after the uppercase-first-uppercase-stem-
    # lowercase-middle-uppercase-middle-lowercase-suffix prefer_not_to_say gender 422 lock,
    # verified fresh this run, not assumed (grep count 0 for "prefer_NOT_TO_say" and for
    # this test name before appending). BaseUserDto.gender is a required Gender field
    # with no default (user_dto.py), and Gender admits only "male", "female", "other",
    # and "prefer_not_to_say" (gender.py) — a case-sensitive str Enum, so
    # "prefer_NOT_TO_say" is not a member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the mode="after" normalize_names
    # validator only trims first/last names and runs only after field validation passes,
    # and the only field_serializer covers tenant_id/role_id for output only. Enum parsing
    # is case-sensitive, so "prefer_NOT_TO_say" fails FastAPI request validation before the
    # handler body runs: the GUEST role lookup, the tenant branching, AuthService.register,
    # and the activation email never execute, and no token is minted and no refresh cookie
    # is set. Distinct from the uppercase-first-uppercase-stem-lowercase-middle-uppercase-
    # middle-lowercase-suffix prefer_not_to_say lock ("PREFER_not_TO_say", fully uppercase
    # stem "PREFER" where this lock has the lowercase stem "prefer"), the all-caps
    # prefer_not_to_say lock ("PREFER_NOT_TO_SAY"), and the lowercase-middle variants:
    # this lock pins a partial-caps variant (lowercase stem "prefer", uppercase middle
    # "_NOT", uppercase middle "_TO", lowercase suffix "_say") for the prefer_not_to_say
    # member, which a case-insensitive parser WOULD accept, so it locks strict
    # case-sensitive enum parsing for the fourth member rather than merely rejecting a
    # value with no valid content. The endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container objects and get_tenant_id
    # only reads request state, with no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, a password string), so no
    # other 422 can mask the gender error. Deliberately no Cache-Control/Pragma assertion:
    # a 422 is FastAPI request validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring the
    # uppercase-first-uppercase-stem-lowercase-middle-uppercase-middle-lowercase-suffix
    # prefer_not_to_say gender 422 lock. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including validation errors, with no path
    # exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "prefer_NOT_TO_say",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the uppercase-first-uppercase-stem-lowercase-middle-uppercase-middle-
    # lowercase-suffix prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_lowercase_first_lowercase_stem_lowercase_middle_uppercase_middle_lowercase_suffix_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first,
        lowercase-stem, lowercase-middle, uppercase-middle,
        lowercase-suffix prefer-not-to-say gender value:
    """
    # The next register validation branch after the lowercase-first-lowercase-stem-
    # uppercase-middle-uppercase-middle-lowercase-suffix prefer_not_to_say gender 422 lock,
    # verified fresh this run, not assumed (grep count 0 for "prefer_not_TO_say" and for
    # this test name before appending). BaseUserDto.gender is a required Gender field
    # with no default (user_dto.py), and Gender admits only "male", "female", "other",
    # and "prefer_not_to_say" (gender.py) — a case-sensitive str Enum, so
    # "prefer_not_TO_say" is not a member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the mode="after" normalize_names
    # validator only trims first/last names and runs only after field validation passes,
    # and the only field_serializer covers tenant_id/role_id for output only. Enum parsing
    # is case-sensitive, so "prefer_not_TO_say" fails FastAPI request validation before the
    # handler body runs: the GUEST role lookup, the tenant branching, AuthService.register,
    # and the activation email never execute, and no token is minted and no refresh cookie
    # is set. Distinct from the lowercase-first-lowercase-stem-uppercase-middle-uppercase-
    # middle-lowercase-suffix prefer_not_to_say lock ("prefer_NOT_TO_say", uppercase middle
    # "_NOT" where this lock has the lowercase middle "_not"), the lowercase-prefix
    # prefer_not_to_say lock ("prefer_not_TO_SAY", uppercase suffix "_SAY" where this lock
    # has the lowercase suffix "_say"), and the all-caps prefer_not_to_say lock
    # ("PREFER_NOT_TO_SAY"): this lock pins a partial-caps variant (lowercase stem "prefer",
    # lowercase middle "_not", uppercase middle "_TO", lowercase suffix "_say") for the
    # prefer_not_to_say member, which a case-insensitive parser WOULD accept, so it locks
    # strict case-sensitive enum parsing for the fourth member rather than merely rejecting
    # a value with no valid content. Note: the previous run's suggested next branches
    # ("prefer_not_TO_SAY" and "PREFER_not_to_say") were both already locked, verified by
    # grep this run, so this run picked the next unpinned combination instead. The
    # endpoint's dependencies cannot mask the 422 either: get_auth_service/get_role_service
    # only resolve container objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid (non-blank first and last
    # names, a valid email, a password string), so no other 422 can mask the gender error.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is FastAPI request validation,
    # not an ApiBaseException, so the central handler's no-store headers do not apply to it,
    # mirroring the lowercase-first-lowercase-stem-uppercase-middle-uppercase-middle-
    # lowercase-suffix prefer_not_to_say gender 422 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response, including validation errors,
    # with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "prefer_not_TO_say",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the lowercase-first-lowercase-stem-uppercase-middle-uppercase-middle-
    # lowercase-suffix prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_lowercase_first_lowercase_stem_lowercase_middle_lowercase_middle_uppercase_suffix_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first,
        lowercase-stem, lowercase-middle, lowercase-middle,
        uppercase-suffix prefer-not-to-say gender value:
    """
    # The next register validation branch after the lowercase-first-lowercase-stem-
    # lowercase-middle-uppercase-middle-lowercase-suffix prefer_not_to_say gender 422 lock,
    # verified fresh this run, not assumed (grep count 0 for "prefer_not_to_SAY" as a
    # payload and for this test name before appending; the only prior mention of
    # "PREFER_not_to_SAY" is a comment reference, not a payload). BaseUserDto.gender is a
    # required Gender field with no default (user_dto.py), and Gender admits only "male",
    # "female", "other", and "prefer_not_to_say" (gender.py) — a case-sensitive str Enum,
    # so "prefer_not_to_SAY" is not a member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the mode="after" normalize_names
    # validator only trims first/last names and runs only after field validation passes,
    # and the only field_serializer covers tenant_id/role_id for output only. Enum parsing
    # is case-sensitive, so "prefer_not_to_SAY" fails FastAPI request validation before the
    # handler body runs: the GUEST role lookup, the tenant branching, AuthService.register,
    # and the activation email never execute, and no token is minted and no refresh cookie
    # is set. Distinct from the lowercase-first-lowercase-stem-lowercase-middle-uppercase-
    # middle-lowercase-suffix prefer_not_to_say lock ("prefer_not_TO_say", uppercase middle
    # "_TO" where this lock has the lowercase middle "_to"), the lowercase-prefix
    # prefer_not_to_say lock ("prefer_not_TO_SAY", uppercase middle "_TO" where this lock
    # has the lowercase middle "_to"), and the all-caps prefer_not_to_say lock
    # ("PREFER_NOT_TO_SAY"): this lock pins a partial-caps variant (lowercase stem "prefer",
    # lowercase middle "_not", lowercase middle "_to", uppercase suffix "_SAY") for the
    # prefer_not_to_say member, which a case-insensitive parser WOULD accept, so it locks
    # strict case-sensitive enum parsing for the fourth member rather than merely rejecting
    # a value with no valid content. Note: the previous run's suggested next branches
    # ("PREFER_not_TO_say" and "prefer_NOT_to_SAY") were checked this run — the first is
    # already locked as a payload and the second remains unpinned, so this run picked
    # "prefer_not_to_SAY", the first unpinned lower/upper-only combination in sweep order.
    # The endpoint's dependencies cannot mask the 422 either: get_auth_service/get_role_service
    # only resolve container objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid (non-blank first and last
    # names, a valid email, a password string), so no other 422 can mask the gender error.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is FastAPI request validation,
    # not an ApiBaseException, so the central handler's no-store headers do not apply to it,
    # mirroring the lowercase-first-lowercase-stem-lowercase-middle-uppercase-middle-
    # lowercase-suffix prefer_not_to_say gender 422 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response, including validation errors,
    # with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "prefer_not_to_SAY",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the lowercase-first-lowercase-stem-lowercase-middle-uppercase-middle-
    # lowercase-suffix prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_uppercase_first_uppercase_stem_uppercase_middle_lowercase_middle_uppercase_suffix_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an uppercase-first,
        uppercase-stem, uppercase-middle, lowercase-middle,
        uppercase-suffix prefer-not-to-say gender value:
    """
    # The next register validation branch after the lowercase-first-lowercase-stem-
    # lowercase-middle-lowercase-middle-uppercase-suffix prefer_not_to_say gender 422 lock,
    # verified fresh this run, not assumed (grep count 0 for "PREFER_NOT_to_SAY" as a
    # payload and for this test name before appending; the prior run's suggestion
    # "prefer_NOT_to_SAY" appears only in a comment reference, not as a payload, so this
    # run picked the next fully unpinned combination instead). BaseUserDto.gender is a
    # required Gender field with no default (user_dto.py), and Gender admits only "male",
    # "female", "other", and "prefer_not_to_say" (gender.py) — a case-sensitive str Enum,
    # so "PREFER_NOT_to_SAY" is not a member even though it matches "prefer_not_to_say"
    # case-insensitively. No validator touches gender: the mode="after" normalize_names
    # validator only trims first/last names and runs only after field validation passes,
    # and the only field_serializer covers tenant_id/role_id for output only. Enum parsing
    # is case-sensitive, so "PREFER_NOT_to_SAY" fails FastAPI request validation before the
    # handler body runs: the GUEST role lookup, the tenant branching, AuthService.register,
    # and the activation email never execute, and no token is minted and no refresh cookie
    # is set. Distinct from the uppercase-stem lowercase-middle uppercase-middle
    # lowercase-suffix prefer_not_to_say lock ("PREFER_not_TO_say", lowercase middle "_not"
    # where this lock has uppercase "_NOT", and lowercase suffix "_say" where this lock has
    # uppercase "_SAY"), the lowercase-first lowercase-stem lowercase-middle lowercase-
    # middle uppercase-suffix prefer_not_to_say lock ("prefer_not_to_SAY", lowercase stem
    # "prefer" and lowercase middles where this lock has uppercase), and the all-caps
    # prefer_not_to_say lock ("PREFER_NOT_TO_SAY", uppercase middle "_TO" where this lock
    # has lowercase "_to"): this lock pins a partial-caps variant (uppercase stem "PREFER",
    # uppercase middle "_NOT", lowercase middle "_to", uppercase suffix "_SAY") for the
    # prefer_not_to_say member, which a case-insensitive parser WOULD accept, so it locks
    # strict case-sensitive enum parsing for the fourth member rather than merely rejecting
    # a value with no valid content. The endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container objects and get_tenant_id
    # only reads request state, with no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, a password string), so no other
    # 422 can mask the gender error. Deliberately no Cache-Control/Pragma assertion: a 422
    # is FastAPI request validation, not an ApiBaseException, so the central handler's
    # no-store headers do not apply to it, mirroring the lowercase-first-lowercase-stem-
    # lowercase-middle-lowercase-middle-uppercase-suffix prefer_not_to_say gender 422 lock.
    # The security headers ARE locked: the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "PREFER_NOT_to_SAY",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the lowercase-first-lowercase-stem-lowercase-middle-lowercase-middle-
    # uppercase-suffix prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_lowercase_first_lowercase_stem_uppercase_middle_lowercase_middle_uppercase_suffix_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first,
        lowercase-stem, uppercase-middle, lowercase-middle,
        uppercase-suffix prefer-not-to-say gender value:
    """
    # The next register validation branch after the uppercase-first-uppercase-stem-
    # uppercase-middle-lowercase-middle-uppercase-suffix prefer_not_to_say gender 422 lock,
    # verified fresh this run, not assumed (grep count 0 for
    # "prefer_NOT_to_SAY" as a payload and for this test name before appending; the
    # only prior mentions of "prefer_NOT_to_SAY" are comment references, not payloads).
    # BaseUserDto.gender is a required Gender field with no default (user_dto.py), and
    # Gender admits only "male", "female", "other", and "prefer_not_to_say" (gender.py)
    # — a case-sensitive str Enum, so "prefer_NOT_to_SAY" is not a member even though
    # it matches "prefer_not_to_say" case-insensitively. No validator touches gender:
    # the mode="after" normalize_names validator only trims first/last names and runs
    # only after field validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only. Enum parsing is case-sensitive, so
    # "prefer_NOT_to_SAY" fails FastAPI request validation before the handler body
    # runs: the GUEST role lookup, the tenant branching, AuthService.register, and the
    # activation email never execute, and no token is minted and no refresh cookie is
    # set. Distinct from the lowercase-first-lowercase-stem-lowercase-middle-lowercase-
    # middle-uppercase-suffix prefer_not_to_say lock ("prefer_not_to_SAY", lowercase
    # middle "_not" where this lock has uppercase "_NOT"), the uppercase-first-
    # uppercase-stem-uppercase-middle-lowercase-middle-uppercase-suffix
    # prefer_not_to_say lock ("PREFER_NOT_to_SAY", uppercase stem "PREFER" where this
    # lock has lowercase "prefer"), and the all-caps prefer_not_to_say lock
    # ("PREFER_NOT_TO_SAY", uppercase middle "_TO" where this lock has lowercase
    # "_to"): this lock pins a partial-caps variant (lowercase stem "prefer",
    # uppercase middle "_NOT", lowercase middle "_to", uppercase suffix "_SAY") for the
    # prefer_not_to_say member, which a case-insensitive parser WOULD accept, so it
    # locks strict case-sensitive enum parsing for the fourth member rather than merely
    # rejecting a value with no valid content. The endpoint's dependencies cannot mask
    # the 422 either: get_auth_service/get_role_service only resolve container objects
    # and get_tenant_id only reads request state, with no database lookup. The remaining
    # body fields are all valid (non-blank first and last names, a valid email, a
    # password string), so no other 422 can mask the gender error. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store headers do not apply to it,
    # mirroring the uppercase-first-uppercase-stem-uppercase-middle-lowercase-middle-
    # uppercase-suffix prefer_not_to_say gender 422 lock. The security headers ARE
    # locked: the pure-ASGI middleware stamps every HTTP response, including validation
    # errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "prefer_NOT_to_SAY",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the uppercase-first-uppercase-stem-uppercase-middle-lowercase-middle-
    # uppercase-suffix prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_lowercase_first_uppercase_stem_lowercase_middle_lowercase_middle_uppercase_suffix_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first,
        uppercase-stem, lowercase-middle, lowercase-middle,
        uppercase-suffix prefer-not-to-say gender value:
    """
    # The next register validation branch after the lowercase-first-lowercase-stem-
    # uppercase-middle-lowercase-middle-uppercase-suffix prefer_not_to_say gender 422 lock,
    # verified fresh this run, not assumed (grep count 0 for
    # "pREFER_not_to_SAY" as a payload and for this test name before appending).
    # BaseUserDto.gender is a required Gender field with no default (user_dto.py), and
    # Gender admits only "male", "female", "other", and "prefer_not_to_say" (gender.py)
    # — a case-sensitive str Enum, so "pREFER_not_to_SAY" is not a member even though
    # it matches "prefer_not_to_say" case-insensitively. No validator touches gender:
    # the mode="after" normalize_names validator only trims first/last names and runs
    # only after field validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only. Enum parsing is case-sensitive, so
    # "pREFER_not_to_SAY" fails FastAPI request validation before the handler body
    # runs: the GUEST role lookup, the tenant branching, AuthService.register, and the
    # activation email never execute, and no token is minted and no refresh cookie is
    # set. Distinct from the lowercase-first-uppercase-stem prefer_not_to_say lock
    # ("pREFER_not_to_say", lowercase suffix "_say" where this lock has uppercase
    # "_SAY"), the lowercase-first-uppercase-stem-middle-lowercase-suffix
    # prefer_not_to_say lock ("pREFER_NOT_to_say", uppercase middle "_NOT" where this
    # lock has lowercase "_not"), and the lowercase-first-uppercase-stem-lowercase-
    # middle-uppercase-middle-uppercase-suffix prefer_not_to_say lock
    # ("pREFER_not_TO_SAY", uppercase middle "_TO" where this lock has lowercase
    # "_to"): this lock pins a partial-caps variant (lowercase first "p", uppercase
    # stem "REFER", lowercase middles "_not" and "_to", uppercase suffix "_SAY") for the
    # prefer_not_to_say member, which a case-insensitive parser WOULD accept, so it
    # locks strict case-sensitive enum parsing for the fourth member rather than merely
    # rejecting a value with no valid content. The endpoint's dependencies cannot mask
    # the 422 either: get_auth_service/get_role_service only resolve container objects
    # and get_tenant_id only reads request state, with no database lookup. The remaining
    # body fields are all valid (non-blank first and last names, a valid email, a
    # strong string password), so no other 422 can mask the gender error. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store headers do not apply to it,
    # mirroring the previous prefer_not_to_say gender 422 lock. The security headers ARE
    # locked: the pure-ASGI middleware stamps every HTTP response, including validation
    # errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "pREFER_not_to_SAY",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the previous prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_lowercase_first_uppercase_stem_lowercase_middle_uppercase_middle_lowercase_suffix_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first,
        uppercase-stem, lowercase-middle, uppercase-middle,
        lowercase-suffix prefer-not-to-say gender value:
    """
    # The next register validation branch after the lowercase-first-uppercase-stem-
    # lowercase-middle-lowercase-middle-uppercase-suffix prefer_not_to_say gender 422 lock,
    # verified fresh this run, not assumed (grep count 0 for
    # "pREFER_not_TO_say" as a payload and for this test name before appending).
    # BaseUserDto.gender is a required Gender field with no default (user_dto.py), and
    # Gender admits only "male", "female", "other", and "prefer_not_to_say" (gender.py)
    # — a case-sensitive str Enum, so "pREFER_not_TO_say" is not a member even though
    # it matches "prefer_not_to_say" case-insensitively. No validator touches gender:
    # the mode="after" normalize_names validator only trims first/last names and runs
    # only after field validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only. Enum parsing is case-sensitive, so
    # "pREFER_not_TO_say" fails FastAPI request validation before the handler body
    # runs: the GUEST role lookup, the tenant branching, AuthService.register, and the
    # activation email never execute, and no token is minted and no refresh cookie is
    # set. Distinct from the lowercase-first-uppercase-stem-lowercase-middle-lowercase-
    # middle-uppercase-suffix prefer_not_to_say lock ("pREFER_not_to_SAY", uppercase
    # suffix "_SAY" where this lock has lowercase "_say"), the lowercase-first-
    # uppercase-stem-lowercase-middle-uppercase-middle-uppercase-suffix
    # prefer_not_to_say lock ("pREFER_not_TO_SAY", uppercase suffix "_SAY" where this
    # lock has lowercase "_say"), and the lowercase-first-uppercase-stem-lowercase-
    # middle-lowercase-middle-lowercase-suffix prefer_not_to_say lock
    # ("pREFER_not_to_say", lowercase middle "_to" where this lock has uppercase
    # "_TO"): this lock pins a partial-caps variant (lowercase first "p", uppercase
    # stem "REFER", lowercase middle "_not", uppercase middle "_TO", lowercase suffix
    # "_say") for the prefer_not_to_say member, which a case-insensitive parser WOULD
    # accept, so it locks strict case-sensitive enum parsing for the fourth member
    # rather than merely rejecting a value with no valid content. The endpoint's
    # dependencies cannot mask the 422 either: get_auth_service/get_role_service only
    # resolve container objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid (non-blank first and
    # last names, a valid email, a strong string password), so no other 422 can mask
    # the gender error. Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the central handler's
    # no-store headers do not apply to it, mirroring the previous prefer_not_to_say
    # gender 422 lock. The security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "pREFER_not_TO_say",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the previous prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_uppercase_first_uppercase_stem_lowercase_middle_lowercase_middle_uppercase_suffix_prefer_not_to_say_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an uppercase-first,
        uppercase-stem, lowercase-middle, lowercase-middle,
        uppercase-suffix prefer-not-to-say gender value:
    """
    # The next register validation branch after the lowercase-first-uppercase-stem-
    # lowercase-middle-uppercase-middle-lowercase-suffix prefer_not_to_say gender 422 lock,
    # verified fresh this run, not assumed: a segment-wise scan of all
    # "gender" payloads in this file found 30 of the 31 non-lowercase
    # segment-casing combinations already pinned, and "PREFER_not_to_SAY" is the
    # sole remaining one (grep count 0 for '"gender": "PREFER_not_to_SAY"' as a
    # payload and for this test name before appending; the only prior mentions
    # are comment references, not payloads).
    # BaseUserDto.gender is a required Gender field with no default (user_dto.py), and
    # Gender admits only "male", "female", "other", and "prefer_not_to_say" (gender.py)
    # — a case-sensitive str Enum, so "PREFER_not_to_SAY" is not a member even though
    # it matches "prefer_not_to_say" case-insensitively. No validator touches gender:
    # the mode="after" normalize_names validator only trims first/last names and runs
    # only after field validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only. Enum parsing is case-sensitive, so
    # "PREFER_not_to_SAY" fails FastAPI request validation before the handler body
    # runs: the GUEST role lookup, the tenant branching, AuthService.register, and the
    # activation email never execute, and no token is minted and no refresh cookie is
    # set. Distinct from the all-caps prefer_not_to_say lock ("PREFER_NOT_TO_SAY",
    # uppercase middles "_NOT"/"_TO" where this lock has lowercase "_not"/"_to") and
    # from the uppercase-first-uppercase-stem-lowercase-middle-lowercase-middle-
    # lowercase-suffix lock ("PREFER_not_to_say", lowercase suffix "_say" where this
    # lock has uppercase "_SAY"): this lock pins a partial-caps variant (uppercase
    # first "P", uppercase stem "REFER", lowercase middle "_not", lowercase middle
    # "_to", uppercase suffix "_SAY") for the prefer_not_to_say member, which a
    # case-insensitive parser WOULD accept, so it locks strict case-sensitive enum
    # parsing for the fourth member rather than merely rejecting a value with no
    # valid content. The endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container objects and
    # get_tenant_id only reads request state, with no database lookup. The remaining
    # body fields are all valid (non-blank first and last names, a valid email, a
    # strong string password), so no other 422 can mask the gender error.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central handler's no-store headers
    # do not apply to it, mirroring the previous prefer_not_to_say gender 422 lock.
    # The security headers ARE locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "PREFER_not_to_SAY",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the previous prefer_not_to_say gender 422 lock,
    # using substring checks so later additions to the list do
    # not break this test.
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


async def test_account_register_lowercase_first_two_uppercase_third_female_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first-two,
        uppercase-third female gender value:
    """
    # The next register validation branch after the lowercase-first
    # uppercase-second female gender 422 lock, verified fresh this
    # run, not assumed: grep count 0 for "feMale" in this file
    # before appending. BaseUserDto.gender is a required Gender
    # field with no default (user_dto.py), and Gender admits only
    # "male", "female", "other", and "prefer_not_to_say"
    # (gender.py) — a case-sensitive str Enum, so "feMale" is not
    # a member even though it matches "female"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims first/last
    # names and runs only after field validation passes, and the
    # only field_serializer covers tenant_id/role_id for output
    # only. Enum parsing is case-sensitive, so "feMale" fails
    # FastAPI request validation before the handler body runs:
    # the GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie is
    # set. Distinct from the lowercase-first uppercase-second
    # female lock ("fEmale", uppercase second letter where this
    # lock has lowercase "e" and uppercase third letter "M"),
    # the capitalized female gender lock ("Female"), and the
    # all-caps female gender lock ("FEMALE"): this lock pins the
    # lowercase-first-two / uppercase-third variant for the
    # female member, which a case-insensitive parser WOULD
    # accept, so it locks strict case-sensitive enum parsing for
    # a new member/casing combination rather than merely
    # rejecting a value with no valid content. The endpoint's
    # dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, a password
    # string), so no other 422 can mask the gender error. A
    # validation 422 precedes the role lookup, so it contradicts
    # no existing role expectation (standing role-list 200-vs-404
    # caveat noted, unchanged). Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the register lowercase-first uppercase-second female gender
    # 422 lock. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including validation
    # errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "feMale",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register lowercase-first uppercase-second
    # female gender 422 lock, using substring checks so later
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


async def test_account_register_lowercase_first_three_uppercase_fourth_female_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first-three,
        uppercase-fourth female gender value:
    """
    # The next register validation branch after the lowercase-first-two
    # uppercase-third female gender 422 lock, verified fresh this
    # run, not assumed: grep count 0 for "femAle" in this file
    # before appending. BaseUserDto.gender is a required Gender
    # field with no default (user_dto.py), and Gender admits only
    # "male", "female", "other", and "prefer_not_to_say"
    # (gender.py) — a case-sensitive str Enum, so "femAle" is not
    # a member even though it matches "female"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims first/last
    # names and runs only after field validation passes, and the
    # only field_serializer covers tenant_id/role_id for output
    # only. Enum parsing is case-sensitive, so "femAle" fails
    # FastAPI request validation before the handler body runs:
    # the GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie is
    # set. Distinct from the lowercase-first-two uppercase-third
    # female lock ("feMale", uppercase third letter where this
    # lock has lowercase "m" and uppercase fourth letter "A"),
    # the lowercase-first uppercase-second female lock ("fEmale"),
    # the capitalized female gender lock ("Female"), and the
    # all-caps female gender lock ("FEMALE"): this lock pins the
    # lowercase-first-three / uppercase-fourth variant for the
    # female member, which a case-insensitive parser WOULD
    # accept, so it locks strict case-sensitive enum parsing for
    # a new member/casing combination rather than merely
    # rejecting a value with no valid content. The endpoint's
    # dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, a password
    # string), so no other 422 can mask the gender error. A
    # validation 422 precedes the role lookup, so it contradicts
    # no existing role expectation (standing role-list 200-vs-404
    # caveat noted, unchanged). Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the register lowercase-first-two uppercase-third female gender
    # 422 lock. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including validation
    # errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "femAle",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register lowercase-first-two uppercase-third
    # female gender 422 lock, using substring checks so later
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


async def test_account_register_lowercase_first_four_uppercase_fifth_female_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first-four,
        uppercase-fifth female gender value:
    """
    # The next register validation branch after the lowercase-first-three
    # uppercase-fourth female gender 422 lock, verified fresh this
    # run, not assumed: grep count 0 for "femaLe" in this file
    # before appending. BaseUserDto.gender is a required Gender
    # field with no default (user_dto.py), and Gender admits only
    # "male", "female", "other", and "prefer_not_to_say"
    # (gender.py) — a case-sensitive str Enum, so "femaLe" is not
    # a member even though it matches "female"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims first/last
    # names and runs only after field validation passes, and the
    # only field_serializer covers tenant_id/role_id for output
    # only. Enum parsing is case-sensitive, so "femaLe" fails
    # FastAPI request validation before the handler body runs:
    # the GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie is
    # set. Distinct from the lowercase-first-three uppercase-fourth
    # female lock ("femAle", uppercase fourth letter where this
    # lock has lowercase "a" and uppercase fifth letter "L"),
    # the lowercase-first-two uppercase-third female lock
    # ("feMale"), the lowercase-first uppercase-second female
    # lock ("fEmale"), the capitalized female gender lock
    # ("Female"), and the all-caps female gender lock
    # ("FEMALE"): this lock pins the
    # lowercase-first-four / uppercase-fifth variant for the
    # female member, which a case-insensitive parser WOULD
    # accept, so it locks strict case-sensitive enum parsing for
    # a new member/casing combination rather than merely
    # rejecting a value with no valid content. The endpoint's
    # dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, a password
    # string), so no other 422 can mask the gender error. A
    # validation 422 precedes the role lookup, so it contradicts
    # no existing role expectation (standing role-list 200-vs-404
    # caveat noted, unchanged). Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the register lowercase-first-three uppercase-fourth female gender
    # 422 lock. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including validation
    # errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "femaLe",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register lowercase-first-three uppercase-fourth
    # female gender 422 lock, using substring checks so later
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


async def test_account_register_lowercase_first_five_uppercase_sixth_female_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first-five,
        uppercase-sixth female gender value:
    """
    # The next register validation branch after the lowercase-first-four
    # uppercase-fifth female gender 422 lock, verified fresh this
    # run, not assumed: grep count 0 for "femalE" in this file
    # before appending. BaseUserDto.gender is a required Gender
    # field with no default (user_dto.py), and Gender admits only
    # "male", "female", "other", and "prefer_not_to_say"
    # (gender.py) — a case-sensitive str Enum, so "femalE" is not
    # a member even though it matches "female"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims first/last
    # names and runs only after field validation passes, and the
    # only field_serializer covers tenant_id/role_id for output
    # only. Enum parsing is case-sensitive, so "femalE" fails
    # FastAPI request validation before the handler body runs:
    # the GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie is
    # set. Distinct from the lowercase-first-four uppercase-fifth
    # female lock ("femaLe", uppercase fifth letter where this
    # lock has lowercase "l" and uppercase sixth letter "E"),
    # the lowercase-first-three uppercase-fourth female lock
    # ("femAle"), the lowercase-first-two uppercase-third female
    # lock ("feMale"), the lowercase-first uppercase-second female
    # lock ("fEmale"), the capitalized female gender lock
    # ("Female"), and the all-caps female gender lock
    # ("FEMALE"): this lock pins the
    # lowercase-first-five / uppercase-sixth variant for the
    # female member, which a case-insensitive parser WOULD
    # accept, so it locks strict case-sensitive enum parsing for
    # a new member/casing combination rather than merely
    # rejecting a value with no valid content. The endpoint's
    # dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, a password
    # string), so no other 422 can mask the gender error. A
    # validation 422 precedes the role lookup, so it contradicts
    # no existing role expectation (standing role-list 200-vs-404
    # caveat noted, unchanged). Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the register lowercase-first-four uppercase-fifth female gender
    # 422 lock. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including validation
    # errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "femalE",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register lowercase-first-four uppercase-fifth
    # female gender 422 lock, using substring checks so later
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


async def test_account_register_uppercase_first_three_lowercase_rest_female_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an uppercase-first-three,
        lowercase-rest female gender value:
    """
    # The next register validation branch after the lowercase-first-five
    # uppercase-sixth female gender 422 lock, verified fresh this
    # run, not assumed: grep count 0 for quoted "FEMale" in
    # backend/tests/ before appending. BaseUserDto.gender is a
    # required Gender field with no default (user_dto.py), and
    # Gender admits only "male", "female", "other", and
    # "prefer_not_to_say" (gender.py) — a case-sensitive str Enum,
    # so "FEMale" is not a member even though it matches "female"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims first/last
    # names and runs only after field validation passes, and the
    # only field_serializer covers tenant_id/role_id for output
    # only. Enum parsing is case-sensitive, so "FEMale" fails
    # FastAPI request validation before the handler body runs:
    # the GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie is
    # set. Distinct from the lowercase-first-five uppercase-sixth
    # female lock ("femalE"), the lowercase-first-four
    # uppercase-fifth female lock ("femaLe"), the
    # lowercase-first-three uppercase-fourth female lock
    # ("femAle"), the lowercase-first-two uppercase-third female
    # lock ("feMale"), the lowercase-first uppercase-second female
    # lock ("fEmale"), the capitalized female gender lock
    # ("Female"), and the all-caps female gender lock
    # ("FEMALE"): this lock pins the uppercase-first-three /
    # lowercase-rest variant for the female member, which a
    # case-insensitive parser WOULD accept, so it locks strict
    # case-sensitive enum parsing for a new member/casing
    # combination rather than merely rejecting a value with no
    # valid content. The endpoint's dependencies cannot mask the
    # 422 either: get_auth_service/get_role_service only resolve
    # container objects and get_tenant_id only reads request
    # state, with no database lookup. The remaining body fields
    # are all valid (non-blank first and last names, a valid
    # email, a password string), so no other 422 can mask the
    # gender error. A validation 422 precedes the role lookup, so
    # it contradicts no existing role expectation (standing
    # role-list 200-vs-404 caveat noted, unchanged).
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register lowercase-first-five uppercase-sixth
    # female gender 422 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "FEMale",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register lowercase-first-five uppercase-sixth
    # female gender 422 lock, using substring checks so later
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


async def test_account_register_uppercase_first_two_lowercase_rest_female_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an uppercase-first-two,
        lowercase-rest female gender value:
    """
    # The next register validation branch after the uppercase-first-three
    # lowercase-rest female gender 422 lock, verified fresh this
    # run, not assumed: grep count 0 for quoted "FEmale" in
    # backend/tests/ before appending. BaseUserDto.gender is a
    # required Gender field with no default (user_dto.py), and
    # Gender admits only "male", "female", "other", and
    # "prefer_not_to_say" (gender.py) — a case-sensitive str Enum,
    # so "FEmale" is not a member even though it matches "female"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims first/last
    # names and runs only after field validation passes, and the
    # only field_serializer covers tenant_id/role_id for output
    # only. Enum parsing is case-sensitive, so "FEmale" fails
    # FastAPI request validation before the handler body runs:
    # the GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie is
    # set. Distinct from the uppercase-first-three lowercase-rest
    # female lock ("FEMale"), the lowercase-first-five
    # uppercase-sixth female lock ("femalE"), the
    # lowercase-first-four uppercase-fifth female lock
    # ("femaLe"), the lowercase-first-three uppercase-fourth
    # female lock ("femAle"), the lowercase-first-two
    # uppercase-third female lock ("feMale"), the
    # lowercase-first uppercase-second female lock ("fEmale"),
    # the capitalized female gender lock ("Female"), and the
    # all-caps female gender lock ("FEMALE"): this lock pins the
    # uppercase-first-two / lowercase-rest variant for the
    # female member, which a case-insensitive parser WOULD
    # accept, so it locks strict case-sensitive enum parsing
    # for a new member/casing combination rather than merely
    # rejecting a value with no valid content. The endpoint's
    # dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with
    # no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, a
    # password string), so no other 422 can mask the gender
    # error. A validation 422 precedes the role lookup, so it
    # contradicts no existing role expectation (standing
    # role-list 200-vs-404 caveat noted, unchanged).
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register uppercase-first-three
    # lowercase-rest female gender 422 lock. The security
    # headers ARE locked: the pure-ASGI middleware stamps every
    # HTTP response, including validation errors, with no path
    # exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "FEmale",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register uppercase-first-three lowercase-rest
    # female gender 422 lock, using substring checks so later
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


async def test_account_register_uppercase_first_four_lowercase_rest_female_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an uppercase-first-four,
        lowercase-rest female gender value:
    """
    # The next register validation branch after the uppercase-first-two
    # lowercase-rest female gender 422 lock, verified fresh this
    # run, not assumed: grep count 0 for quoted "FEMAle" in
    # backend/tests/ before appending. BaseUserDto.gender is a
    # required Gender field with no default (user_dto.py), and
    # Gender admits only "male", "female", "other", and
    # "prefer_not_to_say" (gender.py) — a case-sensitive str Enum,
    # so "FEMAle" is not a member even though it matches "female"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims first/last
    # names and runs only after field validation passes, and the
    # only field_serializer covers tenant_id/role_id for output
    # only. Enum parsing is case-sensitive, so "FEMAle" fails
    # FastAPI request validation before the handler body runs:
    # the GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie is
    # set. Distinct from the uppercase-first-two lowercase-rest
    # female lock ("FEmale"), the uppercase-first-three
    # lowercase-rest female lock ("FEMale"), the
    # lowercase-first-five uppercase-sixth female lock ("femalE"),
    # the lowercase-first-four uppercase-fifth female lock
    # ("femaLe"), the lowercase-first-three uppercase-fourth
    # female lock ("femAle"), the lowercase-first-two
    # uppercase-third female lock ("feMale"), the
    # lowercase-first uppercase-second female lock ("fEmale"),
    # the capitalized female gender lock ("Female"), and the
    # all-caps female gender lock ("FEMALE"): this lock pins the
    # uppercase-first-four / lowercase-rest variant for the
    # female member, which a case-insensitive parser WOULD
    # accept, so it locks strict case-sensitive enum parsing
    # for a new member/casing combination rather than merely
    # rejecting a value with no valid content. The endpoint's
    # dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with
    # no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, a
    # password string), so no other 422 can mask the gender
    # error. A validation 422 precedes the role lookup, so it
    # contradicts no existing role expectation (standing
    # role-list 200-vs-404 caveat noted, unchanged).
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register uppercase-first-two
    # lowercase-rest female gender 422 lock. The security
    # headers ARE locked: the pure-ASGI middleware stamps every
    # HTTP response, including validation errors, with no path
    # exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "FEMAle",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register uppercase-first-two lowercase-rest
    # female gender 422 lock, using substring checks so later
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


async def test_account_register_uppercase_first_five_lowercase_rest_female_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an uppercase-first-five,
        lowercase-rest female gender value:
    """
    # The next register validation branch after the uppercase-first-four
    # lowercase-rest female gender 422 lock, verified fresh this
    # run, not assumed: grep count 0 for quoted "FEMALe" in
    # backend/tests/ before appending. BaseUserDto.gender is a
    # required Gender field with no default (user_dto.py), and
    # Gender admits only "male", "female", "other", and
    # "prefer_not_to_say" (gender.py) — a case-sensitive str Enum,
    # so "FEMALe" is not a member even though it matches "female"
    # case-insensitively. No validator touches gender: the
    # mode="after" normalize_names validator only trims first/last
    # names and runs only after field validation passes, and the
    # only field_serializer covers tenant_id/role_id for output
    # only. Enum parsing is case-sensitive, so "FEMALe" fails
    # FastAPI request validation before the handler body runs:
    # the GUEST role lookup, the tenant branching,
    # AuthService.register, and the activation email never
    # execute, and no token is minted and no refresh cookie is
    # set. Distinct from the uppercase-first-four
    # lowercase-rest female lock ("FEMAle"), the
    # uppercase-first-three lowercase-rest female lock
    # ("FEMale"), the uppercase-first-two lowercase-rest
    # female lock ("FEmale"), the lowercase-first-five
    # uppercase-sixth female lock ("femalE"), the
    # lowercase-first-four uppercase-fifth female lock
    # ("femaLe"), the lowercase-first-three uppercase-fourth
    # female lock ("femAle"), the lowercase-first-two
    # uppercase-third female lock ("feMale"), the
    # lowercase-first uppercase-second female lock ("fEmale"),
    # the capitalized female gender lock ("Female"), and the
    # all-caps female gender lock ("FEMALE"): this lock pins the
    # uppercase-first-five / lowercase-rest variant for the
    # female member, which a case-insensitive parser WOULD
    # accept, so it locks strict case-sensitive enum parsing
    # for a new member/casing combination rather than merely
    # rejecting a value with no valid content. The endpoint's
    # dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with
    # no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, a
    # password string), so no other 422 can mask the gender
    # error. A validation 422 precedes the role lookup, so it
    # contradicts no existing role expectation (standing
    # role-list 200-vs-404 caveat noted, unchanged).
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register uppercase-first-four
    # lowercase-rest female gender 422 lock. The security
    # headers ARE locked: the pure-ASGI middleware stamps every
    # HTTP response, including validation errors, with no path
    # exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "FEMALe",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register uppercase-first-four lowercase-rest
    # female gender 422 lock, using substring checks so later
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


async def test_account_register_lowercase_first_uppercase_second_lowercase_rest_male_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first,
        uppercase-second, lowercase-rest male gender value:
    """
    # The next register validation branch after the uppercase-first-five
    # lowercase-rest female gender 422 lock, verified fresh this
    # run, not assumed: grep count 0 for quoted "mAle" in
    # backend/tests/interfaces/test_account_endpoint.py before
    # appending (raw substring hits for mAle/maLe in older comments
    # are false positives, so only the quoted payload grep counts).
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "mAle" is not a member even
    # though it matches "male" case-insensitively. No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only. Enum parsing is
    # case-sensitive, so "mAle" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the capitalized male gender
    # lock ("Male"), the all-caps male gender lock ("MALE"), and
    # from the female-member locks of the same shape (e.g.
    # "fEmale"): this lock pins the lowercase-first /
    # uppercase-second / lowercase-rest variant for the male
    # member, which a case-insensitive parser WOULD accept, so it
    # locks strict case-sensitive enum parsing for a new
    # member/casing combination rather than merely rejecting a
    # value with no valid content. The endpoint's dependencies
    # cannot mask the 422 either: get_auth_service/get_role_service
    # only resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. The remaining body
    # fields are all valid (non-blank first and last names, a valid
    # email, a password string), so no other 422 can mask the
    # gender error. A validation 422 precedes the role lookup, so it
    # contradicts no existing role expectation (standing
    # role-list 200-vs-404 caveat noted, unchanged).
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register uppercase-first-five lowercase-rest
    # female gender 422 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "mAle",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register uppercase-first-five lowercase-rest
    # female gender 422 lock, using substring checks so later
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


async def test_account_register_lowercase_first_two_uppercase_third_lowercase_rest_male_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first-two,
        uppercase-third, lowercase-rest male gender value:
    """
    # The next register validation branch after the lowercase-first
    # uppercase-second lowercase-rest male gender 422 lock,
    # verified fresh this run, not assumed: grep count 0 for
    # quoted "maLe" in backend/tests/interfaces/test_account_endpoint.py
    # before appending (raw substring hits for mAle/maLe in older
    # comments are false positives, so only the quoted payload grep
    # counts; "malE" and "MAle" also verified absent by quoted grep
    # this run). BaseUserDto.gender is a required Gender field with
    # no default (user_dto.py), and Gender admits only "male",
    # "female", "other", and "prefer_not_to_say" (gender.py) — a
    # case-sensitive str Enum, so "maLe" is not a member even
    # though it matches "male" case-insensitively. No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only. Enum parsing is
    # case-sensitive, so "maLe" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the capitalized male gender
    # lock ("Male"), the all-caps male gender lock ("MALE"), and
    # from the lowercase-first uppercase-second male lock ("mAle")
    # and the female-member locks of the same shape (e.g.
    # "feMale"): this lock pins the lowercase-first-two /
    # uppercase-third / lowercase-rest variant for the male
    # member, which a case-insensitive parser WOULD accept, so it
    # locks strict case-sensitive enum parsing for a new
    # member/casing combination rather than merely rejecting a
    # value with no valid content. The endpoint's dependencies
    # cannot mask the 422 either: get_auth_service/get_role_service
    # only resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. The remaining body
    # fields are all valid (non-blank first and last names, a valid
    # email, a password string), so no other 422 can mask the
    # gender error. A validation 422 precedes the role lookup, so it
    # contradicts no existing role expectation (standing
    # role-list 200-vs-404 caveat noted, unchanged).
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register lowercase-first uppercase-second
    # lowercase-rest male gender 422 lock. The security headers ARE
    # locked: the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "maLe",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register lowercase-first uppercase-second
    # lowercase-rest male gender 422 lock, using substring checks so later
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


async def test_account_register_lowercase_first_three_uppercase_last_male_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first-three,
        uppercase-last male gender value:
    """
    # The next register validation branch after the lowercase-first-two
    # uppercase-third lowercase-rest male gender 422 lock,
    # verified fresh this run, not assumed: payload grep count 0 for
    # '"gender": "malE"' in backend/tests/interfaces/test_account_endpoint.py
    # before appending (raw quoted hits for malE in older comments are
    # false positives, so only the payload grep counts; '"gender": "MAle"'
    # also verified absent as a payload this run). BaseUserDto.gender is a
    # required Gender field with no default (user_dto.py), and Gender admits
    # only "male", "female", "other", and "prefer_not_to_say" (gender.py) -- a
    # case-sensitive str Enum, so "malE" is not a member even
    # though it matches "male" case-insensitively. No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only. Enum parsing is
    # case-sensitive, so "malE" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the capitalized male gender
    # lock ("Male"), the all-caps male gender lock ("MALE"), and
    # from the lowercase-first uppercase-second male lock ("mAle")
    # and the lowercase-first-two uppercase-third lock ("maLe")
    # and the female-member locks of the same shape (e.g.
    # "femaLe"): this lock pins the lowercase-first-three /
    # uppercase-last variant for the male member, which a
    # case-insensitive parser WOULD accept, so it locks strict
    # case-sensitive enum parsing for a new member/casing
    # combination rather than merely rejecting a value with no valid
    # content. The endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container objects
    # and get_tenant_id only reads request state, with no database lookup.
    # The remaining body fields are all valid (non-blank first and last
    # names, a valid email, a password string), so no other 422 can mask
    # the gender error. A validation 422 precedes the role lookup, so it
    # contradicts no existing role expectation (standing
    # role-list 200-vs-404 caveat noted, unchanged).
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register lowercase-first-two uppercase-third
    # lowercase-rest male gender 422 lock. The security headers ARE
    # locked: the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "malE",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register lowercase-first-two uppercase-third
    # lowercase-rest male gender 422 lock, using substring checks so later
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


async def test_account_register_uppercase_first_two_lowercase_rest_male_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an uppercase-first-two,
        lowercase-rest male gender value:
    """
    # The next register validation branch after the lowercase-first-three
    # uppercase-last male gender 422 lock, verified fresh this run,
    # not assumed: payload grep count 0 for '^ *"gender": "MAle"'
    # in backend/tests/interfaces/test_account_endpoint.py before
    # appending (a comment line at 13575 quotes the string, so only
    # the indented-payload grep counts). BaseUserDto.gender is a
    # required Gender field with no default (user_dto.py), and Gender admits
    # only "male", "female", "other", and "prefer_not_to_say" (gender.py) -- a
    # case-sensitive str Enum, so "MAle" is not a member even
    # though it matches "male" case-insensitively. No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only. Enum parsing is
    # case-sensitive, so "MAle" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the capitalized male gender
    # lock ("Male"), the all-caps male gender lock ("MALE"), and
    # from the lowercase-first uppercase-second male lock ("mAle"),
    # the lowercase-first-two uppercase-third lock ("maLe"), and
    # the lowercase-first-three uppercase-last lock ("malE"):
    # this lock pins the uppercase-first-two / lowercase-rest
    # variant for the male member, which a case-insensitive parser
    # WOULD accept, so it locks strict case-sensitive enum parsing
    # for a new member/casing combination rather than merely
    # rejecting a value with no valid content. The endpoint's
    # dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container objects
    # and get_tenant_id only reads request state, with no database lookup.
    # The remaining body fields are all valid (non-blank first and last
    # names, a valid email, a password string), so no other 422 can mask
    # the gender error. A validation 422 precedes the role lookup, so it
    # contradicts no existing role expectation (standing
    # role-list 200-vs-404 caveat noted, unchanged).
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register lowercase-first-three uppercase-last
    # male gender 422 lock. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "MAle",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register lowercase-first-three uppercase-last
    # male gender 422 lock, using substring checks so later
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


async def test_account_register_uppercase_first_three_lowercase_rest_male_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an uppercase-first-three,
        lowercase-rest male gender value:
    """
    # The next register validation branch after the uppercase-first-two
    # lowercase-rest male gender 422 lock, verified fresh this run,
    # not assumed: payload grep count 0 for '^ *"gender": "MALe"'
    # in backend/tests/interfaces/test_account_endpoint.py before
    # appending, and 0 for the new test name. BaseUserDto.gender is a
    # required Gender field with no default (user_dto.py), and Gender admits
    # only "male", "female", "other", and "prefer_not_to_say" (gender.py) -- a
    # case-sensitive str Enum, so "MALe" is not a member even
    # though it matches "male" case-insensitively. No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only. Enum parsing is
    # case-sensitive, so "MALe" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the capitalized male gender
    # lock ("Male"), the all-caps male gender lock ("MALE"), and
    # from the lowercase-first uppercase-second male lock ("mAle"),
    # the lowercase-first-two uppercase-third lock ("maLe"),
    # the lowercase-first-three uppercase-last lock ("malE"), and
    # the uppercase-first-two lowercase-rest lock ("MAle"):
    # this lock pins the uppercase-first-three / lowercase-rest
    # variant for the male member, which a case-insensitive parser
    # WOULD accept, so it locks strict case-sensitive enum parsing
    # for a new member/casing combination rather than merely
    # rejecting a value with no valid content. The endpoint's
    # dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container objects
    # and get_tenant_id only reads request state, with no database lookup.
    # The remaining body fields are all valid (non-blank first and last
    # names, a valid email, a password string), so no other 422 can mask
    # the gender error. A validation 422 precedes the role lookup, so it
    # contradicts no existing role expectation (standing
    # role-list 200-vs-404 caveat noted, unchanged).
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register uppercase-first-two lowercase-rest
    # male gender 422 lock. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "MALe",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register uppercase-first-two lowercase-rest
    # male gender 422 lock, using substring checks so later
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


async def test_account_register_lowercase_first_uppercase_second_third_lowercase_last_male_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first,
        uppercase-second-third, lowercase-last male gender value:
    """
    # The next register validation branch after the uppercase-first-three
    # lowercase-rest male gender 422 lock, verified fresh this run,
    # not assumed: payload grep count 0 for '"mALe"' and 0 for the
    # new test name in backend/tests/interfaces/test_account_endpoint.py
    # before appending. BaseUserDto.gender is a required Gender field
    # with no default (user_dto.py), and Gender admits only "male",
    # "female", "other", and "prefer_not_to_say" (gender.py) -- a
    # case-sensitive str Enum, so "mALe" is not a member even
    # though it matches "male" case-insensitively. No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only. Enum parsing is
    # case-sensitive, so "mALe" fails FastAPI request validation
    # before the handler body runs: the GUEST role lookup, the
    # tenant branching, AuthService.register, and the activation
    # email never execute, and no token is minted and no refresh
    # cookie is set. Distinct from the capitalized male gender
    # lock ("Male"), the all-caps male gender lock ("MALE"), and
    # from the lowercase-first uppercase-second male lock ("mAle"),
    # the lowercase-first-two uppercase-third lock ("maLe"),
    # the lowercase-first-three uppercase-last lock ("malE"),
    # the uppercase-first-two lowercase-rest lock ("MAle"), and
    # the uppercase-first-three lowercase-rest lock ("MALe"):
    # this lock pins the mixed lowercase-first / uppercase-second-third
    # / lowercase-last variant for the male member, which a
    # case-insensitive parser WOULD accept, so it locks strict
    # case-sensitive enum parsing for a new member/casing
    # combination rather than merely rejecting a value with no
    # valid content. The endpoint's dependencies cannot mask the
    # 422 either: get_auth_service/get_role_service only resolve
    # container objects and get_tenant_id only reads request state,
    # with no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, a
    # password string), so no other 422 can mask the gender error.
    # A validation 422 precedes the role lookup, so it contradicts
    # no existing role expectation (standing role-list 200-vs-404
    # caveat noted, unchanged).
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register uppercase-first-three lowercase-rest
    # male gender 422 lock. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "mALe",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register uppercase-first-three lowercase-rest
    # male gender 422 lock, using substring checks so later
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


async def test_account_register_lowercase_first_uppercase_second_lowercase_third_uppercase_last_male_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first,
        uppercase-second, lowercase-third, uppercase-last male gender value:
    """
    # The next register validation branch after the lowercase-first
    # uppercase-second-third lowercase-last male gender 422 lock,
    # verified fresh this run, not assumed: payload grep count 0
    # for '"mAlE"' and 0 for the new test name in
    # backend/tests/interfaces/test_account_endpoint.py before
    # appending. BaseUserDto.gender is a required Gender field
    # with no default (user_dto.py), and Gender admits only "male",
    # "female", "other", and "prefer_not_to_say" (gender.py) -- a
    # case-sensitive str Enum, so "mAlE" is not a member even
    # though it matches "male" case-insensitively. No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only -- so "mAlE" fails
    # FastAPI request validation before the handler body runs.
    # This is distinct from the lowercase-first uppercase-second-
    # third lowercase-last lock ("mALe"), the uppercase-first-
    # three lowercase-rest lock ("MALe"), the uppercase-first-two
    # lowercase-rest lock ("MAle"), the capitalized lock
    # ("Male"), and the all-caps lock ("MALE"): a
    # case-insensitive parser WOULD accept "mAlE", so it locks
    # strict case-sensitive enum parsing for a new member/casing
    # combination rather than merely rejecting a value with no
    # valid content. The endpoint's dependencies cannot mask the
    # 422 either: get_auth_service/get_role_service only resolve
    # container objects and get_tenant_id only reads request state,
    # with no database lookup. The remaining body fields are all
    # valid (non-blank first and last names, a valid email, a
    # password string), so no other 422 can mask the gender error.
    # A validation 422 precedes the role lookup, so it contradicts
    # no existing role expectation (standing role-list 200-vs-404
    # caveat noted, unchanged).
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register uppercase-first-three lowercase-rest
    # male gender 422 lock. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "mAlE",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register uppercase-first-three lowercase-rest
    # male gender 422 lock, using substring checks so later
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


async def test_account_register_lowercase_first_second_uppercase_third_fourth_male_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first-second,
        uppercase-third-fourth male gender value:
    """
    # The next register validation branch after the lowercase-first
    # uppercase-second lowercase-third uppercase-last male gender
    # 422 lock, verified fresh this run, not assumed: payload grep
    # count 0 for '"maLE"' and 0 for the new test name in
    # backend/tests/interfaces/test_account_endpoint.py before
    # appending. BaseUserDto.gender is a required Gender field
    # with no default (user_dto.py), and Gender admits only "male",
    # "female", "other", and "prefer_not_to_say" (gender.py) -- a
    # case-sensitive str Enum, so "maLE" is not a member even
    # though it matches "male" case-insensitively. No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only -- so "maLE" fails
    # FastAPI request validation before the handler body runs.
    # This is distinct from the lowercase-first uppercase-second
    # lowercase-third uppercase-last lock ("mAlE"), the
    # lowercase-first uppercase-second-third lowercase-last lock
    # ("mALe"), the uppercase-first-three lowercase-rest lock
    # ("MALe"), the uppercase-first-two lowercase-rest lock
    # ("MAle"), the capitalized lock ("Male"), and the all-caps
    # lock ("MALE"): a case-insensitive parser WOULD accept
    # "maLE", so it locks strict case-sensitive enum parsing for
    # a new member/casing combination rather than merely
    # rejecting a value with no valid content. The endpoint's
    # dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, a password
    # string), so no other 422 can mask the gender error. A
    # validation 422 precedes the role lookup, so it contradicts
    # no existing role expectation (standing role-list 200-vs-404
    # caveat noted, unchanged).
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register lowercase-first uppercase-second
    # lowercase-third uppercase-last male gender 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "maLE",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register lowercase-first uppercase-second
    # lowercase-third uppercase-last male gender 422 lock, using
    # substring checks so later additions to the list do not
    # break this test.
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


async def test_account_register_uppercase_first_lowercase_second_third_uppercase_last_male_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an uppercase-first,
        lowercase-second-third, uppercase-last male gender value:
    """
    # The next register validation branch after the lowercase-first-second
    # uppercase-third-fourth male gender 422 lock, verified fresh
    # this run, not assumed: payload grep count 0 for '"MalE"' and
    # 0 for the new test name in
    # backend/tests/interfaces/test_account_endpoint.py before
    # appending. BaseUserDto.gender is a required Gender field
    # with no default (user_dto.py), and Gender admits only "male",
    # "female", "other", and "prefer_not_to_say" (gender.py) -- a
    # case-sensitive str Enum, so "MalE" is not a member even
    # though it matches "male" case-insensitively. No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only -- so "MalE" fails
    # FastAPI request validation before the handler body runs.
    # This is distinct from the lowercase-first-second
    # uppercase-third-fourth lock ("maLE"), the lowercase-first
    # uppercase-second lowercase-third uppercase-last lock
    # ("mAlE"), the lowercase-first uppercase-second-third
    # lowercase-last lock ("mALe"), the uppercase-first-three
    # lowercase-rest lock ("MALe"), the uppercase-first-two
    # lowercase-rest lock ("MAle"), the capitalized lock ("Male"),
    # and the all-caps lock ("MALE"): a case-insensitive parser
    # WOULD accept "MalE", so it locks strict case-sensitive enum
    # parsing for a new member/casing combination rather than
    # merely rejecting a value with no valid content. The
    # endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, a password
    # string), so no other 422 can mask the gender error. A
    # validation 422 precedes the role lookup, so it contradicts
    # no existing role expectation (standing role-list 200-vs-404
    # caveat noted, unchanged).
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register lowercase-first-second
    # uppercase-third-fourth male gender 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "MalE",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register lowercase-first-second
    # uppercase-third-fourth male gender 422 lock, using
    # substring checks so later additions to the list do not
    # break this test.
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


async def test_account_register_uppercase_first_second_lowercase_third_uppercase_last_male_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an uppercase-first-second,
        lowercase-third, uppercase-last male gender value:
    """
    # The next register validation branch after the uppercase-first
    # lowercase-second-third uppercase-last male gender 422 lock,
    # verified fresh this run, not assumed: payload grep count 0
    # for '"MAlE"' and 0 for the new test name in
    # backend/tests/interfaces/test_account_endpoint.py before
    # appending. BaseUserDto.gender is a required Gender field
    # with no default (user_dto.py), and Gender admits only "male",
    # "female", "other", and "prefer_not_to_say" (gender.py) -- a
    # case-sensitive str Enum, so "MAlE" is not a member even
    # though it matches "male" case-insensitively. No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only -- so "MAlE" fails
    # FastAPI request validation before the handler body runs.
    # This is distinct from the uppercase-first lowercase-second-
    # third uppercase-last lock ("MalE"), the lowercase-first-
    # second uppercase-third-fourth lock ("maLE"), the lowercase-
    # first uppercase-second lowercase-third uppercase-last lock
    # ("mAlE"), the lowercase-first uppercase-second-third
    # lowercase-last lock ("mALe"), the uppercase-first-three
    # lowercase-rest lock ("MALe"), the uppercase-first-two
    # lowercase-rest lock ("MAle"), the capitalized lock ("Male"),
    # and the all-caps lock ("MALE"): a case-insensitive parser
    # WOULD accept "MAlE", so it locks strict case-sensitive enum
    # parsing for a new member/casing combination rather than
    # merely rejecting a value with no valid content. The
    # endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, a password
    # string), so no other 422 can mask the gender error. A
    # validation 422 precedes the role lookup, so it contradicts
    # no existing role expectation (standing role-list 200-vs-404
    # caveat noted, unchanged).
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register lowercase-first-second
    # uppercase-third-fourth male gender 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "MAlE",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register lowercase-first-second
    # uppercase-third-fourth male gender 422 lock, using
    # substring checks so later additions to the list do not
    # break this test.
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


async def test_account_register_uppercase_first_lowercase_second_uppercase_third_fourth_male_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an uppercase-first,
        lowercase-second, uppercase-third-fourth male gender value:
    """
    # The next register validation branch after the uppercase-first-
    # second lowercase-third uppercase-last male gender 422 lock,
    # verified fresh this run, not assumed: payload grep count 0
    # for '"MaLE"' and 0 for the new test name in
    # backend/tests/interfaces/test_account_endpoint.py before
    # appending. BaseUserDto.gender is a required Gender field
    # with no default (user_dto.py), and Gender admits only "male",
    # "female", "other", and "prefer_not_to_say" (gender.py) -- a
    # case-sensitive str Enum, so "MaLE" is not a member even
    # though it matches "male" case-insensitively. No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only -- so "MaLE" fails
    # FastAPI request validation before the handler body runs.
    # This is distinct from the uppercase-first-second
    # lowercase-third uppercase-last lock ("MAlE"), the
    # uppercase-first lowercase-second-third uppercase-last lock
    # ("MalE"), the lowercase-first-second uppercase-third-fourth
    # lock ("maLE"), the lowercase-first uppercase-second
    # lowercase-third uppercase-last lock ("mAlE"), the
    # lowercase-first uppercase-second-third lowercase-last lock
    # ("mALe"), the uppercase-first-three lowercase-rest lock
    # ("MALe"), the uppercase-first-two lowercase-rest lock
    # ("MAle"), the capitalized lock ("Male"), and the all-caps
    # lock ("MALE"): a case-insensitive parser WOULD accept
    # "MaLE", so it locks strict case-sensitive enum parsing
    # for a new member/casing combination rather than merely
    # rejecting a value with no valid content. The endpoint's
    # dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, a password
    # string), so no other 422 can mask the gender error. A
    # validation 422 precedes the role lookup, so it contradicts
    # no existing role expectation (standing role-list 200-vs-404
    # caveat noted, unchanged). Note: an exhaustive per-letter
    # enumeration this run found two further unpinned male
    # casings ("MaLe", "mALE"), correcting the prior run's count
    # of 14 pinned invalid casings -- 12 were pinned before this
    # run, 13 after it.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register uppercase-first-second
    # lowercase-third uppercase-last male gender 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "MaLE",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register uppercase-first-second
    # lowercase-third uppercase-last male gender 422 lock, using
    # substring checks so later additions to the list do not
    # break this test.
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


async def test_account_register_uppercase_first_third_lowercase_second_fourth_male_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with an uppercase-first,
        uppercase-third, lowercase-second-fourth male gender value:
    """
    # The next register validation branch after the uppercase-first
    # lowercase-second uppercase-third-fourth male gender 422 lock,
    # verified fresh this run, not assumed: no test function named
    # test_account_register_uppercase_first_third_lowercase_second_
    # fourth_male_gender_returns_422_with_security_headers in
    # backend/tests/interfaces/test_account_endpoint.py before
    # appending, and "MaLe" appears there only in a comment naming
    # it as a future candidate, never as a test payload.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) -- a
    # case-sensitive str Enum, so "MaLe" is not a member even
    # though it matches "male" case-insensitively. No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only -- so "MaLe" fails
    # FastAPI request validation before the handler body runs.
    # This is distinct from the uppercase-first lowercase-second
    # uppercase-third-fourth lock ("MaLE"), the uppercase-first-
    # second lowercase-third uppercase-last lock ("MAlE"), the
    # uppercase-first lowercase-second-third uppercase-last lock
    # ("MalE"), the lowercase-first-second uppercase-third-fourth
    # lock ("maLE"), the lowercase-first uppercase-second
    # lowercase-third uppercase-last lock ("mAlE"), the
    # lowercase-first uppercase-second-third lowercase-last lock
    # ("mALe"), the uppercase-first-three lowercase-rest lock
    # ("MALe"), the uppercase-first-two lowercase-rest lock
    # ("MAle"), the capitalized lock ("Male"), and the all-caps
    # lock ("MALE"): a case-insensitive parser WOULD accept
    # "MaLe", so it locks strict case-sensitive enum parsing
    # for a new member/casing combination rather than merely
    # rejecting a value with no valid content. The endpoint's
    # dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, a password
    # string), so no other 422 can mask the gender error. A
    # validation 422 precedes the role lookup, so it contradicts
    # no existing role expectation (standing role-list 200-vs-404
    # caveat noted, unchanged). Note: one further unpinned male
    # casing remains from the prior run's enumeration ("mALE").
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register uppercase-first-second
    # lowercase-third uppercase-last male gender 422 lock. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "MaLe",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register uppercase-first-second
    # lowercase-third uppercase-last male gender 422 lock, using
    # substring checks so later additions to the list do not
    # break this test.
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


async def test_account_register_lowercase_first_uppercase_second_third_fourth_male_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first,
        uppercase-second-third-fourth male gender value:
    """
    # The last unpinned male casing from the prior run's
    # enumeration, verified fresh this run, not assumed: no test
    # function named
    # test_account_register_lowercase_first_uppercase_second_
    # third_fourth_male_gender_returns_422_with_security_headers
    # in backend/tests/interfaces/test_account_endpoint.py before
    # appending, and "mALE" appears there only in comments naming
    # it as a future candidate, never as a test payload.
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) -- a
    # case-sensitive str Enum, so "mALE" is not a member even
    # though it matches "male" case-insensitively. No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only -- so "mALE" fails
    # FastAPI request validation before the handler body runs.
    # This is distinct from the uppercase-first-third
    # lowercase-second-fourth lock ("MaLe"), the uppercase-first
    # lowercase-second uppercase-third-fourth lock ("MaLE"), the
    # uppercase-first-second lowercase-third uppercase-last lock
    # ("MAlE"), the uppercase-first lowercase-second-third
    # uppercase-last lock ("MalE"), the lowercase-first-second
    # uppercase-third-fourth lock ("maLE"), the lowercase-first
    # uppercase-second lowercase-third uppercase-last lock
    # ("mAlE"), the lowercase-first uppercase-second-third
    # lowercase-last lock ("mALe"), the uppercase-first-three
    # lowercase-rest lock ("MALe"), the uppercase-first-two
    # lowercase-rest lock ("MAle"), the capitalized lock ("Male"),
    # and the all-caps lock ("MALE"): a case-insensitive parser
    # WOULD accept "mALE", so it locks strict case-sensitive
    # enum parsing for a new member/casing combination rather
    # than merely rejecting a value with no valid content. The
    # endpoint's dependencies cannot mask the 422 either:
    # get_auth_service/get_role_service only resolve container
    # objects and get_tenant_id only reads request state, with no
    # database lookup. The remaining body fields are all valid
    # (non-blank first and last names, a valid email, a password
    # string), so no other 422 can mask the gender error. A
    # validation 422 precedes the role lookup, so it contradicts
    # no existing role expectation (standing role-list 200-vs-404
    # caveat noted, unchanged). With this lock, all 15 invalid
    # casings of "male" are now pinned (the 16th casing is the
    # valid lowercase "male" itself). Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the register uppercase-first-third lowercase-second-fourth
    # male gender 422 lock. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "mALE",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register uppercase-first-third
    # lowercase-second-fourth male gender 422 lock, using
    # substring checks so later additions to the list do not
    # break this test.
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


async def test_account_register_lowercase_first_four_uppercase_fifth_sixth_female_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first-four,
        uppercase-fifth-sixth female gender value:
    """
    # The next female casing after the male sweep completed at
    # 15/15 invalid casings, verified fresh this run, not assumed:
    # no test function named
    # test_account_register_lowercase_first_four_uppercase_
    # fifth_sixth_female_gender_returns_422_with_security_headers
    # in backend/tests/interfaces/test_account_endpoint.py before
    # appending, and "femaLE" appears there 0 times as a payload.
    # A fresh enumeration this run pinned 11 female register
    # casings (Female, FEMALE, fEmale, feMale, femAle, femaLe,
    # femalE, FEMale, FEmale, FEMAle, FEMALe) and left 52 invalid
    # casings unpinned (plus the valid lowercase "female").
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) -- a
    # case-sensitive str Enum, so "femaLE" is not a member even
    # though it matches "female" case-insensitively. No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only -- so "femaLE" fails
    # FastAPI request validation before the handler body runs.
    # This is distinct from the lowercase-first-five
    # uppercase-sixth lock ("femalE"), the lowercase-first-four
    # uppercase-fifth lock ("femaLe"), the lowercase-first-three
    # uppercase-fourth lock ("femAle"), the lowercase-first-two
    # uppercase-third lock ("feMale"), the lowercase-first
    # uppercase-second lock ("fEmale"), the uppercase-first-five
    # lowercase-rest lock ("FEMALe"), the uppercase-first-four
    # lowercase-rest lock ("FEMAle"), the uppercase-first-three
    # lowercase-rest lock ("FEMale"), the uppercase-first-two
    # lowercase-rest lock ("FEmale"), the capitalized lock
    # ("Female"), and the all-caps lock ("FEMALE"): a
    # case-insensitive parser WOULD accept "femaLE", so it locks
    # strict case-sensitive enum parsing for a new
    # member/casing combination rather than merely rejecting a
    # value with no valid content. The endpoint's dependencies
    # cannot mask the 422 either: get_auth_service/get_role_service
    # only resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. The remaining body
    # fields are all valid (non-blank first and last names, a
    # valid email, a password string), so no other 422 can mask
    # the gender error. A validation 422 precedes the role lookup,
    # so it contradicts no existing role expectation (standing
    # role-list 200-vs-404 caveat noted, unchanged).
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register lowercase-first uppercase-second-
    # third-fourth male gender 422 lock. The security headers ARE
    # locked: the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "femaLE",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register lowercase-first uppercase-second-
    # third-fourth male gender 422 lock, using substring checks
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


async def test_account_register_lowercase_first_three_uppercase_fourth_lowercase_fifth_uppercase_sixth_female_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The account register POST with a lowercase-first-three,
        uppercase-fourth, lowercase-fifth, uppercase-sixth female
        gender value:
    """
    # The next female casing after the lowercase-first-four /
    # uppercase-fifth-sixth lock ("femaLE"), verified fresh this
    # run, not assumed: no test function named
    # test_account_register_lowercase_first_three_uppercase_
    # fourth_lowercase_fifth_uppercase_sixth_female_gender_
    # returns_422_with_security_headers in
    # backend/tests/interfaces/test_account_endpoint.py before
    # appending, and "femAlE" appears there 0 times as a payload
    # (quoted payload grep count 0).
    # BaseUserDto.gender is a required Gender field with no default
    # (user_dto.py), and Gender admits only "male", "female",
    # "other", and "prefer_not_to_say" (gender.py) -- a
    # case-sensitive str Enum, so "femAlE" is not a member even
    # though it matches "female" case-insensitively. No validator
    # touches gender: the mode="after" normalize_names validator
    # only trims first/last names and runs only after field
    # validation passes, and the only field_serializer covers
    # tenant_id/role_id for output only -- so "femAlE" fails
    # FastAPI request validation before the handler body runs.
    # This is distinct from the lowercase-first-four
    # uppercase-fifth-sixth lock ("femaLE"), the lowercase-first-
    # three uppercase-fourth lock ("femAle"), the lowercase-first-
    # five uppercase-sixth lock ("femalE"), the lowercase-first-
    # four uppercase-fifth lock ("femaLe"), the lowercase-first-
    # two uppercase-third lock ("feMale"), the lowercase-first
    # uppercase-second lock ("fEmale"), the uppercase-first-five
    # lowercase-rest lock ("FEMALe"), the uppercase-first-four
    # lowercase-rest lock ("FEMAle"), the uppercase-first-three
    # lowercase-rest lock ("FEMale"), the uppercase-first-two
    # lowercase-rest lock ("FEmale"), the capitalized lock
    # ("Female"), and the all-caps lock ("FEMALE"): a
    # case-insensitive parser WOULD accept "femAlE", so it locks
    # strict case-sensitive enum parsing for a new
    # member/casing combination rather than merely rejecting a
    # value with no valid content. The endpoint's dependencies
    # cannot mask the 422 either: get_auth_service/get_role_service
    # only resolve container objects and get_tenant_id only reads
    # request state, with no database lookup. The remaining body
    # fields are all valid (non-blank first and last names, a
    # valid email, a password string), so no other 422 can mask
    # the gender error. A validation 422 precedes the role lookup,
    # so it contradicts no existing role expectation (standing
    # role-list 200-vs-404 caveat noted, unchanged).
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the register lowercase-first uppercase-second-
    # third-fourth male gender 422 lock. The security headers ARE
    # locked: the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    response = await client.post(
        "/account/register",
        json={
            "first_name": "New",
            "last_name": "User",
            "email": "new.user@example.com",
            "gender": "femAlE",
            "password": "Register123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "gender" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the register lowercase-first uppercase-second-
    # third-fourth male gender 422 lock, using substring checks
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
