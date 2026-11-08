import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_get_audit_logs_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The audit-logs GET:
    """
    # The audit-logs area had no interface test file at all, so
    # deleting the audit-logs router from api/__init__.py — or
    # dropping the central ApiBaseException no-store lines or the
    # security-headers middleware registration — would previously
    # have gone uncaught here even though every other interface
    # area locks its headers in. The success path is not asserted
    # here: the GET is permission-gated (AUDIT_LOGS_VIEW_ONLY via
    # a router-level dependency), so it needs a DB role lookup,
    # and the shared conftest client seeds no role — the features
    # test documents the same exclusion for its endpoint. The
    # error path below is deterministic instead: the mocked host
    # user's role_id points at no row in the fresh test database
    # (Role is in the conftest model set), so the permission
    # dependency raises RoleNotFoundException before the handler
    # runs, and the central ApiBaseException handler turns it
    # into a 404. That 404 must still carry the error-response
    # headers: audit entries are tenant-scoped admin data, so a
    # cached 404 could otherwise be served to a different admin
    # after an account switch on a shared machine.
    response = await client.get("/audit-logs/")
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the features test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the audit-logs 404 must carry the same
    # headers as the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the features lock, using substring checks so later additions
    # to the list do not break this test. The full value lives in
    # _SECURITY_HEADERS. Each directive is safe to lock here for
    # the same reasons as on the other routes: the SPA has no
    # camera, microphone, geolocation, payment, clipboard-read,
    # display-capture, fullscreen, motion-sensor, compass, XR, or
    # idle-detection flow (verified by grep in the earlier sweeps:
    # zero IdleDetector/requestIdleCallback matches and zero
    # case-insensitive idle matches across frontend/app/src, and
    # the remaining flows verified absent).
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
async def test_post_audit_logs_download_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        Second path for the audit-logs area: the existing test above
    locks only the GET list route. The POST /download route is a
    separate handler with its own extra AUDIT_LOGS_DOWNLOAD
    permission dependency, and deleting just that route — or
    dropping the central no-store lines — would previously have
    gone uncaught even though the list route stayed locked. The
    success path is not asserted here: it would trigger a Celery
    download report (and an email), which tests must never send.
    The error path below is deterministic instead, for the same
    reason as the GET: the router-level AUDIT_LOGS_VIEW_ONLY
    dependency runs before the handler (and before the download
    permission dependency), and the mocked host user's role_id
    points at no row in the fresh test database, so it raises
    RoleNotFoundException before any download is queued, and the
    central ApiBaseException handler turns it into a 404. The
    body is valid (total_records > 0) so validation cannot mask
    the permission path with a 422. That 404 must still carry
    the error-response headers, for the same shared-machine
    cache reason as the GET.
    """
    response = await client.post("/audit-logs/download", json={"total_records": 5})
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the audit-logs GET test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the download 404 must carry the same
    # headers as the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the audit-logs GET lock, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the GET:
    # the SPA has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen, motion-sensor,
    # compass, XR, or idle-detection flow (re-verified fresh this
    # run: zero IdleDetector/requestIdleCallback matches and zero
    # case-insensitive idle matches across frontend/app/src).
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
async def test_get_audit_logs_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The audit-logs list scope-guard error path:
    """
    # The audit-logs scope-guard branch, not yet locked:
    # function-name grep count 0 for
    # get_audit_logs_outside_tenant_scope (verified fresh this
    # run), and no test in this file asserts a 403 at all - the
    # locks cover only the missing-role 404s on the GET list and
    # POST /download paths. Deleting _assert_audit_logs_scope
    # (audit_logs_endpoint.py) would previously have gone
    # uncaught, and a tenant caller reading on the host DB (no
    # X-Tenant-ID/subdomain) would then read tenant-stamped audit
    # entries sitting in the host DB - another tenant's audit
    # trail presented as their own. The guard runs in the handler
    # body, after the AUDIT_LOGS_VIEW_ONLY router-level permission
    # dependency, so the gate must be satisfied first: the shared
    # conftest mock points at role id 68c302ef6bf7a039b7e9b386 with
    # no row in the fresh test database, which is why the 404
    # locks fail there. Seeding that exact id carrying
    # AUDIT_LOGS_VIEW_ONLY, mirroring the users list 403 seed
    # precedent, lets the dependency pass: get_role_by_id is
    # called with no tenant filter, and _caller_may_access
    # returns True for a host-stamped row when the caller tenant
    # is None (role_service.py:18-19), so the seeded row is
    # visible regardless of the caller's tenant scope. The
    # caller is then made tenant-scoped by swapping in a
    # per-test MeResponseDto override (tenant_id set),
    # mirroring the users list 403 lock's override pattern, and
    # restored in finally so no other test's mock is affected.
    # With no X-Tenant-ID header the tenant middleware resolves
    # host scope, so request_tenant_id is None and the guard
    # raises ForbiddenException before any read runs - no side
    # effect, and the default limit/skip query values pass
    # validation, so no 422 can mask the 403. The central
    # ApiBaseException handler maps ForbiddenException to 403
    # (api/__init__.py:98-103) with {"error": ..., "code": 403}
    # and the no-store/Pragma error headers, since the handler
    # sets them only after the guard. A future change that drops
    # the guard would break this lock while leaving the
    # missing-role 404 lock green, so the two paths are locked
    # separately.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant audit log viewer",
        description="Role carrying AUDIT_LOGS_VIEW_ONLY for the mocked caller",
        permissions=[Permission.AUDIT_LOGS_VIEW_ONLY],
    ).insert()

    async def override_get_current_user_tenant_scoped():
        return MeResponseDto(
            first_name="Admin",
            last_name="User",
            id="68c302ef6bf7a039b7e9b385",
            email="admin@example.com",
            gender=Gender.OTHER,
            is_active=True,
            role_id="68c302ef6bf7a039b7e9b386",
            tenant_id="68c302ef6bf7a039b7e9b387",
            created_at="2024-10-01T00:00:00Z",
            updated_at="2024-10-01T00:00:00Z",
            role=RoleDto(
                id="68c302ef6bf7a039b7e9b386",
                name="Tenant audit log viewer",
                description="Role carrying AUDIT_LOGS_VIEW_ONLY for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.AUDIT_LOGS_VIEW_ONLY],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.get("/audit-logs/")
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 403
    body = response.json()
    assert body["code"] == 403
    assert "outside your tenant's scope" in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 403 must still carry the error-response headers: the
    # handler sets no-store only after the guard, so on this path
    # they come from the central ApiBaseException handler, and a
    # cached 403 could otherwise be served to a different admin
    # after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the audit-logs GET 404 test:
    # the pure-ASGI middleware stamps every HTTP response with
    # no path exclusions, so the audit-logs 403 must carry the
    # same headers as the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the audit-logs GET lock, using substring checks
    # so later additions to the list do not break this test.
    # Each directive is safe to lock here for the same reasons
    # as on the GET: the SPA has no camera, microphone,
    # geolocation, payment, clipboard-read, display-capture,
    # fullscreen, motion-sensor, compass, XR, or idle-detection
    # flow (verified by grep in the earlier sweeps).
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
    # Postcondition: the guard fires before any read, so the
    # list is side-effect free - the seeded role is still there
    # with its permission.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.AUDIT_LOGS_VIEW_ONLY]


@pytest.mark.asyncio
async def test_post_audit_logs_download_non_string_action_returns_422_with_security_headers(client: AsyncClient):
    """
    The audit-logs POST /download with a non-string `action`
    (a JSON list): `action` is an `Optional[AuditActionType]`
    field of DownloadAuditRequestDto, where AuditActionType is
    the literal ("create", "update", "delete", "read", "login",
    "logout", "error", "download"), and Pydantic v2 does not
    coerce lists to a literal member, so request validation
    rejects the body with 422 before the handler body runs.
    """
    # Function-name grep count 0 for
    # post_audit_logs_download_non_string_action before
    # appending, verified fresh this run, not assumed. This is
    # the FIRST lock of the audit-logs POST /download
    # per-field validation sweep: the route's only existing
    # locks are the missing-role 404 and the outside-scope
    # 403, neither of which exercises body validation, so a
    # regression that dropped validation on this route would
    # pass them while accepting a wrong-typed body -- and a
    # wrong-typed action would then be queued to Celery as a
    # download report (trigger_download_report.delay runs
    # inside the handler, after validation) with an action
    # the worker cannot match. The other field,
    # total_records, is locked separately (non-int and
    # missing remain). `total_records` is sent valid (5) so
    # nothing else can mask the 422. A list is used as the
    # non-string payload because Pydantic v2 lax mode has no
    # list-to-literal coercion path, and a string outside the
    # literal (e.g. "archive") would pin the invalid-value
    # class, not the non-string class. Note `action` is
    # Optional with default None, so None is a valid value --
    # only the non-string type is locked here. Verified from
    # backend/api/domain/dtos/audit_logs_dto.py (37 lines,
    # no model_validator on DownloadAuditRequestDto, only
    # the two plain fields) that nothing can mask the 422
    # for a list payload; verified from
    # backend/api/interfaces/api_controllers/
    # audit_logs_endpoint.py that download_audit_logs
    # (lines 74-93) takes DownloadAuditRequestDto as its
    # body and only reads it inside the handler body, after
    # validation, so the total_records <= 0 guard, the
    # Celery queue call, and the scope logic cannot mask
    # the 422. The route carries two permission
    # dependencies -- the router-level AUDIT_LOGS_VIEW_ONLY
    # and the handler-level AUDIT_LOGS_DOWNLOAD (both
    # parameter dependencies, solved before the endpoint's
    # own body is validated) -- so the caller role must
    # carry both, otherwise a permission 404 would mask
    # the 422, exactly as in the branding PATCH 422 locks.
    # The Role row (id 68c302ef6bf7a039b7e9b386) is seeded
    # with both permissions for those dependencies,
    # mirroring the audit-logs 403 lock's seed: the
    # dependency looks the role up by the mocked caller's
    # role_id, so the default host caller needs no
    # override -- the host scope (no X-Tenant-ID header)
    # is legitimate here because validation fails before
    # the handler's tenant-scope logic ever runs.
    # Deliberately no exact error-type assertion,
    # mirroring the branding PATCH non-string-field 422
    # locks. Deliberately no Cache-Control / Pragma
    # assertion: a 422 is FastAPI request validation, not
    # an ApiBaseException, so the central handler's
    # no-store headers do not apply to it, mirroring the
    # branding POST/PATCH 422 locks. The security headers
    # ARE locked: the pure-ASGI middleware stamps every
    # HTTP response, including validation errors, with no
    # path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Audit log downloader",
        description="Role carrying AUDIT_LOGS_VIEW_ONLY and AUDIT_LOGS_DOWNLOAD for the mocked caller",
        permissions=[Permission.AUDIT_LOGS_VIEW_ONLY, Permission.AUDIT_LOGS_DOWNLOAD],
    ).insert()

    response = await client.post(
        "/audit-logs/download",
        json={
            "action": ["create"],
            "total_records": 5,
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "action" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the audit-logs GET lock, using substring
    # checks so later additions to the list do not break
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
    # Postconditions: validation fails before the handler
    # runs, so no Celery download report is queued and no
    # record is created -- the seeded role is still there
    # with both permissions, mirroring the audit-logs 403
    # lock's postcondition.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.AUDIT_LOGS_VIEW_ONLY, Permission.AUDIT_LOGS_DOWNLOAD]


@pytest.mark.asyncio
async def test_post_audit_logs_download_non_int_total_records_returns_422_with_security_headers(client: AsyncClient):
    """
    The audit-logs POST /download with a non-int `total_records`
    (a JSON list): `total_records` is a required plain `int`
    field of DownloadAuditRequestDto, and Pydantic v2 does not
    coerce lists to int, so request validation rejects the body
    with 422 before the handler body runs.
    """
    # Function-name grep count 0 for
    # post_audit_logs_download_non_int_total_records before
    # appending, verified fresh this run, not assumed. This is
    # the SECOND lock of the audit-logs POST /download
    # per-field validation sweep: the non-string `action` lock
    # pins the other field, but a regression that dropped
    # validation on this route would still pass it while
    # accepting a wrong-typed total_records -- and a
    # wrong-typed total_records would then reach the
    # `total_records <= 0` guard in the handler (a comparison
    # against a list raises TypeError, surfacing as a 500
    # instead of a 422) or be queued to Celery as a download
    # report with a record count the worker cannot use.
    # `action` is sent valid ("create") so nothing else can
    # mask the 422. A list is used as the non-int payload
    # because Pydantic v2 lax mode coerces numeric strings
    # ("5" -> 5) but has no list-to-int coercion path, so a
    # string payload would pin the coercion class, not the
    # non-int class. Note `total_records` is required (no
    # default), so the missing-field class is locked
    # separately. Verified from
    # backend/api/domain/dtos/audit_logs_dto.py (no
    # model_validator on DownloadAuditRequestDto, only the
    # two plain fields) that nothing can mask the 422 for a
    # list payload; verified from
    # backend/api/interfaces/api_controllers/
    # audit_logs_endpoint.py that download_audit_logs
    # (lines 74-93) takes DownloadAuditRequestDto as its
    # body and only reads it inside the handler body, after
    # validation, so the total_records <= 0 guard, the
    # Celery queue call, and the scope logic cannot mask
    # the 422. The route carries two permission
    # dependencies -- the router-level AUDIT_LOGS_VIEW_ONLY
    # and the handler-level AUDIT_LOGS_DOWNLOAD (both
    # parameter dependencies, solved before the endpoint's
    # own body is validated) -- so the caller role must
    # carry both, otherwise a permission 404 would mask
    # the 422, exactly as in the non-string action lock.
    # The Role row (id 68c302ef6bf7a039b7e9b386) is seeded
    # with both permissions for those dependencies,
    # mirroring that lock: the dependency looks the role
    # up by the mocked caller's role_id, so the default
    # host caller needs no override -- the host scope (no
    # X-Tenant-ID header) is legitimate here because
    # validation fails before the handler's tenant-scope
    # logic ever runs. Deliberately no exact error-type
    # assertion, mirroring the branding PATCH non-string-field
    # 422 locks. Deliberately no Cache-Control / Pragma
    # assertion: a 422 is FastAPI request validation, not
    # an ApiBaseException, so the central handler's
    # no-store headers do not apply to it, mirroring the
    # branding POST/PATCH 422 locks. The security headers
    # ARE locked: the pure-ASGI middleware stamps every
    # HTTP response, including validation errors, with no
    # path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Audit log downloader",
        description="Role carrying AUDIT_LOGS_VIEW_ONLY and AUDIT_LOGS_DOWNLOAD for the mocked caller",
        permissions=[Permission.AUDIT_LOGS_VIEW_ONLY, Permission.AUDIT_LOGS_DOWNLOAD],
    ).insert()

    response = await client.post(
        "/audit-logs/download",
        json={
            "action": "create",
            "total_records": [5],
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "total_records" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the audit-logs GET lock, using substring
    # checks so later additions to the list do not break
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
    # Postconditions: validation fails before the handler
    # runs, so no Celery download report is queued and no
    # record is created -- the seeded role is still there
    # with both permissions, mirroring the audit-logs 403
    # lock's postcondition.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.AUDIT_LOGS_VIEW_ONLY, Permission.AUDIT_LOGS_DOWNLOAD]


@pytest.mark.asyncio
async def test_post_audit_logs_download_missing_total_records_returns_422_with_security_headers(client: AsyncClient):
    """
    The audit-logs POST /download with `total_records` omitted:
    `total_records` is a required plain `int` field of
    DownloadAuditRequestDto (no default), so request validation
    rejects the body with 422 before the handler body runs.
    """
    # Function-name grep count 0 for
    # post_audit_logs_download_missing_total_records before
    # appending, verified fresh this run, not assumed. This is
    # the THIRD and FINAL lock of the audit-logs POST /download
    # per-field validation sweep: the non-string `action` and
    # non-int `total_records` locks pin the wrong-type classes,
    # but a regression that made `total_records` optional (or
    # dropped validation on this route) would still pass them
    # while accepting a body with no record count -- and a
    # missing total_records would then reach the
    # `total_records <= 0` guard in the handler as None and
    # raise TypeError (500) instead of a 422, or be queued
    # to Celery as a download report with no record count.
    # `action` is sent valid ("create") so nothing else can
    # mask the 422. Note `action` is Optional with default
    # None, so omitting it would still be valid -- only the
    # missing required field is locked here. Verified from
    # backend/api/domain/dtos/audit_logs_dto.py (no
    # model_validator on DownloadAuditRequestDto, only the
    # two plain fields) that nothing can mask the 422 for a
    # missing field; verified from
    # backend/api/interfaces/api_controllers/
    # audit_logs_endpoint.py that download_audit_logs
    # takes DownloadAuditRequestDto as its body and only
    # reads it inside the handler body, after validation,
    # so the total_records <= 0 guard, the Celery queue
    # call, and the scope logic cannot mask the 422. The
    # route carries two permission dependencies -- the
    # router-level AUDIT_LOGS_VIEW_ONLY and the
    # handler-level AUDIT_LOGS_DOWNLOAD (both parameter
    # dependencies, solved before the endpoint's own body
    # is validated) -- so the caller role must carry both,
    # otherwise a permission 404 would mask the 422,
    # exactly as in the non-string action lock. The Role
    # row (id 68c302ef6bf7a039b7e9b386) is seeded with both
    # permissions for those dependencies, mirroring that
    # lock: the dependency looks the role up by the mocked
    # caller's role_id, so the default host caller needs
    # no override -- the host scope (no X-Tenant-ID header)
    # is legitimate here because validation fails before
    # the handler's tenant-scope logic ever runs.
    # Deliberately no exact error-type assertion, mirroring
    # the branding PATCH non-string-field 422 locks.
    # Deliberately no Cache-Control / Pragma assertion: a
    # 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the branding
    # POST/PATCH 422 locks. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Audit log downloader",
        description="Role carrying AUDIT_LOGS_VIEW_ONLY and AUDIT_LOGS_DOWNLOAD for the mocked caller",
        permissions=[Permission.AUDIT_LOGS_VIEW_ONLY, Permission.AUDIT_LOGS_DOWNLOAD],
    ).insert()

    response = await client.post(
        "/audit-logs/download",
        json={
            "action": "create",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "total_records" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the audit-logs GET lock, using substring
    # checks so later additions to the list do not break
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
    # Postconditions: validation fails before the handler
    # runs, so no Celery download report is queued and no
    # record is created -- the seeded role is still there
    # with both permissions, mirroring the audit-logs 403
    # lock's postcondition.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.AUDIT_LOGS_VIEW_ONLY, Permission.AUDIT_LOGS_DOWNLOAD]


@pytest.mark.asyncio
async def test_get_audit_logs_limit_zero_returns_422_with_security_headers(client: AsyncClient):
    """
    The audit-logs GET list with `limit=0`: `limit` is declared
    as `Query(10, ge=1, le=100)`, so request validation rejects
    the query with 422 before the handler body runs.
    """
    # Function-name grep count 0 for
    # get_audit_logs_limit_zero before appending, verified
    # fresh this run, not assumed. This is the FIRST lock of
    # the audit-logs GET list query-param validation sweep:
    # the POST /download per-field sweep is COMPLETE (non-string
    # action, non-int total_records, missing total_records),
    # but no lock in this file exercises query validation on
    # the GET list route -- a regression that dropped the
    # `ge=1` bound (or validation on this route) would pass
    # the existing 404/403 locks while accepting limit=0,
    # and the service would then read with a zero page size
    # (the repository scans skip + limit entries, so a zero
    # limit returns an empty page that looks like "no audit
    # entries" instead of a client error). The other query
    # params -- limit above the max, skip below/above its
    # bounds, non-int limit, invalid action -- are locked
    # separately. The route carries one permission dependency,
    # the router-level AUDIT_LOGS_VIEW_ONLY (a parameter
    # dependency, solved before the endpoint's own query
    # validation), so the caller role must carry it, otherwise
    # a permission 404 would mask the 422, exactly as in the
    # POST /download 422 locks. The Role row (id
    # 68c302ef6bf7a039b7e9b386) is seeded with that permission,
    # mirroring the 403 lock's seed: the dependency looks the
    # role up by the mocked caller's role_id, so the default
    # host caller needs no override -- the host scope (no
    # X-Tenant-ID header) is legitimate here because
    # validation fails before the handler's tenant-scope
    # guard ever runs, and the default skip=0 / no action
    # values pass validation, so nothing else can mask the
    # 422. Verified from
    # backend/api/interfaces/api_controllers/
    # audit_logs_endpoint.py (lines 51-71) that list_audit_logs
    # declares `limit: int = Query(10, ge=1, le=100)` and
    # reads it only inside the handler body, after validation,
    # so the scope guard and the service call cannot mask the
    # 422. Deliberately no exact error-type assertion,
    # mirroring the branding PATCH non-string-field 422 locks.
    # Deliberately no Cache-Control / Pragma assertion: a 422
    # is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply
    # to it, mirroring the POST /download 422 locks. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Audit log viewer",
        description="Role carrying AUDIT_LOGS_VIEW_ONLY for the mocked caller",
        permissions=[Permission.AUDIT_LOGS_VIEW_ONLY],
    ).insert()

    response = await client.get("/audit-logs/?limit=0")
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "limit" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the audit-logs GET lock, using substring
    # checks so later additions to the list do not break
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
    # Postconditions: validation fails before the handler
    # runs, so no audit read runs -- the seeded role is still
    # there with its permission, mirroring the audit-logs 403
    # lock's postcondition.
    stored_role = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored_role is not None
    assert stored_role.permissions == [Permission.AUDIT_LOGS_VIEW_ONLY]
