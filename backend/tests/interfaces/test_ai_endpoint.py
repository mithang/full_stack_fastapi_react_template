import pytest
from httpx import AsyncClient

from api import app
from api.common.enums.gender import Gender
from api.domain.dtos.auth_dto import MeResponseDto
from api.domain.dtos.role_dto import RoleDto
from api.infrastructure.security.current_user import get_current_user


@pytest.mark.asyncio
async def test_get_ai_models_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The AI area had no interface test file at all, so
    deleting the AI router from api/__init__.py — or dropping
    the central ApiBaseException no-store lines or the
    security-headers middleware registration — would previously
    have gone uncaught here even though every other interface
    area locks its headers in. The AI router is feature-gated
    at the router level (Feature.CHAT), in front of every
    handler, so the success path is not asserted here: it
    needs a tenant with the chat feature enabled plus a live
    Ollama model list, neither of which the shared conftest
    client provides. The error path below is deterministic
    instead, but it cannot reuse the missing-role 404 pattern
    of the features/audit-logs/SSO/storage/branding tests:
    check_feature_access reads currentUser.role before any
    role lookup, and the shared conftest mock is a plain
    UserDto, which carries no role attribute at all — so
    under that mock the gate fails with an AttributeError
    500, not a deterministic error. In production that
    cannot happen: get_current_user builds a MeResponseDto
    (role is a required field) and raises RoleNotFoundException
    before any feature check when the role row is missing.
    This test therefore swaps in, for this one request only,
    a MeResponseDto with a role carrying no permissions and
    no tenant — the host-scope branch of check_feature_access
    then raises FeatureNotEnabledException("chat") before the
    handler runs, and the central ApiBaseException handler
    turns it into a 403. The original override is restored
    in finally, so no other test's mock is affected.
    That 403 must still carry the error-response headers: a
    cached 403 could otherwise be served to a different user
    after an account switch on a shared machine, and the AI
    model list is account-visible configuration.
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
        response = await client.get("/ai/models")
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 403
    body = response.json()
    assert body["code"] == 403
    assert "chat" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the branding test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the AI 403 must carry the same headers
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
    # the branding lock, using substring checks so later additions
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


@pytest.mark.asyncio
async def test_get_ai_history_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        Second AI route lock, mirroring the /ai/models lock in this
        file: GET /ai/history was the only other untested AI read.
        The AI router is feature-gated at the router level
        (Feature.CHAT), in front of every handler, and it is
        included unconditionally in api/__init__.py, so the gate
        runs before the handler, its read-scope guard, and its
        LocalAIService dependency — no LLM call, no history read,
        no side effect. The GET takes no params or body, so no
        422 can mask the 403. The per-test MeResponseDto override
        (role with no permissions, no tenant) is reused because
        the shared conftest mock is a plain UserDto with no role
        attribute and would 500 under the gate; the host-scope
        branch of check_feature_access then raises
        FeatureNotEnabledException("chat") before the handler
        runs. The original override is restored in finally.
        That 403 must still carry the error-response headers: a
        cached 403 could otherwise be served to a different user
        after an account switch, and chat history is private
        per-user data.
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
        response = await client.get("/ai/history")
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 403
    body = response.json()
    assert body["code"] == 403
    assert "chat" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the /ai/models test: the
    # pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the AI 403 must carry the same headers
    # as the authenticated GETs, including the exception-handler
    # responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the /ai/models lock, using substring checks so
    # later additions to the list do not break this test. The
    # idle-detection justification was re-verified fresh this
    # run: zero case-insensitive idle matches and zero
    # IdleDetector/requestIdleCallback matches across
    # frontend/app/src.
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
async def test_get_ai_new_session_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        Third AI route lock, mirroring the /ai/models and
        /ai/history locks in this file: GET /ai/new_session
        was the next untested AI route. The AI router is
        feature-gated at the router level (Feature.CHAT), in
        front of every handler, and it is included
        unconditionally in api/__init__.py, so the gate runs
        before the handler, its CurrentUser dependency, and
        the session-id minting — no LLM call, no DB write,
        no side effect. The GET takes no params or body, so
        no 422 can mask the 403. The per-test MeResponseDto
        override (role with no permissions, no tenant) is
        reused because the shared conftest mock is a plain
        UserDto with no role attribute and would 500 under
        the gate; the host-scope branch of
        check_feature_access then raises
        FeatureNotEnabledException("chat") before the
        handler runs. The original override is restored in
        finally. That 403 must still carry the
        error-response headers: a cached 403 could
        otherwise be served to a different user after an
        account switch, and the success path mints a fresh
        session id on every call, so any caching around
        this route would merge distinct conversations.
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
        response = await client.get("/ai/new_session")
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 403
    body = response.json()
    assert body["code"] == 403
    assert "chat" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the /ai/models and
    # /ai/history tests: the pure-ASGI middleware stamps
    # every HTTP response with no path exclusions, so the
    # AI 403 must carry the same headers as the
    # authenticated GETs, including the exception-handler
    # responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the /ai/models lock, using substring checks
    # so later additions to the list do not break this
    # test. The idle-detection justification was re-verified
    # fresh this run: zero case-insensitive idle matches and
    # zero IdleDetector/requestIdleCallback matches across
    # frontend/app/src.
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
async def test_get_ai_single_session_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        Fourth AI route lock, mirroring the /ai/models,
        /ai/history, and /ai/new_session locks in this file:
        GET /ai/sessions/{session_id} was the next untested
        AI route. The AI router is feature-gated at the
        router level (Feature.CHAT), in front of every
        handler, and it is included unconditionally in
        api/__init__.py, so the gate runs before the
        handler, its CurrentUser dependency, its
        LocalAIService/get_tenant_id dependencies, and its
        read-scope guard — no history read, no LLM call,
        no side effect. The session_id path param is a
        plain str, so any value passes validation and no
        422 can mask the 403; the dummy id below is never
        looked up because the gate raises first. The
        per-test MeResponseDto override (role with no
        permissions, no tenant) is reused because the
        shared conftest mock is a plain UserDto with no
        role attribute and would 500 under the gate; the
        host-scope branch of check_feature_access then
        raises FeatureNotEnabledException("chat") before
        the handler runs. The original override is
        restored in finally. That 403 must still carry
        the error-response headers: a cached 403 could
        otherwise be served to a different user after an
        account switch, and the success path returns a
        private per-user chat transcript, so any caching
        around this route would leak one user's
        conversation to another.
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
        response = await client.get("/ai/sessions/68c302ef6bf7a039b7e9b385")
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 403
    body = response.json()
    assert body["code"] == 403
    assert "chat" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the /ai/models,
    # /ai/history, and /ai/new_session tests: the
    # pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the AI 403 must carry
    # the same headers as the authenticated GETs,
    # including the exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the /ai/models lock, using substring checks
    # so later additions to the list do not break this
    # test. The idle-detection justification was re-verified
    # fresh this run: zero case-insensitive idle matches and
    # zero IdleDetector/requestIdleCallback matches across
    # frontend/app/src.
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
async def test_delete_ai_session_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        Fifth AI route lock, mirroring the /ai/models,
        /ai/history, /ai/new_session, and single-session
        locks in this file: DELETE /ai/sessions/{session_id}
        was the next untested AI route. The AI router is
        feature-gated at the router level (Feature.CHAT),
        in front of every handler, and it is included
        unconditionally in api/__init__.py, so the gate runs
        before the handler, its CurrentUser dependency, its
        LocalAIService/get_tenant_id dependencies, and its
        read-scope guard — no session is deleted, no history
        read, no LLM call, no side effect. DELETE takes no
        body and the session_id path param is a plain str,
        so no 422 can mask the 403; the dummy id below is
        never looked up because the gate raises first. The
        per-test MeResponseDto override (role with no
        permissions, no tenant) is reused because the
        shared conftest mock is a plain UserDto with no
        role attribute and would 500 under the gate; the
        host-scope branch of check_feature_access then
        raises FeatureNotEnabledException("chat") before
        the handler runs. The original override is
        restored in finally. That 403 must still carry
        the error-response headers: a cached 403 could
        otherwise be served to a different user after an
        account switch, and the success path deletes a
        private per-user chat session, so any caching
        around this route would leak one user's
        conversation state to another.
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
        response = await client.delete("/ai/sessions/68c302ef6bf7a039b7e9b385")
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 403
    body = response.json()
    assert body["code"] == 403
    assert "chat" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the /ai/models,
    # /ai/history, /ai/new_session, and single-session
    # tests: the pure-ASGI middleware stamps every HTTP
    # response with no path exclusions, so the AI 403 must
    # carry the same headers as the authenticated GETs,
    # including the exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the /ai/models lock, using substring checks
    # so later additions to the list do not break this
    # test. The idle-detection justification was re-verified
    # fresh this run: zero case-insensitive idle matches and
    # zero IdleDetector/requestIdleCallback matches across
    # frontend/app/src.
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
async def test_put_ai_set_model_preference_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        Sixth AI route lock, mirroring the /ai/models,
        /ai/history, /ai/new_session, single-session, and
        delete-session locks in this file: PUT
        /ai/set_model_preference/{model_name} was the next
        untested AI route. The AI router is feature-gated
        at the router level (Feature.CHAT), in front of
        every handler, and it is included unconditionally
        in api/__init__.py, so the gate runs before the
        handler, its CurrentUser dependency, its
        UserPreferenceService/get_tenant_id dependencies,
        and its preference-scope guard — no preference is
        written, no model is looked up, no LLM call, no
        side effect. PUT takes no body and the model_name
        path param uses the :path converter, so any
        non-empty name passes validation and no 422 can
        mask the 403; the dummy name below is never
        stored because the gate raises first. The
        per-test MeResponseDto override (role with no
        permissions, no tenant) is reused because the
        shared conftest mock is a plain UserDto with no
        role attribute and would 500 under the gate; the
        host-scope branch of check_feature_access then
        raises FeatureNotEnabledException("chat") before
        the handler runs. The original override is
        restored in finally. That 403 must still carry
        the error-response headers: a cached 403 could
        otherwise be served to a different user after an
        account switch, and the success path writes a
        per-user model preference, so any caching around
        this route would leak one user's preference state
        to another.
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
        response = await client.put("/ai/set_model_preference/llama3")
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 403
    body = response.json()
    assert body["code"] == 403
    assert "chat" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the /ai/models,
    # /ai/history, /ai/new_session, single-session, and
    # delete-session tests: the pure-ASGI middleware
    # stamps every HTTP response with no path exclusions,
    # so the AI 403 must carry the same headers as the
    # authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the /ai/models lock, using substring checks
    # so later additions to the list do not break this
    # test. The idle-detection justification was re-verified
    # fresh this run: zero case-insensitive idle matches and
    # zero IdleDetector/requestIdleCallback matches across
    # frontend/app/src.
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
async def test_post_ai_ask_with_feature_disabled_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        Seventh and last AI route lock, mirroring the /ai/models,
        /ai/history, /ai/new_session, single-session,
        delete-session, and set-model-preference locks in this
        file: POST /ai/ask was the only untested AI route.
        The AI router is feature-gated at the router level
        (Feature.CHAT), in front of every handler, and it is
        included unconditionally in api/__init__.py, so the
        gate runs before the handler, its CurrentUser
        dependency, its LocalAIService/get_tenant_id
        dependencies, its create-scope guard, and the
        OllamaChat construction — no LLM call is made, no
        streaming response is produced, and no chat history
        or session record is written (no side effect). The
        body below is fully valid under AIAskRequestDto
        (a short non-empty question within the 2000-char cap
        and a non-empty model_name), so no 422 can mask the
        403 even if body validation runs before the gate.
        The per-test MeResponseDto override (role with no
        permissions, no tenant) is reused because the shared
        conftest mock is a plain UserDto with no role
        attribute and would 500 under the gate; the
        host-scope branch of check_feature_access then
        raises FeatureNotEnabledException("chat") before
        the handler runs. The original override is restored
        in finally. That 403 must still carry the
        error-response headers: a cached 403 could
        otherwise be served to a different user after an
        account switch, and the success path writes
        per-user chat history, so any caching around this
        route would leak one user's conversation state to
        another.
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
        response = await client.post(
            "/ai/ask",
            json={"question": "Hello", "model_name": "llama3"},
        )
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 403
    body = response.json()
    assert body["code"] == 403
    assert "chat" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the /ai/models,
    # /ai/history, /ai/new_session, single-session,
    # delete-session, and set-model-preference tests: the
    # pure-ASGI middleware stamps every HTTP response with
    # no path exclusions, so the AI 403 must carry the same
    # headers as the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the /ai/models lock, using substring checks
    # so later additions to the list do not break this
    # test. The idle-detection justification was re-verified
    # fresh this run: zero case-insensitive idle matches and
    # zero IdleDetector/requestIdleCallback matches across
    # frontend/app/src.
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
async def test_post_ai_ask_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The AI create scope-guard error path:
    """
    # The /ai/ask scope-guard branch, not yet locked:
    # function-name grep count 0 for
    # post_ai_ask_outside_tenant_scope (verified fresh this
    # run), and no test in this file asserts a 403 with an
    # "outside your tenant's scope" message - the locks cover
    # only the feature-disabled 403s. Deleting
    # _assert_create_scope (ai_endpoint.py) would previously
    # have gone uncaught, and a tenant caller asking on the
    # wrong DB would then have their chat history written to
    # the host DB - invisible to their own tenant DB's
    # history list, and a duplicate session row under the
    # same session_id, since the existing tenant-DB session
    # is not found in the host DB. The guard runs first in
    # the handler body, before any LLM call or history write.
    # It cannot be reached the way the roles/users/audit-logs
    # locks reach their guards (tenant-scoped caller, no
    # X-Tenant-ID header): the AI router is feature-gated,
    # and check_feature_access looks the tenant up by
    # request.state.tenant_id before the handler runs, so
    # with no header the lookup gets None, BaseRepository.get
    # returns None, and get_tenant_by_id raises
    # TenantNotFoundException - a 404 from the gate, never
    # the scope 403. The lock therefore uses the mismatched
    # scope the guard is written for: the caller is
    # tenant-scoped to 68c302ef6bf7a039b7e9b387 while the
    # request carries X-Tenant-ID
    # 68c302ef6bf7a039b7e9b388, a seeded tenant with the CHAT
    # feature enabled, so the feature gate passes (Tenant
    # stays bound to the host DB - init_db excludes it from
    # the tenant-DB models, mongodb.py:53-56 - so the lookup
    # finds the seeded row) and the guard raises
    # ForbiddenException before any LLM call or write. The
    # caller override mirrors the audit-logs lock's pattern
    # (per-test MeResponseDto, restored in finally); the
    # role needs no permissions on the tenant branch of the
    # feature gate. The body is fully valid under
    # AIAskRequestDto (a short non-empty question within the
    # 2000-char cap and a non-empty model_name), so no 422
    # can mask the 403. The central ApiBaseException handler
    # maps ForbiddenException to 403 (api/__init__.py:98-103)
    # with {"error": ..., "code": 403} and the no-store/Pragma
    # error headers. A future change that drops the guard
    # would break this lock while leaving the feature-disabled
    # /ai/ask 403 lock green, so the two paths are locked
    # separately.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.ai import AISessions
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.infrastructure.security.current_user import get_current_user

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="ai-scope-tenant",
        subdomain="ai-scope.fsrapp.com",
        features=[Feature(name=FeatureEnum.CHAT, enabled=True)],
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
                name="Tenant AI caller",
                description="Role for the tenant-scoped AI ask caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/ai/ask",
            json={"question": "Hello", "model_name": "llama3"},
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
        )
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
    # cached 403 could otherwise be served to a different user
    # after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the /ai/ask feature-disabled
    # test: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the AI 403 must carry the same
    # headers as the authenticated calls, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the /ai/ask feature-disabled lock, using
    # substring checks so later additions to the list do not
    # break this test. Each directive is safe to lock here for
    # the same reasons as on the other AI routes: the SPA has
    # no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow
    # (verified by grep in the earlier sweeps).
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
    # Postconditions: the guard fires before any LLM call or
    # history write, so no chat session was created - the
    # exchange is never saved - and the seeded tenant is still
    # there with the CHAT feature enabled.
    stored = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored is not None
    assert stored.features == [Feature(name=FeatureEnum.CHAT, enabled=True)]
    sessions = await AISessions.find_all().to_list()
    assert sessions == []


@pytest.mark.asyncio
async def test_get_ai_history_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The AI read scope-guard error path:
    """
    # The /ai/history scope-guard branch, not yet locked:
    # function-name grep count 0 for
    # get_ai_history_outside_tenant_scope (verified fresh this
    # run), and no test in this file asserts a 403 with an
    # "outside your tenant's scope" message on a read - the
    # locks cover only the feature-disabled 403s and the
    # /ai/ask create-scope 403. Deleting _assert_read_scope
    # (ai_endpoint.py:47-66) would previously have gone
    # uncaught, and a tenant caller reading history on the
    # wrong DB would then read host-DB rows matching their
    # user id (normally empty, but a user-id collision across
    # DBs would leak another user's chat history), instead
    # of their own tenant history. The guard runs first in
    # the handler body, before any history read. It cannot be
    # reached the way the roles/users/audit-logs locks reach
    # their guards (tenant-scoped caller, no X-Tenant-ID
    # header): the AI router is feature-gated, and
    # check_feature_access looks the tenant up by
    # request.state.tenant_id before the handler runs, so
    # with no header the lookup gets None, BaseRepository.get
    # returns None, and get_tenant_by_id raises
    # TenantNotFoundException - a 404 from the gate, never
    # the scope 403. The lock therefore uses the mismatched
    # scope the guard is written for, mirroring the /ai/ask
    # create-scope lock: the caller is tenant-scoped to
    # 68c302ef6bf7a039b7e9b387 while the request carries
    # X-Tenant-ID 68c302ef6bf7a039b7e9b388, a seeded tenant
    # with the CHAT feature enabled, so the feature gate
    # passes (Tenant stays bound to the host DB - init_db
    # excludes it from the tenant-DB models, mongodb.py:53-56
    # - so the lookup finds the seeded row) and the guard
    # raises ForbiddenException before any history read. The
    # caller override mirrors the /ai/ask lock's pattern
    # (per-test MeResponseDto, restored in finally); the role
    # needs no permissions on the tenant branch of the
    # feature gate. The GET takes no params or body, so no
    # 422 can mask the 403. The central ApiBaseException
    # handler maps ForbiddenException to 403
    # (api/__init__.py:98-103) with {"error": ..., "code":
    # 403} and the no-store/Pragma error headers. A future
    # change that drops the guard would break this lock while
    # leaving the feature-disabled /ai/history 403 lock and
    # the /ai/ask create-scope 403 lock green, so the paths
    # are locked separately.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.ai import AISessions
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.infrastructure.security.current_user import get_current_user

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="ai-scope-tenant",
        subdomain="ai-scope.fsrapp.com",
        features=[Feature(name=FeatureEnum.CHAT, enabled=True)],
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
                name="Tenant AI caller",
                description="Role for the tenant-scoped AI history caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.get(
            "/ai/history",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
        )
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
    # cached 403 could otherwise be served to a different user
    # after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the /ai/history
    # feature-disabled test: the pure-ASGI middleware stamps
    # every HTTP response with no path exclusions, so the AI
    # 403 must carry the same headers as the authenticated
    # calls, including the exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the /ai/history feature-disabled lock, using
    # substring checks so later additions to the list do not
    # break this test. Each directive is safe to lock here for
    # the same reasons as on the other AI routes: the SPA has
    # no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow
    # (verified by grep in the earlier sweeps).
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
    # Postconditions: the guard fires before any history read,
    # so no session rows were created or exposed, and the
    # seeded tenant is still there with the CHAT feature
    # enabled.
    stored = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored is not None
    assert stored.features == [Feature(name=FeatureEnum.CHAT, enabled=True)]
    sessions = await AISessions.find_all().to_list()
    assert sessions == []


@pytest.mark.asyncio
async def test_get_ai_single_session_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The AI read scope-guard error path on the single-session
        route:
    """
    # The /ai/sessions/{session_id} scope-guard branch, not yet
    # locked: function-name grep count 0 for
    # get_ai_single_session_outside_tenant_scope (verified fresh
    # this run), and no test in this file asserts a 403 with an
    # "outside your tenant's scope" message on a single-session
    # read - the locks cover only the feature-disabled 403s,
    # the /ai/ask create-scope 403, and the /ai/history
    # read-scope 403. Deleting _assert_read_scope
    # (ai_endpoint.py:47-66) would previously have gone
    # uncaught on this route, and a tenant caller reading one
    # session on the wrong DB would then read host-DB rows
    # matching their user id (normally empty, but a user-id
    # collision across DBs would leak another user's chat
    # transcript), instead of their own tenant history. The
    # guard runs first in the handler body, before any history
    # read. It cannot be reached the way the roles/users/
    # audit-logs locks reach their guards (tenant-scoped
    # caller, no X-Tenant-ID header): the AI router is
    # feature-gated, and check_feature_access looks the
    # tenant up by request.state.tenant_id before the handler
    # runs, so with no header the lookup gets None,
    # BaseRepository.get returns None, and get_tenant_by_id
    # raises TenantNotFoundException - a 404 from the gate,
    # never the scope 403. The lock therefore uses the
    # mismatched scope the guard is written for, mirroring
    # the /ai/history read-scope lock: the caller is
    # tenant-scoped to 68c302ef6bf7a039b7e9b387 while the
    # request carries X-Tenant-ID 68c302ef6bf7a039b7e9b388, a
    # seeded tenant with the CHAT feature enabled, so the
    # feature gate passes (Tenant stays bound to the host DB
    # - init_db excludes it from the tenant-DB models,
    # mongodb.py:53-56 - so the lookup finds the seeded row)
    # and the guard raises ForbiddenException before any
    # history read. The caller override mirrors the
    # /ai/history lock's pattern (per-test MeResponseDto,
    # restored in finally); the role needs no permissions on
    # the tenant branch of the feature gate. The session_id
    # path param is a plain str, so any value passes
    # validation and no 422 can mask the 403; the dummy id
    # below is never looked up because the guard raises
    # first. The central ApiBaseException handler maps
    # ForbiddenException to 403 (api/__init__.py:98-103)
    # with {"error": ..., "code": 403} and the no-store/
    # Pragma error headers. A future change that drops the
    # guard would break this lock while leaving the
    # feature-disabled /ai/sessions/{session_id} 403 lock
    # and the /ai/history read-scope 403 lock green, so the
    # paths are locked separately.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.ai import AISessions
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.infrastructure.security.current_user import get_current_user

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="ai-scope-tenant",
        subdomain="ai-scope.fsrapp.com",
        features=[Feature(name=FeatureEnum.CHAT, enabled=True)],
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
                name="Tenant AI caller",
                description="Role for the tenant-scoped AI single-session caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.get(
            "/ai/sessions/68c302ef6bf7a039b7e9b385",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
        )
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
    # cached 403 could otherwise be served to a different user
    # after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the /ai/history
    # read-scope test: the pure-ASGI middleware stamps
    # every HTTP response with no path exclusions, so the AI
    # 403 must carry the same headers as the authenticated
    # calls, including the exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the /ai/history read-scope lock, using
    # substring checks so later additions to the list do not
    # break this test. Each directive is safe to lock here for
    # the same reasons as on the other AI routes: the SPA has
    # no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow
    # (verified by grep in the earlier sweeps).
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
    # Postconditions: the guard fires before any history read,
    # so no session rows were created or exposed, and the
    # seeded tenant is still there with the CHAT feature
    # enabled.
    stored = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored is not None
    assert stored.features == [Feature(name=FeatureEnum.CHAT, enabled=True)]
    sessions = await AISessions.find_all().to_list()
    assert sessions == []


@pytest.mark.asyncio
async def test_delete_ai_session_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The AI read scope-guard error path on the delete-session
        route:
    """
    # The /ai/sessions/{session_id} DELETE scope-guard branch,
    # not yet locked: function-name grep count 0 for
    # delete_ai_session_outside_tenant_scope (verified fresh
    # this run), and no test in this file asserts a 403 with an
    # "outside your tenant's scope" message on a session
    # delete - the locks cover only the feature-disabled 403s,
    # the /ai/ask create-scope 403, and the /ai/history and
    # single-session read-scope 403s. Deleting
    # _assert_read_scope (ai_endpoint.py:47-66) would
    # previously have gone uncaught on this route, and a
    # tenant caller deleting one session on the wrong DB
    # would then delete host-DB rows matching their user id
    # (normally empty, but a user-id collision across DBs
    # would destroy another user's chat session), instead
    # of their own tenant history. The guard runs first in
    # the handler body, before any delete. It cannot be
    # reached the way the roles/users/audit-logs locks reach
    # their guards (tenant-scoped caller, no X-Tenant-ID
    # header): the AI router is feature-gated, and
    # check_feature_access looks the tenant up by
    # request.state.tenant_id before the handler runs, so
    # with no header the lookup gets None,
    # BaseRepository.get returns None, and get_tenant_by_id
    # raises TenantNotFoundException - a 404 from the gate,
    # never the scope 403. The lock therefore uses the
    # mismatched scope the guard is written for, mirroring
    # the /ai/history and single-session read-scope locks:
    # the caller is tenant-scoped to
    # 68c302ef6bf7a039b7e9b387 while the request carries
    # X-Tenant-ID 68c302ef6bf7a039b7e9b388, a seeded tenant
    # with the CHAT feature enabled, so the feature gate
    # passes (Tenant stays bound to the host DB - init_db
    # excludes it from the tenant-DB models,
    # mongodb.py:53-56 - so the lookup finds the seeded row)
    # and the guard raises ForbiddenException before any
    # delete. The caller override mirrors the single-session
    # lock's pattern (per-test MeResponseDto, restored in
    # finally); the role needs no permissions on the tenant
    # branch of the feature gate. DELETE takes no body and
    # the session_id path param is a plain str, so any value
    # passes validation and no 422 can mask the 403; the
    # dummy id below is never looked up because the guard
    # raises first. The central ApiBaseException handler
    # maps ForbiddenException to 403
    # (api/__init__.py:98-103) with {"error": ..., "code":
    # 403} and the no-store/Pragma error headers. A future
    # change that drops the guard would break this lock
    # while leaving the feature-disabled
    # /ai/sessions/{session_id} DELETE 403 lock and the
    # /ai/history and single-session read-scope 403 locks
    # green, so the paths are locked separately.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.ai import AISessions
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.infrastructure.security.current_user import get_current_user

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="ai-scope-tenant",
        subdomain="ai-scope.fsrapp.com",
        features=[Feature(name=FeatureEnum.CHAT, enabled=True)],
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
                name="Tenant AI caller",
                description="Role for the tenant-scoped AI delete-session caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.delete(
            "/ai/sessions/68c302ef6bf7a039b7e9b385",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
        )
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
    # delete handler takes no Response param, so it sets no
    # no-store headers itself - on this path they come from the
    # central ApiBaseException handler, and a cached 403 could
    # otherwise be served to a different user after an account
    # switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the single-session
    # read-scope test: the pure-ASGI middleware stamps
    # every HTTP response with no path exclusions, so the AI
    # 403 must carry the same headers as the authenticated
    # calls, including the exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the single-session read-scope lock, using
    # substring checks so later additions to the list do not
    # break this test. Each directive is safe to lock here for
    # the same reasons as on the other AI routes: the SPA has
    # no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow
    # (verified by grep in the earlier sweeps).
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
    # Postconditions: the guard fires before any delete, so
    # no session rows were created or removed, and the
    # seeded tenant is still there with the CHAT feature
    # enabled.
    stored = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored is not None
    assert stored.features == [Feature(name=FeatureEnum.CHAT, enabled=True)]
    sessions = await AISessions.find_all().to_list()
    assert sessions == []


@pytest.mark.asyncio
async def test_put_ai_set_model_preference_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The AI preference scope-guard error path on the
        set-model-preference route:
    """
    # The /ai/set_model_preference/{model_name} PUT
    # scope-guard branch, not yet locked: function-name grep
    # count 0 for
    # put_ai_set_model_preference_outside_tenant_scope
    # (verified fresh this run), and no test in this file
    # asserts a 403 with an "outside your tenant's scope"
    # message on a preference write - the locks cover only
    # the feature-disabled 403s, the /ai/ask create-scope
    # 403, and the /ai/history, single-session, and
    # session-delete read-scope 403s. Deleting
    # _assert_preference_scope (ai_endpoint.py:139-156)
    # would previously have gone uncaught on this route,
    # and a tenant caller saving a model preference on the
    # wrong DB would then write their preference into the
    # host DB - invisible to their own tenant DB, and
    # under a user-id collision across DBs it would
    # overwrite another user's preference - instead of
    # their own tenant preference. The guard runs first in
    # the handler body, before the empty-name check and
    # before any preference write. It cannot be reached the
    # way the roles/users/audit-logs locks reach their
    # guards (tenant-scoped caller, no X-Tenant-ID header):
    # the AI router is feature-gated, and
    # check_feature_access looks the tenant up by
    # request.state.tenant_id before the handler runs, so
    # with no header the lookup gets None,
    # BaseRepository.get returns None, and get_tenant_by_id
    # raises TenantNotFoundException - a 404 from the gate,
    # never the scope 403. The lock therefore uses the
    # mismatched scope the guard is written for, mirroring
    # the /ai/ask, /ai/history, single-session, and
    # session-delete scope locks: the caller is
    # tenant-scoped to 68c302ef6bf7a039b7e9b387 while the
    # request carries X-Tenant-ID
    # 68c302ef6bf7a039b7e9b388, a seeded tenant with the
    # CHAT feature enabled, so the feature gate passes
    # (Tenant stays bound to the host DB - init_db excludes
    # it from the tenant-DB models, mongodb.py:53-56 - so
    # the lookup finds the seeded row) and the guard raises
    # ForbiddenException before any preference write. The
    # caller override mirrors the session-delete lock's
    # pattern (per-test MeResponseDto, restored in
    # finally); the role needs no permissions on the tenant
    # branch of the feature gate. PUT takes no body and the
    # model_name path param uses the :path converter, so the
    # dummy name below passes validation and no 422 can mask
    # the 403; it is never stored because the guard raises
    # first. The central ApiBaseException handler maps
    # ForbiddenException to 403 (api/__init__.py:98-103)
    # with {"error": ..., "code": 403} and the no-store/Pragma
    # error headers. A future change that drops the guard
    # would break this lock while leaving the
    # feature-disabled /ai/set_model_preference PUT 403 lock
    # and the /ai/ask, /ai/history, single-session, and
    # session-delete scope 403 locks green, so the paths are
    # locked separately.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.tenant import Feature, Tenant
    from api.domain.entities.user_preference import UserPreference
    from api.domain.enum.feature import Feature as FeatureEnum
    from api.infrastructure.security.current_user import get_current_user

    await Tenant(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        name="ai-scope-tenant",
        subdomain="ai-scope.fsrapp.com",
        features=[Feature(name=FeatureEnum.CHAT, enabled=True)],
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
                name="Tenant AI caller",
                description="Role for the tenant-scoped AI preference caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.put(
            "/ai/set_model_preference/llama3",
            headers={"X-Tenant-ID": "68c302ef6bf7a039b7e9b388"},
        )
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
    # preference handler takes no Response param, so it sets no
    # no-store headers itself - on this path they come from the
    # central ApiBaseException handler, and a cached 403 could
    # otherwise be served to a different user after an account
    # switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the session-delete
    # read-scope test: the pure-ASGI middleware stamps
    # every HTTP response with no path exclusions, so the AI
    # 403 must carry the same headers as the authenticated
    # calls, including the exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened:
    # lock the twelve most sensitive directives as disabled,
    # mirroring the session-delete read-scope lock, using
    # substring checks so later additions to the list do not
    # break this test. Each directive is safe to lock here for
    # the same reasons as on the other AI routes: the SPA has
    # no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow
    # (verified by grep in the earlier sweeps).
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
    # Postconditions: the guard fires before any preference
    # write, so no user-preference rows were created, and the
    # seeded tenant is still there with the CHAT feature
    # enabled.
    stored = await Tenant.find_one(
        Tenant.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert stored is not None
    assert stored.features == [Feature(name=FeatureEnum.CHAT, enabled=True)]
    preferences = await UserPreference.find_all().to_list()
    assert preferences == []


@pytest.mark.asyncio
async def test_post_ai_ask_nonstring_question_returns_422_with_security_headers(client: AsyncClient):
    """
        The AI ask POST with a non-string question:
    """
    # The FIRST lock of the AI ask per-field validation sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for post_ai_ask_nonstring_question before
    # appending. No test in this file locks a 422 on /ai/ask
    # yet -- the existing locks cover only the feature-disabled
    # 403, the create/read scope-guard 403s, and the
    # set-model-preference 403s. The endpoint takes a
    # required `query: AIAskRequestDto` body parameter
    # (ai_endpoint.py:191-199) whose fields are question
    # (required str, max_length=2000), model_name
    # (Optional[str]), and session_id (Optional[str])
    # (ai_dto.py:36-40), so a JSON list question cannot
    # coerce to the str field and fails FastAPI request
    # validation before the handler runs: no OllamaChat is
    # constructed, no LLM call is made, no streaming
    # response is produced, and no chat history or session
    # record is written. The AI router is feature-gated at
    # the router level (Feature.CHAT), and FastAPI solves
    # dependencies before validating the endpoint's own
    # body, so the gate must pass first -- otherwise its
    # FeatureNotEnabledException 403 would mask the 422.
    # The default conftest mock is a plain UserDto with no
    # role attribute and would 500 under the gate
    # (check_feature_access reads currentUser.role), so
    # the caller is overridden per-test with a MeResponseDto
    # whose role carries HOST_MANAGE_TENANTS and whose
    # tenant_id is None: the gate's host branch returns
    # True immediately (feature_access_management.py),
    # with no tenant lookup, mirroring the host-caller
    # pattern of the feature-disabled lock in this file
    # but with the permission that admits the host caller.
    # The override is restored in finally. The other field
    # sent is valid (model_name "llama3"); session_id is
    # omitted (valid None). A list is used as the
    # non-string payload because Pydantic v2 lax mode has
    # no list-to-str coercion path, and a blank string
    # would also 422 but would pin the blank-value class
    # (the handler's "Question cannot be empty" path),
    # not the non-string class. The DTO's
    # normalize_identifiers model_validator (mode="after")
    # runs only after field validation passes and only
    # touches model_name/session_id when already str, so
    # it cannot mask the 422. The endpoint's
    # get_local_ai_service and get_tenant_id dependencies
    # are also solved before body validation but cannot
    # fail here (container resolve; request.state lookup
    # returning None with no header). Deliberately no
    # exact error-type assertion, mirroring the tenant
    # non-string locks. Deliberately no Cache-Control/
    # Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it,
    # mirroring the notification 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors,
    # with no path exclusions.
    from api.domain.entities.ai import AISessions
    from api.domain.enum.permission import Permission

    async def override_get_current_user_host_admin():
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
                name="Host AI administrator",
                description="Role carrying HOST_MANAGE_TENANTS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.HOST_MANAGE_TENANTS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_host_admin
    try:
        response = await client.post(
            "/ai/ask",
            json={"question": ["Hello"], "model_name": "llama3"},
        )
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "question" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the /ai/ask feature-disabled lock, using
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
    # Postcondition: validation fails before the handler runs,
    # so no chat session was created -- the exchange is never
    # saved.
    sessions = await AISessions.find_all().to_list()
    assert sessions == []


@pytest.mark.asyncio
async def test_post_ai_ask_nonstring_model_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The AI ask POST with a non-string model_name:
    """
    # The SECOND lock of the AI ask per-field validation sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for post_ai_ask_nonstring_model_name before
    # appending; the only existing 422 lock in this file is the
    # question lock (iteration 2872). The endpoint takes a
    # required `query: AIAskRequestDto` body parameter
    # (ai_endpoint.py:191-199) whose fields are question
    # (required str, max_length=2000), model_name
    # (Optional[str]), and session_id (Optional[str])
    # (ai_dto.py:36-40), so a JSON list model_name cannot
    # coerce to the str field and fails FastAPI request
    # validation before the handler runs: no OllamaChat is
    # constructed, no LLM call is made, no streaming
    # response is produced, and no chat history or session
    # record is written. The AI router is feature-gated at
    # the router level (Feature.CHAT), and FastAPI solves
    # dependencies before validating the endpoint's own
    # body, so the gate must pass first -- otherwise its
    # FeatureNotEnabledException 403 would mask the 422.
    # The default conftest mock is a plain UserDto with no
    # role attribute and would 500 under the gate
    # (check_feature_access reads currentUser.role), so
    # the caller is overridden per-test with a MeResponseDto
    # whose role carries HOST_MANAGE_TENANTS and whose
    # tenant_id is None: the gate's host branch returns
    # True immediately (feature_access_management.py),
    # with no tenant lookup, mirroring the host-caller
    # pattern of the question lock in this file. The
    # override is restored in finally. The other field
    # sent is valid (question "Hello"); session_id is
    # omitted (valid None). A list is used as the
    # non-string payload because Pydantic v2 lax mode has
    # no list-to-str coercion path, and model_name is
    # Optional[str] with default None, so None is a valid
    # value -- only the non-string type is locked here.
    # The DTO's normalize_identifiers model_validator
    # (mode="after") runs only after field validation
    # passes and only touches model_name/session_id when
    # already str, so it cannot mask the 422. The
    # endpoint's get_local_ai_service and get_tenant_id
    # dependencies are also solved before body validation
    # but cannot fail here (container resolve;
    # request.state lookup returning None with no
    # header). Deliberately no exact error-type assertion,
    # mirroring the tenant non-string locks. Deliberately
    # no Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to
    # it, mirroring the notification 422 locks. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation
    # errors, with no path exclusions.
    from api.domain.entities.ai import AISessions
    from api.domain.enum.permission import Permission

    async def override_get_current_user_host_admin():
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
                name="Host AI administrator",
                description="Role carrying HOST_MANAGE_TENANTS for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.HOST_MANAGE_TENANTS],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_host_admin
    try:
        response = await client.post(
            "/ai/ask",
            json={"question": "Hello", "model_name": ["llama3"]},
        )
    finally:
        if original_override is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = original_override
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "model_name" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the /ai/ask feature-disabled lock, using
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
    # Postcondition: validation fails before the handler runs,
    # so no chat session was created -- the exchange is never
    # saved.
    sessions = await AISessions.find_all().to_list()
    assert sessions == []
