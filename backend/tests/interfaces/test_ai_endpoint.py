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
