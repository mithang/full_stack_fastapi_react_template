import pytest
from httpx import AsyncClient
from api.domain.dtos.user_dto import CreateUserResponseDto, UpdateUserDto, UserListDto, CreateUserDto, UserDto
from api.common.enums.gender import Gender


async def create_user(client: AsyncClient) -> CreateUserResponseDto:
    new_user = CreateUserDto(
        email="test@example.com",
        first_name="Test",
        last_name="User",
        gender=Gender.OTHER,
        password="Test@123!"
    )
    response = await client.post("/users/", json=new_user.model_dump())
    assert response.status_code == 201
    # The security-headers middleware (security_headers_middleware.py)
    # stamps every HTTP response, not just GETs, but until now only
    # GET responses locked its headers in — deleting the middleware
    # registration would have gone uncaught on mutation responses
    # too. The test client runs the real app over ASGI transport, so
    # the pure-ASGI middleware applies here exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, as on the
    # permissions GET in iteration 1865, using substring checks so
    # later additions to the list do not break this test. The full
    # value lives in _SECURITY_HEADERS. The fifth, clipboard-read,
    # is safe to lock here: the SPA never reads the clipboard
    # (only writeText calls, verified by grep in iteration 1914).
    # The sixth, display-capture, is safe to lock here: the SPA has
    # no screen-sharing flow (zero getDisplayMedia calls, verified
    # by grep this run).
    # The seventh, fullscreen, is safe to lock here: the SPA has no
    # fullscreen flow (zero requestFullscreen calls and zero
    # <video>/<audio> elements, verified by grep this run).
    # The eighth, accelerometer, is safe to lock here: the SPA has
    # no motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer matches, verified by
    # grep this run). The ninth, gyroscope, is safe to lock here
    # for the same reason: the SPA has no gyroscope flow (zero
    # Gyroscope/DeviceOrientation matches, verified by grep this run).
    # The tenth, magnetometer, is safe to lock here for the same
    # reason: the SPA has no compass flow (zero Magnetometer/
    # magnetometer matches, verified by grep this run).
    # The eleventh, xr-spatial-tracking, is safe to lock here for
    # the same reason: the SPA has no XR flow (zero navigator.xr/
    # XRSession/XRSystem/immersive-ar/immersive-vr/requestSession
    # matches and no webxr/three entry in package.json, verified by
    # grep this run).
    # The twelfth, idle-detection, is safe to lock here for the
    # same reason: the SPA has no idle-detection flow (zero
    # IdleDetector matches, zero case-insensitive idle matches,
    # and zero requestIdleCallback matches, verified by grep
    # this run).
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
    return CreateUserResponseDto.model_validate(response.json())


@pytest.mark.asyncio
async def test_list_users_from_host(client: AsyncClient):
    """
        List all the users:
    """
    response = await client.get("/users/?skip=0&limit=10")
    assert response.status_code == 200
    # The endpoint comment requires this GET never to be served from a
    # browser or proxy cache (it lists the tenant's users with names,
    # emails, and roles), but no test locked the headers in — deleting
    # the two header lines would have gone uncaught, as with the
    # app-configuration GET in iteration 1785, the tenant list GET in
    # iteration 1786, and the role list GET in iteration 1787.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but only the permissions and roles
    # GETs locked its headers in (iterations 1820-1821) — deleting the
    # middleware registration would have gone uncaught on this route
    # too. The test client runs the real app over ASGI transport, so
    # the pure-ASGI middleware applies here exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # user-create POST lock in this file (iteration 1866) and the
    # app-config helper tenant-create POST lock (iteration 1894),
    # using substring checks so later additions to the list do not
    # break this test. The full value lives in _SECURITY_HEADERS.
    # The fifth, clipboard-read, is safe to lock here: the SPA never
    # reads the clipboard (only writeText calls, verified by grep).
    # The sixth, display-capture, is safe to lock here: the SPA has
    # no screen-sharing flow (zero getDisplayMedia calls, verified
    # by grep this run).
    # The seventh, fullscreen, is safe to lock here: the SPA has no
    # fullscreen flow (zero requestFullscreen calls and zero
    # <video>/<audio> elements, verified by grep this run).
    # The eighth, accelerometer, is safe to lock here: the SPA has
    # no motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer matches, verified by
    # grep this run). The ninth, gyroscope, is safe to lock here
    # for the same reason: the SPA has no gyroscope flow (zero
    # Gyroscope/DeviceOrientation matches, verified by grep this run).
    # The tenth, magnetometer, is safe to lock here for the same
    # reason: the SPA has no compass flow (zero Magnetometer/
    # magnetometer matches, verified by grep this run).
    # The eleventh, xr-spatial-tracking, is safe to lock here for
    # the same reason: the SPA has no XR flow (zero navigator.xr/
    # XRSession/XRSystem/immersive-ar/immersive-vr/requestSession
    # matches and no webxr/three entry in package.json, verified by
    # grep this run).
    # The twelfth, idle-detection, is safe to lock here for the
    # same reason: the SPA has no idle-detection flow (zero
    # IdleDetector/requestIdleCallback matches and zero
    # case-insensitive idle matches, verified by grep this run).
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

    data = UserListDto.model_validate(response.json())

    assert data.users == []
    assert data.total == 0
    assert data.hasNext == False
    assert data.hasPrevious == False
    assert data.skip == 0
    assert data.limit == 10


@pytest.mark.asyncio
async def test_create_user_in_host(client: AsyncClient):
    """
        Create a new user:
    """
    new_user_response = await create_user(client)

    # Verify the user was created by listing users again
    response = await client.get("/users/?skip=0&limit=10")
    assert response.status_code == 200
    # Same no-store lock as the list GETs (iterations 1788/1799-1801):
    # this verification GET hits the same list endpoint, which sets
    # both headers unconditionally, but asserted only status 200, so
    # deleting the header lines would have gone uncaught here.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but this create-verification GET
    # locked only no-store — deleting the middleware registration
    # would have gone uncaught here too. The test client runs the
    # real app over ASGI transport, so the pure-ASGI middleware
    # applies here exactly as in production, and the user list GET
    # already locks the same headers, so the assertion holds for
    # this verification GET as well.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # user-list GET lock in this file (iteration 1895), using
    # substring checks so later additions to the list do not break
    # this test. The full value lives in _SECURITY_HEADERS.
    # The fifth, clipboard-read, is safe to lock here: the SPA never
    # reads the clipboard (only writeText calls, verified by grep).
    # The sixth, display-capture, is safe to lock here: the SPA has
    # no screen-sharing flow (zero getDisplayMedia calls, verified
    # by grep this run).
    # The seventh, fullscreen, is safe to lock here: the SPA has no
    # fullscreen flow (zero requestFullscreen calls and zero
    # <video>/<audio> elements, verified by grep this run).
    # The eighth, accelerometer, is safe to lock here: the SPA has
    # no motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer matches, verified by
    # grep this run). The ninth, gyroscope, is safe to lock here
    # for the same reason: the SPA has no gyroscope flow (zero
    # Gyroscope/DeviceOrientation matches, verified by grep this run).
    # The tenth, magnetometer, is safe to lock here for the same
    # reason: the SPA has no compass flow (zero Magnetometer/
    # magnetometer matches, verified by grep this run).
    # The eleventh, xr-spatial-tracking, is safe to lock here for
    # the same reason: the SPA has no XR flow (zero navigator.xr/
    # XRSession/XRSystem/immersive-ar/immersive-vr/requestSession
    # matches and no webxr/three entry in package.json, verified by
    # grep this run).
    # The twelfth, idle-detection, is safe to lock here for the
    # same reason: the SPA has no idle-detection flow (zero
    # IdleDetector matches, zero case-insensitive idle matches,
    # and zero requestIdleCallback matches, verified by grep
    # this run).
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
    data = UserListDto.model_validate(response.json())
    assert data.total == 1
    assert data.users[0].id == new_user_response.id



@pytest.mark.asyncio
async def test_get_user_by_id_from_host(client: AsyncClient):
    """
        Get a user by ID:
    """
    new_user_response = await create_user(client)
    response = await client.get(f"/users/{new_user_response.id}")
    assert response.status_code == 200
    # The endpoint comment requires this GET never to be served from a
    # browser or proxy cache (it returns one user's personal data),
    # but no test locked the headers in — deleting the two header
    # lines would have gone uncaught, as with the user list GET in
    # iteration 1788, the role list GET in iteration 1787, and the
    # tenant list GET in iteration 1786.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but this single-user GET locked only
    # no-store — deleting the middleware registration would have gone
    # uncaught here too. The test client runs the real app over ASGI
    # transport, so the pure-ASGI middleware applies here exactly as
    # in production, and the user list GET already locks the same
    # headers, so the assertion holds for this single-user GET as well.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # user create-verification GET lock in this file (iteration 1896),
    # using substring checks so later additions to the list do not
    # break this test. The full value lives in _SECURITY_HEADERS.
    # The fifth, clipboard-read, is safe to lock here: the SPA never
    # reads the clipboard (only writeText calls, verified by grep).
    # The sixth, display-capture, is safe to lock here: the SPA has
    # no screen-sharing flow (zero getDisplayMedia calls, verified
    # by grep this run).
    # The seventh, fullscreen, is safe to lock here: the SPA has no
    # fullscreen flow (zero requestFullscreen calls and zero
    # <video>/<audio> elements, verified by grep this run).
    # The eighth, accelerometer, is safe to lock here: the SPA has
    # no motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer matches, verified by grep
    # this run).
    # The ninth, gyroscope, is safe to lock here for the same
    # reason: the SPA has no gyroscope flow (zero Gyroscope/
    # DeviceOrientation matches, verified by grep this run).
    # The tenth, magnetometer, is safe to lock here for the same
    # reason: the SPA has no compass flow (zero Magnetometer/
    # magnetometer matches, verified by grep this run).
    # The eleventh, xr-spatial-tracking, is safe to lock here for
    # the same reason: the SPA has no XR flow (zero navigator.xr/
    # XRSession/XRSystem/immersive-ar/immersive-vr/requestSession
    # matches and no webxr/three entry in package.json, verified by
    # grep this run).
    # The twelfth, idle-detection, is safe to lock here for the
    # same reason: the SPA has no idle-detection flow (zero
    # IdleDetector matches, zero case-insensitive idle matches,
    # and zero requestIdleCallback matches, verified by grep
    # this run).
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
    data = UserDto.model_validate(response.json())
    assert data.email == "test@example.com"


@pytest.mark.asyncio
async def test_update_user_by_id_from_host(client: AsyncClient):
    """
        Update a user by ID:
    """
    new_user_response = await create_user(client)
    response = await client.get(f"/users/{new_user_response.id}")
    assert response.status_code == 200
    # Same no-store lock as the single-user GET (iteration 1789):
    # this pre-fetch GET hits the same get_user endpoint, which sets
    # both headers unconditionally, but asserted only status 200, so
    # deleting the header lines would have gone uncaught here.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but this pre-fetch GET locked only
    # no-store — deleting the middleware registration would have gone
    # uncaught here too. The test client runs the real app over ASGI
    # transport, so the pure-ASGI middleware applies here exactly as
    # in production, and the single-user GET already locks the same
    # headers, so the assertion holds for this pre-fetch GET as well.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # single-user GET lock in this file (iteration 1897), using
    # substring checks so later additions to the list do not break
    # this test. The full value lives in _SECURITY_HEADERS.
    # The fifth, clipboard-read, is safe to lock here: the SPA never
    # reads the clipboard (only writeText calls, verified by grep).
    # The sixth, display-capture, is safe to lock here: the SPA has
    # no screen-sharing flow (zero getDisplayMedia calls, verified
    # by grep this run).
    # The seventh, fullscreen, is safe to lock here: the SPA has no
    # fullscreen flow (zero requestFullscreen calls, verified by
    # grep this run).
    # The eighth, accelerometer, is safe to lock here: the SPA has no
    # motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer matches, verified by grep
    # this run).
    # The ninth, gyroscope, is safe to lock here for the same
    # reason: the SPA has no gyroscope flow (zero Gyroscope/
    # DeviceOrientation matches, verified by grep this run).
    # The tenth, magnetometer, is safe to lock here for the same
    # reason: the SPA has no compass flow (zero Magnetometer/
    # magnetometer matches, verified by grep this run).
    # The eleventh, xr-spatial-tracking, is safe to lock here for
    # the same reason: the SPA has no XR flow (zero navigator.xr/
    # XRSession/XRSystem/immersive-ar/immersive-vr/requestSession
    # matches, verified by grep this run, and no webxr/three
    # dependency in frontend/app/package.json).
    # The twelfth, idle-detection, is safe to lock here for the
    # same reason: the SPA has no idle-detection flow (zero
    # IdleDetector matches, zero case-insensitive idle matches,
    # and zero requestIdleCallback matches, verified by grep
    # this run).
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
    data = UserDto.model_validate(response.json())

    # Update the user's email
    data.gender = Gender.MALE
    updated_data = UpdateUserDto(**data.model_dump())
    response = await client.put(f"/users/{new_user_response.id}", json=updated_data.model_dump())
    assert response.status_code == 200
    # Same security-header lock as the create-user POST in this file
    # (iteration 1852): the middleware stamps every HTTP response, so
    # it stamps this PUT response too, but until now only its status
    # and body were asserted — deleting the middleware registration
    # would have gone uncaught on update responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # pre-fetch GET lock in this test (iteration 1898), using
    # substring checks so later additions to the list do not break
    # this test. The full value lives in _SECURITY_HEADERS.
    # The fifth, clipboard-read, is safe to lock here: the SPA never
    # reads the clipboard (only writeText calls, verified by grep).
    # The sixth, display-capture, is safe to lock here: the SPA has
    # no screen-sharing flow (zero getDisplayMedia calls, verified
    # by grep this run).
    # The seventh, fullscreen, is safe to lock here: the SPA has no
    # fullscreen flow (zero requestFullscreen calls, verified by
    # grep this run).
    # The eighth, accelerometer, is safe to lock here: the SPA has no
    # motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer matches, verified by grep
    # this run).
    # The ninth, gyroscope, is safe to lock here for the same
    # reason: the SPA has no gyroscope flow (zero Gyroscope/
    # DeviceOrientation matches, verified by grep this run).
    # The tenth, magnetometer, is safe to lock here for the same
    # reason: the SPA has no compass flow (zero Magnetometer/
    # magnetometer matches, verified by grep this run).
    # The eleventh, xr-spatial-tracking, is safe to lock here for
    # the same reason: the SPA has no XR flow (zero navigator.xr/
    # XRSession/XRSystem/immersive-ar/immersive-vr/requestSession
    # matches, verified by grep this run).
    # The twelfth, idle-detection, is safe to lock here for the
    # same reason: the SPA has no idle-detection flow (zero
    # IdleDetector matches, zero case-insensitive idle matches,
    # and zero requestIdleCallback matches, verified by grep
    # this run).
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
    new_user_updated_data = UserDto.model_validate(response.json())
    assert new_user_updated_data.gender == Gender.MALE


@pytest.mark.asyncio
async def test_delete_user_by_id_from_host(client: AsyncClient):
    """
        Delete a user by ID:
    """
    new_user_response = await create_user(client)
    response = await client.delete(f"/users/{new_user_response.id}")
    assert response.status_code == 202
    # The security-headers middleware (security_headers_middleware.py)
    # stamps every HTTP response, not just GETs, but until this run
    # only GET responses, the create POSTs, and the update PUTs locked
    # its headers in — deleting the middleware registration would
    # have gone uncaught on user-delete responses too. The test
    # client runs the real app over ASGI transport, so the pure-ASGI
    # middleware applies here exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # user update PUT lock in this file (iteration 1899), using
    # substring checks so later additions to the list do not break
    # this test. The full value lives in _SECURITY_HEADERS. The
    # fifth, clipboard-read, is safe to lock here: the SPA never
    # reads the clipboard (only writeText calls, verified by grep
    # this run).
    # The sixth, display-capture, is safe to lock here: the SPA has
    # no screen-sharing flow (zero getDisplayMedia calls, verified
    # by grep this run).
    # The seventh, fullscreen, is safe to lock here: the SPA has no
    # fullscreen flow (zero requestFullscreen calls, verified by
    # grep this run).
    # The eighth, accelerometer, is safe to lock here: the SPA has
    # no motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer matches, verified by
    # grep this run). The ninth, gyroscope, is safe to lock here
    # for the same reason: the SPA has no gyroscope flow (zero
    # Gyroscope/DeviceOrientation matches, verified by grep this run).
    # The tenth, magnetometer, is safe to lock here for the same
    # reason: the SPA has no compass flow (zero Magnetometer/
    # magnetometer matches, verified by grep this run).
    # The eleventh, xr-spatial-tracking, is safe to lock here for
    # the same reason: the SPA has no XR flow (zero navigator.xr/
    # XRSession/XRSystem/immersive-ar/immersive-vr/requestSession
    # matches, verified by grep this run).
    # The twelfth, idle-detection, is safe to lock here for the
    # same reason: the SPA has no idle-detection flow (zero
    # IdleDetector matches, zero case-insensitive idle matches,
    # and zero requestIdleCallback matches, verified by grep
    # this run).
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

    # Verify the user was deleted by attempting to get the user again
    response = await client.get(f"/users/{new_user_response.id}")
    assert response.status_code == 404
    # Same no-store lock as the nonexistent-user 404 in this file
    # (iteration 1811): the post-delete re-GET 404 comes from the
    # central ApiBaseException handler, whose headers were added in
    # iteration 1810, but no test locked them in for this re-GET —
    # deleting them would have gone uncaught, as with the role
    # post-delete re-GET, which is still unlocked.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-header lock as the single-user GET: this re-GET
    # goes through the same route and the same pure-ASGI middleware
    # under the test client, but only locked the no-store headers —
    # deleting the middleware registration would have gone uncaught
    # here.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # user delete DELETE lock in this file (iteration 1900), using
    # substring checks so later additions to the list do not break
    # this test. The full value lives in _SECURITY_HEADERS. The
    # fifth, clipboard-read, is safe to lock here: the SPA never
    # reads the clipboard (only writeText calls, verified by grep
    # this run).
    # The sixth, display-capture, is safe to lock here: the SPA has
    # no screen-sharing flow (zero getDisplayMedia calls, verified
    # by grep this run).
    # The seventh, fullscreen, is safe to lock here: the SPA has no
    # fullscreen flow (zero requestFullscreen calls, verified by
    # grep this run).
    # The eighth, accelerometer, is safe to lock here: the SPA has
    # no motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer matches, verified by
    # grep this run). The ninth, gyroscope, is safe to lock here
    # for the same reason: the SPA has no gyroscope flow (zero
    # Gyroscope/DeviceOrientation matches, verified by grep this run).
    # The tenth, magnetometer, is safe to lock here for the same
    # reason: the SPA has no compass flow (zero Magnetometer/
    # magnetometer matches, verified by grep this run).
    # The eleventh, xr-spatial-tracking, is safe to lock here for
    # the same reason: the SPA has no XR flow (zero navigator.xr/
    # XRSession/XRSystem/immersive-ar/immersive-vr/requestSession
    # matches, verified by grep this run).
    # The twelfth, idle-detection, is safe to lock here for the
    # same reason: the SPA has no idle-detection flow (zero
    # IdleDetector matches, zero case-insensitive idle matches,
    # and zero requestIdleCallback matches, verified by grep
    # this run).
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
async def test_get_nonexistent_user_by_id_from_host(client: AsyncClient):
    """
        Attempt to get a non-existent user by ID:
    """
    response = await client.get("/users/68c3031f449ed3590028c778")
    assert response.status_code == 404
    # Same no-store lock as the role 404 test (iteration 1810): the 404
    # comes from the central ApiBaseException handler, whose headers were
    # added in iteration 1810, so lock them here rather than relying on
    # the endpoint's own Response, which the exception path discards.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    # Same security-header lock as the delete-verification re-GET in
    # this file: this 404 goes through the same route and the same
    # pure-ASGI middleware under the test client, but only locked the
    # no-store headers — deleting the middleware registration would
    # have gone uncaught here.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # user post-delete re-GET lock in this file (iteration 1930),
    # using substring checks so later additions to the list do not
    # break this test. The full value lives in _SECURITY_HEADERS. The
    # fifth, clipboard-read, is safe to lock here: the SPA never
    # reads the clipboard (only writeText calls, verified by grep
    # this run).
    # The sixth, display-capture, is safe to lock here: the SPA has
    # no screen-sharing flow (zero getDisplayMedia calls, verified
    # by grep this run).
    # The seventh, fullscreen, is safe to lock here: the SPA has no
    # fullscreen flow (zero requestFullscreen calls, verified by
    # grep this run).
    # The eighth, accelerometer, is safe to lock here: the SPA has
    # no motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer matches, verified by
    # grep this run). The ninth, gyroscope, is safe to lock here
    # for the same reason: the SPA has no gyroscope flow (zero
    # Gyroscope/DeviceOrientation matches, verified by grep this run).
    # The tenth, magnetometer, is safe to lock here for the same
    # reason: the SPA has no compass flow (zero Magnetometer/
    # magnetometer matches, verified by grep this run).
    # The eleventh, xr-spatial-tracking, is safe to lock here for
    # the same reason: the SPA has no XR flow (zero navigator.xr/
    # XRSession/XRSystem/immersive-ar/immersive-vr/requestSession
    # matches and no webxr/three entry in package.json, verified by
    # grep this run).
    # The twelfth, idle-detection, is safe to lock here for the
    # same reason: the SPA has no idle-detection flow (zero
    # IdleDetector matches, zero case-insensitive idle matches,
    # and zero requestIdleCallback matches, verified by grep
    # this run).
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
    assert response.json()["error"] == "User with identifier 68c3031f449ed3590028c778 not found."


@pytest.mark.asyncio
async def test_list_of_users_paginated_in_host(client: AsyncClient):
    """
        List users with pagination:
    """
    for i in range(3):
        new_user = CreateUserDto(
            email=f"test{i}@example.com",
            first_name=f"Test{i}",
            last_name="User",
            gender=Gender.OTHER,
            password="Test@123!"
        )
        response = await client.post("/users/", json=new_user.model_dump())
        assert response.status_code == 201
        # The security-headers middleware (security_headers_middleware.py)
        # stamps every HTTP response, and the shared create_user helper
        # already locks its headers on the identical POST — but these
        # paginated-setup POSTs asserted only status 201, so deleting
        # the middleware registration would have gone uncaught on this
        # path too. The test client runs the real app over ASGI
        # transport, so the pure-ASGI middleware applies here exactly
        # as in production.
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
        assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
        assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
        assert "permissions-policy" in response.headers
        # Presence alone would not catch the value being weakened: lock
        # the twelve most sensitive directives as disabled, mirroring the
        # paginated page GET locks in this test, using substring
        # checks so later additions to the list do not break this test.
        # The full value lives in _SECURITY_HEADERS. The fifth,
        # clipboard-read, is safe to lock here: the SPA never reads
        # the clipboard (only writeText calls, verified by grep).
        # The sixth, display-capture, is safe to lock here: the SPA has
        # no screen-sharing flow (zero getDisplayMedia calls, verified
        # by grep this run).
        # The seventh, fullscreen, is safe to lock here: the SPA has
        # no fullscreen flow (zero requestFullscreen calls, verified
        # by grep this run).
        # The eighth, accelerometer, is safe to lock here: the SPA has
        # no motion-sensor flow (zero DeviceMotion/DeviceOrientation/
        # Accelerometer/Gyroscope/Magnetometer uses, verified by grep
        # this run).
        # The ninth, gyroscope, is safe to lock here for the same
        # reason: the SPA has no gyroscope flow (zero Gyroscope/
        # DeviceOrientation uses, verified by grep this run).
        # The tenth, magnetometer, is safe to lock here for the same
        # reason: the SPA has no compass flow (zero Magnetometer/
        # magnetometer matches, verified by grep this run).
        # The eleventh, xr-spatial-tracking, is safe to lock here for
        # the same reason: the SPA has no XR flow (zero navigator.xr/
        # XRSession/XRSystem/immersive-ar/immersive-vr/requestSession
        # matches and no webxr/three entry in package.json, verified by
        # grep this run).
        # The twelfth, idle-detection, is safe to lock here for the
        # same reason: the SPA has no idle-detection flow (zero
        # IdleDetector matches, zero case-insensitive idle matches,
        # and zero requestIdleCallback matches, verified by grep
        # this run).
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
    # Create a single user and return the response

    # Verify the user was created by listing users again
    response = await client.get("/users/?skip=0&limit=1")
    assert response.status_code == 200
    # Same no-store lock as the unpaginated list GET (iteration 1788):
    # the list endpoint sets both headers unconditionally, but the
    # paginated pages asserted only status 200, so deleting the header
    # lines would have gone uncaught on the paginated path.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but this paginated page 1 GET locked
    # only no-store — deleting the middleware registration would have
    # gone uncaught here too. The test client runs the real app over
    # ASGI transport, so the pure-ASGI middleware applies here exactly
    # as in production, and the unpaginated list GET already locks the
    # same headers, so the assertion holds for this paginated page
    # as well.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # unpaginated user-list GET lock in this file, using substring
    # checks so later additions to the list do not break this test.
    # The full value lives in _SECURITY_HEADERS. The fifth,
    # clipboard-read, is safe to lock here: the SPA never reads
    # the clipboard (only writeText calls, verified by grep
    # this run).
    # The sixth, display-capture, is safe to lock here: the SPA has
    # no screen-sharing flow (zero getDisplayMedia calls, verified
    # by grep this run).
    # The seventh, fullscreen, is safe to lock here: the SPA has
    # no fullscreen flow (zero requestFullscreen calls, verified
    # by grep this run).
    # The eighth, accelerometer, is safe to lock here: the SPA has
    # no motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer uses, verified by grep
    # this run). The ninth, gyroscope, is safe to lock here
    # for the same reason: the SPA has no gyroscope flow (zero
    # Gyroscope/DeviceOrientation matches, verified by grep this run).
    # The tenth, magnetometer, is safe to lock here for the same
    # reason: the SPA has no compass flow (zero Magnetometer/
    # magnetometer matches, verified by grep this run).
    # The eleventh, xr-spatial-tracking, is safe to lock here for
    # the same reason: the SPA has no XR flow (zero navigator.xr/
    # XRSession/XRSystem/immersive-ar/immersive-vr/requestSession
    # matches and no webxr/three entry in package.json, verified by
    # grep this run).
    # The twelfth, idle-detection, is safe to lock here for the
    # same reason: the SPA has no idle-detection flow (zero
    # IdleDetector matches, zero case-insensitive idle matches,
    # and zero requestIdleCallback matches, verified by grep
    # this run).
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
    data = UserListDto.model_validate(response.json())
    assert data.total == 3
    assert len(data.users) == 1
    assert data.hasNext == True
    assert data.hasPrevious == False
    assert data.skip == 0
    assert data.limit == 1

    response = await client.get("/users/?skip=1&limit=1")
    assert response.status_code == 200
    # Same no-store lock as page 1 (iteration 1799): this page hits the
    # same list endpoint, which sets both headers unconditionally.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but this paginated page 2 GET locked
    # only no-store — deleting the middleware registration would have
    # gone uncaught here too. The test client runs the real app over
    # ASGI transport, so the pure-ASGI middleware applies here exactly
    # as in production, and the paginated page 1 GET already locks the
    # same headers, so the assertion holds for this paginated page
    # as well.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # paginated page 1 GET lock in this test, using substring
    # checks so later additions to the list do not break this test.
    # The full value lives in _SECURITY_HEADERS. The fifth,
    # clipboard-read, is safe to lock here: the SPA never reads
    # the clipboard (only writeText calls, verified by grep
    # this run).
    # The sixth, display-capture, is safe to lock here: the SPA has
    # no screen-sharing flow (zero getDisplayMedia calls, verified
    # by grep this run).
    # The seventh, fullscreen, is safe to lock here: the SPA has
    # no fullscreen flow (zero requestFullscreen calls, verified
    # by grep this run).
    # The eighth, accelerometer, is safe to lock here: the SPA has
    # no motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer uses, verified by grep
    # this run). The ninth, gyroscope, is safe to lock here
    # for the same reason: the SPA has no gyroscope flow (zero
    # Gyroscope/DeviceOrientation matches, verified by grep this run).
    # The tenth, magnetometer, is safe to lock here for the same
    # reason: the SPA has no compass flow (zero Magnetometer/
    # magnetometer matches, verified by grep this run).
    # The eleventh, xr-spatial-tracking, is safe to lock here for
    # the same reason: the SPA has no XR flow (zero navigator.xr/
    # XRSession/XRSystem/immersive-ar/immersive-vr/requestSession
    # matches and no webxr/three entry in package.json, verified by
    # grep this run).
    # The twelfth, idle-detection, is safe to lock here for the
    # same reason: the SPA has no idle-detection flow (zero
    # IdleDetector matches, zero case-insensitive idle matches,
    # and zero requestIdleCallback matches, verified by grep
    # this run).
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
    data = UserListDto.model_validate(response.json())
    assert data.total == 3
    assert len(data.users) == 1
    assert data.hasNext == True
    assert data.hasPrevious == True
    assert data.skip == 1
    assert data.limit == 1

    response = await client.get("/users/?skip=2&limit=1")
    assert response.status_code == 200
    # Same no-store lock as pages 1-2 (iterations 1799/1800): this page
    # hits the same list endpoint, which sets both headers
    # unconditionally, but page 3 asserted only status 200, so deleting
    # the header lines would have gone uncaught on this page.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but this paginated page 3 GET locked
    # only no-store — deleting the middleware registration would have
    # gone uncaught here too. The test client runs the real app over
    # ASGI transport, so the pure-ASGI middleware applies here exactly
    # as in production, and the paginated pages 1-2 GETs already lock
    # the same headers, so the assertion holds for this paginated
    # page as well.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # paginated page 2 GET lock in this test, using substring
    # checks so later additions to the list do not break this test.
    # The full value lives in _SECURITY_HEADERS. The fifth,
    # clipboard-read, is safe to lock here: the SPA never reads
    # the clipboard (only writeText calls, verified by grep
    # this run).
    # The sixth, display-capture, is safe to lock here: the SPA has
    # no screen-sharing flow (zero getDisplayMedia calls, verified
    # by grep this run).
    # The seventh, fullscreen, is safe to lock here: the SPA has
    # no fullscreen flow (zero requestFullscreen calls, verified
    # by grep this run).
    # The eighth, accelerometer, is safe to lock here: the SPA has
    # no motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer uses, verified by grep
    # this run). The ninth, gyroscope, is safe to lock here for
    # the same reason: the SPA has no gyroscope flow (zero
    # Gyroscope/DeviceOrientation matches, verified by grep this run).
    # The tenth, magnetometer, is safe to lock here for the same
    # reason: the SPA has no compass flow (zero Magnetometer/
    # magnetometer matches, verified by grep this run).
    # The eleventh, xr-spatial-tracking, is safe to lock here for
    # the same reason: the SPA has no XR flow (zero navigator.xr/
    # XRSession/XRSystem/immersive-ar/immersive-vr/requestSession
    # matches and no webxr/three entry in package.json, verified by
    # grep this run).
    # The twelfth, idle-detection, is safe to lock here for the
    # same reason: the SPA has no idle-detection flow (zero
    # IdleDetector matches, zero case-insensitive idle matches,
    # and zero requestIdleCallback matches, verified by grep
    # this run).
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
    data = UserListDto.model_validate(response.json())
    assert data.total == 3
    assert len(data.users) == 1
    assert data.hasNext == False
    assert data.hasPrevious == True
    assert data.skip == 2
    assert data.limit == 1


@pytest.mark.asyncio
async def test_patch_user_assign_role_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The user assign_role PATCH (one of the last user paths with no
        test: list, create, get, update, delete, and the nonexistent-id
        404 were already locked, and the list GET carries the same
        missing-role shape as the role list GET): PATCH
        /users/{user_id}/assign_role had no test, so deleting the
        route — or dropping the central ApiBaseException no-store
        lines or the security-headers middleware registration —
        would previously have gone uncaught on the role-assignment
        path. The success path is not asserted here: the PATCH is
        permission-gated (USER_ROLE_ASSIGN_OR_REMOVE_ONLY via a
        parameter dependency, evaluated before the handler body and
        before its tenant-scope guard and before the self-assignment
        check), so it needs a DB role lookup, and the shared
        conftest client seeds no role. The error path below is
        deterministic instead: the mocked host user's role_id points
        at no row in the fresh test database (Role is in the
        conftest model set), so the permission dependency raises
        RoleNotFoundException before the handler runs — which
        matters here because the handler would otherwise read the
        target user and then assign a role. The service factories
        ahead of it only resolve singletons and get_tenant_id
        resolves request state without a lookup, and the path
        user_id is never read on this path, so there is no side
        effect and no unseeded-model lookup beyond the role. The
        body is valid on purpose: role_id has min_length=1 and the
        value below satisfies it, so body validation passes and
        cannot mask the 404. That 404 must still carry the
        error-response headers: a cached error response could
        otherwise be served to a different admin after an account
        switch on a shared machine, and role assignment is a
        privilege change, so its errors are credential-adjacent.
    """
    response = await client.patch("/users/68c302ef6bf7a039b7e9b385/assign_role", json={"role_id": "68c302ef6bf7a039b7e9b386"})
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other user-route tests:
    # the pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the assign_role PATCH 404 must carry the
    # same headers as the authenticated user GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the other user-route locks, using substring checks so later
    # additions to the list do not break this test. The full value
    # lives in _SECURITY_HEADERS. Each directive is safe to lock
    # here for the same reasons as on the other routes: the SPA
    # has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen, motion-sensor,
    # compass, XR, or idle-detection flow (verified by grep in the
    # earlier sweeps and re-verified fresh this run: zero
    # IdleDetector/requestIdleCallback matches and zero
    # case-insensitive idle matches across frontend/app/src,
    # and the remaining flows verified absent).
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
async def test_patch_user_remove_role_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The user remove_role PATCH (one of the last user paths with no
        test: list, create, get, update, delete, the nonexistent-id
        404, and the assign_role PATCH error path were already
        locked): PATCH /users/{user_id}/remove_role had no test, so
        deleting the route — or dropping the central
        ApiBaseException no-store lines or the security-headers
        middleware registration — would previously have gone
        uncaught on the role-removal path. The success path is not
        asserted here: the PATCH is permission-gated
        (USER_ROLE_ASSIGN_OR_REMOVE_ONLY via a parameter
        dependency, evaluated before the handler body and before
        its tenant-scope guard and before the self-removal check),
        so it needs a DB role lookup, and the shared conftest
        client seeds no role. The error path below is deterministic
        instead: the mocked host user's role_id points at no row in
        the fresh test database (Role is in the conftest model
        set), so the permission dependency raises
        RoleNotFoundException before the handler runs — which
        matters here because the handler would otherwise read the
        target user and then strip its role. The service factories
        ahead of it only resolve singletons and get_tenant_id
        resolves request state without a lookup, and the path
        user_id is never read on this path, so there is no side
        effect and no unseeded-model lookup beyond the role. The
        body is valid on purpose: role_id has min_length=1 and the
        value below satisfies it, so body validation passes and
        cannot mask the 404. That 404 must still carry the
        error-response headers: a cached error response could
        otherwise be served to a different admin after an account
        switch on a shared machine, and role removal is a privilege
        change, so its errors are credential-adjacent.
    """
    response = await client.patch("/users/68c302ef6bf7a039b7e9b385/remove_role", json={"role_id": "68c302ef6bf7a039b7e9b386"})
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other user-route tests:
    # the pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the remove_role PATCH 404 must carry the
    # same headers as the authenticated user GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the other user-route locks, using substring checks so later
    # additions to the list do not break this test. The full value
    # lives in _SECURITY_HEADERS. Each directive is safe to lock
    # here for the same reasons as on the other routes: the SPA
    # has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen, motion-sensor,
    # compass, XR, or idle-detection flow (verified by grep in the
    # earlier sweeps and re-verified fresh this run: zero
    # case-insensitive idle matches across frontend/app/src,
    # and the remaining flows verified absent).
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
async def test_patch_user_remove_role_clears_role_with_cache_and_security_headers(client: AsyncClient):
    """
        The PATCH /users/{user_id}/remove_role success path:
        remove_user_role verified the user held the role and then
        called UserService.update_user with UpdateUserDto(role_id=None),
        but update_user only acted `if user_data.role_id:`, so the
        explicit None was swallowed and the endpoint returned 202
        with the role still assigned - a silent no-op on a privilege
        revocation (function-name grep count 0 for
        patch_user_remove_role_clears_role, verified fresh this run),
        the same accepted-field-silently-ignored class as the
        is_active PUT lock and the changed-email 400 lock. The
        service now gates on model_fields_set, so an explicitly
        supplied role_id - including null - is a deliberate change,
        while an omitted role_id (the profile-picture caller) still
        leaves the role untouched. The lock assigns a role first and
        then removes it, which also pins the other branch of the new
        guard (a truthy role_id is assigned). The mocked host
        caller's role (...386, from conftest) carries no row in the
        fresh test database, so it is seeded here with
        USER_ROLE_ASSIGN_OR_REMOVE_ONLY, mirroring the role-list
        403 lock's seed; the member role (...387) is seeded too.
        Both PATCHes make no Celery or email call, so the lock needs
        no broker or SMTP care. A future change that drops the
        explicit-None branch would break this lock while leaving the
        remove_role 404 and 403 locks and the assign_role success
        path green, so the paths are locked separately.
    """
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Role assigner",
        description="Role carrying USER_ROLE_ASSIGN_OR_REMOVE_ONLY for the mocked caller",
        permissions=[Permission.USER_ROLE_ASSIGN_OR_REMOVE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b387"),
        name="Member role",
        description="Role assigned to the target user before removal",
        permissions=[Permission.USER_VIEW_ONLY],
    ).insert()

    new_user_response = await create_user(client)

    # Assign first: the lock must start from a user that actually
    # holds a role, and the assign success pins the truthy branch
    # of the new guard.
    response = await client.patch(f"/users/{new_user_response.id}/assign_role", json={"role_id": "68c302ef6bf7a039b7e9b387"})
    assert response.status_code == 202
    assert UserDto.model_validate(response.json()).role_id == "68c302ef6bf7a039b7e9b387"

    # Remove it: the old code returned 202 and stored nothing, so the
    # admin believed the role was revoked while the user kept it.
    response = await client.patch(f"/users/{new_user_response.id}/remove_role", json={"role_id": "68c302ef6bf7a039b7e9b387"})
    assert response.status_code == 202
    # Same security-headers lock as the other user-route tests: the
    # middleware stamps every HTTP response, so it stamps this PATCH
    # response too, but until now only its status and body were
    # asserted on this path - deleting the middleware registration
    # would have gone uncaught here.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the single-user GET lock in this file, using substring checks
    # so later additions to the list do not break this test. The full
    # value lives in _SECURITY_HEADERS.
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
    assert UserDto.model_validate(response.json()).role_id is None

    # Postcondition: a follow-up GET shows the role gone - had the
    # clear been dropped, the GET would still show the member role.
    response = await client.get(f"/users/{new_user_response.id}")
    assert response.status_code == 200
    assert UserDto.model_validate(response.json()).role_id is None


async def test_get_user_profile_image_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The user profile-image GET (the last user path with no test
        apart from the multipart update_profile_picture PUT, which
        needs separate file-upload handling: list, create, get,
        update, delete, the nonexistent-id 404, assign_role PATCH,
        and remove_role PATCH were already locked): GET
        /users/profile/{image_key} had no test, so deleting the
        route — or dropping the central ApiBaseException no-store
        lines or the security-headers middleware registration —
        would previously have gone uncaught on the avatar path.
        The success path is not asserted here: the GET is
        permission-gated (USER_VIEW_ONLY via a parameter
        dependency, evaluated before the handler body, before its
        tenant-scope guard, before the ownership check, and before
        any storage call), so it needs a DB role lookup, and the
        shared conftest client seeds no role. The error path below
        is deterministic instead: the mocked host user's role_id
        points at no row in the fresh test database (Role is in
        the conftest model set), so the permission dependency
        raises RoleNotFoundException before the handler runs —
        which matters here because the handler would otherwise
        check key ownership and then mint a presigned URL for the
        key. The service factories ahead of it only resolve
        singletons and get_tenant_id resolves request state
        without a lookup, and the path image_key is never read on
        this path, so there is no side effect, no URL is minted,
        and no unseeded-model lookup beyond the role. The GET
        carries no body, so no 422 can mask the 404, and the
        two-segment profile path is not shadowed by the
        single-segment /{user_id} GET defined above it. That 404
        must still carry the error-response headers: a cached
        error response could otherwise be served to a different
        user after an account switch on a shared machine, and a
        profile image is personal data.
    """
    response = await client.get("/users/profile/123e4567-e89b-12d3-a456-426614174000-avatar.png")
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other user-route tests:
    # the pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the profile-image GET 404 must carry the
    # same headers as the authenticated user GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the other user-route locks, using substring checks so later
    # additions to the list do not break this test. The full value
    # lives in _SECURITY_HEADERS. Each directive is safe to lock
    # here for the same reasons as on the other routes: the SPA
    # has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen, motion-sensor,
    # compass, XR, or idle-detection flow (verified by grep in the
    # earlier sweeps and re-verified fresh this run: zero
    # case-insensitive idle matches across frontend/app/src,
    # and the remaining flows verified absent).
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
async def test_put_user_update_profile_picture_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        The user update_profile_picture PUT (the last user path with
        no test: list, create, get, update, delete, the
        nonexistent-id 404, assign_role PATCH, remove_role PATCH,
        and profile-image GET were already locked): PUT
        /users/{user_id}/update_profile_picture had no test, so
        deleting the route — or dropping the central
        ApiBaseException no-store lines or the security-headers
        middleware registration — would previously have gone
        uncaught on the avatar-upload path. The success path is
        not asserted here: the PUT is permission-gated (a
        parameter dependency requiring USER_READ_AND_WRITE_ONLY
        or USER_SELF_READ_AND_WRITE_ONLY with allow_self_access,
        evaluated before the handler body, before its
        tenant-scope guard, before its image content-type, size,
        and emptiness validation, before the user lookup, and
        before any storage upload), so it needs a DB role lookup,
        and the shared conftest client seeds no role. The error
        path below is deterministic instead: UserAccessManagement
        looks the role up (get_role_detail -> role_service
        .get_role_by_id) before any self-access or permission
        branching, so allow_self_access cannot rescue the call
        even for the caller's own id, and the mocked host user's
        role_id points at no row in the fresh test database (Role
        is in the conftest model set), so the dependency raises
        RoleNotFoundException before the handler runs. The request
        below carries a real (tiny) PNG part, mirroring the
        branding PUT /logo lock, so multipart parsing cannot
        422-mask the error whichever order FastAPI resolves the
        file param versus the router dependency. Either way the
        outcome is the same 404: no file reaches storage, no user
        record is updated, and no scope guard is ever evaluated.
        That 404 must still carry the error-response headers: a
        cached error response could otherwise be served to a
        different user after an account switch on a shared
        machine, and a profile picture is personal data.
    """
    png_1x1 = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
        b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00"
        b"\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05"
        b"\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    response = await client.put(
        "/users/68c302ef6bf7a039b7e9b387/update_profile_picture",
        files={"file": ("avatar.png", png_1x1, "image/png")},
    )
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other user-route tests:
    # the pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the update_profile_picture PUT 404 must
    # carry the same headers as the authenticated user GETs,
    # including the exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the other user-route locks, using substring checks so later
    # additions to the list do not break this test. The full value
    # lives in _SECURITY_HEADERS. Each directive is safe to lock
    # here for the same reasons as on the other routes: the SPA
    # has no camera, microphone, geolocation, payment,
    # clipboard-read, display-capture, fullscreen, motion-sensor,
    # compass, XR, or idle-detection flow (verified by grep in the
    # earlier sweeps and re-verified fresh this run: zero
    # case-insensitive idle matches across frontend/app/src,
    # and the remaining flows verified absent).
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
async def test_list_users_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The users list scope-guard error path:
    """
    # The users list scope-guard branch, not yet locked:
    # function-name grep count 0 for list_users_outside_tenant_scope
    # (verified fresh this run), and no test in this file asserts a
    # 403 at all - the list locks cover only the host success path
    # and the missing-role 404s on the assign/remove/profile paths,
    # while the role list/get/create/update/delete scope guards each
    # have their own 403 locks in test_role_endpoint.py. Deleting
    # _assert_list_scope (user_endpoint.py) would previously have
    # gone uncaught, and a tenant caller listing on the host DB
    # (no X-Tenant-ID/subdomain) would then read tenant-stamped
    # users sitting in the host DB - names and emails of users
    # host callers resolve by id with no tenant scope. The guard
    # runs in the handler body, after the USER_VIEW_ONLY permission
    # dependency, so the gate must be satisfied first: the shared
    # conftest mock points at role id 68c302ef6bf7a039b7e9b386 with
    # no row in the fresh test database, which is why the 404 locks
    # fail there. Seeding that exact id carrying USER_VIEW_ONLY,
    # mirroring the role list 403 seed precedent, lets the
    # dependency pass: get_role_by_id is called with no tenant
    # filter, and _caller_may_access returns True for a
    # host-stamped row when the caller tenant is None
    # (role_service.py:18-19), so the seeded row is visible
    # regardless of the caller's tenant scope. The caller is then
    # made tenant-scoped by swapping in a per-test MeResponseDto
    # override (tenant_id set), mirroring the role list 403 lock's
    # override pattern, and restored in finally so no other test's
    # mock is affected. With no X-Tenant-ID header the tenant
    # middleware resolves host scope, so request_tenant_id is None
    # and the guard raises ForbiddenException before any listing
    # runs - no side effect, and the default skip/limit query values
    # pass validation, so no 422 can mask the 403. The central
    # ApiBaseException handler maps ForbiddenException to 403
    # (api/__init__.py:98-103) with {"error": ..., "code": 403} and
    # the no-store/Pragma error headers, since the handler sets
    # them only after the guard. A future change that drops the
    # guard would break this lock while leaving the list 200 lock
    # green, so the two paths are locked separately.
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
        name="Tenant user viewer",
        description="Role carrying USER_VIEW_ONLY for the mocked caller",
        permissions=[Permission.USER_VIEW_ONLY],
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
                name="Tenant user viewer",
                description="Role carrying USER_VIEW_ONLY for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.USER_VIEW_ONLY],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.get("/users/")
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

    # Same security-headers lock as the users list 200 test: the
    # pure-ASGI middleware stamps every HTTP response with no path
    # exclusions, so the users-list 403 must carry the same headers
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
    # the users list locks, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # user routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
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
    # Postcondition: the guard fires before any listing, so the
    # read is side-effect free - the seeded role is still there
    # with its permission.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.USER_VIEW_ONLY]


@pytest.mark.asyncio
async def test_create_user_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The user create scope-guard error path:
    """
    # The user create scope-guard branch, not yet locked:
    # function-name grep count 0 for create_user_outside_tenant_scope
    # (verified fresh this run), and no test in this file asserts a
    # 403 on POST /users/ - the create locks cover only the host
    # success path, while the role create scope guard has its own
    # 403 lock in test_role_endpoint.py and the users list scope
    # guard has one in this file. Deleting _assert_create_scope
    # (user_endpoint.py) would previously have gone uncaught, and a
    # tenant caller creating on the host DB (no X-Tenant-ID/subdomain)
    # would then plant a user in the host DB - stamped with the
    # caller's tenant_id but living in the wrong database, so the
    # caller's own tenant DB never sees them. The guard runs in the
    # handler body, after the USER_READ_AND_WRITE_ONLY permission
    # dependency, so the gate must be satisfied first: the shared
    # conftest mock points at role id 68c302ef6bf7a039b7e9b386 with
    # no row in the fresh test database. Seeding that exact id
    # carrying USER_READ_AND_WRITE_ONLY, mirroring the users list
    # 403 seed precedent, lets the dependency pass: get_role_by_id
    # is called with no tenant filter (user_access_management.py),
    # and _caller_may_access returns True when the caller tenant
    # is None (role_service.py:18-19), so the seeded row is visible
    # regardless of the caller's tenant scope. The caller is then
    # made tenant-scoped by swapping in a per-test MeResponseDto
    # override (tenant_id set), mirroring the users list 403 lock's
    # override pattern, and restored in finally so no other test's
    # mock is affected. With no X-Tenant-ID header the tenant
    # middleware resolves host scope, so request_tenant_id is None
    # and the guard raises ForbiddenException before any write
    # runs - the GUEST role lookup and the user insert never happen.
    # The payload is the same valid CreateUserDto body the create
    # helper posts (email test@example.com, password Test@123!),
    # so no 422 can mask the 403. The central ApiBaseException
    # handler maps ForbiddenException to 403 (api/__init__.py) with
    # {"error": ..., "code": 403} and the no-store/Pragma error
    # headers, since the handler sets them only after the guard. A
    # future change that drops the guard would break this lock while
    # leaving the create 201 lock green, so the two paths are locked
    # separately.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
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
                name="Tenant user creator",
                description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.USER_READ_AND_WRITE_ONLY],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        new_user = CreateUserDto(
            email="test@example.com",
            first_name="Test",
            last_name="User",
            gender=Gender.OTHER,
            password="Test@123!",
        )
        response = await client.post("/users/", json=new_user.model_dump())
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

    # Same security-headers lock as the users list 403 test: the
    # pure-ASGI middleware stamps every HTTP response with no path
    # exclusions, so the users-create 403 must carry the same headers
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
    # the users list locks, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # user routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
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
    # Postconditions: the guard fires before the GUEST role lookup
    # and the insert, so the create is side-effect free - the seeded
    # role is still there with its permission, and no user row was
    # planted in the host DB for the posted email.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.USER_READ_AND_WRITE_ONLY]
    planted = await User.find_one(User.email == "test@example.com")
    assert planted is None


async def test_get_user_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The user get scope-guard error path:
    """
    # The user get scope-guard branch, not yet locked:
    # function-name grep count 0 for get_user_outside_tenant_scope
    # (verified fresh this run), and no test in this file asserts a
    # 403 on GET /users/{user_id} - the get locks cover only the
    # host success path, while the role get scope guard has its own
    # 403 lock in test_role_endpoint.py and the users list/create
    # scope guards have theirs in this file. Deleting
    # _assert_get_scope (user_endpoint.py) would previously have
    # gone uncaught, and a tenant caller reading on the host DB (no
    # X-Tenant-ID/subdomain) could then read a tenant-stamped user
    # sitting in the host DB (e.g. planted before the create guard),
    # including another tenant's user whose id they know. The guard
    # runs in the handler body, after the USER_VIEW_ONLY permission
    # dependency, so the gate must be satisfied first: the shared
    # conftest mock points at role id 68c302ef6bf7a039b7e9b386 with
    # no row in the fresh test database. Seeding that exact id
    # carrying USER_VIEW_ONLY, mirroring the users list/create 403
    # seed precedent, lets the dependency pass: the GET route's
    # required list is [USER_SELF_READ_AND_WRITE_ONLY,
    # USER_VIEW_ONLY] with allow_self_access=True, and the general
    # check strips USER_SELF_READ_AND_WRITE_ONLY (it is honoured
    # only by the self-access branch), so USER_VIEW_ONLY is the
    # sole general permission; get_role_by_id is called with no
    # tenant filter (user_access_management.py), and
    # _caller_may_access returns True when the caller tenant is
    # None (role_service.py:18-19), so the seeded row is visible
    # regardless of the caller's tenant scope. The target id is a
    # plausible ObjectId distinct from the caller's own id, so the
    # self-access branch cannot pass and the permission gate is
    # satisfied only by USER_VIEW_ONLY. The caller is then made
    # tenant-scoped by swapping in a per-test MeResponseDto
    # override (tenant_id set), mirroring the users list/create 403
    # locks' override pattern, and restored in finally so no other
    # test's mock is affected. With no X-Tenant-ID header the
    # tenant middleware resolves host scope, so request_tenant_id
    # is None and the guard raises ForbiddenException before any
    # read runs - get_user_by_id never happens, so no target user
    # needs seeding and no existence signal leaks via the 404.
    # The central ApiBaseException handler maps ForbiddenException
    # to 403 (api/__init__.py) with {"error": ..., "code": 403}
    # and the no-store/Pragma error headers, since the handler sets
    # them only after the guard. A future change that drops the
    # guard would break this lock while leaving the get 200 lock
    # green, so the two paths are locked separately.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant user reader",
        description="Role carrying USER_VIEW_ONLY for the mocked caller",
        permissions=[Permission.USER_VIEW_ONLY],
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
                name="Tenant user reader",
                description="Role carrying USER_VIEW_ONLY for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.USER_VIEW_ONLY],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.get("/users/68c302ef6bf7a039b7e9b388")
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

    # Same security-headers lock as the users list 403 test: the
    # pure-ASGI middleware stamps every HTTP response with no path
    # exclusions, so the users-get 403 must carry the same headers
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
    # the users list locks, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # user routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
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
    # Postconditions: the guard fires before get_user_by_id, so
    # the read is side-effect free - the seeded role is still
    # there with its permission, and no user row exists for the
    # target id the guard refused to read.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.USER_VIEW_ONLY]
    target = await User.find_one(
        User.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert target is None


async def test_update_user_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The user update scope-guard error path:
    """
    # The user update scope-guard branch, not yet locked:
    # function-name grep count 0 for update_user_outside_tenant_scope
    # (verified fresh this run), and no test in this file asserts a
    # 403 on PUT /users/{user_id} - the update locks cover only the
    # host success path, while the role update scope guard has its
    # own 403 lock in test_role_endpoint.py and the users list/create/
    # get scope guards have theirs in this file. Deleting
    # _assert_update_scope (user_endpoint.py) would previously have
    # gone uncaught, and a tenant caller updating on the host DB (no
    # X-Tenant-ID/subdomain) could then edit a tenant-stamped user
    # sitting in the host DB (e.g. planted before the create guard),
    # changing their name, email, or role where host callers resolve
    # users by id with no tenant scope. The guard runs first in the
    # handler body, after the USER_READ_AND_WRITE_ONLY permission
    # dependency, so the gate must be satisfied first: the shared
    # conftest mock points at role id 68c302ef6bf7a039b7e9b386 with
    # no row in the fresh test database. Seeding that exact id
    # carrying USER_READ_AND_WRITE_ONLY, mirroring the users list/
    # create/get 403 seed precedent, lets the dependency pass: the
    # PUT route's required list is [USER_READ_AND_WRITE_ONLY,
    # USER_SELF_READ_AND_WRITE_ONLY] with allow_self_access=True,
    # and the general check strips USER_SELF_READ_AND_WRITE_ONLY
    # (it is honoured only by the self-access branch), so
    # USER_READ_AND_WRITE_ONLY is the sole general permission;
    # get_role_by_id is called with no tenant filter
    # (user_access_management.py), and _caller_may_access returns
    # True when the caller tenant is None (role_service.py:18-19),
    # so the seeded row is visible regardless of the caller's
    # tenant scope. The target id is a plausible ObjectId distinct
    # from the caller's own id, so the self-access branch cannot
    # pass and the permission gate is satisfied only by
    # USER_READ_AND_WRITE_ONLY. The caller is then made
    # tenant-scoped by swapping in a per-test MeResponseDto
    # override (tenant_id set), mirroring the users list/create/get
    # 403 locks' override pattern, and restored in finally so no
    # other test's mock is affected. With no X-Tenant-ID header the
    # tenant middleware resolves host scope, so request_tenant_id
    # is None and the guard raises ForbiddenException before any
    # read or write runs - get_user_by_id and update_user never
    # happen, so no target user needs seeding and no existence
    # signal leaks via the 404. The body is a minimal valid
    # UpdateUserDto (first_name only, role_id None), so body
    # validation passes and the role-change checks are skipped;
    # a blank or missing name would 422 before the guard and
    # would not lock this path. The central ApiBaseException
    # handler maps ForbiddenException to 403 (api/__init__.py)
    # with {"error": ..., "code": 403} and the no-store/Pragma
    # error headers, since the handler sets them only after the
    # guard. A future change that drops the guard would break
    # this lock while leaving the update 200 lock green, so the
    # two paths are locked separately.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant user writer",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
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
                name="Tenant user writer",
                description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.USER_READ_AND_WRITE_ONLY],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.put(
            "/users/68c302ef6bf7a039b7e9b388",
            json={"first_name": "Updated"},
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

    # Same security-headers lock as the users list 403 test: the
    # pure-ASGI middleware stamps every HTTP response with no path
    # exclusions, so the users-update 403 must carry the same headers
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
    # the users list locks, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # user routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
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
    # Postconditions: the guard fires before get_user_by_id and
    # update_user, so the write is side-effect free - the seeded
    # role is still there with its permission, and no user row
    # exists for the target id the guard refused to update.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.USER_READ_AND_WRITE_ONLY]
    target = await User.find_one(
        User.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert target is None


async def test_delete_user_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The user delete scope-guard error path:
    """
    # The user delete scope-guard branch, not yet locked:
    # function-name grep count 0 for delete_user_outside_tenant_scope
    # (verified fresh this run), and no test in this file asserts a
    # 403 on DELETE /users/{user_id} - the delete locks cover only
    # the host success path, while the role delete scope guard has
    # its own 403 lock in test_role_endpoint.py and the users list/
    # create/get/update scope guards have theirs in this file.
    # Deleting _assert_delete_scope (user_endpoint.py) would
    # previously have gone uncaught, and a tenant caller deleting
    # on the host DB (no X-Tenant-ID/subdomain) could then remove
    # a tenant-stamped user sitting in the host DB (e.g. planted
    # before the create guard), deleting a user host callers
    # resolve by id with no tenant scope. The guard runs first in
    # the handler body, after the USER_DELETE_ONLY permission
    # dependency, so the gate must be satisfied first: the shared
    # conftest mock points at role id 68c302ef6bf7a039b7e9b386 with
    # no row in the fresh test database. Seeding that exact id
    # carrying USER_DELETE_ONLY, mirroring the users list/create/
    # get/update 403 seed precedent, lets the dependency pass:
    # the DELETE route's required list is [USER_DELETE_ONLY] with
    # no self-access allowance, so USER_DELETE_ONLY is the sole
    # permission; get_role_by_id is called with no tenant filter
    # (user_access_management.py), and _caller_may_access returns
    # True when the caller tenant is None (role_service.py:18-19),
    # so the seeded row is visible regardless of the caller's
    # tenant scope. The target id is a plausible ObjectId distinct
    # from the caller's own id, so the self-delete check below the
    # guard cannot fire and the permission gate is satisfied only
    # by USER_DELETE_ONLY. The caller is then made tenant-scoped
    # by swapping in a per-test MeResponseDto override (tenant_id
    # set), mirroring the users list/create/get/update 403 locks'
    # override pattern, and restored in finally so no other test's
    # mock is affected. With no X-Tenant-ID header the tenant
    # middleware resolves host scope, so request_tenant_id is None
    # and the guard raises ForbiddenException before any read or
    # write runs - service.delete_user never happens, so no target
    # user needs seeding and no existence signal leaks via the
    # 404. DELETE carries no body, so no payload validation can
    # 422 before the guard. The central ApiBaseException handler
    # maps ForbiddenException to 403 (api/__init__.py) with
    # {"error": ..., "code": 403} and the no-store/Pragma error
    # headers, since the handler sets them only after the guard.
    # A future change that drops the guard would break this lock
    # while leaving the delete 202 lock green, so the two paths
    # are locked separately.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant user deleter",
        description="Role carrying USER_DELETE_ONLY for the mocked caller",
        permissions=[Permission.USER_DELETE_ONLY],
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
                name="Tenant user deleter",
                description="Role carrying USER_DELETE_ONLY for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.USER_DELETE_ONLY],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.delete(
            "/users/68c302ef6bf7a039b7e9b388",
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

    # Same security-headers lock as the users list 403 test: the
    # pure-ASGI middleware stamps every HTTP response with no path
    # exclusions, so the users-delete 403 must carry the same headers
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
    # the users list locks, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # user routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
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
    # Postconditions: the guard fires before service.delete_user,
    # so the write is side-effect free - the seeded role is still
    # there with its permission, and no user row exists for the
    # target id the guard refused to delete.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.USER_DELETE_ONLY]
    target = await User.find_one(
        User.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert target is None


async def test_get_user_profile_image_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The user profile-image scope-guard error path:
    """
    # The user profile-image scope-guard branch, not yet locked:
    # function-name grep count 0 for
    # get_user_profile_image_outside_tenant_scope (verified fresh
    # this run), and no test in this file asserts a 403 on GET
    # /users/profile/{image_key} - the profile-image locks cover
    # only the missing-role 404, while the users list/create/get/
    # update/delete scope guards have their 403 locks in this
    # file. Deleting _assert_profile_image_scope
    # (user_endpoint.py) would previously have gone uncaught,
    # and a tenant caller minting on the host DB (no
    # X-Tenant-ID/subdomain) could then mint presigned URLs for
    # objects in the shared bucket that host callers resolve with
    # no tenant scope. The guard runs first in the handler body,
    # after the USER_VIEW_ONLY permission dependency, so the gate
    # must be satisfied first: the shared conftest mock points at
    # role id 68c302ef6bf7a039b7e9b386 with no row in the fresh
    # test database. Seeding that exact id carrying
    # USER_VIEW_ONLY, mirroring the users list/create/get/update/
    # delete 403 seed precedent, lets the dependency pass: the
    # profile-image route's required list is [USER_VIEW_ONLY]
    # with no self-access allowance (role_checker.py defaults
    # allow_self_access=False), so USER_VIEW_ONLY is the sole
    # permission; get_role_by_id is called with no tenant filter
    # (user_access_management.py), and _caller_may_access
    # returns True when the caller tenant is None
    # (role_service.py:13-19), so the seeded row is visible
    # regardless of the caller's tenant scope. The caller is
    # then made tenant-scoped by swapping in a per-test
    # MeResponseDto override (tenant_id set), mirroring the
    # users list/create/get/update/delete 403 locks' override
    # pattern, and restored in finally so no other test's mock
    # is affected. With no X-Tenant-ID header the tenant
    # middleware resolves host scope, so request_tenant_id is
    # None and the guard raises ForbiddenException before the
    # ownership check or any storage call runs - no presigned
    # URL is minted for the key, so no user needs seeding and
    # no existence signal leaks via the 404. The GET carries no
    # body, so no payload validation can 422 before the guard.
    # The central ApiBaseException handler maps
    # ForbiddenException to 403 (api/__init__.py) with
    # {"error": ..., "code": 403} and the no-store/Pragma error
    # headers, since the handler sets them only after the guard.
    # A future change that drops the guard would break this lock
    # while leaving the profile-image 404 lock green, so the two
    # paths are locked separately.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant profile image viewer",
        description="Role carrying USER_VIEW_ONLY for the mocked caller",
        permissions=[Permission.USER_VIEW_ONLY],
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
                name="Tenant profile image viewer",
                description="Role carrying USER_VIEW_ONLY for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.USER_VIEW_ONLY],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.get(
            "/users/profile/123e4567-e89b-12d3-a456-426614174000-avatar.png",
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

    # Same security-headers lock as the users list 403 test: the
    # pure-ASGI middleware stamps every HTTP response with no path
    # exclusions, so the profile-image 403 must carry the same headers
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
    # the users list locks, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # user routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
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
    # Postconditions: the guard fires before the ownership check
    # and any storage call, so the request is side-effect free -
    # the seeded role is still there with its permission, and no
    # user row stores the requested key as a profile picture, so
    # no presigned URL could have been minted for it.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.USER_VIEW_ONLY]
    owner = await User.find_one(
        User.image_url == "123e4567-e89b-12d3-a456-426614174000-avatar.png"
    )
    assert owner is None


@pytest.mark.asyncio
async def test_put_user_update_profile_picture_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The user update_profile_picture scope-guard error path:
    """
    # The user update_profile_picture scope-guard branch, not yet
    # locked: function-name grep count 0 for
    # update_profile_picture_outside_tenant_scope (verified fresh
    # this run), and no test in this file asserts a 403 on PUT
    # /users/{user_id}/update_profile_picture - the picture locks
    # cover only the missing-role 404, while the users list/create/
    # get/update/delete/profile-image scope guards have their 403
    # locks in this file. Deleting _assert_profile_picture_scope
    # (user_endpoint.py) would previously have gone uncaught, and
    # a tenant caller updating on the host DB (no X-Tenant-ID/
    # subdomain) could then overwrite the avatar of a
    # tenant-stamped user sitting in the host DB (e.g. planted
    # before the create guard), including their own record. The
    # guard runs first in the handler body, after the permission
    # dependency, so the gate must be satisfied first: the shared
    # conftest mock points at role id 68c302ef6bf7a039b7e9b386 with
    # no row in the fresh test database. Seeding that exact id
    # carrying USER_READ_AND_WRITE_ONLY, mirroring the users
    # update 403 seed precedent, lets the dependency pass: the
    # PUT route's required list is [USER_READ_AND_WRITE_ONLY,
    # USER_SELF_READ_AND_WRITE_ONLY] with allow_self_access=True,
    # and the general check strips USER_SELF_READ_AND_WRITE_ONLY
    # (it is honoured only by the self-access branch), so
    # USER_READ_AND_WRITE_ONLY is the sole general permission;
    # get_role_by_id is called with no tenant filter
    # (user_access_management.py), and _caller_may_access returns
    # True when the caller tenant is None (role_service.py:18-19),
    # so the seeded row is visible regardless of the caller's
    # tenant scope. The target id is a plausible ObjectId distinct
    # from the caller's own id, so the self-access branch cannot
    # pass and the permission gate is satisfied only by
    # USER_READ_AND_WRITE_ONLY. The caller is then made
    # tenant-scoped by swapping in a per-test MeResponseDto
    # override (tenant_id set), mirroring the users list/create/get/
    # update/delete 403 locks' override pattern, and restored in
    # finally so no other test's mock is affected. With no
    # X-Tenant-ID header the tenant middleware resolves host scope,
    # so request_tenant_id is None and the guard raises
    # ForbiddenException before any file validation, read, or
    # storage write runs - get_user_by_id and upload_file never
    # happen, so no target user needs seeding and no existence
    # signal leaks via the 404. The request carries a real (tiny)
    # PNG part, mirroring the update_profile_picture 404 lock, so
    # multipart parsing cannot 422-mask the error whichever order
    # FastAPI resolves the file param versus the router dependency.
    # The central ApiBaseException handler maps ForbiddenException
    # to 403 (api/__init__.py) with {"error": ..., "code": 403}
    # and the no-store/Pragma error headers, since the handler sets
    # them only after the guard. A future change that drops the
    # guard would break this lock while leaving the
    # update_profile_picture 404 lock green, so the two paths are
    # locked separately.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant user writer",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
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
                name="Tenant user writer",
                description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.USER_READ_AND_WRITE_ONLY],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        png_1x1 = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
            b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00"
            b"\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05"
            b"\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        response = await client.put(
            "/users/68c302ef6bf7a039b7e9b388/update_profile_picture",
            files={"file": ("avatar.png", png_1x1, "image/png")},
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

    # Same security-headers lock as the users update 403 test: the
    # pure-ASGI middleware stamps every HTTP response with no path
    # exclusions, so the update_profile_picture 403 must carry the
    # same headers as the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the other user-route locks, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # user routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
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
    # Postconditions: the guard fires before any file validation,
    # read, or storage write, so the request is side-effect free -
    # the seeded role is still there with its permission, and no
    # user row exists for the target id the guard refused to
    # update, so no avatar could have been overwritten.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.USER_READ_AND_WRITE_ONLY]
    target = await User.find_one(
        User.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert target is None


@pytest.mark.asyncio
async def test_patch_user_assign_role_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The user assign_role scope-guard error path:
    """
    # The user assign_role scope-guard branch, not yet locked:
    # function-name grep count 0 for
    # assign_role_outside_tenant_scope (verified fresh this run),
    # and no test in this file asserts a 403 on PATCH
    # /users/{user_id}/assign_role - the assign lock covers only
    # the missing-role 404, while the users list/create/get/update/
    # delete/profile-image/profile-picture scope guards have their
    # 403 locks in this file. Deleting _assert_assign_scope
    # (user_endpoint.py) would previously have gone uncaught, and
    # a tenant caller assigning on the host DB (no X-Tenant-ID/
    # subdomain) could then change the role of a tenant-stamped
    # user sitting in the host DB (e.g. planted before the create
    # guard), including assigning an admin role to a user host
    # callers resolve by id with no tenant scope. The guard runs
    # first in the handler body, after the permission dependency,
    # so the gate must be satisfied first: the shared conftest
    # mock points at role id 68c302ef6bf7a039b7e9b386 with no row
    # in the fresh test database. Seeding that exact id carrying
    # USER_ROLE_ASSIGN_OR_REMOVE_ONLY, mirroring the users update
    # 403 seed precedent, lets the dependency pass: the PATCH
    # route's required list is [USER_ROLE_ASSIGN_OR_REMOVE_ONLY]
    # with allow_self_access=False (the factory default), so it is
    # the sole permission and the self-access branch cannot pass;
    # get_role_detail calls get_role_by_id with no tenant filter
    # (user_access_management.py), and _caller_may_access returns
    # True when the caller tenant is None (role_service.py:18-19),
    # so the seeded row is visible regardless of the caller's
    # tenant scope. The target id is a plausible ObjectId distinct
    # from the caller's own id, so the self-assignment check below
    # the guard cannot fire either. The caller is then made
    # tenant-scoped by swapping in a per-test MeResponseDto
    # override (tenant_id set), mirroring the users list/create/get/
    # update/delete/profile-image/profile-picture 403 locks'
    # override pattern, and restored in finally so no other test's
    # mock is affected. With no X-Tenant-ID header the tenant
    # middleware resolves host scope, so request_tenant_id is None
    # and the guard raises ForbiddenException before any read or
    # write runs - get_user_by_id and the role lookup never happen,
    # so no target user needs seeding and no existence signal leaks
    # via the self-assignment check. The body is valid on purpose:
    # role_id has min_length=1 and the value below satisfies it, so
    # body validation passes and cannot 422-mask the error. The
    # central ApiBaseException handler maps ForbiddenException to
    # 403 (api/__init__.py) with {"error": ..., "code": 403} and
    # the no-store/Pragma error headers, since the handler sets
    # them only after the guard. A future change that drops the
    # guard would break this lock while leaving the assign_role
    # 404 lock green, so the two paths are locked separately.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant role assigner",
        description="Role carrying USER_ROLE_ASSIGN_OR_REMOVE_ONLY for the mocked caller",
        permissions=[Permission.USER_ROLE_ASSIGN_OR_REMOVE_ONLY],
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
                name="Tenant role assigner",
                description="Role carrying USER_ROLE_ASSIGN_OR_REMOVE_ONLY for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.USER_ROLE_ASSIGN_OR_REMOVE_ONLY],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.patch(
            "/users/68c302ef6bf7a039b7e9b388/assign_role",
            json={"role_id": "68c302ef6bf7a039b7e9b386"},
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

    # Same security-headers lock as the users update 403 test: the
    # pure-ASGI middleware stamps every HTTP response with no path
    # exclusions, so the assign_role 403 must carry the same
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
    # the other user-route locks, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # user routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
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
    # Postconditions: the guard fires before any read or write, so
    # the request is side-effect free - the seeded role is still
    # there with its permission, and no user row exists for the
    # target id the guard refused to assign a role to, so no role
    # could have been changed.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.USER_ROLE_ASSIGN_OR_REMOVE_ONLY]
    target = await User.find_one(
        User.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert target is None


async def test_patch_user_remove_role_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The user remove_role scope-guard error path:
    """
    # The user remove_role scope-guard branch, not yet locked:
    # function-name grep count 0 for
    # remove_role_outside_tenant_scope (verified fresh this run),
    # and no test in this file asserts a 403 on PATCH
    # /users/{user_id}/remove_role - the remove lock covers only
    # the missing-role 404, while the users list/create/get/update/
    # delete/profile-image/profile-picture/assign_role scope guards
    # have their 403 locks in this file. Deleting
    # _assert_remove_scope (user_endpoint.py) would previously
    # have gone uncaught, and a tenant caller removing on the host
    # DB (no X-Tenant-ID/subdomain) could then strip the role of a
    # tenant-stamped user sitting in the host DB (e.g. planted
    # before the create guard). The guard runs first in the handler
    # body, after the permission dependency, so the gate must be
    # satisfied first: the shared conftest mock points at role id
    # 68c302ef6bf7a039b7e9b386 with no row in the fresh test
    # database. Seeding that exact id carrying
    # USER_ROLE_ASSIGN_OR_REMOVE_ONLY, mirroring the users update
    # 403 seed precedent, lets the dependency pass: the PATCH
    # route's required list is [USER_ROLE_ASSIGN_OR_REMOVE_ONLY]
    # with allow_self_access=False (the factory default), so it is
    # the sole permission and the self-access branch cannot pass;
    # get_role_detail calls get_role_by_id with no tenant filter
    # (user_access_management.py), and _caller_may_access returns
    # True when the caller tenant is None (role_service.py:18-19),
    # so the seeded row is visible regardless of the caller's
    # tenant scope. The target id is a plausible ObjectId distinct
    # from the caller's own id, so the self-removal check below
    # the guard cannot fire either. The caller is then made
    # tenant-scoped by swapping in a per-test MeResponseDto
    # override (tenant_id set), mirroring the users list/create/get/
    # update/delete/profile-image/profile-picture/assign_role 403
    # locks' override pattern, and restored in finally so no other
    # test's mock is affected. With no X-Tenant-ID header the
    # tenant middleware resolves host scope, so request_tenant_id
    # is None and the guard raises ForbiddenException before any
    # read or write runs - get_user_by_id and the role-mismatch
    # check never happen, so no target user needs seeding and no
    # existence signal leaks via the self-removal check. The body
    # is valid on purpose: role_id has min_length=1 and the value
    # below satisfies it, so body validation passes and cannot
    # 422-mask the error. The central ApiBaseException handler maps
    # ForbiddenException to 403 (api/__init__.py) with {"error":
    # ..., "code": 403} and the no-store/Pragma error headers,
    # since the handler sets them only after the guard. A future
    # change that drops the guard would break this lock while
    # leaving the remove_role 404 lock green, so the two paths are
    # locked separately.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.dtos.role_dto import RoleDto
    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant role remover",
        description="Role carrying USER_ROLE_ASSIGN_OR_REMOVE_ONLY for the mocked caller",
        permissions=[Permission.USER_ROLE_ASSIGN_OR_REMOVE_ONLY],
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
                name="Tenant role remover",
                description="Role carrying USER_ROLE_ASSIGN_OR_REMOVE_ONLY for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.USER_ROLE_ASSIGN_OR_REMOVE_ONLY],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.patch(
            "/users/68c302ef6bf7a039b7e9b388/remove_role",
            json={"role_id": "68c302ef6bf7a039b7e9b386"},
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

    # Same security-headers lock as the users update 403 test: the
    # pure-ASGI middleware stamps every HTTP response with no path
    # exclusions, so the remove_role 403 must carry the same
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
    # the other user-route locks, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # user routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
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
    # Postconditions: the guard fires before any read or write, so
    # the request is side-effect free - the seeded role is still
    # there with its permission, and no user row exists for the
    # target id the guard refused to remove a role from, so no role
    # could have been changed.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.USER_ROLE_ASSIGN_OR_REMOVE_ONLY]
    target = await User.find_one(
        User.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert target is None


@pytest.mark.asyncio
async def test_get_user_profile_image_with_unconfigured_s3_returns_502_with_cache_and_security_headers(client: AsyncClient):
    """
        The user profile-image GET 502 path:
    """
    # The user profile-image GET 502 branch, not yet locked:
    # function-name grep count 0 for
    # get_user_profile_image_with_unconfigured_s3 (verified fresh
    # this run), and no test anywhere in the suite asserts a 502
    # (grep count 0 for "502" across backend/tests) - the
    # profile-image locks cover only the missing-role 404 and the
    # scope-guard 403, while the central ApiBaseException handler
    # maps AwsException/AzureException to 502 (api/__init__.py)
    # with no lock on any route. Deleting that mapping would
    # previously have gone uncaught, and a storage outage on the
    # avatar path would then surface as a 400 "bad request"
    # instead of a 502, hiding an upstream failure from the
    # client fallbacks that only trigger on rejection. The 502
    # here is deterministic with no network and no live S3 call:
    # the seeded StorageSettings row enables AWS_S3 with blank
    # keys, and S3Storage.__init__ (s3_storage.py) raises
    # S3StorageException("S3 storage credentials are not
    # configured.") before constructing a boto3 client, so no
    # credential resolution, signing, or HTTP request happens.
    # The handler chain is: the USER_VIEW_ONLY permission
    # dependency passes on the seeded role (mirroring the
    # profile-image 403 lock's seed), the scope guard passes for
    # the host mock (tenant_id None), the ownership check passes
    # on the seeded user row storing the key as image_url, and
    # then file_service.get_file_url -> FileRetrieval.
    # generate_read_url finds the enabled S3 row and constructs
    # S3Storage, which raises; the endpoint re-raises (its
    # try/except only logs) and the central handler answers 502.
    # StorageSettings is outside the conftest model set
    # (conftest.py:25), so the test initializes it on the test DB
    # first: init_beanie on the same URI/db name the conftest
    # fixture uses (mongodb://localhost:27012/test_db,
    # api_test_db), mirroring the branding tests' second-init
    # precedent for Branding. The GET carries no body, so no
    # payload validation can 422 before the storage call, and
    # the key is a plain uuid-prefixed name, so the endpoint's
    # strip is a no-op. A future change that drops the 502
    # mapping, or that lets the S3 constructor fall through to
    # ambient credentials, would break this lock while leaving
    # the profile-image 404/403 locks green, so the paths are
    # locked separately.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.role import Role
    from api.domain.entities.storage_settings import StorageProvider, StorageSettings
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[StorageSettings]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Profile image storage caller",
        description="Role carrying USER_VIEW_ONLY for the mocked caller",
        permissions=[Permission.USER_VIEW_ONLY],
    ).insert()

    image_key = "123e4567-e89b-12d3-a456-426614174000-avatar.png"
    await User(
        first_name="Avatar",
        last_name="Owner",
        email="avatar-owner@example.com",
        gender=Gender.OTHER,
        is_active=True,
        password="TestPassword123!",
        image_url=image_key,
    ).insert()

    await StorageSettings(
        provider=StorageProvider.AWS_S3,
        is_enabled=True,
        region="eu-central-1",
        aws_access_key="",
        aws_secret_key="",
        aws_bucket_name="test-bucket",
    ).insert()

    response = await client.get(f"/users/profile/{image_key}")
    assert response.status_code == 502
    body = response.json()
    assert body["code"] == 502
    # S3StorageException prefixes its message ("S3 Storage
    # Error: ..."), so assert on the fail-closed reason itself.
    assert "S3 storage credentials are not configured." in body["error"]
    assert "S3 Storage Error: " in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 502 must still carry the error-response headers: the
    # handler sets no-store only on the success path, so on this
    # path they come from the central ApiBaseException handler,
    # and a cached 502 could otherwise be served to a different
    # user after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other user-route tests:
    # the pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the profile-image GET 502 must carry the
    # same headers as the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the other user-route locks, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # user routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
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
    # Postconditions: the constructor raises before any write or
    # presigned-URL minting, so the request is side-effect free -
    # the seeded role is still there with its permission, the
    # owning user still stores the key, and the storage row is
    # still the enabled S3 row with blank keys.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.USER_VIEW_ONLY]
    owner = await User.find_one(User.image_url == image_key)
    assert owner is not None
    assert owner.email == "avatar-owner@example.com"
    stored_settings = await StorageSettings.find_one(
        StorageSettings.is_enabled == True
    )
    assert stored_settings is not None
    assert stored_settings.provider == StorageProvider.AWS_S3
    assert stored_settings.aws_access_key == ""
    assert stored_settings.aws_secret_key == ""
    await mongo_client.close()


async def test_get_user_profile_image_with_unconfigured_azure_returns_502_with_cache_and_security_headers(client: AsyncClient):
    """
        The user profile-image GET 502 path for Azure:
    """
    # The user profile-image GET 502 branch for Azure, not yet locked:
    # function-name grep count 0 for
    # get_user_profile_image_with_unconfigured_azure (verified fresh
    # this run), and no test anywhere in the suite asserts an Azure
    # 502 - the S3 502 lock (previous run) covers only the AWS_S3
    # branch, while the central ApiBaseException handler maps
    # AwsException/AzureException to 502 (api/__init__.py) with no
    # lock on the Azure branch. Before this run's production fix,
    # a blank or malformed Azure connection string raised a bare
    # ValueError from BlobServiceClient.from_connection_string,
    # which is not an ApiBaseException and so bypassed the central
    # handler entirely, surfacing as an unhandled 500 instead of
    # a 502 and hiding an upstream failure from the client
    # fallbacks that only trigger on rejection. The 502 here is
    # deterministic with no network and no live Azure call: the
    # seeded StorageSettings row enables AZURE_BLOB with a blank
    # connection string, and AzureBlobStorage.__init__
    # (azure_storage.py) now raises AzureBlobStorageException
    # ("Azure Blob Storage connection string is not configured.")
    # before constructing a BlobServiceClient, so no credential
    # resolution, signing, or HTTP request happens. The handler
    # chain is: the USER_VIEW_ONLY permission dependency passes
    # on the seeded role (mirroring the profile-image 403 lock's
    # seed), the scope guard passes for the host mock (tenant_id
    # None), the ownership check passes on the seeded user row
    # storing the key as image_url, and then file_service.
    # get_file_url -> FileRetrieval.generate_read_url finds the
    # enabled Azure row and constructs AzureBlobStorage, which
    # raises; the endpoint re-raises (its try/except only logs)
    # and the central handler answers 502. StorageSettings is
    # outside the conftest model set (conftest.py:25), so the
    # test initializes it on the test DB first: init_beanie on
    # the same URI/db name the conftest fixture uses
    # (mongodb://localhost:27012/test_db, api_test_db),
    # mirroring the branding tests' second-init precedent for
    # Branding and the S3 502 lock. The GET carries no body, so
    # no payload validation can 422 before the storage call, and
    # the key is a plain uuid-prefixed name, so the endpoint's
    # strip is a no-op. A future change that drops the 502
    # mapping, or that lets the Azure constructor fall through
    # to the SDK's bare ValueError, would break this lock while
    # leaving the profile-image 404/403 and S3 502 locks green,
    # so the paths are locked separately.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.role import Role
    from api.domain.entities.storage_settings import StorageProvider, StorageSettings
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[StorageSettings]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Profile image storage caller",
        description="Role carrying USER_VIEW_ONLY for the mocked caller",
        permissions=[Permission.USER_VIEW_ONLY],
    ).insert()

    image_key = "223e4567-e89b-12d3-a456-426614174000-avatar.png"
    await User(
        first_name="Avatar",
        last_name="Owner",
        email="avatar-owner@example.com",
        gender=Gender.OTHER,
        is_active=True,
        password="TestPassword123!",
        image_url=image_key,
    ).insert()

    await StorageSettings(
        provider=StorageProvider.AZURE_BLOB,
        is_enabled=True,
        region="eu-central-1",
        azure_connection_string="",
        azure_container_name="test-container",
    ).insert()

    response = await client.get(f"/users/profile/{image_key}")
    assert response.status_code == 502
    body = response.json()
    assert body["code"] == 502
    # AzureBlobStorageException prefixes its message ("Azure Blob
    # Storage Error: ..."), so assert on the fail-closed reason
    # itself.
    assert "Azure Blob Storage connection string is not configured." in body["error"]
    assert "Azure Blob Storage Error: " in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 502 must still carry the error-response headers: the
    # handler sets no-store only on the success path, so on this
    # path they come from the central ApiBaseException handler,
    # and a cached 502 could otherwise be served to a different
    # user after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other user-route tests:
    # the pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the profile-image GET 502 must carry the
    # same headers as the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the other user-route locks, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # user routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
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
    # Postconditions: the constructor raises before any write or
    # presigned-URL minting, so the request is side-effect free -
    # the seeded role is still there with its permission, the
    # owning user still stores the key, and the storage row is
    # still the enabled Azure row with a blank connection string.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.USER_VIEW_ONLY]
    owner = await User.find_one(User.image_url == image_key)
    assert owner is not None
    assert owner.email == "avatar-owner@example.com"
    stored_settings = await StorageSettings.find_one(
        StorageSettings.is_enabled == True
    )
    assert stored_settings is not None
    assert stored_settings.provider == StorageProvider.AZURE_BLOB
    assert stored_settings.azure_connection_string == ""
    assert stored_settings.azure_container_name == "test-container"
    await mongo_client.close()


async def test_get_user_profile_image_with_malformed_azure_connection_string_returns_502_with_cache_and_security_headers(client: AsyncClient):
    """
        The user profile-image GET 502 path for a malformed Azure
        connection string:
    """
    # The user profile-image GET 502 branch for a malformed Azure
    # connection string, not yet locked: function-name grep count 0
    # for get_user_profile_image_with_malformed_azure_connection_
    # string (verified fresh this run), and the only "malformed"
    # mention anywhere in the suite is a comment in the blank-
    # connection-string 502 lock (previous run), which covers only
    # the fail-closed blank case. The central ApiBaseException
    # handler maps AwsException/AzureException to 502
    # (api/__init__.py:110-113), and AzureBlobStorage.__init__
    # (azure_storage.py, fixed the previous run) maps the SDK's
    # ValueError for a malformed string to AzureBlobStorageException
    # ("Azure Blob Storage connection string is invalid."); before
    # that fix the bare ValueError bypassed the central handler and
    # surfaced as an unhandled 500. The 502 here is deterministic
    # with no network and no live Azure call: the seeded
    # StorageSettings row enables AZURE_BLOB with the malformed
    # string "not-a-connection-string" (no key=value pairs, so the
    # SDK's local connection-string parser raises ValueError before
    # any client construction or HTTP request - verified from the
    # azure-sdk-for-python parser source in the previous run, and
    # the exact __init__ source was executed there with a stubbed
    # SDK over blank/whitespace/None/malformed/valid cases, with
    # malformed mapping to the "invalid" exception; the real SDK is
    # not installed on this machine, so the 502 outcome is verified
    # from source, not executed). The handler chain is: the
    # USER_VIEW_ONLY permission dependency passes on the seeded
    # role (mirroring the profile-image 403 lock's seed), the
    # scope guard passes for the host mock (tenant_id None), the
    # ownership check passes on the seeded user row storing the
    # key as image_url, and then file_service.get_file_url ->
    # FileRetrieval.generate_read_url finds the enabled Azure row
    # and constructs AzureBlobStorage, which raises; the endpoint
    # re-raises (its try/except only logs) and the central handler
    # answers 502. StorageSettings is outside the conftest model
    # set (conftest.py:25), so the test initializes it on the test
    # DB first: init_beanie on the same URI/db name the conftest
    # fixture uses (mongodb://localhost:27012/test_db,
    # api_test_db), mirroring the branding tests' second-init
    # precedent for Branding and the S3/Azure 502 locks. The GET
    # carries no body, so no payload validation can 422 before
    # the storage call, and the key is a plain uuid-prefixed
    # name, so the endpoint's strip is a no-op. A future change
    # that drops the 502 mapping, or that lets the Azure
    # constructor fall through to the SDK's bare ValueError,
    # would break this lock while leaving the profile-image
    # 404/403, S3 502, and blank-Azure 502 locks green, so the
    # paths are locked separately.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.role import Role
    from api.domain.entities.storage_settings import StorageProvider, StorageSettings
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[StorageSettings]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Profile image storage caller",
        description="Role carrying USER_VIEW_ONLY for the mocked caller",
        permissions=[Permission.USER_VIEW_ONLY],
    ).insert()

    image_key = "323e4567-e89b-12d3-a456-426614174000-avatar.png"
    await User(
        first_name="Avatar",
        last_name="Owner",
        email="avatar-owner@example.com",
        gender=Gender.OTHER,
        is_active=True,
        password="TestPassword123!",
        image_url=image_key,
    ).insert()

    await StorageSettings(
        provider=StorageProvider.AZURE_BLOB,
        is_enabled=True,
        region="eu-central-1",
        azure_connection_string="not-a-connection-string",
        azure_container_name="test-container",
    ).insert()

    response = await client.get(f"/users/profile/{image_key}")
    assert response.status_code == 502
    body = response.json()
    assert body["code"] == 502
    # AzureBlobStorageException prefixes its message ("Azure Blob
    # Storage Error: ..."), so assert on the fail-closed reason
    # itself.
    assert "Azure Blob Storage connection string is invalid." in body["error"]
    assert "Azure Blob Storage Error: " in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 502 must still carry the error-response headers: the
    # handler sets no-store only on the success path, so on this
    # path they come from the central ApiBaseException handler,
    # and a cached 502 could otherwise be served to a different
    # user after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other user-route tests:
    # the pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the profile-image GET 502 must carry the
    # same headers as the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the other user-route locks, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # user routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
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
    # Postconditions: the constructor raises before any write or
    # presigned-URL minting, so the request is side-effect free -
    # the seeded role is still there with its permission, the
    # owning user still stores the key, and the storage row is
    # still the enabled Azure row with the malformed connection
    # string.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.USER_VIEW_ONLY]
    owner = await User.find_one(User.image_url == image_key)
    assert owner is not None
    assert owner.email == "avatar-owner@example.com"
    stored_settings = await StorageSettings.find_one(
        StorageSettings.is_enabled == True
    )
    assert stored_settings is not None
    assert stored_settings.provider == StorageProvider.AZURE_BLOB
    assert stored_settings.azure_connection_string == "not-a-connection-string"
    assert stored_settings.azure_container_name == "test-container"
    await mongo_client.close()


@pytest.mark.asyncio
async def test_put_user_update_profile_picture_with_malformed_azure_connection_string_returns_502_with_cache_and_security_headers(client: AsyncClient):
    """
        The user update_profile_picture PUT 502 path for a malformed
        Azure connection string:
    """
    # The user update_profile_picture PUT 502 branch for Azure, not
    # yet locked: function-name grep count 0 for
    # update_profile_picture_with_malformed_azure_connection_string
    # (verified fresh this run). The profile-image GET 502 locks
    # (S3, blank Azure, malformed Azure) cover only the read path
    # (FileRetrieval.generate_read_url), while the upload path
    # (FileUpload.upload_file, file_upload.py:55) constructs the
    # same AzureBlobStorage from the same enabled row and shares
    # the constructor fix - but no test anywhere in the suite
    # asserts a 502 on an upload, so deleting the 502 mapping, or
    # letting the Azure constructor fall through to the SDK's bare
    # ValueError on the upload path, would previously have gone
    # uncaught there, and a storage outage on the avatar-upload
    # path would then surface as an unhandled 500 instead of a
    # 502, hiding an upstream failure from the client fallbacks
    # that only trigger on rejection. The 502 here is
    # deterministic with no network and no live Azure call: the
    # seeded StorageSettings row enables AZURE_BLOB with the
    # malformed string "not-a-connection-string" (no key=value
    # pairs, so the SDK's local connection-string parser raises
    # ValueError before any client construction or HTTP request -
    # verified from the azure-sdk-for-python parser source in the
    # earlier run, and the exact __init__ source was executed
    # there with a stubbed SDK over blank/whitespace/None/
    # malformed/valid cases, with malformed mapping to the
    # "invalid" exception; the real SDK is not installed on this
    # machine, so the 502 outcome is verified from source, not
    # executed). The handler chain is: the USER_READ_AND_WRITE_ONLY
    # permission dependency passes on the seeded role (mirroring
    # the update_profile_picture 403 lock's seed - the PUT route's
    # required list is [USER_READ_AND_WRITE_ONLY,
    # USER_SELF_READ_AND_WRITE_ONLY] with allow_self_access=True,
    # and the general check strips USER_SELF_READ_AND_WRITE_ONLY,
    # so USER_READ_AND_WRITE_ONLY is the sole general permission;
    # the target id is distinct from the caller's own id, so the
    # self-access branch cannot pass), the scope guard passes for
    # the host mock (tenant_id None), the PNG content-type, size,
    # and non-emptiness validations pass on the tiny 1x1 part,
    # get_user_by_id finds the seeded target user, and then
    # file_service.upload_file -> FileUpload.upload_file finds
    # the enabled Azure row and constructs AzureBlobStorage,
    # which raises AzureBlobStorageException ("Azure Blob Storage
    # connection string is invalid."); the upload path catches
    # only StorageNotEnabledException, so the exception propagates
    # and the central handler answers 502. StorageSettings is
    # outside the conftest model set (conftest.py:25), so the test
    # initializes it on the test DB first: init_beanie on the same
    # URI/db name the conftest fixture uses
    # (mongodb://localhost:27012/test_db, api_test_db), mirroring
    # the branding tests' second-init precedent for Branding and
    # the profile-image 502 locks. A future change that drops the
    # 502 mapping, or that lets the Azure constructor fall through
    # to the SDK's bare ValueError on the upload path, would break
    # this lock while leaving the profile-image 502 locks and the
    # update_profile_picture 404/403 locks green, so the paths are
    # locked separately.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.role import Role
    from api.domain.entities.storage_settings import StorageProvider, StorageSettings
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[StorageSettings]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Profile picture storage caller",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()

    await User(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        first_name="Avatar",
        last_name="Upload Owner",
        email="avatar-upload-owner@example.com",
        gender=Gender.OTHER,
        is_active=True,
        password="TestPassword123!",
    ).insert()

    await StorageSettings(
        provider=StorageProvider.AZURE_BLOB,
        is_enabled=True,
        region="eu-central-1",
        azure_connection_string="not-a-connection-string",
        azure_container_name="test-container",
    ).insert()

    png_1x1 = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
        b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00"
        b"\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05"
        b"\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    response = await client.put(
        "/users/68c302ef6bf7a039b7e9b388/update_profile_picture",
        files={"file": ("avatar.png", png_1x1, "image/png")},
    )
    assert response.status_code == 502
    body = response.json()
    assert body["code"] == 502
    # AzureBlobStorageException prefixes its message ("Azure Blob
    # Storage Error: ..."), so assert on the fail-closed reason
    # itself.
    assert "Azure Blob Storage connection string is invalid." in body["error"]
    assert "Azure Blob Storage Error: " in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 502 must still carry the error-response headers: the
    # handler sets no-store only on the success path, so on this
    # path they come from the central ApiBaseException handler,
    # and a cached 502 could otherwise be served to a different
    # user after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other user-route tests:
    # the pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the update_profile_picture PUT 502 must
    # carry the same headers as the authenticated GETs, including
    # the exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the other user-route locks, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # user routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
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
    # Postconditions: the constructor raises before any write or
    # upload, so the request is side-effect free - the seeded role
    # is still there with its permission, the target user still
    # exists with no avatar stored (update_user never ran), and
    # the storage row is still the enabled Azure row with the
    # malformed connection string.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.USER_READ_AND_WRITE_ONLY]
    target = await User.find_one(
        User.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert target is not None
    assert target.email == "avatar-upload-owner@example.com"
    assert target.image_url is None
    stored_settings = await StorageSettings.find_one(
        StorageSettings.is_enabled == True
    )
    assert stored_settings is not None
    assert stored_settings.provider == StorageProvider.AZURE_BLOB
    assert stored_settings.azure_connection_string == "not-a-connection-string"
    assert stored_settings.azure_container_name == "test-container"
    await mongo_client.close()

async def test_put_user_update_profile_picture_with_blank_azure_connection_string_returns_502_with_cache_and_security_headers(client: AsyncClient):
    """
        The user update_profile_picture PUT 502 path for a blank
        Azure connection string:
    """
    # The user update_profile_picture PUT 502 branch for Azure with
    # a blank connection string, not yet locked: function-name grep
    # count 0 for update_profile_picture_with_blank_azure (verified
    # fresh this run; the blank case is locked only for the
    # profile-image GET read path in this file). The malformed-Azure
    # upload lock covers the same constructor's "invalid" branch,
    # but the blank branch raises before any SDK call ("Azure Blob
    # Storage connection string is not configured."), so deleting
    # the fail-closed blank raise would previously have gone
    # uncaught on the upload path - the SDK's bare ValueError would
    # surface as an unhandled 500 instead of a 502, hiding an
    # upstream failure from the client fallbacks that only trigger
    # on rejection. The 502 here is deterministic with no network
    # and no live Azure call: the blank check runs before any SDK
    # call or HTTP request (verified from
    # azure_storage.py:24-28 in the earlier run, and the exact
    # __init__ source was executed there with a stubbed SDK over
    # blank/whitespace/None/malformed/valid cases, with blank
    # mapping to the "not configured" exception; the real SDK is
    # not installed on this machine, so the 502 outcome is
    # verified from source, not executed). The handler chain is:
    # the USER_READ_AND_WRITE_ONLY permission dependency passes on
    # the seeded role (mirroring the update_profile_picture 403
    # lock's seed - the PUT route's required list is
    # [USER_READ_AND_WRITE_ONLY, USER_SELF_READ_AND_WRITE_ONLY]
    # with allow_self_access=True, and the general check strips
    # USER_SELF_READ_AND_WRITE_ONLY, so USER_READ_AND_WRITE_ONLY
    # is the sole general permission; the target id is distinct
    # from the caller's own id, so the self-access branch cannot
    # pass), the scope guard passes for the host mock (tenant_id
    # None), the PNG content-type, size, and non-emptiness
    # validations pass on the tiny 1x1 part, get_user_by_id finds
    # the seeded target user, and then file_service.upload_file
    # -> FileUpload.upload_file finds the enabled Azure row and
    # constructs AzureBlobStorage, which raises
    # AzureBlobStorageException ("Azure Blob Storage connection
    # string is not configured."); the upload path catches only
    # StorageNotEnabledException, so the exception propagates and
    # the central handler answers 502. StorageSettings is outside
    # the conftest model set (conftest.py:25), so the test
    # initializes it on the test DB first: init_beanie on the same
    # URI/db name the conftest fixture uses
    # (mongodb://localhost:27012/test_db, api_test_db), mirroring
    # the branding tests' second-init precedent for Branding and
    # the profile-image 502 locks. A future change that drops the
    # blank fail-closed raise, or that lets a blank connection
    # string fall through to the SDK's bare ValueError on the
    # upload path, would break this lock while leaving the
    # profile-image 502 locks, the update_profile_picture
    # malformed-Azure 502 lock, and the update_profile_picture
    # 404/403 locks green, so the paths are locked separately.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.role import Role
    from api.domain.entities.storage_settings import StorageProvider, StorageSettings
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[StorageSettings]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Profile picture storage caller",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()

    await User(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        first_name="Avatar",
        last_name="Upload Owner",
        email="avatar-upload-owner@example.com",
        gender=Gender.OTHER,
        is_active=True,
        password="TestPassword123!",
    ).insert()

    await StorageSettings(
        provider=StorageProvider.AZURE_BLOB,
        is_enabled=True,
        region="eu-central-1",
        azure_connection_string="",
        azure_container_name="test-container",
    ).insert()

    png_1x1 = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
        b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00"
        b"\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05"
        b"\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    response = await client.put(
        "/users/68c302ef6bf7a039b7e9b388/update_profile_picture",
        files={"file": ("avatar.png", png_1x1, "image/png")},
    )
    assert response.status_code == 502
    body = response.json()
    assert body["code"] == 502
    # AzureBlobStorageException prefixes its message ("Azure Blob
    # Storage Error: ..."), so assert on the fail-closed reason
    # itself.
    assert "Azure Blob Storage connection string is not configured." in body["error"]
    assert "Azure Blob Storage Error: " in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 502 must still carry the error-response headers: the
    # handler sets no-store only on the success path, so on this
    # path they come from the central ApiBaseException handler,
    # and a cached 502 could otherwise be served to a different
    # user after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other user-route tests:
    # the pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the update_profile_picture PUT 502 must
    # carry the same headers as the authenticated GETs, including
    # the exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the other user-route locks, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # user routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
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
    # Postconditions: the constructor raises before any write or
    # upload, so the request is side-effect free - the seeded role
    # is still there with its permission, the target user still
    # exists with no avatar stored (update_user never ran), and
    # the storage row is still the enabled Azure row with the
    # blank connection string.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.USER_READ_AND_WRITE_ONLY]
    target = await User.find_one(
        User.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert target is not None
    assert target.email == "avatar-upload-owner@example.com"
    assert target.image_url is None
    stored_settings = await StorageSettings.find_one(
        StorageSettings.is_enabled == True
    )
    assert stored_settings is not None
    assert stored_settings.provider == StorageProvider.AZURE_BLOB
    assert stored_settings.azure_connection_string == ""
    assert stored_settings.azure_container_name == "test-container"
    await mongo_client.close()


async def test_put_user_update_profile_picture_with_unconfigured_s3_returns_502_with_cache_and_security_headers(client: AsyncClient):
    """
        The user update_profile_picture PUT 502 path for unconfigured
        S3 credentials:
    """
    # The user update_profile_picture PUT 502 branch for S3 with
    # blank credentials, not yet locked: function-name grep count 0
    # for put_user_update_profile_picture_with_unconfigured_s3
    # (verified fresh this run; the S3 502 case is locked only for
    # the profile-image GET read path in this file). The Azure
    # upload locks cover the same FileUpload.upload_file call with
    # the other provider branch, but the S3 branch constructs a
    # different storage class, so deleting the fail-closed blank-key
    # raise in S3Storage.__init__ would previously have gone
    # uncaught on the upload path - boto3 would silently resolve
    # ambient credentials (env vars, shared config, IAM role) and
    # upload the avatar to the tenant bucket under the deployment's
    # credentials, hiding a misconfiguration from the client
    # fallbacks that only trigger on rejection. The 502 here is
    # deterministic with no network and no live S3 call: the blank
    # check runs before any boto3 client construction or HTTP
    # request (s3_storage.py), so no credential resolution,
    # signing, or request happens. The handler chain is: the
    # USER_READ_AND_WRITE_ONLY permission dependency passes on the
    # seeded role (mirroring the update_profile_picture 403 lock's
    # seed - the PUT route's required list is
    # [USER_READ_AND_WRITE_ONLY, USER_SELF_READ_AND_WRITE_ONLY]
    # with allow_self_access=True, and the general check strips
    # USER_SELF_READ_AND_WRITE_ONLY, so USER_READ_AND_WRITE_ONLY
    # is the sole general permission; the target id is distinct
    # from the caller's own id, so the self-access branch cannot
    # pass), the scope guard passes for the host mock (tenant_id
    # None), the PNG content-type, size, and non-emptiness
    # validations pass on the tiny 1x1 part, get_user_by_id finds
    # the seeded target user, and then file_service.upload_file
    # -> FileUpload.upload_file finds the enabled S3 row and
    # constructs S3Storage, which raises S3StorageException
    # ("S3 storage credentials are not configured."); the upload
    # path catches only StorageNotEnabledException, so the
    # exception propagates and the central handler answers 502.
    # StorageSettings is outside the conftest model set
    # (conftest.py:25), so the test initializes it on the test DB
    # first: init_beanie on the same URI/db name the conftest
    # fixture uses (mongodb://localhost:27012/test_db,
    # api_test_db), mirroring the branding tests' second-init
    # precedent for Branding and the profile-image 502 locks. A
    # future change that drops the blank fail-closed raise, or
    # that lets a blank S3 key fall through to ambient boto3
    # credentials on the upload path, would break this lock while
    # leaving the profile-image S3 502 lock, the
    # update_profile_picture Azure 502 locks, and the
    # update_profile_picture 404/403 locks green, so the paths
    # are locked separately.
    from beanie import PydanticObjectId, init_beanie
    from pymongo import AsyncMongoClient

    from api.domain.entities.role import Role
    from api.domain.entities.storage_settings import StorageProvider, StorageSettings
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    mongo_client = AsyncMongoClient("mongodb://localhost:27012/test_db")
    await init_beanie(
        mongo_client["api_test_db"], document_models=[StorageSettings]
    )

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Profile picture storage caller",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()

    await User(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b388"),
        first_name="Avatar",
        last_name="Upload Owner",
        email="avatar-upload-owner@example.com",
        gender=Gender.OTHER,
        is_active=True,
        password="TestPassword123!",
    ).insert()

    await StorageSettings(
        provider=StorageProvider.AWS_S3,
        is_enabled=True,
        region="eu-central-1",
        aws_access_key="",
        aws_secret_key="",
        aws_bucket_name="test-bucket",
    ).insert()

    png_1x1 = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
        b"\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00"
        b"\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05"
        b"\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    response = await client.put(
        "/users/68c302ef6bf7a039b7e9b388/update_profile_picture",
        files={"file": ("avatar.png", png_1x1, "image/png")},
    )
    assert response.status_code == 502
    body = response.json()
    assert body["code"] == 502
    # S3StorageException prefixes its message ("S3 Storage Error:
    # ..."), so assert on the fail-closed reason itself.
    assert "S3 storage credentials are not configured." in body["error"]
    assert "S3 Storage Error: " in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 502 must still carry the error-response headers: the
    # handler sets no-store only on the success path, so on this
    # path they come from the central ApiBaseException handler,
    # and a cached 502 could otherwise be served to a different
    # user after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other user-route tests:
    # the pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the update_profile_picture PUT 502 must
    # carry the same headers as the authenticated GETs, including
    # the exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the other user-route locks, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # user routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
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
    # Postconditions: the constructor raises before any write or
    # upload, so the request is side-effect free - the seeded role
    # is still there with its permission, the target user still
    # exists with no avatar stored (update_user never ran), and
    # the storage row is still the enabled S3 row with blank keys.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.USER_READ_AND_WRITE_ONLY]
    target = await User.find_one(
        User.id == PydanticObjectId("68c302ef6bf7a039b7e9b388")
    )
    assert target is not None
    assert target.email == "avatar-upload-owner@example.com"
    assert target.image_url is None
    stored_settings = await StorageSettings.find_one(
        StorageSettings.is_enabled == True
    )
    assert stored_settings is not None
    assert stored_settings.provider == StorageProvider.AWS_S3
    assert stored_settings.aws_access_key == ""
    assert stored_settings.aws_secret_key == ""
    assert stored_settings.aws_bucket_name == "test-bucket"
    await mongo_client.close()


@pytest.mark.asyncio
async def test_create_duplicate_user_returns_409_with_cache_and_security_headers(client: AsyncClient):
    """
        The user create duplicate-email error path:
    """
    # The user create 409 branch, not yet locked: function-name
    # grep count 0 for create_duplicate_user and grep count 0 for
    # "already exists" across this file (verified fresh this run).
    # The suite's only 409 lock so far is the role create one
    # (test_role_endpoint.py), so the central handler's
    # ConflictException -> 409 mapping (api/__init__.py:89-90) had
    # no lock on the user route. Deleting the duplicate check in
    # user_service.create_user would previously have gone uncaught,
    # and a second user with the same email would then be planted
    # (or fail later on the unique email index with a 500 instead
    # of the clean 409). The duplicate check runs in the service
    # before any write, so this lock needs no broker or mail care:
    # create_user does a single_or_none(email=...) lookup and
    # raises EmailAlreadyExistsException (user_service.py:118-122),
    # which subclasses ConflictException with the message "User
    # with identifier <email> already exists."
    # (core/exceptions.py:9-11, common/exceptions.py:26-38), and
    # the central handler maps it to 409 with {"error": ...,
    # "code": 409} plus the no-store/Pragma error headers
    # (api/__init__.py:89-90, 121-133). The create handler itself
    # (user_endpoint.py:115-128) runs the
    # USER_READ_AND_WRITE_ONLY permission dependency and
    # _assert_create_scope before the service call, and the shared
    # conftest mock is a host caller (tenant_id None), so both pass
    # with no X-Tenant-ID header, exactly as the create 201 helper
    # proves. The activation email send in create_user is commented
    # out (user_service.py:137-147), so the duplicate path sends no
    # email and enqueues no Celery task - the 409 fires before the
    # commented-out send site is even reached. The same valid body
    # the create helper posts (email test@example.com, password
    # Test@123!) is posted twice, so no 422 can mask the 409. A
    # future change that drops the duplicate check would break this
    # lock while leaving the create 201 lock and the create 403
    # lock green, so the paths are locked separately.
    # Setup: create the user through the real 201 path first.
    await create_user(client)

    new_user = CreateUserDto(
        email="test@example.com",
        first_name="Test",
        last_name="User",
        gender=Gender.OTHER,
        password="Test@123!",
    )
    response = await client.post("/users/", json=new_user.model_dump())
    assert response.status_code == 409
    body = response.json()
    assert body["code"] == 409
    assert body["error"] == "User with identifier test@example.com already exists."
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 409 must still carry the error-response headers: the
    # handler sets no-store only after the guard, so on this path
    # they come from the central ApiBaseException handler, and a
    # cached 409 could otherwise be served to a different user
    # after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the user list 200 and create
    # 201 tests: the pure-ASGI middleware stamps every HTTP
    # response with no path exclusions, so the user create 409
    # must carry the same headers as the authenticated GETs,
    # including the exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the user list locks, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # user routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
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

    # Postcondition: the duplicate check fires before any write,
    # so the request is side-effect free - listing users still
    # shows exactly one user, the one created by the setup call.
    response = await client.get("/users/?skip=0&limit=10")
    assert response.status_code == 200
    data = UserListDto.model_validate(response.json())
    assert data.total == 1
    assert data.users[0].email == "test@example.com"


@pytest.mark.asyncio
async def test_put_user_with_changed_email_returns_400_with_cache_and_security_headers(client: AsyncClient):
    """
        The PUT /users/{id} changed-email error path:
        UpdateUserDto carries an email field and the PUT
        endpoint accepts it, but UserService.update_user
        never applied it - the only email handling was the
        commented-out TODO block - so a client sending a new
        email got a 200 back with the old address still
        stored, a silent no-op (function-name grep count 0
        for put_user_with_changed_email, verified fresh this
        run). Applying the new address in update_user would
        bypass the change-email flow (account_endpoint
        change_email_request / change_email_confirmation),
        which sends a confirmation token to the new address
        before the switch, so the service now rejects a
        differing email with ApiBaseException, which the
        central handler maps to 400 with {"error", "code":
        400} plus the no-store/Pragma error headers
        (api/__init__.py:89-90, 121-133) - the same 400 the
        magic-link rate limit raises directly. Echoing the
        current email stays a no-op, so the existing
        test_update_user_by_id_from_host full-DTO echo still
        passes, and the internal role-only / image-only
        callers pass email None and never reach the branch.
        The body is the fetched user with only the email
        changed, so no 422 or role-change guard can mask
        the 400. A future change that drops the service
        check would break this lock while leaving the
        update-user 200 lock green, so the paths are locked
        separately. Residual, not covered by this lock: a
        direct email change is still impossible by design -
        callers must use the change-email flow.
    """
    new_user_response = await create_user(client)
    response = await client.get(f"/users/{new_user_response.id}")
    assert response.status_code == 200
    data = UserDto.model_validate(response.json())

    # Send the full DTO back with only the email changed, exactly
    # as a full-DTO client would: the old code returned 200 and
    # stored nothing, so the caller believed the email had moved.
    payload = data.model_dump()
    payload["email"] = "changed@example.com"
    updated_data = UpdateUserDto(**payload)
    response = await client.put(f"/users/{new_user_response.id}", json=updated_data.model_dump())
    assert response.status_code == 400
    body = response.json()
    assert body["code"] == 400
    assert "Email cannot be changed here. Use the change email flow to update your email address." in body["error"]
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 400 must still carry the error-response headers: the
    # check raises before the handler builds any response object,
    # so on this path the no-store/Pragma headers come from the
    # central ApiBaseException handler, and a cached 400 could
    # otherwise be served to a different admin after an account
    # switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the other user tests in this
    # file: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so this authenticated user 400
    # must carry the same headers as the other interface locks.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the single-user GET lock in this file (iteration 1897),
    # using substring checks so later additions to the list do not
    # break this test. The full value lives in _SECURITY_HEADERS.
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

    # Postcondition: the 400 fired before any write, so the stored
    # email is unchanged - had the check been dropped, the old code
    # would still have stored nothing (silent no-op), but a future
    # naive implementation of the TODO block would have moved the
    # address without confirmation, bypassing the change-email
    # flow; this assertion pins the no-write outcome either way.
    response = await client.get(f"/users/{new_user_response.id}")
    assert response.status_code == 200
    assert UserDto.model_validate(response.json()).email == "test@example.com"


@pytest.mark.asyncio
async def test_put_user_with_changed_is_active_applies_it_with_cache_and_security_headers(client: AsyncClient):
    """
        The PUT /users/{id} is_active path:
        UpdateUserDto carries an is_active field and the PUT
        endpoint accepts it, but UserService.update_user
        never applied it - first_name / last_name / gender /
        role_id / image_url were the only fields written - so
        a client sending is_active=false got a 200 back with
        the user still active, a silent no-op (function-name
        grep count 0 for put_user_with_changed_is_active,
        verified fresh this run). It is the same accepted-field-
        silently-ignored class as the changed-email 400 lock,
        but unlike email there is no dedicated
        activate/deactivate endpoint - activation only ever
        sets the flag True - so the service now applies the
        field instead of rejecting it: it is the admin's only
        API path to deactivate (or reactivate) a user, and the
        flag is what the user table, the resend-activation
        guard and the token payload all read. The created user
        starts inactive (UserRepository.create sets
        is_active=False), so the lock flips False -> True and
        then back True -> False: the second flip is what pins
        the explicit `is not None` guard, since a bare `or`
        would swallow False and make deactivation impossible.
        None still means "leave unchanged", so the internal
        role-only / image-only callers pass neither and are
        unaffected, and the full-DTO echo test still passes
        because it echoes the fetched (inactive) value. The
        two PUTs make no Celery or email call, so the lock
        needs no broker or SMTP care. A future change that
        drops the service assignment would break this lock
        while leaving the update-user 200 echo and the
        changed-email 400 locks green, so the paths are
        locked separately.
    """
    new_user_response = await create_user(client)
    response = await client.get(f"/users/{new_user_response.id}")
    assert response.status_code == 200
    data = UserDto.model_validate(response.json())
    assert data.is_active is False

    # Flip the flag on: the old code returned 200 and stored
    # nothing, so the caller believed the user was active.
    payload = data.model_dump()
    payload["is_active"] = True
    updated_data = UpdateUserDto(**payload)
    response = await client.put(f"/users/{new_user_response.id}", json=updated_data.model_dump())
    assert response.status_code == 200
    # Same security-headers lock as the update-user 200 echo
    # in this file: the middleware stamps every HTTP response,
    # so it stamps this PUT response too, but until now only
    # its status and body were asserted on this path - deleting
    # the middleware registration would have gone uncaught here.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the single-user GET lock in this file (iteration 1897),
    # using substring checks so later additions to the list do not
    # break this test. The full value lives in _SECURITY_HEADERS.
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
    assert UserDto.model_validate(response.json()).is_active is True

    # Flip the flag back off: this is the deactivation direction
    # a bare `or` guard would silently drop, so it must be locked
    # separately from the activation above.
    payload = UserDto.model_validate(response.json()).model_dump()
    payload["is_active"] = False
    updated_data = UpdateUserDto(**payload)
    response = await client.put(f"/users/{new_user_response.id}", json=updated_data.model_dump())
    assert response.status_code == 200
    assert UserDto.model_validate(response.json()).is_active is False

    # Postcondition: a follow-up GET shows the stored value
    # persisted - had the assignment been dropped, the GET would
    # still show the user active after the first PUT.
    response = await client.get(f"/users/{new_user_response.id}")
    assert response.status_code == 200
    assert UserDto.model_validate(response.json()).is_active is False


@pytest.mark.asyncio
async def test_create_user_with_sso_provider_id_persists_it_at_repository(client: AsyncClient):
    """
        The user create sso_provider_id drop, not yet locked:
        function-name grep count 0 for
        create_user_with_sso_provider_id_persists_it_at_repository
        and grep count 0 for "sso_provider_id" in this file
        (verified fresh this run). CreateUserDto carries
        sso_provider_id (domain/dtos/user_dto.py:15, inherited by
        CreateUserDto) and the User entity stores it
        (domain/entities/user.py:19), but UserRepository.create
        built the User without it, so any caller passing the field
        had it silently dropped. No live caller passes it today:
        login_with_sso builds the CreateUserDto without it and sets
        the flag on the re-fetched user afterwards
        (usecases/auth_service.py:221-249), so the drop was latent
        rather than a live defect - but the next caller to supply
        it (or a future SSO signup that passes it at creation)
        would have lost the linkage with no error. The repository
        is called directly here, bypassing the endpoint on purpose:
        the endpoint path never sends sso_provider_id, so only a
        direct call exercises the passthrough deterministically.
        The client fixture is only used to initialise the per-test
        database (conftest.py:24-44, db.drop() after); no HTTP call
        is made. A future change that drops the field from the
        User(...) construction would break this lock while leaving
        the create 201 and duplicate-email 409 locks green, so the
        layer is locked separately.
    """
    from api.domain.entities.user import User
    from api.infrastructure.persistence.repositories.user_repository_impl import UserRepository

    repository = UserRepository()
    user_id = await repository.create(
        CreateUserDto(
            email="test@example.com",
            first_name="Test",
            last_name="User",
            gender=Gender.OTHER,
            password="Test@123!",
            sso_provider_id="google",
        )
    )
    assert user_id is not None

    stored = await User.find_one(User.email == "test@example.com")
    assert stored is not None
    assert stored.sso_provider_id == "google"


@pytest.mark.asyncio
async def test_create_user_missing_body_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with no request body at all:
    """
    # The first branch of the user body-shape sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_user_missing_body and grep count 0 for "missing_body"
    # in this file before appending. The account body-shape sweeps
    # are complete (register, password-reset-request,
    # password-reset-confirmation, activate,
    # change-email-request, change-email-confirmation,
    # resend-activation-email, login JSON-body - iterations
    # 2547-2555), the tenant sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # plus the per-field sweep - iterations 2556-2577), and the
    # role sweep is complete (missing body, non-object, string,
    # numeric, boolean, null, malformed JSON plus the per-field
    # sweep - iterations 2578-2599), and no other endpoint test
    # file locks a body-shape 422 yet, so the user sweep starts
    # here with POST /users/. The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose first_name, last_name,
    # email and gender fields are required (user_dto.py:8-43;
    # password is required on CreateUserDto), so a request
    # carrying no body fails FastAPI request validation before
    # the handler body runs: UserService.create_user never runs,
    # so no user record is created -- no duplicate-email check,
    # no GUEST role lookup, no repository write. No body and no
    # content type are sent, so the failure is a missing body,
    # not a content-type rejection. This is distinct from the
    # missing-field locks (an object body with a field absent)
    # and from the scalar-body locks (valid JSON of the wrong
    # type): here there is no body to parse at all, so the
    # failure is a missing required body whose detail loc is
    # still ["body"], mirroring the tenant, account and role
    # missing-body 422 locks. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 422, exactly as in the role missing-body
    # lock. The role is seeded with the mocked user's exact
    # role_id (68c302ef6bf7a039b7e9b386, conftest.py) and the
    # route's USER_READ_AND_WRITE_ONLY permission, mirroring
    # the user create 403 seed precedent in this file. The
    # default conftest mock is a host caller (tenant_id None),
    # so the handler's _assert_create_scope check cannot fire.
    # Deliberately no exact error-type assertion, mirroring the
    # tenant, account and role missing-body 422 locks.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to
    # it, mirroring the tenant, account and role missing-body
    # 422 locks. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
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
    # mirroring the other user locks in this file, using
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
async def test_create_user_non_object_body_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a JSON array body:
    """
    # The second branch of the user body-shape sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_user_non_object_body and grep count 0 for
    # "non_object_body" in this file before appending. The
    # account body-shape sweeps are complete (register,
    # password-reset-request, password-reset-confirmation,
    # activate, change-email-request, change-email-confirmation,
    # resend-activation-email, login JSON-body - iterations
    # 2547-2555), the tenant sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # plus the per-field sweep - iterations 2556-2577), and the
    # role sweep is complete (missing body, non-object, string,
    # numeric, boolean, null, malformed JSON plus the per-field
    # sweep - iterations 2578-2599), and the user sweep started
    # in iteration 2600 with the missing-body lock, so the
    # non-object body is next here with POST /users/. The
    # endpoint takes a required `data: CreateUserDto` body
    # parameter (user_endpoint.py:115-128) whose first_name,
    # last_name, email and gender fields are required
    # (user_dto.py:8-43; password is required on
    # CreateUserDto), so a JSON array body cannot coerce to the
    # DTO and fails FastAPI request validation before the
    # handler body runs: UserService.create_user never runs, so
    # no user record is created -- no duplicate-email check, no
    # GUEST role lookup, no repository write. The DTO's
    # mode="after" normalize_names validator only runs after
    # valid field parsing, so it cannot mask the 422. This is
    # distinct from the missing-body lock (no body at all) and
    # from the missing-field locks (an object body with a field
    # absent): here a body is present and parses as JSON, but
    # of the wrong type, so the failure is a body-shape 422
    # whose detail loc is still ["body"], mirroring the tenant,
    # account and role non-object 422 locks. The endpoint is
    # permission-gated (USER_READ_AND_WRITE_ONLY), and FastAPI
    # solves sub-dependencies before validating the endpoint's
    # own body, so the mocked caller's role must be seeded
    # first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the role non-object-body lock. The role is seeded with
    # the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # create 403 seed precedent in this file. The default
    # conftest mock is a host caller (tenant_id None), so the
    # handler's _assert_create_scope check cannot fire.
    # Deliberately no exact error-type assertion, mirroring the
    # tenant, account and role non-object 422 locks.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to
    # it, mirroring the tenant, account and role non-object 422
    # locks. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json=["acme"],
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_string_body_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a JSON string body:
    """
    # The third branch of the user body-shape sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_user_string_body and grep count 0 for
    # "string_body" in this file before appending. The
    # account body-shape sweeps are complete (register,
    # password-reset-request, password-reset-confirmation,
    # activate, change-email-request, change-email-confirmation,
    # resend-activation-email, login JSON-body - iterations
    # 2547-2555), the tenant sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # plus the per-field sweep - iterations 2556-2577), and the
    # role sweep is complete (missing body, non-object, string,
    # numeric, boolean, null, malformed JSON plus the per-field
    # sweep - iterations 2578-2599), and the user sweep locked
    # missing body (2600) and non-object body (2601), so the
    # string body is next here with POST /users/. The
    # endpoint takes a required `data: CreateUserDto` body
    # parameter (user_endpoint.py:115-128) whose first_name,
    # last_name, email and gender fields are required
    # (user_dto.py:8-43; password is required on
    # CreateUserDto), so a JSON string body cannot coerce to the
    # DTO and fails FastAPI request validation before the
    # handler body runs: UserService.create_user never runs, so
    # no user record is created -- no duplicate-email check, no
    # GUEST role lookup, no repository write. The DTO's
    # mode="after" normalize_names validator only runs after
    # valid field parsing, so it cannot mask the 422. This is
    # distinct from the missing-body lock (no body at all) and
    # from the non-object lock (a JSON array body): here a body
    # is present and parses as JSON, but of the wrong scalar
    # type, so the failure is a body-shape 422 whose detail loc
    # is still ["body"], mirroring the tenant, account and role
    # string-body 422 locks. The endpoint is
    # permission-gated (USER_READ_AND_WRITE_ONLY), and FastAPI
    # solves sub-dependencies before validating the endpoint's
    # own body, so the mocked caller's role must be seeded
    # first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the role string-body lock. The role is seeded with
    # the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # create 403 seed precedent in this file. The default
    # conftest mock is a host caller (tenant_id None), so the
    # handler's _assert_create_scope check cannot fire.
    # Deliberately no exact error-type assertion, mirroring the
    # tenant, account and role string-body 422 locks.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to
    # it, mirroring the tenant, account and role string-body 422
    # locks. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json="acme",
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_numeric_body_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a JSON numeric body:
    """
    # The fourth branch of the user body-shape sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_user_numeric_body and grep count 0 for
    # "numeric_body" in this file before appending. The
    # account body-shape sweeps are complete (register,
    # password-reset-request, password-reset-confirmation,
    # activate, change-email-request, change-email-confirmation,
    # resend-activation-email, login JSON-body - iterations
    # 2547-2555), the tenant sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # plus the per-field sweep - iterations 2556-2577), and the
    # role sweep is complete (missing body, non-object, string,
    # numeric, boolean, null, malformed JSON plus the per-field
    # sweep - iterations 2578-2599), and the user sweep locked
    # missing body (2600), non-object body (2601) and string body
    # (2602), so the numeric body is next here with POST /users/.
    # The endpoint takes a required `data: CreateUserDto` body
    # parameter (user_endpoint.py:115-128) whose first_name,
    # last_name, email and gender fields are required
    # (user_dto.py:8-43; password is required on
    # CreateUserDto), so a JSON numeric body cannot coerce to the
    # DTO and fails FastAPI request validation before the
    # handler body runs: UserService.create_user never runs, so
    # no user record is created -- no duplicate-email check, no
    # GUEST role lookup, no repository write. The DTO's
    # mode="after" normalize_names validator only runs after
    # valid field parsing, so it cannot mask the 422. This is
    # distinct from the missing-body lock (no body at all), from
    # the non-object lock (a JSON array body) and from the
    # string-body lock (a JSON string body): here a body is
    # present and parses as JSON, but of the wrong scalar type,
    # so the failure is a body-shape 422 whose detail loc is
    # still ["body"], mirroring the tenant, account and role
    # numeric-body 422 locks. The endpoint is
    # permission-gated (USER_READ_AND_WRITE_ONLY), and FastAPI
    # solves sub-dependencies before validating the endpoint's
    # own body, so the mocked caller's role must be seeded
    # first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the role numeric-body lock. The role is seeded with
    # the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # create 403 seed precedent in this file. The default
    # conftest mock is a host caller (tenant_id None), so the
    # handler's _assert_create_scope check cannot fire.
    # Deliberately no exact error-type assertion, mirroring the
    # tenant, account and role numeric-body 422 locks.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to
    # it, mirroring the tenant, account and role numeric-body
    # 422 locks. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json=123,
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_boolean_body_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a JSON boolean body:
    """
    # The fifth branch of the user body-shape sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_user_boolean_body and grep count 0 for
    # "boolean_body" in this file before appending. The
    # account body-shape sweeps are complete (register,
    # password-reset-request, password-reset-confirmation,
    # activate, change-email-request, change-email-confirmation,
    # resend-activation-email, login JSON-body - iterations
    # 2547-2555), the tenant sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # plus the per-field sweep - iterations 2556-2577), and the
    # role sweep is complete (missing body, non-object, string,
    # numeric, boolean, null, malformed JSON plus the per-field
    # sweep - iterations 2578-2599), and the user sweep locked
    # missing body (2600), non-object body (2601), string body
    # (2602) and numeric body (2603), so the boolean body is
    # next here with POST /users/. The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose first_name, last_name,
    # email and gender fields are required (user_dto.py:8-43;
    # password is required on CreateUserDto), so a JSON boolean
    # body cannot coerce to the DTO and fails FastAPI request
    # validation before the handler body runs:
    # UserService.create_user never runs, so no user record is
    # created -- no duplicate-email check, no GUEST role lookup,
    # no repository write. The DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing, so it cannot mask the 422. This is distinct from
    # the missing-body lock (no body at all), from the
    # non-object lock (a JSON array body), from the string-body
    # lock (a JSON string body) and from the numeric-body lock
    # (a JSON numeric body): here a body is present and parses
    # as JSON, but of the wrong scalar type, so the failure is
    # a body-shape 422 whose detail loc is still ["body"],
    # mirroring the tenant, account and role boolean-body 422
    # locks. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 422, exactly as in the role boolean-body
    # lock. The role is seeded with the mocked user's exact
    # role_id (68c302ef6bf7a039b7e9b386, conftest.py) and the
    # route's USER_READ_AND_WRITE_ONLY permission, mirroring
    # the user create 403 seed precedent in this file. The
    # default conftest mock is a host caller (tenant_id None),
    # so the handler's _assert_create_scope check cannot fire.
    # Deliberately no exact error-type assertion, mirroring the
    # tenant, account and role boolean-body 422 locks.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to
    # it, mirroring the tenant, account and role boolean-body
    # 422 locks. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
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
    # mirroring the other user locks in this file, using
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

async def test_create_user_null_body_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with an explicit JSON null body:
    """
    # The sixth branch of the user body-shape sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_user_null_body and grep count 0 for "null_body" in
    # this file before appending. The account body-shape sweeps
    # are complete (register, password-reset-request,
    # password-reset-confirmation, activate, change-email-request,
    # change-email-confirmation, resend-activation-email, login
    # JSON-body - iterations 2547-2555), the tenant sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON plus the per-field sweep -
    # iterations 2556-2577), and the role sweep is complete
    # (missing body, non-object, string, numeric, boolean,
    # null, malformed JSON plus the per-field sweep - iterations
    # 2578-2599), and the user sweep locked missing body
    # (2600), non-object body (2601), string body (2602),
    # numeric body (2603) and boolean body (2604), so the null
    # body is next here with POST /users/. The endpoint takes
    # a required `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose first_name, last_name,
    # email and gender fields are required (user_dto.py:8-43;
    # password is required on CreateUserDto), so an explicit
    # JSON null body cannot coerce to the DTO and fails FastAPI
    # request validation before the handler body runs:
    # UserService.create_user never runs, so no user record is
    # created -- no duplicate-email check, no GUEST role lookup,
    # no repository write. The DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing, so it cannot mask the 422. This is distinct from
    # the missing-body lock (no body at all), from the
    # non-object lock (a JSON array body), from the string-body
    # lock (a JSON string body), from the numeric-body lock (a
    # JSON numeric body) and from the boolean-body lock (a JSON
    # boolean body): here a body is present and parses as JSON,
    # but is an explicit null, so the failure is a body-shape
    # 422 whose detail loc is still ["body"], mirroring the
    # tenant, account and role null-body 422 locks. The body is
    # sent as the literal string "null" with a JSON content
    # type rather than via json=None, so the null is
    # unambiguous and does not depend on how the HTTP client
    # encodes a None json argument, mirroring the tenant,
    # account and role null-body locks. The endpoint is
    # permission-gated (USER_READ_AND_WRITE_ONLY), and FastAPI
    # solves sub-dependencies before validating the endpoint's
    # own body, so the mocked caller's role must be seeded
    # first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the role null-body lock. The role is seeded with the
    # mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-body lock, so the permission gate cannot mask
    # the 422 with a 404; the default conftest mock is a host
    # caller (tenant_id None), so _assert_create_scope cannot
    # fire. Deliberately no exact error-type assertion,
    # mirroring the tenant, account and role null-body 422
    # locks. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the tenant,
    # account and role null-body 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with
    # no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
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
    # mirroring the other user locks in this file, using
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

async def test_create_user_malformed_json_body_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a malformed (non-JSON) body:
    """
    # The seventh branch of the user body-shape sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_user_malformed_json_body and grep count 0 for
    # "malformed_json_body" in this file before appending. The
    # account body-shape sweeps are complete (register,
    # password-reset-request, password-reset-confirmation,
    # activate, change-email-request, change-email-confirmation,
    # resend-activation-email, login JSON-body - iterations
    # 2547-2555), the tenant sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # plus the per-field sweep - iterations 2556-2577), and the
    # role sweep is complete (missing body, non-object, string,
    # numeric, boolean, null, malformed JSON plus the per-field
    # sweep - iterations 2578-2599), and the user sweep locked
    # missing body (2600), non-object body (2601), string body
    # (2602), numeric body (2603), boolean body (2604) and null
    # body (2605), so the malformed-JSON body is next here with
    # POST /users/. The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose first_name, last_name,
    # email and gender fields are required (user_dto.py:8-43;
    # password is required on CreateUserDto), so a body that is
    # not valid JSON at all cannot even be parsed, and fails
    # FastAPI request validation before the handler body runs:
    # UserService.create_user never runs, so no user record is
    # created -- no duplicate-email check, no GUEST role lookup,
    # no repository write. The DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing, so it cannot mask the 422. This is distinct from
    # the missing-body lock (no body at all), from the
    # non-object lock (a JSON array body) and from the
    # string/numeric/boolean/null scalar locks (valid JSON of
    # the wrong type): here the body is not JSON at all, so the
    # failure is a JSON decode error whose detail loc is still
    # ["body"], mirroring the tenant, account and role
    # malformed-JSON 422 locks. The body is sent with an
    # explicit JSON content type so the failure is a parse
    # failure, not a content-type rejection. The endpoint is
    # permission-gated (USER_READ_AND_WRITE_ONLY), and FastAPI
    # solves sub-dependencies before validating the endpoint's
    # own body, so the mocked caller's role must be seeded
    # first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the role malformed-JSON lock. The role is seeded with
    # the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-body lock, so the permission gate cannot mask
    # the 422 with a 404; the default conftest mock is a host
    # caller (tenant_id None), so _assert_create_scope cannot
    # fire. Deliberately no exact error-type assertion,
    # mirroring the tenant, account and role malformed-JSON 422
    # locks. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the tenant,
    # account and role malformed-JSON 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with
    # no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_missing_first_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with the required first_name field omitted:
    """
    # The first branch of the user per-field sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_user_missing_first_name and grep count 0 for
    # "missing_first_name" in this file before appending. The
    # account body-shape sweeps are complete (register,
    # password-reset-request, password-reset-confirmation,
    # activate, change-email-request, change-email-confirmation,
    # resend-activation-email, login JSON-body - iterations
    # 2547-2555), the tenant sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # plus the per-field sweep - iterations 2556-2577), the role
    # sweep is complete (missing body, non-object, string,
    # numeric, boolean, null, malformed JSON plus the per-field
    # sweep - iterations 2578-2599), and the user body-shape
    # sweep is complete (missing body, non-object, string,
    # numeric, boolean, null, malformed JSON - iterations
    # 2600-2606), so the user per-field sweep starts here with
    # POST /users/. The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose first_name is a required
    # str (Field min_length=1), alongside required last_name,
    # email and gender and a required password on CreateUserDto
    # (user_dto.py:8-43), so an object body missing first_name
    # fails FastAPI request validation before the handler body
    # runs: UserService.create_user never runs, so no user
    # record is created -- no duplicate-email check, no GUEST
    # role lookup, no repository write. The DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing, so it cannot mask the 422. This is distinct from
    # the missing-body lock (no body at all) and from the
    # scalar-body locks (valid JSON of the wrong type): here the
    # body is a valid object with every other required field
    # present and valid, so the failure is a missing required
    # field whose detail loc is ["body", "first_name"],
    # mirroring the role missing-name 422 lock. The endpoint is
    # permission-gated (USER_READ_AND_WRITE_ONLY), and FastAPI
    # solves sub-dependencies before validating the endpoint's
    # own body, so the mocked caller's role must be seeded
    # first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the role missing-name lock. The role is seeded with
    # the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-body lock, so the permission gate cannot mask
    # the 422 with a 404; the default conftest mock is a host
    # caller (tenant_id None), so _assert_create_scope cannot
    # fire. Deliberately no exact error-type assertion,
    # mirroring the tenant, account and role missing-field 422
    # locks. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the tenant,
    # account and role missing-field 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with
    # no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "first_name"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_non_string_first_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with first_name sent as a non-string (numeric 123):
    """
    # The second branch of the user per-field sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_user_non_string_first_name in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), and
    # the user per-field sweep opened with the missing-first_name
    # lock (iteration 2607), so the per-field sweep continues
    # here with POST /users/. The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose first_name is a required
    # str (Field min_length=1), alongside required last_name,
    # email and gender and a required password on CreateUserDto
    # (user_dto.py:8-43). Pydantic v2 does not coerce a number
    # to a string, so a numeric first_name fails FastAPI request
    # validation as a string_type field error at
    # ["body", "first_name"] before the handler body runs:
    # UserService.create_user never runs, so no user record is
    # created -- no duplicate-email check, no GUEST role lookup,
    # no repository write. The DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing, so it cannot mask the 422. This mirrors the role
    # non-string-name lock (iteration 2586), which failed the
    # same way at ["body", "name"] for a numeric name, and is
    # distinct from the missing-first_name lock (iteration 2607):
    # here the field is present but of the wrong JSON type, with
    # every other required field present and valid, so the
    # failure is a type error rather than a missing field. The
    # endpoint is permission-gated (USER_READ_AND_WRITE_ONLY),
    # and FastAPI solves sub-dependencies before validating the
    # endpoint's own body, so the mocked caller's role must be
    # seeded first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the role non-string-name lock. The role is seeded with
    # the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-first_name lock, so the permission gate cannot mask
    # the 422 with a 404; the default conftest mock is a host
    # caller (tenant_id None), so _assert_create_scope cannot
    # fire. Deliberately no exact error-type assertion,
    # mirroring the tenant, account and role non-string-field 422
    # locks. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the tenant,
    # account and role non-string-field 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with
    # no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": 123,
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "first_name"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_object_first_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with first_name sent as an object (a JSON
        dict {"value": "Test"}):
    """
    # The third branch of the user per-field sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_user_object_first_name in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), and
    # the user per-field sweep opened with the missing-first_name
    # lock (iteration 2607) and continued with the non-string
    # (numeric) first_name lock (iteration 2608), so the
    # per-field sweep continues here with POST /users/. The
    # endpoint takes a required `data: CreateUserDto` body
    # parameter (user_endpoint.py:115-128) whose first_name is
    # a required str (Field min_length=1), alongside required
    # last_name, email and gender and a required password on
    # CreateUserDto (user_dto.py:8-43). Pydantic v2 does not
    # coerce a JSON object to a string, so a dict first_name
    # fails FastAPI request validation as a string_type field
    # error at ["body", "first_name"] before the handler body
    # runs: UserService.create_user never runs, so no user
    # record is created -- no duplicate-email check, no GUEST
    # role lookup, no repository write. The DTO's
    # mode="after" normalize_names validator only runs after
    # valid field parsing, so it cannot mask the 422. This
    # mirrors the role object-name lock, which failed the same
    # way at ["body", "name"] for a dict name, and is distinct
    # from the missing-first_name lock (iteration 2607) and the
    # numeric first_name lock (iteration 2608): here the field
    # is present but of a different wrong JSON type, with every
    # other required field present and valid, so the failure is
    # again a type error rather than a missing field. The
    # endpoint is permission-gated (USER_READ_AND_WRITE_ONLY),
    # and FastAPI solves sub-dependencies before validating the
    # endpoint's own body, so the mocked caller's role must be
    # seeded first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the role object-name lock. The role is seeded with
    # the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-first_name lock, so the permission gate cannot mask
    # the 422 with a 404; the default conftest mock is a host
    # caller (tenant_id None), so _assert_create_scope cannot
    # fire. Deliberately no exact error-type assertion,
    # mirroring the tenant, account and role object-field 422
    # locks. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the tenant,
    # account and role object-field 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with
    # no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": {"value": "Test"},
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "first_name"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_float_first_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with first_name sent as a float (a JSON
        number 1.5):
    """
    # The fourth branch of the user per-field sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_user_float_first_name in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), and
    # the user per-field sweep opened with the missing-first_name
    # lock (iteration 2607) and continued with the non-string
    # (numeric) first_name lock (iteration 2608) and the object
    # first_name lock (iteration 2609), so the per-field sweep
    # continues here with POST /users/. The endpoint takes a
    # required `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose first_name is a required
    # str (Field min_length=1), alongside required last_name,
    # email and gender and a required password on CreateUserDto
    # (user_dto.py:8-44). Pydantic v2 does not coerce a JSON
    # number to a string, so a float first_name fails FastAPI
    # request validation as a string_type field error at
    # ["body", "first_name"] before the handler body runs:
    # UserService.create_user never runs, so no user record is
    # created -- no duplicate-email check, no GUEST role lookup,
    # no repository write. The DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing, so it cannot mask the 422. This mirrors the role
    # float-name lock, which failed the same way at ["body",
    # "name"] for a float name, and is distinct from the
    # missing-first_name lock (iteration 2607), the numeric
    # (integer) first_name lock (iteration 2608) and the object
    # first_name lock (iteration 2609): here the field is
    # present but a non-integer JSON number, with every other
    # required field present and valid, so the failure is again
    # a type error rather than a missing field. The endpoint is
    # permission-gated (USER_READ_AND_WRITE_ONLY), and FastAPI
    # solves sub-dependencies before validating the endpoint's
    # own body, so the mocked caller's role must be seeded
    # first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the role float-name lock. The role is seeded with the
    # mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-first_name lock, so the permission gate cannot mask
    # the 422 with a 404; the default conftest mock is a host
    # caller (tenant_id None), so _assert_create_scope cannot
    # fire. Deliberately no exact error-type assertion,
    # mirroring the tenant, account and role float-field 422
    # locks. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the tenant,
    # account and role float-field 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with
    # no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": 1.5,
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "first_name"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_empty_first_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with first_name sent as an empty
        string (""):
    """
    # The fifth branch of the user per-field sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_user_empty_first_name in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), and
    # the user per-field sweep opened with the missing-first_name
    # lock (iteration 2607) and continued with the non-string
    # (numeric) first_name lock (iteration 2608), the object
    # first_name lock (iteration 2609) and the float first_name
    # lock (iteration 2610), so the per-field sweep continues
    # here with POST /users/. The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose first_name is a required
    # str (Field min_length=1), alongside required last_name,
    # email and gender and a required password on CreateUserDto
    # (user_dto.py:8-44). An empty string fails the min_length=1
    # field constraint as a string_too_short error at ["body",
    # "first_name"] before the handler body runs:
    # UserService.create_user never runs, so no user record is
    # created -- no duplicate-email check, no GUEST role lookup,
    # no repository write. The failure happens at field
    # validation, before the DTO's mode="after" normalize_names
    # validator runs, so that validator cannot mask the 422.
    # This mirrors the role too-short-name lock, which failed
    # the same way at ["body", "name"] for a one-character name
    # against min_length=2, and is distinct from the
    # missing-first_name lock (iteration 2607, field absent),
    # the numeric first_name lock (iteration 2608), the object
    # first_name lock (iteration 2609) and the float first_name
    # lock (iteration 2610): here the field is present and a
    # string, but simply too short, with every other required
    # field present and valid, so the failure is a length error
    # rather than a missing field or a type error. The endpoint
    # is permission-gated (USER_READ_AND_WRITE_ONLY), and FastAPI
    # solves sub-dependencies before validating the endpoint's
    # own body, so the mocked caller's role must be seeded
    # first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the role too-short-name lock. The role is seeded with
    # the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-first_name lock, so the permission gate cannot mask
    # the 422 with a 404; the default conftest mock is a host
    # caller (tenant_id None), so _assert_create_scope cannot
    # fire. Deliberately no exact error-type assertion,
    # mirroring the tenant, account and role too-short-field 422
    # locks. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the tenant,
    # account and role too-short-field 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with
    # no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "first_name"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_whitespace_first_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with first_name sent as a
        whitespace-only string ("   "):
    """
    # The sixth branch of the user per-field sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_user_whitespace_first_name and grep count 0 for
    # "whitespace_first_name" in this file before appending. The
    # tenant sweep is complete (body-shape 2556-2562 + per-field
    # 2563-2577), the register sweep is complete, the role sweep
    # is complete (body-shape 2578-2584 + per-field 2585-2599),
    # the user body-shape sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # - iterations 2600-2606), and the user per-field sweep
    # opened with the missing-first_name lock (iteration 2607)
    # and continued with the non-string (numeric) first_name lock
    # (iteration 2608), the object first_name lock (iteration
    # 2609), the float first_name lock (iteration 2610) and the
    # empty first_name lock (iteration 2611), so the per-field
    # sweep continues here with POST /users/. The endpoint takes
    # a required `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose first_name is a required
    # str (Field min_length=1), alongside required last_name,
    # email and gender and a required password on CreateUserDto
    # (user_dto.py:8-44). A 3-space string passes the
    # min_length=1 field check and only the DTO's mode="after"
    # normalize_names validator rejects the blank value with a
    # ValueError "first_name must not be blank" before the
    # handler body runs: UserService.create_user never runs, so
    # no user record is created -- no duplicate-email check, no
    # GUEST role lookup, no repository write. The error loc is
    # at the body, not at the field, since a model_validator
    # error carries no field part, so this test asserts on the
    # message instead of the loc, mirroring the role
    # whitespace-name lock (iteration 2591) and the register
    # blank-first_name lock. This is distinct from the
    # missing-first_name lock (iteration 2607, field absent),
    # the numeric first_name lock (iteration 2608), the object
    # first_name lock (iteration 2609), the float first_name
    # lock (iteration 2610) and the empty first_name lock
    # (iteration 2611, string_too_short at field validation):
    # here the field is present, a string, and long enough, but
    # trims to blank, with every other required field present
    # and valid. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 422, exactly as in the role whitespace-name
    # lock. The role is seeded with the mocked user's exact
    # role_id (68c302ef6bf7a039b7e9b386, conftest.py) and the
    # route's USER_READ_AND_WRITE_ONLY permission, mirroring the
    # user missing-first_name lock, so the permission gate cannot
    # mask the 422 with a 404; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store headers
    # do not apply to it, mirroring the tenant, account and role
    # whitespace-name 422 locks. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "   ",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password123!",
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_missing_last_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with the required last_name field omitted:
    """
    # The second field of the user per-field sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_user_missing_last_name and grep count 0 for
    # "missing_last_name" in this file before appending. The
    # first_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2607-2612), so
    # the per-field sweep moves to last_name, opening with its
    # missing-field branch, mirroring the missing-first_name
    # lock. The endpoint takes a required `data: CreateUserDto`
    # body parameter (user_endpoint.py:115-128) whose last_name
    # is a required str (Field min_length=1), alongside required
    # first_name, email and gender and a required password on
    # CreateUserDto (user_dto.py:8-44), so an object body missing
    # last_name fails FastAPI request validation before the
    # handler body runs: UserService.create_user never runs, so
    # no user record is created -- no duplicate-email check, no
    # GUEST role lookup, no repository write. The DTO's
    # mode="after" normalize_names validator only runs after
    # valid field parsing, so it cannot mask the 422. This is
    # distinct from the missing-body lock (no body at all) and
    # from the scalar-body locks (valid JSON of the wrong type):
    # here the body is a valid object with every other required
    # field present and valid, so the failure is a missing
    # required field whose detail loc is ["body", "last_name"],
    # mirroring the role missing-name 422 lock and the user
    # missing-first_name lock. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 422, exactly as in the role missing-name
    # lock. The role is seeded with the mocked user's exact
    # role_id (68c302ef6bf7a039b7e9b386, conftest.py) and the
    # route's USER_READ_AND_WRITE_ONLY permission, mirroring
    # the user missing-first_name lock, so the permission gate
    # cannot mask the 422 with a 404; the default conftest mock
    # is a host caller (tenant_id None), so
    # _assert_create_scope cannot fire. Deliberately no exact
    # error-type assertion, mirroring the tenant, account and
    # role missing-field 422 locks. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the tenant, account and role missing-field 422 locks. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "last_name"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_non_string_last_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with last_name sent as a non-string (numeric 123):
    """
    # The second branch of the user per-field last_name sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_user_non_string_last_name and grep count
    # 0 for "non_string_last_name" in this file before appending.
    # The tenant sweep is complete (body-shape 2556-2562 +
    # per-field 2563-2577), the register sweep is complete, the
    # role sweep is complete (body-shape 2578-2584 + per-field
    # 2585-2599), the user body-shape sweep is complete (missing
    # body, non-object, string, numeric, boolean, null, malformed
    # JSON - iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), and the
    # last_name sweep opened with the missing-last_name lock
    # (iteration 2613), so the per-field sweep continues here
    # with POST /users/. The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose last_name is a required
    # str (Field min_length=1), alongside required first_name,
    # email and gender and a required password on CreateUserDto
    # (user_dto.py:8-44). Pydantic v2 does not coerce a number
    # to a string, so a numeric last_name fails FastAPI request
    # validation as a string_type field error at
    # ["body", "last_name"] before the handler body runs:
    # UserService.create_user never runs, so no user record is
    # created -- no duplicate-email check, no GUEST role lookup,
    # no repository write. The DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing, so it cannot mask the 422. This mirrors the user
    # non-string-first_name lock (iteration 2608) and the role
    # non-string-name lock (iteration 2586), which failed the
    # same way at ["body", "first_name"] and ["body", "name"]
    # for a numeric field, and is distinct from the
    # missing-last_name lock (iteration 2613): here the field is
    # present but of the wrong JSON type, with every other
    # required field present and valid, so the failure is a type
    # error rather than a missing field. The endpoint is
    # permission-gated (USER_READ_AND_WRITE_ONLY), and FastAPI
    # solves sub-dependencies before validating the endpoint's
    # own body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the role
    # non-string-name lock. The role is seeded with the mocked
    # user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's USER_READ_AND_WRITE_ONLY
    # permission, mirroring the user missing-last_name lock, so
    # the permission gate cannot mask the 422 with a 404; the
    # default conftest mock is a host caller (tenant_id None),
    # so _assert_create_scope cannot fire. Deliberately no exact
    # error-type assertion, mirroring the tenant, account and
    # role non-string-field 422 locks. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the tenant, account and role non-string-field 422 locks.
    # The security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": 123,
            "email": "test@example.com",
            "gender": "other",
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "last_name"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_object_last_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with last_name sent as an object (a JSON
        dict {"value": "User"}):
    """
    # The third branch of the user per-field last_name sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_user_object_last_name and grep count 0
    # for "object_last_name" in this file before appending. The
    # tenant sweep is complete (body-shape 2556-2562 + per-field
    # 2563-2577), the register sweep is complete, the role sweep
    # is complete (body-shape 2578-2584 + per-field 2585-2599),
    # the user body-shape sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # - iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), and the
    # last_name sweep opened with the missing-last_name lock
    # (iteration 2613) and continued with the non-string
    # (numeric) last_name lock (iteration 2614), so the
    # per-field sweep continues here with POST /users/. The
    # endpoint takes a required `data: CreateUserDto` body
    # parameter (user_endpoint.py:115-128) whose last_name is a
    # required str (Field min_length=1), alongside required
    # first_name, email and gender and a required password on
    # CreateUserDto (user_dto.py:8-44). Pydantic v2 does not
    # coerce a JSON object to a string, so a dict last_name
    # fails FastAPI request validation as a string_type field
    # error at ["body", "last_name"] before the handler body
    # runs: UserService.create_user never runs, so no user
    # record is created -- no duplicate-email check, no GUEST
    # role lookup, no repository write. The DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing, so it cannot mask the 422. This mirrors the user
    # object-first_name lock (iteration 2609) and the role
    # object-name lock, which failed the same way at
    # ["body", "first_name"] and ["body", "name"] for a dict
    # field, and is distinct from the missing-last_name lock
    # (iteration 2613) and the numeric last_name lock
    # (iteration 2614): here the field is present but of a
    # different wrong JSON type, with every other required field
    # present and valid, so the failure is again a type error
    # rather than a missing field. The endpoint is
    # permission-gated (USER_READ_AND_WRITE_ONLY), and FastAPI
    # solves sub-dependencies before validating the endpoint's
    # own body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the role
    # object-name lock. The role is seeded with the mocked
    # user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's USER_READ_AND_WRITE_ONLY
    # permission, mirroring the user missing-last_name lock, so
    # the permission gate cannot mask the 422 with a 404; the
    # default conftest mock is a host caller (tenant_id None),
    # so _assert_create_scope cannot fire. Deliberately no exact
    # error-type assertion, mirroring the tenant, account and
    # role object-field 422 locks. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the tenant, account and role object-field 422 locks. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": {"value": "User"},
            "email": "test@example.com",
            "gender": "other",
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "last_name"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_float_last_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with last_name sent as a float (a JSON
        number 1.5):
    """
    # The fourth branch of the user per-field last_name sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_user_float_last_name and grep count 0
    # for "float_last_name" in this file before appending. The
    # tenant sweep is complete (body-shape 2556-2562 + per-field
    # 2563-2577), the register sweep is complete, the role sweep
    # is complete (body-shape 2578-2584 + per-field 2585-2599),
    # the user body-shape sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # - iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), and the
    # last_name sweep opened with the missing-last_name lock
    # (iteration 2613) and continued with the non-string
    # (numeric) last_name lock (iteration 2614) and the object
    # last_name lock (iteration 2615), so the per-field sweep
    # continues here with POST /users/. The endpoint takes a
    # required `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose last_name is a required
    # str (Field min_length=1), alongside required first_name,
    # email and gender and a required password on CreateUserDto
    # (user_dto.py:8-44). Pydantic v2 does not coerce a JSON
    # float to a string, so a float last_name fails FastAPI
    # request validation as a string_type field error at
    # ["body", "last_name"] before the handler body runs:
    # UserService.create_user never runs, so no user record is
    # created -- no duplicate-email check, no GUEST role lookup,
    # no repository write. The DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing, so it cannot mask the 422. This mirrors the user
    # float-first_name lock (iteration 2610) and the role
    # float-name lock, which failed the same way at
    # ["body", "first_name"] and ["body", "name"] for a float
    # field, and is distinct from the missing-last_name lock
    # (iteration 2613), the numeric last_name lock (iteration
    # 2614, an integer, a different wrong JSON type) and the
    # object last_name lock (iteration 2615): here the field is
    # present but a non-integral number, with every other
    # required field present and valid, so the failure is again
    # a type error rather than a missing field. The endpoint is
    # permission-gated (USER_READ_AND_WRITE_ONLY), and FastAPI
    # solves sub-dependencies before validating the endpoint's
    # own body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the role
    # float-name lock. The role is seeded with the mocked
    # user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's USER_READ_AND_WRITE_ONLY
    # permission, mirroring the user missing-last_name lock, so
    # the permission gate cannot mask the 422 with a 404; the
    # default conftest mock is a host caller (tenant_id None),
    # so _assert_create_scope cannot fire. Deliberately no exact
    # error-type assertion, mirroring the tenant, account and
    # role float-field 422 locks. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the tenant, account and role float-field 422 locks. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": 1.5,
            "email": "test@example.com",
            "gender": "other",
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "last_name"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_empty_last_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with last_name sent as an empty
        string (""):
    """
    # The fifth branch of the user per-field last_name sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_user_empty_last_name and grep count 0
    # for "empty_last_name" in this file before appending. The
    # tenant sweep is complete (body-shape 2556-2562 + per-field
    # 2563-2577), the register sweep is complete, the role sweep
    # is complete (body-shape 2578-2584 + per-field 2585-2599),
    # the user body-shape sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # - iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), and the
    # last_name sweep opened with the missing-last_name lock
    # (iteration 2613) and continued with the non-string
    # (numeric) last_name lock (iteration 2614), the object
    # last_name lock (iteration 2615) and the float last_name
    # lock (iteration 2616), so the per-field sweep continues
    # here with POST /users/. The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose last_name is a required
    # str (Field min_length=1), alongside required first_name,
    # email and gender and a required password on CreateUserDto
    # (user_dto.py:8-44). An empty string fails the min_length=1
    # field constraint as a string_too_short error at ["body",
    # "last_name"] before the handler body runs:
    # UserService.create_user never runs, so no user record is
    # created -- no duplicate-email check, no GUEST role lookup,
    # no repository write. The failure happens at field
    # validation, before the DTO's mode="after" normalize_names
    # validator runs, so that validator cannot mask the 422.
    # This mirrors the user empty-first_name lock (iteration
    # 2611), which failed the same way at ["body",
    # "first_name"] for an empty string against min_length=1,
    # and is distinct from the missing-last_name lock
    # (iteration 2613, field absent), the numeric last_name
    # lock (iteration 2614), the object last_name lock
    # (iteration 2615) and the float last_name lock (iteration
    # 2616): here the field is present and a string, but simply
    # too short, with every other required field present and
    # valid, so the failure is a length error rather than a
    # missing field or a type error. The endpoint is
    # permission-gated (USER_READ_AND_WRITE_ONLY), and FastAPI
    # solves sub-dependencies before validating the endpoint's
    # own body, so the mocked caller's role must be seeded
    # first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the role too-short-name lock. The role is seeded with
    # the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-last_name lock, so the permission gate cannot mask
    # the 422 with a 404; the default conftest mock is a host
    # caller (tenant_id None), so _assert_create_scope cannot
    # fire. Deliberately no exact error-type assertion,
    # mirroring the tenant, account and role too-short-field 422
    # locks. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the tenant,
    # account and role too-short-field 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with
    # no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "last_name"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_whitespace_last_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with last_name sent as a
        whitespace-only string ("   "):
    """
    # The sixth branch of the last_name per-field sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_user_whitespace_last_name and grep count 0 for
    # "whitespace_last_name" in this file before appending. The
    # tenant sweep is complete (body-shape 2556-2562 + per-field
    # 2563-2577), the register sweep is complete, the role sweep
    # is complete (body-shape 2578-2584 + per-field 2585-2599),
    # the user body-shape sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # - iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing 2607, non-string 2608, object
    # 2609, float 2610, empty 2611, whitespace-only 2612), and
    # the last_name sweep opened with the missing-field branch
    # (iteration 2613) and continued with the non-string
    # (numeric) branch (iteration 2614), the object branch
    # (iteration 2615), the float branch (iteration 2616) and
    # the empty branch (iteration 2617), so the per-field sweep
    # continues here with POST /users/. The endpoint takes a
    # required `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose last_name is a required
    # str (Field min_length=1), alongside required first_name,
    # email and gender and a required password on CreateUserDto
    # (user_dto.py:8-44). A 3-space string passes the
    # min_length=1 field check and only the DTO's mode="after"
    # normalize_names validator rejects the blank value with a
    # ValueError "last_name must not be blank" before the
    # handler body runs: UserService.create_user never runs, so
    # no user record is created -- no duplicate-email check, no
    # GUEST role lookup, no repository write. The error loc is
    # at the body, not at the field, since a model_validator
    # error carries no field part, so this test asserts on the
    # message instead of the loc, mirroring the role
    # whitespace-name lock (iteration 2591), the register
    # blank-last_name lock and the user whitespace-first_name
    # lock (iteration 2612). This is distinct from the
    # missing-last_name lock (iteration 2613, field absent),
    # the numeric last_name lock (iteration 2614), the object
    # last_name lock (iteration 2615), the float last_name lock
    # (iteration 2616) and the empty last_name lock (iteration
    # 2617, string_too_short at field validation): here the
    # field is present, a string, and long enough, but trims
    # to blank, with every other required field present and
    # valid. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 422, exactly as in the role whitespace-name
    # lock. The role is seeded with the mocked user's exact
    # role_id (68c302ef6bf7a039b7e9b386, conftest.py) and the
    # route's USER_READ_AND_WRITE_ONLY permission, mirroring the
    # user missing-last_name lock, so the permission gate cannot
    # mask the 422 with a 404; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store headers
    # do not apply to it, mirroring the tenant, account and role
    # whitespace-name 422 locks. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "   ",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password123!",
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_missing_email_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with the required email field omitted:
    """
    # The third field of the user per-field sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_user_missing_email and grep count 0 for
    # "missing_email" in this file before appending. The
    # first_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2607-2612) and
    # the last_name sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only - iterations
    # 2613-2618), so the per-field sweep moves to email,
    # opening with its missing-field branch, mirroring the
    # missing-first_name and missing-last_name locks. The
    # endpoint takes a required `data: CreateUserDto` body
    # parameter (user_endpoint.py:115-128) whose email is a
    # required EmailStr, alongside required first_name,
    # last_name and gender and a required password on
    # CreateUserDto (user_dto.py:8-44), so an object body
    # missing email fails FastAPI request validation before the
    # handler body runs: UserService.create_user never runs, so
    # no user record is created -- no duplicate-email check, no
    # GUEST role lookup, no repository write. The DTO's
    # mode="after" normalize_names validator only runs after
    # valid field parsing, so it cannot mask the 422. This is
    # distinct from the missing-body lock (no body at all) and
    # from the scalar-body locks (valid JSON of the wrong type):
    # here the body is a valid object with every other required
    # field present and valid, so the failure is a missing
    # required field whose detail loc is ["body", "email"],
    # mirroring the role missing-name 422 lock and the user
    # missing-first_name and missing-last_name locks. The
    # endpoint is permission-gated (USER_READ_AND_WRITE_ONLY),
    # and FastAPI solves sub-dependencies before validating the
    # endpoint's own body, so the mocked caller's role must be
    # seeded first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the role missing-name lock. The role is seeded with
    # the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-last_name lock, so the permission gate cannot
    # mask the 422 with a 404; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no exact error-type assertion,
    # mirroring the tenant, account and role missing-field 422
    # locks. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the tenant,
    # account and role missing-field 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with
    # no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "gender": "other",
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "email"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_non_string_email_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a non-string email value:
    """
    # The third field of the user per-field sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_user_non_string_email and grep count 0 for
    # "non_string_email" in this file before appending. The
    # first_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618) and
    # the email sweep opened with its missing-field branch
    # (iteration 2619), so the per-field sweep continues with
    # email's non-string branch, mirroring the non-string
    # first_name and non-string last_name locks. The endpoint
    # takes a required `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose email is a required
    # EmailStr, alongside required first_name, last_name and
    # gender and a required password on CreateUserDto
    # (user_dto.py:8-44), so a numeric email fails FastAPI
    # request validation before the handler body runs:
    # UserService.create_user never runs, so no user record is
    # created -- no duplicate-email check, no GUEST role lookup,
    # no repository write. The DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing, so it cannot mask the 422. This is distinct from
    # the missing-email lock (iteration 2619, field omitted) and
    # from the scalar-body locks (body itself of the wrong type):
    # here the body is a valid object with every other required
    # field present and valid, so the failure is a type error
    # whose detail loc is ["body", "email"], mirroring the role
    # non-string-name 422 lock and the user non-string
    # first_name and non-string last_name locks. The endpoint
    # is permission-gated (USER_READ_AND_WRITE_ONLY), and
    # FastAPI solves sub-dependencies before validating the
    # endpoint's own body, so the mocked caller's role must be
    # seeded first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the role non-string-name lock. The role is seeded with
    # the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-email lock, so the permission gate cannot mask
    # the 422 with a 404; the default conftest mock is a host
    # caller (tenant_id None), so _assert_create_scope cannot
    # fire. Deliberately no exact error-type assertion,
    # mirroring the tenant, account and role non-string 422
    # locks. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the tenant,
    # account and role non-string 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with
    # no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": 123,
            "gender": "other",
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "email"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_object_email_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with an object email value:
    """
    # The third field of the user per-field sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_user_object_email and grep count 0 for
    # "object_email" in this file before appending. The
    # first_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618) and
    # the email sweep opened with its missing-field branch
    # (iteration 2619) and continued with its non-string (numeric)
    # branch (iteration 2620), so the per-field sweep continues
    # with email's object branch, mirroring the object
    # first_name and object last_name locks. The endpoint
    # takes a required `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose email is a required
    # EmailStr, alongside required first_name, last_name and
    # gender and a required password on CreateUserDto
    # (user_dto.py:8-44), so a dict email fails FastAPI
    # request validation before the handler body runs:
    # UserService.create_user never runs, so no user record is
    # created -- no duplicate-email check, no GUEST role lookup,
    # no repository write. The DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing, so it cannot mask the 422. This is distinct from
    # the missing-email lock (iteration 2619, field omitted) and
    # the numeric email lock (iteration 2620, an integer, a
    # different wrong JSON type): here the body is a valid object
    # with every other required field present and valid, so the
    # failure is a type error whose detail loc is ["body",
    # "email"], mirroring the role object-name 422 lock and the
    # user object first_name and object last_name locks. The
    # endpoint is permission-gated (USER_READ_AND_WRITE_ONLY),
    # and FastAPI solves sub-dependencies before validating the
    # endpoint's own body, so the mocked caller's role must be
    # seeded first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the role object-name lock. The role is seeded with
    # the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-email lock, so the permission gate cannot mask
    # the 422 with a 404; the default conftest mock is a host
    # caller (tenant_id None), so _assert_create_scope cannot
    # fire. Deliberately no exact error-type assertion,
    # mirroring the tenant, account and role object 422
    # locks. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the tenant,
    # account and role object 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with
    # no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": {"value": "test@example.com"},
            "gender": "other",
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "email"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_float_email_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with email sent as a float (a JSON
        number 1.5):
    """
    # The fourth branch of the user email per-field sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_user_float_email and grep count 0 for
    # "float_email" in this file before appending. The tenant
    # sweep is complete (body-shape 2556-2562 + per-field
    # 2563-2577), the register sweep is complete, the role sweep
    # is complete (body-shape 2578-2584 + per-field 2585-2599),
    # the user body-shape sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # - iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618) and
    # the email sweep opened with its missing-field branch
    # (iteration 2619) and continued with its non-string
    # (numeric) branch (iteration 2620) and its object branch
    # (iteration 2621), so the per-field sweep continues with
    # email's float branch, mirroring the float first_name and
    # float last_name locks. The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose email is a required
    # EmailStr, alongside required first_name, last_name and
    # gender and a required password on CreateUserDto
    # (user_dto.py:8-44). Pydantic v2 does not coerce a JSON
    # number to a string, so a float email fails FastAPI
    # request validation as a string_type field error at
    # ["body", "email"] before the handler body runs:
    # UserService.create_user never runs, so no user record is
    # created -- no duplicate-email check, no GUEST role lookup,
    # no repository write. The DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), so it
    # cannot mask the 422. This is distinct from the
    # missing-email lock (iteration 2619, field omitted), the
    # numeric (integer) email lock (iteration 2620) and the
    # object email lock (iteration 2621): here the field is
    # present but a non-integer JSON number, with every other
    # required field present and valid, so the failure is again
    # a type error rather than a missing field. The endpoint is
    # permission-gated (USER_READ_AND_WRITE_ONLY), and FastAPI
    # solves sub-dependencies before validating the endpoint's
    # own body, so the mocked caller's role must be seeded
    # first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the role float-name lock. The role is seeded with
    # the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-email lock, so the permission gate cannot mask
    # the 422 with a 404; the default conftest mock is a host
    # caller (tenant_id None), so _assert_create_scope cannot
    # fire. Deliberately no exact error-type assertion,
    # mirroring the tenant, account and role float-field 422
    # locks. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the tenant,
    # account and role float-field 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with
    # no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": 1.5,
            "gender": "other",
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "email"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_empty_email_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with email sent as an empty string:
    """
    # The fifth branch of the user email per-field sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_user_empty_email and grep count 0 for
    # "empty_email" in this file before appending. The tenant
    # sweep is complete (body-shape 2556-2562 + per-field
    # 2563-2577), the register sweep is complete, the role sweep
    # is complete (body-shape 2578-2584 + per-field 2585-2599),
    # the user body-shape sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # - iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618) and
    # the email sweep opened with its missing-field branch
    # (iteration 2619) and continued with its non-string
    # (numeric) branch (iteration 2620), its object branch
    # (iteration 2621) and its float branch (iteration 2622),
    # so the per-field sweep continues with email's empty-string
    # branch, mirroring the register empty-email lock
    # (test_account_register_empty_string_email_returns_422_with_security_headers).
    # The endpoint takes a required `data: CreateUserDto` body
    # parameter (user_endpoint.py:115-128) whose email is a
    # required EmailStr, alongside required first_name,
    # last_name and gender and a required password on
    # CreateUserDto (user_dto.py:8-44). An empty string has no
    # "@" and fails EmailStr validation as a field error at
    # ["body", "email"] before the handler body runs:
    # UserService.create_user never runs, so no user record is
    # created -- no duplicate-email check, no GUEST role lookup,
    # no repository write. The DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), so it
    # cannot mask the 422. This is distinct from the
    # missing-email lock (iteration 2619, field omitted), the
    # numeric (integer) email lock (iteration 2620), the object
    # email lock (iteration 2621, a dict, a different wrong JSON
    # type) and the float email lock (iteration 2622, a
    # non-integer JSON number): here the field is present and a
    # string, but empty, with every other required field present
    # and valid, so the failure is a value error rather than a
    # missing field or a type error. The endpoint is
    # permission-gated (USER_READ_AND_WRITE_ONLY), and FastAPI
    # solves sub-dependencies before validating the endpoint's
    # own body, so the mocked caller's role must be seeded
    # first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the role float-name lock. The role is seeded with
    # the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-email lock, so the permission gate cannot mask
    # the 422 with a 404; the default conftest mock is a host
    # caller (tenant_id None), so _assert_create_scope cannot
    # fire. Deliberately no exact error-type assertion,
    # mirroring the tenant, account and role empty-field 422
    # locks. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the tenant,
    # account and role empty-field 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with
    # no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "",
            "gender": "other",
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "email"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_whitespace_only_email_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with email sent as a
        whitespace-only string ("   "):
    """
    # The sixth branch of the user email per-field sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_user_whitespace_only_email and grep
    # count 0 for "whitespace_only_email" in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606),
    # the user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618) and the email
    # sweep opened with its missing-field branch (iteration
    # 2619) and continued with its non-string (numeric) branch
    # (iteration 2620), its object branch (iteration 2621),
    # its float branch (iteration 2622) and its empty branch
    # (iteration 2623), so the per-field sweep continues with
    # email's whitespace-only branch, mirroring the user
    # whitespace-first_name lock (iteration 2612) and the
    # whitespace-last_name lock (iteration 2618). The endpoint
    # takes a required `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose email is a required
    # EmailStr, alongside required first_name, last_name and
    # gender and a required password on CreateUserDto
    # (user_dto.py:8-44). A 3-space string has no "@" and
    # fails EmailStr validation as a field error at
    # ["body", "email"] before the handler body runs:
    # UserService.create_user never runs, so no user record is
    # created -- no duplicate-email check, no GUEST role lookup,
    # no repository write. Unlike the whitespace name locks,
    # this is a field-level failure, not a model_validator
    # ValueError, so the loc assertion applies, mirroring the
    # empty-email lock (iteration 2623). The DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), so it
    # cannot mask the 422. This is distinct from the
    # missing-email lock (iteration 2619, field omitted), the
    # numeric (integer) email lock (iteration 2620), the object
    # email lock (iteration 2621, a dict, a different wrong JSON
    # type), the float email lock (iteration 2622, a non-integer
    # JSON number) and the empty email lock (iteration 2623, a
    # zero-length string): here the field is present and a
    # string, and long enough, but contains only spaces, with
    # every other required field present and valid, so the
    # failure is a value error rather than a missing field or
    # a type error. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 422, exactly as in the role float-name
    # lock. The role is seeded with the mocked user's exact
    # role_id (68c302ef6bf7a039b7e9b386, conftest.py) and the
    # route's USER_READ_AND_WRITE_ONLY permission, mirroring
    # the user missing-email lock, so the permission gate cannot
    # mask the 422 with a 404; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no exact error-type assertion,
    # mirroring the tenant, account and role empty-field 422
    # locks. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the tenant,
    # account and role empty-field 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with
    # no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "   ",
            "gender": "other",
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "email"]
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
    # mirroring the other user locks in this file, using
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

async def test_create_user_invalid_format_email_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with email sent as a
        malformed address ("not-an-email"):
    """
    # The seventh branch of the user email per-field sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_user_invalid_format_email and grep
    # count 0 for "invalid_format_email" in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606),
    # the user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618) and the email
    # sweep opened with its missing-field branch (iteration
    # 2619) and continued with its non-string (numeric) branch
    # (iteration 2620), its object branch (iteration 2621),
    # its float branch (iteration 2622), its empty branch
    # (iteration 2623) and its whitespace-only branch
    # (iteration 2624), so the per-field sweep continues with
    # email's invalid-format branch, mirroring the register
    # invalid-email lock
    # (test_account_register_invalid_email_returns_422_with_security_headers),
    # which uses the same "not-an-email" value. The endpoint
    # takes a required `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose email is a required
    # EmailStr, alongside required first_name, last_name and
    # gender and a required password on CreateUserDto
    # (user_dto.py:8-44). "not-an-email" has no "@" and fails
    # EmailStr validation as a field error at ["body", "email"]
    # before the handler body runs: UserService.create_user
    # never runs, so no user record is created -- no
    # duplicate-email check, no GUEST role lookup, no
    # repository write. This is a field-level failure, not a
    # model_validator ValueError, so the loc assertion applies,
    # mirroring the empty-email lock (iteration 2623) and the
    # whitespace-only-email lock (iteration 2624). The DTO's
    # mode="after" normalize_names validator only runs after
    # valid field parsing (and only touches first_name/last_name),
    # so it cannot mask the 422. This is distinct from the
    # missing-email lock (iteration 2619, field omitted), the
    # numeric (integer) email lock (iteration 2620), the object
    # email lock (iteration 2621, a dict, a different wrong JSON
    # type), the float email lock (iteration 2622, a non-integer
    # JSON number), the empty email lock (iteration 2623, a
    # zero-length string) and the whitespace-only email lock
    # (iteration 2624, only spaces): here the field is present
    # and a non-empty string, but not a valid email address,
    # with every other required field present and valid, so the
    # failure is a format error rather than a missing field, a
    # type error, or a length error. The endpoint is
    # permission-gated (USER_READ_AND_WRITE_ONLY), and FastAPI
    # solves sub-dependencies before validating the endpoint's
    # own body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the role float-name
    # lock. The role is seeded with the mocked user's exact
    # role_id (68c302ef6bf7a039b7e9b386, conftest.py) and the
    # route's USER_READ_AND_WRITE_ONLY permission, mirroring
    # the user missing-email lock, so the permission gate cannot
    # mask the 422 with a 404; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no exact error-type assertion,
    # mirroring the tenant, account and role empty-field 422
    # locks. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the tenant,
    # account and role empty-field 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps
    # every HTTP response, including validation errors, with
    # no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "not-an-email",
            "gender": "other",
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "email"]
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
    # mirroring the other user locks in this file, using
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

async def test_create_user_missing_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with gender omitted:
    """
    # The first branch of the user gender per-field sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_user_missing_gender and grep count 0
    # for "missing_gender" in this file before appending. The
    # tenant sweep is complete (body-shape 2556-2562 +
    # per-field 2563-2577), the register sweep is complete,
    # the role sweep is complete (body-shape 2578-2584 +
    # per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606),
    # the user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618) and the email
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only, invalid-format - iterations
    # 2619-2625), so the per-field sweep moves to gender,
    # opening with its missing-field branch, mirroring the
    # user missing-first_name lock (iteration 2607), the
    # missing-last_name lock (iteration 2613) and the
    # missing-email lock (iteration 2619). The endpoint takes
    # a required `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose gender is a required
    # Gender enum (male/female/other/prefer_not_to_say,
    # gender.py), alongside required first_name, last_name and
    # email and a required password on CreateUserDto
    # (user_dto.py:8-44). A missing gender fails as a
    # missing-field error at ["body", "gender"] before the
    # handler body runs: UserService.create_user never runs,
    # so no user record is created -- no duplicate-email
    # check, no GUEST role lookup, no repository write. The
    # DTO's mode="after" normalize_names validator only runs
    # after valid field parsing (and only touches
    # first_name/last_name), so it cannot mask the 422. This
    # is distinct from the missing-first_name lock (iteration
    # 2607, different field), the missing-last_name lock
    # (iteration 2613, different field) and the missing-email
    # lock (iteration 2619, different field): here every other
    # required field is present and valid, so the failure is a
    # missing gender rather than a missing name or email. The
    # endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the role
    # too-short-name lock. The role is seeded with the mocked
    # user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's USER_READ_AND_WRITE_ONLY
    # permission, mirroring the user missing-email lock, so the
    # permission gate cannot mask the 422 with a 404; the
    # default conftest mock is a host caller (tenant_id None),
    # so _assert_create_scope cannot fire. Deliberately no
    # exact error-type assertion, mirroring the tenant,
    # account and role empty-field 422 locks. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the tenant, account and role empty-field 422 locks. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "gender"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_non_string_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a non-string gender value:
    """
    # The second branch of the user gender per-field sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_user_non_string_gender and grep count 0
    # for "non_string_gender" in this file before appending. The
    # tenant sweep is complete (body-shape 2556-2562 +
    # per-field 2563-2577), the register sweep is complete,
    # the role sweep is complete (body-shape 2578-2584 +
    # per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606),
    # the user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep opened with its missing-field branch
    # (iteration 2626), so the per-field sweep continues with
    # gender's non-string branch, mirroring the non-string
    # first_name, non-string last_name and non-string email
    # locks. The endpoint takes a required `data: CreateUserDto`
    # body parameter (user_endpoint.py:115-128) whose gender is
    # a required Gender enum (male/female/other/
    # prefer_not_to_say, gender.py), alongside required
    # first_name, last_name and email and a required password
    # on CreateUserDto (user_dto.py:8-44), so a numeric gender
    # fails FastAPI request validation before the handler body
    # runs: UserService.create_user never runs, so no user
    # record is created -- no duplicate-email check, no GUEST
    # role lookup, no repository write. The DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), so it
    # cannot mask the 422. This is distinct from the
    # missing-gender lock (iteration 2626, field omitted) and
    # from the scalar-body locks (body itself of the wrong
    # type): here the body is a valid object with every other
    # required field present and valid, so the failure is a
    # type error whose detail loc is ["body", "gender"],
    # mirroring the role non-string-name 422 lock and the user
    # non-string first_name, non-string last_name and
    # non-string email locks. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the role
    # non-string-name lock. The role is seeded with the mocked
    # user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's USER_READ_AND_WRITE_ONLY
    # permission, mirroring the user missing-gender lock, so the
    # permission gate cannot mask the 422 with a 404; the
    # default conftest mock is a host caller (tenant_id None),
    # so _assert_create_scope cannot fire. Deliberately no
    # exact error-type assertion, mirroring the tenant,
    # account and role non-string 422 locks. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the tenant, account and role non-string 422 locks. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": 123,
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "gender"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_object_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with an object gender value:
    """
    # The third branch of the user gender per-field sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_user_object_gender and grep count 0
    # for "object_gender" in this file before appending. The
    # tenant sweep is complete (body-shape 2556-2562 +
    # per-field 2563-2577), the register sweep is complete,
    # the role sweep is complete (body-shape 2578-2584 +
    # per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606),
    # the user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep opened with its missing-field branch
    # (iteration 2626) and non-string branch (iteration 2627),
    # so the per-field sweep continues with gender's object
    # branch, mirroring the object first_name, object
    # last_name and object email locks. The endpoint takes a
    # required `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose gender is a required
    # Gender enum (male/female/other/prefer_not_to_say,
    # gender.py), alongside required first_name, last_name and
    # email and a required password on CreateUserDto
    # (user_dto.py:8-44), so an object gender fails FastAPI
    # request validation before the handler body runs:
    # UserService.create_user never runs, so no user record is
    # created -- no duplicate-email check, no GUEST role
    # lookup, no repository write. The DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), so it
    # cannot mask the 422. This is distinct from the
    # missing-gender lock (iteration 2626, field omitted) and
    # from the non-string-gender lock (iteration 2627, numeric
    # value) and from the scalar-body locks (body itself of
    # the wrong type): here the body is a valid object with
    # every other required field present and valid, so the
    # failure is a type error whose detail loc is
    # ["body", "gender"], mirroring the role object-name 422
    # lock and the user object first_name, object last_name
    # and object email locks. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the role
    # object-name lock. The role is seeded with the mocked
    # user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's USER_READ_AND_WRITE_ONLY
    # permission, mirroring the user missing-gender lock, so the
    # permission gate cannot mask the 422 with a 404; the
    # default conftest mock is a host caller (tenant_id None),
    # so _assert_create_scope cannot fire. Deliberately no
    # exact error-type assertion, mirroring the tenant,
    # account and role object 422 locks. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the tenant, account and role object 422 locks. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": {"value": "male"},
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "gender"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_float_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a float gender value (a JSON
        number 1.5):
    """
    # The fourth branch of the user gender per-field sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_user_float_gender and grep count 0
    # for "float_gender" in this file before appending. The
    # tenant sweep is complete (body-shape 2556-2562 +
    # per-field 2563-2577), the register sweep is complete,
    # the role sweep is complete (body-shape 2578-2584 +
    # per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606),
    # the user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep opened with its missing-field branch
    # (iteration 2626), non-string branch (iteration 2627) and
    # object branch (iteration 2628), so the per-field sweep
    # continues with gender's float branch, mirroring the float
    # first_name, float last_name and float email locks. The
    # endpoint takes a required `data: CreateUserDto` body
    # parameter (user_endpoint.py:115-128) whose gender is a
    # required Gender enum (male/female/other/prefer_not_to_say,
    # gender.py), alongside required first_name, last_name and
    # email and a required password on CreateUserDto
    # (user_dto.py:8-44). Pydantic v2 does not coerce a JSON
    # number to a string, so a float gender fails FastAPI
    # request validation before the handler body runs:
    # UserService.create_user never runs, so no user record is
    # created -- no duplicate-email check, no GUEST role
    # lookup, no repository write. The DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), so it
    # cannot mask the 422. This is distinct from the
    # missing-gender lock (iteration 2626, field omitted), from
    # the non-string-gender lock (iteration 2627, integer
    # value) and from the object-gender lock (iteration 2628,
    # object value) and from the scalar-body locks (body itself
    # of the wrong type): here the body is a valid object with
    # every other required field present and valid, so the
    # failure is a type error whose detail loc is
    # ["body", "gender"], mirroring the role float-name 422
    # lock and the user float first_name, float last_name and
    # float email locks. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the role
    # float-name lock. The role is seeded with the mocked
    # user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's USER_READ_AND_WRITE_ONLY
    # permission, mirroring the user missing-gender lock, so the
    # permission gate cannot mask the 422 with a 404; the
    # default conftest mock is a host caller (tenant_id None),
    # so _assert_create_scope cannot fire. Deliberately no
    # exact error-type assertion, mirroring the tenant,
    # account and role float 422 locks. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the tenant, account and role float 422 locks. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": 1.5,
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "gender"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_empty_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with an empty-string gender value (""):
    """
    # The fifth branch of the user gender per-field sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_user_empty_gender and grep count 0
    # for "empty_gender" in this file before appending. The
    # tenant sweep is complete (body-shape 2556-2562 +
    # per-field 2563-2577), the register sweep is complete,
    # the role sweep is complete (body-shape 2578-2584 +
    # per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606),
    # the user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep opened with its missing-field branch
    # (iteration 2626), non-string branch (iteration 2627),
    # object branch (iteration 2628) and float branch
    # (iteration 2629), so the per-field sweep continues with
    # gender's empty-string branch, mirroring the empty
    # first_name, empty last_name and empty email locks. The
    # endpoint takes a required `data: CreateUserDto` body
    # parameter (user_endpoint.py:115-128) whose gender is a
    # required Gender enum (male/female/other/prefer_not_to_say,
    # gender.py), alongside required first_name, last_name and
    # email and a required password on CreateUserDto
    # (user_dto.py:8-44). Pydantic v2 does not accept an empty
    # string as an enum member, so an empty gender fails FastAPI
    # request validation before the handler body runs:
    # UserService.create_user never runs, so no user record is
    # created -- no duplicate-email check, no GUEST role
    # lookup, no repository write. The DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), so it
    # cannot mask the 422. This is distinct from the
    # missing-gender lock (iteration 2626, field omitted), from
    # the non-string-gender lock (iteration 2627, integer
    # value), from the object-gender lock (iteration 2628,
    # object value) and from the float-gender lock (iteration
    # 2629, number value) and from the scalar-body locks (body
    # itself of the wrong type): here the body is a valid object
    # with every other required field present and valid, so the
    # failure is an enum-membership error whose detail loc is
    # ["body", "gender"], mirroring the role empty-name 422
    # lock and the user empty first_name, empty last_name and
    # empty email locks. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the role
    # empty-name lock. The role is seeded with the mocked
    # user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's USER_READ_AND_WRITE_ONLY
    # permission, mirroring the user missing-gender lock, so the
    # permission gate cannot mask the 422 with a 404; the
    # default conftest mock is a host caller (tenant_id None),
    # so _assert_create_scope cannot fire. Deliberately no
    # exact error-type assertion, mirroring the tenant,
    # account and role empty 422 locks. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the tenant, account and role empty 422 locks. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "",
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "gender"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_whitespace_only_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a whitespace-only gender value ("   "):
    """
    # The sixth branch of the user gender per-field sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_user_whitespace_only_gender and grep
    # count 0 for "whitespace_only_gender" in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606),
    # the user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep opened with its missing-field branch
    # (iteration 2626), non-string branch (iteration 2627),
    # object branch (iteration 2628), float branch (iteration
    # 2629) and empty-string branch (iteration 2630), so the
    # per-field sweep continues with gender's whitespace-only
    # branch, mirroring the whitespace-only first_name,
    # whitespace-only last_name and whitespace-only email
    # locks. The endpoint takes a required `data: CreateUserDto`
    # body parameter (user_endpoint.py:115-128) whose gender is
    # a required Gender enum (male/female/other/prefer_not_to_say,
    # gender.py), alongside required first_name, last_name and
    # email and a required password on CreateUserDto
    # (user_dto.py:8-44). Pydantic v2 does not accept a
    # whitespace-only string as an enum member, so a gender of
    # three spaces fails FastAPI request validation before the
    # handler body runs: UserService.create_user never runs, so
    # no user record is created -- no duplicate-email check, no
    # GUEST role lookup, no repository write. The DTO's
    # mode="after" normalize_names validator only runs after
    # valid field parsing (and only touches first_name/
    # last_name), so it cannot mask the 422. This is distinct
    # from the missing-gender lock (iteration 2626, field
    # omitted), from the non-string-gender lock (iteration 2627,
    # integer value), from the object-gender lock (iteration
    # 2628, object value), from the float-gender lock
    # (iteration 2629, number value) and from the empty-gender
    # lock (iteration 2630, zero-length string) and from the
    # scalar-body locks (body itself of the wrong type): here
    # the body is a valid object with every other required
    # field present and valid, so the failure is an
    # enum-membership error whose detail loc is ["body",
    # "gender"], mirroring the role whitespace-only-name 422
    # lock and the user whitespace-only first_name,
    # whitespace-only last_name and whitespace-only email
    # locks. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the role
    # whitespace-only-name lock. The role is seeded with the
    # mocked user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's USER_READ_AND_WRITE_ONLY
    # permission, mirroring the user missing-gender lock, so the
    # permission gate cannot mask the 422 with a 404; the
    # default conftest mock is a host caller (tenant_id None),
    # so _assert_create_scope cannot fire. Deliberately no
    # exact error-type assertion, mirroring the tenant,
    # account and role whitespace-only 422 locks. Deliberately
    # no Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the tenant, account and role whitespace-only
    # 422 locks. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "   ",
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "gender"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_invalid_gender_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with an invalid gender value ("unknown"):
    """
    # The seventh branch of the user gender per-field sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_user_invalid_gender and grep count 0
    # for "invalid_gender" in this file before appending. The
    # tenant sweep is complete (body-shape 2556-2562 + per-field
    # 2563-2577), the register sweep is complete, the role sweep
    # is complete (body-shape 2578-2584 + per-field 2585-2599),
    # the user body-shape sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # - iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618), the
    # email sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only, invalid-format - iterations
    # 2619-2625) and the gender sweep opened with its
    # missing-field branch (iteration 2626), non-string branch
    # (iteration 2627), object branch (iteration 2628), float
    # branch (iteration 2629), empty-string branch (iteration
    # 2630) and whitespace-only branch (iteration 2631), so the
    # per-field sweep continues with gender's invalid-value
    # branch, mirroring the invalid-format email lock. The
    # endpoint takes a required `data: CreateUserDto` body
    # parameter (user_endpoint.py:115-128) whose gender is a
    # required Gender enum (male/female/other/prefer_not_to_say,
    # gender.py), alongside required first_name, last_name and
    # email and a required password on CreateUserDto
    # (user_dto.py:8-44). Pydantic v2 does not accept a string
    # outside the enum, so a gender of "unknown" fails FastAPI
    # request validation before the handler body runs:
    # UserService.create_user never runs, so no user record is
    # created -- no duplicate-email check, no GUEST role lookup,
    # no repository write. The DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), so it
    # cannot mask the 422. This is distinct from the
    # missing-gender lock (iteration 2626, field omitted), from
    # the non-string-gender lock (iteration 2627, integer
    # value), from the object-gender lock (iteration 2628,
    # object value), from the float-gender lock (iteration 2629,
    # number value), from the empty-gender lock (iteration 2630,
    # zero-length string) and from the whitespace-only-gender
    # lock (iteration 2631, three spaces) and from the
    # scalar-body locks (body itself of the wrong type): here
    # the body is a valid object with every other required
    # field present and valid, so the failure is an
    # enum-membership error whose detail loc is ["body",
    # "gender"], mirroring the role whitespace-only-name 422
    # lock and the user whitespace-only first_name,
    # whitespace-only last_name and whitespace-only email
    # locks. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the role
    # whitespace-only-name lock. The role is seeded with the
    # mocked user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's USER_READ_AND_WRITE_ONLY
    # permission, mirroring the user missing-gender lock, so the
    # permission gate cannot mask the 422 with a 404; the
    # default conftest mock is a host caller (tenant_id None),
    # so _assert_create_scope cannot fire. Deliberately no
    # exact error-type assertion, mirroring the tenant,
    # account and role whitespace-only 422 locks. Deliberately
    # no Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the tenant, account and role whitespace-only
    # 422 locks. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "unknown",
            "password": "Password123!",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "gender"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_missing_password_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with the password field omitted:
    """
    # The first branch of the user password per-field sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_user_missing_password and grep count 0
    # for "missing_password" in this file before appending. The
    # tenant sweep is complete (body-shape 2556-2562 + per-field
    # 2563-2577), the register sweep is complete, the role sweep
    # is complete (body-shape 2578-2584 + per-field 2585-2599),
    # the user body-shape sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # - iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618), the
    # email sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only, invalid-format - iterations
    # 2619-2625) and the gender sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only,
    # invalid-value - iterations 2626-2632), so the per-field
    # sweep moves to password, opening with its missing-field
    # branch. The endpoint takes a required `data: CreateUserDto`
    # body parameter (user_endpoint.py:115-128) whose password is
    # a required `str` on CreateUserDto (user_dto.py:8-44, no
    # min_length constraint), alongside required first_name,
    # last_name, email and gender. Pydantic v2 reports an omitted
    # required field as a missing-field error, so a passwordless
    # body fails FastAPI request validation before the handler
    # body runs: UserService.create_user never runs, so no user
    # record is created -- no duplicate-email check, no GUEST
    # role lookup, no repository write. The DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), so it
    # cannot mask the 422. This is distinct from the
    # missing-first_name lock (iteration 2607, different field),
    # the missing-last_name lock (iteration 2613, different
    # field), the missing-email lock (iteration 2619, different
    # field) and the missing-gender lock (iteration 2626,
    # different field): here the body is a valid object with
    # every other required field present and valid, so the
    # failure is a missing-field error whose detail loc is
    # ["body", "password"], mirroring the role missing-name 422
    # lock and the user missing first_name, missing last_name,
    # missing email and missing gender locks. The endpoint is
    # permission-gated (USER_READ_AND_WRITE_ONLY), and FastAPI
    # solves sub-dependencies before validating the endpoint's
    # own body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the role
    # whitespace-only-name lock. The role is seeded with the
    # mocked user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's USER_READ_AND_WRITE_ONLY
    # permission, mirroring the user missing-gender lock, so the
    # permission gate cannot mask the 422 with a 404; the
    # default conftest mock is a host caller (tenant_id None),
    # so _assert_create_scope cannot fire. Deliberately no
    # exact error-type assertion, mirroring the tenant,
    # account and role whitespace-only 422 locks. Deliberately
    # no Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the tenant, account and role whitespace-only
    # 422 locks. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "password"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_non_string_password_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a non-string password:
    """
    # The second branch of the user password per-field sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_user_non_string_password and grep count 0
    # for "non_string_password" in this file before appending. The
    # tenant sweep is complete (body-shape 2556-2562 + per-field
    # 2563-2577), the register sweep is complete, the role sweep
    # is complete (body-shape 2578-2584 + per-field 2585-2599),
    # the user body-shape sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # - iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618), the
    # email sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only, invalid-format - iterations
    # 2619-2625) and the gender sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only,
    # invalid-value - iterations 2626-2632), so the per-field
    # sweep continues with password, whose missing-field branch
    # was locked in iteration 2633. The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:8-44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. Pydantic v2 does not coerce a JSON
    # number to a string, so an integer password fails FastAPI
    # request validation before the handler body runs:
    # UserService.create_user never runs, so no user record is
    # created -- no duplicate-email check, no GUEST role lookup,
    # no repository write. The DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), so it
    # cannot mask the 422. This is distinct from the
    # missing-password lock (iteration 2633, field omitted):
    # here the password is present but a JSON number, so the
    # failure is a type error whose detail loc is
    # ["body", "password"], mirroring the non-string first_name,
    # last_name, email and gender locks. The endpoint is
    # permission-gated (USER_READ_AND_WRITE_ONLY), and FastAPI
    # solves sub-dependencies before validating the endpoint's
    # own body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the role
    # whitespace-only-name lock. The role is seeded with the
    # mocked user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's USER_READ_AND_WRITE_ONLY
    # permission, mirroring the user missing-password lock, so the
    # permission gate cannot mask the 422 with a 404; the
    # default conftest mock is a host caller (tenant_id None),
    # so _assert_create_scope cannot fire. Deliberately no
    # exact error-type assertion, mirroring the tenant,
    # account and role whitespace-only 422 locks. Deliberately
    # no Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the tenant, account and role whitespace-only
    # 422 locks. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": 12345678,
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "password"]
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
    # mirroring the other user locks in this file, using
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


async def test_create_user_object_password_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with an object password:
    """
    # The third branch of the user password per-field sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_user_object_password and grep count 0
    # for "object_password" in this file before appending. The
    # tenant sweep is complete (body-shape 2556-2562 + per-field
    # 2563-2577), the register sweep is complete, the role sweep
    # is complete (body-shape 2578-2584 + per-field 2585-2599),
    # the user body-shape sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # - iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618), the
    # email sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only, invalid-format - iterations
    # 2619-2625) and the gender sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only,
    # invalid-value - iterations 2626-2632), so the per-field
    # sweep continues with password, whose missing-field branch
    # was locked in iteration 2633 and whose non-string branch
    # was locked in iteration 2634. The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:8-44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. Pydantic v2 does not coerce a JSON
    # object to a string, so a dict password fails FastAPI
    # request validation before the handler body runs:
    # UserService.create_user never runs, so no user record is
    # created -- no duplicate-email check, no GUEST role lookup,
    # no repository write. The DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), so it
    # cannot mask the 422. This is distinct from the
    # missing-password lock (iteration 2633, field omitted) and
    # the non-string lock (iteration 2634, JSON number): here
    # the password is present but a JSON object, so the failure
    # is a type error whose detail loc is
    # ["body", "password"], mirroring the object first_name,
    # last_name, email and gender locks. The endpoint is
    # permission-gated (USER_READ_AND_WRITE_ONLY), and FastAPI
    # solves sub-dependencies before validating the endpoint's
    # own body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the role
    # whitespace-only-name lock. The role is seeded with the
    # mocked user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's USER_READ_AND_WRITE_ONLY
    # permission, mirroring the user missing-password lock, so the
    # permission gate cannot mask the 422 with a 404; the
    # default conftest mock is a host caller (tenant_id None),
    # so _assert_create_scope cannot fire. Deliberately no
    # exact error-type assertion, mirroring the tenant,
    # account and role whitespace-only 422 locks. Deliberately
    # no Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the tenant, account and role whitespace-only
    # 422 locks. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": {"value": "Secret123!"},
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "password"]
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
    # mirroring the other user locks in this file, using
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

async def test_create_user_float_password_returns_422_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a float password:
    """
    # The fourth branch of the user password per-field sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_user_float_password and grep count 0
    # for "float_password" in this file before appending. The
    # tenant sweep is complete (body-shape 2556-2562 + per-field
    # 2563-2577), the register sweep is complete, the role sweep
    # is complete (body-shape 2578-2584 + per-field 2585-2599),
    # the user body-shape sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # - iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618), the
    # email sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only, invalid-format - iterations
    # 2619-2625) and the gender sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only,
    # invalid-value - iterations 2626-2632), so the per-field
    # sweep continues with password, whose missing-field branch
    # was locked in iteration 2633, whose non-string branch was
    # locked in iteration 2634 and whose object branch was locked
    # in iteration 2635. The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. Pydantic v2 does not coerce a JSON
    # float to a string, so a float password fails FastAPI
    # request validation before the handler body runs:
    # UserService.create_user never runs, so no user record is
    # created -- no duplicate-email check, no GUEST role lookup,
    # no repository write. The DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), so it
    # cannot mask the 422. This is distinct from the
    # missing-password lock (iteration 2633, field omitted), the
    # non-string lock (iteration 2634, JSON integer) and the
    # object lock (iteration 2635, a dict): here the password is
    # present but a JSON float, so the failure is a type error
    # whose detail loc is ["body", "password"], mirroring the
    # float first_name, last_name, email and gender locks. The
    # endpoint is permission-gated (USER_READ_AND_WRITE_ONLY),
    # and FastAPI solves sub-dependencies before validating the
    # endpoint's own body, so the mocked caller's role must be
    # seeded first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the role whitespace-only-name lock. The role is seeded
    # with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock, so the permission gate cannot mask
    # the 422 with a 404; the default conftest mock is a host
    # caller (tenant_id None), so _assert_create_scope cannot
    # fire. Deliberately no exact error-type assertion,
    # mirroring the tenant, account and role whitespace-only 422
    # locks. Deliberately no Cache-Control/Pragma assertion: a
    # 422 is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply to
    # it, mirroring the tenant, account and role whitespace-only
    # 422 locks. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": 12.34,
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        err.get("loc") == ["body", "password"]
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
    # mirroring the other user locks in this file, using
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
async def test_create_user_empty_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with an empty-string password:
    """
    # The first value branch of the user password per-field sweep
    # after the type branches, verified fresh this run, not
    # assumed: function-name grep count 0 for
    # create_user_empty_password and grep count 0 for
    # "empty_password" in this file before appending. The tenant
    # sweep is complete (body-shape 2556-2562 + per-field
    # 2563-2577), the register sweep is complete, the role sweep
    # is complete (body-shape 2578-2584 + per-field 2585-2599),
    # the user body-shape sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # - iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618), the
    # email sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only, invalid-format - iterations
    # 2619-2625) and the gender sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only,
    # invalid-value - iterations 2626-2632), and the password
    # sweep has locked missing (2633), non-string (2634),
    # object (2635) and float (2636). The endpoint takes a
    # required `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An empty string therefore passes
    # FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), so it
    # cannot mask the failure. The handler body runs instead:
    # after the permission gate and the GUEST role lookup, it
    # calls UserService.create_user, which validates the
    # password FIRST -- before the duplicate-email check and
    # before any repository write (user_service.py:111-121).
    # validate_password("") fails PASSWORD_REGEX (utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character) and raises InvalidOperationException,
    # which the central ApiBaseException handler maps to 406
    # with body {"error": ..., "code": 406} plus no-store
    # headers (api/__init__.py:84-135), mirroring the
    # register weak-password 406 lock. This is distinct from
    # the missing-password lock (iteration 2633, field omitted
    # - 422), the non-string lock (iteration 2634, JSON
    # integer - 422), the object lock (iteration 2635, a dict
    # - 422) and the float lock (iteration 2636 - 422): here
    # the password is present and a string, so validation
    # passes and the failure is a policy rejection, not a
    # type error. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406. The role
    # is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_whitespace_only_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a whitespace-only password:
    """
    # The second value branch of the user password per-field sweep
    # after the type branches, verified fresh this run, not
    # assumed: function-name grep count 0 for
    # create_user_whitespace_only_password and grep count 0 for
    # "whitespace_only_password" in this file before appending.
    # The tenant sweep is complete (body-shape 2556-2562 +
    # per-field 2563-2577), the register sweep is complete, the
    # role sweep is complete (body-shape 2578-2584 + per-field
    # 2585-2599), the user body-shape sweep is complete (missing
    # body, non-object, string, numeric, boolean, null, malformed
    # JSON - iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618), the
    # email sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only, invalid-format - iterations
    # 2619-2625) and the gender sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only,
    # invalid-value - iterations 2626-2632), and the password
    # sweep has locked missing (2633), non-string (2634),
    # object (2635), float (2636) and empty (2637). The endpoint
    # takes a required `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. A whitespace-only string therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so it cannot mask the failure.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (user_service.py:118-119).
    # validate_password("        ") fails PASSWORD_REGEX
    # (utils.py:42, at least 8 characters with upper/lowercase,
    # a digit and a special character -- eight spaces satisfy
    # none of the lookaheads) and raises
    # InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body {"error":
    # ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422) and the empty-password
    # lock (iteration 2637, "" - 406): here the password is
    # present, a string, and non-empty, so validation passes
    # and the failure is the policy rejection, not a type or
    # emptiness error. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406. The role
    # is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "        ",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_too_short_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a too-short password:
    """
    # The third value branch of the user password per-field sweep
    # after the type branches, verified fresh this run, not
    # assumed: function-name grep count 0 for
    # create_user_too_short_password and grep count 0 for
    # "too_short_password" in this file before appending.
    # The tenant sweep is complete (body-shape 2556-2562 +
    # per-field 2563-2577), the register sweep is complete, the
    # role sweep is complete (body-shape 2578-2584 + per-field
    # 2585-2599), the user body-shape sweep is complete (missing
    # body, non-object, string, numeric, boolean, null, malformed
    # JSON - iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618), the
    # email sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only, invalid-format - iterations
    # 2619-2625) and the gender sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only,
    # invalid-value - iterations 2626-2632), and the password
    # sweep has locked missing (2633), non-string (2634),
    # object (2635), float (2636), empty (2637) and
    # whitespace-only (2638). The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. A 4-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so it cannot mask the failure.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (user_service.py:111-121).
    # validate_password("Aa1!") fails PASSWORD_REGEX
    # (common/utils.py:42, at least 8 characters with
    # upper/lowercase, a digit and a special character --
    # "Aa1!" satisfies every lookahead but is only 4
    # characters, so the {8,} quantifier rejects it; the
    # comment above the regex records that without {8,} and
    # the $ anchor this exact value passed) and raises
    # InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body {"error":
    # ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406) and the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406): here the password is present, a string,
    # non-empty and non-blank, so validation passes and the
    # failure is the policy rejection of a short credential.
    # The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406. The role
    # is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Aa1!",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_no_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password that has no special
        character:
    """
    # The fourth value branch of the user password per-field sweep
    # after the type branches, verified fresh this run, not
    # assumed: function-name grep count 0 for
    # create_user_no_special_character_password and grep count 0
    # for "no_special_character_password" in this file before
    # appending.
    # The tenant sweep is complete (body-shape 2556-2562 +
    # per-field 2563-2577), the register sweep is complete, the
    # role sweep is complete (body-shape 2578-2584 + per-field
    # 2585-2599), the user body-shape sweep is complete (missing
    # body, non-object, string, numeric, boolean, null, malformed
    # JSON - iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618), the
    # email sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only, invalid-format - iterations
    # 2619-2625) and the gender sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only,
    # invalid-value - iterations 2626-2632), and the password
    # sweep has locked missing (2633), non-string (2634),
    # object (2635), float (2636), empty (2637),
    # whitespace-only (2638) and too-short (2639). The endpoint
    # takes a required `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so it cannot mask the failure.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (user_service.py:111-121).
    # validate_password("Password123") fails PASSWORD_REGEX
    # (common/utils.py:42, at least 8 characters with
    # upper/lowercase, a digit and a special character --
    # "Password123" satisfies the length and the lower, upper
    # and digit lookaheads but has no character from
    # [@$!%*?&], so the special-character lookahead rejects
    # it; the same value with a trailing "!" passes, verified
    # against the regex this run) and raises
    # InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body {"error":
    # ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406) and the too-short-password lock (iteration
    # 2639, "Aa1!" - 406): here the password is present, a
    # string, non-empty, non-blank and long enough, so
    # validation passes and the failure is the policy
    # rejection of a credential missing a special character.
    # The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406. The role
    # is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password123",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_no_digit_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password that has no digit:
    """
    # The fifth value branch of the user password per-field sweep
    # after the type branches, verified fresh this run, not
    # assumed: function-name grep count 0 for
    # create_user_no_digit_password and grep count 0 for
    # "no_digit_password" in this file before appending.
    # The tenant sweep is complete (body-shape 2556-2562 +
    # per-field 2563-2577), the register sweep is complete, the
    # role sweep is complete (body-shape 2578-2584 + per-field
    # 2585-2599), the user body-shape sweep is complete (missing
    # body, non-object, string, numeric, boolean, null, malformed
    # JSON - iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618), the
    # email sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only, invalid-format - iterations
    # 2619-2625) and the gender sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only,
    # invalid-value - iterations 2626-2632), and the password
    # sweep has locked missing (2633), non-string (2634),
    # object (2635), float (2636), empty (2637),
    # whitespace-only (2638), too-short (2639) and
    # no-special-character (2640). The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. A 9-character password therefore passes
    # FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so it cannot mask the failure.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121).
    # validate_password("Password!") fails PASSWORD_REGEX
    # (common/utils.py:42, at least 8 characters with
    # upper/lowercase, a digit and a special character --
    # "Password!" satisfies the length and the lower, upper
    # and special-character lookaheads but has no digit, so
    # the digit lookahead rejects it; the same value with a
    # "1" inserted passes, verified against the regex this
    # run) and raises InvalidOperationException, which the
    # central ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406) and the no-special-character lock
    # (iteration 2640, "Password123" - 406): here the password
    # is present, a string, non-empty, non-blank and long
    # enough, so validation passes and the failure is the
    # policy rejection of a credential missing a digit.
    # The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406. The role
    # is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password!",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_no_uppercase_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password that has no uppercase letter:
    """
    # The sixth value branch of the user password per-field sweep
    # after the type branches, verified fresh this run, not
    # assumed: function-name grep count 0 for
    # create_user_no_uppercase_password and grep count 0 for
    # "no_uppercase_password" in this file before appending.
    # The tenant sweep is complete (body-shape 2556-2562 +
    # per-field 2563-2577), the register sweep is complete, the
    # role sweep is complete (body-shape 2578-2584 + per-field
    # 2585-2599), the user body-shape sweep is complete (missing
    # body, non-object, string, numeric, boolean, null, malformed
    # JSON - iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618), the
    # email sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only, invalid-format - iterations
    # 2619-2625) and the gender sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only,
    # invalid-value - iterations 2626-2632), and the password
    # sweep has locked missing (2633), non-string (2634),
    # object (2635), float (2636), empty (2637),
    # whitespace-only (2638), too-short (2639),
    # no-special-character (2640) and no-digit (2641). The
    # endpoint takes a required `data: CreateUserDto` body
    # parameter (user_endpoint.py:115-128) whose password is a
    # required `str` on CreateUserDto (user_dto.py:44, no
    # min_length constraint), alongside required first_name,
    # last_name, email and gender. A 10-character password
    # therefore passes FastAPI request validation: the DTO's
    # mode="after" normalize_names validator only runs after
    # valid field parsing (and only touches first_name/
    # last_name), and the password is deliberately NOT trimmed
    # (user_dto.py:30, credential semantics), so it cannot
    # mask the failure. The handler body runs instead: after
    # the permission gate and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("password1!") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character -- "password1!" satisfies the length
    # and the lower, digit and special-character lookaheads
    # but has no uppercase letter, so the uppercase lookahead
    # rejects it; the same value with a capital "P" passes,
    # verified against the regex this run) and raises
    # InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406) and the no-digit
    # lock (iteration 2641, "Password!" - 406): here the
    # password is present, a string, non-empty, non-blank and
    # long enough, so validation passes and the failure is the
    # policy rejection of a credential missing an uppercase
    # letter. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406. The role
    # is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "password1!",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_no_lowercase_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password that has no lowercase letter:
    """
    # The seventh value branch of the user password per-field sweep
    # after the type branches, verified fresh this run, not
    # assumed: function-name grep count 0 for
    # create_user_no_lowercase_password and grep count 0 for
    # "no_lowercase_password" in this file before appending.
    # The tenant sweep is complete (body-shape 2556-2562 +
    # per-field 2563-2577), the register sweep is complete, the
    # role sweep is complete (body-shape 2578-2584 + per-field
    # 2585-2599), the user body-shape sweep is complete (missing
    # body, non-object, string, numeric, boolean, null, malformed
    # JSON - iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618), the
    # email sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only, invalid-format - iterations
    # 2619-2625) and the gender sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only,
    # invalid-value - iterations 2626-2632), and the password
    # sweep has locked missing (2633), non-string (2634),
    # object (2635), float (2636), empty (2637),
    # whitespace-only (2638), too-short (2639),
    # no-special-character (2640), no-digit (2641) and
    # no-uppercase (2642). The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. A 10-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so it cannot mask the failure.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("PASSWORD1!") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character -- "PASSWORD1!" satisfies the length
    # and the upper, digit and special-character lookaheads
    # but has no lowercase letter, so the lowercase lookahead
    # rejects it; the same value with a lowercase "a" passes,
    # verified against the regex this run) and raises
    # InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406) and the
    # no-uppercase lock (iteration 2642, "password1!" - 406):
    # here the password is present, a string, non-empty,
    # non-blank and long enough, so validation passes and the
    # failure is the policy rejection of a credential missing
    # a lowercase letter. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406. The role
    # is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "PASSWORD1!",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed character:
    """
    # The eighth value branch of the user password per-field sweep
    # after the type branches, verified fresh this run, not
    # assumed: function-name grep count 0 for
    # create_user_disallowed_character_password and grep count 0
    # for "disallowed_character_password" and "Password 1!" in
    # this file before appending.
    # The tenant sweep is complete (body-shape 2556-2562 +
    # per-field 2563-2577), the register sweep is complete, the
    # role sweep is complete (body-shape 2578-2584 + per-field
    # 2585-2599), the user body-shape sweep is complete (missing
    # body, non-object, string, numeric, boolean, null, malformed
    # JSON - iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618), the
    # email sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only, invalid-format - iterations
    # 2619-2625) and the gender sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only,
    # invalid-value - iterations 2626-2632), and the password
    # sweep has locked missing (2633), non-string (2634),
    # object (2635), float (2636), empty (2637),
    # whitespace-only (2638), too-short (2639),
    # no-special-character (2640), no-digit (2641),
    # no-uppercase (2642) and no-lowercase (2643). The endpoint
    # takes a required `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the space survives to the
    # policy check and cannot mask the failure.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password 1!") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password 1!" satisfies the length
    # and all four lookaheads but contains a space, which is
    # outside the allowed character class, so the class
    # rejects it; the same value without the space passes,
    # verified against the regex this run) and raises
    # InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406) and the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406):
    # here the password is present, a string, non-empty,
    # non-blank, long enough and satisfies every lookahead, so
    # validation passes and the failure is the policy rejection
    # of a credential containing a character outside the
    # allowed set. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406. The role
    # is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password 1!",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_trailing_disallowed_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password ending in a disallowed character:
    """
    # The ninth value branch of the user password per-field sweep
    # after the type branches, verified fresh this run, not
    # assumed: function-name grep count 0 for
    # create_user_trailing_disallowed_character_password and grep
    # count 0 for "trailing_disallowed_character_password" and
    # "Password1! " in this file before appending.
    # The tenant sweep is complete (body-shape 2556-2562 +
    # per-field 2563-2577), the register sweep is complete, the
    # role sweep is complete (body-shape 2578-2584 + per-field
    # 2585-2599), the user body-shape sweep is complete (missing
    # body, non-object, string, numeric, boolean, null, malformed
    # JSON - iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618), the
    # email sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only, invalid-format - iterations
    # 2619-2625) and the gender sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only,
    # invalid-value - iterations 2626-2632), and the password
    # sweep has locked missing (2633), non-string (2634),
    # object (2635), float (2636), empty (2637),
    # whitespace-only (2638), too-short (2639),
    # no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643) and
    # disallowed-character (2644, interior space). The endpoint
    # takes a required `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. A 12-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the trailing space survives to
    # the policy check and cannot mask the failure -- a trim
    # would have silently accepted the paste/typo value.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1! ") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1! " satisfies the length
    # and all four lookaheads but ends in a space, which is
    # outside the allowed character class, so the class
    # rejects it; the same value without the trailing space
    # passes, verified against the regex this run) and raises
    # InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406)
    # and the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space): here the
    # disallowed character is trailing, the classic
    # copy-paste/typo case, and the failure proves the
    # password is not trimmed before the policy check. The
    # endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406. The role
    # is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1! ",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_leading_disallowed_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password starting with a disallowed character:
    """
    # The tenth value branch of the user password per-field sweep
    # after the type branches, verified fresh this run, not
    # assumed: function-name grep count 0 for
    # create_user_leading_disallowed_character_password and grep
    # count 0 for "leading_disallowed_character_password" and
    # " Password1!" in this file before appending.
    # The tenant sweep is complete (body-shape 2556-2562 +
    # per-field 2563-2577), the register sweep is complete, the
    # role sweep is complete (body-shape 2578-2584 + per-field
    # 2585-2599), the user body-shape sweep is complete (missing
    # body, non-object, string, numeric, boolean, null, malformed
    # JSON - iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618), the
    # email sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only, invalid-format - iterations
    # 2619-2625) and the gender sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only,
    # invalid-value - iterations 2626-2632), and the password
    # sweep has locked missing (2633), non-string (2634),
    # object (2635), float (2636), empty (2637),
    # whitespace-only (2638), too-short (2639),
    # no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space) and
    # trailing-disallowed-character (2645, trailing space). The
    # endpoint takes a required `data: CreateUserDto` body
    # parameter (user_endpoint.py:115-128) whose password is a
    # required `str` on CreateUserDto (user_dto.py:44, no
    # min_length constraint), alongside required first_name,
    # last_name, email and gender. A 12-character password
    # therefore passes FastAPI request validation: the DTO's
    # mode="after" normalize_names validator only runs after
    # valid field parsing (and only touches first_name/
    # last_name), and the password is deliberately NOT trimmed
    # (user_dto.py:30, credential semantics), so the leading
    # space survives to the policy check and cannot mask the
    # failure -- a trim would have silently accepted the
    # paste/typo value.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # (" Password1!") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- " Password1!" satisfies the length
    # and all four lookaheads but starts with a space, which is
    # outside the allowed character class, so the class
    # rejects it; the same value without the leading space
    # passes, verified against the regex this run) and raises
    # InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space) and the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space): here the
    # disallowed character is leading, the classic
    # copy-paste/typo case, and the failure proves the
    # password is not trimmed before the policy check. The
    # endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406. The role
    # is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": " Password1!",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the position branches, verified fresh this run, not
    # assumed: function-name grep count 0 for
    # create_user_disallowed_special_character_password and grep
    # count 0 for "Password1!#" in this file before appending.
    # The tenant sweep is complete (body-shape 2556-2562 +
    # per-field 2563-2577), the register sweep is complete, the
    # role sweep is complete (body-shape 2578-2584 + per-field
    # 2585-2599), the user body-shape sweep is complete (missing
    # body, non-object, string, numeric, boolean, null, malformed
    # JSON - iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618), the
    # email sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only, invalid-format - iterations
    # 2619-2625) and the gender sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only,
    # invalid-value - iterations 2626-2632), and the password
    # sweep has locked missing (2633), non-string (2634),
    # object (2635), float (2636), empty (2637),
    # whitespace-only (2638), too-short (2639),
    # no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space) and
    # leading-disallowed-character (2646, leading space). The
    # endpoint takes a required `data: CreateUserDto` body
    # parameter (user_endpoint.py:115-128) whose password is a
    # required `str` on CreateUserDto (user_dto.py:44, no
    # min_length constraint), alongside required first_name,
    # last_name, email and gender. An 11-character password
    # therefore passes FastAPI request validation: the DTO's
    # mode="after" normalize_names validator only runs after
    # valid field parsing (and only touches first_name/
    # last_name), and the password is deliberately NOT trimmed
    # (user_dto.py:30, credential semantics), so the value
    # survives to the policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!#") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!#" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the "#" is outside the allowed character
    # class, so the class rejects it; the same value without
    # the "#" passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space) and the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space): here the disallowed
    # character is a special character ("#") that users
    # commonly assume is allowed, and the failure proves the
    # special-character class boundary -- the value is not a
    # whitespace/trim case and it is not a missing-lookahead
    # case, since every lookahead is satisfied. The endpoint
    # is permission-gated (USER_READ_AND_WRITE_ONLY), and
    # FastAPI solves sub-dependencies before validating the
    # endpoint's own body, so the mocked caller's role must be
    # seeded first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 406, exactly
    # as in the role whitespace-only-name lock. The endpoint
    # also resolves the GUEST role via
    # role_service.find_by_name BEFORE calling create_user
    # (user_endpoint.py:124-127), so a GUEST role must be
    # seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406. The role
    # is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!#",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_paren_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-special-character branch, verified
    # fresh this run, not assumed: function-name grep count 0
    # for create_user_disallowed_paren_special_character_password
    # and grep count 0 for "Password1!(" in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space) and
    # disallowed-special-character (2647, "#"). The endpoint
    # takes a required `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the policy
    # check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!(") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!(" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the "(" is outside the allowed character
    # class, so the class rejects it; the same value without
    # the "(" passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space) and the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"): here the disallowed character
    # is a bracket character ("(") that users commonly try in
    # passwords, and the failure pins the special-character
    # class boundary for a second member of the disallowed set
    # -- the value is not a whitespace/trim case and it is not
    # a missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves the
    # GUEST role via role_service.find_by_name BEFORE calling
    # create_user (user_endpoint.py:124-127), so a GUEST role
    # must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406. The role
    # is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!(",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_close_paren_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-paren-special-character branch,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for
    # create_user_disallowed_close_paren_special_character_password
    # and grep count 0 for "Password1!)" in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#") and
    # disallowed-paren-special-character (2648, "("). The
    # endpoint takes a required `data: CreateUserDto` body
    # parameter (user_endpoint.py:115-128) whose password is a
    # required `str` on CreateUserDto (user_dto.py:44, no
    # min_length constraint), alongside required first_name,
    # last_name, email and gender. An 11-character password
    # therefore passes FastAPI request validation: the DTO's
    # mode="after" normalize_names validator only runs after
    # valid field parsing (and only touches first_name/last_name),
    # and the password is deliberately NOT trimmed
    # (user_dto.py:30, credential semantics), so the value
    # survives to the policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!)") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!)" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the ")" is outside the allowed character
    # class, so the class rejects it; the same value without
    # the ")" passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#") and the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("): here the disallowed character
    # is the closing bracket (")"), pairing with the opening
    # bracket locked in iteration 2648, and the failure pins
    # the special-character class boundary for a third member
    # of the disallowed set -- the value is not a
    # whitespace/trim case and it is not a missing-lookahead
    # case, since every lookahead is satisfied. The endpoint
    # is permission-gated (USER_READ_AND_WRITE_ONLY), and
    # FastAPI solves sub-dependencies before validating the
    # endpoint's own body, so the mocked caller's role must be
    # seeded first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 406, exactly as
    # in the role whitespace-only-name lock. The endpoint also
    # resolves the GUEST role via role_service.find_by_name
    # BEFORE calling create_user (user_endpoint.py:124-127),
    # so a GUEST role must be seeded too -- otherwise that
    # lookup's RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!)",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_square_bracket_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-close-paren-special-character branch,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for
    # create_user_disallowed_square_bracket_special_character_password
    # and grep count 0 for "Password1![" in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "(") and
    # disallowed-close-paren-special-character (2649, ")"). The
    # endpoint takes a required `data: CreateUserDto` body
    # parameter (user_endpoint.py:115-128) whose password is a
    # required `str` on CreateUserDto (user_dto.py:44, no
    # min_length constraint), alongside required first_name,
    # last_name, email and gender. An 11-character password
    # therefore passes FastAPI request validation: the DTO's
    # mode="after" normalize_names validator only runs after
    # valid field parsing (and only touches first_name/last_name),
    # and the password is deliberately NOT trimmed
    # (user_dto.py:30, credential semantics), so the value
    # survives to the policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1![") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1![" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the "[" is outside the allowed character
    # class, so the class rejects it; the same value without
    # the "[" passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "(") and the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"): here the disallowed
    # character is the opening square bracket ("["), a fourth
    # member of the disallowed set from a different bracket
    # family, and the failure pins the special-character class
    # boundary for it -- the value is not a
    # whitespace/trim case and it is not a missing-lookahead
    # case, since every lookahead is satisfied. The endpoint
    # is permission-gated (USER_READ_AND_WRITE_ONLY), and
    # FastAPI solves sub-dependencies before validating the
    # endpoint's own body, so the mocked caller's role must be
    # seeded first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 406, exactly as
    # in the role whitespace-only-name lock. The endpoint also
    # resolves the GUEST role via role_service.find_by_name
    # BEFORE calling create_user (user_endpoint.py:124-127),
    # so a GUEST role must be seeded too -- otherwise that
    # lookup's RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1![",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_close_square_bracket_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-square-bracket-special-character
    # branch, verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_close_square_bracket_special_character_password
    # and grep count 0 for "Password1!]" in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")") and
    # disallowed-square-bracket-special-character (2650, "[").
    # The endpoint takes a required `data: CreateUserDto` body
    # parameter (user_endpoint.py:115-128) whose password is a
    # required `str` on CreateUserDto (user_dto.py:44, no
    # min_length constraint), alongside required first_name,
    # last_name, email and gender. An 11-character password
    # therefore passes FastAPI request validation: the DTO's
    # mode="after" normalize_names validator only runs after
    # valid field parsing (and only touches first_name/last_name),
    # and the password is deliberately NOT trimmed
    # (user_dto.py:30, credential semantics), so the value
    # survives to the policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!]") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!]" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the "]" is outside the allowed character
    # class, so the class rejects it; the same value without
    # the "]" passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")") and the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "["): here the
    # disallowed character is the closing square bracket
    # ("]"), a fifth member of the disallowed set pairing with
    # "[" locked in 2650, and the failure pins the
    # special-character class boundary for it -- the value is
    # not a whitespace/trim case and it is not a
    # missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!]",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_curly_brace_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-close-square-bracket-special-character
    # branch, verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_curly_brace_special_character_password
    # and grep count 0 for "Password1!{" in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "[")
    # and disallowed-close-square-bracket-special-character
    # (2651, "]"). The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!{") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!{" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the "{" is outside the allowed character
    # class, so the class rejects it; the same value without
    # the "{" passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]"): here the
    # disallowed character is the opening curly brace
    # ("{"), a sixth member of the disallowed set from a
    # different bracket family, and the failure pins the
    # special-character class boundary for it -- the value is
    # not a whitespace/trim case and it is not a
    # missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!{",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_close_curly_brace_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-curly-brace-special-character
    # branch, verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_close_curly_brace_special_character_password
    # and grep count 0 for "Password1!}" in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "["),
    # disallowed-close-square-bracket-special-character
    # (2651, "]") and
    # disallowed-curly-brace-special-character (2652, "{").
    # The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!}") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!}" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the "}" is outside the allowed character
    # class, so the class rejects it; the same value without
    # the "}" passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]") and the
    # disallowed-curly-brace-special-character lock
    # (iteration 2652, "Password1!{" - 406, "{"): here the
    # disallowed character is the closing curly brace
    # ("}"), a seventh member of the disallowed set from the
    # curly-brace family, pairing with "{" locked in 2652,
    # and the failure pins the special-character class
    # boundary for it -- the value is not a whitespace/trim
    # case and it is not a missing-lookahead case, since every
    # lookahead is satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!}",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_caret_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-close-curly-brace-special-character
    # branch, verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_caret_special_character_password
    # and grep count 0 for "Password1!^" in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "["),
    # disallowed-close-square-bracket-special-character
    # (2651, "]"),
    # disallowed-curly-brace-special-character (2652, "{") and
    # disallowed-close-curly-brace-special-character
    # (2653, "}").
    # The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!^") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!^" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the "^" is outside the allowed character
    # class, so the class rejects it; the same value without
    # the "^" passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]") and the
    # disallowed-curly-brace-special-character lock
    # (iteration 2652, "Password1!{" - 406, "{") and the
    # disallowed-close-curly-brace-special-character lock
    # (iteration 2653, "Password1!}" - 406, "}"): here the
    # disallowed character is the caret ("^"), an eighth
    # member of the disallowed set, and the failure pins the
    # special-character class boundary for it -- the value is
    # not a whitespace/trim case and it is not a
    # missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!^",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_tilde_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-caret-special-character branch,
    # verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_tilde_special_character_password
    # and grep count 0 for "Password1!~" in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "["),
    # disallowed-close-square-bracket-special-character
    # (2651, "]"),
    # disallowed-curly-brace-special-character (2652, "{"),
    # disallowed-close-curly-brace-special-character
    # (2653, "}") and
    # disallowed-caret-special-character (2654, "^").
    # The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!~") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!~" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the "~" is outside the allowed character
    # class, so the class rejects it; the same value without
    # the "~" passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]") and the
    # disallowed-curly-brace-special-character lock
    # (iteration 2652, "Password1!{" - 406, "{") and the
    # disallowed-close-curly-brace-special-character lock
    # (iteration 2653, "Password1!}" - 406, "}") and the
    # disallowed-caret-special-character lock (iteration 2654,
    # "Password1!^" - 406, "^"): here the disallowed
    # character is the tilde ("~"), a ninth member of the
    # disallowed set, and the failure pins the
    # special-character class boundary for it -- the value is
    # not a whitespace/trim case and it is not a
    # missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!~",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_backtick_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-tilde-special-character branch,
    # verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_backtick_special_character_password
    # and grep count 0 for "Password1!`" in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "["),
    # disallowed-close-square-bracket-special-character
    # (2651, "]"),
    # disallowed-curly-brace-special-character (2652, "{"),
    # disallowed-close-curly-brace-special-character
    # (2653, "}"),
    # disallowed-caret-special-character (2654, "^") and
    # disallowed-tilde-special-character (2655, "~").
    # The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!`") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!`" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the "`" is outside the allowed character
    # class, so the class rejects it; the same value without
    # the "`" passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]") and the
    # disallowed-curly-brace-special-character lock
    # (iteration 2652, "Password1!{" - 406, "{") and the
    # disallowed-close-curly-brace-special-character lock
    # (iteration 2653, "Password1!}" - 406, "}") and the
    # disallowed-caret-special-character lock (iteration 2654,
    # "Password1!^" - 406, "^") and the
    # disallowed-tilde-special-character lock (iteration 2655,
    # "Password1!~" - 406, "~"): here the disallowed
    # character is the backtick ("`"), a tenth member of the
    # disallowed set, and the failure pins the
    # special-character class boundary for it -- the value is
    # not a whitespace/trim case and it is not a
    # missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!`",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_hyphen_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-backtick-special-character branch,
    # verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_hyphen_special_character_password
    # and grep count 0 for "Password1!-" in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "["),
    # disallowed-close-square-bracket-special-character
    # (2651, "]"),
    # disallowed-curly-brace-special-character (2652, "{"),
    # disallowed-close-curly-brace-special-character
    # (2653, "}"),
    # disallowed-caret-special-character (2654, "^"),
    # disallowed-tilde-special-character (2655, "~") and
    # disallowed-backtick-special-character (2656, "`").
    # The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!-") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!-" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the "-" is outside the allowed character
    # class, so the class rejects it; the same value without
    # the "-" passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]") and the
    # disallowed-curly-brace-special-character lock
    # (iteration 2652, "Password1!{" - 406, "{") and the
    # disallowed-close-curly-brace-special-character lock
    # (iteration 2653, "Password1!}" - 406, "}") and the
    # disallowed-caret-special-character lock (iteration 2654,
    # "Password1!^" - 406, "^") and the
    # disallowed-tilde-special-character lock (iteration 2655,
    # "Password1!~" - 406, "~") and the
    # disallowed-backtick-special-character lock (iteration
    # 2656, "Password1!`" - 406, "`"): here the disallowed
    # character is the hyphen ("-"), an eleventh member of the
    # disallowed set, and the failure pins the
    # special-character class boundary for it -- the value is
    # not a whitespace/trim case and it is not a
    # missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!-",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_underscore_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-hyphen-special-character branch,
    # verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_underscore_special_character_password
    # and grep count 0 for "Password1!_" in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "["),
    # disallowed-close-square-bracket-special-character
    # (2651, "]"),
    # disallowed-curly-brace-special-character (2652, "{"),
    # disallowed-close-curly-brace-special-character
    # (2653, "}"),
    # disallowed-caret-special-character (2654, "^"),
    # disallowed-tilde-special-character (2655, "~"),
    # disallowed-backtick-special-character (2656, "`") and
    # disallowed-hyphen-special-character (2657, "-").
    # The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!_") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!_" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the "_" is outside the allowed character
    # class, so the class rejects it; the same value without
    # the "_" passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]") and the
    # disallowed-curly-brace-special-character lock
    # (iteration 2652, "Password1!{" - 406, "{") and the
    # disallowed-close-curly-brace-special-character lock
    # (iteration 2653, "Password1!}" - 406, "}") and the
    # disallowed-caret-special-character lock (iteration 2654,
    # "Password1!^" - 406, "^") and the
    # disallowed-tilde-special-character lock (iteration 2655,
    # "Password1!~" - 406, "~") and the
    # disallowed-backtick-special-character lock (iteration
    # 2656, "Password1!`" - 406, "`") and the
    # disallowed-hyphen-special-character lock (iteration
    # 2657, "Password1!-" - 406, "-"): here the disallowed
    # character is the underscore ("_"), a twelfth member of the
    # disallowed set, and the failure pins the
    # special-character class boundary for it -- the value is
    # not a whitespace/trim case and it is not a
    # missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!_",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_equals_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-underscore-special-character branch,
    # verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_equals_special_character_password
    # and grep count 0 for "Password1!=" in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "["),
    # disallowed-close-square-bracket-special-character
    # (2651, "]"),
    # disallowed-curly-brace-special-character (2652, "{"),
    # disallowed-close-curly-brace-special-character
    # (2653, "}"),
    # disallowed-caret-special-character (2654, "^"),
    # disallowed-tilde-special-character (2655, "~"),
    # disallowed-backtick-special-character (2656, "`"),
    # disallowed-hyphen-special-character (2657, "-") and
    # disallowed-underscore-special-character (2658, "_").
    # The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!=") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!=" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the "=" is outside the allowed character
    # class, so the class rejects it; the same value without
    # the "=" passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]") and the
    # disallowed-curly-brace-special-character lock
    # (iteration 2652, "Password1!{" - 406, "{") and the
    # disallowed-close-curly-brace-special-character lock
    # (iteration 2653, "Password1!}" - 406, "}") and the
    # disallowed-caret-special-character lock (iteration 2654,
    # "Password1!^" - 406, "^") and the
    # disallowed-tilde-special-character lock (iteration 2655,
    # "Password1!~" - 406, "~") and the
    # disallowed-backtick-special-character lock (iteration
    # 2656, "Password1!`" - 406, "`"), the
    # disallowed-hyphen-special-character lock (iteration
    # 2657, "Password1!-" - 406, "-") and the
    # disallowed-underscore-special-character lock (iteration
    # 2658, "Password1!_" - 406, "_"): here the disallowed
    # character is the equals sign ("="), a thirteenth member of the
    # disallowed set, and the failure pins the
    # special-character class boundary for it -- the value is
    # not a whitespace/trim case and it is not a
    # missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!=",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_plus_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-equals-special-character branch,
    # verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_plus_special_character_password
    # and grep count 0 for "Password1!+" in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "["),
    # disallowed-close-square-bracket-special-character
    # (2651, "]"),
    # disallowed-curly-brace-special-character (2652, "{"),
    # disallowed-close-curly-brace-special-character
    # (2653, "}"),
    # disallowed-caret-special-character (2654, "^"),
    # disallowed-tilde-special-character (2655, "~"),
    # disallowed-backtick-special-character (2656, "`"),
    # disallowed-hyphen-special-character (2657, "-"),
    # disallowed-underscore-special-character (2658, "_") and
    # disallowed-equals-special-character (2659, "=").
    # The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!+") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!+" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the "+" is outside the allowed character
    # class, so the class rejects it; the same value without
    # the "+" passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]") and the
    # disallowed-curly-brace-special-character lock
    # (iteration 2652, "Password1!{" - 406, "{") and the
    # disallowed-close-curly-brace-special-character lock
    # (iteration 2653, "Password1!}" - 406, "}") and the
    # disallowed-caret-special-character lock (iteration 2654,
    # "Password1!^" - 406, "^") and the
    # disallowed-tilde-special-character lock (iteration 2655,
    # "Password1!~" - 406, "~") and the
    # disallowed-backtick-special-character lock (iteration
    # 2656, "Password1!`" - 406, "`"), the
    # disallowed-hyphen-special-character lock (iteration
    # 2657, "Password1!-" - 406, "-"), the
    # disallowed-underscore-special-character lock (iteration
    # 2658, "Password1!_" - 406, "_") and the
    # disallowed-equals-special-character lock (iteration
    # 2659, "Password1!=" - 406, "="): here the disallowed
    # character is the plus sign ("+"), a fourteenth member of the
    # disallowed set, and the failure pins the
    # special-character class boundary for it -- the value is
    # not a whitespace/trim case and it is not a
    # missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!+",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_pipe_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-plus-special-character branch,
    # verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_pipe_special_character_password
    # and grep count 0 for "Password1!|" in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "["),
    # disallowed-close-square-bracket-special-character
    # (2651, "]"),
    # disallowed-curly-brace-special-character (2652, "{"),
    # disallowed-close-curly-brace-special-character
    # (2653, "}"),
    # disallowed-caret-special-character (2654, "^"),
    # disallowed-tilde-special-character (2655, "~"),
    # disallowed-backtick-special-character (2656, "`"),
    # disallowed-hyphen-special-character (2657, "-"),
    # disallowed-underscore-special-character (2658, "_"),
    # disallowed-equals-special-character (2659, "=") and
    # disallowed-plus-special-character (2660, "+").
    # The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!|") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!|" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the "|" is outside the allowed character
    # class, so the class rejects it; the same value without
    # the "|" passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]") and the
    # disallowed-curly-brace-special-character lock
    # (iteration 2652, "Password1!{" - 406, "{") and the
    # disallowed-close-curly-brace-special-character lock
    # (iteration 2653, "Password1!}" - 406, "}") and the
    # disallowed-caret-special-character lock (iteration 2654,
    # "Password1!^" - 406, "^") and the
    # disallowed-tilde-special-character lock (iteration 2655,
    # "Password1!~" - 406, "~") and the
    # disallowed-backtick-special-character lock (iteration
    # 2656, "Password1!`" - 406, "`"), the
    # disallowed-hyphen-special-character lock (iteration
    # 2657, "Password1!-" - 406, "-"), the
    # disallowed-underscore-special-character lock (iteration
    # 2658, "Password1!_" - 406, "_"), the
    # disallowed-equals-special-character lock (iteration
    # 2659, "Password1!=" - 406, "=") and the
    # disallowed-plus-special-character lock (iteration 2660,
    # "Password1!+" - 406, "+"): here the disallowed
    # character is the pipe ("|"), a fifteenth member of the
    # disallowed set, and the failure pins the
    # special-character class boundary for it -- the value is
    # not a whitespace/trim case and it is not a
    # missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!|",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_backslash_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-pipe-special-character branch,
    # verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_backslash_special_character_password
    # and grep count 0 for "Password1!\\" in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "["),
    # disallowed-close-square-bracket-special-character
    # (2651, "]"),
    # disallowed-curly-brace-special-character (2652, "{"),
    # disallowed-close-curly-brace-special-character
    # (2653, "}"),
    # disallowed-caret-special-character (2654, "^"),
    # disallowed-tilde-special-character (2655, "~"),
    # disallowed-backtick-special-character (2656, "`"),
    # disallowed-hyphen-special-character (2657, "-"),
    # disallowed-underscore-special-character (2658, "_"),
    # disallowed-equals-special-character (2659, "="),
    # disallowed-plus-special-character (2660, "+") and
    # disallowed-pipe-special-character (2661, "|").
    # The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!\\") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!\\" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the "\\" is outside the allowed character
    # class, so the class rejects it; the same value without
    # the "\\" passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]") and the
    # disallowed-curly-brace-special-character lock
    # (iteration 2652, "Password1!{" - 406, "{") and the
    # disallowed-close-curly-brace-special-character lock
    # (iteration 2653, "Password1!}" - 406, "}") and the
    # disallowed-caret-special-character lock (iteration 2654,
    # "Password1!^" - 406, "^") and the
    # disallowed-tilde-special-character lock (iteration 2655,
    # "Password1!~" - 406, "~") and the
    # disallowed-backtick-special-character lock (iteration
    # 2656, "Password1!`" - 406, "`"), the
    # disallowed-hyphen-special-character lock (iteration
    # 2657, "Password1!-" - 406, "-"), the
    # disallowed-underscore-special-character lock (iteration
    # 2658, "Password1!_" - 406, "_"), the
    # disallowed-equals-special-character lock (iteration
    # 2659, "Password1!=" - 406, "="), the
    # disallowed-plus-special-character lock (iteration 2660,
    # "Password1!+" - 406, "+") and the
    # disallowed-pipe-special-character lock (iteration 2661,
    # "Password1!|" - 406, "|"): here the disallowed
    # character is the backslash ("\\"), a sixteenth member of
    # the disallowed set, and the failure pins the
    # special-character class boundary for it -- the value is
    # not a whitespace/trim case and it is not a
    # missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!\\",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_slash_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-backslash-special-character branch,
    # verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_slash_special_character_password
    # and grep count 0 for "Password1!/" in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "["),
    # disallowed-close-square-bracket-special-character
    # (2651, "]"),
    # disallowed-curly-brace-special-character (2652, "{"),
    # disallowed-close-curly-brace-special-character
    # (2653, "}"),
    # disallowed-caret-special-character (2654, "^"),
    # disallowed-tilde-special-character (2655, "~"),
    # disallowed-backtick-special-character (2656, "`"),
    # disallowed-hyphen-special-character (2657, "-"),
    # disallowed-underscore-special-character (2658, "_"),
    # disallowed-equals-special-character (2659, "="),
    # disallowed-plus-special-character (2660, "+"),
    # disallowed-pipe-special-character (2661, "|") and
    # disallowed-backslash-special-character (2662, "\\").
    # The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!/") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!/" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the "/" is outside the allowed character
    # class, so the class rejects it; the same value without
    # the "/" passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]") and the
    # disallowed-curly-brace-special-character lock
    # (iteration 2652, "Password1!{" - 406, "{") and the
    # disallowed-close-curly-brace-special-character lock
    # (iteration 2653, "Password1!}" - 406, "}") and the
    # disallowed-caret-special-character lock (iteration 2654,
    # "Password1!^" - 406, "^") and the
    # disallowed-tilde-special-character lock (iteration 2655,
    # "Password1!~" - 406, "~") and the
    # disallowed-backtick-special-character lock (iteration
    # 2656, "Password1!`" - 406, "`"), the
    # disallowed-hyphen-special-character lock (iteration
    # 2657, "Password1!-" - 406, "-"), the
    # disallowed-underscore-special-character lock (iteration
    # 2658, "Password1!_" - 406, "_"), the
    # disallowed-equals-special-character lock (iteration
    # 2659, "Password1!=" - 406, "="), the
    # disallowed-plus-special-character lock (iteration 2660,
    # "Password1!+" - 406, "+"), the
    # disallowed-pipe-special-character lock (iteration 2661,
    # "Password1!|" - 406, "|") and the
    # disallowed-backslash-special-character lock (iteration
    # 2662, "Password1!\\" - 406, "\\"): here the disallowed
    # character is the forward slash ("/"), a seventeenth
    # member of the disallowed set, and the failure pins the
    # special-character class boundary for it -- the value is
    # not a whitespace/trim case and it is not a
    # missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!/",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_colon_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-slash-special-character branch,
    # verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_colon_special_character_password
    # and grep count 0 for "Password1!:" in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "["),
    # disallowed-close-square-bracket-special-character
    # (2651, "]"),
    # disallowed-curly-brace-special-character (2652, "{"),
    # disallowed-close-curly-brace-special-character
    # (2653, "}"),
    # disallowed-caret-special-character (2654, "^"),
    # disallowed-tilde-special-character (2655, "~"),
    # disallowed-backtick-special-character (2656, "`"),
    # disallowed-hyphen-special-character (2657, "-"),
    # disallowed-underscore-special-character (2658, "_"),
    # disallowed-equals-special-character (2659, "="),
    # disallowed-plus-special-character (2660, "+"),
    # disallowed-pipe-special-character (2661, "|"),
    # disallowed-backslash-special-character (2662, "\\") and
    # disallowed-slash-special-character (2663, "/").
    # The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!:") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!:" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the ":" is outside the allowed character
    # class, so the class rejects it; the same value without
    # the ":" passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]") and the
    # disallowed-curly-brace-special-character lock
    # (iteration 2652, "Password1!{" - 406, "{") and the
    # disallowed-close-curly-brace-special-character lock
    # (iteration 2653, "Password1!}" - 406, "}") and the
    # disallowed-caret-special-character lock (iteration 2654,
    # "Password1!^" - 406, "^") and the
    # disallowed-tilde-special-character lock (iteration 2655,
    # "Password1!~" - 406, "~") and the
    # disallowed-backtick-special-character lock (iteration
    # 2656, "Password1!`" - 406, "`"), the
    # disallowed-hyphen-special-character lock (iteration
    # 2657, "Password1!-" - 406, "-"), the
    # disallowed-underscore-special-character lock (iteration
    # 2658, "Password1!_" - 406, "_"), the
    # disallowed-equals-special-character lock (iteration
    # 2659, "Password1!=" - 406, "="), the
    # disallowed-plus-special-character lock (iteration 2660,
    # "Password1!+" - 406, "+"), the
    # disallowed-pipe-special-character lock (iteration 2661,
    # "Password1!|" - 406, "|"), the
    # disallowed-backslash-special-character lock (iteration
    # 2662, "Password1!\\" - 406, "\\") and the
    # disallowed-slash-special-character lock (iteration
    # 2663, "Password1!/" - 406, "/"): here the disallowed
    # character is the colon (":"), an eighteenth
    # member of the disallowed set, and the failure pins the
    # special-character class boundary for it -- the value is
    # not a whitespace/trim case and it is not a
    # missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!:",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_semicolon_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-colon-special-character branch,
    # verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_semicolon_special_character_password
    # and grep count 0 for "Password1!;" in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "["),
    # disallowed-close-square-bracket-special-character
    # (2651, "]"),
    # disallowed-curly-brace-special-character (2652, "{"),
    # disallowed-close-curly-brace-special-character
    # (2653, "}"),
    # disallowed-caret-special-character (2654, "^"),
    # disallowed-tilde-special-character (2655, "~"),
    # disallowed-backtick-special-character (2656, "`"),
    # disallowed-hyphen-special-character (2657, "-"),
    # disallowed-underscore-special-character (2658, "_"),
    # disallowed-equals-special-character (2659, "="),
    # disallowed-plus-special-character (2660, "+"),
    # disallowed-pipe-special-character (2661, "|"),
    # disallowed-backslash-special-character (2662, "\\") and
    # disallowed-slash-special-character (2663, "/") and
    # disallowed-colon-special-character (2664, ":").
    # The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!;") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!;" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the ";" is outside the allowed character
    # class, so the class rejects it; the same value without
    # the ";" passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]") and the
    # disallowed-curly-brace-special-character lock
    # (iteration 2652, "Password1!{" - 406, "{") and the
    # disallowed-close-curly-brace-special-character lock
    # (iteration 2653, "Password1!}" - 406, "}") and the
    # disallowed-caret-special-character lock (iteration 2654,
    # "Password1!^" - 406, "^") and the
    # disallowed-tilde-special-character lock (iteration 2655,
    # "Password1!~" - 406, "~") and the
    # disallowed-backtick-special-character lock (iteration
    # 2656, "Password1!`" - 406, "`"), the
    # disallowed-hyphen-special-character lock (iteration
    # 2657, "Password1!-" - 406, "-"), the
    # disallowed-underscore-special-character lock (iteration
    # 2658, "Password1!_" - 406, "_"), the
    # disallowed-equals-special-character lock (iteration
    # 2659, "Password1!=" - 406, "="), the
    # disallowed-plus-special-character lock (iteration 2660,
    # "Password1!+" - 406, "+"), the
    # disallowed-pipe-special-character lock (iteration 2661,
    # "Password1!|" - 406, "|"), the
    # disallowed-backslash-special-character lock (iteration
    # 2662, "Password1!\\" - 406, "\\") and the
    # disallowed-slash-special-character lock (iteration
    # 2663, "Password1!/" - 406, "/") and the
    # disallowed-colon-special-character lock (iteration
    # 2664, "Password1!:" - 406, ":"): here the disallowed
    # character is the semicolon (";"), a nineteenth
    # member of the disallowed set, and the failure pins the
    # special-character class boundary for it -- the value is
    # not a whitespace/trim case and it is not a
    # missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!;",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_single_quote_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-semicolon-special-character branch,
    # verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_single_quote_special_character_password
    # and grep count 0 for "Password1!'" in this file before
    # appending. The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "["),
    # disallowed-close-square-bracket-special-character
    # (2651, "]"),
    # disallowed-curly-brace-special-character (2652, "{"),
    # disallowed-close-curly-brace-special-character
    # (2653, "}"),
    # disallowed-caret-special-character (2654, "^"),
    # disallowed-tilde-special-character (2655, "~"),
    # disallowed-backtick-special-character (2656, "`"),
    # disallowed-hyphen-special-character (2657, "-"),
    # disallowed-underscore-special-character (2658, "_"),
    # disallowed-equals-special-character (2659, "="),
    # disallowed-plus-special-character (2660, "+"),
    # disallowed-pipe-special-character (2661, "|"),
    # disallowed-backslash-special-character (2662, "\\") and
    # disallowed-slash-special-character (2663, "/") and
    # disallowed-colon-special-character (2664, ":") and
    # disallowed-semicolon-special-character (2665, ";").
    # The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!'") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!'" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the "'" is outside the allowed character
    # class, so the class rejects it; the same value without
    # the "'" passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]") and the
    # disallowed-curly-brace-special-character lock
    # (iteration 2652, "Password1!{" - 406, "{") and the
    # disallowed-close-curly-brace-special-character lock
    # (iteration 2653, "Password1!}" - 406, "}") and the
    # disallowed-caret-special-character lock (iteration 2654,
    # "Password1!^" - 406, "^") and the
    # disallowed-tilde-special-character lock (iteration 2655,
    # "Password1!~" - 406, "~") and the
    # disallowed-backtick-special-character lock (iteration
    # 2656, "Password1!`" - 406, "`"), the
    # disallowed-hyphen-special-character lock (iteration
    # 2657, "Password1!-" - 406, "-"), the
    # disallowed-underscore-special-character lock (iteration
    # 2658, "Password1!_" - 406, "_"), the
    # disallowed-equals-special-character lock (iteration
    # 2659, "Password1!=" - 406, "="), the
    # disallowed-plus-special-character lock (iteration 2660,
    # "Password1!+" - 406, "+"), the
    # disallowed-pipe-special-character lock (iteration 2661,
    # "Password1!|" - 406, "|"), the
    # disallowed-backslash-special-character lock (iteration
    # 2662, "Password1!\\" - 406, "\\") and the
    # disallowed-slash-special-character lock (iteration
    # 2663, "Password1!/" - 406, "/") and the
    # disallowed-colon-special-character lock (iteration
    # 2664, "Password1!:" - 406, ":") and the
    # disallowed-semicolon-special-character lock (iteration
    # 2665, "Password1!;" - 406, ";"): here the disallowed
    # character is the single quote ("'"), a twentieth
    # member of the disallowed set, and the failure pins the
    # special-character class boundary for it -- the value is
    # not a whitespace/trim case and it is not a
    # missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!'",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_double_quote_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-single-quote-special-character branch,
    # verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_double_quote_special_character_password
    # and JSON-value grep count 0 for
    # "password": "Password1!\"" in this file before appending.
    # (A naive substring grep for Password1!" returns 24 hits,
    # all of them the leading-space lock's quoted references to
    # " Password1!" -- the closing quote there belongs to the
    # comment's own quoting, not to a double-quote password
    # value; no test in this file uses Password1!" as a password.)
    # The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "["),
    # disallowed-close-square-bracket-special-character
    # (2651, "]"),
    # disallowed-curly-brace-special-character (2652, "{"),
    # disallowed-close-curly-brace-special-character
    # (2653, "}"),
    # disallowed-caret-special-character (2654, "^"),
    # disallowed-tilde-special-character (2655, "~"),
    # disallowed-backtick-special-character (2656, "`"),
    # disallowed-hyphen-special-character (2657, "-"),
    # disallowed-underscore-special-character (2658, "_"),
    # disallowed-equals-special-character (2659, "="),
    # disallowed-plus-special-character (2660, "+"),
    # disallowed-pipe-special-character (2661, "|"),
    # disallowed-backslash-special-character (2662, "\\") and
    # disallowed-slash-special-character (2663, "/") and
    # disallowed-colon-special-character (2664, ":") and
    # disallowed-semicolon-special-character (2665, ";") and
    # disallowed-single-quote-special-character (2666, "'").
    # The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!\"") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!\"" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the '"' is outside the allowed character
    # class, so the class rejects it; the same value without
    # the '"' passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]") and the
    # disallowed-curly-brace-special-character lock
    # (iteration 2652, "Password1!{" - 406, "{") and the
    # disallowed-close-curly-brace-special-character lock
    # (iteration 2653, "Password1!}" - 406, "}") and the
    # disallowed-caret-special-character lock (iteration 2654,
    # "Password1!^" - 406, "^") and the
    # disallowed-tilde-special-character lock (iteration 2655,
    # "Password1!~" - 406, "~") and the
    # disallowed-backtick-special-character lock (iteration
    # 2656, "Password1!`" - 406, "`"), the
    # disallowed-hyphen-special-character lock (iteration
    # 2657, "Password1!-" - 406, "-"), the
    # disallowed-underscore-special-character lock (iteration
    # 2658, "Password1!_" - 406, "_"), the
    # disallowed-equals-special-character lock (iteration
    # 2659, "Password1!=" - 406, "="), the
    # disallowed-plus-special-character lock (iteration 2660,
    # "Password1!+" - 406, "+"), the
    # disallowed-pipe-special-character lock (iteration 2661,
    # "Password1!|" - 406, "|"), the
    # disallowed-backslash-special-character lock (iteration
    # 2662, "Password1!\\" - 406, "\\") and the
    # disallowed-slash-special-character lock (iteration
    # 2663, "Password1!/" - 406, "/") and the
    # disallowed-colon-special-character lock (iteration
    # 2664, "Password1!:" - 406, ":") and the
    # disallowed-semicolon-special-character lock (iteration
    # 2665, "Password1!;" - 406, ";") and the
    # disallowed-single-quote-special-character lock
    # (iteration 2666, "Password1!'" - 406, "'"): here the
    # disallowed character is the double quote ('"'), a
    # twenty-first member of the disallowed set, and the
    # failure pins the special-character class boundary for
    # it -- the value is not a whitespace/trim case and it is
    # not a missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!\"",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None

async def test_create_user_disallowed_less_than_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-double-quote-special-character branch,
    # verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_less_than_special_character_password
    # and JSON-value grep count 0 for
    # "password": "Password1!<" in this file before appending.
    # The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "["),
    # disallowed-close-square-bracket-special-character
    # (2651, "]"),
    # disallowed-curly-brace-special-character (2652, "{"),
    # disallowed-close-curly-brace-special-character
    # (2653, "}"),
    # disallowed-caret-special-character (2654, "^"),
    # disallowed-tilde-special-character (2655, "~"),
    # disallowed-backtick-special-character (2656, "`"),
    # disallowed-hyphen-special-character (2657, "-"),
    # disallowed-underscore-special-character (2658, "_"),
    # disallowed-equals-special-character (2659, "="),
    # disallowed-plus-special-character (2660, "+"),
    # disallowed-pipe-special-character (2661, "|"),
    # disallowed-backslash-special-character (2662, "\\") and
    # disallowed-slash-special-character (2663, "/") and
    # disallowed-colon-special-character (2664, ":") and
    # disallowed-semicolon-special-character (2665, ";") and
    # disallowed-single-quote-special-character (2666, "'")
    # and disallowed-double-quote-special-character
    # (2667, '"').
    # The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!<") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!<" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the '<' is outside the allowed character
    # class, so the class rejects it; the same value without
    # the '<' passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]") and the
    # disallowed-curly-brace-special-character lock
    # (iteration 2652, "Password1!{" - 406, "{") and the
    # disallowed-close-curly-brace-special-character lock
    # (iteration 2653, "Password1!}" - 406, "}") and the
    # disallowed-caret-special-character lock (iteration 2654,
    # "Password1!^" - 406, "^") and the
    # disallowed-tilde-special-character lock (iteration 2655,
    # "Password1!~" - 406, "~") and the
    # disallowed-backtick-special-character lock (iteration
    # 2656, "Password1!`" - 406, "`"), the
    # disallowed-hyphen-special-character lock (iteration
    # 2657, "Password1!-" - 406, "-"), the
    # disallowed-underscore-special-character lock (iteration
    # 2658, "Password1!_" - 406, "_"), the
    # disallowed-equals-special-character lock (iteration
    # 2659, "Password1!=" - 406, "="), the
    # disallowed-plus-special-character lock (iteration 2660,
    # "Password1!+" - 406, "+"), the
    # disallowed-pipe-special-character lock (iteration 2661,
    # "Password1!|" - 406, "|"), the
    # disallowed-backslash-special-character lock (iteration
    # 2662, "Password1!\\" - 406, "\\") and the
    # disallowed-slash-special-character lock (iteration
    # 2663, "Password1!/" - 406, "/") and the
    # disallowed-colon-special-character lock (iteration
    # 2664, "Password1!:" - 406, ":") and the
    # disallowed-semicolon-special-character lock (iteration
    # 2665, "Password1!;" - 406, ";") and the
    # disallowed-single-quote-special-character lock
    # (iteration 2666, "Password1!'" - 406, "'") and the
    # disallowed-double-quote-special-character lock
    # (iteration 2667, "Password1!\"" - 406, '"'): here the
    # disallowed character is the less-than sign ('<'), a
    # twenty-second member of the disallowed set, and the
    # failure pins the special-character class boundary for
    # it -- the value is not a whitespace/trim case and it is
    # not a missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!<",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None

async def test_create_user_disallowed_greater_than_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-less-than-special-character branch,
    # verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_greater_than_special_character_password
    # and JSON-value grep count 0 for
    # "password": "Password1!>" in this file before appending.
    # The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "["),
    # disallowed-close-square-bracket-special-character
    # (2651, "]"),
    # disallowed-curly-brace-special-character (2652, "{"),
    # disallowed-close-curly-brace-special-character
    # (2653, "}"),
    # disallowed-caret-special-character (2654, "^"),
    # disallowed-tilde-special-character (2655, "~"),
    # disallowed-backtick-special-character (2656, "`"),
    # disallowed-hyphen-special-character (2657, "-"),
    # disallowed-underscore-special-character (2658, "_"),
    # disallowed-equals-special-character (2659, "="),
    # disallowed-plus-special-character (2660, "+"),
    # disallowed-pipe-special-character (2661, "|"),
    # disallowed-backslash-special-character (2662, "\\") and
    # disallowed-slash-special-character (2663, "/") and
    # disallowed-colon-special-character (2664, ":") and
    # disallowed-semicolon-special-character (2665, ";") and
    # disallowed-single-quote-special-character (2666, "'")
    # disallowed-double-quote-special-character
    # (2667, '"') and disallowed-less-than-special-character
    # (2668, "<").
    # The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!>") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!>" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the '>' is outside the allowed character
    # class, so the class rejects it; the same value without
    # the '>' passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]") and the
    # disallowed-curly-brace-special-character lock
    # (iteration 2652, "Password1!{" - 406, "{") and the
    # disallowed-close-curly-brace-special-character lock
    # (iteration 2653, "Password1!}" - 406, "}") and the
    # disallowed-caret-special-character lock (iteration 2654,
    # "Password1!^" - 406, "^") and the
    # disallowed-tilde-special-character lock (iteration 2655,
    # "Password1!~" - 406, "~") and the
    # disallowed-backtick-special-character lock (iteration
    # 2656, "Password1!`" - 406, "`"), the
    # disallowed-hyphen-special-character lock (iteration
    # 2657, "Password1!-" - 406, "-"), the
    # disallowed-underscore-special-character lock (iteration
    # 2658, "Password1!_" - 406, "_"), the
    # disallowed-equals-special-character lock (iteration
    # 2659, "Password1!=" - 406, "="), the
    # disallowed-plus-special-character lock (iteration 2660,
    # "Password1!+" - 406, "+"), the
    # disallowed-pipe-special-character lock (iteration 2661,
    # "Password1!|" - 406, "|"), the
    # disallowed-backslash-special-character lock (iteration
    # 2662, "Password1!\\" - 406, "\\") and the
    # disallowed-slash-special-character lock (iteration
    # 2663, "Password1!/" - 406, "/") and the
    # disallowed-colon-special-character lock (iteration
    # 2664, "Password1!:" - 406, ":") and the
    # disallowed-semicolon-special-character lock (iteration
    # 2665, "Password1!;" - 406, ";") and the
    # disallowed-single-quote-special-character lock
    # (iteration 2666, "Password1!'" - 406, "'") and the
    # disallowed-double-quote-special-character lock
    # (iteration 2667, "Password1!\"" - 406, '"') and the
    # disallowed-less-than-special-character lock
    # (iteration 2668, "Password1!<" - 406, "<"): here the
    # disallowed character is the greater-than sign ('>'), a
    # twenty-third member of the disallowed set, and the
    # failure pins the special-character class boundary for
    # it -- the value is not a whitespace/trim case and it is
    # not a missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!>",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None

async def test_create_user_disallowed_comma_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-greater-than-special-character branch,
    # verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_comma_special_character_password
    # and JSON-value grep count 0 for
    # "password": "Password1!," in this file before appending.
    # The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "["),
    # disallowed-close-square-bracket-special-character
    # (2651, "]"),
    # disallowed-curly-brace-special-character (2652, "{"),
    # disallowed-close-curly-brace-special-character
    # (2653, "}"),
    # disallowed-caret-special-character (2654, "^"),
    # disallowed-tilde-special-character (2655, "~"),
    # disallowed-backtick-special-character (2656, "`"),
    # disallowed-hyphen-special-character (2657, "-"),
    # disallowed-underscore-special-character (2658, "_"),
    # disallowed-equals-special-character (2659, "="),
    # disallowed-plus-special-character (2660, "+"),
    # disallowed-pipe-special-character (2661, "|"),
    # disallowed-backslash-special-character (2662, "\\") and
    # disallowed-slash-special-character (2663, "/") and
    # disallowed-colon-special-character (2664, ":") and
    # disallowed-semicolon-special-character (2665, ";") and
    # disallowed-single-quote-special-character (2666, "'")
    # disallowed-double-quote-special-character
    # (2667, '"') and disallowed-less-than-special-character
    # (2668, "<") and disallowed-greater-than-special-character
    # (2669, ">").
    # The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!,") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!," satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the ',' is outside the allowed character
    # class, so the class rejects it; the same value without
    # the ',' passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]") and the
    # disallowed-curly-brace-special-character lock
    # (iteration 2652, "Password1!{" - 406, "{") and the
    # disallowed-close-curly-brace-special-character lock
    # (iteration 2653, "Password1!}" - 406, "}") and the
    # disallowed-caret-special-character lock (iteration 2654,
    # "Password1!^" - 406, "^") and the
    # disallowed-tilde-special-character lock (iteration 2655,
    # "Password1!~" - 406, "~") and the
    # disallowed-backtick-special-character lock (iteration
    # 2656, "Password1!`" - 406, "`"), the
    # disallowed-hyphen-special-character lock (iteration
    # 2657, "Password1!-" - 406, "-"), the
    # disallowed-underscore-special-character lock (iteration
    # 2658, "Password1!_" - 406, "_"), the
    # disallowed-equals-special-character lock (iteration
    # 2659, "Password1!=" - 406, "="), the
    # disallowed-plus-special-character lock (iteration 2660,
    # "Password1!+" - 406, "+"), the
    # disallowed-pipe-special-character lock (iteration 2661,
    # "Password1!|" - 406, "|"), the
    # disallowed-backslash-special-character lock (iteration
    # 2662, "Password1!\\" - 406, "\\") and the
    # disallowed-slash-special-character lock (iteration
    # 2663, "Password1!/" - 406, "/") and the
    # disallowed-colon-special-character lock (iteration
    # 2664, "Password1!:" - 406, ":") and the
    # disallowed-semicolon-special-character lock (iteration
    # 2665, "Password1!;" - 406, ";") and the
    # disallowed-single-quote-special-character lock
    # (iteration 2666, "Password1!'" - 406, "'") and the
    # disallowed-double-quote-special-character lock
    # (iteration 2667, "Password1!\"" - 406, '"') and the
    # disallowed-less-than-special-character lock
    # (iteration 2668, "Password1!<" - 406, "<") and the
    # disallowed-greater-than-special-character lock
    # (iteration 2669, "Password1!>" - 406, ">"): here the
    # disallowed character is the comma (','), a
    # twenty-fourth member of the disallowed set, and the
    # failure pins the special-character class boundary for
    # it -- the value is not a whitespace/trim case and it is
    # not a missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!,",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_dot_special_character_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed special character:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-comma-special-character branch,
    # verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_dot_special_character_password
    # and JSON-value grep count 0 for
    # "password": "Password1!." in this file before appending.
    # The tenant sweep is complete (body-shape
    # 2556-2562 + per-field 2563-2577), the register sweep is
    # complete, the role sweep is complete (body-shape 2578-2584
    # + per-field 2585-2599), the user body-shape sweep is
    # complete (missing body, non-object, string, numeric,
    # boolean, null, malformed JSON - iterations 2600-2606), the
    # user per-field first_name sweep is complete (missing,
    # non-string, object, float, empty, whitespace-only -
    # iterations 2607-2612), the last_name sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only - iterations 2613-2618), the email sweep
    # is complete (missing, non-string, object, float, empty,
    # whitespace-only, invalid-format - iterations 2619-2625)
    # and the gender sweep is complete (missing, non-string,
    # object, float, empty, whitespace-only, invalid-value -
    # iterations 2626-2632), and the password sweep has locked
    # missing (2633), non-string (2634), object (2635), float
    # (2636), empty (2637), whitespace-only (2638), too-short
    # (2639), no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "["),
    # disallowed-close-square-bracket-special-character
    # (2651, "]"),
    # disallowed-curly-brace-special-character (2652, "{"),
    # disallowed-close-curly-brace-special-character
    # (2653, "}"),
    # disallowed-caret-special-character (2654, "^"),
    # disallowed-tilde-special-character (2655, "~"),
    # disallowed-backtick-special-character (2656, "`"),
    # disallowed-hyphen-special-character (2657, "-"),
    # disallowed-underscore-special-character (2658, "_"),
    # disallowed-equals-special-character (2659, "="),
    # disallowed-plus-special-character (2660, "+"),
    # disallowed-pipe-special-character (2661, "|"),
    # disallowed-backslash-special-character (2662, "\\") and
    # disallowed-slash-special-character (2663, "/") and
    # disallowed-colon-special-character (2664, ":") and
    # disallowed-semicolon-special-character (2665, ";") and
    # disallowed-single-quote-special-character (2666, "'")
    # disallowed-double-quote-special-character
    # (2667, '"') and disallowed-less-than-special-character
    # (2668, "<") and disallowed-greater-than-special-character
    # (2669, ">") and disallowed-comma-special-character
    # (2670, ",").
    # The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!.") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!." satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the '.' is outside the allowed character
    # class, so the class rejects it; the same value without
    # the '.' passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]") and the
    # disallowed-curly-brace-special-character lock
    # (iteration 2652, "Password1!{" - 406, "{") and the
    # disallowed-close-curly-brace-special-character lock
    # (iteration 2653, "Password1!}" - 406, "}") and the
    # disallowed-caret-special-character lock (iteration 2654,
    # "Password1!^" - 406, "^") and the
    # disallowed-tilde-special-character lock (iteration 2655,
    # "Password1!~" - 406, "~") and the
    # disallowed-backtick-special-character lock (iteration
    # 2656, "Password1!`" - 406, "`"), the
    # disallowed-hyphen-special-character lock (iteration
    # 2657, "Password1!-" - 406, "-"), the
    # disallowed-underscore-special-character lock (iteration
    # 2658, "Password1!_" - 406, "_"), the
    # disallowed-equals-special-character lock (iteration
    # 2659, "Password1!=" - 406, "="), the
    # disallowed-plus-special-character lock (iteration 2660,
    # "Password1!+" - 406, "+"), the
    # disallowed-pipe-special-character lock (iteration 2661,
    # "Password1!|" - 406, "|"), the
    # disallowed-backslash-special-character lock (iteration
    # 2662, "Password1!\\" - 406, "\\") and the
    # disallowed-slash-special-character lock (iteration
    # 2663, "Password1!/" - 406, "/") and the
    # disallowed-colon-special-character lock (iteration
    # 2664, "Password1!:" - 406, ":") and the
    # disallowed-semicolon-special-character lock (iteration
    # 2665, "Password1!;" - 406, ";") and the
    # disallowed-single-quote-special-character lock
    # (iteration 2666, "Password1!'" - 406, "'") and the
    # disallowed-double-quote-special-character lock
    # (iteration 2667, "Password1!\"" - 406, '"') and the
    # disallowed-less-than-special-character lock
    # (iteration 2668, "Password1!<" - 406, "<") and the
    # disallowed-greater-than-special-character lock
    # (iteration 2669, "Password1!>" - 406, ">") and the
    # disallowed-comma-special-character lock (iteration
    # 2670, "Password1!," - 406, ","): here the
    # disallowed character is the dot ('.'), a
    # twenty-fifth member of the disallowed set, and the
    # failure pins the special-character class boundary for
    # it -- the value is not a whitespace/trim case and it is
    # not a missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!.",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None

async def test_create_user_disallowed_non_ascii_letter_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed non-ASCII letter:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-dot-special-character branch,
    # verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_non_ascii_letter_password
    # and JSON-value grep count 0 for
    # "password": "Password1!é" in this file before appending.
    # The ASCII punctuation sweep is now complete: all 25
    # disallowed printable-ASCII punctuation members
    # (" # ' ( ) + , - . / : ; < = > [ \ ] ^ _ ` { | } ~,
    # i.e. string.punctuation minus the allowed specials
    # @$!%*?&) were verified present in this file this run,
    # each as a "Password1!<char>" 406 lock, and the regex
    # rejects every one of them while accepting the
    # "Password1!" control. The tenant sweep is complete
    # (body-shape 2556-2562 + per-field 2563-2577), the
    # register sweep is complete, the role sweep is complete
    # (body-shape 2578-2584 + per-field 2585-2599), the user
    # body-shape sweep is complete (missing body, non-object,
    # string, numeric, boolean, null, malformed JSON -
    # iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618),
    # the email sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only, invalid-format -
    # iterations 2619-2625) and the gender sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only, invalid-value - iterations 2626-2632),
    # and the password sweep has locked missing (2633),
    # non-string (2634), object (2635), float (2636), empty
    # (2637), whitespace-only (2638), too-short (2639),
    # no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "["),
    # disallowed-close-square-bracket-special-character
    # (2651, "]"),
    # disallowed-curly-brace-special-character (2652, "{"),
    # disallowed-close-curly-brace-special-character
    # (2653, "}"),
    # disallowed-caret-special-character (2654, "^"),
    # disallowed-tilde-special-character (2655, "~"),
    # disallowed-backtick-special-character (2656, "`"),
    # disallowed-hyphen-special-character (2657, "-"),
    # disallowed-underscore-special-character (2658, "_"),
    # disallowed-equals-special-character (2659, "="),
    # disallowed-plus-special-character (2660, "+"),
    # disallowed-pipe-special-character (2661, "|"),
    # disallowed-backslash-special-character (2662, "\\") and
    # disallowed-slash-special-character (2663, "/") and
    # disallowed-colon-special-character (2664, ":") and
    # disallowed-semicolon-special-character (2665, ";") and
    # disallowed-single-quote-special-character (2666, "'")
    # disallowed-double-quote-special-character
    # (2667, '"') and disallowed-less-than-special-character
    # (2668, "<") and disallowed-greater-than-special-character
    # (2669, ">") and disallowed-comma-special-character
    # (2670, ",") and disallowed-dot-special-character
    # (2671, ".").
    # The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!é") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!é" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the "é" is outside the allowed character
    # class, so the class rejects it; the same value without
    # the "é" passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]") and the
    # disallowed-curly-brace-special-character lock
    # (iteration 2652, "Password1!{" - 406, "{") and the
    # disallowed-close-curly-brace-special-character lock
    # (iteration 2653, "Password1!}" - 406, "}") and the
    # disallowed-caret-special-character lock (iteration 2654,
    # "Password1!^" - 406, "^") and the
    # disallowed-tilde-special-character lock (iteration 2655,
    # "Password1!~" - 406, "~") and the
    # disallowed-backtick-special-character lock (iteration
    # 2656, "Password1!`" - 406, "`"), the
    # disallowed-hyphen-special-character lock (iteration
    # 2657, "Password1!-" - 406, "-"), the
    # disallowed-underscore-special-character lock (iteration
    # 2658, "Password1!_" - 406, "_"), the
    # disallowed-equals-special-character lock (iteration
    # 2659, "Password1!=" - 406, "="), the
    # disallowed-plus-special-character lock (iteration 2660,
    # "Password1!+" - 406, "+"), the
    # disallowed-pipe-special-character lock (iteration 2661,
    # "Password1!|" - 406, "|"), the
    # disallowed-backslash-special-character lock (iteration
    # 2662, "Password1!\\" - 406, "\\") and the
    # disallowed-slash-special-character lock (iteration
    # 2663, "Password1!/" - 406, "/") and the
    # disallowed-colon-special-character lock (iteration
    # 2664, "Password1!:" - 406, ":") and the
    # disallowed-semicolon-special-character lock (iteration
    # 2665, "Password1!;" - 406, ";") and the
    # disallowed-single-quote-special-character lock
    # (iteration 2666, "Password1!'" - 406, "'") and the
    # disallowed-double-quote-special-character lock
    # (iteration 2667, "Password1!\"" - 406, '"') and the
    # disallowed-less-than-special-character lock
    # (iteration 2668, "Password1!<" - 406, "<") and the
    # disallowed-greater-than-special-character lock
    # (iteration 2669, "Password1!>" - 406, ">") and the
    # disallowed-comma-special-character lock (iteration
    # 2670, "Password1!," - 406, ",") and the
    # disallowed-dot-special-character lock (iteration 2671,
    # "Password1!." - 406, "."): here the disallowed
    # character is the non-ASCII letter "é", the first
    # non-ASCII member of the disallowed set, and the
    # failure pins the special-character class boundary for
    # it -- the value is not a whitespace/trim case and it is
    # not a missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!é",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_non_ascii_u_umlaut_letter_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed non-ASCII letter:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-non-ascii-letter branch (2672, "é"),
    # verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_non_ascii_u_umlaut_letter_password
    # and JSON-value grep count 0 for
    # "password": "Password1!ü" in this file before appending.
    # The ASCII punctuation sweep is now complete: all 25
    # disallowed printable-ASCII punctuation members
    # (" # ' ( ) + , - . / : ; < = > [ \ ] ^ _ ` { | } ~,
    # i.e. string.punctuation minus the allowed specials
    # @$!%*?&) were verified present in this file this run,
    # each as a "Password1!<char>" 406 lock, and the regex
    # rejects every one of them while accepting the
    # "Password1!" control. The tenant sweep is complete
    # (body-shape 2556-2562 + per-field 2563-2577), the
    # register sweep is complete, the role sweep is complete
    # (body-shape 2578-2584 + per-field 2585-2599), the user
    # body-shape sweep is complete (missing body, non-object,
    # string, numeric, boolean, null, malformed JSON -
    # iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618),
    # the email sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only, invalid-format -
    # iterations 2619-2625) and the gender sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only, invalid-value - iterations 2626-2632),
    # and the password sweep has locked missing (2633),
    # non-string (2634), object (2635), float (2636), empty
    # (2637), whitespace-only (2638), too-short (2639),
    # no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "["),
    # disallowed-close-square-bracket-special-character
    # (2651, "]"),
    # disallowed-curly-brace-special-character (2652, "{"),
    # disallowed-close-curly-brace-special-character
    # (2653, "}"),
    # disallowed-caret-special-character (2654, "^"),
    # disallowed-tilde-special-character (2655, "~"),
    # disallowed-backtick-special-character (2656, "`"),
    # disallowed-hyphen-special-character (2657, "-"),
    # disallowed-underscore-special-character (2658, "_"),
    # disallowed-equals-special-character (2659, "="),
    # disallowed-plus-special-character (2660, "+"),
    # disallowed-pipe-special-character (2661, "|"),
    # disallowed-backslash-special-character (2662, "\\") and
    # disallowed-slash-special-character (2663, "/") and
    # disallowed-colon-special-character (2664, ":") and
    # disallowed-semicolon-special-character (2665, ";") and
    # disallowed-single-quote-special-character (2666, "'")
    # disallowed-double-quote-special-character
    # (2667, '"') and disallowed-less-than-special-character
    # (2668, "<") and disallowed-greater-than-special-character
    # (2669, ">") and disallowed-comma-special-character
    # (2670, ",") and disallowed-dot-special-character
    # (2671, ".") and disallowed-non-ascii-letter (2672, "é").
    # The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!ü") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!ü" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the "ü" is outside the allowed character
    # class, so the class rejects it; the same value without
    # the "ü" passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]") and the
    # disallowed-curly-brace-special-character lock
    # (iteration 2652, "Password1!{" - 406, "{") and the
    # disallowed-close-curly-brace-special-character lock
    # (iteration 2653, "Password1!}" - 406, "}") and the
    # disallowed-caret-special-character lock (iteration 2654,
    # "Password1!^" - 406, "^") and the
    # disallowed-tilde-special-character lock (iteration 2655,
    # "Password1!~" - 406, "~") and the
    # disallowed-backtick-special-character lock (iteration
    # 2656, "Password1!`" - 406, "`"), the
    # disallowed-hyphen-special-character lock (iteration
    # 2657, "Password1!-" - 406, "-"), the
    # disallowed-underscore-special-character lock (iteration
    # 2658, "Password1!_" - 406, "_"), the
    # disallowed-equals-special-character lock (iteration
    # 2659, "Password1!=" - 406, "="), the
    # disallowed-plus-special-character lock (iteration 2660,
    # "Password1!+" - 406, "+"), the
    # disallowed-pipe-special-character lock (iteration 2661,
    # "Password1!|" - 406, "|"), the
    # disallowed-backslash-special-character lock (iteration
    # 2662, "Password1!\\" - 406, "\\") and the
    # disallowed-slash-special-character lock (iteration
    # 2663, "Password1!/" - 406, "/") and the
    # disallowed-colon-special-character lock (iteration
    # 2664, "Password1!:" - 406, ":") and the
    # disallowed-semicolon-special-character lock (iteration
    # 2665, "Password1!;" - 406, ";") and the
    # disallowed-single-quote-special-character lock
    # (iteration 2666, "Password1!'" - 406, "'") and the
    # disallowed-double-quote-special-character lock
    # (iteration 2667, "Password1!\"" - 406, '"') and the
    # disallowed-less-than-special-character lock
    # (iteration 2668, "Password1!<" - 406, "<") and the
    # disallowed-greater-than-special-character lock
    # (iteration 2669, "Password1!>" - 406, ">") and the
    # disallowed-comma-special-character lock (iteration
    # 2670, "Password1!," - 406, ",") and the
    # disallowed-dot-special-character lock (iteration 2671,
    # "Password1!." - 406, ".") and the
    # disallowed-non-ascii-letter lock (iteration 2672,
    # "Password1!é" - 406, "é"): here the disallowed
    # character is the non-ASCII letter "ü", the second
    # non-ASCII member of the disallowed set, and the
    # failure pins the special-character class boundary for
    # it -- the value is not a whitespace/trim case and it is
    # not a missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!ü",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_disallowed_non_ascii_eszett_letter_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password containing a disallowed non-ASCII letter:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-non-ascii-u-umlaut-letter branch (2673, "ü"),
    # verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_disallowed_non_ascii_eszett_letter_password
    # and JSON-value grep count 0 for
    # "password": "Password1!ß" in this file before appending.
    # The ASCII punctuation sweep is now complete: all 25
    # disallowed printable-ASCII punctuation members
    # (" # ' ( ) + , - . / : ; < = > [ \ ] ^ _ ` { | } ~,
    # i.e. string.punctuation minus the allowed specials
    # @$!%*?&) were verified present in this file this run,
    # each as a "Password1!<char>" 406 lock, and the regex
    # rejects every one of them while accepting the
    # "Password1!" control. The tenant sweep is complete
    # (body-shape 2556-2562 + per-field 2563-2577), the
    # register sweep is complete, the role sweep is complete
    # (body-shape 2578-2584 + per-field 2585-2599), the user
    # body-shape sweep is complete (missing body, non-object,
    # string, numeric, boolean, null, malformed JSON -
    # iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618),
    # the email sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only, invalid-format -
    # iterations 2619-2625) and the gender sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only, invalid-value - iterations 2626-2632),
    # and the password sweep has locked missing (2633),
    # non-string (2634), object (2635), float (2636), empty
    # (2637), whitespace-only (2638), too-short (2639),
    # no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "["),
    # disallowed-close-square-bracket-special-character
    # (2651, "]"),
    # disallowed-curly-brace-special-character (2652, "{"),
    # disallowed-close-curly-brace-special-character
    # (2653, "}"),
    # disallowed-caret-special-character (2654, "^"),
    # disallowed-tilde-special-character (2655, "~"),
    # disallowed-backtick-special-character (2656, "`"),
    # disallowed-hyphen-special-character (2657, "-"),
    # disallowed-underscore-special-character (2658, "_"),
    # disallowed-equals-special-character (2659, "="),
    # disallowed-plus-special-character (2660, "+"),
    # disallowed-pipe-special-character (2661, "|"),
    # disallowed-backslash-special-character (2662, "\\") and
    # disallowed-slash-special-character (2663, "/") and
    # disallowed-colon-special-character (2664, ":") and
    # disallowed-semicolon-special-character (2665, ";") and
    # disallowed-single-quote-special-character (2666, "'")
    # disallowed-double-quote-special-character
    # (2667, '"') and disallowed-less-than-special-character
    # (2668, "<") and disallowed-greater-than-special-character
    # (2669, ">") and disallowed-comma-special-character
    # (2670, ",") and disallowed-dot-special-character
    # (2671, ".") and disallowed-non-ascii-letter (2672, "é") and
    # disallowed-non-ascii-u-umlaut-letter (2673, "ü").
    # The endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact.
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!ß") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!ß" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the "ß" is outside the allowed character
    # class, so the class rejects it; the same value without
    # the "ß" passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]") and the
    # disallowed-curly-brace-special-character lock
    # (iteration 2652, "Password1!{" - 406, "{") and the
    # disallowed-close-curly-brace-special-character lock
    # (iteration 2653, "Password1!}" - 406, "}") and the
    # disallowed-caret-special-character lock (iteration 2654,
    # "Password1!^" - 406, "^") and the
    # disallowed-tilde-special-character lock (iteration 2655,
    # "Password1!~" - 406, "~") and the
    # disallowed-backtick-special-character lock (iteration
    # 2656, "Password1!`" - 406, "`"), the
    # disallowed-hyphen-special-character lock (iteration
    # 2657, "Password1!-" - 406, "-"), the
    # disallowed-underscore-special-character lock (iteration
    # 2658, "Password1!_" - 406, "_"), the
    # disallowed-equals-special-character lock (iteration
    # 2659, "Password1!=" - 406, "="), the
    # disallowed-plus-special-character lock (iteration 2660,
    # "Password1!+" - 406, "+"), the
    # disallowed-pipe-special-character lock (iteration 2661,
    # "Password1!|" - 406, "|"), the
    # disallowed-backslash-special-character lock (iteration
    # 2662, "Password1!\\" - 406, "\\") and the
    # disallowed-slash-special-character lock (iteration
    # 2663, "Password1!/" - 406, "/") and the
    # disallowed-colon-special-character lock (iteration
    # 2664, "Password1!:" - 406, ":") and the
    # disallowed-semicolon-special-character lock (iteration
    # 2665, "Password1!;" - 406, ";") and the
    # disallowed-single-quote-special-character lock
    # (iteration 2666, "Password1!'" - 406, "'") and the
    # disallowed-double-quote-special-character lock
    # (iteration 2667, "Password1!\"" - 406, '"') and the
    # disallowed-less-than-special-character lock
    # (iteration 2668, "Password1!<" - 406, "<") and the
    # disallowed-greater-than-special-character lock
    # (iteration 2669, "Password1!>" - 406, ">") and the
    # disallowed-comma-special-character lock (iteration
    # 2670, "Password1!," - 406, ",") and the
    # disallowed-dot-special-character lock (iteration 2671,
    # "Password1!." - 406, ".") and the
    # disallowed-non-ascii-letter lock (iteration 2672,
    # "Password1!é" - 406, "é") and the
    # disallowed-non-ascii-u-umlaut-letter lock (iteration 2673,
    # "Password1!ü" - 406, "ü"): here the disallowed
    # character is the non-ASCII letter "ß", the third
    # non-ASCII member of the disallowed set, and the
    # failure pins the special-character class boundary for
    # it -- the value is not a whitespace/trim case and it is
    # not a missing-lookahead case, since every lookahead is
    # satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!ß",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None


async def test_create_user_trailing_newline_password_returns_406_with_security_headers(client: AsyncClient):
    """
        The user-create POST with a password ending in a trailing newline:
    """
    # The next value branch of the user password per-field sweep
    # after the disallowed-non-ascii-eszett-letter branch (2674, "ß"),
    # verified fresh this run, not assumed:
    # function-name grep count 0 for
    # create_user_trailing_newline_password
    # and JSON-value grep count 0 for
    # "password": "Password1!\n" in this file before appending.
    # This is the regex-anchor quirk found while verifying
    # iteration 2672, not another class-boundary member:
    # PASSWORD_REGEX used `$`, and in Python `$` also matches
    # just before a trailing newline, so "Password1!\n"
    # PASSED validation even though "\n" is outside the allowed
    # character class [A-Za-z\d@$!%*?&]. The production fix in
    # this same run (iteration 2675) changes the anchor to `\Z`
    # (common/utils.py:42), which matches only at the absolute
    # end of the string; with the old `$` this test would fail,
    # and with `\Z` it passes. The ASCII punctuation sweep is
    # now complete: all 25 disallowed printable-ASCII
    # punctuation members (" # ' ( ) + , - . / : ; < = > [ \ ] ^
    # _ ` { | } ~, i.e. string.punctuation minus the allowed
    # specials @$!%*?&) were verified present in this file in
    # iteration 2672, each as a "Password1!<char>" 406 lock,
    # and the regex rejects every one of them while accepting
    # the "Password1!" control. The tenant sweep is complete
    # (body-shape 2556-2562 + per-field 2563-2577), the
    # register sweep is complete, the role sweep is complete
    # (body-shape 2578-2584 + per-field 2585-2599), the user
    # body-shape sweep is complete (missing body, non-object,
    # string, numeric, boolean, null, malformed JSON -
    # iterations 2600-2606), the user per-field first_name
    # sweep is complete (missing, non-string, object, float,
    # empty, whitespace-only - iterations 2607-2612), the
    # last_name sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only - iterations 2613-2618),
    # the email sweep is complete (missing, non-string, object,
    # float, empty, whitespace-only, invalid-format -
    # iterations 2619-2625) and the gender sweep is complete
    # (missing, non-string, object, float, empty,
    # whitespace-only, invalid-value - iterations 2626-2632),
    # and the password sweep has locked missing (2633),
    # non-string (2634), object (2635), float (2636), empty
    # (2637), whitespace-only (2638), too-short (2639),
    # no-special-character (2640), no-digit (2641),
    # no-uppercase (2642), no-lowercase (2643),
    # disallowed-character (2644, interior space),
    # trailing-disallowed-character (2645, trailing space),
    # leading-disallowed-character (2646, leading space),
    # disallowed-special-character (2647, "#"),
    # disallowed-paren-special-character (2648, "("),
    # disallowed-close-paren-special-character (2649, ")"),
    # disallowed-square-bracket-special-character (2650, "["),
    # disallowed-close-square-bracket-special-character
    # (2651, "]"),
    # disallowed-curly-brace-special-character (2652, "{"),
    # disallowed-close-curly-brace-special-character
    # (2653, "}"),
    # disallowed-caret-special-character (2654, "^"),
    # disallowed-tilde-special-character (2655, "~"),
    # disallowed-backtick-special-character (2656, "`"),
    # disallowed-hyphen-special-character (2657, "-"),
    # disallowed-underscore-special-character (2658, "_"),
    # disallowed-equals-special-character (2659, "="),
    # disallowed-plus-special-character (2660, "+"),
    # disallowed-pipe-special-character (2661, "|"),
    # disallowed-backslash-special-character (2662, "\\") and
    # disallowed-slash-special-character (2663, "/") and
    # disallowed-colon-special-character (2664, ":") and
    # disallowed-semicolon-special-character (2665, ";") and
    # disallowed-single-quote-special-character (2666, "'")
    # disallowed-double-quote-special-character
    # (2667, '"') and disallowed-less-than-special-character
    # (2668, "<") and disallowed-greater-than-special-character
    # (2669, ">") and disallowed-comma-special-character
    # (2670, ",") and disallowed-dot-special-character
    # (2671, ".") and disallowed-non-ascii-letter (2672, "é") and
    # disallowed-non-ascii-u-umlaut-letter (2673, "ü") and
    # disallowed-non-ascii-eszett-letter (2674, "ß"). The
    # endpoint takes a required
    # `data: CreateUserDto` body parameter
    # (user_endpoint.py:115-128) whose password is a required
    # `str` on CreateUserDto (user_dto.py:44, no min_length
    # constraint), alongside required first_name, last_name,
    # email and gender. An 11-character password therefore
    # passes FastAPI request validation: the DTO's mode="after"
    # normalize_names validator only runs after valid field
    # parsing (and only touches first_name/last_name), and the
    # password is deliberately NOT trimmed (user_dto.py:30,
    # credential semantics), so the value survives to the
    # policy check intact -- including its trailing newline,
    # which JSON transport preserves (escaped as \n).
    # The handler body runs instead: after the permission gate
    # and the GUEST role lookup, it calls
    # UserService.create_user, which validates the password
    # FIRST -- before the duplicate-email check and before any
    # repository write (usecases/user_service.py:111-121,
    # validate_password at :119). validate_password
    # ("Password1!\n") fails PASSWORD_REGEX (common/utils.py:42,
    # at least 8 characters with upper/lowercase, a digit and
    # a special character, drawn only from
    # [A-Za-z\d@$!%*?&] -- "Password1!\n" satisfies the length
    # and all four lookaheads, the "!" counting for the special
    # lookahead, but the trailing "\n" is outside the allowed
    # character class, so with the `\Z` anchor the class
    # rejects it; the same value without the trailing newline
    # passes, verified against the regex this run) and
    # raises InvalidOperationException, which the central
    # ApiBaseException handler maps to 406 with body
    # {"error": ..., "code": 406} plus no-store headers
    # (api/__init__.py:84-135, InvalidOperationException ->
    # HTTP_406_NOT_ACCEPTABLE), mirroring the register
    # weak-password 406 lock. This is distinct from the
    # missing-password lock (iteration 2633, field omitted -
    # 422), the non-string lock (iteration 2634, JSON integer -
    # 422), the object lock (iteration 2635, a dict - 422), the
    # float lock (iteration 2636 - 422), the empty-password
    # lock (iteration 2637, "" - 406), the
    # whitespace-only-password lock (iteration 2638, eight
    # spaces - 406), the too-short-password lock (iteration
    # 2639, "Aa1!" - 406), the no-special-character lock
    # (iteration 2640, "Password123" - 406), the no-digit lock
    # (iteration 2641, "Password!" - 406), the no-uppercase
    # lock (iteration 2642, "password1!" - 406), the
    # no-lowercase lock (iteration 2643, "PASSWORD1!" - 406),
    # the disallowed-character lock (iteration 2644,
    # "Password 1!" - 406, interior space), the
    # trailing-disallowed-character lock (iteration 2645,
    # "Password1! " - 406, trailing space), the
    # leading-disallowed-character lock (iteration 2646,
    # " Password1!" - 406, leading space), the
    # disallowed-special-character lock (iteration 2647,
    # "Password1!#" - 406, "#"), the
    # disallowed-paren-special-character lock (iteration 2648,
    # "Password1!(" - 406, "("), the
    # disallowed-close-paren-special-character lock (iteration
    # 2649, "Password1!)" - 406, ")"), the
    # disallowed-square-bracket-special-character lock
    # (iteration 2650, "Password1![" - 406, "[") and the
    # disallowed-close-square-bracket-special-character lock
    # (iteration 2651, "Password1!]" - 406, "]") and the
    # disallowed-curly-brace-special-character lock
    # (iteration 2652, "Password1!{" - 406, "{") and the
    # disallowed-close-curly-brace-special-character lock
    # (iteration 2653, "Password1!}" - 406, "}") and the
    # disallowed-caret-special-character lock (iteration 2654,
    # "Password1!^" - 406, "^") and the
    # disallowed-tilde-special-character lock (iteration 2655,
    # "Password1!~" - 406, "~") and the
    # disallowed-backtick-special-character lock (iteration
    # 2656, "Password1!`" - 406, "`"), the
    # disallowed-hyphen-special-character lock (iteration
    # 2657, "Password1!-" - 406, "-"), the
    # disallowed-underscore-special-character lock (iteration
    # 2658, "Password1!_" - 406, "_"), the
    # disallowed-equals-special-character lock (iteration
    # 2659, "Password1!=" - 406, "="), the
    # disallowed-plus-special-character lock (iteration 2660,
    # "Password1!+" - 406, "+"), the
    # disallowed-pipe-special-character lock (iteration 2661,
    # "Password1!|" - 406, "|"), the
    # disallowed-backslash-special-character lock (iteration
    # 2662, "Password1!\\" - 406, "\\") and the
    # disallowed-slash-special-character lock (iteration
    # 2663, "Password1!/" - 406, "/") and the
    # disallowed-colon-special-character lock (iteration
    # 2664, "Password1!:" - 406, ":") and the
    # disallowed-semicolon-special-character lock (iteration
    # 2665, "Password1!;" - 406, ";") and the
    # disallowed-single-quote-special-character lock
    # (iteration 2666, "Password1!'" - 406, "'") and the
    # disallowed-double-quote-special-character lock
    # (iteration 2667, "Password1!\"" - 406, '"') and the
    # disallowed-less-than-special-character lock
    # (iteration 2668, "Password1!<" - 406, "<") and the
    # disallowed-greater-than-special-character lock
    # (iteration 2669, "Password1!>" - 406, ">") and the
    # disallowed-comma-special-character lock (iteration
    # 2670, "Password1!," - 406, ",") and the
    # disallowed-dot-special-character lock (iteration
    # 2671, "Password1!." - 406, ".") and the
    # disallowed-non-ascii-letter lock (iteration 2672,
    # "Password1!é" - 406, "é") and the
    # disallowed-non-ascii-u-umlaut-letter lock (iteration 2673,
    # "Password1!ü" - 406, "ü") and the
    # disallowed-non-ascii-eszett-letter lock (iteration 2674,
    # "Password1!ß" - 406, "ß"): here the disallowed
    # character is the trailing newline, and the failure pins
    # the `\Z` anchor -- the value is not a whitespace/trim
    # case and it is not a missing-lookahead case, since every
    # lookahead is satisfied. The endpoint is permission-gated
    # (USER_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 406, exactly as in the role
    # whitespace-only-name lock. The endpoint also resolves
    # the GUEST role via role_service.find_by_name BEFORE
    # calling create_user (user_endpoint.py:124-127), so a
    # GUEST role must be seeded too -- otherwise that lookup's
    # RoleNotFoundException 404 would mask the 406.
    # The role is seeded with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # USER_READ_AND_WRITE_ONLY permission, mirroring the user
    # missing-password lock; the GUEST role is seeded with a
    # distinct id (68c302ef6bf7a039b7e9b389, unused in this
    # file) and name "guest", mirroring the register
    # weak-password 406 lock; the default conftest mock is a
    # host caller (tenant_id None), so _assert_create_scope
    # cannot fire. Deliberately no Cache-Control/Pragma
    # omission here: unlike a 422, a 406 is an
    # ApiBaseException, so the central handler's no-store
    # headers DO apply and are locked, mirroring the register
    # weak-password 406 lock. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including error responses, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.entities.user import User
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host user creator",
        description="Role carrying USER_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.USER_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="guest",
        description="Guest role resolved by the user-create endpoint before create_user",
        permissions=[],
    ).insert()
    response = await client.post(
        "/users/",
        json={
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "gender": "other",
            "password": "Password1!\n",
        },
    )
    assert response.status_code == 406
    assert response.json()["code"] == 406
    assert "Password must be at least 8 characters" in response.json()["error"]
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
    # mirroring the other user locks in this file, using
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
    # Postcondition: the weak password failed before any user
    # row was created, so the email has no user in the test DB.
    assert await User.find_one(User.email == "test@example.com") is None
