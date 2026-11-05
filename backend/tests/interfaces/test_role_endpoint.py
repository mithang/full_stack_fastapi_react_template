import pytest
from httpx import AsyncClient

from api.domain.dtos.role_dto import CreateRoleDto, CreateRoleResponseDto, RoleListDto, UpdateRoleDto, RoleDto
from api.domain.enum.permission import Permission


async def create_role(client: AsyncClient) -> CreateRoleResponseDto:
    new_role = CreateRoleDto(
        name="Test Role",
        description="A role for testing purposes",
    )
    response = await client.post("/roles/", json=new_role.model_dump())
    assert response.status_code == 201
    # The security-headers middleware (security_headers_middleware.py)
    # stamps every HTTP response, not just GETs, but until iteration
    # 1852 only GET responses and the user-create POST locked its
    # headers in — deleting the middleware registration would have
    # gone uncaught on role-create responses too. The test client
    # runs the real app over ASGI transport, so the pure-ASGI
    # middleware applies here exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, as on the
    # permissions GET in iteration 1865 and the user-create POST in
    # iteration 1866, using substring checks so later additions to
    # the list do not break this test. The full value lives in
    # _SECURITY_HEADERS. The fifth, clipboard-read, is safe to lock
    # here: the SPA never reads the clipboard (only writeText calls,
    # verified by grep in iteration 1914). The sixth, display-capture,
    # is safe to lock here: the SPA has no screen-sharing flow (zero
    # getDisplayMedia calls, verified by grep this run). The seventh,
    # fullscreen, is safe to lock here: the SPA has no fullscreen
    # flow (zero requestFullscreen calls and zero <video>/<audio>
    # elements, verified by grep this run). The eighth, accelerometer,
    # is safe to lock here: the SPA has no motion-sensor flow (zero
    # DeviceMotion/DeviceOrientation/Accelerometer/Gyroscope/
    # Magnetometer matches, verified by grep this run), and the
    # middleware value already contains accelerometer=(). The ninth,
    # gyroscope, is safe to lock here: the SPA has no gyroscope
    # flow (zero Gyroscope/DeviceOrientation uses, verified by grep
    # this run), so no sensor flow exists to break, and the
    # middleware value already contains gyroscope=(). The tenth,
    # magnetometer, is safe to lock here: the SPA has no compass
    # flow (zero Magnetometer matches, verified by grep this run),
    # so no sensor flow exists to break, and the middleware value
    # already contains magnetometer=(). The eleventh,
    # xr-spatial-tracking, is safe to lock here: the SPA has no XR
    # flow (zero navigator.xr/XRSession/XRSystem/immersive-ar/
    # immersive-vr/requestSession matches, verified by grep this
    # run, and no webxr/three dependency in package.json), so no
    # XR flow exists to break, and the middleware value already
    # contains xr-spatial-tracking=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    # immediately after xr-spatial-tracking=().
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    assert "accelerometer=()" in permissions_policy
    assert "gyroscope=()" in permissions_policy
    assert "magnetometer=()" in permissions_policy
    assert "xr-spatial-tracking=()" in permissions_policy
    assert "idle-detection=()" in permissions_policy
    return CreateRoleResponseDto.model_validate(response.json())


@pytest.mark.asyncio
async def test_list_roles_from_host(client: AsyncClient):
    """
        List all the roles:
    """
    response = await client.get("/roles/?skip=0&limit=10")
    assert response.status_code == 200
    # The endpoint comment requires this GET never to be served from a
    # browser or proxy cache (it lists roles with their permissions),
    # but no test locked the headers in — deleting the two header
    # lines would have gone uncaught, as with the app-configuration
    # GET in iteration 1785 and the tenant list GET in iteration 1786.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but only the permissions GET locked
    # its headers in (iteration 1820) — deleting the middleware
    # registration would have gone uncaught on this route too.
    # The test client runs the real app over ASGI transport, so the
    # pure-ASGI middleware applies here exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # tenant-list GET lock (iteration 1870), using substring checks
    # so later additions to the list do not break this test. The
    # full value lives in _SECURITY_HEADERS. The fifth, clipboard-read,
    # is safe to lock here: the SPA never reads the clipboard (only
    # writeText calls, verified by grep this run). The sixth,
    # display-capture, is safe to lock here: the SPA has no
    # screen-sharing flow (zero getDisplayMedia calls, verified by
    # grep this run). The seventh, fullscreen, is safe to lock here:
    # the SPA has no fullscreen flow (zero requestFullscreen calls
    # and zero <video>/<audio> elements, verified by grep this run).
    # The eighth, accelerometer, is safe to lock here: the SPA has no
    # motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer API uses, verified by grep this run). The ninth,
    # gyroscope, is safe to lock here: the SPA has no gyroscope
    # flow (zero Gyroscope/DeviceOrientation uses, verified by grep
    # this run), so no sensor flow exists to break, and the
    # middleware value already contains gyroscope=(). The tenth,
    # magnetometer, is safe to lock here: the SPA has no compass
    # flow (zero Magnetometer matches, verified by grep this run),
    # so no sensor flow exists to break, and the middleware value
    # already contains magnetometer=(). The eleventh,
    # xr-spatial-tracking, is safe to lock here: the SPA has no XR
    # flow (zero navigator.xr/XRSession/XRSystem/immersive-ar/
    # immersive-vr/requestSession matches, verified by grep this
    # run, and no webxr/three dependency in package.json), so no
    # XR flow exists to break, and the middleware value already
    # contains xr-spatial-tracking=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    # immediately after xr-spatial-tracking=().
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    assert "accelerometer=()" in permissions_policy
    assert "gyroscope=()" in permissions_policy
    assert "magnetometer=()" in permissions_policy
    assert "xr-spatial-tracking=()" in permissions_policy
    assert "idle-detection=()" in permissions_policy

    data = RoleListDto.model_validate(response.json())

    assert data.roles == []
    assert data.total == 0
    assert data.hasNext == False
    assert data.hasPrevious == False
    assert data.skip == 0
    assert data.limit == 10

@pytest.mark.asyncio
async def test_create_role_in_host(client: AsyncClient):
    """
        Create a new role:
    """
    new_role_response = await create_role(client)

    # Verify the role was created by listing roles again
    response = await client.get("/roles/?skip=0&limit=10")
    assert response.status_code == 200
    # The endpoint comment requires this GET never to be served from a
    # browser or proxy cache (it lists roles with their permissions),
    # but no test locked the headers in — deleting the two header
    # lines would have gone uncaught, as with the single-role
    # verification GET in iteration 1794 and the role list GET in
    # iteration 1787.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but only the role list GET locked
    # its headers in — deleting the middleware registration would
    # have gone uncaught on this verification GET too. The test
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
    # role-list GET lock (iteration 1882), using substring checks
    # so later additions to the list do not break this test. The
    # full value lives in _SECURITY_HEADERS. The fifth, clipboard-read,
    # is safe to lock here: the SPA never reads the clipboard (only
    # writeText calls, verified by grep this run). The sixth,
    # display-capture, is safe to lock here: the SPA has no
    # screen-sharing flow (zero getDisplayMedia calls, verified by
    # grep this run). The seventh,
    # fullscreen, is safe to lock here: the SPA has no fullscreen flow
    # (zero requestFullscreen calls and zero <video>/<audio> elements,
    # verified by grep this run). The eighth, accelerometer, is safe
    # to lock here: the SPA has no motion-sensor flow (zero
    # DeviceMotion/DeviceOrientation/Accelerometer/Gyroscope/
    # Magnetometer matches, verified by grep this run). The ninth,
    # gyroscope, is safe to lock here: the SPA has no gyroscope
    # flow (zero Gyroscope/DeviceOrientation matches, verified by
    # grep this run), and the middleware value already contains
    # gyroscope=(). The tenth, magnetometer, is safe to lock here:
    # the SPA has no compass flow (zero Magnetometer matches,
    # verified by grep this run), and the middleware value already
    # contains magnetometer=(). The eleventh,
    # xr-spatial-tracking, is safe to lock here: the SPA has no XR
    # flow (zero navigator.xr/XRSession/XRSystem/immersive-ar/
    # immersive-vr/requestSession matches, verified by grep this run),
    # and the middleware value already contains xr-spatial-tracking=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    # immediately after xr-spatial-tracking=().
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    assert "accelerometer=()" in permissions_policy
    assert "gyroscope=()" in permissions_policy
    assert "magnetometer=()" in permissions_policy
    assert "xr-spatial-tracking=()" in permissions_policy
    assert "idle-detection=()" in permissions_policy

    data = RoleListDto.model_validate(response.json())
    assert data.total == 1
    assert data.roles[0].id == new_role_response.id

@pytest.mark.asyncio
async def test_get_role_by_id_from_host(client: AsyncClient):
    """
        Get a role by ID:
    """
    new_role_response = await create_role(client)
    response = await client.get(f"/roles/{new_role_response.id}")
    assert response.status_code == 200
    # The endpoint comment requires this GET never to be served from a
    # browser or proxy cache (it returns a single role's name and
    # permissions), but no test locked the headers in — deleting the
    # two header lines would have gone uncaught, as with the user
    # single GET in iteration 1789, the user list GET in iteration
    # 1788, and the role list GET in iteration 1787.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but only the role list and
    # create-role verification GETs locked its headers in — deleting
    # the middleware registration would have gone uncaught on this
    # single-role GET too. The test client runs the real app over
    # ASGI transport, so the pure-ASGI middleware applies here
    # exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # role-list GET lock (iteration 1882), using substring checks
    # so later additions to the list do not break this test. The
    # full value lives in _SECURITY_HEADERS. The fifth, clipboard-read,
    # is safe to lock here: the SPA never reads the clipboard (only
    # writeText calls, verified by grep this run). The sixth,
    # display-capture, is safe to lock here: the SPA has no
    # screen-sharing flow (zero getDisplayMedia calls, verified by
    # grep this run). The seventh, fullscreen, is safe to lock here:
    # the SPA has no fullscreen flow (zero requestFullscreen calls
    # and zero <video>/<audio> elements, verified by grep this run).
    # The eighth, accelerometer, is safe to lock here: the SPA has no
    # motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer matches, verified by grep
    # this run). The ninth, gyroscope, is safe to lock here: the SPA
    # has no gyroscope flow (zero Gyroscope/gyroscope matches,
    # verified by grep this run). The tenth, magnetometer, is safe
    # to lock here: the SPA has no compass flow (zero Magnetometer/
    # magnetometer matches, verified by grep this run), and the
    # middleware value already contains magnetometer=(). The eleventh,
    # xr-spatial-tracking, is safe to lock here: the SPA has no XR
    # flow (zero navigator.xr/XRSession/XRSystem/immersive-ar/
    # immersive-vr/requestSession matches, verified by grep this
    # run, and no webxr/three dependency in package.json), so no
    # XR flow exists to break, and the middleware value already
    # contains xr-spatial-tracking=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    # immediately after xr-spatial-tracking=().
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    assert "accelerometer=()" in permissions_policy
    assert "gyroscope=()" in permissions_policy
    assert "magnetometer=()" in permissions_policy
    assert "xr-spatial-tracking=()" in permissions_policy
    assert "idle-detection=()" in permissions_policy

    data = RoleDto.model_validate(response.json())
    assert data.name == "Test Role"


@pytest.mark.asyncio
async def test_update_role_by_id_from_host(client: AsyncClient):
    """
        Update a role by ID:
    """
    new_role_response = await create_role(client)
    response = await client.get(f"/roles/{new_role_response.id}")
    assert response.status_code == 200
    # The endpoint comment requires this GET never to be served from a
    # browser or proxy cache (it returns a single role's name and
    # permissions), but no test locked the headers in — deleting the
    # two header lines would have gone uncaught, as with the single
    # role GET in iteration 1790 and the tenant search GETs in
    # iterations 1791-1792.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but only the role list, create-role
    # verification, and single-role GETs locked its headers in —
    # deleting the middleware registration would have gone uncaught
    # on this pre-update GET too. The test client runs the real app
    # over ASGI transport, so the pure-ASGI middleware applies here
    # exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the role-create default-permissions verification GET lock
    # (iteration 1888), using substring checks so later additions to
    # the list do not break this test. The full value lives in
    # _SECURITY_HEADERS. The fifth, clipboard-read, is safe to lock
    # here: the SPA never reads the clipboard (only writeText calls,
    # verified by grep this run). The sixth, display-capture,
    # is safe to lock here: the SPA has no screen-sharing flow (zero
    # getDisplayMedia calls, verified by grep this run). The seventh,
    # fullscreen, is safe to lock here: the SPA has no fullscreen
    # flow (zero requestFullscreen calls and zero <video>/<audio>
    # elements, verified by grep this run). The eighth, accelerometer,
    # is safe to lock here: the SPA has no motion-sensor flow (zero
    # DeviceMotion/DeviceOrientation/Accelerometer/Gyroscope/
    # Magnetometer matches, verified by grep this run), and the
    # middleware value already contains accelerometer=(). The ninth,
    # gyroscope, is safe to lock here: the SPA has no gyroscope flow
    # (zero Gyroscope/DeviceOrientation matches, verified by grep this
    # run), and the middleware value already contains gyroscope=().
    # The tenth, magnetometer, is safe to lock here: the SPA has no
    # compass flow (zero Magnetometer/magnetometer matches, verified
    # by grep this run), and the middleware value already contains
    # magnetometer=(). The eleventh, xr-spatial-tracking, is safe to
    # lock here: the SPA has no XR flow (zero navigator.xr/XRSession/
    # XRSystem/immersive-ar/immersive-vr/requestSession matches and
    # no webxr/three dependency, verified by grep this run), and the
    # middleware value already contains xr-spatial-tracking=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    # immediately after xr-spatial-tracking=().
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    assert "accelerometer=()" in permissions_policy
    assert "gyroscope=()" in permissions_policy
    assert "magnetometer=()" in permissions_policy
    assert "xr-spatial-tracking=()" in permissions_policy
    assert "idle-detection=()" in permissions_policy

    data = RoleDto.model_validate(response.json())

    # Update the role's name
    updated_data = UpdateRoleDto(name="Test Role Updated")
    response = await client.put(f"/roles/{new_role_response.id}", json=updated_data.model_dump())
    assert response.status_code == 200
    # Same security-header lock as the user-update PUT in this suite
    # (iteration 1855): the middleware stamps every HTTP response, so
    # it stamps this PUT response too, but until now only its status
    # and body were asserted — deleting the middleware registration
    # would have gone uncaught on role-update responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the role pre-update GET lock (iteration 1889), using substring
    # checks so later additions to the list do not break this test.
    # The full value lives in _SECURITY_HEADERS. The fifth,
    # clipboard-read, is safe to lock here: the SPA never reads the
    # clipboard (only writeText calls, verified by grep this run).
    # The sixth, display-capture, is safe to lock here: the SPA has
    # no screen-sharing flow (zero getDisplayMedia calls, verified
    # by grep this run), and the middleware already emits it. The
    # seventh, fullscreen, is safe to lock here: the SPA has no
    # fullscreen flow (zero requestFullscreen calls and zero
    # <video>/<audio> elements, verified by grep this run). The
    # eighth, accelerometer, is safe to lock here: the SPA has no
    # motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer matches, verified by
    # grep this run), and the middleware value already contains
    # accelerometer=(). The ninth, gyroscope, is safe to lock here:
    # the SPA has no gyroscope flow (zero Gyroscope/
    # DeviceOrientation matches, verified by grep this run), and the
    # middleware value already contains gyroscope=(). The tenth,
    # magnetometer, is safe to lock here: the SPA has no compass
    # flow (zero Magnetometer/magnetometer matches, verified by
    # grep this run), and the middleware value already contains
    # magnetometer=(). The eleventh, xr-spatial-tracking, is safe to
    # lock here: the SPA has no XR flow (zero navigator.xr/XRSession/
    # XRSystem/immersive-ar/immersive-vr/requestSession matches and
    # no webxr/three dependency, verified by grep this run), and the
    # middleware value already contains xr-spatial-tracking=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    assert "accelerometer=()" in permissions_policy
    assert "gyroscope=()" in permissions_policy
    assert "magnetometer=()" in permissions_policy
    assert "xr-spatial-tracking=()" in permissions_policy
    assert "idle-detection=()" in permissions_policy
    new_role_updated_data = RoleDto.model_validate(response.json())
    assert new_role_updated_data.name == "Test Role Updated"
    assert data.name != new_role_updated_data.name


@pytest.mark.asyncio
async def test_delete_role_by_id_from_host(client: AsyncClient):
    """
        Delete a role by ID:
    """
    new_role_response = await create_role(client)
    response = await client.delete(f"/roles/{new_role_response.id}")
    assert response.status_code == 202
    # Same security-header lock as the tenant-delete and user-delete
    # DELETE responses (iterations 1857-1858): the middleware stamps
    # every HTTP response, so it stamps this DELETE response too, but
    # until now only its status was asserted — deleting the middleware
    # registration would have gone uncaught on role-delete responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # role-update PUT lock (iteration 1890), using substring checks
    # so later additions to the list do not break this test. The
    # full value lives in _SECURITY_HEADERS. The fifth,
    # clipboard-read, is safe to lock here: the SPA never reads the
    # clipboard (only writeText calls, verified by grep this run).
    # The sixth, display-capture, is safe to lock here: the SPA has
    # no screen-sharing flow (zero getDisplayMedia calls, verified
    # by grep this run), and the middleware value already contains
    # display-capture=(). The seventh, fullscreen, is safe to lock
    # here: the SPA has no fullscreen flow (zero requestFullscreen
    # calls and zero <video>/<audio> elements, verified by grep this
    # run), and the middleware value already contains fullscreen=().
    # The eighth, accelerometer, is safe to lock here: the SPA has no
    # motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer matches, verified by grep
    # this run), and the middleware value already contains
    # accelerometer=(). The ninth, gyroscope, is safe to lock here:
    # the SPA has no gyroscope flow (zero Gyroscope/
    # DeviceOrientation matches, verified by grep this run), and the
    # middleware value already contains gyroscope=(). The tenth,
    # magnetometer, is safe to lock here: the SPA has no compass
    # flow (zero Magnetometer/magnetometer matches, verified by grep
    # this run), and the middleware value already contains
    # magnetometer=(). The eleventh, xr-spatial-tracking, is safe
    # to lock here: the SPA has no XR flow (zero navigator.xr/
    # XRSession/XRSystem/immersive-ar/immersive-vr/requestSession
    # matches, verified by grep this run, and no webxr/three
    # dependency in package.json), so no XR flow exists to break,
    # and the middleware value already contains
    # xr-spatial-tracking=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    assert "accelerometer=()" in permissions_policy
    assert "gyroscope=()" in permissions_policy
    assert "magnetometer=()" in permissions_policy
    assert "xr-spatial-tracking=()" in permissions_policy
    assert "idle-detection=()" in permissions_policy

    # Verify the role was deleted by attempting to get the role again
    response = await client.get(f"/roles/{new_role_response.id}")
    assert response.status_code == 404
    # Same central-handler no-store lock as the nonexistent-role 404
    # above (iteration 1810): the deleted role's GET raises
    # RoleNotFoundException via the service, so this 404 also goes
    # through api_exception_handler.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but only the role list, create-role
    # verification, single-role, and pre-update GETs locked its headers
    # in — deleting the middleware registration would have gone
    # uncaught on this delete-verification 404 too. The middleware is
    # app-level pure ASGI, so it stamps exception-handler responses
    # exactly as it stamps success responses, and the test client runs
    # the real app over ASGI transport.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # role-delete DELETE lock (iteration 1937), using substring checks
    # so later additions to the list do not break this test. The
    # full value lives in _SECURITY_HEADERS. The fifth,
    # clipboard-read, is safe to lock here: the SPA never reads the
    # clipboard (only writeText calls, verified by grep this run).
    # The sixth, display-capture, is safe to lock here: the SPA has
    # no screen-sharing flow (zero getDisplayMedia calls, verified
    # by grep this run), and the middleware value already contains
    # display-capture=(). The seventh, fullscreen, is safe to lock
    # here: the SPA has no fullscreen flow (zero requestFullscreen
    # calls and zero <video>/<audio> elements, verified by grep this
    # run), and the middleware value already contains fullscreen=().
    # The eighth, accelerometer, is safe to lock here: the SPA has no
    # motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer matches, verified by grep
    # this run), and the middleware value already contains
    # accelerometer=(). The ninth, gyroscope, is safe to lock here:
    # the SPA has no gyroscope flow (zero Gyroscope/
    # DeviceOrientation matches, verified by grep this run), and the
    # middleware value already contains gyroscope=(). The tenth,
    # magnetometer, is safe to lock here: the SPA has no compass
    # flow (zero Magnetometer/magnetometer matches, verified by grep
    # this run), and the middleware value already contains
    # magnetometer=(). The eleventh, xr-spatial-tracking, is safe
    # to lock here: the SPA has no XR flow (zero navigator.xr/
    # XRSession/XRSystem/immersive-ar/immersive-vr/requestSession
    # matches, verified by grep this run, and no webxr/three
    # dependency in package.json), so no XR flow exists to break,
    # and the middleware value already contains
    # xr-spatial-tracking=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
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
async def test_get_nonexistent_role_by_id_from_host(client: AsyncClient):
    """
        Attempt to get a non-existent role by ID:
    """
    response = await client.get("/roles/68c3031f449ed3590028c778")
    assert response.status_code == 404
    # The 404 comes from the central ApiBaseException handler, not from
    # the endpoint's own Response: the endpoint sets no-store headers
    # before the lookup, but the exception path discards them, so until
    # iteration 1810 this error response carried no cache headers at
    # all. Lock the handler's headers in here, the same no-store
    # hardening as the success-path GET locks.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but this 404 GET locked only no-store
    # — deleting the middleware registration would have gone uncaught
    # on this route too. The middleware is app-level pure ASGI
    # (api/__init__.py add_middleware), so it stamps exception-handler
    # 404s exactly as success responses, and the test client runs the
    # real app over ASGI transport.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # role post-delete 404 lock (iteration 1938), using substring
    # checks so later additions to the list do not break this test.
    # The full value lives in _SECURITY_HEADERS. The fifth,
    # clipboard-read, is safe to lock here: the SPA never reads the
    # clipboard (only writeText calls, verified by grep this run).
    # The sixth, display-capture, is safe to lock here: the SPA has
    # no screen-sharing flow (zero getDisplayMedia calls, verified
    # by grep this run).
    # The seventh, fullscreen, is safe to lock here: the SPA has no
    # fullscreen flow (zero requestFullscreen calls and zero
    # <video>/<audio> elements, verified by grep this run).
    # The eighth, accelerometer, is safe to lock here: the SPA has no
    # motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer matches, verified by grep
    # this run), and the middleware value already contains
    # accelerometer=().
    # The ninth, gyroscope, is safe to lock here: the SPA has no
    # gyroscope flow (zero Gyroscope/DeviceOrientation matches,
    # verified by grep this run), and the middleware value already
    # contains gyroscope=().
    # The tenth, magnetometer, is safe to lock here: the SPA has no
    # compass flow (zero Magnetometer/magnetometer matches, verified
    # by grep this run), and the middleware value already contains
    # magnetometer=().
    # The eleventh, xr-spatial-tracking, is safe to lock here: the
    # SPA has no XR flow (zero navigator.xr/XRSession/XRSystem/
    # immersive-ar/immersive-vr/requestSession matches, verified by
    # grep this run, and no webxr/three dependency), and the
    # middleware value already contains xr-spatial-tracking=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    assert "accelerometer=()" in permissions_policy
    assert "gyroscope=()" in permissions_policy
    assert "magnetometer=()" in permissions_policy
    assert "xr-spatial-tracking=()" in permissions_policy
    assert "idle-detection=()" in permissions_policy

    assert response.json()["error"] == "Role with identifier 68c3031f449ed3590028c778 not found."


@pytest.mark.asyncio
async def test_list_of_roles_paginated_in_host(client: AsyncClient):
    """
        List roles with pagination:
    """
    for i in range(3):
        new_role = CreateRoleDto(
          name=f"Test Role {i}",
          description=f"A role for testing purposes {i}",
        )
        response = await client.post("/roles/", json=new_role.model_dump())
        assert response.status_code == 201
        # The security-headers middleware (security_headers_middleware.py)
        # stamps every HTTP response, and the shared create_role helper
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
        # clipboard-read, is safe to lock here: the SPA never reads the
        # clipboard (no readText in frontend/app/src, only writeText
        # calls in ai-chat and copy-text). The sixth, display-capture,
        # is safe to lock here: the SPA has no screen-sharing flow
        # (no getDisplayMedia in frontend/app/src). The seventh,
        # fullscreen, is safe to lock here: the SPA has no fullscreen
        # flow (zero requestFullscreen calls and zero <video>/<audio>
        # elements in frontend/app/src, verified by grep this run).
        # The eighth, accelerometer, is safe to lock here: the SPA has
        # no motion-sensor flow (zero DeviceMotion/DeviceOrientation/
        # Accelerometer/Gyroscope/Magnetometer matches in
        # frontend/app/src, verified by grep this run), and the
        # middleware value already contains accelerometer=().
        # The ninth, gyroscope, is safe to lock here: the SPA has no
        # gyroscope flow (zero Gyroscope/DeviceOrientation matches in
        # frontend/app/src, verified by grep this run), and the
        # middleware value already contains gyroscope=().
        # The tenth, magnetometer, is safe to lock here: the SPA has no
        # compass flow (zero Magnetometer/magnetometer matches in
        # frontend/app/src, verified by grep this run), and the
        # middleware value already contains magnetometer=().
        # The eleventh, xr-spatial-tracking, is safe to lock here: the
        # SPA has no XR flow (zero navigator.xr/XRSession/XRSystem/
        # immersive-ar/immersive-vr/requestSession matches in
        # frontend/app/src, verified by grep this run, and no webxr/
        # three dependency in package.json), and the middleware value
        # already contains xr-spatial-tracking=().
        # The twelfth, idle-detection, is safe to lock here: the SPA has
        # no idle-detection flow (zero IdleDetector/idle matches in
        # frontend/app/src, verified by grep this run), and the
        # middleware value already contains idle-detection=()
        # immediately after xr-spatial-tracking=().
        permissions_policy = response.headers["permissions-policy"]
        assert "camera=()" in permissions_policy
        assert "microphone=()" in permissions_policy
        assert "geolocation=()" in permissions_policy
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
    response = await client.get("/roles/?skip=0&limit=1")
    assert response.status_code == 200
    # The endpoint comment requires this GET never to be served from a
    # browser or proxy cache (it lists roles with their permissions),
    # but no test locked the headers in for the paginated pages —
    # deleting the two header lines would have gone uncaught on these
    # pages even though the unpaginated list GET is locked, as with
    # the create-role list verification GET in iteration 1795.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but this paginated page locked only
    # no-store — deleting the middleware registration would have gone
    # uncaught on this page too. The test client runs the real app
    # over ASGI transport, so the pure-ASGI middleware applies here
    # exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # role-list GET lock (iteration 1882), using substring checks
    # so later additions to the list do not break this test. The
    # full value lives in _SECURITY_HEADERS. The fifth,
    # clipboard-read, is safe to lock here: the SPA never reads the
    # clipboard (no readText in frontend/app/src, only writeText
    # calls in ai-chat and copy-text). The sixth, display-capture,
    # is safe to lock here: the SPA has no screen-sharing flow
    # (no getDisplayMedia in frontend/app/src). The seventh,
    # fullscreen, is safe to lock here: the SPA has no fullscreen
    # flow (zero requestFullscreen calls and zero <video>/<audio>
    # elements in frontend/app/src, verified by grep this run),
    # and the middleware value already contains fullscreen=().
    # The eighth, accelerometer, is safe to lock here: the SPA has
    # no motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains accelerometer=().
    # The ninth, gyroscope, is safe to lock here: the SPA has no
    # gyroscope flow (zero Gyroscope/DeviceOrientation matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains gyroscope=().
    # The tenth, magnetometer, is safe to lock here: the SPA has no
    # compass flow (zero Magnetometer/magnetometer matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains magnetometer=().
    # The eleventh, xr-spatial-tracking, is safe to lock here: the
    # SPA has no XR flow (zero navigator.xr/XRSession/XRSystem/
    # immersive-ar/immersive-vr/requestSession matches in
    # frontend/app/src, verified by grep this run, and no webxr/
    # three dependency in package.json), and the middleware value
    # already contains xr-spatial-tracking=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    # immediately after xr-spatial-tracking=().
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    assert "accelerometer=()" in permissions_policy
    assert "gyroscope=()" in permissions_policy
    assert "magnetometer=()" in permissions_policy
    assert "xr-spatial-tracking=()" in permissions_policy
    assert "idle-detection=()" in permissions_policy

    data = RoleListDto.model_validate(response.json())
    assert data.total == 3
    assert len(data.roles) == 1
    assert data.hasNext == True
    assert data.hasPrevious == False
    assert data.skip == 0
    assert data.limit == 1

    response = await client.get("/roles/?skip=1&limit=1")
    assert response.status_code == 200
    # Same no-store lock as the first paginated page (iteration 1796):
    # the list endpoint sets both headers unconditionally, so the
    # assertion holds for page 2 as well, and deleting the header
    # lines would otherwise go uncaught on this page.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but this paginated page locked only
    # no-store — deleting the middleware registration would have gone
    # uncaught on this page too. The test client runs the real app
    # over ASGI transport, so the pure-ASGI middleware applies here
    # exactly as in production.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # paginated page 1 lock (iteration 1885), using substring checks
    # so later additions to the list do not break this test. The
    # full value lives in _SECURITY_HEADERS. The fifth,
    # clipboard-read, is safe to lock here: the SPA never reads the
    # clipboard (no readText in frontend/app/src, only writeText
    # calls in ai-chat and copy-text). The sixth, display-capture,
    # is safe to lock here: the SPA has no screen-sharing flow
    # (no getDisplayMedia in frontend/app/src). The seventh,
    # fullscreen, is safe to lock here: the SPA has no fullscreen
    # flow (zero requestFullscreen calls and zero <video>/<audio>
    # elements in frontend/app/src, verified by grep this run),
    # and the middleware value already contains fullscreen=().
    # The eighth, accelerometer, is safe to lock here: the SPA has
    # no motion-sensor flow (zero DeviceMotion/DeviceOrientation/
    # Accelerometer/Gyroscope/Magnetometer matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains accelerometer=().
    # The ninth, gyroscope, is safe to lock here: the SPA has no
    # gyroscope flow (zero Gyroscope/DeviceOrientation matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains gyroscope=().
    # The tenth, magnetometer, is safe to lock here: the SPA has no
    # compass flow (zero Magnetometer/magnetometer matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains magnetometer=().
    # The eleventh, xr-spatial-tracking, is safe to lock here: the
    # SPA has no XR flow (zero navigator.xr/XRSession/XRSystem/
    # immersive-ar/immersive-vr/requestSession matches in
    # frontend/app/src, verified by grep this run, and no webxr/
    # three dependency in package.json), and the middleware value
    # already contains xr-spatial-tracking=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    # immediately after xr-spatial-tracking=().
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    assert "accelerometer=()" in permissions_policy
    assert "gyroscope=()" in permissions_policy
    assert "magnetometer=()" in permissions_policy
    assert "xr-spatial-tracking=()" in permissions_policy
    assert "idle-detection=()" in permissions_policy
    data = RoleListDto.model_validate(response.json())
    assert data.total == 3
    assert len(data.roles) == 1
    assert data.hasNext == True
    assert data.hasPrevious == True
    assert data.skip == 1
    assert data.limit == 1

    response = await client.get("/roles/?skip=2&limit=1")
    assert response.status_code == 200
    # Same no-store lock as paginated pages 1-2 (iterations 1796-1797):
    # the list endpoint sets both headers unconditionally, so the
    # assertion holds for the last page as well, and deleting the
    # header lines would otherwise go uncaught on this page.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but this paginated page locked only
    # no-store — deleting the middleware registration would have gone
    # uncaught on this page too. The test client runs the real app
    # over ASGI transport, so the pure-ASGI middleware applies here
    # exactly as in production, and pages 1-2 already lock the same
    # headers, so the assertion holds for the last page as well.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # paginated page 2 lock (iteration 1886), using substring checks
    # so later additions to the list do not break this test. The
    # full value lives in _SECURITY_HEADERS. The fifth, clipboard-read,
    # is safe to lock here: the SPA never reads the clipboard.
    # The sixth, display-capture, is safe to lock here: the SPA has
    # no screen-sharing flow (no getDisplayMedia in frontend/app/src).
    # The seventh, fullscreen, is safe to lock here: the SPA has no
    # fullscreen flow (zero requestFullscreen calls and zero
    # <video>/<audio> elements in frontend/app/src, verified by grep
    # this run), and the middleware value already contains
    # fullscreen=(). The eighth, accelerometer, is safe to lock
    # here: the SPA has no motion-sensor flow (zero
    # DeviceMotion/DeviceOrientation/Accelerometer/Gyroscope/
    # Magnetometer matches in frontend/app/src, verified by grep
    # this run), and the middleware value already contains
    # accelerometer=(). The ninth, gyroscope, is safe to lock here:
    # the SPA has no gyroscope flow (zero Gyroscope/DeviceOrientation
    # matches in frontend/app/src, verified by grep this run), and the
    # middleware value already contains gyroscope=(). The tenth,
    # magnetometer, is safe to lock here: the SPA has no compass
    # flow (zero Magnetometer/magnetometer matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains magnetometer=(). The
    # eleventh, xr-spatial-tracking, is safe to lock here: the
    # SPA has no XR flow (zero navigator.xr/XRSession/XRSystem/
    # immersive-ar/immersive-vr/requestSession matches in
    # frontend/app/src, verified by grep this run, and no webxr/
    # three dependency in package.json), and the middleware value
    # already contains xr-spatial-tracking=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    # immediately after xr-spatial-tracking=().
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    assert "accelerometer=()" in permissions_policy
    assert "gyroscope=()" in permissions_policy
    assert "magnetometer=()" in permissions_policy
    assert "xr-spatial-tracking=()" in permissions_policy
    assert "idle-detection=()" in permissions_policy
    data = RoleListDto.model_validate(response.json())
    assert data.total == 3
    assert len(data.roles) == 1
    assert data.hasNext == False
    assert data.hasPrevious == True
    assert data.skip == 2
    assert data.limit == 1


@pytest.mark.asyncio
async def test_create_role_with_default_permissions_in_host(client: AsyncClient):
    """
        Create a new role with default permissions:
    """
    new_role_response = await create_role(client)

    # Verify the role was created by listing roles again
    response = await client.get(f"/roles/{new_role_response.id}")
    assert response.status_code == 200
    # The endpoint comment requires this GET never to be served from a
    # browser or proxy cache (it returns a single role's name and
    # permissions), but no test locked the headers in — deleting the
    # two header lines would have gone uncaught, as with the pre-update
    # single-role GET in iteration 1793 and the single-role GET in
    # iteration 1790.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # The security-headers middleware (security_headers_middleware.py)
    # must stamp every response, but this verification GET locked only
    # no-store — deleting the middleware registration would have gone
    # uncaught here too. The test client runs the real app over ASGI
    # transport, so the pure-ASGI middleware applies here exactly as
    # in production, and the single-role GET already locks the same
    # headers, so the assertion holds for this verification GET as well.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring the
    # paginated role-list page 3 lock (iteration 1887), using
    # substring checks so later additions to the list do not break
    # this test. The full value lives in _SECURITY_HEADERS. The fifth,
    # clipboard-read, is safe to lock here: the SPA never reads the
    # clipboard (only writeText calls, verified by grep this run).
    # The sixth, display-capture, is safe to lock here: the SPA has
    # no screen-sharing flow (no getDisplayMedia calls, verified by
    # grep this run). The seventh, fullscreen, is safe to lock here:
    # the SPA has no fullscreen flow (zero requestFullscreen calls
    # and zero <video>/<audio> elements in frontend/app/src,
    # verified by grep this run), and the middleware value already
    # contains fullscreen=(). The eighth, accelerometer, is safe to
    # lock here: the SPA has no motion-sensor flow (zero
    # DeviceMotion/DeviceOrientation/Accelerometer/Gyroscope/
    # Magnetometer matches in frontend/app/src, verified by grep
    # this run), and the middleware value already contains
    # accelerometer=(). The ninth, gyroscope, is safe to lock here:
    # the SPA has no gyroscope flow (zero Gyroscope/
    # DeviceOrientation matches in frontend/app/src, verified by
    # grep this run), and the middleware value already contains
    # gyroscope=(). The tenth, magnetometer, is safe to lock here:
    # the SPA has no compass flow (zero Magnetometer matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains magnetometer=(). The
    # eleventh, xr-spatial-tracking, is safe to lock here: the SPA
    # has no XR flow (zero navigator.xr/XRSession/XRSystem/
    # immersive-ar/immersive-vr/requestSession matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains xr-spatial-tracking=().
    # The twelfth, idle-detection, is safe to lock here: the SPA has
    # no idle-detection flow (zero IdleDetector/idle matches in
    # frontend/app/src, verified by grep this run), and the
    # middleware value already contains idle-detection=()
    # immediately after xr-spatial-tracking=().
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
    assert "payment=()" in permissions_policy
    assert "clipboard-read=()" in permissions_policy
    assert "display-capture=()" in permissions_policy
    assert "fullscreen=()" in permissions_policy
    assert "accelerometer=()" in permissions_policy
    assert "gyroscope=()" in permissions_policy
    assert "magnetometer=()" in permissions_policy
    assert "xr-spatial-tracking=()" in permissions_policy
    assert "idle-detection=()" in permissions_policy
    data = RoleDto.model_validate(response.json())
    assert data.permissions == [Permission.USER_VIEW_ONLY, Permission.ROLE_VIEW_ONLY]


@pytest.mark.asyncio
async def test_list_roles_with_missing_role_returns_404_with_cache_and_security_headers(client: AsyncClient):
    """
        GET /roles/ was the one role route with no error-path lock:
        the role test file locked the list success path (no-store,
        Pragma, and the security headers), the create/get/update/
        delete success paths, and the post-delete and nonexistent-id
        404s, but never the permission-gate failure on the list
        itself, so dropping the ROLE_VIEW_ONLY dependency — or
        dropping the central ApiBaseException no-store lines or the
        security-headers middleware registration — would previously
        have gone uncaught on this route. The success path is not
        asserted here: the list is permission-gated
        (ROLE_VIEW_ONLY), so it needs a DB role lookup, and the
        shared conftest client seeds no role. The error path below
        is deterministic instead: the mocked host user's role_id
        points at no row in the fresh test database (Role is in
        the conftest model set), so the permission dependency's
        get_role_by_id raises RoleNotFoundException before the
        scope guard, any role listing, or any write — no side
        effect, and the default skip/limit query values pass
        validation, so no 422 can mask the 404. That 404 must
        still carry the error-response headers: a cached 404
        could otherwise be served to a different admin after an
        account switch on a shared machine, and the success path
        lists roles with their permissions.
    """
    response = await client.get("/roles/")
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == 404
    assert "Role" in body["error"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the role success-path tests:
    # the pure-ASGI middleware stamps every HTTP response with no
    # path exclusions, so the role-list 404 must carry the same
    # headers as the list 200, including the exception-handler
    # responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the role success-path locks, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # role routes: the SPA has no camera, microphone, geolocation,
    # payment, clipboard-read, display-capture, fullscreen,
    # motion-sensor, compass, XR, or idle-detection flow
    # (re-verified fresh this run: zero case-insensitive idle
    # matches and zero IdleDetector/requestIdleCallback matches
    # across frontend/app/src).
    permissions_policy = response.headers["permissions-policy"]
    assert "camera=()" in permissions_policy
    assert "microphone=()" in permissions_policy
    assert "geolocation=()" in permissions_policy
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
async def test_list_roles_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The roles list scope-guard error path:
    """
    # The roles list scope-guard branch, not yet locked:
    # function-name grep count 0 for list_roles_outside_tenant_scope
    # (verified fresh this run), and no test in this file asserts a
    # 403 at all - the list locks cover only the host success path
    # and the missing-role 404, while the create/get/update/delete
    # scope guards have their own locks elsewhere. Deleting
    # _assert_list_scope (role_endpoint.py) would previously have
    # gone uncaught, and a tenant caller listing on the host DB
    # (no X-Tenant-ID/subdomain) would then read tenant-stamped
    # roles sitting in the host DB - names and permissions of roles
    # host callers resolve by id with no tenant scope. The guard
    # runs in the handler body, after the ROLE_VIEW_ONLY permission
    # dependency, so the gate must be satisfied first: the shared
    # conftest mock points at role id 68c302ef6bf7a039b7e9b386 with
    # no row in the fresh test database, which is why the 404 lock
    # fails there. Seeding that exact id carrying ROLE_VIEW_ONLY,
    # mirroring the features 200 seed precedent, lets the
    # dependency pass: get_role_by_id is called with no tenant
    # filter, and _caller_may_access returns True for a
    # host-stamped row when the caller tenant is None
    # (role_service.py:18-19), so the seeded row is visible
    # regardless of the caller's tenant scope. The caller is then
    # made tenant-scoped by swapping in a per-test MeResponseDto
    # override (tenant_id set), mirroring the dashboard 403 lock's
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
    # guard would break this lock while leaving the list 200 and
    # the missing-role 404 locks green, so the three paths are
    # locked separately.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.entities.role import Role
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant role viewer",
        description="Role carrying ROLE_VIEW_ONLY for the mocked caller",
        permissions=[Permission.ROLE_VIEW_ONLY],
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
                name="Tenant role viewer",
                description="Role carrying ROLE_VIEW_ONLY for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.ROLE_VIEW_ONLY],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.get("/roles/")
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

    # Same security-headers lock as the role list 200 and 404
    # tests: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the roles-list 403 must carry
    # the same headers as the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the role list locks, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # role routes: the SPA has no camera, microphone, geolocation,
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
    assert stored.permissions == [Permission.ROLE_VIEW_ONLY]


@pytest.mark.asyncio
async def test_get_role_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The single-role read scope-guard error path:
    """
    # The single-role read scope-guard branch, not yet locked:
    # function-name grep count 0 for get_role_outside_tenant_scope
    # (verified fresh this run), and no test in this file asserts a
    # 403 on GET /roles/{role_id} at all - the list 403 lock covers
    # only _assert_list_scope, while the create/update/delete guards
    # have their own messages and handlers. Deleting _assert_get_scope
    # (role_endpoint.py) would previously have gone uncaught, and a
    # tenant caller reading on the host DB (no X-Tenant-ID/subdomain)
    # would then read a tenant-stamped role sitting in the host DB -
    # its name and permissions, which host callers resolve by id
    # with no tenant scope. The guard runs in the handler body,
    # after the ROLE_VIEW_ONLY permission dependency, so the gate
    # must be satisfied first: the shared conftest mock points at
    # role id 68c302ef6bf7a039b7e9b386 with no row in the fresh test
    # database, which is why the missing-role 404 lock fails there.
    # Seeding that exact id carrying ROLE_VIEW_ONLY, mirroring the
    # list 403 seed precedent, lets the dependency pass:
    # UserAccessManagement.get_role_detail calls
    # get_role_by_id(role_id) with no tenant filter
    # (user_access_management.py:36-39), and _caller_may_access
    # returns True for a host-stamped row when the caller tenant
    # is None (role_service.py:18-19), so the seeded row is
    # visible regardless of the caller's tenant scope. The caller
    # is then made tenant-scoped by swapping in a per-test
    # MeResponseDto override (tenant_id set), mirroring the list
    # 403 lock's override pattern, and restored in finally so no
    # other test's mock is affected. With no X-Tenant-ID header
    # the tenant middleware resolves host scope, so
    # request_tenant_id is None and the guard raises
    # ForbiddenException before any read runs - no side effect,
    # and the id is a valid ObjectId, so no 422 can mask the
    # 403. The central ApiBaseException handler maps
    # ForbiddenException to 403 (api/__init__.py:98-103) with
    # {"error": ..., "code": 403} and the no-store/Pragma error
    # headers, since the handler sets them only after the guard.
    # A future change that drops the guard would break this lock
    # while leaving the list 403 and the missing-role 404 locks
    # green, so the three paths are locked separately.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.entities.role import Role
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant role viewer",
        description="Role carrying ROLE_VIEW_ONLY for the mocked caller",
        permissions=[Permission.ROLE_VIEW_ONLY],
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
                name="Tenant role viewer",
                description="Role carrying ROLE_VIEW_ONLY for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.ROLE_VIEW_ONLY],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.get("/roles/68c302ef6bf7a039b7e9b386")
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

    # Same security-headers lock as the role list 200 and 404
    # tests: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the single-role read 403 must
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
    # the role list locks, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # role routes: the SPA has no camera, microphone, geolocation,
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
    # Postcondition: the guard fires before any read, so the
    # request is side-effect free - the seeded role is still there
    # with its permission.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.ROLE_VIEW_ONLY]


@pytest.mark.asyncio
async def test_create_role_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The role create scope-guard error path:
    """
    # The role create scope-guard branch, not yet locked:
    # function-name grep count 0 for create_role_outside_tenant_scope
    # (verified fresh this run), and no test in this file asserts a
    # 403 on POST /roles/ at all - the list and single-role read 403
    # locks cover only _assert_list_scope and _assert_get_scope,
    # while the create/update/delete guards have their own messages
    # and handlers. Deleting _assert_create_scope
    # (role_endpoint.py) would previously have gone uncaught, and a
    # tenant caller creating on the host DB (no X-Tenant-ID/subdomain)
    # would then plant a role in the host DB that host callers see
    # in their global list. The guard runs in the handler body,
    # after the ROLE_READ_AND_WRITE_ONLY permission dependency, so
    # the gate must be satisfied first: the shared conftest mock
    # points at role id 68c302ef6bf7a039b7e9b386 with no row in the
    # fresh test database, which is why the missing-role 404 lock
    # fails there. Seeding that exact id carrying
    # ROLE_READ_AND_WRITE_ONLY, mirroring the list/get 403 seed
    # precedent, lets the dependency pass:
    # UserAccessManagement.get_role_detail calls
    # get_role_by_id(role_id) with no tenant filter
    # (user_access_management.py:36-39), and _caller_may_access
    # returns True for a host-stamped row when the caller tenant
    # is None (role_service.py:18-19), so the seeded row is
    # visible regardless of the caller's tenant scope. The caller
    # is then made tenant-scoped by swapping in a per-test
    # MeResponseDto override (tenant_id set), mirroring the list
    # 403 lock's override pattern, and restored in finally so no
    # other test's mock is affected. With no X-Tenant-ID header
    # the tenant middleware resolves host scope, so
    # request_tenant_id is None and the guard raises
    # ForbiddenException before any write runs - no side effect.
    # The payload is the same valid body the create helper posts
    # (name "Test Role", description "A role for testing
    # purposes"), so it passes the CreateRoleDto validation
    # (name 2-20, description 10-200, trimmed by the model
    # validator) and no 422 can mask the 403. The central
    # ApiBaseException handler maps ForbiddenException to 403
    # (api/__init__.py:98-103) with {"error": ..., "code": 403}
    # and the no-store/Pragma error headers, since the handler
    # sets them only after the guard. A future change that drops
    # the guard would break this lock while leaving the list and
    # single-role read 403 locks green, so the three paths are
    # locked separately.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.entities.role import Role
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant role writer",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
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
                name="Tenant role writer",
                description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.post(
            "/roles/",
            json=CreateRoleDto(
                name="Test Role",
                description="A role for testing purposes",
            ).model_dump(),
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

    # Same security-headers lock as the role list 200 and 404
    # tests: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the role create 403 must carry
    # the same headers as the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the role list locks, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # role routes: the SPA has no camera, microphone, geolocation,
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
    # Postcondition: the guard fires before any write, so the
    # request is side-effect free - no "Test Role" row was planted
    # in the host DB, and the seeded role is still there with its
    # permission.
    planted = await Role.find_one(Role.name == "Test Role")
    assert planted is None
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.ROLE_READ_AND_WRITE_ONLY]


@pytest.mark.asyncio
async def test_update_role_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The role update scope-guard error path:
    """
    # The role update scope-guard branch, not yet locked:
    # function-name grep count 0 for update_role_outside_tenant_scope
    # (verified fresh this run), and no test in this file asserts a
    # 403 on PUT /roles/{role_id} at all - the list, single-role read
    # and create 403 locks cover only _assert_list_scope,
    # _assert_get_scope and _assert_create_scope, while the
    # update/delete guards have their own messages and handlers.
    # Deleting _assert_update_scope (role_endpoint.py) would
    # previously have gone uncaught, and a tenant caller updating
    # on the host DB (no X-Tenant-ID/subdomain) could then edit a
    # tenant-stamped role sitting in the host DB (e.g. planted
    # before the create guard), changing its name or permissions
    # where host callers resolve roles by id with no tenant scope.
    # The guard runs in the handler body, after the
    # ROLE_READ_AND_WRITE_ONLY permission dependency, so the gate
    # must be satisfied first: the shared conftest mock points at
    # role id 68c302ef6bf7a039b7e9b386 with no row in the fresh
    # test database, which is why the missing-role 404 lock fails
    # there. Seeding that exact id carrying
    # ROLE_READ_AND_WRITE_ONLY, mirroring the list/get/create 403
    # seed precedent, lets the dependency pass:
    # UserAccessManagement.get_role_detail calls
    # get_role_by_id(role_id) with no tenant filter
    # (user_access_management.py:36-39), and _caller_may_access
    # returns True for a host-stamped row when the caller tenant
    # is None (role_service.py:18-19), so the seeded row is
    # visible regardless of the caller's tenant scope. The caller
    # is then made tenant-scoped by swapping in a per-test
    # MeResponseDto override (tenant_id set), mirroring the list
    # 403 lock's override pattern, and restored in finally so no
    # other test's mock is affected. With no X-Tenant-ID header
    # the tenant middleware resolves host scope, so
    # request_tenant_id is None and the guard raises
    # ForbiddenException before any write runs - no side effect.
    # The payload is the same valid body the host update test
    # puts (UpdateRoleDto name "Test Role Updated", description
    # left None), so it passes the UpdateRoleDto validation
    # (name 2-20, trimmed by the model validator) and no 422 can
    # mask the 403. The central ApiBaseException handler maps
    # ForbiddenException to 403 (api/__init__.py:98-103) with
    # {"error": ..., "code": 403} and the no-store/Pragma error
    # headers, since the handler sets them only after the guard.
    # A future change that drops the guard would break this lock
    # while leaving the list, single-role read and create 403
    # locks green, so the four paths are locked separately.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.entities.role import Role
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant role writer",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
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
                name="Tenant role writer",
                description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.put(
            "/roles/68c302ef6bf7a039b7e9b386",
            json=UpdateRoleDto(
                name="Test Role Updated",
            ).model_dump(),
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

    # Same security-headers lock as the role list 200 and 404
    # tests: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the role update 403 must carry
    # the same headers as the authenticated GETs, including the
    # exception-handler responses.
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Presence alone would not catch the value being weakened: lock
    # the twelve most sensitive directives as disabled, mirroring
    # the role list locks, using substring checks so later
    # additions to the list do not break this test. Each directive
    # is safe to lock here for the same reasons as on the other
    # role routes: the SPA has no camera, microphone, geolocation,
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
    # Postcondition: the guard fires before any write, so the
    # request is side-effect free - the seeded role still has its
    # original name and permission, and no role was renamed to
    # "Test Role Updated".
    renamed = await Role.find_one(Role.name == "Test Role Updated")
    assert renamed is None
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.name == "Tenant role writer"
    assert stored.permissions == [Permission.ROLE_READ_AND_WRITE_ONLY]
