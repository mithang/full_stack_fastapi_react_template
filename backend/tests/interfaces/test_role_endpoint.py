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


@pytest.mark.asyncio
async def test_delete_role_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The role delete scope-guard error path:
    """
    # The role delete scope-guard branch, not yet locked:
    # function-name grep count 0 for delete_role_outside_tenant_scope
    # (verified fresh this run), and no test in this file asserts a
    # 403 on DELETE /roles/{role_id} at all - the list, single-role
    # read, create and update 403 locks cover only _assert_list_scope,
    # _assert_get_scope, _assert_create_scope and _assert_update_scope,
    # while the delete guard has its own message and handler.
    # Deleting _assert_delete_scope (role_endpoint.py) would
    # previously have gone uncaught, and a tenant caller deleting
    # on the host DB (no X-Tenant-ID/subdomain) could then delete a
    # tenant-stamped role sitting in the host DB (e.g. planted
    # before the create guard), removing a role that host callers
    # resolve by id with no tenant scope.
    # The guard runs in the handler body, after the
    # ROLE_DELETE_ONLY permission dependency, so the gate must be
    # satisfied first: the shared conftest mock points at
    # role id 68c302ef6bf7a039b7e9b386 with no row in the fresh
    # test database, which is why the missing-role 404 lock fails
    # there. Seeding that exact id carrying ROLE_DELETE_ONLY,
    # mirroring the list/get/create/update 403 seed precedent,
    # lets the dependency pass: UserAccessManagement.get_role_detail
    # calls get_role_by_id(role_id) with no tenant filter
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
    # ForbiddenException before any delete runs - no side effect.
    # The central ApiBaseException handler maps
    # ForbiddenException to 403 (api/__init__.py:98-103) with
    # {"error": ..., "code": 403} and the no-store/Pragma error
    # headers, since the handler sets them only after the guard.
    # A future change that drops the guard would break this lock
    # while leaving the list, single-role read, create and update
    # 403 locks green, so the five paths are locked separately.
    # This is the last of the five role scope guards.
    from beanie import PydanticObjectId

    from api import app
    from api.common.enums.gender import Gender
    from api.domain.dtos.auth_dto import MeResponseDto
    from api.domain.entities.role import Role
    from api.infrastructure.security.current_user import get_current_user

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant role deleter",
        description="Role carrying ROLE_DELETE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_DELETE_ONLY],
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
                name="Tenant role deleter",
                description="Role carrying ROLE_DELETE_ONLY for the mocked caller",
                created_at="2024-10-01T00:00:00Z",
                updated_at="2024-10-01T00:00:00Z",
                permissions=[Permission.ROLE_DELETE_ONLY],
            ),
            subscription=None,
        )

    original_override = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = override_get_current_user_tenant_scoped
    try:
        response = await client.delete(
            "/roles/68c302ef6bf7a039b7e9b386",
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
    # with no path exclusions, so the role delete 403 must carry
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
    # Postcondition: the guard fires before any delete, so the
    # request is side-effect free - the seeded role still exists
    # with its original name and permission.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.name == "Tenant role deleter"
    assert stored.permissions == [Permission.ROLE_DELETE_ONLY]


@pytest.mark.asyncio
async def test_search_role_by_name_outside_tenant_scope_returns_403_with_cache_and_security_headers(client: AsyncClient):
    """
        The role search-by-name scope-guard error path:
    """
    # The role search-by-name scope-guard branch, not yet locked:
    # function-name grep count 0 for
    # search_role_by_name_outside_tenant_scope (verified fresh this
    # run), and no test in this file hits /roles/search_by_name at
    # all - the list 403 lock covers only GET /roles/, while the
    # search handler is a separate route that shares the same
    # _assert_list_scope guard (role_endpoint.py:162). Deleting the
    # guard call in search_role_by_name would previously have gone
    # uncaught, and a tenant caller searching on the host DB (no
    # X-Tenant-ID/subdomain) would then read tenant-stamped roles
    # sitting in the host DB - names and permissions of roles host
    # callers resolve by id with no tenant scope. The guard runs in
    # the handler body, after the ROLE_VIEW_ONLY permission
    # dependency, so the gate must be satisfied first: the shared
    # conftest mock points at role id 68c302ef6bf7a039b7e9b386 with
    # no row in the fresh test database, which is why the 404 lock
    # fails there. Seeding that exact id carrying ROLE_VIEW_ONLY,
    # mirroring the list 403 seed precedent, lets the dependency
    # pass: get_role_by_id is called with no tenant filter, and
    # _caller_may_access returns True for a host-stamped row when
    # the caller tenant is None (role_service.py:18-19), so the
    # seeded row is visible regardless of the caller's tenant
    # scope. The caller is then made tenant-scoped by swapping in
    # a per-test MeResponseDto override (tenant_id set), mirroring
    # the list 403 lock's override pattern, and restored in finally
    # so no other test's mock is affected. With no X-Tenant-ID
    # header the tenant middleware resolves host scope, so
    # request_tenant_id is None and the guard raises
    # ForbiddenException before any search runs - no side effect,
    # and the required name query param is supplied, so no 422 can
    # mask the 403. The central ApiBaseException handler maps
    # ForbiddenException to 403 (api/__init__.py:98-103) with
    # {"error": ..., "code": 403} and the no-store/Pragma error
    # headers, since the handler sets them only after the guard. A
    # future change that drops the guard in this handler would break
    # this lock while leaving the list 403 lock green, so the two
    # paths are locked separately.
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
        response = await client.get(
            "/roles/search_by_name", params={"name": "Tenant role viewer"}
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
    # with no path exclusions, so the search 403 must carry the
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
    # Postcondition: the guard fires before any search, so the
    # request is side-effect free - the seeded role is still there
    # with its permission.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.ROLE_VIEW_ONLY]


@pytest.mark.asyncio
async def test_create_duplicate_role_returns_409_with_cache_and_security_headers(client: AsyncClient):
    """
        The role create duplicate-name error path:
    """
    # The role create 409 branch, not yet locked: function-name
    # grep count 0 for create_duplicate_role and grep count 0 for
    # "already exists" across this file (verified fresh this run),
    # and no test anywhere in the suite asserts a 409 at all - the
    # 409 tenant-create path stays deferred (it needs a unique index
    # plus a real create that enqueues a Celery post-tenant task),
    # so the central handler's ConflictException -> 409 mapping
    # (api/__init__.py:89-90) had no lock. Deleting the duplicate
    # check in role_service.create_role would previously have gone
    # uncaught, and a second role with the same name would then be
    # planted (or fail later on the unique name index with a 500
    # instead of the clean 409). The duplicate check runs in the
    # service before any write, so this lock needs no broker care:
    # create_role does a single_or_none(name=...) lookup and raises
    # RoleAlreadyExistsException (role_service.py:95-98), which
    # subclasses ConflictException with the message "Role with
    # identifier <name> already exists." (exceptions.py:26-38), and
    # the central handler maps it to 409 with {"error": ..., "code":
    # 409} plus the no-store/Pragma error headers
    # (api/__init__.py:89-90, 121-133). The create handler itself
    # (role_endpoint.py:179-203) runs the ROLE_READ_AND_WRITE_ONLY
    # permission dependency and _assert_create_scope before the
    # service call, so the gate must be satisfied first: the shared
    # conftest mock is a host caller (tenant_id None, role id
    # 68c302ef6bf7a039b7e9b386 with no row in the fresh test
    # database), so seeding that exact id carrying
    # ROLE_READ_AND_WRITE_ONLY, mirroring the create 403 lock's
    # seed precedent, lets the dependency pass - get_role_detail
    # calls get_role_by_id(role_id) with no tenant filter
    # (user_access_management.py:36-39) - and the host caller
    # passes _assert_create_scope with no X-Tenant-ID header. A
    # second seeded role carries the duplicate name "Test Role",
    # the same valid body the create helper posts (name 2-20,
    # description 10-200, trimmed by the model validator), so no
    # 422 can mask the 409. A future change that drops the
    # duplicate check would break this lock while leaving the
    # create 201 lock and the create 403 lock green, so the paths
    # are locked separately.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant role writer",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="Test Role",
        description="A role for testing purposes",
        permissions=[Permission.ROLE_VIEW_ONLY],
    ).insert()

    response = await client.post(
        "/roles/",
        json=CreateRoleDto(
            name="Test Role",
            description="A role for testing purposes",
        ).model_dump(),
    )
    assert response.status_code == 409
    body = response.json()
    assert body["code"] == 409
    assert body["error"] == "Role with identifier Test Role already exists."
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 409 must still carry the error-response headers: the
    # handler sets no-store only after the guard, so on this path
    # they come from the central ApiBaseException handler, and a
    # cached 409 could otherwise be served to a different user
    # after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the role list 200 and 404
    # tests: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the role create 409 must carry
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
    # Postcondition: the duplicate check fires before any write,
    # so the request is side-effect free - still exactly one
    # "Test Role" row (the seeded one, id ...389), and the seeded
    # permission role is still there with its permission.
    duplicates = await Role.find(Role.name == "Test Role").to_list()
    assert len(duplicates) == 1
    assert duplicates[0].id == PydanticObjectId("68c302ef6bf7a039b7e9b389")
    assert duplicates[0].permissions == [Permission.ROLE_VIEW_ONLY]
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.ROLE_READ_AND_WRITE_ONLY]


async def test_update_duplicate_role_returns_409_with_cache_and_security_headers(client: AsyncClient):
    """
        The role update duplicate-name error path:
    """
    # The role update 409 branch, not yet locked: function-name
    # grep count 0 for update_duplicate_role and grep count 0 for
    # "already exists" on a PUT in this file (verified fresh this
    # run). create_role already guards the name (role_service.py:
    # 95-98) and the create 409 lock covers it, but update_role
    # had no duplicate check at all - so renaming a role onto
    # another role's name escaped the service and hit Role.name's
    # unique index inside the repository's doc.update()
    # (BaseRepository.update catches nothing, and the central
    # handler only maps ApiBaseException / StarletteHTTPException),
    # surfacing as an unhandled DuplicateKeyError - a 500 instead
    # of the clean 409 create returns. The fix mirrors create_role
    # in update_role: single_or_none(name=...) before any write,
    # raising RoleAlreadyExistsException (exceptions.py:40-42),
    # which subclasses ConflictException with the message "Role
    # with identifier <name> already exists."
    # (common/exceptions.py:26-38), and the central handler maps
    # it to 409 with {"error": ..., "code": 409} plus the
    # no-store/Pragma error headers (api/__init__.py:89-90,
    # 121-133). The PUT handler itself (role_endpoint.py:230-242)
    # runs the ROLE_READ_AND_WRITE_ONLY permission dependency and
    # _assert_update_scope before the service call, so the gate
    # must be satisfied first: the shared conftest mock is a host
    # caller (tenant_id None, role id 68c302ef6bf7a039b7e9b386 with
    # no row in the fresh test database), so seeding that exact id
    # carrying ROLE_READ_AND_WRITE_ONLY, mirroring the create 409
    # lock's seed precedent, lets the dependency pass -
    # get_role_detail calls get_role_by_id(role_id) with no tenant
    # filter (user_access_management.py:36-39) - and the host
    # caller passes _assert_update_scope with no X-Tenant-ID
    # header. A second seeded role is the rename target ("Other
    # Role") and a third carries the duplicate name "Test Role",
    # the same valid body the update helper puts (name 2-20,
    # description left None, trimmed by the model validator), so
    # no 422 can mask the 409. A future change that drops the
    # duplicate check would break this lock while leaving the
    # create 409 lock and the update 200/403 locks green, so the
    # paths are locked separately.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Tenant role writer",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b387"),
        name="Other Role",
        description="The role being renamed in this test",
        permissions=[Permission.ROLE_VIEW_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b389"),
        name="Test Role",
        description="A role for testing purposes",
        permissions=[Permission.ROLE_VIEW_ONLY],
    ).insert()

    response = await client.put(
        "/roles/68c302ef6bf7a039b7e9b387",
        json=UpdateRoleDto(
            name="Test Role",
        ).model_dump(),
    )
    assert response.status_code == 409
    body = response.json()
    assert body["code"] == 409
    assert body["error"] == "Role with identifier Test Role already exists."
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    # The 409 must still carry the error-response headers: the
    # handler sets no-store only after the guard, so on this path
    # they come from the central ApiBaseException handler, and a
    # cached 409 could otherwise be served to a different user
    # after an account switch on a shared machine.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"

    # Same security-headers lock as the role list 200 and 404
    # tests: the pure-ASGI middleware stamps every HTTP response
    # with no path exclusions, so the role update 409 must carry
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
    # Postcondition: the duplicate check fires before any write,
    # so the request is side-effect free - still exactly one
    # "Test Role" row (the seeded holder, id ...389), the rename
    # target still carries its old name, and the seeded
    # permission role is still there with its permission.
    duplicates = await Role.find(Role.name == "Test Role").to_list()
    assert len(duplicates) == 1
    assert duplicates[0].id == PydanticObjectId("68c302ef6bf7a039b7e9b389")
    assert duplicates[0].permissions == [Permission.ROLE_VIEW_ONLY]
    target = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b387")
    )
    assert target is not None
    assert target.name == "Other Role"
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.permissions == [Permission.ROLE_READ_AND_WRITE_ONLY]


@pytest.mark.asyncio
async def test_update_role_duplicate_name_raises_conflict_at_repository(client: AsyncClient):
    """
        The role update DuplicateKeyError backstop, not yet locked:
        function-name grep count 0 for
        update_role_duplicate_name_raises_conflict_at_repository in
        this file (verified fresh this run). The endpoint-level 409
        lock (test_update_duplicate_role...) covers the service
        check in role_service.update_role, but two concurrent
        renames onto the same name can both pass that
        single_or_none check before either writes, so the second
        write hits Role.name's unique index inside the repository's
        doc.update() - and without a backstop that DuplicateKeyError
        escaped as a 500. The fix maps it in
        RoleRepository.update to RoleAlreadyExistsException
        (core/exceptions.py:40-42), which subclasses
        ConflictException with the message "Role with identifier
        <name> already exists." (common/exceptions.py:26-38), so
        the central handler returns the same 409 the service check
        returns. The repository is called directly here, bypassing
        the service guard on purpose: the guard would return 409
        before the repository is reached, so only a direct call
        exercises the DuplicateKeyError path deterministically (a
        concurrent-PUT test would be timing-dependent). The client
        fixture is only used to initialise the per-test database
        (conftest.py:24-44, db.drop() after); no HTTP call is made.
        Name is the only unique index on Role (domain/entities/
        role.py:7, no Settings.indexes), so any DuplicateKeyError
        from this update is a name collision. A future change that
        drops the repository catch would break this lock while
        leaving the endpoint-level update 409 lock green, so the
        two layers are locked separately.
    """
    from beanie import PydanticObjectId

    from api.core.exceptions import RoleAlreadyExistsException
    from api.domain.entities.role import Role
    from api.infrastructure.persistence.repositories.role_repository_impl import RoleRepository

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b390"),
        name="Other Role",
        description="The role being renamed in this test",
        permissions=[Permission.ROLE_VIEW_ONLY],
    ).insert()
    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b391"),
        name="Test Role",
        description="A role for testing purposes",
        permissions=[Permission.ROLE_VIEW_ONLY],
    ).insert()

    repository = RoleRepository()
    with pytest.raises(RoleAlreadyExistsException) as excinfo:
        await repository.update(
            role_id="68c302ef6bf7a039b7e9b390",
            data=UpdateRoleDto(name="Test Role"),
        )
    assert excinfo.value.message == "Role with identifier Test Role already exists."

    # Postcondition: the failed write left no trace - still exactly
    # one "Test Role" row (the seeded holder, id ...391) and the
    # rename target still carries its old name.
    duplicates = await Role.find(Role.name == "Test Role").to_list()
    assert len(duplicates) == 1
    assert duplicates[0].id == PydanticObjectId("68c302ef6bf7a039b7e9b391")
    target = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b390")
    )
    assert target is not None
    assert target.name == "Other Role"


@pytest.mark.asyncio
async def test_create_role_duplicate_name_raises_conflict_at_repository(client: AsyncClient):
    """
        The role create DuplicateKeyError backstop, not yet locked:
        function-name grep count 0 for
        create_role_duplicate_name_raises_conflict_at_repository in
        this file (verified fresh this run). The endpoint-level 409
        lock (test_create_duplicate_role...) covers the service
        check in role_service.create_role, but two concurrent
        creates with the same name can both pass that
        single_or_none check before either writes, so the second
        insert hits Role.name's unique index inside the repository's
        doc.insert() - and without a backstop that DuplicateKeyError
        escaped as a 500. The fix maps it in
        RoleRepository.create to RoleAlreadyExistsException
        (core/exceptions.py:40-42), which subclasses
        ConflictException with the message "Role with identifier
        <name> already exists." (common/exceptions.py:26-38), so
        the central handler returns the same 409 the service check
        returns. The repository is called directly here, bypassing
        the service guard on purpose: the guard would return 409
        before the repository is reached, so only a direct call
        exercises the DuplicateKeyError path deterministically (a
        concurrent-POST test would be timing-dependent). The client
        fixture is only used to initialise the per-test database
        (conftest.py:24-44, db.drop() after); no HTTP call is made.
        Name is the only unique index on Role (domain/entities/
        role.py:7, no Settings.indexes), so any DuplicateKeyError
        from this create is a name collision. A future change that
        drops the repository catch would break this lock while
        leaving the endpoint-level create 409 lock and the update
        repository backstop lock green, so the layers are locked
        separately.
    """
    from beanie import PydanticObjectId

    from api.core.exceptions import RoleAlreadyExistsException
    from api.domain.entities.role import Role
    from api.infrastructure.persistence.repositories.role_repository_impl import RoleRepository

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b392"),
        name="Test Role",
        description="A role for testing purposes",
        permissions=[Permission.ROLE_VIEW_ONLY],
    ).insert()

    repository = RoleRepository()
    with pytest.raises(RoleAlreadyExistsException) as excinfo:
        await repository.create(
            data=CreateRoleDto(
                name="Test Role",
                description="A role for testing purposes",
            ),
        )
    assert excinfo.value.message == "Role with identifier Test Role already exists."

    # Postcondition: the failed insert left no trace - still exactly
    # one "Test Role" row (the seeded holder, id ...392).
    duplicates = await Role.find(Role.name == "Test Role").to_list()
    assert len(duplicates) == 1
    assert duplicates[0].id == PydanticObjectId("68c302ef6bf7a039b7e9b392")


async def test_create_role_missing_body_returns_422_with_security_headers(client: AsyncClient):
    """
        The role-create POST with no request body at all:
    """
    # The first branch of the role body-shape sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_role_missing_body before appending. The account
    # body-shape sweeps are complete (register,
    # password-reset-request, password-reset-confirmation,
    # activate, change-email-request, change-email-confirmation,
    # resend-activation-email, login JSON-body - iterations
    # 2547-2555) and the tenant sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # plus the per-field sweep - iterations 2556-2577), and no
    # other endpoint test file locks a body-shape 422 yet, so the
    # role sweep starts here with POST /roles/. The endpoint takes
    # a required `data: CreateRoleDto` body parameter
    # (role_endpoint.py:178-189) whose name field is required
    # (role_dto.py:27-30; description and tenant_id are optional),
    # so a request carrying no body fails FastAPI request
    # validation before the handler body runs:
    # RoleService.create_role never runs, so no role record is
    # created -- no duplicate-name check, no repository write.
    # No body and no content type are sent, so the failure is a
    # missing body, not a content-type rejection. This is distinct
    # from the missing-field locks (an object body with a field
    # absent) and from the scalar-body locks (valid JSON of the
    # wrong type): here there is no body to parse at all, so the
    # failure is a missing required body whose detail loc is still
    # ["body"], mirroring the tenant and account missing-body 422
    # locks. The endpoint is permission-gated
    # (ROLE_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own body,
    # so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 422, exactly as in the tenant missing-body
    # lock. The role is seeded with the mocked user's exact
    # role_id (68c302ef6bf7a039b7e9b386, conftest.py) and the
    # route's ROLE_READ_AND_WRITE_ONLY permission. The default
    # conftest mock is a host caller (tenant_id None), so the
    # handler's _assert_create_scope check cannot fire.
    # Deliberately no exact error-type assertion, mirroring the
    # tenant and account missing-body 422 locks. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the tenant and account missing-body 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps every
    # HTTP response, including validation errors, with no path
    # exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/roles/",
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
    # mirroring the other role locks in this file, using
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


async def test_create_role_non_object_body_returns_422_with_security_headers(client: AsyncClient):
    """
        The role-create POST with a JSON array body:
    """
    # The second branch of the role body-shape sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_role_non_object_body before appending. The account
    # body-shape sweeps are complete (register,
    # password-reset-request, password-reset-confirmation,
    # activate, change-email-request, change-email-confirmation,
    # resend-activation-email, login JSON-body - iterations
    # 2547-2555) and the tenant sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # plus the per-field sweep - iterations 2556-2577), and the
    # role sweep started in iteration 2578 with the missing-body
    # lock, so the non-object body is next here with POST
    # /roles/. The endpoint takes a required `data:
    # CreateRoleDto` body parameter (role_endpoint.py:178-189)
    # whose name field is required (role_dto.py:27-30;
    # description and tenant_id are optional), so a JSON array
    # body cannot coerce to the DTO and fails FastAPI request
    # validation before the handler body runs:
    # RoleService.create_role never runs, so no role record is
    # created -- no duplicate-name check, no repository write.
    # The DTO's mode="after" normalize_name_and_description
    # validator only runs after valid field parsing, so it cannot
    # mask the 422. This is distinct from the missing-body lock
    # (no body at all) and from the missing-field locks (an
    # object body with a field absent): here a body is present
    # and parses as JSON, but of the wrong type, so the failure
    # is a body-shape 422 whose detail loc is still ["body"],
    # mirroring the tenant and account non-object 422 locks. The
    # endpoint is permission-gated (ROLE_READ_AND_WRITE_ONLY),
    # and FastAPI solves sub-dependencies before validating the
    # endpoint's own body, so the mocked caller's role must be
    # seeded first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the tenant non-object-body lock. The role is seeded
    # with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # ROLE_READ_AND_WRITE_ONLY permission. The default conftest
    # mock is a host caller (tenant_id None), so the handler's
    # _assert_create_scope check cannot fire. Deliberately no
    # exact error-type assertion, mirroring the tenant and
    # account non-object 422 locks. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the tenant and account non-object 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps every
    # HTTP response, including validation errors, with no path
    # exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/roles/",
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
    # mirroring the other role locks in this file, using
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


async def test_create_role_string_body_returns_422_with_security_headers(client: AsyncClient):
    """
        The role-create POST with a JSON string body:
    """
    # The third branch of the role body-shape sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_role_string_body before appending. The account
    # body-shape sweeps are complete (register,
    # password-reset-request, password-reset-confirmation,
    # activate, change-email-request, change-email-confirmation,
    # resend-activation-email, login JSON-body - iterations
    # 2547-2555) and the tenant sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # plus the per-field sweep - iterations 2556-2577), and the
    # role sweep locked missing body (2578) and non-object body
    # (2579), so the string body is next here with POST
    # /roles/. The endpoint takes a required `data:
    # CreateRoleDto` body parameter (role_endpoint.py:178-189)
    # whose name field is required (role_dto.py:27-30;
    # description and tenant_id are optional), so a JSON string
    # body cannot coerce to the DTO and fails FastAPI request
    # validation before the handler body runs:
    # RoleService.create_role never runs, so no role record is
    # created -- no duplicate-name check, no repository write.
    # The DTO's mode="after" normalize_name_and_description
    # validator only runs after valid field parsing, so it cannot
    # mask the 422. This is distinct from the missing-body lock
    # (no body at all) and from the non-object lock (a JSON array
    # body): here a body is present and parses as JSON, but of
    # the wrong scalar type, so the failure is a body-shape 422
    # whose detail loc is still ["body"], mirroring the tenant
    # and account string-body 422 locks. The endpoint is
    # permission-gated (ROLE_READ_AND_WRITE_ONLY), and FastAPI
    # solves sub-dependencies before validating the endpoint's
    # own body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the tenant
    # string-body lock. The role is seeded with the mocked
    # user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's ROLE_READ_AND_WRITE_ONLY
    # permission. The default conftest mock is a host caller
    # (tenant_id None), so the handler's _assert_create_scope
    # check cannot fire. Deliberately no exact error-type
    # assertion, mirroring the tenant and account string-body
    # 422 locks. Deliberately no Cache-Control/Pragma assertion:
    # a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store headers
    # do not apply to it, mirroring the tenant and account
    # string-body 422 locks. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/roles/",
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
    # mirroring the other role locks in this file, using
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


async def test_create_role_numeric_body_returns_422_with_security_headers(client: AsyncClient):
    """
        The role-create POST with a JSON numeric body:
    """
    # The fourth branch of the role body-shape sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_role_numeric_body before appending. The account
    # body-shape sweeps are complete (register,
    # password-reset-request, password-reset-confirmation,
    # activate, change-email-request, change-email-confirmation,
    # resend-activation-email, login JSON-body - iterations
    # 2547-2555) and the tenant sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # plus the per-field sweep - iterations 2556-2577), and the
    # role sweep locked missing body (2578), non-object body
    # (2579) and string body (2580), so the numeric body is next
    # here with POST /roles/. The endpoint takes a required `data:
    # CreateRoleDto` body parameter (role_endpoint.py:178-189)
    # whose name field is required (role_dto.py:27-30;
    # description and tenant_id are optional), so a JSON numeric
    # body cannot coerce to the DTO and fails FastAPI request
    # validation before the handler body runs:
    # RoleService.create_role never runs, so no role record is
    # created -- no duplicate-name check, no repository write.
    # The DTO's mode="after" normalize_name_and_description
    # validator only runs after valid field parsing, so it cannot
    # mask the 422. This is distinct from the missing-body lock
    # (no body at all), from the non-object lock (a JSON array
    # body) and from the string-body lock (a JSON string body):
    # here a body is present and parses as JSON, but of the wrong
    # scalar type, so the failure is a body-shape 422 whose
    # detail loc is still ["body"], mirroring the tenant and
    # account numeric-body 422 locks. The endpoint is
    # permission-gated (ROLE_READ_AND_WRITE_ONLY), and FastAPI
    # solves sub-dependencies before validating the endpoint's
    # own body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the tenant
    # numeric-body lock. The role is seeded with the mocked
    # user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's ROLE_READ_AND_WRITE_ONLY
    # permission. The default conftest mock is a host caller
    # (tenant_id None), so the handler's _assert_create_scope
    # check cannot fire. Deliberately no exact error-type
    # assertion, mirroring the tenant and account numeric-body
    # 422 locks. Deliberately no Cache-Control/Pragma assertion:
    # a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store headers
    # do not apply to it, mirroring the tenant and account
    # numeric-body 422 locks. The security headers ARE locked:
    # the pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/roles/",
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
    # mirroring the other role locks in this file, using
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


async def test_create_role_boolean_body_returns_422_with_security_headers(client: AsyncClient):
    """
        The role-create POST with a JSON boolean body:
    """
    # The fifth branch of the role body-shape sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_role_boolean_body before appending. The account
    # body-shape sweeps are complete (register,
    # password-reset-request, password-reset-confirmation,
    # activate, change-email-request, change-email-confirmation,
    # resend-activation-email, login JSON-body - iterations
    # 2547-2555) and the tenant sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # plus the per-field sweep - iterations 2556-2577), and the
    # role sweep locked missing body (2578), non-object body
    # (2579), string body (2580) and numeric body (2581), so the
    # boolean body is next here with POST /roles/. The endpoint
    # takes a required `data: CreateRoleDto` body parameter
    # (role_endpoint.py:178-189) whose name field is required
    # (role_dto.py:27-30; description and tenant_id are
    # optional), so a JSON boolean body cannot coerce to the DTO
    # and fails FastAPI request validation before the handler
    # body runs: RoleService.create_role never runs, so no role
    # record is created -- no duplicate-name check, no
    # repository write. The DTO's mode="after"
    # normalize_name_and_description validator only runs after
    # valid field parsing, so it cannot mask the 422. This is
    # distinct from the missing-body lock (no body at all), from
    # the non-object lock (a JSON array body), from the
    # string-body lock (a JSON string body) and from the
    # numeric-body lock (a JSON number body): here a body is
    # present and parses as JSON, but of the wrong scalar type,
    # so the failure is a body-shape 422 whose detail loc is
    # still ["body"], mirroring the tenant and account
    # boolean-body 422 locks. The endpoint is permission-gated
    # (ROLE_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 422, exactly as in the tenant boolean-body
    # lock. The role is seeded with the mocked user's exact
    # role_id (68c302ef6bf7a039b7e9b386, conftest.py) and the
    # route's ROLE_READ_AND_WRITE_ONLY permission. The default
    # conftest mock is a host caller (tenant_id None), so the
    # handler's _assert_create_scope check cannot fire.
    # Deliberately no exact error-type assertion, mirroring the
    # tenant and account boolean-body 422 locks. Deliberately
    # no Cache-Control/Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it,
    # mirroring the tenant and account boolean-body 422 locks.
    # The security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/roles/",
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
    # mirroring the other role locks in this file, using
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


async def test_create_role_null_body_returns_422_with_security_headers(client: AsyncClient):
    """
        The role-create POST with an explicit JSON null body:
    """
    # The sixth branch of the role body-shape sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_role_null_body before appending. The account
    # body-shape sweeps are complete (register,
    # password-reset-request, password-reset-confirmation,
    # activate, change-email-request, change-email-confirmation,
    # resend-activation-email, login JSON-body - iterations
    # 2547-2555) and the tenant sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # plus the per-field sweep - iterations 2556-2577), and the
    # role sweep locked missing body (2578), non-object body
    # (2579), string body (2580), numeric body (2581) and
    # boolean body (2582), so the null body is next here with
    # POST /roles/. The endpoint takes a required
    # `data: CreateRoleDto` body parameter
    # (role_endpoint.py:178-189) whose name field is required
    # (role_dto.py:27-30; description and tenant_id are
    # optional), so an explicit JSON null body cannot coerce to
    # the DTO and fails FastAPI request validation before the
    # handler body runs: RoleService.create_role never runs, so
    # no role record is created -- no duplicate-name check, no
    # repository write. The DTO's mode="after"
    # normalize_name_and_description validator only runs after
    # valid field parsing, so it cannot mask the 422. This is
    # distinct from the missing-body lock (no body at all), from
    # the non-object lock (a JSON array body), from the
    # string-body lock (a JSON string body), from the
    # numeric-body lock (a JSON number body) and from the
    # boolean-body lock (a JSON boolean body): here a body is
    # present and parses as JSON, but is an explicit null, so
    # the failure is a body-shape 422 whose detail loc is
    # still ["body"], mirroring the tenant and account
    # null-body 422 locks. The body is sent as the literal
    # string "null" with a JSON content type rather than via
    # json=None, so the null is unambiguous and does not depend
    # on how the HTTP client encodes a None json argument,
    # mirroring the tenant and account null-body locks. The
    # endpoint is permission-gated (ROLE_READ_AND_WRITE_ONLY),
    # and FastAPI solves sub-dependencies before validating the
    # endpoint's own body, so the mocked caller's role must be
    # seeded first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the tenant null-body lock. The role is seeded with the
    # mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # ROLE_READ_AND_WRITE_ONLY permission. The default conftest
    # mock is a host caller (tenant_id None), so the handler's
    # _assert_create_scope check cannot fire. Deliberately no
    # exact error-type assertion, mirroring the tenant and
    # account null-body 422 locks. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the tenant and account null-body 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps every
    # HTTP response, including validation errors, with no path
    # exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/roles/",
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
    # mirroring the other role locks in this file, using
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


async def test_create_role_malformed_json_body_returns_422_with_security_headers(client: AsyncClient):
    """
        The role-create POST with a malformed (non-JSON) body:
    """
    # The seventh branch of the role body-shape sweep, verified
    # fresh this run, not assumed: function-name grep count 0 for
    # create_role_malformed_json_body before appending. The account
    # body-shape sweeps are complete (register,
    # password-reset-request, password-reset-confirmation,
    # activate, change-email-request, change-email-confirmation,
    # resend-activation-email, login JSON-body - iterations
    # 2547-2555) and the tenant sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # plus the per-field sweep - iterations 2556-2577), and the
    # role sweep locked missing body (2578), non-object body
    # (2579), string body (2580), numeric body (2581), boolean
    # body (2582) and null body (2583), so the malformed-JSON
    # body is next here with POST /roles/. The endpoint takes a
    # required `data: CreateRoleDto` body parameter
    # (role_endpoint.py:178-189) whose name field is required
    # (role_dto.py:27-30; description and tenant_id are
    # optional), so a body that is not valid JSON at all cannot
    # even be parsed, and fails FastAPI request validation
    # before the handler body runs: RoleService.create_role
    # never runs, so no role record is created -- no
    # duplicate-name check, no repository write. This is
    # distinct from the missing-body lock (no body at all) and
    # from the non-object lock (a JSON array body) and from the
    # string/numeric/boolean/null scalar locks (valid JSON of
    # the wrong type): here the body is not JSON at all, so the
    # failure is a JSON decode error whose detail loc is still
    # ["body"], mirroring the tenant and account malformed-JSON
    # 422 locks. The body is sent with an explicit JSON content
    # type so the failure is a parse failure, not a
    # content-type rejection. The DTO's mode="after"
    # normalize_name_and_description validator only runs after
    # valid field parsing, so it cannot mask the 422. The
    # endpoint is permission-gated (ROLE_READ_AND_WRITE_ONLY),
    # and FastAPI solves sub-dependencies before validating
    # the endpoint's own body, so the mocked caller's role
    # must be seeded first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly
    # as in the tenant malformed-JSON lock. The role is seeded
    # with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # ROLE_READ_AND_WRITE_ONLY permission. The default conftest
    # mock is a host caller (tenant_id None), so the handler's
    # _assert_create_scope check cannot fire. Deliberately no
    # exact error-type assertion, mirroring the tenant and
    # account malformed-JSON 422 locks. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the tenant and account malformed-JSON 422 locks. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation errors,
    # with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/roles/",
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
    # mirroring the other role locks in this file, using
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


async def test_create_role_missing_name_returns_422_with_security_headers(client: AsyncClient):
    """
    The role-create POST with the name field omitted entirely:
    `name` is a required `str` field with no default, so
    Pydantic request validation rejects the body with 422 before
    the handler body runs.
    """
    # The first per-field validation branch of the role sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_role_missing_name before appending. The
    # role body-shape sweep is complete (missing body, non-object,
    # string, numeric, boolean, null, malformed JSON locked in
    # iterations 2578-2584), so the per-field sweep starts here
    # with POST /roles/. The endpoint takes a required
    # `data: CreateRoleDto` body parameter
    # (role_endpoint.py:178-189) whose name field is required
    # (role_dto.py:27-30; description and tenant_id are
    # optional), so a body with name omitted fails FastAPI
    # request validation before the handler body runs:
    # RoleService.create_role never runs, so no role record is
    # created -- no duplicate-name check, no repository write.
    # This is distinct from the missing-body lock (no body at
    # all) and from the non-object/scalar locks (valid JSON of
    # the wrong type): here the body is a valid JSON object with
    # every other field valid, so the failure is a "missing"
    # error whose detail loc is ["body", "name"], mirroring the
    # tenant missing-field 422 locks. The description sent is a
    # valid 10+ character string, so it cannot mask the 422.
    # The DTO's mode="after" normalize_name_and_description
    # validator only runs after valid field parsing, so it cannot
    # mask the 422. The endpoint is permission-gated
    # (ROLE_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 422, exactly as in the tenant
    # missing-field locks. The role is seeded with the mocked
    # user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's ROLE_READ_AND_WRITE_ONLY
    # permission. The default conftest mock is a host caller
    # (tenant_id None), so the handler's _assert_create_scope
    # check cannot fire. Deliberately no exact error-type
    # assertion, mirroring the tenant missing-field 422 locks.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to
    # it, mirroring the tenant and role 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps every
    # HTTP response, including validation errors, with no path
    # exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/roles/",
        json={
            "description": "A role for testing the missing name field",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "name" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other role locks in this file, using
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


async def test_create_role_non_string_name_returns_422_with_security_headers(client: AsyncClient):
    """
    The role-create POST with a non-string `name` (a JSON number):
    `name` is a required `str` field, and Pydantic v2 does not coerce
    numbers to strings, so request validation rejects the body with
    422 before the handler body runs.
    """
    # The second per-field validation branch of the role sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_role_non_string_name before appending.
    # The role body-shape sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # locked in iterations 2578-2584) and the per-field sweep
    # started with the missing-name lock (iteration 2585), so
    # the non-string name is next here with POST /roles/. The
    # endpoint takes a required `data: CreateRoleDto` body
    # parameter (role_endpoint.py:178-189) whose name field is a
    # required str (role_dto.py:27-30; description and tenant_id
    # are optional), so a body with name=123 fails FastAPI
    # request validation before the handler body runs:
    # RoleService.create_role never runs, so no role record is
    # created -- no duplicate-name check, no repository write.
    # This is distinct from the missing-name lock (field absent)
    # and from the scalar-body locks (valid JSON of the wrong
    # type for the whole body): here the body is a valid JSON
    # object with every other field valid, so the failure is a
    # "string_type" error whose detail loc is ["body", "name"],
    # mirroring the tenant non-string-field 422 locks. The
    # description sent is a valid 10+ character string, so it
    # cannot mask the 422. The DTO's mode="after"
    # normalize_name_and_description validator only runs after
    # valid field parsing, so it cannot mask the 422. The
    # endpoint is permission-gated (ROLE_READ_AND_WRITE_ONLY),
    # and FastAPI solves sub-dependencies before validating the
    # endpoint's own body, so the mocked caller's role must be
    # seeded first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the tenant missing-field locks. The role is seeded with
    # the mocked user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's ROLE_READ_AND_WRITE_ONLY
    # permission. The default conftest mock is a host caller
    # (tenant_id None), so the handler's _assert_create_scope
    # check cannot fire. Deliberately no exact error-type
    # assertion, mirroring the tenant non-string-field 422 locks.
    # Deliberately no Cache-Control/Pragma assertion: a 422 is
    # FastAPI request validation, not an ApiBaseException, so
    # the central handler's no-store headers do not apply to
    # it, mirroring the tenant and role 422 locks. The security
    # headers ARE locked: the pure-ASGI middleware stamps every
    # HTTP response, including validation errors, with no path
    # exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/roles/",
        json={
            "name": 123,
            "description": "A role for testing a non-string name",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "name" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other role locks in this file, using
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


async def test_create_role_object_name_returns_422_with_security_headers(client: AsyncClient):
    """
    The role-create POST with an object `name` (a JSON object):
    `name` is a required `str` field, and Pydantic v2 does not coerce
    objects to strings, so request validation rejects the body with
    422 before the handler body runs.
    """
    # The third per-field validation branch of the role sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_role_object_name before appending.
    # The role body-shape sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # locked in iterations 2578-2584) and the per-field sweep
    # started with the missing-name lock (iteration 2585) and
    # the non-string-name lock (iteration 2586), so the object
    # name is next here with POST /roles/. The endpoint takes
    # a required `data: CreateRoleDto` body parameter
    # (role_endpoint.py:178-189) whose name field is a required
    # str (role_dto.py:27-30; description and tenant_id are
    # optional), so a body with name={"nested": "object"} fails
    # FastAPI request validation before the handler body runs:
    # RoleService.create_role never runs, so no role record is
    # created -- no duplicate-name check, no repository write.
    # This is distinct from the missing-name lock (field absent)
    # and from the non-string-name lock (a JSON number): here the
    # name is a JSON object, so the failure is a "string_type"
    # error whose detail loc is ["body", "name"], mirroring the
    # tenant non-string-field 422 locks. The description sent is
    # a valid 10+ character string, so it cannot mask the 422.
    # The DTO's mode="after" normalize_name_and_description
    # validator only runs after valid field parsing, so it cannot
    # mask the 422. The endpoint is permission-gated
    # (ROLE_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own body,
    # so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 422, exactly as in the tenant
    # missing-field locks. The role is seeded with the mocked
    # user's exact role_id (68c302ef6bf7a039b7e9b386, conftest.py)
    # and the route's ROLE_READ_AND_WRITE_ONLY permission. The
    # default conftest mock is a host caller (tenant_id None), so
    # the handler's _assert_create_scope check cannot fire.
    # Deliberately no exact error-type assertion, mirroring the
    # tenant non-string-field 422 locks. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the tenant and role 422 locks. The security headers ARE
    # locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/roles/",
        json={
            "name": {"nested": "object"},
            "description": "A role for testing an object name",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "name" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other role locks in this file, using
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

async def test_create_role_float_name_returns_422_with_security_headers(client: AsyncClient):
    """
    The role-create POST with a float `name` (a JSON number 1.5):
    `name` is a required `str` field, and Pydantic v2 does not coerce
    floats to strings, so request validation rejects the body with
    422 before the handler body runs.
    """
    # The fourth per-field validation branch of the role sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_role_float_name before appending.
    # The role body-shape sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # locked in iterations 2578-2584) and the per-field sweep
    # started with the missing-name lock (iteration 2585), the
    # non-string-name lock (iteration 2586) and the object-name
    # lock (iteration 2587), so the float name is next here with
    # POST /roles/. The endpoint takes a required
    # `data: CreateRoleDto` body parameter
    # (role_endpoint.py:178-189) whose name field is a required
    # str (role_dto.py:27-30; description and tenant_id are
    # optional), so a body with name=1.5 fails FastAPI request
    # validation before the handler body runs: RoleService
    # .create_role never runs, so no role record is created --
    # no duplicate-name check, no repository write. This is
    # distinct from the missing-name lock (field absent), the
    # non-string-name lock (a JSON integer) and the object-name
    # lock (a JSON object): here the name is a JSON float, so the
    # failure is a "string_type" error whose detail loc is
    # ["body", "name"], mirroring the tenant non-string-field
    # 422 locks. The description sent is a valid 10+ character
    # string, so it cannot mask the 422. The DTO's mode="after"
    # normalize_name_and_description validator only runs after
    # valid field parsing, so it cannot mask the 422. The
    # endpoint is permission-gated (ROLE_READ_AND_WRITE_ONLY),
    # and FastAPI solves sub-dependencies before validating the
    # endpoint's own body, so the mocked caller's role must be
    # seeded first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the tenant missing-field locks. The role is seeded with
    # the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # ROLE_READ_AND_WRITE_ONLY permission. The default conftest
    # mock is a host caller (tenant_id None), so the handler's
    # _assert_create_scope check cannot fire. Deliberately no
    # exact error-type assertion, mirroring the tenant
    # non-string-field 422 locks. Deliberately no Cache-Control
    # /Pragma assertion: a 422 is FastAPI request validation,
    # not an ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the tenant and role
    # 422 locks. The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/roles/",
        json={
            "name": 1.5,
            "description": "A role for testing a float name",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "name" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other role locks in this file, using
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

async def test_create_role_too_short_name_returns_422_with_security_headers(client: AsyncClient):
    """
    The role-create POST with a one-character `name` ("a"):
    `name` is a required `str` field with min_length=2, so request
    validation rejects the body with 422 before the handler body
    runs.
    """
    # The fifth per-field validation branch of the role sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_role_too_short_name before appending.
    # The role body-shape sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # locked in iterations 2578-2584) and the per-field sweep
    # started with the missing-name lock (iteration 2585), the
    # non-string-name lock (iteration 2586), the object-name lock
    # (iteration 2587) and the float-name lock (iteration 2588),
    # so the too-short name is next here with POST /roles/. The
    # endpoint takes a required `data: CreateRoleDto` body
    # parameter (role_endpoint.py:178-189) whose name field is a
    # required str with min_length=2 and max_length=20
    # (role_dto.py:27-30; description and tenant_id are
    # optional), so a body with name="a" fails FastAPI request
    # validation before the handler body runs: RoleService
    # .create_role never runs, so no role record is created --
    # no duplicate-name check, no repository write. This is
    # distinct from the missing-name lock (field absent), the
    # non-string-name lock (a JSON integer), the object-name
    # lock (a JSON object) and the float-name lock (a JSON
    # float): here the name is a valid JSON string that is
    # simply too short, so the failure is a "string_too_short"
    # error whose detail loc is ["body", "name"], mirroring
    # the tenant per-field 422 locks. The field-level
    # min_length check runs before the DTO's mode="after"
    # normalize_name_and_description validator, so the
    # validator cannot mask the 422. The description sent is
    # a valid 10+ character string, so it cannot mask the
    # 422. The endpoint is permission-gated
    # (ROLE_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the tenant
    # missing-field locks. The role is seeded with the mocked
    # user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's ROLE_READ_AND_WRITE_ONLY
    # permission. The default conftest mock is a host caller
    # (tenant_id None), so the handler's _assert_create_scope
    # check cannot fire. Deliberately no exact error-type
    # assertion, mirroring the tenant non-string-field 422
    # locks. Deliberately no Cache-Control /Pragma assertion:
    # a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the tenant and
    # role 422 locks. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/roles/",
        json={
            "name": "a",
            "description": "A role for testing a short name",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "name" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other role locks in this file, using
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

async def test_create_role_too_long_name_returns_422_with_security_headers(client: AsyncClient):
    """
    The role-create POST with a 21-character `name`
    ("RoleNameThatIsTooLong"): `name` is a required `str`
    field with max_length=20, so request validation rejects
    the body with 422 before the handler body runs.
    """
    # The sixth per-field validation branch of the role sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_role_too_long_name before appending.
    # The role body-shape sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # locked in iterations 2578-2584) and the per-field sweep
    # started with the missing-name lock (iteration 2585), the
    # non-string-name lock (iteration 2586), the object-name lock
    # (iteration 2587), the float-name lock (iteration 2588) and
    # the too-short-name lock (iteration 2589), so the too-long
    # name is next here with POST /roles/. The endpoint takes a
    # required `data: CreateRoleDto` body parameter
    # (role_endpoint.py:178-189) whose name field is a required
    # str with min_length=2 and max_length=20
    # (role_dto.py:27-30; description and tenant_id are
    # optional), so a body with name="RoleNameThatIsTooLong"
    # (21 characters) fails FastAPI request validation before
    # the handler body runs: RoleService.create_role never
    # runs, so no role record is created -- no duplicate-name
    # check, no repository write. This is distinct from the
    # missing-name lock (field absent), the non-string-name
    # lock (a JSON integer), the object-name lock (a JSON
    # object), the float-name lock (a JSON float) and the
    # too-short-name lock (a 1-character string): here the
    # name is a valid JSON string that is simply too long, so
    # the failure is a "string_too_long" error whose detail
    # loc is ["body", "name"], mirroring the tenant per-field
    # 422 locks. The field-level max_length check runs before
    # the DTO's mode="after" normalize_name_and_description
    # validator, so the validator cannot mask the 422. The
    # description sent is a valid 10+ character string, so it
    # cannot mask the 422. The endpoint is permission-gated
    # (ROLE_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the tenant
    # missing-field locks. The role is seeded with the mocked
    # user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's ROLE_READ_AND_WRITE_ONLY
    # permission. The default conftest mock is a host caller
    # (tenant_id None), so the handler's _assert_create_scope
    # check cannot fire. Deliberately no exact error-type
    # assertion, mirroring the tenant non-string-field 422
    # locks. Deliberately no Cache-Control /Pragma assertion:
    # a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the tenant and
    # role 422 locks. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/roles/",
        json={
            "name": "RoleNameThatIsTooLong",
            "description": "A role for testing a long name",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "name" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other role locks in this file, using
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


async def test_create_role_whitespace_name_returns_422_with_security_headers(client: AsyncClient):
    """
    The role-create POST with a whitespace-only `name`
    ("   "): `name` is a required `str` field with
    min_length=2, so the 3-space string passes the field
    check and only the DTO's mode="after" validator
    rejects the blank value with 422 before the handler
    body runs.
    """
    # The seventh per-field validation branch of the role sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_role_whitespace_name before appending.
    # The role body-shape sweep is complete (missing body,
    # non-object, string, numeric, boolean, null, malformed JSON
    # locked in iterations 2578-2584) and the per-field sweep
    # continued with the missing-name lock (iteration 2585), the
    # non-string-name lock (iteration 2586), the object-name lock
    # (iteration 2587), the float-name lock (iteration 2588), the
    # too-short-name lock (iteration 2589) and the too-long-name
    # lock (iteration 2590), so the whitespace-only name is next
    # here with POST /roles/. The endpoint takes a required
    # `data: CreateRoleDto` body parameter
    # (role_endpoint.py:178-189) whose name field is a required
    # str with min_length=2 and max_length=20
    # (role_dto.py:27-30; description and tenant_id are
    # optional), so a body with name="   " (3 spaces) passes
    # the field-level min_length check and only fails in the
    # DTO's mode="after" normalize_name_and_description
    # validator, which strips the value to "" and raises
    # ValueError "name must not be blank". That is still
    # FastAPI request validation, so it fails before the
    # handler body runs: RoleService.create_role never runs,
    # so no role record is created -- no duplicate-name check,
    # no repository write. This is distinct from the
    # too-short-name lock (a 1-character string failing the
    # field-level min_length) and from the missing/non-string/
    # object/float locks: here the name is a valid JSON string
    # of valid length that is blank after trimming, so the
    # failure is a model-validator "value_error". The
    # assertion reads the validator message rather than the
    # error loc: a model_validator error is located at the
    # body, not at the field, so its loc carries no "name"
    # part, mirroring the register blank-first_name 422 lock.
    # The description sent is a valid 10+ character string,
    # so it cannot mask the 422. The endpoint is
    # permission-gated (ROLE_READ_AND_WRITE_ONLY), and FastAPI
    # solves sub-dependencies before validating the
    # endpoint's own body, so the mocked caller's role must
    # be seeded first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly
    # as in the tenant missing-field locks. The role is seeded
    # with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # ROLE_READ_AND_WRITE_ONLY permission. The default
    # conftest mock is a host caller (tenant_id None), so the
    # handler's _assert_create_scope check cannot fire.
    # Deliberately no Cache-Control /Pragma assertion: a 422
    # is FastAPI request validation, not an ApiBaseException,
    # so the central handler's no-store headers do not apply
    # to it, mirroring the tenant and role 422 locks. The
    # security headers ARE locked: the pure-ASGI middleware
    # stamps every HTTP response, including validation
    # errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/roles/",
        json={
            "name": "   ",
            "description": "A role for testing a blank name",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "name must not be blank" in str(err.get("msg", ""))
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
    # mirroring the other role locks in this file, using
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


async def test_create_role_whitespace_description_returns_422_with_security_headers(client: AsyncClient):
    """
    The role-create POST with a whitespace-only `description`
    ("          "): `description` is an optional `str` field
    with min_length=10, so the 10-space string passes the
    field check and only the DTO's mode="after" validator
    rejects the blank value with 422 before the handler
    body runs.
    """
    # The eighth per-field validation branch of the role sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_role_whitespace_description before
    # appending. The role body-shape sweep is complete (missing
    # body, non-object, string, numeric, boolean, null,
    # malformed JSON locked in iterations 2578-2584) and the
    # per-field sweep continued with the missing-name lock
    # (iteration 2585), the non-string-name lock (iteration
    # 2586), the object-name lock (iteration 2587), the
    # float-name lock (iteration 2588), the too-short-name lock
    # (iteration 2589), the too-long-name lock (iteration 2590)
    # and the whitespace-only-name lock (iteration 2591), so
    # the whitespace-only description is next here with POST
    # /roles/. The endpoint takes a required `data:
    # CreateRoleDto` body parameter (role_endpoint.py:178-189)
    # whose description field is an optional str with
    # min_length=10 and max_length=200 (role_dto.py:27-30;
    # name is required, tenant_id optional), so a body with
    # description="          " (10 spaces) passes the
    # field-level min_length check and only fails in the DTO's
    # mode="after" normalize_name_and_description validator,
    # which strips the value to "" and raises ValueError
    # "description must not be blank". That is still FastAPI
    # request validation, so it fails before the handler body
    # runs: RoleService.create_role never runs, so no role
    # record is created -- no duplicate-name check, no
    # repository write. This is distinct from the
    # whitespace-only-name lock (iteration 2591), which
    # exercised only the validator's name branch: here the
    # name is a valid "Test Role" string and only the
    # description branch rejects the blank value. The
    # assertion reads the validator message rather than the
    # error loc: a model_validator error is located at the
    # body, not at the field, so its loc carries no
    # "description" part, mirroring the register
    # blank-first_name 422 lock and the whitespace-name lock.
    # The endpoint is permission-gated
    # (ROLE_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the tenant
    # missing-field locks. The role is seeded with the mocked
    # user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's ROLE_READ_AND_WRITE_ONLY
    # permission. The default conftest mock is a host caller
    # (tenant_id None), so the handler's _assert_create_scope
    # check cannot fire. Deliberately no Cache-Control /Pragma
    # assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the tenant and
    # role 422 locks. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/roles/",
        json={
            "name": "Test Role",
            "description": "          ",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "description must not be blank" in str(err.get("msg", ""))
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
    # mirroring the other role locks in this file, using
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


async def test_create_role_missing_description_returns_201_with_security_headers(client: AsyncClient):
    """
    The role-create POST with `description` omitted entirely:
    `description` is an optional `str` field with default None
    (min_length=10, max_length=200), so a body carrying only a
    valid `name` must succeed with 201 and persist the role with
    description None -- the success branch of the optional-field
    sweep, distinct from the 422 locks that reject a present-but
    blank description.
    """
    # The ninth per-field validation branch of the role sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_role_missing_description before
    # appending. The role body-shape sweep is complete (missing
    # body, non-object, string, numeric, boolean, null,
    # malformed JSON locked in iterations 2578-2584) and the
    # per-field sweep continued with the missing-name lock
    # (iteration 2585), the non-string-name lock (iteration
    # 2586), the object-name lock (iteration 2587), the
    # float-name lock (iteration 2588), the too-short-name lock
    # (iteration 2589), the too-long-name lock (iteration 2590),
    # the whitespace-only-name lock (iteration 2591) and the
    # whitespace-only-description lock (iteration 2592), so the
    # omitted description is next here with POST /roles/. The
    # endpoint takes a required `data: CreateRoleDto` body
    # parameter (role_endpoint.py:178-189) whose description
    # field is an optional str with default None, min_length=10
    # and max_length=200 (role_dto.py:27-30; name is required,
    # tenant_id optional), so omitting it leaves description
    # None: the DTO's mode="after"
    # normalize_name_and_description validator only strips a
    # description when it is a str, and None passes through
    # untouched. The service path confirms the success branch
    # end to end (role_service.py:94-98): create_role checks
    # for a duplicate name -- "Test Role" is fresh in the
    # per-test database, which the conftest fixture drops after
    # each test -- then repository.create persists the DTO as
    # given, so the stored role carries description None
    # (role.py:8, description is Optional[str] | None). This is
    # distinct from the whitespace-only-description lock
    # (iteration 2592), which exercised only the validator's
    # blank-description rejection: here no description is sent
    # at all, so the request must succeed. The endpoint is
    # permission-gated (ROLE_READ_AND_WRITE_ONLY), and FastAPI
    # solves sub-dependencies before validating the endpoint's
    # own body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 201, exactly as in the tenant
    # missing-field locks. The role is seeded with the mocked
    # user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's ROLE_READ_AND_WRITE_ONLY
    # permission. The default conftest mock is a host caller
    # (tenant_id None), so the handler's _assert_create_scope
    # check cannot fire. Deliberately no Cache-Control /Pragma
    # assertion: a 201 is a create response, not a cacheable
    # list/get, and the central handler's no-store headers do
    # not apply to it, mirroring the create_role helper's 201
    # lock at the top of this file. The security headers ARE
    # locked: the pure-ASGI middleware stamps every HTTP
    # response, including create responses, with no path
    # exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/roles/",
        json={
            "name": "Test Role",
        },
    )
    assert response.status_code == 201
    created_id = response.json()["id"]
    assert isinstance(created_id, str) and created_id
    assert "refresh_token" not in response.headers.get("set-cookie", "")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
    assert "permissions-policy" in response.headers
    # Lock the twelve most sensitive directives as disabled,
    # mirroring the other role locks in this file, using
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
    # Postcondition: the role was actually persisted with the
    # omitted description stored as None, not defaulted to an
    # empty string or dropped by the create path.
    stored = await Role.find_one(
        Role.id == PydanticObjectId(created_id)
    )
    assert stored is not None
    assert stored.name == "Test Role"
    assert stored.description is None


async def test_create_role_too_short_description_returns_422_with_security_headers(client: AsyncClient):
    """
    The role-create POST with a too-short `description`
    ("short", 5 chars): `description` is an optional `str`
    field with min_length=10, so the 5-character string fails
    the field-level check and FastAPI request validation
    rejects it with 422 before the handler body runs.
    """
    # The tenth per-field validation branch of the role sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_role_too_short_description before
    # appending. The role body-shape sweep is complete (missing
    # body, non-object, string, numeric, boolean, null,
    # malformed JSON locked in iterations 2578-2584) and the
    # per-field sweep continued with the missing-name lock
    # (iteration 2585), the non-string-name lock (iteration
    # 2586), the object-name lock (iteration 2587), the
    # float-name lock (iteration 2588), the too-short-name lock
    # (iteration 2589), the too-long-name lock (iteration 2590),
    # the whitespace-only-name lock (iteration 2591), the
    # whitespace-only-description lock (iteration 2592) and the
    # omitted-description lock (iteration 2593), so the
    # too-short description is next here with POST /roles/.
    # The endpoint takes a required `data: CreateRoleDto` body
    # parameter (role_endpoint.py:178-189) whose description
    # field is an optional str with default None, min_length=10
    # and max_length=200 (role_dto.py:27-30; name is required,
    # tenant_id optional), so a body with description="short"
    # (5 chars) fails the field-level min_length check: this is
    # a field error located at ["body", "description"], unlike
    # the whitespace-only-description lock (iteration 2592),
    # whose 10-space value passed min_length and only failed in
    # the DTO's mode="after" validator with a body-level loc.
    # The mode="after" validator would also reject a stripped
    # description under 10 chars, but the field constraint fires
    # first, so the loc assertion mirrors the too-short-name
    # lock (iteration 2589). FastAPI request validation fails
    # before the handler body runs: RoleService.create_role
    # never runs, so no role record is created -- no
    # duplicate-name check, no repository write. This is
    # distinct from the omitted-description lock (iteration
    # 2593), which exercised only the success branch for a
    # missing description: here a description IS sent, but it
    # is too short to be accepted. The endpoint is
    # permission-gated (ROLE_READ_AND_WRITE_ONLY), and FastAPI
    # solves sub-dependencies before validating the endpoint's
    # own body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the tenant
    # missing-field locks. The role is seeded with the mocked
    # user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's ROLE_READ_AND_WRITE_ONLY
    # permission. The default conftest mock is a host caller
    # (tenant_id None), so the handler's _assert_create_scope
    # check cannot fire. Deliberately no Cache-Control /Pragma
    # assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the tenant and
    # role 422 locks. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/roles/",
        json={
            "name": "Test Role",
            "description": "short",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "description" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other role locks in this file, using
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


async def test_create_role_too_long_description_returns_422_with_security_headers(client: AsyncClient):
    """
    The role-create POST with a too-long `description`
    ("x" * 201, 201 chars): `description` is an optional `str`
    field with max_length=200, so the 201-character string fails
    the field-level check and FastAPI request validation
    rejects it with 422 before the handler body runs.
    """
    # The eleventh per-field validation branch of the role sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_role_too_long_description before
    # appending. The role body-shape sweep is complete (missing
    # body, non-object, string, numeric, boolean, null,
    # malformed JSON locked in iterations 2578-2584) and the
    # per-field sweep continued with the missing-name lock
    # (iteration 2585), the non-string-name lock (iteration
    # 2586), the object-name lock (iteration 2587), the
    # float-name lock (iteration 2588), the too-short-name lock
    # (iteration 2589), the too-long-name lock (iteration 2590),
    # the whitespace-only-name lock (iteration 2591), the
    # whitespace-only-description lock (iteration 2592), the
    # omitted-description lock (iteration 2593) and the
    # too-short-description lock (iteration 2594), so the
    # too-long description is next here with POST /roles/.
    # The endpoint takes a required `data: CreateRoleDto` body
    # parameter (role_endpoint.py:178-189) whose description
    # field is an optional str with default None, min_length=10
    # and max_length=200 (role_dto.py:27-30; name is required,
    # tenant_id optional), so a body with a 201-char
    # description fails the field-level max_length check: this
    # is a field error located at ["body", "description"],
    # mirroring the too-short-description lock (iteration
    # 2594), which failed the min_length=10 check at the same
    # loc. FastAPI request validation fails before the handler
    # body runs: RoleService.create_role never runs, so no role
    # record is created -- no duplicate-name check, no
    # repository write. This is distinct from the
    # omitted-description lock (iteration 2593), which
    # exercised only the success branch for a missing
    # description: here a description IS sent, but it is too
    # long to be accepted. The endpoint is permission-gated
    # (ROLE_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 422, exactly as in the tenant
    # missing-field locks. The role is seeded with the mocked
    # user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's ROLE_READ_AND_WRITE_ONLY
    # permission. The default conftest mock is a host caller
    # (tenant_id None), so the handler's _assert_create_scope
    # check cannot fire. Deliberately no Cache-Control /Pragma
    # assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it, mirroring the tenant and
    # role 422 locks. The security headers ARE locked: the
    # pure-ASGI middleware stamps every HTTP response,
    # including validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/roles/",
        json={
            "name": "Test Role",
            "description": "x" * 201,
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "description" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other role locks in this file, using
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


async def test_create_role_non_string_description_returns_422_with_security_headers(client: AsyncClient):
    """
    The role-create POST with a non-string `description` (a JSON
    number): `description` is an optional `str` field, and
    Pydantic v2 does not coerce numbers to strings, so request
    validation rejects the body with 422 before the handler body
    runs.
    """
    # The twelfth per-field validation branch of the role sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_role_non_string_description before
    # appending. The role body-shape sweep is complete (missing
    # body, non-object, string, numeric, boolean, null,
    # malformed JSON locked in iterations 2578-2584) and the
    # per-field sweep continued with the missing-name lock
    # (iteration 2585), the non-string-name lock (iteration
    # 2586), the object-name lock (iteration 2587), the
    # float-name lock (iteration 2588), the too-short-name lock
    # (iteration 2589), the too-long-name lock (iteration 2590),
    # the whitespace-only-name lock (iteration 2591), the
    # whitespace-only-description lock (iteration 2592), the
    # omitted-description lock (iteration 2593), the
    # too-short-description lock (iteration 2594) and the
    # too-long-description lock (iteration 2595), so the
    # non-string description is next here with POST /roles/.
    # The endpoint takes a required `data: CreateRoleDto` body
    # parameter (role_endpoint.py:178-189) whose description
    # field is an optional str with default None, min_length=10
    # and max_length=200 (role_dto.py:27-30; name is required,
    # tenant_id optional), so a body with description=12345
    # fails the field-level string check: this is a field error
    # located at ["body", "description"], mirroring the
    # non-string-name lock (iteration 2586), which failed the
    # same way at ["body", "name"]. The name sent is a valid
    # 9-character string, so it cannot mask the 422. The DTO's
    # mode="after" normalize_name_and_description validator only
    # runs after valid field parsing, so it cannot mask the
    # 422. This is distinct from the omitted-description lock
    # (iteration 2593), which exercised only the success branch
    # for a missing description: here a description IS sent,
    # but it is not a string. FastAPI request validation fails
    # before the handler body runs: RoleService.create_role
    # never runs, so no role record is created -- no
    # duplicate-name check, no repository write. The endpoint
    # is permission-gated (ROLE_READ_AND_WRITE_ONLY), and
    # FastAPI solves sub-dependencies before validating the
    # endpoint's own body, so the mocked caller's role must be
    # seeded first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the tenant missing-field locks. The role is seeded
    # with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # ROLE_READ_AND_WRITE_ONLY permission. The default conftest
    # mock is a host caller (tenant_id None), so the handler's
    # _assert_create_scope check cannot fire. Deliberately no
    # exact error-type assertion, mirroring the tenant
    # non-string-field 422 locks. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the tenant and role 422 locks. The security headers ARE
    # locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/roles/",
        json={
            "name": "Test Role",
            "description": 12345,
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "description" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other role locks in this file, using
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


async def test_create_role_non_string_tenant_id_returns_422_with_security_headers(client: AsyncClient):
    """
    The role-create POST with a non-string `tenant_id` (a JSON
    list): `tenant_id` is an optional `PydanticObjectId` field,
    and Pydantic v2 does not coerce lists to object ids, so
    request validation rejects the body with 422 before the
    handler body runs.
    """
    # Function-name grep count 0 for
    # create_role_non_string_tenant_id before appending,
    # verified fresh this run, not assumed. The create
    # per-field sweep so far covers name (non-string lock,
    # iteration 2586) and description (non-string lock,
    # iteration 2596), so tenant_id is the remaining
    # CreateRoleDto field: name: str, description:
    # Optional[str], tenant_id: PydanticObjectId | None
    # (role_dto.py:27-30). The endpoint takes a required
    # `data: CreateRoleDto` body parameter
    # (role_endpoint.py:178-189), so a body with
    # tenant_id=["not-an-object-id"] fails the field-level
    # object-id check: this is a field error located at
    # ["body", "tenant_id"], mirroring the non-string
    # description lock, which failed the same way at
    # ["body", "description"]. The name sent is a valid
    # 9-character string, so it cannot mask the 422, and no
    # description is sent (it is optional), so it cannot
    # mask it either. The DTO's mode="after"
    # normalize_name_and_description validator only runs
    # after valid field parsing, so it cannot mask the 422.
    # Note the handler overwrites data.tenant_id with the
    # caller's own tenant_id (role_endpoint.py:190-196), but
    # that assignment runs only after request validation, so
    # it cannot rescue a non-object-id body. FastAPI request
    # validation fails before the handler body runs:
    # RoleService.create_role never runs, so no role record
    # is created -- no duplicate-name check, no repository
    # write. The endpoint is permission-gated
    # (ROLE_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the tenant
    # missing-field locks. The role is seeded with the mocked
    # user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's
    # ROLE_READ_AND_WRITE_ONLY permission. The default
    # conftest mock is a host caller (tenant_id None), so the
    # handler's _assert_create_scope check cannot fire.
    # Deliberately no exact error-type assertion, mirroring
    # the tenant non-string-field 422 locks. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the tenant and role 422 locks. The security headers ARE
    # locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/roles/",
        json={
            "name": "Test Role",
            "tenant_id": ["not-an-object-id"],
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
    # mirroring the other role locks in this file, using
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


async def test_create_role_object_description_returns_422_with_security_headers(client: AsyncClient):
    """
    The role-create POST with an object `description` (a JSON
    object): `description` is an optional `str` field, and
    Pydantic v2 does not coerce objects to strings, so request
    validation rejects the body with 422 before the handler body
    runs.
    """
    # The thirteenth per-field validation branch of the role sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_role_object_description before
    # appending. The role body-shape sweep is complete (missing
    # body, non-object, string, numeric, boolean, null,
    # malformed JSON locked in iterations 2578-2584) and the
    # per-field sweep continued with the missing-name lock
    # (iteration 2585), the non-string-name lock (iteration
    # 2586), the object-name lock (iteration 2587), the
    # float-name lock (iteration 2588), the too-short-name lock
    # (iteration 2589), the too-long-name lock (iteration 2590),
    # the whitespace-only-name lock (iteration 2591), the
    # whitespace-only-description lock (iteration 2592), the
    # omitted-description lock (iteration 2593), the
    # too-short-description lock (iteration 2594), the
    # too-long-description lock (iteration 2595) and the
    # non-string-description lock (iteration 2596), so the
    # object description is next here with POST /roles/.
    # The endpoint takes a required `data: CreateRoleDto` body
    # parameter (role_endpoint.py:178-189) whose description
    # field is an optional str with default None, min_length=10
    # and max_length=200 (role_dto.py:27-30; name is required,
    # tenant_id optional), so a body with description={"key":
    # "value"} fails the field-level string check: this is a
    # field error located at ["body", "description"],
    # mirroring the non-string-description lock (iteration
    # 2596), which failed the same way at ["body",
    # "description"] for a numeric description, and the
    # object-name lock (iteration 2587), which failed the same
    # way at ["body", "name"]. The name sent is a valid
    # 9-character string, so it cannot mask the 422. The DTO's
    # mode="after" normalize_name_and_description validator only
    # runs after valid field parsing, so it cannot mask the
    # 422. This is distinct from the omitted-description lock
    # (iteration 2593), which exercised only the success branch
    # for a missing description: here a description IS sent,
    # but it is not a string. FastAPI request validation fails
    # before the handler body runs: RoleService.create_role
    # never runs, so no role record is created -- no
    # duplicate-name check, no repository write. The endpoint
    # is permission-gated (ROLE_READ_AND_WRITE_ONLY), and
    # FastAPI solves sub-dependencies before validating the
    # endpoint's own body, so the mocked caller's role must be
    # seeded first -- otherwise the permission gate's
    # RoleNotFoundException 404 would mask the 422, exactly as
    # in the tenant missing-field locks. The role is seeded
    # with the mocked user's exact role_id
    # (68c302ef6bf7a039b7e9b386, conftest.py) and the route's
    # ROLE_READ_AND_WRITE_ONLY permission. The default conftest
    # mock is a host caller (tenant_id None), so the handler's
    # _assert_create_scope check cannot fire. Deliberately no
    # exact error-type assertion, mirroring the tenant
    # non-string-field 422 locks. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the tenant and role 422 locks. The security headers ARE
    # locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/roles/",
        json={
            "name": "Test Role",
            "description": {"key": "value"},
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "description" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other role locks in this file, using
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


async def test_create_role_float_description_returns_422_with_security_headers(client: AsyncClient):
    """
    The role-create POST with a float `description` (a JSON
    number 1.5): `description` is an optional `str` field, and
    Pydantic v2 does not coerce floats to strings, so request
    validation rejects the body with 422 before the handler body
    runs.
    """
    # The fourteenth per-field validation branch of the role sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_role_float_description before
    # appending. The role body-shape sweep is complete (missing
    # body, non-object, string, numeric, boolean, null,
    # malformed JSON locked in iterations 2578-2584) and the
    # per-field sweep continued with the missing-name lock
    # (iteration 2585), the non-string-name lock (iteration
    # 2586), the object-name lock (iteration 2587), the
    # float-name lock (iteration 2588), the too-short-name lock
    # (iteration 2589), the too-long-name lock (iteration 2590),
    # the whitespace-only-name lock (iteration 2591), the
    # whitespace-only-description lock (iteration 2592), the
    # omitted-description lock (iteration 2593), the
    # too-short-description lock (iteration 2594), the
    # too-long-description lock (iteration 2595), the
    # non-string-description lock (iteration 2596) and the
    # object-description lock (iteration 2597), so the float
    # description is next here with POST /roles/.
    # The endpoint takes a required `data: CreateRoleDto` body
    # parameter (role_endpoint.py:178-189) whose description
    # field is an optional str with default None, min_length=10
    # and max_length=200 (role_dto.py:27-30; name is required,
    # tenant_id optional), so a body with description=1.5 fails
    # the field-level string check: this is a field error
    # located at ["body", "description"], mirroring the
    # non-string-description lock (iteration 2596), which failed
    # the same way at ["body", "description"] for a numeric
    # description, and the float-name lock (iteration 2588),
    # which failed the same way at ["body", "name"] for a float
    # name. The name sent is a valid 9-character string, so it
    # cannot mask the 422. The DTO's mode="after"
    # normalize_name_and_description validator only runs after
    # valid field parsing, so it cannot mask the 422. This is
    # distinct from the omitted-description lock (iteration
    # 2593), which exercised only the success branch for a
    # missing description: here a description IS sent, but it is
    # not a string. FastAPI request validation fails before the
    # handler body runs: RoleService.create_role never runs, so
    # no role record is created -- no duplicate-name check, no
    # repository write. The endpoint is permission-gated
    # (ROLE_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 422, exactly as in the tenant missing-field
    # locks. The role is seeded with the mocked user's exact
    # role_id (68c302ef6bf7a039b7e9b386, conftest.py) and the
    # route's ROLE_READ_AND_WRITE_ONLY permission. The default
    # conftest mock is a host caller (tenant_id None), so the
    # handler's _assert_create_scope check cannot fire.
    # Deliberately no exact error-type assertion, mirroring the
    # tenant non-string-field 422 locks. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the tenant and role 422 locks. The security headers ARE
    # locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/roles/",
        json={
            "name": "Test Role",
            "description": 1.5,
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "description" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other role locks in this file, using
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

async def test_create_role_boolean_description_returns_422_with_security_headers(client: AsyncClient):
    """
    The role-create POST with a boolean `description` (a JSON
    true): `description` is an optional `str` field, and
    Pydantic v2 does not coerce booleans to strings, so request
    validation rejects the body with 422 before the handler body
    runs.
    """
    # The fifteenth per-field validation branch of the role sweep,
    # verified fresh this run, not assumed: function-name grep
    # count 0 for create_role_boolean_description before
    # appending. The role body-shape sweep is complete (missing
    # body, non-object, string, numeric, boolean, null,
    # malformed JSON locked in iterations 2578-2584) and the
    # per-field sweep continued with the missing-name lock
    # (iteration 2585), the non-string-name lock (iteration
    # 2586), the object-name lock (iteration 2587), the
    # float-name lock (iteration 2588), the too-short-name lock
    # (iteration 2589), the too-long-name lock (iteration 2590),
    # the whitespace-only-name lock (iteration 2591), the
    # whitespace-only-description lock (iteration 2592), the
    # omitted-description lock (iteration 2593), the
    # too-short-description lock (iteration 2594), the
    # too-long-description lock (iteration 2595), the
    # non-string-description lock (iteration 2596), the
    # object-description lock (iteration 2597) and the
    # float-description lock (iteration 2598), so the boolean
    # description is next here with POST /roles/.
    # The endpoint takes a required `data: CreateRoleDto` body
    # parameter (role_endpoint.py:178-189) whose description
    # field is an optional str with default None, min_length=10
    # and max_length=200 (role_dto.py:27-30; name is required,
    # tenant_id optional), so a body with description=true fails
    # the field-level string check: this is a field error
    # located at ["body", "description"], mirroring the
    # non-string-description lock (iteration 2596), which failed
    # the same way at ["body", "description"] for a numeric
    # description, and the float-description lock (iteration
    # 2598), which failed the same way at ["body", "description"]
    # for a float description. The name sent is a valid
    # 9-character string, so it cannot mask the 422. The DTO's
    # mode="after" normalize_name_and_description validator only
    # runs after valid field parsing, so it cannot mask the 422.
    # This is distinct from the omitted-description lock
    # (iteration 2593), which exercised only the success branch
    # for a missing description: here a description IS sent, but
    # it is not a string. FastAPI request validation fails before
    # the handler body runs: RoleService.create_role never runs,
    # so no role record is created -- no duplicate-name check, no
    # repository write. The endpoint is permission-gated
    # (ROLE_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first --
    # otherwise the permission gate's RoleNotFoundException 404
    # would mask the 422, exactly as in the tenant missing-field
    # locks. The role is seeded with the mocked user's exact
    # role_id (68c302ef6bf7a039b7e9b386, conftest.py) and the
    # route's ROLE_READ_AND_WRITE_ONLY permission. The default
    # conftest mock is a host caller (tenant_id None), so the
    # handler's _assert_create_scope check cannot fire.
    # Deliberately no exact error-type assertion, mirroring the
    # tenant non-string-field 422 locks. Deliberately no
    # Cache-Control/Pragma assertion: a 422 is FastAPI request
    # validation, not an ApiBaseException, so the central
    # handler's no-store headers do not apply to it, mirroring
    # the tenant and role 422 locks. The security headers ARE
    # locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.post(
        "/roles/",
        json={
            "name": "Test Role",
            "description": True,
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "description" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other role locks in this file, using
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


async def test_update_role_nonstring_name_returns_422_with_security_headers(client: AsyncClient):
    """
        The role-update PUT with a non-string `name`:
    """
    # The first per-field validation branch of the role-update
    # sweep, verified fresh this run, not assumed:
    # function-name grep count 0 for
    # update_role_nonstring_name before appending. The
    # role-create per-field sweep already locks non-string
    # name and description (iterations 2585-2586 area), but
    # the update endpoint (PUT /roles/{role_id}) had no
    # per-field non-string lock at all -- only success,
    # scope-403, and duplicate-409 tests. The endpoint takes
    # a required `data: UpdateRoleDto` body parameter
    # (role_endpoint.py:229-242) whose name field is a
    # required str inherited from CreateRoleDto
    # (role_dto.py:27-30), so a JSON-list value cannot be
    # coerced to a str under any Pydantic version and fails
    # FastAPI request validation before the handler body
    # runs: the scope guard, the role lookup, and
    # RoleService.update_role never run, so no role record
    # is read or written and no path role_id needs to exist
    # (the seeded role's id is used as the path value
    # anyway). The DTO's mode="after"
    # normalize_name_and_description validator only runs
    # after valid field parsing, so it cannot mask the 422.
    # The description sent is a valid 10+ character string,
    # so it cannot mask the 422, and permissions defaults to
    # an empty list. The endpoint is permission-gated
    # (ROLE_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the create-role
    # non-string locks. The role is seeded with the mocked
    # user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's ROLE_READ_AND_WRITE_ONLY
    # permission, mirroring the create-role non-string name
    # lock in this file. The default conftest mock is a host
    # caller (tenant_id None), so the handler's
    # _assert_update_scope check cannot fire. Deliberately
    # no exact error-type assertion, mirroring the
    # create-role non-string locks in this file: a str-type
    # error type has no precedent here. Deliberately no
    # Cache-Control / Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it.
    # The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.put(
        "/roles/68c302ef6bf7a039b7e9b386",
        json={
            "name": ["not", "a", "string"],
            "description": "A role for testing a non-string name",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "name" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other role locks in this file, using
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
    # Postcondition: the handler never ran, so no role was
    # read or written and the seeded role is still there with
    # its permission and original name.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.name == "Host administrator"
    assert stored.permissions == [Permission.ROLE_READ_AND_WRITE_ONLY]


async def test_update_role_nonstring_description_returns_422_with_security_headers(client: AsyncClient):
    """
        The role-update PUT with a non-string `description`:
    """
    # The second per-field validation branch of the role-update
    # sweep, verified fresh this run, not assumed:
    # function-name grep count 0 for
    # update_role_nonstring_description before appending. The
    # role-create per-field sweep already locks non-string
    # name and description (iterations 2585-2586 area), and
    # the update endpoint (PUT /roles/{role_id}) gained its
    # first per-field lock for non-string name in iteration
    # 2814, but had no description lock -- only success,
    # scope-403, and duplicate-409 tests besides it. The
    # endpoint takes a required `data: UpdateRoleDto` body
    # parameter (role_endpoint.py:235-243) whose description
    # field is an optional str with default None,
    # min_length=10 and max_length=200 inherited from
    # CreateRoleDto (role_dto.py:27-30), so a JSON-list value
    # cannot be coerced to a str under any Pydantic version
    # and fails FastAPI request validation before the handler
    # body runs: the scope guard, the role lookup, and
    # RoleService.update_role never run, so no role record
    # is read or written and no path role_id needs to exist
    # (the seeded role's id is used as the path value
    # anyway). The DTO's mode="after"
    # normalize_name_and_description validator only runs
    # after valid field parsing, so it cannot mask the 422.
    # The name sent is a valid 9-character string, so it
    # cannot mask the 422, and permissions defaults to an
    # empty list. The endpoint is permission-gated
    # (ROLE_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the create-role
    # non-string locks. The role is seeded with the mocked
    # user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's ROLE_READ_AND_WRITE_ONLY
    # permission, mirroring the update-role non-string name
    # lock in this file. The default conftest mock is a host
    # caller (tenant_id None), so the handler's
    # _assert_update_scope check cannot fire. Deliberately
    # no exact error-type assertion, mirroring the
    # create-role non-string locks in this file: a str-type
    # error type has no precedent here. Deliberately no
    # Cache-Control / Pragma assertion: a 422 is FastAPI
    # request validation, not an ApiBaseException, so the
    # central handler's no-store headers do not apply to it.
    # The security headers ARE locked: the pure-ASGI
    # middleware stamps every HTTP response, including
    # validation errors, with no path exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.put(
        "/roles/68c302ef6bf7a039b7e9b386",
        json={
            "name": "Test Role",
            "description": ["not", "a", "string"],
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "description" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other role locks in this file, using
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
    # Postcondition: the handler never ran, so no role was
    # read or written and the seeded role is still there with
    # its permission and original name and description.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.name == "Host administrator"
    assert stored.description == "Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller"
    assert stored.permissions == [Permission.ROLE_READ_AND_WRITE_ONLY]


async def test_update_role_nonstring_tenant_id_returns_422_with_security_headers(client: AsyncClient):
    """
        The role-update PUT with a non-string `tenant_id`:
    """
    # The third per-field validation branch of the role-update
    # sweep, verified fresh this run, not assumed:
    # function-name grep count 0 for
    # update_role_nonstring_tenant_id before appending. The
    # role-create per-field sweep already locks non-string
    # name and description, and the update endpoint (PUT
    # /roles/{role_id}) gained per-field locks for non-string
    # name in iteration 2814 and non-string description in
    # iteration 2815, but had no tenant_id lock -- only
    # success, scope-403, and duplicate-409 tests besides
    # them. The endpoint takes a required `data:
    # UpdateRoleDto` body parameter
    # (role_endpoint.py:230-238) whose tenant_id field is a
    # PydanticObjectId or None, default None, inherited from
    # CreateRoleDto (role_dto.py:29), so a JSON-list value
    # cannot be coerced to an ObjectId under any Pydantic
    # version and fails FastAPI request validation before the
    # handler body runs: the scope guard, the role lookup,
    # and RoleService.update_role never run, so no role
    # record is read or written and no path role_id needs to
    # exist (the seeded role's id is used as the path value
    # anyway). The DTO's mode="after"
    # normalize_name_and_description validator only runs
    # after valid field parsing, so it cannot mask the 422.
    # The name sent is a valid 9-character string and the
    # description a valid 21-character string, so neither
    # can mask the 422, and permissions defaults to an empty
    # list. The endpoint is permission-gated
    # (ROLE_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the create-role
    # non-string locks. The role is seeded with the mocked
    # user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's ROLE_READ_AND_WRITE_ONLY
    # permission, mirroring the update-role non-string name
    # and description locks in this file. The default
    # conftest mock is a host caller (tenant_id None), so
    # the handler's _assert_update_scope check cannot fire.
    # Deliberately no exact error-type assertion, mirroring
    # the create-role non-string locks in this file: an
    # ObjectId-type error type has no precedent here.
    # Deliberately no Cache-Control / Pragma assertion: a
    # 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it. The security headers ARE
    # locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.put(
        "/roles/68c302ef6bf7a039b7e9b386",
        json={
            "name": "Test Role",
            "description": "A valid description",
            "tenant_id": ["not", "an", "objectid"],
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
    # mirroring the other role locks in this file, using
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
    # Postcondition: the handler never ran, so no role was
    # read or written and the seeded role is still there with
    # its permission and original name and description.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.name == "Host administrator"
    assert stored.description == "Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller"
    assert stored.permissions == [Permission.ROLE_READ_AND_WRITE_ONLY]


async def test_update_role_nonstring_permissions_returns_422_with_security_headers(client: AsyncClient):
    """
        The role-update PUT with a non-string `permissions`:
    """
    # The fourth per-field validation branch of the role-update
    # sweep, verified fresh this run, not assumed:
    # function-name grep count 0 for
    # update_role_nonstring_permissions before appending. The
    # role-create per-field sweep already locks non-string
    # name and description, and the update endpoint (PUT
    # /roles/{role_id}) gained per-field locks for non-string
    # name in iteration 2814, non-string description in
    # iteration 2815, and non-string tenant_id in iteration
    # 2816, but had no permissions lock -- only success,
    # scope-403, and duplicate-409 tests besides them. The
    # endpoint takes a required `data: UpdateRoleDto` body
    # parameter (role_endpoint.py:230-238) whose permissions
    # field is a List[Permission] with default_factory=list
    # (role_dto.py:65-66), so a JSON-string value cannot be
    # coerced to a list under any Pydantic version and fails
    # FastAPI request validation before the handler body
    # runs: the scope guard, the role lookup, and
    # RoleService.update_role never run, so no role record
    # is read or written and no path role_id needs to exist
    # (the seeded role's id is used as the path value
    # anyway). The DTO's mode="after"
    # normalize_name_and_description validator only runs
    # after valid field parsing, so it cannot mask the 422.
    # The name sent is a valid 9-character string and the
    # description a valid 21-character string, and tenant_id
    # is omitted (defaults to None), so no other 422 can
    # mask it. The endpoint is permission-gated
    # (ROLE_READ_AND_WRITE_ONLY), and FastAPI solves
    # sub-dependencies before validating the endpoint's own
    # body, so the mocked caller's role must be seeded first
    # -- otherwise the permission gate's RoleNotFoundException
    # 404 would mask the 422, exactly as in the create-role
    # non-string locks. The role is seeded with the mocked
    # user's exact role_id (68c302ef6bf7a039b7e9b386,
    # conftest.py) and the route's ROLE_READ_AND_WRITE_ONLY
    # permission, mirroring the update-role non-string name,
    # description, and tenant_id locks in this file. The
    # default conftest mock is a host caller (tenant_id
    # None), so the handler's _assert_update_scope check
    # cannot fire. Deliberately no exact error-type
    # assertion, mirroring the create-role non-string locks
    # in this file: a list-type error type has no precedent
    # here. Deliberately no Cache-Control / Pragma
    # assertion: a 422 is FastAPI request validation, not an
    # ApiBaseException, so the central handler's no-store
    # headers do not apply to it. The security headers ARE
    # locked: the pure-ASGI middleware stamps every HTTP
    # response, including validation errors, with no path
    # exclusions.
    from beanie import PydanticObjectId

    from api.domain.entities.role import Role
    from api.domain.enum.permission import Permission

    await Role(
        id=PydanticObjectId("68c302ef6bf7a039b7e9b386"),
        name="Host administrator",
        description="Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller",
        permissions=[Permission.ROLE_READ_AND_WRITE_ONLY],
    ).insert()
    response = await client.put(
        "/roles/68c302ef6bf7a039b7e9b386",
        json={
            "name": "Test Role",
            "description": "A valid description",
            "permissions": "ROLE_READ_ONLY",
        },
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(
        "permissions" in [str(part) for part in err.get("loc", [])]
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
    # mirroring the other role locks in this file, using
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
    # Postcondition: the handler never ran, so no role was
    # read or written and the seeded role is still there with
    # its permission and original name and description.
    stored = await Role.find_one(
        Role.id == PydanticObjectId("68c302ef6bf7a039b7e9b386")
    )
    assert stored is not None
    assert stored.name == "Host administrator"
    assert stored.description == "Role carrying ROLE_READ_AND_WRITE_ONLY for the mocked caller"
    assert stored.permissions == [Permission.ROLE_READ_AND_WRITE_ONLY]
