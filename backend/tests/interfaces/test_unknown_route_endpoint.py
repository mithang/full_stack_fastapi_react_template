import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_unknown_api_route_returns_no_store_404(client: AsyncClient):
    """
        An unmatched /api/v1 route:
    """
    # Absolute URL, so this does not depend on how httpx merges the
    # shared client's /api/v1 base_url with a relative path: the
    # request must reach the app's catch-all react_router with
    # full_path "api/v1/does-not-exist", which returns the
    # {"detail": "API route not found"} 404.
    response = await client.get("http://test/api/v1/does-not-exist")
    assert response.status_code == 404
    assert response.json() == {"detail": "API route not found"}
    # This 404 bypasses the central ApiBaseException handler (it is a
    # routing fallback, not a raised exception), so the no-store
    # headers added to that handler in iteration 1810 did not cover
    # it: without this lock, a cached 404 for a mistyped or removed
    # route could be served to a different user after an account
    # switch on a shared machine, the same class as the success-path
    # and ApiBaseException GET hardening.
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"


@pytest.mark.asyncio
async def test_spa_shell_returns_no_store_headers(client: AsyncClient):
    """
        An unmatched SPA route:
    """
    # Absolute URL, as in the iteration-1816 lock, so this does not
    # depend on how httpx merges the shared client's /api/v1 base_url:
    # the request must reach the catch-all react_router with a
    # non-api full_path, which serves the committed UI build's
    # index.html. The shell previously set only Cache-Control:
    # no-store, unlike every other no-store site in api/__init__.py,
    # so an HTTP/1.0 cache honouring only Pragma could serve a stale
    # shell from before a deploy, referencing asset files the new
    # build no longer ships.
    response = await client.get("http://test/spa-route-that-does-not-exist")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"


@pytest.mark.asyncio
async def test_bare_api_path_returns_no_store_404(client: AsyncClient):
    """
        A bare /api GET:
    """
    # The catch-all's api/ branch has two spellings: full_path == "api"
    # and full_path.startswith("api/"). The iteration-1816 lock covered
    # only the startswith spelling (/api/v1/does-not-exist); this locks
    # the bare spelling too, which returns the same 404 body and the
    # same no-store headers from the same return site.
    response = await client.get("http://test/api")
    assert response.status_code == 404
    assert response.json() == {"detail": "API route not found"}
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
