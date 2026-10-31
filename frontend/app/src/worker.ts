const pollingDelayInMilliSeconds = 10 * 1000 * 60;
let tenantId: string | null = null;
// Empty = same-origin, matching getApiBaseUrl()'s default. The classic
// worker cannot import utils, so the provider passes the base URL here.
let apiBaseUrl = "";
// The worker previously refreshed only on its 10-minute interval, so a
// freshly loaded page held no access token until the first tick. That
// left the checkout return pages (which finalise only once a token is
// held) sitting on "We're confirming your payment/cancellation" for up
// to 10 minutes after a payer returned from Stripe — a full-page
// redirect, so the in-memory token is always gone on arrival. Refresh
// once as soon as the provider seeds this worker instead of waiting
// for the first tick; the interval below keeps the token alive after
// that. Triggered from the message handler (not at script start) so
// the seed's tenantId/apiBaseUrl are applied before the first call —
// a refresh fired before the seed would go out without X-Tenant-ID
// and, on a separately hosted frontend, to the frontend origin.
let seeded = false;

async function refreshOnce() {
    const url = `${apiBaseUrl}/api/v1/account/refresh`;
    let response: Response;
    try {
        response = await fetch(url, {
            method: "POST",
            credentials: "include",
            headers: {
                "Content-Type": "application/json",
                ...(tenantId && { "X-Tenant-ID": tenantId }),
            },
        });
    } catch (error) {
        // Network failure (offline, backend down): fetch rejects rather
        // than returning a response, so without this the interval callback
        // threw an unhandled rejection. This is not an expired session, so
        // do NOT post an unauthorized message (that would log the user out
        // on a transient outage); the next tick retries the refresh.
        console.error("Worker token refresh network error:", error);
        return;
    }
    const unauthorizedMessage = {
        message: "Unauthorized",
        code: response.status,
    };
    if (!response.ok || response.status === 401) {
        // Check status before parsing the body: a non-JSON error body
        // (e.g. an HTML error page) would make response.json() throw and
        // the provider would never learn the session expired.
        return self.postMessage(unauthorizedMessage);
    }
    let data: unknown = {};
    try {
        data = await response.json();
    } catch {
        // Empty or non-JSON success body: nothing to forward, but the
        // refresh itself succeeded, so do not surface a spurious error.
    }
    self.postMessage(data);
}

self.addEventListener("message", (event: MessageEvent<{ tenantId: string | null; apiBaseUrl?: string }>) => {
    if (event.data && typeof event.data.apiBaseUrl === "string") {
        apiBaseUrl = event.data.apiBaseUrl;
    }
    if (event.data && event.data.tenantId) {
        tenantId = event.data.tenantId;
    } else if (event.data && event.data.tenantId === null) {
        tenantId = null;
    }
    // First message is the provider's seed (posted right after the
    // worker is constructed): refresh now, with the seeded values, and
    // only once — later tenant_set/tenant_removed messages must not
    // re-trigger an immediate refresh on top of the interval.
    if (!seeded) {
        seeded = true;
        void refreshOnce();
    }
});
setInterval(refreshOnce, pollingDelayInMilliSeconds);


