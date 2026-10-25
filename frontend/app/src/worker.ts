const pollingDelayInMilliSeconds = 10 * 1000 * 60;
let tenantId: string | null = null;
// Empty = same-origin, matching getApiBaseUrl()'s default. The classic
// worker cannot import utils, so the provider passes the base URL here.
let apiBaseUrl = "";

self.addEventListener("message", (event: MessageEvent<{ tenantId: string | null; apiBaseUrl?: string }>) => {
    if (event.data && typeof event.data.apiBaseUrl === "string") {
        apiBaseUrl = event.data.apiBaseUrl;
    }
    if (event.data && event.data.tenantId) {
        console.log("Worker received tenantId:", event.data.tenantId);
        tenantId = event.data.tenantId;
    } else if (event.data && event.data.tenantId === null) {
        console.log("Worker received tenantId removal");
        tenantId = null;
    }
});
setInterval(async () => {
    const url = `${apiBaseUrl}/api/v1/account/refresh`;
    console.log("Worker fetching new token with tenantId:", tenantId);
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
}, pollingDelayInMilliSeconds);


