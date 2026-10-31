import { CreateUserDto, Gender, Permission, TokenSetDto, type MeResponseDto } from "@/api";
import { useProfileImage } from "@/hooks/use-profile-image";
import {
    extractErrorMessage,
    getApiBaseUrl,
    getApiClient,
    getTenant,
} from "@/lib/utils";
import { createContext, useContext, useEffect, useRef, useState, useCallback } from "react"
import { useLocation, useNavigate } from "react-router";
import { toast } from "sonner";

// Must match the public routes under DefaultLayout in App.tsx: the
// fetchUser effect and the worker-401 handler both skip these. The old
// list missed /login, /activation and /non-active (so visiting them fired
// spurious /me + refresh calls, and a worker 401 bounced /activation and
// /non-active visitors to /login), and carried a dead /password-reset-request
// entry — the real route is /forgot-password, already listed.
// It also missed the Stripe return routes added later under the same
// public layout: a logged-out payer landing on /checkout/success or
// /checkout/cancel fired /me + refresh, and a failed refresh navigated
// them to /login instead of showing the return page.
const notProtectedRoutes = ["/login", "/password_reset_confirmation", "/register", "/forgot-password", "/activation", "/magic_link_login", "/non-active", "/checkout/success", "/checkout/cancel"];
export type UpdateProfileType = {
    firstName: string;
    lastName: string;
    gender: Gender;
    imageUrl: string | null;
}
type AuthProviderState = {
    isLoggedIn: boolean;
    user: MeResponseDto | null;
    can: (action: Permission) => boolean;
    onUpdateProfile: (data: UpdateProfileType) => Promise<void>;
    refreshCurrentUser: () => Promise<void>;
    accessToken: string,
    // Adopt an already-issued access token (e.g. passkey login returns
    // one): the [accessToken] effect below then fetches the user with
    // it, instead of the caller discarding it and depending on a
    // refresh round-trip.
    loginWithToken: (accessToken: string) => void;
    login: (data: { email: string; password: string }) => Promise<void>
    register: (data: CreateUserDto) => Promise<any>,
    resendActivationEmail: () => Promise<void>;
    logout: () => void;
}

const authContext = createContext<AuthProviderState>({
    isLoggedIn: false,
    user: null,
    can: () => false,
    onUpdateProfile: async () => { },
    refreshCurrentUser: async () => { },
    accessToken: "",
    loginWithToken: () => { },
    login: async () => { },
    register: async () => { },
    resendActivationEmail: async () => { },
    logout: () => { },
});


export function AuthProvider({ children }: { children: React.ReactNode }) {
    const [isLoggedInState, setIsLoggedInState] = useState<boolean>(false);
    const [user, setUser] = useState<MeResponseDto | null>(null);
    const [accessToken, setAccessToken] = useState<string>("");
    // Set by logout() and cleared by login()/loginWithToken(): the worker
    // keeps polling after logout (the provider stays mounted), so a token
    // it posts afterwards must not resurrect the session — see the worker
    // message handler below. A ref (not state) because that handler's
    // closure captures only the mount-time values.
    const loggedOutRef = useRef(false);

    const navigate = useNavigate();
    const { pathname } = useLocation();
    const { getProfileImage } = useProfileImage(accessToken);

    const refreshToken = useCallback(async function refreshToken() {
        setIsLoggedInState(false)
        const auth = getApiClient().account;
        try {
            const authWithRefresh = await auth.refreshTokenApiV1AccountRefreshPost({})
            setAccessToken(authWithRefresh.access_token)

        } catch (error) {
            console.error("Failed to refresh token:", error);
            // Only a server-answered failure means the refresh cookie
            // itself is bad. A failure with no numeric status is a
            // network error — the request never reached the server —
            // so the cookie may still be valid: keep the session and
            // do not navigate to /login, where the effect below skips
            // notProtectedRoutes and could never retry the cookie.
            // isLoggedIn is already false (set above), so the dashboard
            // shows Loading until the worker's next tick refreshes via
            // the cookie and posts a fresh token — the same rule
            // fetchUser follows for network failures.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            if (!hasStatus) {
                console.error("Failed to refresh token (network error, keeping session):", error);
                return;
            }
            // Drop the stale client session too, not just the route: this
            // path runs when fetchUser already failed, so the token in
            // state is known-bad, and leaving it (plus the user) set
            // while navigating to /login mirrors the stale-state bug
            // fixed for sidebar logout. Clearing the token re-runs the
            // effect below, which retries via the refresh cookie; if
            // that cookie is still valid the session self-heals, and if
            // not the refresh fails again with state already empty, so
            // this cannot loop.
            setUser(null);
            setAccessToken("");
            navigate("/login");
        }
    }, []);

    const fetchUser = useCallback(async function fetchUser(force?: boolean) {
        if (isLoggedInState && !force) return;

        const apiClient = getApiClient(accessToken);
        const auth = apiClient.account;
        try {
            const user = await auth.readUsersMeApiV1AccountMeGet();
            let imageUrl = user.image_url
            if (user.image_url) {
                // Keep a failing avatar fetch out of the auth path: this
                // try block's catch treats any failure as an expired
                // session and triggers a refresh (and a logout + /login
                // redirect if the refresh fails), so an avatar 404 or
                // network blip after a successful /me must not land
                // there. Fall back to the raw image key instead.
                try {
                    imageUrl = await getProfileImage(user.image_url);
                } catch {
                    // Fall back to user.image_url above.
                }
            }
            setIsLoggedInState(true);
            setUser({ ...user, image_url: imageUrl });

        } catch (error) {
            // Only fall through to the refresh path when the server
            // actually answered (ApiError carries a numeric status,
            // e.g. 401 for an expired token). A failure with no status
            // is a network error — the request never reached the server
            // — so it is not an expired session: refreshing would fail
            // the same way, and refreshToken's failure path clears the
            // session and navigates to /login, turning a transient
            // outage into a forced re-login (which cannot self-heal,
            // since the effect above skips notProtectedRoutes and the
            // still-valid refresh cookie is never retried there). The
            // worker's next tick retries the refresh instead, and the
            // [accessToken] effect re-fetches the user then — the same
            // rule the worker itself follows for network failures.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            if (hasStatus) {
                // Do not let the refresh fallback resurrect an explicit
                // logout: after logout() arms loggedOutRef, navigating
                // to a protected route re-runs the effect below, /me
                // fails with 401 (no token in state), and refreshing
                // here would silently restore a surviving refresh
                // cookie (network logout, or a cookie rotated by an
                // in-flight refresh) — the same resurrection the
                // worker-token guard blocks, via the effect path
                // instead. Send the user to /login with state already
                // empty instead. A server-rejected logout never arms
                // the flag, so a kept session still refreshes as
                // before, and the next login clears the flag.
                if (loggedOutRef.current) {
                    setUser(null);
                    setAccessToken("");
                    navigate("/login");
                } else {
                    await refreshToken();
                }
            } else {
                console.error("Failed to fetch user (network error, keeping session):", error);
            }
        }

    }, [accessToken]);


    async function resendActivationEmail() {
        if (!user) return;
        try {
            const auth = getApiClient(accessToken).account;
            await auth.resendActivationEmailApiV1AccountResendActivationEmailPost({
                requestBody: {
                    email: user.email,
                    id: user.id,
                    first_name: user.first_name,
                    tenant_id: user.tenant_id
                }
            });
            toast.success("Activation email resent successfully. Please check your email.", {
                richColors: true,
                position: "top-right"
            });
        } catch (error) {
            console.error("Failed to resend activation email:", error);
            // A backend response (ApiError, which carries a numeric status)
            // means the server answered and rejected the resend; a failure
            // with no status is a network error, not a failed resend, and
            // must not send the user requesting another activation email
            // for a connection problem. The generated client rejects network
            // failures with a raw TypeError, while HTTP failures arrive as ApiError.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            // Surface the server's own reason (e.g. a 422/429 detail) instead of
            // only the fixed title; the caller is the authenticated user
            // resending their own activation email, so no enumeration concern.
            toast.error(hasStatus
                ? "Failed to resend activation email"
                : "Unable to reach the server. Check your connection and try again.", {
                description: hasStatus ? extractErrorMessage(error) : undefined,
                richColors: true,
                position: "top-right"
            });
        }

    }

    function can(action: Permission) {
        return user?.role?.permissions?.includes(action) ?? false;
    }

    async function onUpdateProfile(data: UpdateProfileType) {
        if (!user) return
        try {
            const apiClient = getApiClient(accessToken);
            const users = apiClient.users;
            await users.updateUserApiV1UsersUserIdPut({
                userId: user.id,
                requestBody: {
                    first_name: data.firstName,
                    last_name: data.lastName,
                    gender: data.gender,
                }
            })
            toast.success("Profile updated successfully", {
                richColors: true
            });
            // Force the refresh: fetchUser() without force early-returns
            // once isLoggedInState is true in its closure (which it is
            // after any worker token refresh recreates it), so a plain
            // call would leave the displayed profile stale until reload.
            await fetchUser(true);
        } catch (error) {
            console.error("Error updating profile:", error);
            // A backend response (ApiError, which carries a numeric status)
            // means the server answered and rejected the update; a failure
            // with no status is a network error, not a failed profile
            // update, and must not send the user re-entering details that
            // never reached the server. The fetchUser refresh above cannot
            // throw into this catch (it handles its own failures), so the
            // error here is always from the update call itself.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus
                ? "Failed to update profile"
                : "Unable to reach the server. Check your connection and try again.", {
                // Surface the server's own message (body.error/detail or
                // a 422 validation message) instead of only the fixed
                // title; the network branch keeps no description, as
                // before.
                description: hasStatus ? extractErrorMessage(error) : undefined,
                richColors: true
            });
        }
    }

    async function refreshCurrentUser() {
        await fetchUser(true); // Force refresh
    }

    function logout() {
        // Drop the in-memory session: without this, the sidebar logout
        // only navigated to /login while the provider still held the
        // access token and user, so the app still behaved as logged in
        // (and the /login effect re-fetched the user with the old token).
        // Also arm the post-logout guard below: the worker is not torn
        // down by logout, so without it a token it posts afterwards
        // would setAccessToken straight back into a live session.
        loggedOutRef.current = true;
        setIsLoggedInState(false);
        setUser(null);
        setAccessToken("");
    }

    function loginWithToken(token: string) {
        // A fresh login ends the post-logout guard: worker tokens are
        // wanted again from here on (e.g. the self-heal after a network
        // refresh failure), so clear the flag before adopting the token.
        loggedOutRef.current = false;
        // Same pattern as login() below: do not fetch the user here
        // with a stale closure token. Setting the token re-runs the
        // [accessToken] effect, which fetches the user with it, and
        // DashboardLayout shows Loading until then.
        setAccessToken(token);
    }

    async function login(data: { email: string; password: string }) {
        const auth = getApiClient().account

        try {
            const result = await auth.loginApiV1AccountLoginPost({
                formData: {
                    username: data.email,
                    password: data.password
                }
            });
            toast.success("Login successful!", {
                richColors: true
            });
            // As in loginWithToken: a fresh login ends the post-logout
            // guard, so the worker's later tokens are accepted again.
            loggedOutRef.current = false;
            setAccessToken(result.access_token)
            // Do not call fetchUser() here: this closure captures the
            // pre-login (empty) access token, so /me would go out without
            // Authorization, fail with 401, and fall back to a refresh
            // round-trip that login should not depend on. The
            // [accessToken] effect below re-runs with the fresh token and
            // fetches the user; DashboardLayout shows Loading until then.
            navigate('/dashboard');

        } catch (e) {
            if (e instanceof Error) {
                throw e;
            } else {
                throw new Error("An unknown error occurred");
            }
        }
    }

    async function register(data: CreateUserDto) {
        const auth = getApiClient().account

        try {
            await auth.registerApiV1AccountRegisterPost({
                requestBody: data
            });

            toast.success("Registration successful! Please check your email to verify your account.", {
                richColors: true,
                position: "top-right",
                description: "Redirecting to login..."
            });
            setTimeout(() => {
                navigate("/login");
            }, 2000);
        } catch (e) {
            if (e instanceof Error) {
                throw e;
            } else {
                throw new Error("An unknown error occurred");
            }
        }
    }

    // Todo: Refactor to auto refresh token using web worker

    useEffect(() => {
        const worker = new Worker(new URL('../../worker.ts', import.meta.url));
        // Seed the worker with the already-selected tenant and API base
        // URL: it otherwise starts with tenantId null / same-origin base
        // and only learns them on a later tenant_set/tenant_removed
        // event, so after a page reload its refresh calls would go out
        // without X-Tenant-ID (and to the frontend origin on a separately
        // hosted frontend) until the tenant was re-selected.
        worker.postMessage({ tenantId: getTenant()?.id ?? null, apiBaseUrl: getApiBaseUrl() });
        worker.addEventListener("message", (event: MessageEvent<TokenSetDto | { type: string } | { message: string; code: number }>) => {
            if (event.data && 'access_token' in event.data) {
                // Ignore tokens posted after an explicit logout: the
                // worker is not torn down by logout(), so a refresh that
                // was in flight when logout ran (its response lands after
                // the logout request deleted the old cookie and sets a
                // rotated one) — or, after a network logout where the
                // cookie survives, the next 10-minute tick — would
                // otherwise setAccessToken straight back into a live
                // session, silently undoing a logout the UI reported as
                // done (same class as the sidebar-logout fix in the
                // previous iteration). The flag is cleared by the next
                // login, so normal worker refreshes are unaffected; and
                // a server-rejected logout never calls logout(), so a
                // kept session keeps receiving worker tokens as before.
                if (loggedOutRef.current) {
                    // Token dropped: see the comment above for why.
                } else {
                    setAccessToken(event.data.access_token);
                }
            } else if (event.data && 'code' in event.data) {
                // 403 joins 401/400 here because the refresh endpoint's
                // missing-cookie error is a ForbiddenException, which the
                // backend handler now maps to 403 instead of the previous
                // default 400: without this, a worker refresh with no
                // cookie would post 403, be ignored, and leave a dead
                // session standing on protected routes until the next
                // interaction. The public-route guard below still applies.
                if (event.data.code === 401 || event.data.code === 400 || event.data.code === 403) {
                    setIsLoggedInState(false);
                    setUser(null);
                    setAccessToken("");
                    // Do not bounce public routes to /login: the worker
                    // polls regardless of route, but the fetchUser effect
                    // above deliberately skips notProtectedRoutes, so a
                    // stale-cookie 401 while visiting /register (or a
                    // password-reset page) must not yank the user away.
                    // window.location is read live because this effect's
                    // closure captures only the mount-time pathname.
                    if (!notProtectedRoutes.includes(window.location.pathname)) {
                        navigate("/login");
                    }
                }
            }

        });
        // Named handlers so the cleanup below can remove them: without
        // it, the effect's worker and listeners were never torn down.
        // React StrictMode runs effects setup -> cleanup -> setup in
        // dev, so each mount leaked an extra worker polling every 10
        // minutes (and duplicate tenant listeners), all posting tokens
        // and 401s into the provider.
        const onTenantSet = () => {
            const tenant = getTenant();
            if (tenant) {
                worker.postMessage({ tenantId: tenant.id, apiBaseUrl: getApiBaseUrl() });
            }

        };

        const onTenantRemoved = () => {
            worker.postMessage({ tenantId: null, apiBaseUrl: getApiBaseUrl() });
        };

        window.addEventListener("tenant_set", onTenantSet)

        window.addEventListener("tenant_removed", onTenantRemoved)

        return () => {
            window.removeEventListener("tenant_set", onTenantSet);
            window.removeEventListener("tenant_removed", onTenantRemoved);
            worker.terminate();
        };

    }, [])

    // pathname is a dependency, not just accessToken: without it,
    // navigating from a public route (where this effect early-returns)
    // to a protected route with an unchanged token never re-ran the
    // effect, so fetchUser never fired and DashboardLayout showed its
    // Loading state forever instead of fetching the user / redirecting
    // to /login via the refresh fallback.
    useEffect(() => {
        if (notProtectedRoutes.includes(pathname)) {
            return;
        }
        if (!accessToken) {
            fetchUser();
        } else if (accessToken) {
            fetchUser().then(() => {
                // navigate("/dashboard");
            });

        }

    }, [accessToken, pathname]);




    return (
        <authContext.Provider value={{
            isLoggedIn: isLoggedInState,
            accessToken,
            user,
            can,
            onUpdateProfile,
            refreshCurrentUser,
            loginWithToken,
            login,
            register,
            resendActivationEmail,
            logout
        }}>
            {children}
        </authContext.Provider>
    );
}


export function useAuthContext() {
    const context = useContext(authContext);
    if (!context) {
        throw new Error("useAuthContext must be used within an AuthProvider");
    }
    return context;
}
