import { CreateUserDto, Gender, Permission, TokenSetDto, type MeResponseDto } from "@/api";
import { useProfileImage } from "@/hooks/use-profile-image";
import {
    getApiBaseUrl,
    getApiClient,
    getTenant,
} from "@/lib/utils";
import { createContext, useContext, useEffect, useState, useCallback } from "react"
import { useLocation, useNavigate } from "react-router";
import { toast } from "sonner";

const notProtectedRoutes = ["/password_reset_confirmation", "/password-reset-request", "/register", "/forgot-password", "/magic_link_login"];
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
    login: async () => { },
    register: async () => { },
    resendActivationEmail: async () => { },
    logout: () => { },
});


export function AuthProvider({ children }: { children: React.ReactNode }) {
    const [isLoggedInState, setIsLoggedInState] = useState<boolean>(false);
    const [user, setUser] = useState<MeResponseDto | null>(null);
    const [accessToken, setAccessToken] = useState<string>("");

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
                imageUrl = await getProfileImage(user.image_url);
            }
            setIsLoggedInState(true);
            setUser({ ...user, image_url: imageUrl });

        } catch (error) {
            await refreshToken();
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
            toast.error("Failed to resend activation email", {
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
            await fetchUser();
        } catch (error) {
            console.error("Error updating profile:", error);
            toast.error("Failed to update profile", {
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
        setIsLoggedInState(false);
        setUser(null);
        setAccessToken("");
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
            setAccessToken(result.access_token)
            await fetchUser()
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
            // Log only the message shape, never the payload: a refreshed
            // token message carries the bearer access token, and logging
            // it would expose a live credential in the browser console
            // (readable by extensions and anyone with console access).
            console.log("AuthProvider received message from worker:", event.data && 'access_token' in event.data ? "token refresh" : event.data && 'code' in event.data ? `status ${event.data.code}` : "unknown");
            if (event.data && 'access_token' in event.data) {
                setAccessToken(event.data.access_token);
            } else if (event.data && 'code' in event.data) {
                if (event.data.code === 401 || event.data.code === 400) {
                    setIsLoggedInState(false);
                    setUser(null);
                    setAccessToken("");
                    navigate("/login");
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
            console.log("tenant_set event received in auth provider");
            const tenant = getTenant();
            if (tenant) {
                worker.postMessage({ tenantId: tenant.id, apiBaseUrl: getApiBaseUrl() });
            }

        };

        const onTenantRemoved = () => {
            console.log("tenant_removed event received in auth provider");
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

    }, [accessToken]);




    return (
        <authContext.Provider value={{
            isLoggedIn: isLoggedInState,
            accessToken,
            user,
            can,
            onUpdateProfile,
            refreshCurrentUser,
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
