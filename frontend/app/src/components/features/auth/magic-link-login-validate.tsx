import { Loading } from "@/components/shared/loading";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { getApiClient } from "@/lib/utils";
import { useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { useAuthContext } from "@/components/providers/auth-provider";


export function MagicLinkLoginValidate() {
    const [params] = useSearchParams(window.location.search);
    const navigate = useNavigate();
    const { loginWithToken } = useAuthContext();

    const [showError, setShowError] = useState(false);
    const [isNetworkError, setIsNetworkError] = useState(false);
    const [loading, setLoading] = useState(true);
    // The magic link token is single-use, but React StrictMode runs
    // effects setup -> cleanup -> setup in dev, so without this guard
    // the effect below would send the token twice: the second call
    // fails and shows the "invalid link" error next to the dashboard
    // navigation. Same guard as activation.tsx; keyed by token and
    // user id so a genuinely different link still runs.
    const attemptedLinkRef = useRef<string | null>(null);
    async function validateMagicLink() {
        setShowError(false);
        setIsNetworkError(false);
        const apiClient = getApiClient();
        try {
            const tokenSet = await apiClient.account.emailMagicLinkValidateApiV1AccountEmailMagicLinkValidateGet({
                token: params.get("token") || "",
                userId: params.get("user_id") || "",
                ...(params.get("tenant_id") && { tenantId: params.get("tenant_id") })
            });

            // Use the issued access token directly: the old code discarded
            // it and navigated to /dashboard, so the session depended on
            // a refresh round-trip via the cookie — and a refresh failure
            // raced navigate("/login") against navigate("/dashboard")
            // (the stale-token class fixed for password login and passkey
            // login in earlier iterations). loginWithToken lets the
            // [accessToken] effect fetch the user with the fresh token.
            loginWithToken(tokenSet.access_token);
            navigate("/dashboard");
        } catch (error) {
            // A backend outage / offline browser must not be reported as
            // an invalid or expired link, which would send users to
            // request a new link for a connection problem. Mirrors the
            // login/passkey/magic-link/activation network-error
            // distinction: the generated client rejects network failures
            // with a raw TypeError, while HTTP failures arrive as ApiError
            // with a numeric status.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            setIsNetworkError(!hasStatus);
            setShowError(true);
        }

    }
    useEffect(() => {
        const token = params.get("token");
        const userId = params.get("user_id");
        if (token && userId) {
            const linkKey = `${token}:${userId}`;
            if (attemptedLinkRef.current === linkKey) {
                return;
            }
            attemptedLinkRef.current = linkKey;
            setLoading(false);
            validateMagicLink()
        }
    }, [params])

    useEffect(() => {
        // Params come from the URL synchronously, so there is nothing to wait
        // for: the old `&& !loading` clause could never become true here,
        // because loading is only set to false when BOTH params are present.
        // A link missing only user_id therefore never showed the error and
        // spun forever. Either param missing is an invalid link.
        if (!params.get("token") || !params.get("user_id")) {
            setShowError(true);
            return;
        }
    }, [params, loading]);


    useEffect(() => {
        if (!showError) {
            return;
        }
        // The alert text promises a redirect "shortly", but the old
        // 100000 ms delay left the user staring at the error for 100
        // seconds; 5 s matches the toast durations used elsewhere.
        const timer = setTimeout(() => {
            navigate("/login");
        }, 5000);
        return () => clearTimeout(timer);
    }, [showError])


    if (showError) {
        return (
            <div className="h-[calc(100rem-80rem)] flex flex-col justify-center items-center">
                <Alert variant="destructive">
                    <AlertTitle>{isNetworkError ? "Unable to reach the server" : "Invalid or expired magic link"}</AlertTitle>
                    <AlertDescription>
                        {isNetworkError
                            ? "Could not reach the server. Check your connection and try again."
                            : "The magic link you used is either invalid or has expired. Please request a new magic link to log in."}
                        You will be redirected to the login page shortly.
                    </AlertDescription>
                </Alert>
            </div>
        );
    }
    if (loading) {

        return (
            <div className="h-[calc(100rem-80rem)] flex justify-center">
                <Loading size="lg" variant="dots" />
            </div>
        );
    }
}
