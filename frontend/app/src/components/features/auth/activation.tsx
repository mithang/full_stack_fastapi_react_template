import { Loading } from "@/components/shared/loading";
import { getApiClient } from "@/lib/utils";
import { useEffect, useRef } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { toast } from "sonner";

export function Activation() {
    const [searchParams] = useSearchParams()
    const userId = searchParams.get('user_id');
    const token = searchParams.get('token');
    const tenantId = searchParams.get('tenant_id');
    const navigate = useNavigate();
    // The activation token is single-use, but React StrictMode runs
    // effects setup -> cleanup -> setup in dev, so without this guard
    // the effect below would send the token twice: the second call
    // fails and shows an "activation failed" toast next to the success
    // toast. Keyed by token so a genuinely different link still runs.
    const attemptedTokenRef = useRef<string | null>(null);
    useEffect(() => {
        console.log("Activating account for user:", userId);
        async function activate() {
            // Either parameter missing makes the link malformed: the
            // old && only rejected a link missing BOTH, so a link with
            // a token but no user_id (or vice versa) was sent to the
            // backend with an empty token and failed with the generic
            // "activation failed" toast instead of "Invalid activation
            // link". This matches password_reset_confirmation.tsx,
            // which already guards with ||.
            if (!userId || !token) {
                navigate('/login');
                toast.error("Invalid activation link", { duration: 5000, position: "top-right", richColors: true });
                return;
            }
            if (attemptedTokenRef.current === token) {
                return;
            }
            attemptedTokenRef.current = token;
            const apiClient = getApiClient();
            try {
                await apiClient.account.activateAccountApiV1AccountActivatePost({
                    requestBody: {
                        token: token!
                    },
                    tenantId

                });

                toast.success("Account activated successfully. Please login.", { duration: 5000, position: "top-right", richColors: true });
            } catch (error) {

                toast.error("Account activation failed. Please try again.", { duration: 5000, position: "top-right", richColors: true });
            }
            finally {
                navigate('/login');
            }
        }

        activate();

    }, [userId, token, tenantId]);
    return <Loading variant="dots" />;
}