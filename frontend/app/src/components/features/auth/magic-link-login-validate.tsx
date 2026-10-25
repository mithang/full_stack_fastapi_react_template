import { Loading } from "@/components/shared/loading";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { getApiClient } from "@/lib/utils";
import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";


export function MagicLinkLoginValidate() {
    const [params] = useSearchParams(window.location.search);
    const navigate = useNavigate();

    const [showError, setShowError] = useState(false);
    const [loading, setLoading] = useState(true);
    async function validateMagicLink() {
        setShowError(false);
        const apiClient = getApiClient();
        try {
            await apiClient.account.emailMagicLinkValidateApiV1AccountEmailMagicLinkValidateGet({
                token: params.get("token") || "",
                userId: params.get("user_id") || "",
                ...(params.get("tenant_id") && { tenantId: params.get("tenant_id") })
            });

            navigate("/dashboard");
        } catch (error) {
            setShowError(true);
        }

    }
    useEffect(() => {
        const token = params.get("token");
        const userId = params.get("user_id");
        if (token && userId) {
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
        if (showError) {
            setTimeout(() => {
                navigate("/login");
            }, 100000)
        }
    }, [showError])


    if (showError) {
        return (
            <div className="h-[calc(100rem-80rem)] flex flex-col justify-center items-center">
                <Alert variant="destructive">
                    <AlertTitle>Invalid or expired magic link</AlertTitle>
                    <AlertDescription>
                        The magic link you used is either invalid or has expired. Please request a new magic link to log in.
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