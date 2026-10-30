import { useEffect, useState } from "react";
import { useDebounce } from "./use-debounce";
import { getApiClient, extractErrorMessage } from "@/lib/utils";
import { useAppConfig } from "@/components/providers/app-config-provider";
import { ApiError, SubdomainAvailabilityDto } from "@/api";

export function useSubdomainCheck() {
    const { host_main_domain } = useAppConfig();
    const [subdomain, setSubdomain] = useState("");
    const debouncedText = useDebounce(subdomain, 800); // 800ms debounce
    const [subdomainAvailability, setSubdomainAvailability] = useState<SubdomainAvailabilityDto | null>(null);
    const [isChecking, setIsChecking] = useState(false);
    const [error, setError] = useState<string | null>(null);

    async function checkSubdomainAvailability() {
        const apiClient = getApiClient();
        try {
            setIsChecking(true);
            // Trim before querying: both callers (register, create-tenant)
            // feed the raw input here, so a pasted " mysub " queried
            // "mysub .<domain>", whose label fails the backend regex and
            // reads as unavailable (InvalidSubdomain -> is_available false)
            // for a subdomain that is actually free. The submit paths
            // already trim/strip, so only this live check was wrong.
            const response = await apiClient.tenants.checkSubdomainAvailabilityApiV1TenantsCheckSubdomainSubdomainGet({
                subdomain: `${debouncedText.trim()}.${host_main_domain}`
            });
            setSubdomainAvailability(response);
            setError(null);
        } catch (error) {
            console.error("Error checking subdomain availability:", error);
            if (error instanceof ApiError) {
                // Backend error bodies come in two shapes ({"error": ...} from
                // the custom handler, {"detail": ...} from FastAPI, where a 422
                // detail is a validation-error list, not a string). Reading
                // only .body.detail swallowed the former and passed the latter
                // through as an array into react-hook-form's string message.
                // extractErrorMessage() handles all three shapes; only its
                // generic fallback is replaced with this field's own message.
                const message = extractErrorMessage(error);
                setError(message === "Something went wrong." ? "Failed to check subdomain availability. Please try again." : message);
            } else {
                setError("Failed to check subdomain availability. Please try again.");
            }
            setSubdomainAvailability(null);
        } finally {
            setIsChecking(false);
        }
    }
    useEffect(() => {
        // Trimmed emptiness, not raw truthiness: a whitespace-only input
        // is truthy, so it previously triggered a check for "   .<domain>"
        // and showed the subdomain as taken; now it clears like empty input.
        if (debouncedText.trim()) {
            checkSubdomainAvailability();
        } else {
            setSubdomainAvailability(null);
            setError(null);
        }
        // host_main_domain is a dependency, not just debouncedText:
        // it starts as "" in AppConfigProvider and only arrives with the
        // app-configuration fetch, so a check that ran before it loaded
        // queried "<subdomain>." instead of "<subdomain>.<main domain>"
        // and never re-ran, leaving a wrong availability verdict (an
        // invalid subdomain reads as unavailable) on screen.
    }, [debouncedText, host_main_domain]);

    return { setSubdomain, subdomainAvailability, isChecking, error };


}