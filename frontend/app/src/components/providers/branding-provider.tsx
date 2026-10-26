import { createContext, useContext, useState, useEffect } from "react";
import { toast } from "sonner";
import { BrandingDto, UpdateBrandingDto } from "@/api";
import { useAuthContext } from "@/components/providers/auth-provider";
import { getApiClient } from "@/lib/utils";
import { useAppConfig } from "@/components/providers/app-config-provider";

interface BrandingProviderState {
    branding?: BrandingDto
    onUpdateBranding: (data: UpdateBrandingDto) => Promise<void>;
    onUploadLogo: (file: Blob) => Promise<boolean>;
}

const initialState: BrandingProviderState = {
    onUpdateBranding: async () => { },
    onUploadLogo: async () => false,
}

const BrandingContext = createContext<BrandingProviderState>(initialState);
interface BrandingProviderProps {
    children: React.ReactNode;
}

export function BrandingProvider({ children }: BrandingProviderProps) {
    const { branding: initialBranding, reloadAppConfig } = useAppConfig();
    const [branding, setBranding] = useState<BrandingDto | undefined>(undefined);
    const { accessToken } = useAuthContext();


    async function onUpdateBranding(data: UpdateBrandingDto) {
        try {
            const apiClient = getApiClient(accessToken);
            await apiClient.branding.updateBrandingApiV1BrandingsPost({
                requestBody: data
            });
            toast.success("Branding updated successfully", { richColors: true, position: "top-right" });
            // Best-effort refresh: a config-fetch failure must not turn a
            // successful update into a "Failed to update branding" error.
            await reloadAppConfig().catch((error) => {
                console.warn("Failed to refresh app config after branding update", error);
            });
        } catch (error) {
            console.error("Failed to update branding", error);
            // A backend response (ApiError, which carries a numeric status)
            // means the server answered; a failure with no status is a
            // network error, not a failed branding update, and must not send
            // the admin to re-enter branding that never reached the server.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus
                ? "Failed to update branding"
                : "Unable to reach the server. Check your connection and try again.", { richColors: true, position: "top-right" });
            // Re-throw so callers can tell failure from success: the branding
            // form shows a "Saved" checkmark after this resolves, and without
            // the throw it would show it for a failed update too. The form's
            // catch already handles the rejection (the provider toast above
            // is the user-facing feedback). onUploadLogo deliberately keeps
            // swallowing: its caller has no catch, so re-throwing there
            // would surface an unhandled rejection.
            throw error;
        }
    }

    async function onUploadLogo(file: Blob) {
        try {

            const apiClient = getApiClient(accessToken);

            await apiClient.branding.uploadLogoApiV1BrandingsLogoPut({
                formData: {
                    file: file,
                },
            });
            toast.success("Logo uploaded successfully", { richColors: true, position: "top-right" });
            // Best-effort refresh: a config-fetch failure must not turn a
            // successful upload into a "Failed to upload logo" error.
            await reloadAppConfig().catch((error) => {
                console.warn("Failed to refresh app config after logo upload", error);
            });
            // Report success so the caller can clear its pending file: the
            // provider still swallows failures (its caller has no catch), so
            // without a return value a successful upload left the Upload
            // button showing a stale file that re-uploaded on a second click.
            return true;
        } catch (error) {
            console.error("Failed to upload logo", error);
            // A backend response (ApiError, which carries a numeric status)
            // means the server answered; a failure with no status is a
            // network error, not a failed logo upload, and must not send
            // the admin to re-select a logo that never reached the server.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus
                ? "Failed to upload logo"
                : "Unable to reach the server. Check your connection and try again.", { richColors: true, position: "top-right" });
            // Keep the caller's pending file so the admin can retry without
            // re-selecting a logo that never reached the server.
            return false;
        }
    }


    useEffect(() => {
        if (initialBranding) {
            setBranding(initialBranding);
        }
    }, [initialBranding]);


    return (
        <BrandingContext.Provider value={{ branding, onUpdateBranding, onUploadLogo }}>
            {children}
        </BrandingContext.Provider>
    )
}

export function useBrandingContext() {
    const ctx = useContext(BrandingContext);
    if (!ctx) {
        throw new Error("useBrandingContext must be used within a BrandingProvider");
    }
    return ctx;
}