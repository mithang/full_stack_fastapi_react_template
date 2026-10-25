import { CreateSSOSettingsDto, SSOSettingsListDto, UpdateSSOSettingsDto } from "@/api";
import { createContext, useContext, useState, useEffect } from "react"
import { useAuthContext } from "./auth-provider";
import { getApiClient } from "@/lib/utils";
import { toast } from "sonner";
import { NoPermissionToAccessResource } from "../shared/no-permission-access-resource";
import { useAppConfig } from "./app-config-provider";

type ProviderType = SSOSettingsListDto["items"]
interface SSOConfigurationContextProps {
    onRefreshSSOConfigurations: () => Promise<void>;
    providers: ProviderType;
    availableProviders: string[];
    onCreateSSOConfiguration: (params: CreateSSOSettingsDto) => Promise<void>;
    onEnableOrDisableSSOLogin: (ssoId: string, enabled: boolean) => Promise<void>;
    onDeleteSSOConfiguration: (ssoId: string) => Promise<void>;
    onUpdateSSOConfiguration: (ssoId: string, params: UpdateSSOSettingsDto) => Promise<void>;
}

const initialState: SSOConfigurationContextProps = {
    onRefreshSSOConfigurations: async () => { },
    providers: [],
    availableProviders: [],
    onCreateSSOConfiguration: async () => { },
    onEnableOrDisableSSOLogin: async () => { },
    onDeleteSSOConfiguration: async () => { },
    onUpdateSSOConfiguration: async () => { },
}

const SSOConfigurationContext = createContext<SSOConfigurationContextProps>(initialState)



interface SSOConfigurationProviderProps {
    children: React.ReactNode;
}
export default function SSOConfigurationProvider({ children }: SSOConfigurationProviderProps) {
    const [providers, setProviders] = useState<ProviderType>([])
    const { accessToken, can } = useAuthContext();
    const { enabled_sso_providers, reloadAppConfig } = useAppConfig()
    const [availableProviders, setAvailableProviders] = useState<string[]>([]);
    const canManageSSOSettings = can('full:access');

    async function fetchAllSSOProviders() {
        const apiClient = getApiClient(accessToken);
        // The two fetches are independent: Promise.all meant a failure of
        // either endpoint discarded the other list too, so a failing
        // available-providers endpoint hid the configured providers.
        const [availableResult, ssoResult] = await Promise.allSettled([
            apiClient.ssoSettings.getAvailableSsoProvidersApiV1SsosAvailableProvidersGet(),
            apiClient.ssoSettings.listApiV1SsosGet()
        ]);
        if (ssoResult.status === "fulfilled") {
            setProviders(ssoResult.value.items);
            if (availableResult.status === "fulfilled") {
                const notEnabledProviders = ssoResult.value.items.filter(item => !item.enabled).map(item => item.provider)
                const filteredProviders = availableResult.value
                    .filter(item => !enabled_sso_providers?.includes(item))
                    .filter(provider_name => !notEnabledProviders.includes(provider_name));

                setAvailableProviders(filteredProviders);
            } else {
                // Best-effort list for the "add provider" dropdown: log it,
                // but do not hide the configured providers over it.
                console.error("Failed to fetch available SSO providers:", availableResult.reason);
            }
        } else {
            console.error("Failed to fetch SSO providers:", ssoResult.reason);
            toast.error("Failed to fetch SSO providers", { richColors: true, position: "top-right" });
        }
    }
    async function refreshSSOConfigurations() {
        // Best-effort refresh after a successful mutation (same pattern as
        // the branding provider): reloadAppConfig throws when the config
        // fetch fails, and that must not land in the CRUD callers' catch
        // and report a successful SSO change as failed.
        await reloadAppConfig().catch((error) => {
            console.error("Failed to refresh app config after SSO configuration change:", error);
        });
        await fetchAllSSOProviders();
    }
    async function createSSOConfiguration(params: CreateSSOSettingsDto) {
        try {
            const apiClient = getApiClient(accessToken);
            await apiClient.ssoSettings.createSsoSettingsApiV1SsosPost({
                requestBody: params
            });
            toast.success("SSO configuration created successfully", { richColors: true, position: "top-right" });
            await refreshSSOConfigurations();
        } catch (error) {
            console.error("Failed to create SSO configuration:", error);
            // A backend response (ApiError, which carries a numeric status)
            // means the server answered; a failure with no status is a
            // network error, not a failed SSO creation, and must not send
            // the admin to re-enter settings that never reached the server.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus
                ? "Failed to create SSO configuration"
                : "Unable to reach the server. Check your connection and try again.", { richColors: true, position: "top-right" });
        }
    }

    async function enableOrDisableSSOLogin(ssoId: string, enabled: boolean) {
        try {
            const apiClient = getApiClient(accessToken);
            const existing = providers.find(p => p.id === ssoId);
            if (!existing) {
                toast.error("SSO configuration not found", { richColors: true, position: "top-right" });
                return;
            }
            await apiClient.ssoSettings.updateSsoSettingsApiV1SsosSsoIdPatch({
                ssoId,
                requestBody: { enabled }
            });
            toast.success(`SSO configuration ${enabled ? "enabled" : "disabled"} successfully`, { richColors: true, position: "top-right" });
            await refreshSSOConfigurations();
        } catch (error) {
            console.error("Failed to toggle SSO configuration:", error);
            toast.error("Failed to toggle SSO configuration", { richColors: true, position: "top-right" });
        }
    }

    async function deleteSSOConfiguration(ssoId: string) {
        try {
            const apiClient = getApiClient(accessToken);
            await apiClient.ssoSettings.deleteSsoSettingsApiV1SsosSsoIdDelete({
                ssoId
            });
            toast.success("SSO configuration deleted successfully", { richColors: true, position: "top-right" });
            await refreshSSOConfigurations();
        } catch (error) {
            console.error("Failed to delete SSO configuration:", error);
            toast.error("Failed to delete SSO configuration", { richColors: true, position: "top-right" });
        }
    }

    async function updateSSOConfiguration(ssoId: string, params: UpdateSSOSettingsDto) {
        try {
            const apiClient = getApiClient(accessToken);
            await apiClient.ssoSettings.updateSsoSettingsApiV1SsosSsoIdPatch({
                ssoId,
                requestBody: params
            });
            toast.success("SSO configuration updated successfully", { richColors: true, position: "top-right" });
            await refreshSSOConfigurations();
        } catch (error) {
            console.error("Failed to update SSO configuration:", error);
            toast.error("Failed to update SSO configuration", { richColors: true, position: "top-right" });
        }
    }

    useEffect(() => {
        if (accessToken && canManageSSOSettings && enabled_sso_providers) {
            fetchAllSSOProviders();
        }
    }, [accessToken, canManageSSOSettings, enabled_sso_providers])

    if (!canManageSSOSettings) {
        return <NoPermissionToAccessResource message='SSO Settings' />;
    }
    return (
        <SSOConfigurationContext.Provider
            value={{
                onRefreshSSOConfigurations: refreshSSOConfigurations,
                providers,
                availableProviders,
                onCreateSSOConfiguration: createSSOConfiguration,
                onEnableOrDisableSSOLogin: enableOrDisableSSOLogin,
                onDeleteSSOConfiguration: deleteSSOConfiguration,
                onUpdateSSOConfiguration: updateSSOConfiguration,
            }}>
            {children}
        </SSOConfigurationContext.Provider>
    )
}

export function useSSOConfiguration() {
    const ctx = useContext(SSOConfigurationContext)
    if (!ctx) {
        throw new Error("useSSOConfiguration must be used within a SSOConfigurationProvider")
    }
    return ctx
}