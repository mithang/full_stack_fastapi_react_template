import { AvailableStorageProviderDto, StorageSettingsDto } from "@/api";
import { getApiClient } from "@/lib/utils";
import { useContext, createContext, useEffect, useState } from "react";
import { toast } from "sonner";
import { useAuthContext } from "./auth-provider";
import { NoPermissionToAccessResource } from "@/components/shared/no-permission-access-resource";
import { useAppConfig } from "./app-config-provider";

export interface StorageFormData extends Omit<AvailableStorageProviderDto, 'id' | 'created_at' | 'updated_at'> { }
interface SettingsContextProps {
    storages: AvailableStorageProviderDto[]
    availableStorages: Array<Record<string, string>>
    onConfigureStorage: (settings: StorageFormData) => Promise<void>;
    loading: boolean;
    onResetStorage: (storageId: string) => Promise<void>;
}


const initialState: SettingsContextProps = {
    storages: [],
    availableStorages: [],
    onConfigureStorage: async () => { },
    loading: true,
    onResetStorage: async () => { }
};

const SettingsContext = createContext<SettingsContextProps>(initialState);

interface SettingsProviderProps {
    children: React.ReactNode;
}
export function SettingsProvider({ children }: SettingsProviderProps) {
    const { accessToken, can } = useAuthContext();
    const { current_tenant } = useAppConfig();
    const apiClient = getApiClient(accessToken);
    const [storages, setStorages] = useState<AvailableStorageProviderDto[]>([]);
    const [availableStorages, setAvailableStorages] = useState<Array<Record<string, string>>>([]);
    const [loading, setLoading] = useState(true);
    const canManageSettings = can('manage:storage_settings') || can('full:access');

    async function fetchSettings() {
        // A failure of either endpoint used to reject this whole fetch:
        // loading stayed true forever (no finally), the floating call
        // from the effect surfaced as an unhandled rejection, and the
        // reset/configure callers — which toast success before calling
        // this — would then report "Failed to reset/configure" for an
        // action that had actually succeeded. Handle the failure here
        // (toast + clear loading) and do not rethrow, so callers keep
        // their accurate success toasts.
        setLoading(true);
        try {
            const [storages, availables] = await Promise.all([
                apiClient.storageSettings.getStorageSettingsApiV1StorageGet(),
                apiClient.storageSettings.getAvailableProvidersApiV1StorageAvailableGet()
            ]);
            setStorages(storages);
            setAvailableStorages(availables);
        } catch (error) {
            // A backend response (ApiError, which carries a numeric
            // status) means the server answered; a failure with no status
            // is a network error, not a failed settings load, and must
            // not surface the raw fetch message ("Failed to fetch") nor
            // send the admin re-checking settings that never reached the
            // server. Mirrors the fetchRoles/fetchUsers error-state
            // distinction (iterations 103-104) for this load toast.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus
                ? "Failed to load storage settings"
                : "Unable to reach the server. Check your connection and try again.", {
                description: hasStatus ? (error as Error).message : undefined,
                richColors: true,
                position: "top-right",
            });
        } finally {
            setLoading(false);
        }
    }

    async function onResetStorage(storageId: string) {
        try {
            await apiClient.storageSettings.resetStorageApiV1StorageStorageIdResetPatch({
                storageId: storageId
            });
            toast.success("Storage reset successfully", {
                richColors: true,
                position: "top-right",
            });
            await fetchSettings();
        } catch (error) {
            // A backend response (ApiError, which carries a numeric status)
            // means the server answered; a failure with no status is a
            // network error, not a failed storage reset, and must not send
            // the admin to re-check a reset that never reached the server.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus
                ? "Failed to reset storage"
                : "Unable to reach the server. Check your connection and try again.", {
                description: (error as Error).message,
                richColors: true,
                position: "top-right",
            });
        }
    }
    async function onConfigureStorage(settings: StorageFormData) {
        try {
            const update = { ...storages.find(s => s.provider === settings.provider), ...settings };
            const requestPayload: StorageSettingsDto = {
                provider: update.provider,
                aws_access_key: update.aws_access_key,
                aws_secret_key: update.aws_secret_key,
                region: update.region,
                aws_bucket_name: update.aws_bucket_name,
                azure_connection_string: update.azure_connection_string,
                azure_container_name: update.azure_container_name,
                is_enabled: update.is_enabled,
            }
            await apiClient.storageSettings.configureStorageApiV1StorageConfigurePost({
                requestBody: requestPayload
            });
            const updatedStorages = await apiClient.storageSettings.getStorageSettingsApiV1StorageGet();
            setStorages(updatedStorages);
            toast.success(`Storage: ${settings.provider}`, {
                description: "The storage settings have been updated successfully.",
                richColors: true,
                position: "top-right",
            });
            await fetchSettings();
        } catch (error) {
            // A backend response (ApiError, which carries a numeric status)
            // means the server answered; a failure with no status is a
            // network error, not a failed storage configuration, and must
            // not leave the admin with only a raw fetch error to act on.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(`Storage: ${settings.provider}`, {
                description: hasStatus
                    ? (error as Error).message
                    : "Unable to reach the server. Check your connection and try again.",
                richColors: true,
                position: "top-right",
            });
        }

    }

    useEffect(() => {
        if ((!canManageSettings || !accessToken) && !current_tenant) return;
        fetchSettings();
        // current_tenant is a dep, not just a guard: storage settings are
        // tenant-scoped (via the X-Tenant-ID the client sends), so a fetch
        // that ran before the tenant loaded — or before a tenant switch —
        // must re-run once the tenant is known, mirroring the products
        // page's configuredStripeSetting dep. Without it the page could
        // keep showing another tenant's (or host-mode) storage settings.
    }, [accessToken, canManageSettings, current_tenant])

    if (!canManageSettings || !current_tenant) {
        return <NoPermissionToAccessResource message='Storage Settings' />;
    }

    return (
        <SettingsContext.Provider value={{ loading, onConfigureStorage, storages, availableStorages, onResetStorage }}>
            {children}
        </SettingsContext.Provider>
    );
}

export function useSettings() {
    const context = useContext(SettingsContext);
    if (!context) {
        throw new Error("useSettings must be used within a SettingsProvider");
    }
    return context;
}