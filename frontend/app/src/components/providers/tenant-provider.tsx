import { CreateTenantDto, TenantListDto, UpdateTenantDto } from '@/api';
import { createContext, useContext, useEffect, useState } from 'react';
import { IResponseData } from '@/components/shared/iresponse-data.inteface';
import { getApiClient } from '@/lib/utils';
import { useSearchParams } from 'react-router';
import { toast } from 'sonner';
import { useAuthContext } from '@/components/providers/auth-provider';
import { NoPermissionToAccessResource } from '@/components/shared/no-permission-access-resource';
import { useAppConfig } from '@/components/providers/app-config-provider';

export type TenantResponse = TenantListDto
export type TenantsType = TenantResponse["tenants"][0]
type ActionType = 'edit' | 'delete' | 'manage_features' | "manage_subscription";
type Action = {
    type: ActionType;
    tenant: TenantsType;
}


interface TenantsProviderState {
    tenantResponse: IResponseData<TenantsType>;
    refreshTenants: () => void;
    isLoading: boolean;
    selectedTenant?: Action;
    onSelectTenant: (action?: Action) => void;
    onCreateNewTenant: (newTenant: CreateTenantDto) => Promise<void>;
    onDeleteTenant: () => Promise<void>;
    onUpdateTenant: (tenantId: string, updatedTenant: UpdateTenantDto) => Promise<void>;

}

const initialState: TenantsProviderState = {
    tenantResponse: {
        items: [],
        total: 0,
        hasNext: false,
        hasPrevious: false,
        limit: 0,
        skip: 0
    },
    refreshTenants: () => { },
    isLoading: true,
    selectedTenant: undefined,
    onSelectTenant: () => { },
    onCreateNewTenant: async () => { },
    onDeleteTenant: async () => { },
    onUpdateTenant: async () => { },
}

const TenantsContext = createContext<TenantsProviderState>(initialState);
interface TenantsProviderProps {
    children: React.ReactNode;
}

export function TenantsProvider({ children }: TenantsProviderProps) {
    const { accessToken, can } = useAuthContext();
    const { current_tenant } = useAppConfig();
    const [tenantResponse, setTenantResponse] = useState<IResponseData<TenantsType>>(initialState.tenantResponse);
    const [searchParams] = useSearchParams();
    const [selectedTenant, setSelectedTenant] = useState<Action | undefined>(undefined);
    const [pending, setPending] = useState(true);
    const isHost = can("host:manage_tenants");
    const apiClient = getApiClient(accessToken);

    async function fetchTenants() {
        toast.dismiss();
        const skip = searchParams.get("skip");
        const limit = searchParams.get("limit");
        // Same URL-pagination guard as the audit-log provider: a
        // non-numeric or negative ?skip=/?limit= falls back to 0/10 instead
        // of reaching the backend as NaN/negative (FastAPI 422), matching
        // AdvanceTable's display guards (iterations 134-135).
        const parsedSkip = skip ? parseInt(skip) : 0;
        const parsedLimit = limit ? parseInt(limit) : 10;
        const safeSkip = Number.isFinite(parsedSkip) && parsedSkip >= 0 ? parsedSkip : 0;
        const safeLimit = Number.isFinite(parsedLimit) && parsedLimit > 0 ? parsedLimit : 10;
        try {
            const response = await apiClient.tenants.listTenantsApiV1TenantsGet({ skip: safeSkip, limit: safeLimit });
            setTenantResponse({
                items: response.tenants,
                total: response.total,
                hasNext: response.has_next,
                hasPrevious: response.has_previous,
                limit: response.limit,
                skip: response.skip
            });
        } catch (error) {
            console.error("Failed to fetch tenants", error);
            // A backend response (ApiError, which carries a numeric status)
            // means the server answered; a failure with no status is a
            // network error, not a failed tenant fetch, and must not
            // send the admin to re-check filters for tenants that never
            // reached the server. The permission hint only applies to a
            // real server response (e.g. a 403 for a non-host user).
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus
                ? "Failed to fetch tenants"
                : "Unable to reach the server. Check your connection and try again.", {
                richColors: true,
                duration: 5000,
                position: "top-right",
                description: !isHost && hasStatus ? "You do not have permission to view this resource." : undefined
            });
        } finally {
            setPending(false);
        }
    }


    const refreshTenants = async () => {
        setPending(true);
        await fetchTenants();
    }

    const onSelectTenant = (action?: Action) => {
        setSelectedTenant(action);
    }

    async function onUpdateTenant(tenantId: string, updatedTenant: UpdateTenantDto) {
        try {
            await apiClient.tenants.updateTenantApiV1TenantsTenantIdPut({
                tenantId,
                requestBody: updatedTenant
            });
            toast.success("Tenant updated successfully", {
                richColors: true,
                position: "top-right"
            });
            await fetchTenants();
        } catch (error) {
            console.error("Failed to update tenant", error);
            // A backend response (ApiError, which carries a numeric status)
            // means the server answered; a failure with no status is a
            // network error, not a failed tenant update, and must not
            // send the admin to re-enter tenant details that never
            // reached the server.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus
                ? "Failed to update tenant"
                : "Unable to reach the server. Check your connection and try again.", {
                richColors: true,
                position: "top-right"
            });
        }
    }

    const onCreateNewTenant = async (newTenant: CreateTenantDto) => {
        try {
            await apiClient.tenants.createTenantApiV1TenantsPost({
                requestBody: newTenant
            });
            toast.success("Tenant created successfully", {
                richColors: true,
                position: "top-right"
            });
            await fetchTenants();
        } catch (error) {
            console.error("Failed to create tenant", error);
            // A backend response (ApiError, which carries a numeric status)
            // means the server answered; a failure with no status is a
            // network error, not a failed tenant creation, and must not
            // send the admin to re-enter tenant details that never
            // reached the server.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus
                ? "Failed to create tenant"
                : "Unable to reach the server. Check your connection and try again.", {
                richColors: true,
                position: "top-right"
            });
        }
    }

    const onDeleteTenant = async () => {
        if (!selectedTenant) return;
        try {
            await apiClient.tenants.deleteTenantApiV1TenantsIdDelete({
                id: selectedTenant.tenant.id!
            });
            toast.success("Tenant deleted successfully", {
                richColors: true,
                position: "top-right"
            });
            setSelectedTenant(undefined);
            await fetchTenants();
        } catch (error) {
            console.error("Failed to delete tenant", error);
            // A backend response (ApiError, which carries a numeric status)
            // means the server answered; a failure with no status is a
            // network error, not a failed tenant deletion, and must not
            // send the admin to re-check a deletion that never
            // reached the server.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus
                ? "Failed to delete tenant"
                : "Unable to reach the server. Check your connection and try again.", {
                richColors: true,
                position: "top-right"
            });
        }
    }

    useEffect(() => {
        if (!accessToken || !isHost) return;
        fetchTenants();
    }, [searchParams, accessToken, isHost]);

    if (!isHost && !current_tenant) {
        return <NoPermissionToAccessResource message='Tenant Management' />;
    }


    return (
        <TenantsContext.Provider value={{
            tenantResponse,
            refreshTenants,
            isLoading: pending,
            selectedTenant,
            onSelectTenant,
            onCreateNewTenant,
            onDeleteTenant,
            onUpdateTenant
        }}>
            {children}
        </TenantsContext.Provider>
    )
}

export function useTenants() {
    const context = useContext(TenantsContext);
    if (!context) {
        throw new Error("useTenants must be used within a TenantsProvider");
    }
    return context;
}