import { CreateRoleDto, RoleListDto, UpdateRoleDto } from '@/api';
import { createContext, useContext, useEffect, useState } from 'react';
import { IResponseData } from '@/components/shared/iresponse-data.inteface';
import { useSearchParams } from 'react-router';
import { toast } from 'sonner';
import { getApiClient } from '@/lib/utils';
import { useAuthContext } from '@/components/providers/auth-provider';
import { useAppConfig } from '@/components/providers/app-config-provider';
import { NoPermissionToAccessResource } from '@/components/shared/no-permission-access-resource';


export type RoleResponse = RoleListDto
export type RolesType = RoleResponse["roles"][0]
type ActionType = 'edit' | 'delete' | 'clone' | 'manage_permissions'
type Action = {
    type: ActionType;
    role: RolesType;
}

interface RolesProviderState {
    roleResponse: IResponseData<RolesType>;
    refreshRoles: () => void;
    onCreateNewRole: (params: CreateRoleDto) => Promise<void>;
    loading: boolean;
    selectedRole?: Action;
    onSelectRole: (action?: Action) => void;
    onUpdateRole: (roleId: string, params: UpdateRoleDto) => Promise<void>;
    onDeleteRole: () => Promise<void>;
    error: string | null
}

const initialState: RolesProviderState = {
    refreshRoles: () => { },
    onCreateNewRole: async () => { },
    loading: true,
    roleResponse: {
        items: [],
        total: 0,
        hasNext: false,
        hasPrevious: false,
        limit: 0,
        skip: 0
    },
    selectedRole: undefined,
    onDeleteRole: () => Promise.resolve(),
    onUpdateRole: (roleId: string, params: UpdateRoleDto) => {
        console.debug("Updating role:", roleId, params);
        return Promise.resolve();
    },
    onSelectRole: () => { },
    error: null
}

const RolesContext = createContext<RolesProviderState>(initialState);

interface RolesProviderProps {
    children: React.ReactNode;
}
export function RolesProvider({ children }: RolesProviderProps) {
    const { accessToken, can } = useAuthContext();
    const { current_tenant } = useAppConfig();
    const [searchParams] = useSearchParams();
    const [pending, setPending] = useState(true);
    const [roleError, setRoleError] = useState<string | null>(null);

    const [roleResponse, setRoleResponse] = useState<IResponseData<RolesType>>(initialState.roleResponse);
    const [selectedRole, setSelectedRole] = useState<Action | undefined>(initialState.selectedRole);
    const apiClient = getApiClient(accessToken);
    const role = apiClient.roles;
    const canViewRoles = can("role:view_only") || can("full:access");


    async function fetchRoles() {
        setRoleError(null);
        const skip = searchParams.get("skip");
        const limit = searchParams.get("limit");
        // Same URL-pagination guard as the audit-log provider: a
        // non-numeric or negative ?skip=/?limit= falls back to 0/10 instead
        // of reaching the backend as NaN/negative (FastAPI 422), matching
        // AdvanceTable's display guards (iterations 134-135).
        const parsedSkip = skip ? parseInt(skip) : 0;
        const parsedLimit = limit ? parseInt(limit) : 10;
        const safeSkip = Number.isFinite(parsedSkip) && parsedSkip >= 0 ? Math.min(parsedSkip, 10000) : 0;
        // Clamp to the backend's Query bound (limit le=100), mirroring the
        // audit-log provider (iteration 398): a hand-edited ?limit=500
        // previously passed the guards above but still failed with 422.
        const safeLimit = Number.isFinite(parsedLimit) && parsedLimit > 0 ? Math.min(parsedLimit, 100) : 10;
        try {
            const res = await role.listRolesApiV1RolesGet({ skip: safeSkip, limit: safeLimit });

            setRoleResponse({
                items: res.roles,
                hasNext: res.has_next,
                total: res.total,
                hasPrevious: res.has_previous,
                limit: res.limit,
                skip: res.skip,
            });
        } catch (error) {
            console.error("Error fetching roles:", error);
            // A backend response (ApiError, which carries a numeric status)
            // means the server answered and rejected the fetch; a failure
            // with no status is a network error, not a failed fetch, and
            // must not surface a raw fetch error (e.g. "Failed to fetch")
            // that sends the admin re-checking filters for roles that
            // never reached the server.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            if (hasStatus && error instanceof Error) {
                setRoleError(error.message);
            } else if (hasStatus) {
                setRoleError("Failed to fetch roles");
            } else {
                setRoleError("Unable to reach the server. Check your connection and try again.");
            }

        }

    }

    async function refreshRoles() {
        setPending(true);
        await fetchRoles();
        setPending(false);
    }

    async function onCreateNewRole(params: CreateRoleDto) {
        await role.createRoleApiV1RolesPost({
            requestBody: params
        });
    }

    async function onUpdateRole(role_id: string, params: CreateRoleDto) {
        await role.updateRoleApiV1RolesRoleIdPut({
            roleId: role_id,
            requestBody: params
        });
    }

    async function onSelectRole(action?: Action) {
        if (action?.type === 'clone') {
            try {
                await onCreateNewRole({
                    name: `${action.role.name} copy(${roleResponse.total + 1})`,
                    description: action.role.description
                });
                toast.success("Role cloned successfully", {
                    richColors: true,
                    position: "top-right",
                });
                await refreshRoles();
            } catch (error) {
                console.error("Error cloning role:", error);
                // A backend response (ApiError, which carries a numeric
                // status) means the server answered and rejected the
                // clone; a failure with no status is a network error,
                // not a bad role, and must not send the user re-trying
                // a clone that never reached the server.
                const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
                toast.error(hasStatus ? "Failed to clone role" : "Unable to reach the server. Check your connection and try again.", {
                    richColors: true,
                    position: "top-right",
                });
            }
            return;
        }
        setSelectedRole(action);

    }

    async function onDeleteRole() {
        if (!selectedRole) return;
        try {
            await role.deleteRoleApiV1RolesRoleIdDelete({
                roleId: selectedRole.role.id
            });
            onSelectRole(undefined);
            toast.success("Role deleted successfully", {
                richColors: true,
                position: "top-right",
            });
            await refreshRoles();
        } catch (error) {
            // A backend response (ApiError, which carries a numeric
            // status) means the server answered and rejected the
            // delete; a failure with no status is a network error,
            // not a bad role, and must not send the user re-checking
            // assignments for a delete that never reached the server.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus ? "Failed to delete role" : "Unable to reach the server. Check your connection and try again.", {
                richColors: true,
                description: hasStatus ? "Check if the role is assigned to any users" : undefined,
                position: "top-right",
                duration: 3000,
            });
        }

    }


    useEffect(() => {
        if (!canViewRoles || !accessToken) return;
        refreshRoles();
        // current_tenant is a dep, not just a guard: the role list is
        // tenant-scoped (the backend picks the tenant database from the
        // X-Tenant-ID header, which the client reads from the stored
        // tenant that AppConfig sets when current_tenant arrives), so a
        // fetch that ran before the tenant loaded — or before a tenant
        // switch — must re-run once the tenant is known, mirroring the
        // users provider's fix. refreshRoles is idempotent, so the
        // extra fetch on tenant arrival/change is safe.
    }, [searchParams, accessToken, canViewRoles, current_tenant]);

    if (!canViewRoles) {
        return <NoPermissionToAccessResource message='Roles Management' />;
    }

    return (
        <RolesContext.Provider value={
            {
                roleResponse,
                selectedRole,
                refreshRoles,
                onCreateNewRole,
                onSelectRole,
                loading: pending,
                onUpdateRole,
                onDeleteRole,
                error: roleError
            }}>
            {children}
        </RolesContext.Provider>
    );
}

export function useRoles() {
    const context = useContext(RolesContext);
    if (!context) {
        throw new Error("useRoles must be used within a RolesProvider");
    }
    return context;
}