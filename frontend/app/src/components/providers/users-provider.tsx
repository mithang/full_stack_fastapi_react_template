import { CreateUserDto, UserListDto, UpdateUserDto } from '@/api';
import { createContext, useContext, useEffect, useState } from 'react';
import { IResponseData } from '@/components/shared/iresponse-data.inteface';
import { getApiClient } from '@/lib/utils';
import { useSearchParams } from 'react-router';
import { toast } from 'sonner';
import { useAuthContext } from '@/components/providers/auth-provider';
import { useAppConfig } from '@/components/providers/app-config-provider';
import { NoPermissionToAccessResource } from '@/components/shared/no-permission-access-resource';

export type UserResponse = UserListDto
export type UsersType = UserResponse["users"][0]
type ActionType = 'edit' | 'delete' | 'resend_email' | 'manage_roles';
type Action = {
    type: ActionType;
    user: UsersType;
}

interface UsersProviderState {
    userResponse: IResponseData<UsersType>;
    refreshUsers: () => void;
    onCreateNewUser: (params: CreateUserDto) => Promise<void>;
    loading: boolean;
    selectedUser?: Action;
    onSelectUser: (action?: Action) => void;
    onUpdateUser: (userId: string, params: UpdateUserDto) => Promise<void>;
    onDeleteUser: () => Promise<void>;
    userError: string | null;
}

const initialState: UsersProviderState = {
    refreshUsers: () => { },
    onCreateNewUser: async () => { },
    loading: true,
    userResponse: {
        items: [],
        total: 0,
        hasNext: false,
        hasPrevious: false,
        limit: 0,
        skip: 0
    },
    userError: null,
    selectedUser: undefined,
    onDeleteUser: () => Promise.resolve(),
    onUpdateUser: (userId: string, params: UpdateUserDto) => {
        console.debug("Updating user:", userId, params);
        return Promise.resolve();
    },
    onSelectUser: () => { }
}

const UsersContext = createContext<UsersProviderState>(initialState);

interface UsersProviderProps {
    children: React.ReactNode;
}

export function UsersProvider({ children }: UsersProviderProps) {
    const { accessToken, can } = useAuthContext();
    const { current_tenant } = useAppConfig();
    const [searchParams] = useSearchParams();
    const [pending, setPending] = useState(true);
    const [userError, setUserError] = useState<string | null>(null);
    const [userResponse, setUserResponse] = useState<IResponseData<UsersType>>(initialState.userResponse);
    const [selectedUser, setSelectedUser] = useState<Action | undefined>(initialState.selectedUser);
    const apiClient = getApiClient(accessToken);
    const user = apiClient.users;
    const auth = apiClient.account;
    const canViewUsers = can("user:view_only") || can("full:access");

    async function fetchUsers() {
        setUserError(null);
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
            const res = await user.listUsersApiV1UsersGet({ skip: safeSkip, limit: safeLimit });
            setUserResponse({
                items: res.users,
                hasNext: res.has_next,
                total: res.total,
                hasPrevious: res.has_previous,
                limit: res.limit,
                skip: res.skip,
            });
        } catch (error) {
            console.error("Failed to fetch users:", error);
            // A backend response (ApiError, which carries a numeric status)
            // means the server answered and rejected the fetch; a failure
            // with no status is a network error, not a failed fetch, and
            // must not surface a raw fetch error (e.g. "Failed to fetch")
            // that sends the admin re-checking filters for users that
            // never reached the server.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            if (hasStatus && error instanceof Error) {
                setUserError(error.message);
            } else if (hasStatus) {
                setUserError("Failed to fetch users");
            } else {
                setUserError("Unable to reach the server. Check your connection and try again.");
            }
        }

    }

    async function refreshUsers() {
        setPending(true);
        await fetchUsers();
        setPending(false);
    }

    async function onCreateNewUser(params: CreateUserDto) {
        await user.createUserApiV1UsersPost({
            requestBody: params
        });
    }

    async function onUpdateUser(user_id: string, params: UpdateUserDto) {
        await user.updateUserApiV1UsersUserIdPut({
            userId: user_id,
            requestBody: {
                first_name: params.first_name,
                last_name: params.last_name,
                gender: params.gender
            }
        });
    }

    async function onSelectUser(action?: Action) {
        if (action?.type === 'resend_email') {
            try {
                await auth.resendActivationEmailApiV1AccountResendActivationEmailPost({
                    requestBody: {
                        email: action.user.email,
                        id: action.user.id,
                        first_name: action.user.first_name,
                        tenant_id: action.user.tenant_id
                    }
                });
                toast.success("User email resent successfully", {
                    richColors: true,
                    position: "top-right",
                });
            } catch (e) {
                console.error("Failed to resend user email", e);
                // A backend response (ApiError, which carries a numeric status)
                // means the server answered and rejected the resend; a failure
                // with no status is a network error, not a failed resend, and
                // must not send the admin requesting another email for a
                // connection problem. Mirrors resendActivationEmail in
                // auth-provider.tsx: the generated client rejects network
                // failures with a raw TypeError, while HTTP failures arrive
                // as ApiError.
                const hasStatus = typeof (e as { status?: unknown } | null)?.status === "number";
                toast.error(hasStatus
                    ? "Failed to resend user email"
                    : "Unable to reach the server. Check your connection and try again.", {
                    richColors: true,
                    position: "top-right",
                });
            }
            return;
        }
        setSelectedUser(action);

    }

    async function onDeleteUser() {
        if (!selectedUser) return;
        try {
            await user.deleteUserApiV1UsersUserIdDelete({
                userId: selectedUser.user.id
            });
            onSelectUser(undefined);
            toast.success("User deleted successfully", {
                richColors: true,
                position: "top-right",
            });
            await refreshUsers();
        } catch (error) {
            console.error("Error deleting user:", error);
            // A backend response (ApiError, which carries a numeric status)
            // means the server answered and rejected the delete; a failure
            // with no status is a network error, not a failed delete, and
            // must not send the admin re-checking user assignments for a
            // connection problem. Mirrors onDeleteRole in roles-provider.tsx:
            // the generated client rejects network failures with a raw
            // TypeError, while HTTP failures arrive as ApiError.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus
                ? "Failed to delete user"
                : "Unable to reach the server. Check your connection and try again.", {
                richColors: true,
                position: "top-right",
            });
        }
    }

    useEffect(() => {
        if (!accessToken || !canViewUsers) return;
        refreshUsers();
        // current_tenant is a dep, not just a guard: the user list is
        // tenant-scoped (the backend picks the tenant database from the
        // X-Tenant-ID header, which the client reads from the stored
        // tenant that AppConfig sets when current_tenant arrives), so a
        // fetch that ran before the tenant loaded — or before a tenant
        // switch — must re-run once the tenant is known, mirroring the
        // settings provider's fix. refreshUsers is idempotent, so the
        // extra fetch on tenant arrival/change is safe.
    }, [searchParams, accessToken, canViewUsers, current_tenant]);

    if (!canViewUsers) {
        return <NoPermissionToAccessResource message='User Management' />;
    }

    return (
        <UsersContext.Provider value={
            {
                userResponse,
                selectedUser,
                refreshUsers,
                onCreateNewUser,
                onSelectUser,
                loading: pending,
                onUpdateUser,
                onDeleteUser,
                userError
            }}>
            {children}
        </UsersContext.Provider>
    );
}

export function useUsers() {
    const context = useContext(UsersContext);
    if (!context) {
        throw new Error("useUsers must be used within a UsersProvider");
    }
    return context;
}
