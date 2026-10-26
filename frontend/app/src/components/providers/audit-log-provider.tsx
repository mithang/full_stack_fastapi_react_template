import { AuditLogListDto } from "@/api";
import { createContext, useContext, useEffect, useState } from "react";
import { useAuthContext } from "./auth-provider";
import { useAppConfig } from "./app-config-provider";
import { extractErrorMessage, getApiClient } from "@/lib/utils";
import { IResponseData } from "../shared/iresponse-data.inteface";
import { useSearchParams } from "react-router";
import { toast } from "sonner";
import { NoPermissionToAccessResource } from "@/components/shared/no-permission-access-resource";

export type AuditLogType = AuditLogListDto["logs"][0];
export type AuditLogActionType = AuditLogType["action"];
interface AuditLogsProviderProps {
    children: React.ReactNode;
}

interface AuditLogsContextProps {
    data: IResponseData<AuditLogType>;
    canDownloadAuditLogs: boolean
    triggerDownloadAuditLogs: () => Promise<void>;
}

const initialState: AuditLogsContextProps = {
    data: {
        items: [],
        total: 0,
        skip: 0,
        limit: 10,
        hasNext: false,
        hasPrevious: false
    },
    canDownloadAuditLogs: false,
    triggerDownloadAuditLogs: async () => { }
};
const AuditLogsContext = createContext<AuditLogsContextProps>(initialState);

export function AuditLogProvider({ children }: AuditLogsProviderProps) {
    const [logs, setLogs] = useState<IResponseData<AuditLogType>>(initialState.data);
    const { accessToken, can } = useAuthContext();
    const { current_tenant } = useAppConfig();
    const [searchParams] = useSearchParams();
    const canViewOrDownloadAuditLogs = can("audit_logs:view_only") || can("audit_logs:download") || can("full:access");
    const canDownloadAuditLogs = can("audit_logs:download") || can("full:access");

    // The backend validates ?action= against its AuditActionType Literal
    // (create/update/delete/read/login/logout/error/download), so an
    // invalid value (hand-edited URL, stale bookmark — including "all",
    // which the UI never writes, since onDropdownChange deletes the param
    // for it) previously reached the backend and failed with 422, while
    // skip/limit were already guarded below (iteration 137). Fall back to
    // no filter instead; "download" stays valid even though it is not a
    // dropdown option, so it must not be dropped here.
    const validAuditActions = ["create", "update", "delete", "read", "login", "logout", "error", "download"];
    const rawAction = searchParams.get("action");
    const safeAction = rawAction && validAuditActions.includes(rawAction) ? rawAction as AuditLogActionType : null;

    async function fetchAuditLogs() {
        toast.dismiss();
        const skip = searchParams.get("skip");
        const limit = searchParams.get("limit");
        const action = safeAction;
        // Guard the URL pagination the same way AdvanceTable guards its
        // display (iterations 134-135): a non-numeric or negative ?skip= /
        // ?limit= (hand-edited URL, stale bookmark) previously reached the
        // backend as NaN/negative — FastAPI rejects NaN as an int (422) —
        // while the table itself displayed the page with the default limit.
        const parsedSkip = skip ? parseInt(skip) : 0;
        const parsedLimit = limit ? parseInt(limit) : 10;
        const safeSkip = Number.isFinite(parsedSkip) && parsedSkip >= 0 ? parsedSkip : 0;
        const safeLimit = Number.isFinite(parsedLimit) && parsedLimit > 0 ? parsedLimit : 10;
        try {
            const apiClient = getApiClient(accessToken);
            const response = await apiClient.auditLogs.listAuditLogsApiV1AuditLogsGet({
                skip: safeSkip,
                limit: safeLimit,
                action: action as AuditLogActionType
            });
            setLogs({
                items: response.logs,
                total: response.total,
                skip: response.skip,
                limit: response.limit,
                hasNext: response.has_next,
                hasPrevious: response.has_previous
            });
        } catch (error: unknown) {
            const errMsg = extractErrorMessage(error);
            console.error("Failed to fetch audit logs:", errMsg);
            // A backend response (ApiError, which carries a numeric status)
            // means the server answered; a failure with no status is a
            // network error, not a failed audit-log fetch, and must not
            // send the admin to re-check filters for logs that never
            // reached the server.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus
                ? "Failed to fetch audit logs"
                : "Unable to reach the server. Check your connection and try again.", {
                richColors: true,
                duration: 5000,
                position: "top-right",
                description: errMsg
            });
        }
    }

    async function triggerDownloadAuditLogs() {
        toast.dismiss();
        try {
            const apiClient = getApiClient(accessToken);
            const response = await apiClient.auditLogs.downloadAuditLogsApiV1AuditLogsDownloadPost({
                requestBody: {
                    // Same invalid-action guard as the list fetch above:
                    // a bogus ?action= would otherwise fail the download
                    // request with 422 as well.
                    action: safeAction,
                    total_records: logs.total
                }
            });

            toast.success("Audit logs download requested", {
                richColors: true,
                duration: 5000,
                position: "top-right",
                description: response.message || "You will receive an email with the download link shortly."
            });
        } catch (error: unknown) {
            const errMsg = extractErrorMessage(error);
            console.error("Failed to download audit logs:", errMsg);
            // A backend response (ApiError, which carries a numeric status)
            // means the server answered; a failure with no status is a
            // network error, not a failed download request, and must not
            // send the admin to re-check a download that never reached
            // the server.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus
                ? "Failed to download audit logs"
                : "Unable to reach the server. Check your connection and try again.", {
                richColors: true,
                duration: 5000,
                position: "top-right",
                description: errMsg
            });
        }
    }

    useEffect(() => {
        if (!accessToken || !canViewOrDownloadAuditLogs) return;
        fetchAuditLogs();
        // current_tenant is a dep, not a gate: audit logs are tenant-DB
        // scoped (the backend picks the tenant database from the
        // X-Tenant-ID header, which the client reads from the stored
        // tenant that AppConfig sets when current_tenant arrives), so a
        // fetch that ran before the tenant loaded must re-run once the
        // tenant is known, mirroring the roles/users providers' fix.
        // fetchAuditLogs is idempotent, so the extra fetch on tenant
        // arrival/change is safe.
    }, [accessToken, searchParams, canViewOrDownloadAuditLogs, current_tenant]);

    if (!canViewOrDownloadAuditLogs) {
        return <NoPermissionToAccessResource message='Audit Logs' />;
    }
    return (
        <AuditLogsContext.Provider value={{ data: logs, canDownloadAuditLogs, triggerDownloadAuditLogs }}>
            {children}
        </AuditLogsContext.Provider>
    );
}


export function useAuditLogsContext() {
    const context = useContext(AuditLogsContext);
    if (!context) {
        throw new Error("useAuditLogsContext must be used within an AuditLogsProvider");
    }
    return context;
}