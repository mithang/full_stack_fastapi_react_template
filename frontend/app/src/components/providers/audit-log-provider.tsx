import { AuditLogListDto } from "@/api";
import { createContext, useContext, useEffect, useState } from "react";
import { useAuthContext } from "./auth-provider";
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
    const [searchParams] = useSearchParams();
    const canViewOrDownloadAuditLogs = can("audit_logs:view_only") || can("audit_logs:download") || can("full:access");
    const canDownloadAuditLogs = can("audit_logs:download") || can("full:access");

    async function fetchAuditLogs() {
        toast.dismiss();
        const skip = searchParams.get("skip");
        const limit = searchParams.get("limit");
        const action = searchParams.get("action") as string | null;
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
                    action: searchParams.get("action") as AuditLogActionType | null,
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
    }, [accessToken, searchParams, canViewOrDownloadAuditLogs]);

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