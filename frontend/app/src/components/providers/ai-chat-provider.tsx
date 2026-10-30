import { AISessionByUserIdDto } from "@/api";
import { extractErrorMessage, getApiClient } from "@/lib/utils";
import { createContext, useContext, useEffect, useState } from "react"
import { useAuthContext } from "@/components/providers/auth-provider";
import { toast } from "sonner";
import { useFeatureCheck } from "@/hooks/use-feature-check";
import { useAppConfig } from "@/components/providers/app-config-provider";
import { FeatureDisabledNotice } from "@/components/shared/feature-disabled";


type AIChatProviderState = {
    fetchAllSessions: () => Promise<void>;
    sessions: AISessionByUserIdDto[];
    onDeleteSession: (sessionId: string) => Promise<void>;
    getAIChatNewSession: () => Promise<string>;
}

const AIChatContext = createContext<AIChatProviderState>({
    fetchAllSessions: async () => { },
    sessions: [],
    onDeleteSession: async () => { },
    getAIChatNewSession: async () => { throw new Error("Not implemented"); }
})

interface AIChatProviderProps {
    children: React.ReactNode;
}

export function AIChatProvider({ children }: AIChatProviderProps) {
    const featureCheck = useFeatureCheck();
    const [sessions, setSessions] = useState<AISessionByUserIdDto[]>([]);
    const { accessToken } = useAuthContext();
    const { current_tenant } = useAppConfig();
    const apiClient = getApiClient(accessToken)
    const isChatFeatureEnabled = featureCheck.requireFeature("chat");
    async function fetchAllSessions() {
        try {
            const response = await apiClient.ai.getHistoryApiV1AiHistoryGet();
            setSessions(response);
        } catch (error: unknown) {
            // History refresh is best-effort: a failure here must not
            // surface as an unhandled rejection from the provider's
            // floating effect call, nor wipe a just-streamed answer
            // (ai-chat.tsx awaits this inside its send-message try).
            // Keep the previous sessions and log only.
            console.error("Failed to fetch chat sessions:", extractErrorMessage(error));
        }
    }

    async function onDeleteSession(sessionId: string) {
        await apiClient.ai.deleteSessionApiV1AiSessionsSessionIdDelete({
            sessionId
        });
        await fetchAllSessions();
    }

    async function getAIChatNewSession() {
        try {
            const response = await apiClient.ai.createNewSessionApiV1AiNewSessionGet();
            return response.session_id;
        } catch (error: unknown) {
            const errMsg = extractErrorMessage(error);

            console.error("Failed to create new AI session:", errMsg);
            // A backend response (ApiError, which carries a numeric status)
            // means the server answered; a failure with no status is a
            // network error, not a failed session creation, and must not
            // send the user to retry a session that never reached the server.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus
                ? "Failed to create new AI session"
                : "Unable to reach the server. Check your connection and try again.", { richColors: true, position: "top-right",
                // Server detail only: on a network failure errMsg is the
                // raw fetch message ("Failed to fetch"), which must not
                // appear as a description under the network title —
                // the same guard the audit-log fetch already uses.
                description: hasStatus ? errMsg : undefined });
            throw new Error("Failed to create new AI session");
        }
    }

    useEffect(() => {
        if (!isChatFeatureEnabled) {
            return;
        }
        fetchAllSessions();
        // current_tenant is a dep, not just a guard: the session list is
        // tenant-scoped (TenantMiddleware switches the database from the
        // X-Tenant-ID header, which the client reads from the stored tenant
        // that AppConfig sets when current_tenant arrives). The enabled flag
        // alone does not cover this: it stays true across a tenant switch
        // when chat is enabled on both tenants, and for host users it is
        // true before any tenant loads — so a fetch that ran early was
        // never re-run, leaving another tenant's (or the host DB's)
        // sessions on screen.
    }, [accessToken, isChatFeatureEnabled, current_tenant])

    if (!isChatFeatureEnabled) {
        return <FeatureDisabledNotice featureName="AI Chat" />;
    }
    return (
        <AIChatContext.Provider value={{ fetchAllSessions, sessions, onDeleteSession, getAIChatNewSession }}>
            {children}
        </AIChatContext.Provider>
    )
}

export function useAIChat() {
    const context = useContext(AIChatContext);
    if (!context) {
        throw new Error("useAIChat must be used within an AIChatProvider");
    }
    return context;
}