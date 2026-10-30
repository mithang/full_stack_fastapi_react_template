import React, { useState, useRef, useEffect, useTransition } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/textarea'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Badge } from '@/components/ui/badge'
import { Loading } from '@/components/shared/loading'
import { cn, extractErrorMessage, getApiBaseUrl, getApiClient, getTenant } from '@/lib/utils'
import { Send, Bot, User, Sparkles, Copy, RefreshCw, Trash2, InfoIcon } from 'lucide-react'
import { useAuthContext } from '@/components/providers/auth-provider'
import { ListLocalAIModels } from '@/components/shared/list-local-ai-models'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { useAppConfig } from '@/components/providers/app-config-provider'
import { toast } from 'sonner'
import { AIChatHistory } from './ai-chat-history'
import { NavLink, useSearchParams } from 'react-router'
import { useAIChat } from '@/components/providers/ai-chat-provider'
import { AIAskRequestDto, AIModelInfoDto } from '@/api'

interface Message {
    id: string
    content: string
    role: 'user' | 'assistant'
    timestamp: Date
    isStreaming?: boolean
}

interface ChatState {
    messages: Message[]
    isLoading: boolean
    error: string | null
}


export function AIChat() {
    const isUserScrollingRef = useRef(false)
    const userScrollTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)
    // Abort controller for the in-flight AI stream, plus the session it
    // belongs to: switching sessions must cancel the old generation
    // (see the history effect below), or it keeps running, holds
    // isLoading true, and locks the composer in the new session until
    // it finishes — while its updates land nowhere, since the new
    // session's messages no longer contain its assistant message id.
    const streamAbortRef = useRef<AbortController | null>(null)
    const prevSessionIdRef = useRef<string | null>(null)
    const [searchParams, setSearchParams] = useSearchParams()
    const { user, accessToken } = useAuthContext()
    const { getAIChatNewSession, fetchAllSessions } = useAIChat()
    const { user_preferences, current_tenant } = useAppConfig()
    const [chatState, setChatState] = useState<ChatState>({
        messages: [],
        isLoading: false,
        error: null
    })
    const [selectedModel, setSelectedModel] = useState<AIModelInfoDto>()
    const [input, setInput] = useState('')
    const scrollAreaRef = useRef<HTMLDivElement>(null)
    const messagesEndRef = useRef<HTMLDivElement>(null)
    const inputRef = useRef<HTMLTextAreaElement>(null)
    const [pending, startTransition] = useTransition()
    const [availableAiModels, setAvailableAIModels] = useState<AIModelInfoDto[]>([])
    const [modelsLoaded, setModelsLoaded] = useState(false)
    // True only once a models fetch has succeeded. The empty-list messages
    // below must not render before that: while the fetch is in flight the
    // list is still its initial [], and after a network failure it stays []
    // while the catch already toasts "Unable to reach the server" — in both
    // cases "install local models" would blame the user's setup for a
    // fetch that never answered.
    // Auto-resize textarea
    const adjustTextareaHeight = () => {
        const textarea = inputRef.current
        if (textarea) {
            textarea.style.height = 'auto'
            textarea.style.height = Math.min(textarea.scrollHeight, 120) + 'px'
        }
    }

    const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
        setInput(e.target.value)
        adjustTextareaHeight()
    }

    // Auto-scroll to bottom when new messages arrive or content changes
    const scrollToBottom = () => {
        if (isUserScrollingRef.current) return
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }


    // fetch histories
    async function fetchHistories(sessionId: string) {

        try {
            const apiClient = getApiClient(accessToken)
            const response = await apiClient.ai.getSingleSessionApiV1AiSessionsSessionIdGet({
                sessionId: sessionId!
            });
            return response
        } catch (error) {
            // ApiError.message is only the mapped status text (e.g.
            // "Not Found") or a verbose "Generic Error: status... body:
            // {...}" dump, so appending it swallowed the server's own
            // detail — the same error-shape class fixed in tenant-setting
            // (iteration 1213) and use-subdomain-check (iteration 1214).
            // extractErrorMessage() reads body.error/detail/message (and
            // 422 validation lists) and falls back to Error.message, so
            // the caller displays the real server message; the status
            // preservation below is unchanged.
            const wrapped = new Error("Failed to fetch chat history for the session. " + extractErrorMessage(error))
            // Preserve the ApiError status on the wrapper: without it the
            // caller cannot tell a server rejection from a network failure,
            // since the wrapped Error itself carries no status.
            const status = (error as { status?: unknown } | null)?.status
            if (typeof status === "number") (wrapped as { status?: number }).status = status
            throw wrapped
        }

    }

    async function fetchAvailableModels() {
        try {
            const apiClient = getApiClient(accessToken)
            const response = await apiClient.ai.getModelsApiV1AiModelsGet();
            setAvailableAIModels(response)
            setModelsLoaded(true)
        } catch (error) {
            console.error("Failed to fetch available AI models:", error)
            // A backend response (ApiError, which carries a numeric
            // status) means the server answered and rejected the
            // request; a failure with no status is a network error,
            // not a bad model list, and must not be reported as one.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus ? "Failed to fetch available AI models" : "Unable to reach the server. Check your connection and try again.", { description: "AI chat won't work.", richColors: true, position: "top-right" })
        }
    }

    // Focus input on mount
    useEffect(() => {
        inputRef.current?.focus()
        function handleScroll() {
            isUserScrollingRef.current = true
            if (userScrollTimeoutRef.current) {
                clearTimeout(userScrollTimeoutRef.current)
            }
            userScrollTimeoutRef.current = setTimeout(() => {
                isUserScrollingRef.current = false
            }, 200)
        }
        // The messages scroll inside the Radix ScrollArea viewport, not
        // the window: the chat pane has a fixed height and its own
        // scrollbar, so a window listener never fired while the user
        // scrolled back through earlier messages — and the streaming
        // auto-scroll then yanked the view to the bottom mid-read.
        // Listen on the viewport itself (window only as a fallback).
        const scrollTarget = scrollAreaRef.current?.querySelector('[data-slot="scroll-area-viewport"]') ?? window
        scrollTarget.addEventListener("scroll", handleScroll)
        return () => {
            scrollTarget.removeEventListener("scroll", handleScroll)
            if (userScrollTimeoutRef.current) {
                clearTimeout(userScrollTimeoutRef.current)
            }
        }
    }, [])

    useEffect(() => {
        if (!accessToken) return;
        fetchAvailableModels()
    }, [accessToken])


    useEffect(() => {
        if (chatState.messages.length > 0) {
            scrollToBottom()
        }
    }, [chatState.messages])

    // Also scroll when streaming content changes
    useEffect(() => {
        if (chatState.isLoading) {
            const timer = setInterval(scrollToBottom, 100)
            return () => clearInterval(timer)
        }
    }, [chatState.isLoading])



    // Clear a selection whose model has disappeared from Ollama: the
    // send guard (iteration 222) already blocks sending with a stale
    // model, but the badge above still showed it as active and the
    // "please select a model" alert stayed hidden (it keys off
    // selectedModel), so the disabled Send button gave no explanation.
    // Clearing restores both. modelsLoaded guards this: a failed models
    // fetch leaves the previous list untouched, so only a successful
    // refetch reporting the model as gone clears the choice.
    useEffect(() => {
        if (!modelsLoaded) return;
        if (selectedModel && !availableAiModels.some((model) => model.name === selectedModel.name)) {
            setSelectedModel(undefined)
        }
    }, [availableAiModels, modelsLoaded, selectedModel])

    // Load preferred model from user preferences
    useEffect(() => {
        // Only apply the preference while no model is selected yet: the
        // models list refetches on every access-token rotation, and the
        // local user_preferences are not reloaded when a manual selection
        // is saved (desktop) or made (mobile, which saves nothing), so
        // re-applying unconditionally reverted a manual choice to the
        // stale stored preference on the next 10-minute token refresh —
        // and a missing preferred model cleared the manual choice to
        // undefined. A fresh page load starts unselected, so the
        // preference still applies there.
        if (selectedModel) return;
        if (user_preferences?.preferences?.model_name && availableAiModels) {
            const preferredModel = availableAiModels.find(model => model.name === user_preferences.preferences.model_name)
            setSelectedModel(preferredModel)
        }
    }, [user_preferences, availableAiModels, selectedModel])

    // Abort an in-flight stream when this page unmounts (navigating to
    // another route mid-generation): the history effect's cleanup cannot
    // do this, since it also runs on token rotation and tenant arrival
    // and must not abort a live stream there. This effect's cleanup runs
    // only on unmount — StrictMode's simulated unmount fires before any
    // stream can exist, so it aborts nothing — and the sendMessage
    // AbortError path already drops the partial message silently.
    useEffect(() => {
        return () => {
            streamAbortRef.current?.abort()
            streamAbortRef.current = null
        }
    }, [])

    useEffect(() => {
        // Cancel a stream from the previous session before loading this
        // one's history: a generation started in another session must not
        // keep running after the user switched away (see streamAbortRef).
        // Only a real session change aborts — token rotations and tenant
        // arrivals re-run this effect with the same session_id, and the
        // new-session creation flow sets new_session, so neither aborts
        // the stream that sendMessage just started for that new session.
        const nextSessionId = searchParams.get("session_id")
        const isNewSession = searchParams.get("new_session") === 'true'
        if (!isNewSession && prevSessionIdRef.current !== nextSessionId) {
            streamAbortRef.current?.abort()
            streamAbortRef.current = null
        }
        prevSessionIdRef.current = nextSessionId

        // The delayed setChatState below must not outlive this effect run:
        // without a cleanup, switching session_id (or unmounting) inside
        // the 1 s delay let the stale timer write the old session's
        // messages over the new session's history (which the new run had
        // already reset to [] / isLoading). The flag also covers a fetch
        // that resolves after cleanup, when no timer exists yet to clear.
        let cancelled = false;
        let historyTimer: ReturnType<typeof setTimeout> | undefined;
        async function fetchSelectedSessionHistory() {
            const sessionId = searchParams.get("session_id")
            try {
                const response = await fetchHistories(sessionId!);
                if (cancelled) return;
                setChatState({
                    error: null,
                    isLoading: true,
                    messages: []
                });

                // The backend returns [] (not an error) for an unknown or
                // already-deleted session, so response[0] is undefined
                // there: reading .histories off it threw, and the catch
                // below misreported it as "Unable to reach the server".
                // An unknown session is just an empty conversation.
                const result = response[0]?.histories ?? []
                const messages: Message[] = [];

                result.forEach(h => {
                    if (h.query) {
                        messages.push({
                            // Suffixed, not the bare history uid: the
                            // user question and its assistant reply
                            // share one history document, so giving
                            // both the same id produced duplicate React
                            // keys in the rendered list (and let a
                            // later update match the wrong sibling).
                            // Retry still works: it matches the trailing
                            // message against the same suffixed user id.
                            id: `${h.uid}-q`,
                            content: h.query,
                            role: "user",
                            timestamp: new Date(h.timestamp)
                        });
                    }

                    if (h.response) {
                        messages.push({
                            id: `${h.uid}-a`,
                            content: h.response,
                            role: "assistant",
                            timestamp: new Date(h.timestamp)
                        });
                    }
                });


                historyTimer = setTimeout(() => {
                    if (cancelled) return;
                    setChatState(prev => ({
                        ...prev,
                        messages: [...messages],
                        isLoading: false,
                        error: null
                    }))
                }, 1000)


            } catch (e) {
                if (cancelled) return;
                console.error("Failed to load previous conversations...")
                // A backend response (ApiError status, preserved on the
                // wrapper by fetchHistories) means the server answered and
                // rejected the history fetch; a failure with no status is a
                // network failure, not a bad session, and must not be
                // reported as a raw "Failed to fetch" message.
                const hasStatus = typeof (e as { status?: unknown } | null)?.status === "number";
                setChatState(prev => ({
                    ...prev,
                    messages: [],
                    isLoading: false,
                    error: hasStatus
                        ? (e instanceof Error ? e.message : 'An error occurred')
                        : "Unable to reach the server. Check your connection and try again."
                }))
            }


        }
        if (searchParams.get("session_id") && !searchParams.get("new_session")) {
            if (accessToken) {
                // Do not refetch history while a stream is in flight: this
                // effect re-runs on every access-token rotation (~10
                // minutes via the refresh worker), and the fetch would
                // reset messages to [] and then overwrite them with
                // server history — which cannot yet contain the live
                // exchange (the backend persists it only after the
                // stream closes). That wipes the streaming messages from
                // view, and the stream's later updates then match no
                // message id and land nowhere. The live exchange is
                // already on screen, so skipping the refetch loses
                // nothing; a rotation with no stream in flight still
                // refetches as before. A session switch is unaffected:
                // the abort above already cleared the ref for it.
                if (!streamAbortRef.current) {
                    startTransition(() => {
                        fetchSelectedSessionHistory()
                    })
                }
            }
        } else if (!searchParams.get("session_id")) {
            // No session open: drop any messages from a session that is
            // no longer selected. Deleting the open session clears only
            // the URL params (the history list cannot reset this
            // component's state), and clearChat does its own reset — but
            // without this branch the deleted session's messages stayed
            // on screen under an empty URL. The new-session flow always
            // carries a session_id, so it never hits this branch, and a
            // fresh page already starts in this state.
            setChatState({
                messages: [],
                isLoading: false,
                error: null
            })
        }
        return () => {
            cancelled = true;
            if (historyTimer) clearTimeout(historyTimer);
        };
        // current_tenant is a dep, not a gate: session histories are
        // tenant-DB scoped (TenantMiddleware switches on the X-Tenant-ID
        // header, which getApiClient reads from the stored tenant that
        // AppConfig sets when current_tenant arrives), so a fetch that ran
        // before the tenant loaded was never re-run, leaving the session's
        // history in an error state even though it exists in the tenant DB.
        // Host users have no tenant, so gating would stop their histories
        // loading; the fetch itself is idempotent, so the extra fetch on
        // tenant arrival is safe.
    }, [searchParams, accessToken, current_tenant])

    const generateId = () => Math.random().toString(36).substr(2, 9)

    const sendMessage = async () => {
        if (!input.trim() || chatState.isLoading) return
        // The Send button is disabled without a selected model or with no
        // models available, but the Enter-key handler calls sendMessage
        // directly and bypassed both guards — so pressing Enter with no
        // model sent a request with model_name undefined instead of
        // doing nothing. Match the button's disabled conditions here.
        // The selected model must also still be in the available list:
        // the list refetches on every access-token rotation, so a model
        // removed from Ollama after selection stayed selected, the Send
        // button stayed enabled, and the request went out with a stale
        // model name — failing as an aborted stream instead of a clear
        // "select a model" prompt.
        if (!selectedModel?.name || availableAiModels.length === 0 || !availableAiModels.some((model) => model.name === selectedModel?.name)) {
            toast.error("Please select a local AI model to start chatting.", { richColors: true, position: "top-right" })
            return
        }
        let sessionId = searchParams.get("session_id")
        if (!sessionId) {
            try {
                sessionId = await getAIChatNewSession()
            } catch {
                // getAIChatNewSession already toasts the failure, so there
                // is nothing more to report — but it must not propagate:
                // sendMessage is called from onClick/onKeyDown with no
                // caller awaiting it, so a throw here was an unhandled
                // rejection. The user's input is left intact to retry.
                return
            }
            setSearchParams({ session_id: sessionId, new_session: 'true' })
        }

        const userMessage: Message = {
            id: generateId(),
            content: input.trim(),
            role: 'user',
            timestamp: new Date()
        }

        const assistantMessage: Message = {
            id: generateId(),
            content: '',
            role: 'assistant',
            timestamp: new Date(),
            isStreaming: true
        }

        setChatState(prev => ({
            ...prev,
            messages: [...prev.messages, userMessage, assistantMessage],
            isLoading: true,
            error: null
        }))

        setInput('')

        // Reset textarea height
        const textarea = inputRef.current
        if (textarea) {
            textarea.style.height = 'auto'
        }

        // Declared outside try so the catch below can clear the ref for
        // this stream too: a const inside try is not visible in catch.
        let streamController: AbortController | null = null

        try {
            const tenant = getTenant();
            const payload: AIAskRequestDto = {
                question: userMessage.content,
                model_name: selectedModel?.name,
                session_id: sessionId
            }
            streamController = new AbortController()
            streamAbortRef.current = streamController
            const response = await fetch(`${getApiBaseUrl()}/api/v1/ai/ask`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${accessToken}`,
                    ...tenant?.id && { 'X-Tenant-ID': tenant.id }
                },
                body: JSON.stringify(payload),
                signal: streamController.signal
            })
            if (!response.ok) {
                let detail = ''
                try {
                    const text = await response.text()
                    if (text) {
                        try {
                            const parsed = JSON.parse(text)
                            const rawDetail = parsed?.error ?? parsed?.detail ?? parsed?.message
                            detail = Array.isArray(rawDetail) ? (rawDetail[0]?.msg ?? String(rawDetail[0] ?? '')) : (typeof rawDetail === 'string' ? rawDetail : text)
                        } catch {
                            detail = text
                        }
                    }
                } catch {
                    // Fall through to the status-based message below.
                }
                throw new Error(`AI request failed (${response.status}): ${detail || response.statusText || 'Unknown error'}. Check if you have selected AI Model.`)
            }
            if (!response.body) throw new Error('No response body.')

            const reader = response.body.getReader()

            let accumulatedContent = ''

            // One decoder for the whole stream, not one per chunk: a
            // multi-byte character split across network chunks must be
            // decoded with the bytes that came before it, or each half
            // decodes as a replacement character. A fresh decoder per
            // chunk has no such state, so non-ASCII replies (e.g.
            // Vietnamese) arrived garbled at chunk boundaries.
            const decoder = new TextDecoder()

            while (true) {
                const { done, value } = await reader.read()
                if (done) break

                const chunk = decoder.decode(value, { stream: true })
                accumulatedContent += chunk

                setChatState(prev => ({
                    ...prev,
                    messages: prev.messages.map(msg =>
                        msg.id === assistantMessage.id
                            ? { ...msg, content: accumulatedContent }
                            : msg
                    )
                }))
            }

            // Flush any bytes the decoder held for a character split
            // across the final chunk boundary; empty on clean streams.
            const flushed = decoder.decode()
            if (flushed) {
                accumulatedContent += flushed
                setChatState(prev => ({
                    ...prev,
                    messages: prev.messages.map(msg =>
                        msg.id === assistantMessage.id
                            ? { ...msg, content: accumulatedContent }
                            : msg
                    )
                }))
            }

            // Mark streaming as complete
            setChatState(prev => ({
                ...prev,
                messages: prev.messages.map(msg =>
                    msg.id === assistantMessage.id
                        ? { ...msg, isStreaming: false }
                        : msg
                ),
                isLoading: false
            }))

            if (streamAbortRef.current === streamController) streamAbortRef.current = null

            const shouldRefresh = new URLSearchParams(window.location.search).get("new_session") === 'true'
            if (shouldRefresh) {
                await fetchAllSessions()

                // Drop the one-shot new_session flag from the URL now
                // that the first exchange is complete: a reload on
                // ?session_id=...&new_session=true skips the history
                // fetch and shows an empty chat even though the exchange
                // is saved server-side. This must be a replaceState, not
                // setSearchParams: a router navigation would re-run the
                // history effect immediately, and the backend persists
                // the exchange in a post-response background task, so
                // that refetch would likely return empty history and
                // overwrite the just-streamed exchange. replaceState
                // changes only the URL — no effect re-runs, displayed
                // messages untouched — so the next reload loads the
                // history normally. The stale flag in router state is
                // harmless (the effect skips fetching while it is set,
                // and the next session switch / clearChat replaces the
                // params entirely).
                const url = new URL(window.location.href)
                url.searchParams.delete("new_session")
                window.history.replaceState(null, "", url)
            }

        } catch (error) {
            if (streamAbortRef.current === streamController) streamAbortRef.current = null
            // An abort means the user left this session mid-generation:
            // the partial assistant message is dropped and no error is
            // shown — leaving the session is not a failure.
            if ((error as { name?: string } | null)?.name === 'AbortError') {
                setChatState(prev => ({
                    ...prev,
                    messages: prev.messages.filter(msg => msg.id !== assistantMessage.id),
                    isLoading: false,
                    error: null
                }))
                return
            }
            // A fetch rejection is a TypeError with no status: the
            // request never reached the server, so the raw
            // "Failed to fetch" text must not be shown as if the AI
            // request itself failed. Errors thrown above (non-OK
            // responses, missing body) already carry their own
            // status/detail message and are shown as-is.
            setChatState(prev => ({
                ...prev,
                messages: prev.messages.filter(msg => msg.id !== assistantMessage.id),
                isLoading: false,
                error: error instanceof TypeError
                    ? 'Unable to reach the server. Check your connection and try again.'
                    : error instanceof Error ? error.message : 'An error occurred'
            }))
        }
    }

    const clearChat = () => {
        setSearchParams({})
        setChatState({
            messages: [],
            isLoading: false,
            error: null
        })
    }

    const copyMessage = async (content: string) => {
        // Clipboard writes reject when permission is denied (and the API
        // is absent outside secure contexts), so an unguarded call here
        // surfaced as an unhandled rejection / uncaught throw from a
        // click handler instead of feedback. A failed copy is reported
        // with a toast; a successful copy needs no toast.
        try {
            await navigator.clipboard.writeText(content)
        } catch {
            toast.error("Failed to copy message to clipboard.", { richColors: true, position: "top-right" })
        }
    }

    const retryLastMessage = () => {
        if (chatState.messages.length > 0) {
            const lastUserMessage = [...chatState.messages].reverse().find(m => m.role === 'user')
            if (lastUserMessage) {
                setInput(lastUserMessage.content)
                // Adjust textarea height after setting content
                setTimeout(adjustTextareaHeight, 0)
                // Remove the last exchange, not just its assistant reply:
                // the question itself now lives in the input for resending,
                // so leaving it in the list would make Send append a
                // second copy of it. A trailing assistant reply is dropped
                // first (successful case); a trailing user message with no
                // reply yet (failed send, whose assistant message the
                // send catch already filtered out) is dropped as well.
                setChatState(prev => {
                    const messages = [...prev.messages]
                    if (messages.length > 0 && messages[messages.length - 1].role === 'assistant') {
                        messages.pop()
                    }
                    if (messages.length > 0 && messages[messages.length - 1].id === lastUserMessage.id) {
                        messages.pop()
                    }
                    return { ...prev, messages }
                })
            }
        }
    }

    // Bound to onKeyDown, not onKeyUp: the newline is inserted on
    // keydown, so preventDefault on keyup arrives too late — Enter
    // would leave a stray newline in the composer (visible when the
    // send is blocked, e.g. no model selected) instead of just sending.
    const handleKeyPress = (e: React.KeyboardEvent) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            // Do not send while an IME composition is in progress:
            // during composition (e.g. Vietnamese/CJK input) Enter
            // confirms the composed character, and sending on it
            // would submit a half-composed message and swallow the
            // keystroke the IME needed. The next Enter, after
            // composition ends, sends normally.
            if (e.nativeEvent.isComposing) return
            e.preventDefault()
            sendMessage()
        }
    }

    const onSelectModelEvent = async (model: AIModelInfoDto) => {
        try {
            const apiClient = getApiClient(accessToken)
            await apiClient.ai.setPreferredModelApiV1AiSetModelPreferenceModelNamePut({ modelName: model.name })
            setSelectedModel(model)
            toast.success(`Model set to ${model.name}`, { richColors: true, position: "top-right" })
        } catch (error) {
            console.error("Failed to set model preference:", error)
            // A backend response (ApiError, which carries a numeric
            // status) means the server answered and rejected the
            // preference; a failure with no status is a network error,
            // not a bad model choice, and must not send the user
            // re-selecting a model that never reached the server.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus ? "Failed to set model preference" : "Unable to reach the server. Check your connection and try again.", { richColors: true, position: "top-right" })
        }
    }

    return (
        <section className="h-full flex flex-col pb-10">
            {/* Page Header */}
            {modelsLoaded && availableAiModels?.length == 0 && (
                <Alert className='mb-5' variant="destructive">
                    <AlertTitle>No AI Models Available</AlertTitle>
                    <AlertDescription>
                        Please ensure you have installed locally running AI models.
                        <NavLink to="https://docs.ollama.com/quickstart"
                            target="_blank" rel="noopener noreferrer" className="underline underline-offset-4 font-medium ml-1">
                            Learn more
                        </NavLink>
                    </AlertDescription>
                </Alert>
            )}
            <section className="border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
                <section className="px-3 sm:px-4 py-4 sm:py-6">
                    <section className="flex items-center flex-wrap md:flex-nowrap justify-between">
                        <section className="flex items-center space-x-2 sm:space-x-3">
                            <section className="p-2 sm:p-3 bg-gradient-to-r from-blue-500 to-purple-600 rounded-lg">
                                <Sparkles className="w-5 h-5 sm:w-6 sm:h-6 text-white" />
                            </section>
                            <section className="min-w-0 flex-1">
                                <h1 className="text-lg sm:text-2xl font-bold truncate">AI Assistant</h1>
                                <section className="flex items-center space-x-2">
                                    <p className="text-muted-foreground text-sm sm:text-base hidden sm:block">
                                        Chat with our intelligent AI assistant
                                    </p>

                                </section>
                                {selectedModel && (
                                    <Badge variant="secondary" className="text-xs bg-primary/10 hover:bg-primary/20">
                                        <section className="w-2 h-2 bg-green-500 rounded-full mr-1.5"></section>
                                        {selectedModel.name}
                                    </Badge>
                                )}
                            </section>
                        </section>

                        <section className="flex items-center mt-5 space-x-3 sm:space-x-4">
                            <section className="hidden sm:block">
                                <ListLocalAIModels
                                    onModelSelect={onSelectModelEvent}
                                    selectedModel={selectedModel}
                                    avilableModels={availableAiModels}
                                />
                            </section>

                            <section className="flex space-x-1 sm:space-x-2 mt-6">
                                <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={retryLastMessage}
                                    disabled={chatState.isLoading || chatState.messages.length === 0}
                                    className="hidden sm:flex"
                                >
                                    <RefreshCw className="w-4 h-4 sm:mr-2" />
                                    <span className="hidden sm:inline">Retry</span>
                                </Button>
                                <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={retryLastMessage}
                                    disabled={chatState.isLoading || chatState.messages.length === 0}
                                    className="sm:hidden"
                                >
                                    <RefreshCw className="w-4 h-4" />
                                </Button>
                                <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={clearChat}
                                    disabled={chatState.isLoading}
                                    className="hidden sm:flex"
                                >
                                    <Trash2 className="w-4 h-4 sm:mr-2" />
                                    <span className="hidden sm:inline">Clear</span>
                                </Button>
                                <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={clearChat}
                                    disabled={chatState.isLoading}
                                    className="sm:hidden"
                                >
                                    <Trash2 className="w-4 h-4" />
                                </Button>
                            </section>
                        </section>

                        {/* Mobile Model Selection */}
                        <section className="sm:hidden mt-4 w-full">
                            <ListLocalAIModels
                                onModelSelect={onSelectModelEvent}
                                selectedModel={selectedModel}
                                avilableModels={availableAiModels}
                            />
                        </section>
                    </section>
                </section>
            </section>
            {!selectedModel?.name && (
                <Alert className='mt-4'>
                    <InfoIcon className="w-4 h-4 mr-2" />
                    <AlertTitle>Information</AlertTitle>
                    <AlertDescription>Please select a local AI model to start chatting with the assistant.</AlertDescription>
                </Alert>
            )}


            {/* Chat Container */}

            {/** Mobile view chat history */}
            <AIChatHistory mobile />

            <section className="flex">
                <AIChatHistory />
                <section className="flex-1 py-3 sm:py-6">
                    <section className="flex flex-col h-full space-y-3 sm:space-y-4">
                        {/* Chat Messages */}
                        <Card className={cn("flex-1 flex flex-col")}>
                            <CardContent className="flex-1 p-0">
                                <ScrollArea className="h-[calc(100vh-280px)] sm:h-[600px] p-3 sm:p-6" ref={scrollAreaRef}>
                                    {chatState.messages.length === 0 ? (
                                        <>
                                            {(pending || chatState.isLoading) ? (
                                                <Loading variant='dots' className='absolute inset-0 flex items-center justify-center' />
                                            ) : (
                                                <section className="flex flex-col items-center justify-center h-full text-center space-y-4 sm:space-y-6 px-4">
                                                    <section className="p-4 sm:p-6 bg-gradient-to-r from-blue-100 to-purple-100 dark:from-blue-900/20 dark:to-purple-900/20 rounded-full">
                                                        <Bot className="w-8 h-8 sm:w-12 sm:h-12 text-blue-600" />
                                                    </section>
                                                    <section className="max-w-md">
                                                        <h3 className="text-lg sm:text-xl font-semibold mb-2">Welcome to AI Chat</h3>
                                                        <p className="text-muted-foreground text-sm sm:text-base">
                                                            Start a conversation with our AI assistant. Ask questions, get help with coding, brainstorm ideas, or just have a friendly chat!
                                                        </p>
                                                    </section>
                                                    <section className="grid grid-cols-1 sm:grid-cols-2 gap-2 sm:gap-3 max-w-md w-full">
                                                        {[
                                                            "What can you help me with?",
                                                            "Explain quantum computing",
                                                            "Write a Python function",
                                                            "Help me brainstorm ideas"
                                                        ].map((suggestion, index) => (
                                                            <Button
                                                                key={index}
                                                                variant="outline"
                                                                size="sm"
                                                                onClick={() => {
                                                                    setInput(suggestion)
                                                                    setTimeout(adjustTextareaHeight, 0)
                                                                }}
                                                                className="justify-start h-auto p-2 sm:p-3 text-left whitespace-normal text-xs sm:text-sm"
                                                            >
                                                                {suggestion}
                                                            </Button>
                                                        ))}
                                                    </section>
                                                </section>
                                            )}

                                        </>
                                    ) : (
                                        <section className="space-y-4 sm:space-y-6">
                                            {chatState.messages.map((message) => (
                                                <section
                                                    key={message.id}
                                                    className={cn(
                                                        "flex space-x-2 sm:space-x-4",
                                                        message.role === 'user' ? 'justify-end' : 'justify-start'
                                                    )}
                                                >
                                                    {message.role === 'assistant' && (
                                                        <Avatar className="w-6 h-6 sm:w-8 sm:h-8 mt-1 flex-shrink-0">
                                                            <AvatarFallback className="bg-gradient-to-r from-blue-500 to-purple-600">
                                                                <Bot className="w-3 h-3 sm:w-4 sm:h-4 text-white" />
                                                            </AvatarFallback>
                                                        </Avatar>
                                                    )}

                                                    <section
                                                        className={cn(
                                                            "max-w-[85%] sm:max-w-[75%] rounded-xl px-3 sm:px-4 py-2 sm:py-3 break-words group relative",
                                                            message.role === 'user'
                                                                ? 'bg-primary text-primary-foreground ml-auto'
                                                                : 'bg-muted hover:bg-muted/80 transition-colors'
                                                        )}
                                                    >
                                                        <section className="whitespace-pre-wrap text-sm leading-relaxed">
                                                            {message.content}
                                                        </section>
                                                        {message.isStreaming && (
                                                            <section className="mt-2 sm:mt-3 flex items-center space-x-2">
                                                                <Loading variant="dots" size="sm" />
                                                                <span className="text-xs opacity-70">AI is typing...</span>
                                                            </section>
                                                        )}

                                                        {/* Message actions */}
                                                        {!message.isStreaming && message.content && (
                                                            <section className="flex items-center justify-between mt-2 border-t border-border/50">
                                                                <span className="text-xs ">
                                                                    {message.timestamp.toLocaleTimeString()}
                                                                </span>
                                                                <Button
                                                                    variant="ghost"
                                                                    size="sm"
                                                                    onClick={() => copyMessage(message.content)}
                                                                    className="h-6 sm:h-7 px-1 sm:px-2 text-xs "
                                                                >
                                                                    <Copy className="w-3 h-3 sm:mr-1" />
                                                                    <span className="hidden sm:inline">Copy</span>
                                                                </Button>
                                                            </section>
                                                        )}
                                                    </section>

                                                    {message.role === 'user' && (
                                                        <Avatar className="w-6 h-6 sm:w-8 sm:h-8 mt-1 flex-shrink-0">
                                                            <AvatarImage src={user?.image_url ?? "https://github.com/evilrabbit.png"} alt={user?.last_name} />
                                                            <AvatarFallback className="bg-primary">
                                                                <User className="w-3 h-3 sm:w-4 sm:h-4 text-primary-foreground" />
                                                            </AvatarFallback>
                                                        </Avatar>
                                                    )}
                                                </section>
                                            ))}
                                            {/* Invisible section for scrolling to bottom */}
                                            <section ref={messagesEndRef} />
                                        </section>
                                    )}
                                </ScrollArea>
                            </CardContent>
                        </Card>

                        {/* Error Display */}
                        {chatState.error && (
                            <Card className="border-destructive bg-destructive/5">
                                <CardContent className="p-3 sm:p-4">
                                    <section className="flex items-center justify-between">
                                        <section className="flex items-center space-x-2 text-destructive">
                                            <span className="text-sm font-medium">Error: {chatState.error}</span>
                                        </section>
                                        <Button
                                            variant="ghost"
                                            size="sm"
                                            onClick={() => setChatState(prev => ({ ...prev, error: null }))}
                                        >
                                            Dismiss
                                        </Button>
                                    </section>
                                </CardContent>
                            </Card>
                        )}

                        {/* Input Area */}
                        <Card className="border-2 border-dashed border-muted-foreground/25 hover:border-muted-foreground/50 transition-colors">
                            <CardContent className="p-3 sm:p-4">
                                <section className="flex space-x-2 sm:space-x-3">
                                    <section className="flex-1 relative">
                                        <Textarea
                                            ref={inputRef}
                                            value={input}
                                            onChange={handleInputChange}
                                            onKeyDown={handleKeyPress}
                                            placeholder="Type your message..."
                                            disabled={chatState.isLoading}
                                            className="pr-8 sm:pr-12 min-h-[40px] sm:min-h-[44px] max-h-[120px] text-sm sm:text-base resize-none"
                                            maxLength={2000}
                                            rows={1}
                                        />
                                        {chatState.isLoading && (
                                            <section className="absolute right-2 sm:right-3 top-1/2 transform -translate-y-1/2">
                                                <Loading variant="spinner" size="sm" />
                                            </section>
                                        )}
                                        {modelsLoaded && availableAiModels?.length === 0 && (
                                            <section className="pt-4 flex items-center">
                                                <InfoIcon className="w-4 h-4 text-muted-foreground" />
                                                <span className="ml-2 text-xs text-muted-foreground">No AI models available. Please install a local AI model to start chatting.</span>
                                            </section>
                                        )}
                                    </section>
                                    <Button
                                        onClick={sendMessage}
                                        disabled={!input.trim() || chatState.isLoading || !selectedModel?.name || availableAiModels.length === 0 || !availableAiModels.some((model) => model.name === selectedModel?.name)}
                                        className="px-3 sm:px-6 h-10 sm:h-11"
                                        size="default"
                                    >
                                        <Send className="w-4 h-4 sm:mr-2" />
                                        <span className="hidden sm:inline">Send</span>
                                    </Button>
                                </section>
                                <section className="flex items-center justify-between mt-2 sm:mt-3 text-xs text-muted-foreground">
                                    <span className="hidden sm:inline">Press Enter to send • Shift+Enter for new line</span>
                                    <span className="sm:hidden">Enter to send</span>
                                    <span className={cn(
                                        "font-mono",
                                        input.length > 1800 && "text-orange-500",
                                        input.length > 1950 && "text-destructive"
                                    )}>
                                        {input.length}/2000
                                    </span>
                                </section>
                            </CardContent>
                        </Card>
                    </section>
                </section>
            </section>
        </section>
    )
}
