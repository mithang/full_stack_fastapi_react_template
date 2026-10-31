import { Button } from "@/components/ui/button"
import { Card, CardContent, CardTitle } from "@/components/ui/card"
import { cn, extractErrorMessage } from "@/lib/utils"
import {
    Select,
    SelectContent,
    SelectGroup,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "@/components/ui/select"
import { Menu } from 'lucide-react'
import { DropdownMenu, DropdownMenuItem, DropdownMenuContent, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { NavLink, useNavigate, useSearchParams } from "react-router"
import { useAIChat } from "@/components/providers/ai-chat-provider"
import { ScrollArea } from "@/components/ui/scroll-area"
import { toast } from "sonner"

interface AIChatHistoryProps {
    mobile?: boolean
}
export function AIChatHistory({ mobile }: AIChatHistoryProps) {
    const [searchParams, setSearchParams] = useSearchParams()
    const { sessions, onDeleteSession } = useAIChat()
    const navigate = useNavigate()
    const histories = sessions || []
    function getTitle(historyId: string) {
        // Use the matched history document, not just the group's first
        // one, and tolerate an empty histories list: a freshly created
        // session has no exchanges yet, so histories[0] is undefined and
        // reading .query off it threw during render, crashing the whole
        // history list. Such a session now shows "Untitled" until its
        // first exchange lands.
        const historyItem = histories.find(h => h.sessions.find(s => s.id === historyId))?.sessions.find(s => s.id === historyId)
        return historyItem?.histories[0]?.query || "Untitled"
    }

    async function onDelete(sessionId: string) {
        try {
            await onDeleteSession(sessionId)
            toast.success("Session deleted successfully.", {
                richColors: true,
                position: "top-right",
                description: "The chat session has been deleted. All associated messages have been removed."
            })
            // Only leave the chat view when the deleted session is the one
            // currently open: deleting another session from its dropdown
            // must not drop the viewed session_id from the URL (which
            // blanked the open conversation).
            if (searchParams.get("session_id") === sessionId) {
                setSearchParams({})
            }
        } catch (error) {
            console.error("Error deleting session:", error)
            // A backend response (ApiError, which carries a numeric
            // status) means the server answered and rejected the
            // delete; a failure with no status is a network error,
            // not a bad session, and must not send the user
            // re-trying a delete that never reached the server.
            // Mirrors the feature-load network-error distinction:
            // the generated client rejects network failures with a
            // raw TypeError, while HTTP failures arrive as ApiError.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus ? "Failed to delete session." : "Unable to reach the server. Check your connection and try again.", {
                richColors: true,
                position: "top-right",
                // Surface the server's own error detail (body.error /
                // body.detail, incl. 422 validation lists) instead of a
                // fixed generic sentence that swallowed it; the
                // provider rethrows the raw ApiError, so it is
                // available here. Network branch keeps no description,
                // as in the role/user/feature dialogs.
                description: hasStatus ? extractErrorMessage(error) : undefined
            })
        }

    }
    if (mobile) {

        return (
            <section className="py-3 md:pr-3 md:hidden">
                <Card className="flex-flex flex-col h-full">
                    <CardTitle className="border-b border-primary/10 p-4">
                        Chat History
                    </CardTitle>
                    <CardContent className="p-4 overflow-auto">
                        <Select
                            value={searchParams.get("session_id") ?? undefined}
                            onValueChange={(value) => {
                                navigate(`?session_id=${value}`)
                            }}>
                            <SelectTrigger className="w-full">
                                <SelectValue placeholder="Show History" />
                            </SelectTrigger>
                            <SelectContent>
                                <SelectGroup>
                                    {histories.map(history => (
                                        <SelectItem key={history.session_id} value={history.session_id}>
                                            {getTitle(history.history_id)} <br />
                                            {new Date(history.created_at).toLocaleString()}
                                        </SelectItem>
                                    ))}
                                </SelectGroup>
                            </SelectContent>
                        </Select>
                    </CardContent>
                </Card>
            </section>
        )
    }

    return (

        <section className="py-6 pr-3 w-xs hidden md:block">
            <section className="h-full space-y-3">
                <Card className="flex-flex flex-col h-full">
                    <CardTitle className="border-b border-primary/10 p-4">
                        Chat History
                    </CardTitle>
                    <CardContent className="p-4">
                        <ScrollArea className="h-[700px]">
                            <ul className=" text-sm font-medium pr-4">
                                {histories.map(history => (
                                    <li key={history.session_id} className={cn("p-2 hover:bg-primary/5 cursor-pointer flex justify-between", {
                                        "bg-primary/5": history.session_id === searchParams.get("session_id")
                                    })}>
                                        <div>
                                            <NavLink to={`?session_id=${history.session_id}`} className="block w-full h-full">
                                                <div className="font-semibold">{getTitle(history.history_id)}</div>
                                                <div className="text-xs text-muted-foreground">{new Date(history.created_at).toLocaleString()}</div>
                                            </NavLink>
                                        </div>
                                        <DropdownMenu>
                                            <DropdownMenuTrigger asChild>
                                                <Button size="icon" variant="ghost">
                                                    <Menu className="h-4 w-4" />
                                                </Button>
                                            </DropdownMenuTrigger>
                                            <DropdownMenuContent align="start">
                                                <DropdownMenuItem onClick={() => onDelete(history.session_id)}>
                                                    Delete
                                                </DropdownMenuItem>
                                            </DropdownMenuContent>
                                        </DropdownMenu>
                                    </li>
                                ))}

                            </ul>
                        </ScrollArea>
                    </CardContent>
                </Card>
            </section>
        </section>
    )
}
