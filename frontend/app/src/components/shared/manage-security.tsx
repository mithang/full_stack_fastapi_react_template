import { Dialog, DialogContent, DialogHeader, DialogTrigger, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { extractErrorMessage, getApiClient } from "@/lib/utils";
import { toast } from "sonner";
import { useAuthContext } from "../providers/auth-provider";
import { useEffect, useState } from "react";
import { RegisteredPasskeyCredentialsDto } from "@/api";
import {
    Table,
    TableBody,
    TableCaption,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table"
import { Trash } from "lucide-react";


interface PassKeyManagementProps {
    accessToken: string;
    shouldRefresh?: boolean;
}
function PassKeyManagement({ accessToken, shouldRefresh }: PassKeyManagementProps) {
    const [allPasskeys, setAllPasskeys] = useState<Array<RegisteredPasskeyCredentialsDto>>([]);
    async function fetchPasskeys() {
        try {
            const apiClient = getApiClient(accessToken);
            const passkeys = await apiClient.manageSecurity.getRegisteredPasskeysApiV1SecurityPasskeysGet();
            setAllPasskeys(passkeys);
        } catch (error) {
            // Previously an unhandled rejection: the dialog silently showed
            // "No registered passkeys found" even when the list simply
            // failed to load, and the delete path's refresh could reject
            // unobserved too. Surface the failure instead.
            // A numeric status means the server answered and rejected
            // the load; a status-less failure is a network error, so
            // it gets the connection message and no raw fetch text.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus ? "Failed to load registered passkeys." : "Unable to reach the server. Check your connection and try again.", {
                description: hasStatus ? extractErrorMessage(error) : undefined,
            });
        }
    }

    async function onDeletePasskey(credentialId: string) {
        // Called floating from onClick, so a rejection here would otherwise
        // go unobserved and leave the row in place with no explanation.
        try {
            const apiClient = getApiClient(accessToken);
            await apiClient.manageSecurity.deleteRegisteredPasskeyApiV1SecurityPasskeysCredentialIdDelete({
                credentialId: credentialId
            });
            // Refresh the list (its own failures are caught inside).
            fetchPasskeys();
        } catch (error) {
            // Same network-vs-server distinction as the load toast
            // above: a status-less failure is a connection problem,
            // not a server rejection of the delete.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus ? "Failed to delete passkey." : "Unable to reach the server. Check your connection and try again.", {
                description: hasStatus ? extractErrorMessage(error) : undefined,
            });
        }
    }

    // accessToken is a dep, not just shouldRefresh: a fetch that runs with
    // an expired token (dialog opened after expiry but before the worker's
    // next refresh tick, e.g. a throttled background tab) 401s and nothing
    // re-ran it, leaving the list empty even after a fresh token arrived.
    // The fetch is idempotent, so the extra fetch on token arrival/rotation
    // while the dialog is open is safe; the guard skips the fetch while no
    // token is held, so no unauthenticated request that can only 401.
    useEffect(() => {
        if (shouldRefresh && accessToken) {
            fetchPasskeys();
        }
    }, [shouldRefresh, accessToken]);

    return (
        <DialogContent>
            <DialogHeader>
                <DialogTitle>
                    List of Registered Passkeys
                </DialogTitle>
            </DialogHeader>
            <section className="mt-4 overflow-x-auto">
                <Table>
                    <TableCaption>A list of your registered passkeys.</TableCaption>
                    <TableHeader>
                        <TableRow>
                            <TableHead>Created At</TableHead>
                            <TableHead>Last Used At</TableHead>
                            <TableHead className="text-right">Action</TableHead>
                        </TableRow>
                    </TableHeader>
                    <TableBody>

                        {allPasskeys.map((passkey) => (
                            <TableRow key={passkey.credential_id}>
                                <TableCell>{new Date(passkey.created_at).toLocaleString()}</TableCell>
                                <TableCell>{passkey.last_used_at ? new Date(passkey.last_used_at).toLocaleString() : "Never"}</TableCell>
                                <TableCell className="text-right">
                                    <Button variant="destructive" size="icon" onClick={() => onDeletePasskey(passkey.credential_id)}>
                                        <Trash />
                                    </Button>
                                </TableCell>
                            </TableRow>
                        ))}
                        {allPasskeys.length === 0 && (
                            <TableRow>
                                <TableCell colSpan={3} className="text-center">No registered passkeys found.</TableCell>
                            </TableRow>
                        )}
                    </TableBody>
                </Table>
            </section>
        </DialogContent >
    )
}

export function ManageSecurity() {
    const { accessToken } = useAuthContext();
    const [shouldRefresh, setShouldRefresh] = useState<boolean>(false);

    function onOpen(isOpen: boolean) {
        // Do not gate arming the refresh on the token held at open time:
        // a dialog opened while no token is held (mid refresh) would never
        // fetch, since shouldRefresh would stay false when the token
        // arrived. Arm unconditionally; the effect above waits for a token.
        if (isOpen) {
            setShouldRefresh(true);
        }
        else if (!isOpen) {
            setShouldRefresh(false);
        }
    }

    return (
        <Dialog onOpenChange={onOpen}>
            <DialogTrigger asChild>
                <Button variant="outline">Manage Security</Button>
            </DialogTrigger>
            <PassKeyManagement accessToken={accessToken!} shouldRefresh={shouldRefresh} />
        </Dialog>
    )
}