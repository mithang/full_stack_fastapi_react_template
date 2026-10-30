import { Permission } from "@/api";
import { useRoles } from "@/components/providers/roles-provider";
import { ListPermission } from "@/components/shared/list-permission";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from "@/components/ui/dialog";
import { useState } from "react";
import { toast } from "sonner";
import { extractErrorMessage } from "@/lib/utils";

interface RoleManagePermissionDialogProps {
    open: boolean;
    onDismiss: () => void;
}

export function RoleManagePermissionDialog({ open, onDismiss }: RoleManagePermissionDialogProps) {
    const { onUpdateRole, selectedRole, refreshRoles } = useRoles()
    const [selectedPermissions, setSelectedPermissions] = useState<string[]>([]);
    // Save was disabled whenever the selection was empty, so an admin
    // could never deliberately clear all of a role's permissions:
    // deselecting the last one disabled the only way to persist it.
    // Track whether the admin actually changed anything instead: the
    // dialog remounts on every open, so this starts false each time and
    // an untouched Save (which would send [] regardless of the role's
    // displayed permissions) stays disabled, while a real change to an
    // empty selection is now saveable. The backend accepts an empty
    // permissions list (UpdateRoleDto defaults to []), so this is valid.
    const [hasChanged, setHasChanged] = useState(false);
    function onDismissHandler(flag: boolean) {
        if (!flag) {
            onDismiss();
        }
    }
    const existingPermission = selectedRole?.role?.permissions || [];
    async function onSaveChanges() {
        try {
            const newPermissions = selectedPermissions.map(permission => permission as Permission)

            await onUpdateRole(selectedRole?.role?.id!, {
                name: selectedRole?.role?.name!,
                description: selectedRole?.role?.description!,
                permissions: newPermissions
            });
            toast.success("Role updated successfully", {
                description: "The role has been updated with the new permissions.",
                position: "top-right",
                richColors: true,
            });
            onDismiss();
            refreshRoles();
        } catch (error) {
            console.error("Error updating role:", error);
            // A backend response (ApiError, which carries a numeric
            // status) means the server answered and rejected the
            // update; a failure with no status is a network error,
            // not a bad permission selection, and must not send the
            // admin re-trying a valid selection. Mirrors the
            // role-update network-error distinction: the generated
            // client rejects network failures with a raw TypeError,
            // while HTTP failures arrive as ApiError.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus ? "Failed to update role" : "Unable to reach the server. Check your connection and try again.", {
                // ApiError.message is only the mapped status text, and a
                // fixed sentence here would swallow the server's own
                // body.error/detail message, so read it via the central
                // helper (which also handles 422 validation lists and
                // falls back to Error.message); the network branch is
                // unchanged.
                description: hasStatus ? extractErrorMessage(error) : undefined,
                richColors: true,
                position: "top-right"
            });
        }

    }
    return (
        <Dialog open={open} onOpenChange={onDismissHandler}>
            <DialogContent>
                <DialogTitle>Manage Permissions</DialogTitle>
                <DialogDescription>
                    Here you can manage the permissions for this role.
                </DialogDescription>
                <section className="">
                    <ListPermission
                        multiSelect
                        value={existingPermission}
                        onChange={(permissions) => { setSelectedPermissions(permissions); setHasChanged(true); }} />
                </section>
                <DialogFooter>
                    <Button variant="outline" onClick={onDismiss}>Cancel</Button>
                    <Button onClick={onSaveChanges} disabled={!hasChanged}>Save changes</Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}
