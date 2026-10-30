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
                        onChange={(permissions) => setSelectedPermissions(permissions)} />
                </section>
                <DialogFooter>
                    <Button variant="outline" onClick={onDismiss}>Cancel</Button>
                    <Button onClick={onSaveChanges} disabled={selectedPermissions.length === 0}>Save changes</Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}
