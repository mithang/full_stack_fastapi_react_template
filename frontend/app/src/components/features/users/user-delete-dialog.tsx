import { useUsers } from "@/components/providers/users-provider";
import {
    AlertDialog,
    AlertDialogAction,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
} from "@/components/ui/alert-dialog"

interface DeleteNewUserDialogProps {
    open: boolean;
    onDismiss: () => void;
}
export function UserDeleteDialog({ open, onDismiss }: DeleteNewUserDialogProps) {
    const { selectedUser, onDeleteUser } = useUsers();
    function onDismissHandler(flag: boolean) {
        if (!flag) onDismiss();
    }
    return (
        <AlertDialog open={open} onOpenChange={onDismissHandler}>
            <AlertDialogContent>
                <AlertDialogHeader>
                    <AlertDialogTitle>Are you absolutely sure?</AlertDialogTitle>
                    <AlertDialogDescription>
                        This action cannot be undone. This will permanently delete this
                        user <strong className="font-bold text-red-500">{selectedUser?.user?.email}</strong>.
                    </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                    <AlertDialogCancel>Cancel</AlertDialogCancel>
                    <AlertDialogAction onClick={onDeleteUser}>Continue</AlertDialogAction>
                </AlertDialogFooter>
            </AlertDialogContent>
        </AlertDialog>
    )
}
