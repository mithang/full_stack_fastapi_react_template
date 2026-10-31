import { useSSOConfiguration } from '@/components/providers/sso-configuration-provider';
import {
    AlertDialog,
    AlertDialogAction,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { useEffect, useState } from 'react';
import { providerConfig } from './sso-provider-configuration';

interface DeleteSSOConfigurationDialogProps {
    deleteSSOProviderId?: string;
    onClose?: () => void;
}

export default function DeleteSSOConfigurationDialog({
    deleteSSOProviderId,
    onClose,
}: DeleteSSOConfigurationDialogProps) {
    const {
        onRefreshSSOConfigurations,
        providers,
        onDeleteSSOConfiguration,
    } = useSSOConfiguration();



    const providerToDelete = providers.find(p => p.id === deleteSSOProviderId);
    const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);

    // Clearing the parent's selection on close is what makes a later
    // delete of the same provider work again: without it the parent
    // keeps passing the same id, so the effect below never re-fires
    // and the dialog stays closed after a cancelled delete.
    function handleDialogOpenChange(open: boolean) {
        setDeleteDialogOpen(open);
        if (!open && onClose) {
            onClose();
        }
    }

    async function confirmDelete() {
        if (!providerToDelete) return;
        await onDeleteSSOConfiguration(providerToDelete.id);
        await onRefreshSSOConfigurations();
        handleDialogOpenChange(false);

    };
    useEffect(() => {
        if (deleteSSOProviderId) {
            setDeleteDialogOpen(true);
        }
    }, [deleteSSOProviderId]);
    return (
        <AlertDialog open={deleteDialogOpen} onOpenChange={handleDialogOpenChange}>
            <AlertDialogContent>
                <AlertDialogHeader>
                    <AlertDialogTitle>Are you sure?</AlertDialogTitle>
                    <AlertDialogDescription>
                        This will permanently delete the SSO provider configuration for{' '}
                        <strong>
                            {providerToDelete &&
                                (providerConfig[providerToDelete.provider]?.label ||
                                    providerToDelete.provider)}
                        </strong>
                        . Users will no longer be able to sign in using this provider.
                    </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                    <AlertDialogCancel>Cancel</AlertDialogCancel>
                    <AlertDialogAction
                        onClick={confirmDelete}
                        className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                    >
                        Delete
                    </AlertDialogAction>
                </AlertDialogFooter>
            </AlertDialogContent>
        </AlertDialog>
    )
}
