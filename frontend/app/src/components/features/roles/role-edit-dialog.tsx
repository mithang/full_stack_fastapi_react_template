import { Button } from "@/components/ui/button";
import { DialogHeader, DialogFooter, Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import {
    Form, FormField, FormLabel, FormControl, FormItem, FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { useState } from "react";
import { toast } from "sonner";
import { useRoles } from "@/components/providers/roles-provider";
import { extractErrorMessage } from "@/lib/utils";
import { Textarea } from "@/components/ui/textarea";


const editNewRoleSchema = z.object({
    // trim() must come before min()/max(): Zod checks run in chain order, so
    // .min(2).trim() validated the untrimmed value — a whitespace-only
    // name/description passed the form, trimmed to "", and was rejected
    // server-side (CreateRoleDto: name 2-20, description 10-200) with only
    // a generic failure toast.
    name: z.string()
        .trim()
        .min(2, { message: "Name must be at least 2 characters long" })
        .max(20, { message: "Name must be at most 20 characters long" }),
    description: z.string()
        .trim()
        .min(10, { message: "Description must be at least 10 characters long" })
        .max(200, { message: "Description must be at most 200 characters long" }),

});

type EditRoleFormInputs = z.infer<typeof editNewRoleSchema>;

interface RoleEditDialogProps {
    open: boolean;
    onDismiss: () => void;
}

export function RoleEditDialog({ open, onDismiss }: RoleEditDialogProps) {
    const [isLoading, setIsLoading] = useState(false);
    const { onUpdateRole, selectedRole } = useRoles();

    const form = useForm<EditRoleFormInputs>({
        resolver: zodResolver(editNewRoleSchema),
        defaultValues: {
            name: selectedRole?.role.name || "",
            description: selectedRole?.role.description || "",
        },
    });

    const onSubmit = async (data: EditRoleFormInputs) => {
        setIsLoading(true);
        try {
            await onUpdateRole(selectedRole?.role.id!, {
                name: data.name,
                description: data.description,
            });

            form.reset();
            toast.success("Role updated successfully!", {
                duration: 5000,
                position: "top-right",
                richColors: true,
            });
            onDismiss();

        } catch (error) {
            // A backend response (ApiError, which carries a numeric
            // status) means the server answered and rejected the
            // update; a failure with no status is a network error,
            // not a bad form, and must not send the admin retyping a
            // valid form. Mirrors the user-update network-error
            // distinction: the generated client rejects network
            // failures with a raw TypeError, while HTTP failures
            // arrive as ApiError.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus
                ? "Role update failed. Please try again."
                : "Unable to reach the server. Check your connection and try again.", {
                // Surface the server's own message (body.error/detail or a
                // 422 validation message) instead of only the fixed title,
                // mirroring the role permission dialog; the network branch
                // keeps no description, as before.
                description: hasStatus ? extractErrorMessage(error) : undefined,
                duration: 5000,
                position: "top-right",
                richColors: true,
            });
        } finally {
            setIsLoading(false);

        }

    };

    function onDismissDialog(flag: boolean) {
        console.log("onDismissDialog called with flag:", flag);
        if (!flag) onDismiss();
    }
    return (

        <Dialog open={open} onOpenChange={onDismissDialog} modal>
            <DialogContent>
                <DialogHeader>
                    <DialogTitle>Edit Role</DialogTitle>

                </DialogHeader>
                <Form {...form}>
                    <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-5">
                        {/* Name */}
                        <FormField
                            control={form.control}
                            name="name"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>Role Name</FormLabel>
                                    <FormControl>
                                        <Input
                                            type="text"
                                            placeholder="Enter the role name"
                                            disabled={isLoading}
                                            {...field}
                                        />
                                    </FormControl>
                                    <FormMessage />
                                </FormItem>
                            )}
                        />

                        {/* Description */}
                        <FormField
                            control={form.control}
                            name="description"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>Role Description</FormLabel>
                                    <FormControl>
                                        <Textarea
                                            placeholder="Enter the role description"
                                            disabled={isLoading}
                                            {...field}
                                        />
                                    </FormControl>
                                    <FormMessage />
                                </FormItem>
                            )}
                        />

                        <DialogFooter>

                            <Button type="submit" className="w-full" disabled={isLoading}>
                                {isLoading ? "Updating Role..." : "Update Role"}
                            </Button>
                        </DialogFooter>
                    </form>
                </Form>
            </DialogContent>
        </Dialog >
    );
}
