import { Button } from "@/components/ui/button";
import { DialogHeader, DialogFooter, Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import {
    Form, FormField, FormLabel, FormControl, FormItem, FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from "@/components/ui/select";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { Gender } from "@/components/features/auth/register";
import { useForm } from "react-hook-form";
import { useState } from "react";
import { toast } from "sonner";
import { useUsers } from "@/components/providers/users-provider";
import { extractErrorMessage } from "@/lib/utils";



const editUserSchema = z.object({

    // trim() must come before min(): Zod checks run in chain order, so
    // .min(1).trim() validated the untrimmed value — a whitespace-only
    // name passed the form, trimmed to "", and was rejected server-side
    // (UpdateUserDto min_length=1) with only a generic failure toast.
    firstName: z.string()
        .trim()
        .min(1, { message: "First name cannot be empty" }),
    lastName: z.string()
        .trim()
        .min(1, { message: "Last name cannot be empty" }),
    gender: z.enum([Gender.MALE, Gender.FEMALE, Gender.OTHER, Gender.UNKNOWN], {
        message: "Gender must be either male, female, other, or unknown"
    })
});

type EditUserFormInputs = z.infer<typeof editUserSchema>;

interface UserEditDialogProps {
    open: boolean;
    onDismiss: () => void;
}

export function UserEditDialog({ open, onDismiss }: UserEditDialogProps) {
    const [isLoading, setIsLoading] = useState(false);
    const { onUpdateUser, selectedUser } = useUsers();

    const form = useForm<EditUserFormInputs>({
        resolver: zodResolver(editUserSchema),
        defaultValues: {
            firstName: selectedUser?.user.first_name || "",
            lastName: selectedUser?.user.last_name || "",
            gender: selectedUser?.user.gender || Gender.UNKNOWN,
        },
    });

    const onSubmit = async (data: EditUserFormInputs) => {
        setIsLoading(true);
        try {
            await onUpdateUser(selectedUser?.user.id!, {
                first_name: data.firstName,
                last_name: data.lastName,
                gender: data.gender
            });

            form.reset();
            toast.success("User updated successfully!", {
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
            // valid form. Mirrors the user-creation network-error
            // distinction: the generated client rejects network
            // failures with a raw TypeError, while HTTP failures
            // arrive as ApiError.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus
                ? "User update failed. Please try again."
                : "Unable to reach the server. Check your connection and try again.", {
                // Surface the server's own message (body.error/detail or a
                // 422 validation message) instead of only the fixed title,
                // mirroring the role dialogs; the network branch keeps no
                // description, as before.
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
        if (!flag) onDismiss();
    }
    return (

        <Dialog open={open} onOpenChange={onDismissDialog} modal>
            <DialogContent>
                <DialogHeader>
                    <DialogTitle>Edit New User</DialogTitle>

                </DialogHeader>
                <Form {...form}>
                    <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-5">
                        {/* First Name */}
                        <FormField
                            control={form.control}
                            name="firstName"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>First Name</FormLabel>
                                    <FormControl>
                                        <Input
                                            type="text"
                                            placeholder="Enter your first name"
                                            disabled={isLoading}
                                            {...field}
                                        />
                                    </FormControl>
                                    <FormMessage />
                                </FormItem>
                            )}
                        />

                        {/* Last Name */}
                        <FormField
                            control={form.control}
                            name="lastName"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>Last Name</FormLabel>
                                    <FormControl>
                                        <Input
                                            type="text"
                                            placeholder="Enter your last name"
                                            disabled={isLoading}
                                            {...field}
                                        />
                                    </FormControl>
                                    <FormMessage />
                                </FormItem>
                            )}
                        />



                        {/* Gender */}
                        <FormField
                            control={form.control}
                            name="gender"
                            render={({ field }) => (
                                <FormItem className="flex flex-row items-center gap-4">
                                    <FormLabel className="w-32 mb-0">Gender</FormLabel>
                                    <div className="flex-1">
                                        <Select onValueChange={field.onChange} defaultValue={field.value} disabled={isLoading}>
                                            <FormControl>
                                                <SelectTrigger className="w-full">
                                                    <SelectValue placeholder="Select your gender" className="w-full" />
                                                </SelectTrigger>
                                            </FormControl>
                                            <SelectContent>
                                                <SelectItem value={Gender.MALE}>Male</SelectItem>
                                                <SelectItem value={Gender.FEMALE}>Female</SelectItem>
                                                <SelectItem value={Gender.OTHER}>Other</SelectItem>
                                                <SelectItem value={Gender.UNKNOWN}>Prefer not to say</SelectItem>
                                            </SelectContent>
                                        </Select>
                                        <FormMessage />
                                    </div>
                                </FormItem>
                            )}
                        />



                        <DialogFooter>

                            <Button type="submit" className="w-full" disabled={isLoading}>
                                {isLoading ? "Updating User..." : "Update User"}
                            </Button>
                        </DialogFooter>
                    </form>
                </Form>
            </DialogContent>
        </Dialog>
    );
}
