import { Button } from "@/components/ui/button";
import { DialogHeader, DialogFooter, Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
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



const createUserSchema = z.object({
    email: z.string().trim().pipe(z.email({ message: "Invalid email address" })),
    // Same policy as backend validate_password() (backend/api/common/utils.py)
    // and the register / password-reset forms: a weaker password passed
    // this form but was rejected server-side, surfacing only as a generic
    // create failure. The max(100) cap is unchanged.
    password: z.string()
        .min(8, { message: "Password must be at least 8 characters" })
        .max(100)
        .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/, {
            message: "Password must contain at least 1 lowercase letter, 1 uppercase letter, 1 number, and 1 symbol",
        }),
    // trim() must come before min(): Zod checks run in chain order, so
    // .min(1).trim() validated the untrimmed value — a whitespace-only
    // name passed the form, trimmed to "", and was rejected server-side
    // (CreateUserDto min_length=1) with only a generic failure toast.
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

type CreateUserFormInputs = z.infer<typeof createUserSchema>;

interface CreateNewUserDialogProps {
    open: boolean;
    onDismiss: () => void;
}

export function CreateNewUserDialog({ open, onDismiss }: CreateNewUserDialogProps) {
    const [isLoading, setIsLoading] = useState(false);
    const { onCreateNewUser } = useUsers();

    const form = useForm<CreateUserFormInputs>({
        resolver: zodResolver(createUserSchema),
        defaultValues: {
            firstName: "",
            lastName: "",
            email: "",
            password: "",
            gender: Gender.UNKNOWN,
        },
    });

    const onSubmit = async (data: CreateUserFormInputs) => {
        // Do not log the submitted form data: it contains the new user's
        // plaintext password, which would be exposed in the browser
        // console (readable by extensions / anyone with console access).
        setIsLoading(true);
        try {
            await onCreateNewUser({
                email: data.email,
                password: data.password,
                first_name: data.firstName,
                last_name: data.lastName,
                gender: data.gender
            });
            toast.success("User created successfully! Please check your email for verification.", {
                duration: 5000,
                position: "top-right",
                richColors: true,
            });
            form.reset();

            onDismiss();

        } catch (error) {
            // A backend response (ApiError, which carries a numeric
            // status) means the server answered and rejected the
            // creation; a failure with no status is a network error,
            // not a bad form, and must not send the admin retyping a
            // valid form. Mirrors the register/login network-error
            // distinction: the generated client rejects network
            // failures with a raw TypeError, while HTTP failures
            // arrive as ApiError.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            toast.error(hasStatus
                ? "User creation failed. Please try again."
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
        console.log("onDismissDialog called with flag:", flag);
        if (!flag) onDismiss();
    }
    return (

        <Dialog open={open} onOpenChange={onDismissDialog} modal>
            <DialogContent>
                <DialogHeader>
                    <DialogTitle>Create New User</DialogTitle>
                    <DialogDescription>
                        Fill in the details to create a new user account.
                    </DialogDescription>
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

                        {/* Email */}
                        <FormField
                            control={form.control}
                            name="email"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>Email</FormLabel>
                                    <FormControl>
                                        <Input
                                            type="email"
                                            placeholder="Enter your email"
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

                        {/* Password */}
                        <FormField
                            control={form.control}
                            name="password"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>Password</FormLabel>
                                    <FormControl>
                                        <Input
                                            type="password"
                                            placeholder="Enter your password"
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
                                {isLoading ? "Creating User..." : "Create New User"}
                            </Button>
                        </DialogFooter>
                    </form>
                </Form>
            </DialogContent>
        </Dialog>
    );
}
