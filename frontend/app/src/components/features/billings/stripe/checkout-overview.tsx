import { useEffect, useRef, useState } from "react";
import { useAuthContext } from "@/components/providers/auth-provider";
import { useAppConfig } from "@/components/providers/app-config-provider";
import { extractErrorMessage, formatDateWithHourAndMinute, formatPrice, getApiClient } from "@/lib/utils";
import { BillingRecordDto } from "@/api";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
    ShoppingCart,
    RefreshCw,
    CheckCircle2,
    Clock,
    XCircle,
    AlertTriangle,
    User,
    Calendar,
    CreditCard,
    TrendingUp,
    Package,
    ArrowLeft,
    ArrowRight,
} from "lucide-react";
import { ShowScreenLoader } from "@/components/shared/show-screen-loader";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useLocation, useNavigate } from "react-router";

export function CheckoutOverview() {
    const { accessToken } = useAuthContext();
    const { current_tenant } = useAppConfig();
    const [records, setRecords] = useState<BillingRecordDto[]>([]);
    const [loading, setLoading] = useState(true);
    const [fetchError, setFetchError] = useState<string | null>(null);
    const { search, pathname } = useLocation();
    const navigate = useNavigate();

    const searchQuery = new URLSearchParams(search);
    // Guard the URL pagination the same way the AdvanceTable providers
    // do (iteration 137): the first checkout fetch sends pagination.limit
    // verbatim, so a non-numeric or negative ?limit= (hand-edited URL,
    // stale bookmark) previously reached the backend as NaN/negative —
    // FastAPI rejects NaN as an int (422) — and a bogus ?skip= seeded the
    // initial display state. Fall back to skip 0 / limit 10; valid and
    // missing values behave as before.
    const parsedInitialSkip = parseInt(searchQuery.get("skip") || "0", 10);
    const parsedInitialLimit = parseInt(searchQuery.get("limit") || "10", 10);
    // Clamped to the backend bounds (iteration 403: skip le=10000,
    // limit le=100), mirroring the roles/tenants/users providers
    // (iteration 402): without this clamp, a hand-edited ?skip=/?limit=
    // above the bounds would fail with 422 at fetch time instead of
    // showing a page.
    const initialSkip = Number.isFinite(parsedInitialSkip) && parsedInitialSkip >= 0 ? Math.min(parsedInitialSkip, 10000) : 0;
    const initialLimit = Number.isFinite(parsedInitialLimit) && parsedInitialLimit > 0 ? Math.min(parsedInitialLimit, 100) : 10;

    const [pagination, setPagination] = useState({
        skip: initialSkip,
        limit: initialLimit,
        total: 0,
        hasPrevious: false,
        hasNext: false,
    });

    // Sequential fetches (fast prev/next navigation, or a Refresh clicked
    // while a page fetch is in flight) can resolve out of order: without
    // sequencing, a stale, slower response for the old page would
    // overwrite the records and pagination of the newer page the URL
    // already shows. Only the latest request may apply its result.
    const fetchRequestIdRef = useRef(0);

    const fetchCheckoutRecords = async (skip: number = 0, limit: number = pagination.limit) => {
        if (!accessToken) return;
        const requestId = ++fetchRequestIdRef.current;
        try {
            setLoading(true);
            setFetchError(null);
            const response = await getApiClient(accessToken).stripeCheckout.listCheckoutRecordsApiV1CheckoutsAllGet({
                skip,
                limit,
            });
            if (requestId !== fetchRequestIdRef.current) return;
            setRecords(response.billing_records);
            setPagination({
                skip: response.skip,
                limit: response.limit,
                total: response.total,
                hasPrevious: response.has_previous,
                hasNext: response.has_next,
            });
        } catch (error) {
            // A stale failure must not overwrite the newer request's
            // state either: it would show an error for a page whose fetch
            // is still in flight (and its finally below must not clear
            // that fetch's loading state).
            if (requestId !== fetchRequestIdRef.current) return;
            console.error("Error fetching checkout records:", error);
            // A backend response (ApiError, which carries a numeric status)
            // means the server answered; a failure with no status is a
            // network failure. Previously every failure fell through to the
            // "No Checkout Records Found" empty state, so an outage looked
            // exactly like having no checkout sessions at all.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            // The banner has no description slot, so the server's own
            // reason is appended to the fixed sentence instead of being
            // swallowed, mirroring the plans-load banner in
            // billing-overview.tsx; the network branch keeps no server
            // detail, as before.
            setFetchError(hasStatus
                ? `Failed to load checkout records. Please try again later. ${extractErrorMessage(error)}`
                : "Unable to reach the server. Check your connection and try again.");
        } finally {
            // Only the latest request may clear loading: a stale request
            // resolving (or failing) first must not hide the newer
            // request's loading state. (A return in try/catch still runs
            // this block, which is why the guard lives here, not there.)
            if (requestId === fetchRequestIdRef.current) setLoading(false);
        }
    };

    useEffect(() => {
        if (accessToken) {
            // Prev/next navigation only writes ?skip= to the URL, so the
            // refetch triggered by the search change must read the skip
            // back out of it: previously this called fetchCheckoutRecords()
            // with its default skip 0, so every page navigation refetched
            // page 1 while the URL (and, after the fetch, the pagination
            // state) claimed another page. Guarded the same way as
            // initialSkip above; the fetch itself overwrites pagination
            // with the backend-echoed skip, so no loop is possible here.
            const urlSkip = parseInt(new URLSearchParams(search).get("skip") || "0", 10);
            // Same gap as skip had before iteration 143, for limit: the
            // effect read only ?skip= from the URL, so a hand-edited
            // ?limit= was silently ignored — the fetch sent the stale
            // state limit while the URL kept showing the edited one.
            // Guarded the same way as initialLimit above; the fetch
            // overwrites pagination with the backend-echoed values, so
            // no loop is possible here. Both values are additionally
            // clamped to the backend bounds (iteration 403), as with
            // initialSkip/initialLimit above.
            const urlLimit = parseInt(new URLSearchParams(search).get("limit") || "10", 10);
            fetchCheckoutRecords(
                Number.isFinite(urlSkip) && urlSkip >= 0 ? Math.min(urlSkip, 10000) : 0,
                Number.isFinite(urlLimit) && urlLimit > 0 ? Math.min(urlLimit, 100) : 10,
            );
        }
        // current_tenant is a dep, not a gate: checkout records are
        // tenant-DB scoped (TenantMiddleware switches on the X-Tenant-ID
        // header, which getApiClient reads from the stored tenant that
        // AppConfig sets when current_tenant arrives), so a fetch that ran
        // before the tenant loaded was never re-run, leaving host-DB or
        // stale-tenant records on screen; host users have no tenant, so
        // gating would stop their records loading. The request-id guard
        // in fetchCheckoutRecords keeps the extra fetch from racing.
    }, [accessToken, search, current_tenant]);

    // Same over-range case iteration 138 clamped in AdvanceTable, for
    // this page: a hand-edited or stale-bookmark ?skip= at/past the total
    // (or a total that shrank since the URL was saved) fetches an empty
    // page, and the empty branch below hides the pagination controls, so
    // there is no Previous button to escape with — while the header
    // claims e.g. "Showing 101 to 25 of 25". The backend echoes the
    // requested skip verbatim (has_previous is just skip > 0), so it
    // never clamps. Fall back to the last page's offset instead; the
    // search-change effect above then refetches that page, and the
    // navigated skip is below the total, so this cannot ping-pong.
    // Guarded on the URL skip (not just pagination.skip) so the
    // navigation itself does not re-trigger a duplicate push before
    // the refetch lands, and skipped while loading so a stale page
    // cannot clamp against a not-yet-loaded total.
    useEffect(() => {
        if (loading || fetchError) return;
        if (pagination.total <= 0 || pagination.limit <= 0) return;
        if (pagination.skip < pagination.total) return;
        const lastPageSkip = Math.floor((pagination.total - 1) / pagination.limit) * pagination.limit;
        const parsedUrlSkip = parseInt(new URLSearchParams(search).get("skip") || "0", 10);
        const urlSkip = Number.isFinite(parsedUrlSkip) && parsedUrlSkip >= 0 ? parsedUrlSkip : 0;
        if (urlSkip === lastPageSkip) return;
        const query = new URLSearchParams(search);
        query.set("skip", lastPageSkip.toString());
        query.set("limit", pagination.limit.toString());
        // Replace, don't push: this URL is a correction of a bad URL, not
        // a page the user navigated to — pushing it would make Back return
        // to the bad URL, which would clamp forward again, so Back would
        // appear to do nothing.
        navigate(`${pathname}?${query.toString()}`, { replace: true });
    }, [loading, fetchError, pagination, search, pathname, navigate]);

    // Same misaligned-offset case iterations 139-140 normalised in
    // AdvanceTable, for this page: a hand-edited or stale-bookmark
    // ?skip= below the total but not on a page boundary (e.g. 15 at
    // limit 10) fetches that raw offset, so the "Page 2 of 3" label
    // promises records 11-20 while the table shows 16-25, and
    // Previous/Next then jump a full page from the misaligned offset
    // (15 -> 5, not 10). Fall back to the page's own offset instead;
    // the search-change effect above then refetches that page. The
    // over-range case is handled by the clamp effect above, so this
    // only acts while skip < total; an already-aligned skip rewrites
    // to itself, so it cannot ping-pong. Guarded on the URL skip and
    // skipped while loading, mirroring the clamp effect.
    useEffect(() => {
        if (loading || fetchError) return;
        if (pagination.total <= 0 || pagination.limit <= 0) return;
        if (pagination.skip >= pagination.total) return;
        if (pagination.skip % pagination.limit === 0) return;
        const alignedSkip = Math.floor(pagination.skip / pagination.limit) * pagination.limit;
        const parsedUrlSkip = parseInt(new URLSearchParams(search).get("skip") || "0", 10);
        const urlSkip = Number.isFinite(parsedUrlSkip) && parsedUrlSkip >= 0 ? parsedUrlSkip : 0;
        if (urlSkip === alignedSkip) return;
        const query = new URLSearchParams(search);
        query.set("skip", alignedSkip.toString());
        query.set("limit", pagination.limit.toString());
        // Replace, don't push, for the same reason as the clamp effect
        // above: a corrected URL must not leave the bad URL behind it
        // in history, or Back would land on it and normalise forward
        // again instead of going back.
        navigate(`${pathname}?${query.toString()}`, { replace: true });
    }, [loading, fetchError, pagination, search, pathname, navigate]);

    // Prev/next build on the router's search string, like every other
    // URL read in this file (fetch effect, clamp/normalise effects,
    // error-state Retry) — not window.location.search, so the page
    // they navigate from is always the page the router is showing.
    const handlePrevious = () => {
        const newSkip = Math.max(0, pagination.skip - pagination.limit);
        const query = new URLSearchParams(search);
        query.set("skip", newSkip.toString());
        query.set("limit", pagination.limit.toString());
        const newUrl = `${pathname}?${query.toString()}`;
        navigate(newUrl);
    };

    const handleNext = () => {
        const newSkip = pagination.skip + pagination.limit;
        const query = new URLSearchParams(search);
        query.set("skip", newSkip.toString());
        query.set("limit", pagination.limit.toString());
        const newUrl = `${pathname}?${query.toString()}`;
        navigate(newUrl);
    };



    const getStatusBadge = (status: string) => {
        const statusConfig: Record<
            string,
            { variant: "default" | "secondary" | "destructive" | "outline"; icon: React.ReactNode; label: string }
        > = {
            succeeded: {
                variant: "default",
                icon: <CheckCircle2 className="h-3 w-3" />,
                label: "Succeeded",
            },
            // A paid Stripe invoice reaches the table verbatim: the
            // backend's from_stripe_invoice_paid sets status to the
            // invoice's own status, and "paid" is in the BillingRecordDto
            // enum, but it had no badge entry here, so paid records
            // rendered with the generic outline/AlertTriangle fallback
            // instead of a success badge like succeeded/active.
            paid: {
                variant: "default",
                icon: <CheckCircle2 className="h-3 w-3" />,
                label: "Paid",
            },
            active: {
                variant: "default",
                icon: <CheckCircle2 className="h-3 w-3" />,
                label: "Active",
            },
            pending: {
                variant: "secondary",
                icon: <Clock className="h-3 w-3" />,
                label: "Pending",
            },
            incomplete: {
                variant: "secondary",
                icon: <Clock className="h-3 w-3" />,
                label: "Incomplete",
            },
            requires_payment_method: {
                variant: "outline",
                icon: <CreditCard className="h-3 w-3" />,
                label: "Requires Payment",
            },
            requires_action: {
                variant: "outline",
                icon: <AlertTriangle className="h-3 w-3" />,
                label: "Requires Action",
            },
            payment_failed: {
                variant: "destructive",
                icon: <XCircle className="h-3 w-3" />,
                label: "Payment Failed",
            },
            canceled: {
                variant: "destructive",
                icon: <XCircle className="h-3 w-3" />,
                label: "Canceled",
            },
        };

        const config = statusConfig[status.toLowerCase()] || {
            variant: "outline" as const,
            icon: <AlertTriangle className="h-3 w-3" />,
            label: status,
        };

        return (
            <Badge variant={config.variant} className="flex items-center gap-1 w-fit">
                {config.icon}
                {config.label}
            </Badge>
        );
    };

    const getScopeBadge = (scope: string) => {
        return (
            <Badge variant="outline" className="capitalize">
                {scope}
            </Badge>
        );
    };

    const getPaymentTypeBadge = (type: string) => {
        return (
            <Badge variant="secondary" className="capitalize">
                {type.replace("_", " ")}
            </Badge>
        );
    };

    if (loading) {
        return <ShowScreenLoader message="Loading checkouts list..." />
    }

    if (fetchError) {
        // The error branch previously offered no way back: no Refresh
        // button and no pagination, so a transient failure left the user
        // stuck unless they reloaded the whole page. A retry reuses the
        // current page (fetchCheckoutRecords clears the error first, so a
        // success returns to the table and a failure re-shows this branch).
        return (
            <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription className="flex items-center justify-between gap-4">
                    <span>{fetchError}</span>
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                            // Retry the page the URL actually shows, not
                            // pagination state: a failed fetch never
                            // overwrites pagination, so after navigating
                            // to a new page and failing, pagination still
                            // holds the previous page — retrying it would
                            // show that page while the URL claims the new
                            // one. Guarded the same way as the fetch
                            // effect above; the initial page (no fetch yet)
                            // matches pagination, so it behaves as before.
                            const urlSkip = parseInt(new URLSearchParams(search).get("skip") || "0", 10);
                            const urlLimit = parseInt(new URLSearchParams(search).get("limit") || "10", 10);
                            fetchCheckoutRecords(
                                Number.isFinite(urlSkip) && urlSkip >= 0 ? Math.min(urlSkip, 10000) : 0,
                                Number.isFinite(urlLimit) && urlLimit > 0 ? Math.min(urlLimit, 100) : 10,
                            );
                        }}
                    >
                        <RefreshCw className="h-4 w-4 mr-2" />
                        Retry
                    </Button>
                </AlertDescription>
            </Alert>
        );
    }

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-start justify-between">
                <div>
                    <h2 className="text-2xl font-bold tracking-tight flex items-center gap-2">
                        <ShoppingCart className="h-6 w-6" />
                        Checkout Overview
                    </h2>
                    <p className="text-muted-foreground mt-1">
                        View and manage all checkout sessions and billing records
                    </p>
                </div>
                <Button onClick={() => fetchCheckoutRecords(pagination.skip)} variant="outline" className="hidden sm:inline-flex">
                    <RefreshCw className="h-4 w-4 mr-2" />
                    Refresh
                </Button>
                <Button onClick={() => fetchCheckoutRecords(pagination.skip)} variant="outline" className="sm:hidden">
                    <RefreshCw className="h-4 w-4" />
                </Button>
            </div>

            {/* Summary Cards: Total is the global count from the backend,
            but the three category cards count only the current page's
            records (the list endpoint returns one page, and there is no
            backend aggregate) — the "(this page)" labels say so, rather
            than letting the categories look like a breakdown of Total. */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <Card>
                    <CardContent className="pt-6">
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-sm text-muted-foreground">Total Records</p>
                                <p className="text-2xl font-bold mt-1">{pagination.total}</p>
                            </div>
                            <ShoppingCart className="h-8 w-8 text-muted-foreground" />
                        </div>
                    </CardContent>
                </Card>
                <Card>
                    <CardContent className="pt-6">
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-sm text-muted-foreground">Succeeded (this page)</p>
                                <p className="text-2xl font-bold mt-1 text-green-600">
                                    {/* "paid" belongs here too: it is a success
                                    outcome (see the badge above), but was
                                    counted by none of the three category
                                    cards, so paid records vanished from the
                                    breakdown while still counted in Total. */}
                                    {records.filter((r) => r.status === "succeeded" || r.status === "active" || r.status === "paid").length}
                                </p>
                            </div>
                            <CheckCircle2 className="h-8 w-8 text-green-600" />
                        </div>
                    </CardContent>
                </Card>
                <Card>
                    <CardContent className="pt-6">
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-sm text-muted-foreground">Pending (this page)</p>
                                <p className="text-2xl font-bold mt-1 text-yellow-600">
                                    {/* requires_payment_method / requires_action are
                                    awaiting-action checkout states, but were counted
                                    by none of the three category cards, so they
                                    vanished from the breakdown exactly as "paid"
                                    did before iteration 150 — they belong with the
                                    pending (not yet completed) outcomes. */}
                                    {records.filter((r) => r.status === "pending" || r.status === "incomplete" || r.status === "requires_payment_method" || r.status === "requires_action").length}
                                </p>
                            </div>
                            <Clock className="h-8 w-8 text-yellow-600" />
                        </div>
                    </CardContent>
                </Card>
                <Card>
                    <CardContent className="pt-6">
                        <div className="flex items-center justify-between">
                            <div>
                                <p className="text-sm text-muted-foreground">Failed/Canceled (this page)</p>
                                <p className="text-2xl font-bold mt-1 text-red-600">
                                    {
                                        records.filter((r) => r.status === "payment_failed" || r.status === "canceled")
                                            .length
                                    }
                                </p>
                            </div>
                            <XCircle className="h-8 w-8 text-red-600" />
                        </div>
                    </CardContent>
                </Card>
            </div>

            {/* Records Table */}
            <Card>
                <CardHeader>
                    <div className="flex items-center justify-between">
                        <div>
                            <CardTitle className="flex items-center gap-2">
                                <TrendingUp className="h-5 w-5" />
                                Checkout Records
                            </CardTitle>
                            <CardDescription>
                                {/* With no records the old "skip + 1" start read "Showing 1 to 0
                                of 0 records"; a zero total has no first record to show. */}
                                Showing {pagination.total === 0 ? 0 : pagination.skip + 1} to{" "}
                                {Math.min(pagination.skip + pagination.limit, pagination.total)} of{" "}
                                {pagination.total} records
                            </CardDescription>
                        </div>
                    </div>
                </CardHeader>
                <CardContent>
                    {records.length === 0 ? (
                        <div className="text-center py-12">
                            <ShoppingCart className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                            <h3 className="text-lg font-semibold mb-2">No Checkout Records Found</h3>
                            <p className="text-muted-foreground text-sm">There are no checkout sessions yet</p>
                        </div>
                    ) : (
                        <>
                            <div className="rounded-md border">
                                <Table>
                                    <TableHeader>
                                        <TableRow>
                                            <TableHead>Scope</TableHead>
                                            <TableHead>Actor</TableHead>
                                            <TableHead>Payment Type</TableHead>
                                            <TableHead>Amount</TableHead>
                                            <TableHead>Status</TableHead>
                                            <TableHead>Customer</TableHead>
                                            <TableHead>Details</TableHead>
                                        </TableRow>
                                    </TableHeader>
                                    <TableBody>
                                        {records.map((record, index) => (
                                            <TableRow key={index}>
                                                <TableCell>{getScopeBadge(record.scope)}</TableCell>
                                                <TableCell>
                                                    <div className="flex items-center gap-2">
                                                        <User className="h-4 w-4 text-muted-foreground" />
                                                        <span className="capitalize">{record.actor.replace("_", " ")}</span>
                                                    </div>
                                                </TableCell>
                                                <TableCell>{getPaymentTypeBadge(record.payment_type)}</TableCell>
                                                <TableCell>
                                                    <div className="font-semibold">
                                                        {formatPrice(record.amount || 0, record.currency)}
                                                    </div>
                                                </TableCell>
                                                <TableCell>{getStatusBadge(record.status)}</TableCell>
                                                <TableCell>
                                                    {record.stripe_customer_id ? (
                                                        <div className="space-y-1">
                                                            <p className="text-xs font-mono">
                                                                {record.stripe_customer_id.slice(0, 20)}...
                                                            </p>
                                                            {record.user_id && (
                                                                <p className="text-xs text-muted-foreground">
                                                                    User: {record.user_id.slice(0, 8)}...
                                                                </p>
                                                            )}
                                                        </div>
                                                    ) : (
                                                        <span className="text-muted-foreground">N/A</span>
                                                    )}
                                                </TableCell>
                                                <TableCell>
                                                    <div className="space-y-1 text-xs">
                                                        {record.stripe_subscription_id && (
                                                            <div className="flex items-center gap-1">
                                                                <CreditCard className="h-3 w-3 text-muted-foreground" />
                                                                <span className="text-muted-foreground">Sub:</span>
                                                                <span className="font-mono">
                                                                    {record.stripe_subscription_id.slice(0, 10)}...
                                                                </span>
                                                            </div>
                                                        )}
                                                        {record.product_id && (
                                                            <div className="flex items-center gap-1">
                                                                <Package className="h-3 w-3 text-muted-foreground" />
                                                                <span className="text-muted-foreground">Product:</span>
                                                                <span className="font-mono">
                                                                    {record.product_id.slice(0, 10)}...
                                                                </span>
                                                            </div>
                                                        )}
                                                        {record.current_period_end && (
                                                            <div className="flex items-center gap-1">
                                                                <Calendar className="h-3 w-3 text-muted-foreground" />
                                                                <span className="text-muted-foreground">Ends:</span>
                                                                <span>{formatDateWithHourAndMinute(record.current_period_end)}</span>
                                                            </div>
                                                        )}
                                                        {record.canceled_at && (
                                                            <div className="flex items-center gap-1">
                                                                <XCircle className="h-3 w-3 text-destructive" />
                                                                <span className="text-destructive">Canceled:</span>
                                                                <span>{formatDateWithHourAndMinute(record.canceled_at)}</span>
                                                            </div>
                                                        )}
                                                        {record.cancellation_reason && (
                                                            <p className="text-muted-foreground italic">
                                                                Reason: {record.cancellation_reason}
                                                            </p>
                                                        )}
                                                    </div>
                                                </TableCell>
                                            </TableRow>
                                        ))}
                                    </TableBody>
                                </Table>
                            </div>

                            {/* Pagination */}
                            {pagination.total > pagination.limit && (
                                <div className="flex items-center justify-between mt-4">
                                    <p className="text-sm text-muted-foreground">
                                        Page {Math.floor(pagination.skip / pagination.limit) + 1} of{" "}
                                        {Math.ceil(pagination.total / pagination.limit)}
                                    </p>
                                    <div className="flex items-center gap-2">
                                        <Button
                                            variant="outline"
                                            size="sm"
                                            onClick={handlePrevious}
                                            disabled={!pagination.hasPrevious}
                                        >
                                            <ArrowLeft className="h-4 w-4 mr-2" />
                                            Previous
                                        </Button>
                                        <Button
                                            variant="outline"
                                            size="sm"
                                            onClick={handleNext}
                                            disabled={!pagination.hasNext}
                                        >
                                            Next
                                            <ArrowRight className="h-4 w-4 ml-2" />
                                        </Button>
                                    </div>
                                </div>
                            )}
                        </>
                    )}
                </CardContent>
            </Card>
        </div>
    );
}
