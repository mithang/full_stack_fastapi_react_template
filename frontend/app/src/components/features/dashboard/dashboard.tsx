import { useEffect, useState } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
} from "recharts";
import { DashboardMetricsDto } from "@/api";
import { Loading } from "@/components/shared/loading";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { AlertTriangle } from "lucide-react";
import { getApiClient } from "@/lib/utils";
import { AllCards } from "./all-cards";
import { useAuthContext } from "@/components/providers/auth-provider";
import { useAppConfig } from "@/components/providers/app-config-provider";



export function Dashboard() {
    const [filter, setFilter] = useState<"today" | "this_week" | "last_3_months">("this_week");
    const [data, setData] = useState<DashboardMetricsDto | null>(null);
    const [fetchError, setFetchError] = useState<string | null>(null);

    const { accessToken } = useAuthContext();
    const { current_tenant } = useAppConfig();
    async function fetchData() {
        try {
            setFetchError(null);
            const metrics = await getApiClient(accessToken).dashboard.getDashboardMetricsApiV1DashboardGet({ filter })
            setData(metrics);
        } catch (error) {
            if (error instanceof Error) {
                console.error("Error fetching dashboard metrics:", error.cause);
            }
            // Previously every failure fell through to the "Fetching
            // Metrics..." loading state forever, so a backend outage looked
            // exactly like metrics still loading. A backend response
            // (ApiError, which carries a numeric status) means the server
            // answered; a failure with no status is a network failure.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            setFetchError(hasStatus
                ? "Failed to load dashboard metrics. Please try again later."
                : "Unable to reach the server. Check your connection and try again.");
        }
    }
    useEffect(() => {
        fetchData();
        // current_tenant is a dep, not a gate: host users have no
        // tenant, so gating would stop their metrics loading, but a
        // fetch that ran before the tenant arrived (fresh load /
        // cleared storage) must re-run once AppConfig sets it, or the
        // chart keeps the host-DB / stale-tenant numbers — the same
        // tenant-arrival race fixed in the providers (iters 176-181).
    }, [filter, accessToken, current_tenant])

    return (
        <div>
            <div className="@container/main flex flex-1 flex-col gap-2 pb-10">
                <AllCards />
            </div>
            <Card>
                <CardHeader>
                    <CardTitle>User Growth ({filter.replace("_", " ")})</CardTitle>
                </CardHeader>
                <CardContent>
                    <div className="flex gap-2 mb-4">
                        <Button
                            variant={filter === "today" ? "default" : "outline"}
                            onClick={() => setFilter("today")}
                        >
                            Today
                        </Button>
                        <Button
                            variant={filter === "this_week" ? "default" : "outline"}
                            onClick={() => setFilter("this_week")}
                        >
                            This Week
                        </Button>
                        <Button
                            variant={filter === "last_3_months" ? "default" : "outline"}
                            onClick={() => setFilter("last_3_months")}
                        >
                            Last 3 Months
                        </Button>
                    </div>

                    {fetchError ? (
                        <Alert variant="destructive">
                            <AlertTriangle className="h-4 w-4" />
                            <AlertDescription>
                                {fetchError}
                                <Button variant="outline" size="sm" className="mt-2" onClick={fetchData}>
                                    Retry
                                </Button>
                            </AlertDescription>
                        </Alert>
                    ) : data ? (
                        <div className="h-72">
                            <ResponsiveContainer width="100%" height="100%">
                                <LineChart data={data.timeseries}>
                                    <CartesianGrid strokeDasharray="3 3" />
                                    <XAxis dataKey="_id" />
                                    <YAxis allowDecimals={false} />
                                    <Tooltip />
                                    <Line
                                        type="monotone"
                                        dataKey="count"
                                        stroke="#4f46e5" // Indigo-600
                                        strokeWidth={2}
                                        dot={{ r: 4 }}
                                    />
                                </LineChart>
                            </ResponsiveContainer>
                            <div className="mt-4 flex justify-between text-sm text-muted-foreground">
                                <span>Total Users: {data.total_users}</span>
                                <span>New: {data.joined_users}</span>
                            </div>
                        </div>
                    ) : (
                        <Loading variant="dots" size="md" text="Fetching Metrics..." />
                    )}
                </CardContent>
            </Card>
        </div>
    )
}