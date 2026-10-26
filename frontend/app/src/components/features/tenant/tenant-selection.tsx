import { useState, useEffect, useRef } from 'react'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { X, Loader2 } from 'lucide-react'
import { TenantDto } from '@/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { cn, getApiClient, getTenant, setTenant } from '@/lib/utils'
import { useAppConfig } from '@/components/providers/app-config-provider'

interface TenantSearchProps {
    onTenantSelect?: (tenant: TenantDto | null) => void
    placeholder?: string
    className?: string
}

export function TenantSelection({
    onTenantSelect,
    placeholder = "Search tenant by name...",
    className
}: TenantSearchProps) {
    const { redirectToTenantDomain } = useAppConfig()
    const [isLoading, setIsLoading] = useState(false)
    const [searchQuery, setSearchQuery] = useState('')
    const [debouncedQuery, setDebouncedQuery] = useState('')
    const searchTimeoutRef = useRef<NodeJS.Timeout | null>(null)
    // Monotonic id of the latest tenant search: a slow earlier search must
    // not overwrite a newer one (or redirect to its tenant) if it resolves
    // after a later search has started.
    const searchRequestIdRef = useRef(0)
    const [error, setError] = useState<string | null>(null)
    useEffect(() => {
        const tenant = getTenant();
        if (tenant) {
            setSearchQuery(tenant.name);
            onTenantSelect?.(tenant);
        }
    }, [])

    // Debounce search query
    useEffect(() => {
        if (searchTimeoutRef.current) {
            clearTimeout(searchTimeoutRef.current)
        }

        searchTimeoutRef.current = setTimeout(() => {
            setDebouncedQuery(searchQuery)
        }, 300)

        return () => {
            if (searchTimeoutRef.current) {
                clearTimeout(searchTimeoutRef.current)
            }
        }
    }, [searchQuery])

    // Search tenants when debounced query changes
    useEffect(() => {
        if (debouncedQuery.length >= 2) {
            searchTenants(debouncedQuery)
        }
    }, [debouncedQuery])

    const searchTenants = async (query: string) => {
        setError(null)

        setIsLoading(true)
        const requestId = ++searchRequestIdRef.current
        try {
            const apiClient = getApiClient()
            const response = await apiClient.tenants.searchByNameApiV1TenantsSearchByNameNameGet({
                name: query
            })

            // A newer search has started since this one; ignore its result
            // entirely, including the tenant-domain redirect below.
            if (requestId !== searchRequestIdRef.current) return

            if (response) {
                setSearchQuery(response.name)
                setTenant(response)
                onTenantSelect?.(response)
                redirectToTenantDomain(response)
            } else {
                onTenantSelect?.(null)
                setTenant(null)
            }
        } catch (error) {
            // A newer search has started; its own result will set the state.
            if (requestId !== searchRequestIdRef.current) return
            // A backend response (ApiError, which carries a numeric status)
            // means the server answered and found no such tenant; a failure
            // with no status is a network error, not a wrong tenant name, and
            // must not send the user retyping a correct name. The generated
            // client rejects network failures with a raw TypeError, while
            // HTTP failures arrive as ApiError.
            const hasStatus = typeof (error as { status?: unknown } | null)?.status === "number";
            setError(hasStatus
                ? "We can't find the tenant you're looking for. Please check the name and try again."
                : "Unable to reach the server. Check your connection and try again.")
            onTenantSelect?.(null)
            setTenant(null)
        } finally {
            // Only the latest search may clear the spinner; a stale one
            // resolving first must not hide the newer search's loading state.
            if (requestId === searchRequestIdRef.current) setIsLoading(false)
        }
    }

    const clearSelection = () => {
        setSearchQuery('')
        onTenantSelect?.(null)
        setTenant(null)
        setError(null)
    }

    return (
        <Card className="w-full max-w-md shadow-lg mb-5">
            <CardHeader>
                <CardTitle>
                    Select Tenant
                </CardTitle>
                <CardDescription>
                    Please enter the tenant name to search.
                </CardDescription>
            </CardHeader>
            <CardContent>
                <div className={`relative ${className || ''}`}>
                    <Input
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        placeholder={placeholder}
                        className={cn("pr-20", error && "border-red-500")}
                    />

                    <div className="absolute top-[5px] right-0 flex items-center pr-3">
                        {isLoading && (
                            <Loader2 className="w-4 h-4 animate-spin text-muted-foreground mr-2" />
                        )}
                        {searchQuery && (
                            <Button
                                type="button"
                                variant="ghost"
                                size="sm"
                                onClick={clearSelection}
                                className="h-auto p-1"
                            >
                                <X className="w-4 h-4" />
                            </Button>
                        )}
                    </div>
                    {error && (
                        <span className="inline-flex pt-4   text-sm text-red-500">{error}</span>
                    )}
                </div>
            </CardContent>
        </Card>
    )
}