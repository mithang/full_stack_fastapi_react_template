import { ApiClient, BrandingDto, type TenantDto } from "@/api"
import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function setTenant(tenant: TenantDto | null) {
  if (!tenant) {
    localStorage.removeItem("_tenant");
    window.dispatchEvent(new Event("tenant_removed"));

    return;
  }
  localStorage.setItem("_tenant", JSON.stringify(tenant));
  window.dispatchEvent(new Event("tenant_set"));

}

export function getTenant(): TenantDto | null {
  const tenant = localStorage.getItem("_tenant");
  return tenant ? JSON.parse(tenant) : null;
}


export function formatPrice(amount: number, currency: string) {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currency.toUpperCase(),
  }).format(amount / 100);
};

export function formatDate(timestamp: number) {
  return new Intl.DateTimeFormat("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  }).format(new Date(timestamp * 1000));
};

export function formatDateWithHourAndMinute(timestamp: number | null | undefined) {
  if (timestamp == null) return "N/A";
  return new Intl.DateTimeFormat("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(timestamp * 1000));
};

export function getApiBaseUrl(): string {
  // Empty (default) = same-origin, as served by the backend.
  // Set VITE_API_BASE_URL for a separate web origin or a mobile
  // client that cannot rely on the Vite dev proxy or same origin.
  // Strip trailing slashes: callers append '/api/v1/...', so a base
  // like 'https://api.example.com/' would otherwise produce a
  // double-slash path ('//api/v1/...') that the backend may not route.
  return (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/+$/, '');
}

export function getApiClient(accessToken?: string) {
  // console.log("Getting API client with access token:", accessToken);
  const tenant = getTenant();
  const apiBase = getApiBaseUrl();
  if (!accessToken) {
    if (tenant) {
      return new ApiClient({
        BASE: apiBase,
        HEADERS: {
          "X-Tenant-ID": tenant.id!
        },
        WITH_CREDENTIALS: true,
      })
    }
    return new ApiClient({
      BASE: apiBase,
      WITH_CREDENTIALS: true,
    });
  }
  return new ApiClient({
    BASE: apiBase,
    HEADERS: {
      Authorization: `Bearer ${accessToken}`,
      ...tenant?.id && { "X-Tenant-ID": tenant.id }
    },
    WITH_CREDENTIALS: true
  });
}


export function extractErrorMessage(error: unknown): string {
  // Backend error bodies come in two shapes: the custom handler returns
  // {"error": ...} while FastAPI HTTPException returns {"detail": ...}
  // (a string, or a list of validation errors). The previous version only
  // read .body.error through a JSON round-trip, so HTTPException errors
  // surfaced as undefined and plain Errors (e.g. network failures, whose
  // message is non-enumerable and stringifies to {}) threw inside the
  // error handler itself, masking the real failure.
  if (typeof error === "object" && error !== null) {
    const body = (error as { body?: unknown }).body;
    if (typeof body === "string" && body) return body;
    if (typeof body === "object" && body !== null) {
      const candidate = (body as { error?: unknown; detail?: unknown; message?: unknown }).error
        ?? (body as { detail?: unknown }).detail
        ?? (body as { message?: unknown }).message;
      if (typeof candidate === "string" && candidate) return candidate;
      if (Array.isArray(candidate)) {
        const firstMsg = (candidate[0] as { msg?: unknown } | undefined)?.msg;
        if (typeof firstMsg === "string" && firstMsg) return firstMsg;
      }
    }
    if (error instanceof Error && error.message) return error.message;
  }
  if (typeof error === "string" && error) return error;
  return "Something went wrong.";
}

export function updateThemeConfiguration(branding: BrandingDto | undefined | null) {
  if (!branding) return;
  setTimeout(() => {
    const root = document.documentElement;
    const isDark = root.classList.contains("dark");
    const theme = isDark ? branding.theme_config?.dark : branding.theme_config?.light;
    if (!theme) return;
    Object.entries(theme).forEach(([key, value]) => {
      root.style.setProperty(`--${key}`, value);
    });
  }, 1)


}