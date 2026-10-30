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
  if (!tenant) return null;
  try {
    const parsed: unknown = JSON.parse(tenant);
    // A syntactically valid but wrong-shape entry (stale schema, partial
    // write that still parses — a bare string, an array, or an object
    // without a string id) previously passed through: getApiClient then
    // sent "X-Tenant-ID": undefined on every call, the worker seeded an
    // undefined tenant, and tenant-selection auto-selected a bogus
    // tenant. The backend guard falls back to host scope for a bad id,
    // but the client should never send one. Treat a wrong-shape entry
    // exactly like a corrupt one: drop it and behave as if no tenant is
    // selected, so the user can re-select one. A real stored tenant
    // always carries a string id (backend ObjectId, serialized).
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed) ||
      typeof (parsed as { id?: unknown }).id !== "string" ||
      (parsed as { id: string }).id === ""
    ) {
      localStorage.removeItem("_tenant");
      return null;
    }
    return parsed as TenantDto;
  } catch {
    // A corrupted _tenant entry (partial write, stale schema) must not
    // crash every API call that reads it via getApiClient: drop it and
    // behave as if no tenant is selected, so the user can re-select one.
    localStorage.removeItem("_tenant");
    return null;
  }
}


export function formatPrice(amount: number, currency: string) {
  // Stripe amounts are in the currency's minor unit, but not every
  // currency has 100 minor units per major unit: dividing by 100
  // unconditionally made a zero-decimal amount (e.g. JPY 1000) render
  // 100x too small (¥10 instead of ¥1,000) in checkout-overview,
  // invoices, and billing-overview, and a three-decimal amount
  // (e.g. KWD) 10x too large. Use Stripe's minor-unit exponent per
  // currency; every other currency keeps the existing /100 behaviour.
  const code = currency.toUpperCase();
  const zeroDecimal = new Set(["BIF", "CLP", "DJF", "GNF", "ISK", "JPY", "KMF", "KRW", "PYG", "RWF", "UGX", "VND", "VUV", "XAF", "XOF", "XPF"]);
  const threeDecimal = new Set(["BHD", "JOD", "KWD", "LYD", "OMR", "TND"]);
  const divisor = zeroDecimal.has(code) ? 1 : threeDecimal.has(code) ? 1000 : 100;
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: code,
  }).format(amount / divisor);
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
  // Also strip one trailing '/api/v1' segment: every caller appends
  // '/api/v1/...' itself (generated services concatenate BASE + the
  // absolute path, ai-chat/SSO/worker all append it), so a base set
  // to the full API URL ('https://api.example.com/api/v1') would
  // otherwise double the prefix ('/api/v1/api/v1/...') and every
  // client call would 404. A subpath base without that segment
  // ('https://host/myapp') is left untouched. Only the exact
  // segment is stripped, so '/api/v1beta' and '/api/v10' are safe.
  // Trim surrounding whitespace first: a pasted value like
  // 'https://api.example.com ' (e.g. quoted in .env) would otherwise
  // keep the space, and every caller would request a URL with a
  // space before '/api/v1/...'. The segment strip is
  // case-insensitive: paths are lowercase on this backend, so an
  // '.../API/V1' base would otherwise double the prefix just like
  // the lowercase form and 404 every client call.
  const withoutSlashes = (import.meta.env.VITE_API_BASE_URL ?? '').trim().replace(/\/+$/, '');
  return withoutSlashes.replace(/\/api\/v1$/i, '');
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