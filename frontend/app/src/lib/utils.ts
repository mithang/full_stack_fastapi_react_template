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
      (parsed as { id: string }).id.trim() === ""
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
  // Same non-finite class as formatDate: a malformed API value
  // (undefined/NaN/Infinity, e.g. an incomplete Stripe record) is not
  // caught by the generated client's types at runtime and previously
  // rendered as "€NaN" in invoices/billing totals. Valid amounts take
  // the path below unchanged.
  if (typeof amount !== "number" || !Number.isFinite(amount)) return "N/A";
  // Stripe amounts are in the currency's minor unit, but not every
  // currency has 100 minor units per major unit: dividing by 100
  // unconditionally made a zero-decimal amount (e.g. JPY 1000) render
  // 100x too small (¥10 instead of ¥1,000) in checkout-overview,
  // invoices, and billing-overview, and a three-decimal amount
  // (e.g. KWD) 10x too large. Use Stripe's minor-unit exponent per
  // currency; every other currency keeps the existing /100 behaviour.
  const code = typeof currency === "string" ? currency.toUpperCase() : "";
  const zeroDecimal = new Set(["BIF", "CLP", "DJF", "GNF", "ISK", "JPY", "KMF", "KRW", "PYG", "RWF", "UGX", "VND", "VUV", "XAF", "XOF", "XPF"]);
  const threeDecimal = new Set(["BHD", "JOD", "KWD", "LYD", "OMR", "TND"]);
  const divisor = zeroDecimal.has(code) ? 1 : threeDecimal.has(code) ? 1000 : 100;
  const value = amount / divisor;
  try {
    return new Intl.NumberFormat("en-US", {
      style: "currency",
      currency: code,
    }).format(value);
  } catch {
    // Intl throws RangeError for a non-ISO currency code, and both the
    // plan form (3 characters, letters not enforced) and the backend
    // (min/max length 3 only) accept codes like "123": a stored plan
    // with such a code crashed billing-overview on render, and typing
    // a partial code in add-a-new-plan crashed the price preview
    // mid-edit. Valid codes take the path above unchanged; anything
    // else falls back to a plain number with the code as typed, so
    // the page keeps rendering instead of crashing.
    return `${code} ${new Intl.NumberFormat("en-US").format(value)}`.trim();
  }
};

export function formatDate(timestamp: number) {
  // DateTimeFormat throws RangeError for an Invalid Date, unlike
  // toLocaleString which renders "Invalid Date": a missing or
  // non-finite timestamp (e.g. an incomplete Stripe invoice record)
  // previously crashed the whole invoices page on render. Valid
  // timestamps take the path below unchanged.
  if (!Number.isFinite(timestamp)) return "N/A";
  // Same RangeError class, one step further: a finite but out-of-range
  // value (e.g. a malformed billing record) makes new Date() invalid,
  // and DateTimeFormat throws on it instead of rendering "Invalid
  // Date" — crashing the whole invoices page on render. Valid
  // timestamps take the path below unchanged.
  const date = new Date(timestamp * 1000);
  if (Number.isNaN(date.getTime())) return "N/A";
  return new Intl.DateTimeFormat("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  }).format(date);
};

export function formatDateWithHourAndMinute(timestamp: number | null | undefined) {
  // Same RangeError class as formatDate: the null/undefined guard did
  // not cover a non-finite value (e.g. a malformed billing record),
  // which crashed checkout-overview on render. Valid timestamps
  // take the path below unchanged.
  if (timestamp == null || !Number.isFinite(timestamp)) return "N/A";
  // Same out-of-range RangeError class as formatDate: a finite but
  // unrepresentable value makes new Date() invalid and DateTimeFormat
  // throws, crashing checkout-overview on render. Valid timestamps
  // take the path below unchanged.
  const date = new Date(timestamp * 1000);
  if (Number.isNaN(date.getTime())) return "N/A";
  return new Intl.DateTimeFormat("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
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

// Path-segment encoder for the generated client. Its default encoder is
// encodeURI, which leaves "?" and "#" unescaped, so a tenant name (or a
// storage key) containing either breaks the request before it reaches
// the backend: "?" starts a query string and "#" is dropped as a
// fragment, so the backend looks up the truncated name and answers 404
// ("can't find the tenant") for a tenant that exists — the tenant
// search sends the user's raw typed query as a path param. A blanket
// encodeURIComponent is not the fix: it also escapes "/", which the
// profile-image route needs (its :path key is "bucket/uuid_name.png",
// passed verbatim by the avatar flow). Encoding just "?" and "#" on top
// of encodeURI keeps "/" intact, as well as "&", "=" and "+" — all legal
// inside a path segment, so "Smith & Co." already worked and still does.
const encodePathSegment = (path: string): string =>
  encodeURI(path).replace(/\?/g, "%3F").replace(/#/g, "%23");

export function getApiClient(accessToken?: string) {
  const tenant = getTenant();
  const apiBase = getApiBaseUrl();
  if (!accessToken) {
    if (tenant) {
      return new ApiClient({
        ENCODE_PATH: encodePathSegment,
        BASE: apiBase,
        HEADERS: {
          "X-Tenant-ID": tenant.id!
        },
        WITH_CREDENTIALS: true,
      })
    }
    return new ApiClient({
      ENCODE_PATH: encodePathSegment,
      BASE: apiBase,
      WITH_CREDENTIALS: true,
    });
  }
  return new ApiClient({
    ENCODE_PATH: encodePathSegment,
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