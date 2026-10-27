import ipaddress
import os
import re
from fastapi import FastAPI, APIRouter, Request, status
from contextlib import asynccontextmanager

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from api.common.exceptions import ApiBaseException, AuthenticationFailedException, AwsException, AzureException, ConflictException, ForbiddenException, InvalidOperationException, NotFoundException, UnauthorizedException
from api.common.utils import get_logger, is_production_environment, is_tenancy_enabled
from api.core.container import container
from api.core.exceptions import InvalidSubdomainException, TenantNotFoundException
from api.infrastructure.persistence.mongodb import Database
from api.interfaces.middlewares.audit_logs_read_middleware import AuditLogsReadMiddleware
from api.interfaces.middlewares.redis_cache_middleware import RedisCacheMiddleware
from api.interfaces.middlewares.security_headers_middleware import SecurityHeadersMiddleware
from api.interfaces.middlewares.tenant_middleware import TenantMiddleware
from api.interfaces.api_controllers.account_endpoint import router as account_router
from api.interfaces.api_controllers.user_endpoint import router as user_router
from api.interfaces.api_controllers.tenant_endpoint import router as tenant_router
from api.interfaces.api_controllers.role_endpoint import router as role_router
from api.interfaces.api_controllers.app_configuration_endpoint import router as app_configuration_router
from api.interfaces.api_controllers.storage_endpoint import router as storage_router
from api.interfaces.api_controllers.permissions_endpoint import router as permissions_router
from api.interfaces.api_controllers.dashboard_endpoint import router as dashboard_router
from api.interfaces.api_controllers.ai_endpoint import router as ai_router
from api.interfaces.api_controllers.health_endpoint import router as health_router
from api.interfaces.api_controllers.manage_security_endpoint import router as manage_security_router
from api.interfaces.api_controllers.features_endpoint import router as features_router
from api.interfaces.api_controllers.product_endpoint import router as product_router
from api.interfaces.api_controllers.prices_endpoint import router as prices_router
from api.interfaces.api_controllers.billing_endpoint import router as billing_router
from api.interfaces.api_controllers.stripe_endpoint import router as stripe_router
from api.interfaces.api_controllers.stripe_endpoint import webhook_router as stripe_webhook_router
from api.interfaces.api_controllers.invoice_endpoint import router as invoice_router
from api.interfaces.api_controllers.checkout_endpoint import router as checkout_router
from api.interfaces.api_controllers.notification_endpoint import router as notification_router
from api.interfaces.api_controllers.audit_logs_endpoint import router as audit_logs_router
from api.interfaces.api_controllers.sso_settings_endpoint import router as sso_router
from api.interfaces.api_controllers.branding_endpoint import router as branding_router

from api.common.logging import configure_logging
from api.core.config import settings
from api.infrastructure.persistence.seeder import seed_initial_data

build_path = os.path.join(os.path.dirname(__file__), "ui")


db: Database = container.resolve(Database)

logger = get_logger(__name__)
@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    # initialization database with application-wide models Typically the host database
    await db.init_db(settings.mongo_db_name, is_tenant=False)
    await seed_initial_data()
    yield
    # Shutdown code
    await db.close()

app = FastAPI(
    lifespan=lifespan,
    title="FastAPI React & MongoDb Template",
    description="A template for building full-stack applications with FastAPI, React and MongoDB. Optional multi-tenancy support.",
    version="1.0.0",
    # Interactive docs and the raw schema expose every route, request
    # shape and auth endpoint: useful in development, but an
    # unnecessary information disclosure on a production deployment
    # (and the generated frontend client never fetches the schema at
    # runtime). Disabled only in production; dev keeps /docs, /redoc
    # and /openapi.json exactly as before. is_production_environment
    # lowercases the env value, unlike the raw == "production" checks
    # elsewhere, so "Production" is treated as production too.
    docs_url=None if is_production_environment() else "/docs",
    redoc_url=None if is_production_environment() else "/redoc",
    openapi_url=None if is_production_environment() else "/openapi.json",
)



@app.exception_handler(ApiBaseException)
async def api_exception_handler(req: Request, ex: ApiBaseException) -> JSONResponse:
    status_code = status.HTTP_400_BAD_REQUEST
    if isinstance(ex, NotFoundException) or isinstance(ex, TenantNotFoundException):
        status_code = status.HTTP_404_NOT_FOUND
    elif isinstance(ex, ConflictException):
        status_code = status.HTTP_409_CONFLICT
    elif isinstance(ex, UnauthorizedException):
        status_code = status.HTTP_401_UNAUTHORIZED
    elif isinstance(ex, AuthenticationFailedException):
        # The only named auth exception still falling through to the
        # default 400: an authentication failure is a 401, the status
        # the frontend treats as an auth signal, not a bad request.
        status_code = status.HTTP_401_UNAUTHORIZED
    elif isinstance(ex, ForbiddenException):
        # ForbiddenException previously fell through to the default 400,
        # so permission denials, self-action guards, and the refresh
        # endpoint's missing-cookie error all surfaced as "bad request"
        # instead of 403 — including FeatureNotEnabledException, which
        # subclasses ForbiddenException. 403 is the status the frontend
        # already expects for these cases (e.g. tenant-provider).
        status_code = status.HTTP_403_FORBIDDEN
    elif isinstance(ex, InvalidSubdomainException):
        status_code = status.HTTP_400_BAD_REQUEST
    elif isinstance(ex, InvalidOperationException):
        status_code = status.HTTP_406_NOT_ACCEPTABLE
    elif isinstance(ex, AwsException) or isinstance(ex, AzureException):
        # S3/Azure storage failures (S3StorageException, AzureBlobStorageException)
        # previously fell through to the default 400, so a storage-provider
        # outage looked like a bad client request. An upstream failure is a
        # 502, the status the frontend already treats as a server error
        # (its fallbacks trigger on any non-2xx rejection, as in the
        # profile-image path), so no client change is needed.
        status_code = status.HTTP_502_BAD_GATEWAY

    
    logger.error(f"API Exception: {ex.message}")
    return JSONResponse(
        status_code=status_code,
        content={"error": ex.message, "code": status_code}
    )

# Audit logging must run before the Redis cache: Starlette runs
# last-added middleware first, so the previous add order (audit
# before cache) made the cache run first, and a cache hit returned
# before the audit middleware ever ran, leaving cached reads of
# users/roles/tenants unlogged while uncached reads were logged.
# With this order the audit entry is written for every GET, cached
# or not, and the cache still sits between audit and the handler.
app.add_middleware(RedisCacheMiddleware)
app.add_middleware(AuditLogsReadMiddleware)

if is_tenancy_enabled(): 
    app.add_middleware(TenantMiddleware)
    logger.info("Multi-tenancy is enabled.")

# CORS must run before the other middlewares for preflight OPTIONS
# requests, so it is added last (Starlette runs last-added first).
# Only enabled when CORS_ALLOW_ORIGINS is explicitly configured, and
# only for those exact origins, so cookie auth is not opened up.
def _canonical_ipv4_decimal(host: str) -> str | None:
    # A zero-padded IPv4 octet ("192.168.001.010") never matches the
    # canonical Origin browsers send ("192.168.1.10"), and ipaddress
    # rejects leading zeros outright, so without this a padded private
    # host would also miss the scheme-less http assumption below.
    # Normalize digit octets through int() and re-validate; hostnames
    # and out-of-range octets are left alone (None). Hex octets are
    # normalized too: the WHATWG URL parser accepts "0xc0.0xa8.1.10"
    # as an IPv4 address and browsers serialize the Origin host in
    # decimal form ("192.168.1.10"), so a configured hex host would
    # otherwise never match, just as a zero-padded one did before.
    # A part is hex only with a "0x" prefix and hex digits; anything
    # else non-digit (e.g. "0xzz", a hostname label) is left alone.
    parts = host.split(".")
    # A lone number is likewise an IPv4 address to WHATWG ("2130706433"
    # and "0x7f000001" both mean 127.0.0.1), and browsers serialize
    # the Origin host in dotted-decimal form, so a configured
    # single-number host would otherwise never match either. Only
    # decimal and 0x-hex single numbers are canonicalized here: a
    # leading-zero single number ("03007000001") is WHATWG-octal, and
    # guessing decimal for it would conflict with the padded-decimal
    # choice above, so this branch returns None for it (the wrapper
    # below resolves it via the octal branch instead, which does not
    # guess decimal), as are out-of-range values.
    if len(parts) == 1:
        p = parts[0]
        if p.lower().startswith("0x"):
            digits = p[2:]
            if not digits or not all(c in "0123456789abcdefABCDEF" for c in digits):
                return None
            value = int(digits, 16)
        elif p.isdigit():
            if len(p) > 1 and p.startswith("0"):
                return None
            value = int(p)
        else:
            return None
        if value > 0xFFFFFFFF:
            return None
        return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))
    # WHATWG 2- and 3-part forms ("127.1" and "127.0.1" both mean
    # 127.0.0.1) are likewise IPv4 addresses, and browsers serialize
    # the Origin host in dotted-decimal form, so a configured 2- or
    # 3-part host would otherwise never match either. The last part
    # carries the remaining bytes: 24 bits for 2 parts, 16 bits for 3
    # parts; every earlier part is a single octet. Digit parts are
    # read as decimal, consistent with the padded-decimal choice
    # above (WHATWG-octal forms are deliberately not handled here),
    # and hex parts use the same "0x" rule as the 4-part branch.
    # Hostnames are left alone: any non-numeric part returns None.
    if len(parts) in (2, 3):
        values = []
        for p in parts:
            if p.lower().startswith("0x"):
                digits = p[2:]
                if not digits or not all(
                    c in "0123456789abcdefABCDEF" for c in digits
                ):
                    return None
                values.append(int(digits, 16))
            elif p.isdigit():
                values.append(int(p))
            else:
                return None
        if any(v > 0xFF for v in values[:-1]):
            return None
        last_bits = 24 if len(parts) == 2 else 16
        if values[-1] > (1 << last_bits) - 1:
            return None
        tail = [
            str((values[-1] >> shift) & 0xFF)
            for shift in range(last_bits - 8, -1, -8)
        ]
        return ".".join(str(v) for v in values[:-1]) + "." + ".".join(tail)
    if len(parts) != 4:
        return None
    values = []
    for p in parts:
        if p.lower().startswith("0x"):
            digits = p[2:]
            if not digits or not all(c in "0123456789abcdefABCDEF" for c in digits):
                return None
            values.append(int(digits, 16))
        elif p.isdigit():
            values.append(int(p))
        else:
            return None
    try:
        canonical = ".".join(str(v) for v in values)
        ipaddress.IPv4Address(canonical)
    except ValueError:
        return None
    return canonical


def _canonical_ipv4_octal(host: str) -> str | None:
    # WHATWG fallback for leading-zero parts the decimal branch
    # rejected: the WHATWG URL parser reads a leading-zero part as
    # octal, so "0300.0250.1.1" means 192.168.1.1 and browsers
    # serialize the Origin host that way. This runs only when the
    # decimal branch returned None (see _canonical_ipv4 below), so
    # it can only rescue entries that currently never match at all;
    # it never overrides the padded-decimal choice for entries the
    # decimal branch already canonicalizes ("192.168.001.010" stays
    # 192.168.1.10). A leading-zero part containing 8 or 9 is not
    # valid octal and returns None, as does any non-numeric part, so
    # hostnames are left alone. Hex parts keep the "0x" rule.
    parts = host.split(".")
    if len(parts) not in (1, 2, 3, 4):
        return None
    values = []
    for p in parts:
        if p.lower().startswith("0x"):
            digits = p[2:]
            if not digits or not all(c in "0123456789abcdefABCDEF" for c in digits):
                return None
            values.append(int(digits, 16))
        elif len(p) > 1 and p.startswith("0"):
            if not p.isdigit() or not all(c in "01234567" for c in p):
                return None
            values.append(int(p, 8))
        elif p.isdigit():
            values.append(int(p))
        else:
            return None
    if len(parts) == 1:
        if values[0] > 0xFFFFFFFF:
            return None
        return ".".join(str((values[0] >> shift) & 0xFF) for shift in (24, 16, 8, 0))
    if any(v > 0xFF for v in values[:-1]):
        return None
    last_bits = {2: 24, 3: 16, 4: 8}[len(parts)]
    if values[-1] > (1 << last_bits) - 1:
        return None
    tail = [
        str((values[-1] >> shift) & 0xFF)
        for shift in range(last_bits - 8, -1, -8)
    ]
    if len(parts) == 4:
        return ".".join(str(v) for v in values)
    return ".".join(str(v) for v in values[:-1]) + "." + ".".join(tail)


def _canonical_ipv4(host: str) -> str | None:
    # Decimal/padded first, WHATWG-octal only as a fallback, so the
    # two readings of a leading-zero part can never conflict: an
    # entry the decimal branch canonicalizes keeps that reading, and
    # the octal branch only rescues entries that otherwise never
    # match (e.g. "0300.0250.1.1", whose decimal 300 is out of range).
    return _canonical_ipv4_decimal(host) or _canonical_ipv4_octal(host)


def _encode_idna(host: str) -> str | None:
    # Browsers serialize Origin hosts per WHATWG URL / UTS46 (IDNA2008),
    # but the stdlib "idna" codec is IDNA2003: it maps ß to "ss" and
    # "ﬀ" to "ff", so "https://faß.de" became "https://fass.de" and
    # never matched the browser's "https://xn--fa-hia.de". Prefer the
    # `idna` package (already a transitive backend dependency via
    # httpx/requests) which follows IDNA2008; fall back to the stdlib
    # codec if it is unavailable, and to None (leave the host alone)
    # if encoding fails. IDNAError subclasses UnicodeError.
    # UTS46 maps the Latin ligatures U+FB00-U+FB06 to their letter
    # expansions (ﬀ -> "ff", ﬁ -> "fi", ﬂ -> "fl", ﬃ -> "ffi",
    # ﬄ -> "ffl", ﬅ/ﬆ -> "st") before IDNA processing, so browsers
    # serialize an Origin from "https://ﬀ.de" as "https://ff.de" —
    # but the `idna` package follows strict IDNA2008, where those
    # codepoints are disallowed, so encoding failed and the entry was
    # left alone and never matched. Map them up front (the stdlib
    # codec did this too, which is why it got ligatures right while
    # getting ß wrong); every other character keeps the IDNA2008 path
    # below, so ß/ς behaviour is unchanged. UTS46 likewise maps the
    # Armenian ligatures U+FB13-U+FB17 to their letter expansions
    # (ﬓ -> "մն", ﬔ -> "մե", ﬕ -> "մի", ﬖ -> "վն", ﬗ -> "մխ"),
    # which the strict IDNA2008 path likewise rejects, so they are
    # mapped in the same table.
    host = host.translate(
        {
            0xFB00: "ff",
            0xFB01: "fi",
            0xFB02: "fl",
            0xFB03: "ffi",
            0xFB04: "ffl",
            0xFB05: "st",
            0xFB06: "st",
            0xFB13: "մն",
            0xFB14: "մե",
            0xFB15: "մի",
            0xFB16: "վն",
            0xFB17: "մխ",
            # UTS46 likewise maps the letterlike symbols MICRO SIGN
            # U+00B5 -> GREEK SMALL LETTER MU and LATIN SMALL LETTER
            # LONG S U+017F -> "s", which the strict IDNA2008 path
            # likewise rejects, so they are mapped here too. (KELVIN
            # SIGN, ANGSTROM SIGN and OHM SIGN are the same class of
            # UTS46 mapping, but the pipeline's lower() already folds
            # them to "k"/"å"/"ω" before this helper runs, so they
            # need no entry here; MICRO SIGN and LONG S survive
            # lower() unchanged, which is why they are the gap.)
            0x00B5: "μ",
            0x017F: "s",
            # UTS46 likewise maps the ordinal indicators MASCULINE
            # ORDINAL INDICATOR U+00BA -> "o" and FEMININE ORDINAL
            # INDICATOR U+00AA -> "a", which the strict IDNA2008 path
            # likewise rejects, so they are mapped here too. Both
            # survive the pipeline's lower() unchanged, which is why
            # they are the gap. (Parenthesized letters U+249C-U+24B5
            # map under UTS46 to "(a)"-style forms that IDNA rejects
            # outright, so they are deliberately left alone.)
            0x00AA: "a",
            0x00BA: "o",
            # UTS46 likewise maps LATIN SMALL LETTER N PRECEDED BY
            # APOSTROPHE U+0149 to MODIFIER LETTER APOSTROPHE
            # U+02BC + "n" before IDNA processing, which the
            # strict IDNA2008 path likewise rejects, so it is mapped
            # here too. The mapped form punycodes under the strict
            # path to the browser-serialized form (U+0149.example ->
            # "xn--n-y6a.example"); it survives the pipeline's
            # lower() unchanged, which is why it is the gap.
            0x0149: "\u02bcn",
        }
    )
    # UTS46 likewise maps the circled letters U+24B6-U+24CF (capitals)
    # and U+24D0-U+24E9 (small letters) to their plain letters (ⓐ ->
    # "a", Ⓐ -> "a"), which the strict IDNA2008 path likewise
    # rejects, so they are mapped here too. Both ranges map to
    # lowercase plain letters, matching the browser-serialized form;
    # the pipeline's lower() already folds capitals to smalls before
    # this helper runs, so mapping both ranges also keeps the helper
    # correct if called directly. Circled digits are the same class:
    # UTS46 maps U+2460-U+2473 (①-⑳) to "1"-"20" and U+24EA (⓪) to
    # "0", which the strict IDNA2008 path likewise rejects, so they
    # are mapped here too. The negative circled forms (e.g. U+24FF
    # ⓿) do not map under UTS46 and are left to the IDNA2008 path.
    host = host.translate(
        {
            cp: chr(ord("a") + cp - 0x24B6)
            if cp < 0x24D0
            else chr(ord("a") + cp - 0x24D0)
            for cp in range(0x24B6, 0x24EA)
        }
        | {cp: str(cp - 0x2460 + 1) for cp in range(0x2460, 0x2474)}
        | {0x24EA: "0"}
    )
    # UTS46 likewise maps the Roman numerals U+2160-U+216F (capitals)
    # and U+2170-U+217F (small letters) to their letter expansions
    # (Ⅷ -> "viii", Ⅻ -> "xii"), which the strict IDNA2008 path
    # likewise rejects, so they are mapped here too. Both ranges map
    # to lowercase plain letters, matching the browser-serialized
    # form; the pipeline's lower() already folds capitals to smalls
    # before this helper runs, so mapping both ranges also keeps the
    # helper correct if called directly.
    _roman = [
        "i", "ii", "iii", "iv", "v", "vi", "vii", "viii",
        "ix", "x", "xi", "xii", "l", "c", "d", "m",
    ]
    host = host.translate(
        {cp: _roman[cp - 0x2160] for cp in range(0x2160, 0x2170)}
        | {cp: _roman[cp - 0x2170] for cp in range(0x2170, 0x2180)}
    )
    # UTS46 likewise maps the superscript and subscript digits to
    # their plain digits (² -> "2", ₀ -> "0"), which the strict
    # IDNA2008 path likewise rejects, so they are mapped here too.
    # Superscript digits are SUPERSCRIPT ONE U+00B9, SUPERSCRIPT TWO
    # U+00B2, SUPERSCRIPT THREE U+00B3, and SUPERSCRIPT ZERO plus
    # FOUR-NINE U+2070/U+2074-U+2079; subscript digits are
    # U+2080-U+2089. SUPERSCRIPT LATIN SMALL LETTER I U+2071 likewise
    # maps under UTS46 to "i", which the strict IDNA2008 path likewise
    # rejects, so it is mapped here too. It survives the pipeline's
    # lower() unchanged, which is why it is the gap. SUPERSCRIPT
    # LATIN SMALL LETTER N U+207F is the same class (UTS46 maps it
    # to "n", strict IDNA2008 rejects it, lower() leaves it alone),
    # so it is mapped here too. The plain-letter
    # modifier letters in U+1D2C-U+1D6A are mapped in the next table
    # below; the remaining modifier letters (the punycode-valid
    # members of that range, and the U+02B0-U+02BF modifier
    # letters) are assessed in the tables below, since they are
    # not the same fix class.
    # The superscript/subscript signs
    # U+207A-U+207C and U+208A-U+208C, which UTS46 does not map to a
    # valid domain form (they fail under both strict and UTS46
    # processing), are deliberately left alone.
    host = host.translate(
        {0x00B9: "1", 0x00B2: "2", 0x00B3: "3"}
        | {0x2070: "0"}
        | {0x2071: "i"}
        | {0x207F: "n"}
        | {cp: str(cp - 0x2070) for cp in range(0x2074, 0x207A)}
        | {cp: str(cp - 0x2080) for cp in range(0x2080, 0x208A)}
    )
    # UTS46 likewise maps the subscript letters U+2090-U+209C to
    # their plain letters (ₐ -> "a", ₑ -> "e", ₒ -> "o", ₓ -> "x",
    # ₕ -> "h", ₖ -> "k", ₗ -> "l", ₘ -> "m", ₙ -> "n", ₚ -> "p",
    # ₛ -> "s", ₜ -> "t"), which the strict IDNA2008 path likewise
    # rejects, so they are mapped here too, as the counterpart of
    # the subscript digits above. They survive the pipeline's
    # lower() unchanged, which is why they are the gap. The one
    # remaining member of the range, SUBSCRIPT SCHWA U+2094, is a
    # different fix class: UTS46 punycodes it as-is
    # (ₔ -> "xn--sna"), so it is left alone here for the UTS46
    # retry, as with the punycode-valid modifier letters.
    host = host.translate(
        {
            0x2090: "a", 0x2091: "e", 0x2092: "o", 0x2093: "x",
            0x2095: "h", 0x2096: "k", 0x2097: "l", 0x2098: "m",
            0x2099: "n", 0x209A: "p", 0x209B: "s", 0x209C: "t",
        }
    )
    # UTS46 likewise maps the modifier letters MODIFIER LETTER SMALL
    # L U+02E1, MODIFIER LETTER SMALL S U+02E2 and MODIFIER LETTER
    # SMALL X U+02E3 to their plain letters (ˡ -> "l", ˢ -> "s",
    # ˣ -> "x"), which the strict IDNA2008 path likewise rejects,
    # so they are mapped here too, as the counterpart of the
    # subscript letters above. They survive the pipeline's lower()
    # unchanged, which is why they are the gap. The neighbouring
    # members of the range, MODIFIER LETTER SMALL GAMMA U+02E0 and
    # MODIFIER LETTER REVERSED GLOTTAL STOP U+02E4, are a different
    # fix class: UTS46 punycodes them as-is (ˠ -> "xn--2na",
    # ˤ -> "xn--ipa"), so they are handled by the UTS46 retry
    # below, not here, as with the punycode-valid modifier
    # letters.
    host = host.translate(
        {0x02E1: "l", 0x02E2: "s", 0x02E3: "x"}
    )
    # UTS46 likewise maps the plain-letter modifier letters in
    # U+1D2C-U+1D6A to their base letters (ᴬ -> "a", ᵃ -> "a",
    # ᵢ -> "i"), which the strict IDNA2008 path likewise rejects,
    # so they are mapped here too. Unlike the circled capitals,
    # the pipeline's lower() does NOT fold these capitals, so both
    # the capital and small forms are listed. The other members of
    # the range (e.g. ᴭ, ᵄ) are valid as-is under UTS46 and
    # serialize as punycode, not as plain letters, so they are a
    # separate fix class and are handled by the UTS46 retry below,
    # not here, as are the plain-letter U+02B0-U+02BF members
    # (mapped in the next table below).
    host = host.translate(
        {
            0x1D2C: "a", 0x1D2E: "b", 0x1D30: "d", 0x1D31: "e",
            0x1D33: "g", 0x1D34: "h", 0x1D35: "i", 0x1D36: "j",
            0x1D37: "k", 0x1D38: "l", 0x1D39: "m", 0x1D3A: "n",
            0x1D3C: "o", 0x1D3E: "p", 0x1D3F: "r", 0x1D40: "t",
            0x1D41: "u", 0x1D42: "w", 0x1D43: "a", 0x1D47: "b",
            0x1D48: "d", 0x1D49: "e", 0x1D4D: "g", 0x1D4F: "k",
            0x1D50: "m", 0x1D52: "o", 0x1D56: "p", 0x1D57: "t",
            0x1D58: "u", 0x1D5B: "v", 0x1D62: "i", 0x1D63: "r",
            0x1D64: "u", 0x1D65: "v",
        }
    )
    # UTS46 likewise maps five of the U+02B0-U+02BF modifier letters
    # to plain letters (ʰ -> "h", ʲ -> "j", ʳ -> "r", ʷ -> "w",
    # ʸ -> "y"), which the strict IDNA2008 path likewise rejects,
    # so they are mapped here too. They survive the pipeline's
    # lower() unchanged, which is why they are the gap. The other
    # members of the range are a different fix class and are handled
    # by the UTS46 retry below, not here: ʱ/ʴ/ʵ/ʶ serialize as
    # punycode under UTS46 (ʱ -> "xn--5na", etc.) but are rejected
    # by the strict IDNA2008 path — the same separate class as
    # ᴭ/ᵄ — while U+02B9-U+02BF already pass the strict path and
    # serialize as punycode, matching the browser.
    host = host.translate(
        {0x02B0: "h", 0x02B2: "j", 0x02B3: "r", 0x02B7: "w", 0x02B8: "y"}
    )
    # UTS46 likewise maps the Cyrillic small letters U+1C80-U+1C88
    # to their ordinary Cyrillic counterparts (ROUNDED VE -> VE,
    # LONG-LEGGED DE -> DE, NARROW O -> O, WIDE ES -> ES, TALL TE
    # and THREE-LEGGED TE -> TE, TALL HARD SIGN -> HARD SIGN, TALL
    # YAT -> YAT, UNBLENDED UK -> UK), which the strict IDNA2008
    # path likewise rejects, so they are mapped here too. They
    # survive the pipeline's lower() unchanged, which is why they
    # are the gap. The remaining members of the block, U+1C89-U+1C8F,
    # are unassigned in the Unicode data the `idna` package uses
    # here and are deliberately left alone.
    host = host.translate(
        {
            0x1C80: "\u0432", 0x1C81: "\u0434", 0x1C82: "\u043e",
            0x1C83: "\u0441", 0x1C84: "\u0442", 0x1C85: "\u0442",
            0x1C86: "\u044a", 0x1C87: "\u0463", 0x1C88: "\ua64b",
        }
    )
    # UTS46 likewise maps two CJK radicals in U+2E80-U+2EFF to
    # their unified ideographs (CJK RADICAL MOTHER U+2E9F -> U+6BCD,
    # CJK RADICAL C-SIMPLIFIED TURTLE U+2EF3 -> U+9F9F), which
    # the strict IDNA2008 path likewise rejects, so they are
    # mapped here too, as the counterpart of the Cyrillic small
    # letters above. They survive the pipeline's lower()
    # unchanged, which is why they are the gap, and the mapped
    # forms pass the strict path, so this is a translate-table
    # fix, not a UTS46 retry. A full scan of U+2E80-U+2EFF
    # confirmed exactly these two are strict-reject/UTS46-ok
    # after lower(): the other radicals of the block fail under
    # the package's UTS46 processing too and are deliberately
    # left alone (the package cannot reproduce the browser
    # form for them, as with U+1C89/U+1C8A above).
    host = host.translate(
        {0x2E9F: "\u6bcd", 0x2EF3: "\u9f9f"}
    )
    # UTS46 likewise maps the letterlike symbols in U+2100-U+214F
    # that denote a single plain letter (ℂ -> "c", ℊ -> "g",
    # ℋ/ℌ/ℍ/ℎ -> "h", ℐ/ℑ/ℹ/ⅈ -> "i", ℒ/ℓ -> "l", ℕ -> "n",
    # ℙ -> "p", ℚ -> "q", ℛ/ℜ/ℝ -> "r", ℤ/ℨ -> "z",
    # ℬ -> "b", ℭ -> "c", ℯ/ℰ/ⅇ -> "e", ℱ -> "f", ℳ -> "m",
    # ℴ -> "o", ⅅ/ⅆ -> "d", ⅉ -> "j") to that letter before IDNA
    # processing, so browsers serialize an Origin from e.g.
    # "https://ℂ.example" as "https://c.example" — but the `idna`
    # package follows strict IDNA2008, where those codepoints are
    # disallowed, so encoding failed and the entry was left alone
    # and never matched. Map them up front; they survive the
    # pipeline's lower() unchanged, which is why they are the gap.
    # The other members of the range are a different fix class and
    # are left alone here: the punycode forms handled by the UTS46
    # retry below (ℇ, ℏ and the like), the punycode-as-is forms
    # handled by the fallback below (℃, ℈, ℉ and the
    # like), and codepoints the browser itself rejects
    # (℀, ℁, ℅, ℆). The multi-letter mappings of the range
    # (№ -> "no", ℠ -> "sm", ℡ -> "tel", ™ -> "tm", ℻ -> "fax")
    # are the same class as the single-letter mappings above —
    # UTS46 maps them before IDNA processing and the strict
    # IDNA2008 path rejects them — so they are mapped in the
    # next table below. They likewise survive the pipeline's
    # lower() unchanged, which is why they are the gap.
    host = host.translate(
        {
            0x2102: "c", 0x210A: "g", 0x210B: "h", 0x210C: "h",
            0x210D: "h", 0x210E: "h", 0x2110: "i", 0x2111: "i",
            0x2112: "l", 0x2113: "l", 0x2115: "n", 0x2119: "p",
            0x211A: "q", 0x211B: "r", 0x211C: "r", 0x211D: "r",
            0x2124: "z", 0x2128: "z", 0x212C: "b", 0x212D: "c",
            0x212F: "e", 0x2130: "e", 0x2131: "f", 0x2133: "m",
            0x2134: "o", 0x2139: "i", 0x2145: "d", 0x2146: "d",
            0x2147: "e", 0x2148: "i", 0x2149: "j",
        }
    )
    # UTS46 likewise maps the multi-letter letterlike symbols in
    # U+2100-U+214F to their letter expansions (№ -> "no",
    # ℠ -> "sm", ℡ -> "tel", ™ -> "tm", ℻ -> "fax"), which the
    # strict IDNA2008 path likewise rejects, so they are mapped
    # here too. They survive the pipeline's lower() unchanged,
    # which is why they are the gap.
    host = host.translate(
        {
            0x2116: "no", 0x2120: "sm", 0x2121: "tel",
            0x2122: "tm", 0x213B: "fax",
        }
    )
    # UTS46 likewise maps the currency symbol RUPEE SIGN U+20A8 to
    # its letter expansion (₨ -> "rs"), which the strict IDNA2008
    # path likewise rejects, so it is mapped here too, as the
    # counterpart of the multi-letter letterlike symbols above.
    # It survives the pipeline's lower() unchanged, which is why
    # it is the gap, and a scan of U+20A0-U+20CF confirmed it is
    # the only currency symbol of that range in this class.
    host = host.translate(
        {0x20A8: "rs"}
    )
    # UTS46 likewise maps the Latin modifier letters LATIN
    # SUBSCRIPT SMALL LETTER J U+2C7C and MODIFIER LETTER CAPITAL
    # V U+2C7D to their plain letters (ⱼ -> "j", ⱽ -> "v"),
    # which the strict IDNA2008 path likewise rejects, so they
    # are mapped here too, as the counterpart of the modifier
    # letters above. They survive the pipeline's lower()
    # unchanged, which is why they are the gap. The neighbouring
    # modifier letters are a different fix class and are left
    # alone here: U+2C7B passes the strict path directly, while
    # U+2C7E-U+2C7F are punycode-as-is under UTS46 and belong to
    # the UTS46 retry, not to a translate table.
    host = host.translate(
        {0x2C7C: "j", 0x2C7D: "v"}
    )
    # UTS46 likewise maps the Latin modifier letters MODIFIER
    # LETTER CAPITAL C U+A7F2, MODIFIER LETTER CAPITAL F U+A7F3
    # and MODIFIER LETTER CAPITAL Q U+A7F4 to their plain letters
    # (ꟲ -> "c", ꟳ -> "f", ꟴ -> "q"), which the strict IDNA2008
    # path likewise rejects, so they are mapped here too, as the
    # counterpart of the modifier letters above. They survive the
    # pipeline's lower() unchanged, which is why they are the gap.
    # A full scan of U+A700-U+A7FF confirmed these three are the
    # block's only members in this class: U+A770/U+A7F8/U+A7F9
    # are punycode-as-is under UTS46 and belong to the UTS46 retry,
    # not to a translate table.
    host = host.translate(
        {0xA7F2: "c", 0xA7F3: "f", 0xA7F4: "q"}
    )
    # UTS46 likewise maps the fullwidth ASCII forms U+FF01-U+FF5E to
    # their ASCII equivalents (ｅｘａｍｐｌｅ -> "example", including
    # the fullwidth full stop U+FF0E -> ".") before IDNA processing,
    # so browsers serialize an Origin from "https://ｅｘａｍｐｌｅ.com"
    # as "https://example.com" — but the `idna` package follows strict
    # IDNA2008, where those codepoints are disallowed, so encoding
    # failed and the entry was left alone and never matched. Map them
    # up front (each is exactly 0xFEE0 above its ASCII equivalent);
    # U+FF5F/U+FF60 are not ASCII forms and are left to the IDNA2008
    # path below, as are halfwidth forms.
    host = host.translate(
        {cp: chr(cp - 0xFEE0) for cp in range(0xFF01, 0xFF5F)}
    )
    try:
        import idna as _idna
    except ImportError:
        try:
            return host.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            return None
    try:
        return _idna.encode(host).decode("ascii")
    except (UnicodeError, ValueError):
        pass
    # UTS46 retry for punycode-valid modifier letters only: the
    # remaining modifier letters in U+02B0-U+02BF (ʱ/ʴ/ʵ/ʶ) and
    # U+1D2C-U+1D6A (ᴭ, ᵄ and the other members listed below) are
    # valid as-is under UTS46 and serialize as punycode (ʱ ->
    # "xn--5na", ᴭ -> "xn--6ca"), but the strict IDNA2008 path
    # above rejects them, so the entry was left alone and never
    # matched. A translate table cannot express this class (there
    # is no plain-letter target), so retry just these hosts with
    # the package's UTS46 processing, which matches the browser
    # serialization verified against Node's WHATWG parser. The
    # guard keeps every other strict-rejected host unchanged: the
    # retry only runs when one of the listed codepoints is present,
    # and a failure here still falls through to the underscore
    # fallback below (e.g. a host with both a modifier letter and
    # "_", which UTS46 rejects) and then to None, as before.
    # The same class covers the punycode-valid letterlike symbols
    # in U+2100-U+214F (ℇ -> "xn--una", ℏ -> "xn--1ea",
    # ℵ/ℶ/ℷ/ℸ -> "xn--4db"/"xn--5db"/"xn--6db"/"xn--7db",
    # ℼ/ℿ -> "xn--1xa", ℽ/ℾ -> "xn--oxa", plus Ω -> "xn--bya"
    # and Å -> "xn--5ca", which the pipeline's lower() already
    # folds to ω/å before this helper runs, so they matter only
    # for direct calls — the same reason the circled and Roman
    # capital ranges are listed). They are kept in a separate
    # set so the two fix classes stay distinct. The remaining
    # letterlike members are a different fix class, handled by
    # the punycode-as-is fallback below rather than here:
    # symbols the browser punycodes as-is but the
    # package's UTS46 processing rejects (℃ -> "°c", ℈, ℉ ->
    # "°f", ℄, ℔ and the like), and codepoints the browser
    # itself rejects (℀, ℁, ℅, ℆).
    _punycode_modifiers = frozenset(
        [
            0x02B1, 0x02B4, 0x02B5, 0x02B6,
            0x1D2D, 0x1D32, 0x1D3D, 0x1D44, 0x1D45, 0x1D46,
            0x1D4A, 0x1D4B, 0x1D4C, 0x1D51, 0x1D53, 0x1D54,
            0x1D55, 0x1D59, 0x1D5A, 0x1D5C, 0x1D5D, 0x1D5E,
            0x1D5F, 0x1D60, 0x1D61, 0x1D66, 0x1D67, 0x1D68,
            0x1D69, 0x1D6A,
        ]
    )
    _punycode_letterlike = frozenset(
        [
            0x2107, 0x210F, 0x2126, 0x212B,
            0x2135, 0x2136, 0x2137, 0x2138,
            0x213C, 0x213D, 0x213E, 0x213F,
        ]
    )
    # The same class covers the Latin digraphs U+0132-U+0133
    # (Ĳ/ĳ), U+01C4-U+01CC (Ǆ/ǅ/ǆ, Ǉ/ǈ/ǉ, Ǌ/ǋ/ǌ) and
    # U+01F1-U+01F3 (Ǳ/ǲ/ǳ): UTS46 maps some to plain letters
    # (Ĳ -> "ij", Ǉ -> "lj", Ǌ -> "nj", Ǳ -> "dz") and punycodes
    # others as-is (Ǆ -> "xn--d-toa"), but the strict IDNA2008
    # path rejects them all, so a configured origin containing one
    # was left alone and never matched. A translate table cannot
    # express the mixed class, so they join the UTS46 retry here;
    # the pipeline's lower() already folds the capitals to their
    # small forms before this helper runs, so the small forms are
    # what the retry sees in practice, but all forms are listed so
    # the helper stays correct if called directly. Verified
    # against Node's WHATWG parser, which matches the package's
    # UTS46 processing for every form above.
    _punycode_digraphs = frozenset(
        [
            0x0132, 0x0133,
            0x01C4, 0x01C5, 0x01C6,
            0x01C7, 0x01C8, 0x01C9,
            0x01CA, 0x01CB, 0x01CC,
            0x01F1, 0x01F2, 0x01F3,
        ]
    )
    # The same class covers the Cherokee small letters U+AB70-U+ABBF
    # and U+13F8-U+13FD: the strict IDNA2008 path rejects them all
    # (the U+13F8-U+13FD forms are the lowercases of U+13F0-U+13F5,
    # whose other capitals fold to U+AB70-U+ABBF), while UTS46
    # punycodes them as-is (ꭰ -> "xn--58d", ᏽ -> "xn--lce"),
    # matching Node's WHATWG parser. A translate table cannot
    # express this class (there is no plain-letter target), so
    # they join the UTS46 retry here; the pipeline's lower()
    # already folds the capitals to these small forms before this
    # helper runs, so the small forms are what the retry sees in
    # practice, but the capitals pass the strict path directly
    # and need no entry. Verified against Node's WHATWG parser,
    # which matches the package's UTS46 processing for every
    # member of both ranges.
    _punycode_cherokee = frozenset(
        list(range(0xAB70, 0xABC0)) + list(range(0x13F8, 0x13FE))
    )
    # The same class covers the Devanagari letters with nukta
    # U+0958-U+095F (क़-य़, the single-codepoint forms of base letter
    # + NUKTA U+093C): the strict IDNA2008 path rejects them all,
    # while UTS46 punycodes them as-is (क़ -> "xn--11b2f"),
    # matching Node's WHATWG parser. A translate table cannot
    # express this class (there is no plain-letter target), so
    # they join the UTS46 retry here; the pipeline's lower()
    # leaves them unchanged, so the forms above are what the
    # retry sees in practice. The nukta letters of other Indic
    # scripts (Bengali, Gurmukhi, Oriya) are the same class but
    # separate ranges, assessed separately.
    _punycode_devanagari = frozenset(range(0x0958, 0x0960))
    # The same class covers the Bengali letters with nukta
    # U+09DC/U+09DD/U+09DF (ড়/ঢ়/য়, the single-codepoint forms
    # of base letter + NUKTA U+09BC): the strict IDNA2008 path
    # rejects them all, while UTS46 punycodes them as-is
    # (ড় -> "xn--15b8c", ঢ় -> "xn--25b6c", য় -> "xn--g6b0a"),
    # matching Node's WHATWG parser. A translate table cannot
    # express this class (there is no plain-letter target), so
    # they join the UTS46 retry here; the pipeline's lower()
    # leaves them unchanged, so the forms above are what the
    # retry sees in practice. The nukta letters of the remaining
    # Indic scripts (Gurmukhi, Oriya) are the same class but
    # separate ranges, assessed separately.
    _punycode_bengali = frozenset([0x09DC, 0x09DD, 0x09DF])
    # The same class covers the Gurmukhi letters
    # U+0A33/U+0A36/U+0A59-U+0A5B/U+0A5E (ਲ਼/ਸ਼/ਖ਼/ਗ਼/ਜ਼/ਫ਼,
    # the latter four being the single-codepoint nukta forms):
    # the strict IDNA2008 path rejects them all, while UTS46
    # punycodes them as-is (ਲ਼ -> "xn--69bu", ਸ਼ -> "xn--dbci",
    # ਖ਼ -> "xn--e9b0f", ਗ਼ -> "xn--f9b8e", ਜ਼ -> "xn--k9b8d",
    # ਫ਼ -> "xn--z9b8a"), matching Node's WHATWG parser. A
    # translate table cannot express this class (there is no
    # plain-letter target), so they join the UTS46 retry here;
    # the pipeline's lower() leaves them unchanged, so the forms
    # above are what the retry sees in practice. The nukta
    # letters of the remaining Indic script (Oriya) are the
    # same class but a separate range, handled below.
    _punycode_gurmukhi = frozenset(
        [0x0A33, 0x0A36, 0x0A59, 0x0A5A, 0x0A5B, 0x0A5E]
    )
    # The same class covers the Oriya letters with nukta
    # U+0B5C/U+0B5D (ଡ଼/ଢ଼, the single-codepoint forms of base
    # letter + NUKTA U+0B3C): the strict IDNA2008 path rejects
    # them both, while UTS46 punycodes them as-is
    # (ଡ଼ -> "xn--0hc8c", ଢ଼ -> "xn--1hc6c"), matching Node's
    # WHATWG parser. A translate table cannot express this
    # class (there is no plain-letter target), so they join
    # the UTS46 retry here; the pipeline's lower() leaves
    # them unchanged, so the forms above are what the retry
    # sees in practice. A full block scan (U+0B01-U+0B7F)
    # confirmed exactly these two are strict-reject/UTS46-ok.
    # The Tibetan forms are the same class but a separate
    # range, handled below.
    _punycode_oriya = frozenset([0x0B5C, 0x0B5D])
    # The same class covers the Tibetan forms U+0F0C/U+0F43/
    # U+0F4D/U+0F52/U+0F57/U+0F5C/U+0F69 (༌/གྷ/ཌྷ/དྷ/བྷ/ཛྷ/ཀྵ):
    # the strict IDNA2008 path rejects them all, while UTS46
    # punycodes them as-is (༌ -> "xn--nbd", གྷ -> "xn--7cd8u",
    # ཌྷ -> "xn--idd8s", དྷ -> "xn--ndd8r", བྷ -> "xn--sdd8q",
    # ཛྷ -> "xn--xdd8p", ཀྵ -> "xn--5cd8u"), matching Node's
    # WHATWG parser. A translate table cannot express this
    # class (there is no plain-letter target), so they join
    # the UTS46 retry here; the pipeline's lower() leaves
    # them unchanged, so the forms above are what the retry
    # sees in practice. A full block scan (U+0F00-U+0FFF)
    # confirmed exactly these seven are strict-reject/UTS46-ok.
    _punycode_tibetan = frozenset(
        [0x0F0C, 0x0F43, 0x0F4D, 0x0F52, 0x0F57, 0x0F5C, 0x0F69]
    )
    # The same class covers the modifier letters MODIFIER LETTER
    # SMALL GAMMA U+02E0 and MODIFIER LETTER REVERSED GLOTTAL
    # STOP U+02E4 (ˠ/ˤ): the strict IDNA2008 path rejects them
    # both, while UTS46 punycodes them as-is (ˠ -> "xn--2na",
    # ˤ -> "xn--ipa"), matching Node's WHATWG parser. A
    # translate table cannot express this class (there is no
    # plain-letter target), so they join the UTS46 retry here;
    # the pipeline's lower() leaves them unchanged, so the forms
    # above are what the retry sees in practice. The neighbouring
    # U+02E1-U+02E3 members map to plain letters and are handled
    # by the translate table above, not here. SUBSCRIPT SCHWA
    # U+2094 is the same class but a separate range, handled
    # separately.
    _punycode_mod02 = frozenset([0x02E0, 0x02E4])
    # The same class covers SUBSCRIPT SCHWA U+2094 (ₔ): the
    # strict IDNA2008 path rejects it, while UTS46 punycodes it
    # as-is (ₔ -> "xn--sna"), matching Node's WHATWG parser. A
    # translate table cannot express this class (there is no
    # plain-letter target), so it joins the UTS46 retry here;
    # the pipeline's lower() leaves it unchanged, so the form
    # above is what the retry sees in practice. The neighbouring
    # U+2090-U+209C subscript letters map to plain letters and
    # are handled by the translate table above, not here.
    _punycode_subschwa = frozenset([0x2094])
    # The same class covers the Greek symbols U+03D0/U+03D1/U+03D2/
    # U+03D3/U+03D4/U+03D5/U+03D6/U+03F0/U+03F1/U+03F2/U+03F5
    # (ϐ/ϑ/ϒ/ϓ/ϔ/ϕ/ϖ/ϰ/ϱ/ϲ/ϵ): the strict IDNA2008 path
    # rejects them all, while UTS46 punycodes them as-is
    # (ϐ -> "xn--nxa", ϑ -> "xn--txa", ϒ -> "xn--6xa",
    # ϓ -> "xn--fya", ϔ -> "xn--dya", ϕ -> "xn--7xa",
    # ϖ -> "xn--1xa", ϰ -> "xn--vxa", ϱ -> "xn--2xa",
    # ϲ -> "xn--4xa", ϵ -> "xn--qxa"), matching Node's WHATWG
    # parser. A translate table cannot express this class (there
    # is no plain-letter target), so they join the UTS46 retry
    # here; the pipeline's lower() leaves them unchanged, so the
    # forms above are what the retry sees in practice. A full
    # scan of U+03D0-U+03F5 confirmed exactly these eleven are
    # strict-reject/UTS46-ok after lower(): the archaic and
    # Coptic capitals fold to smalls that pass strict directly,
    # GREEK CAPITAL THETA SYMBOL U+03F4 folds to θ, and GREEK
    # KAI SYMBOL U+03D7 passes strict directly.
    _punycode_greek = frozenset(
        [
            0x03D0, 0x03D1, 0x03D2, 0x03D3, 0x03D4, 0x03D5,
            0x03D6, 0x03F0, 0x03F1, 0x03F2, 0x03F5,
        ]
    )
    # The same class covers ARMENIAN SMALL LIGATURE ECH YIWN
    # U+0587 (և): the strict IDNA2008 path rejects it, while
    # UTS46 punycodes it as-is (և -> "xn--29a2d"), matching
    # Node's WHATWG parser. A translate table cannot express
    # this class (there is no plain-letter target; it is not
    # expanded to եւ under UTS46, unlike the U+FB13-U+FB17
    # Armenian ligatures mapped in the first table above), so
    # it joins the UTS46 retry here; the pipeline's lower()
    # leaves it unchanged, so the form above is what the retry
    # sees in practice. The Arabic, Lao and Georgian forms
    # flagged alongside it are the same class but separate
    # ranges, each with its own retry set below; the Latin
    # form joins the retry below as well.
    _punycode_armenian = frozenset([0x0587])
    # The same class covers the Arabic high-hamza letters
    # U+0675/U+0676/U+0677/U+0678 (ٵ/ٶ/ٷ/ٸ): the strict
    # IDNA2008 path rejects them all, while UTS46 punycodes
    # them as-is (ٵ -> "xn--mgb8m", ٶ -> "xn--khb2g",
    # ٷ -> "xn--tib9n", ٸ -> "xn--mhb8f"), matching Node's
    # WHATWG parser. A translate table cannot express this
    # class (there is no plain-letter target), so they join
    # the UTS46 retry here; the pipeline's lower() leaves
    # them unchanged, so the forms above are what the retry
    # sees in practice. A full scan of U+0600-U+06FF
    # confirmed exactly these four are strict-reject/UTS46-ok
    # after lower(). The Lao, Georgian and Latin forms
    # flagged alongside them are the same class but separate
    # ranges, assessed separately.
    _punycode_arabic = frozenset([0x0675, 0x0676, 0x0677, 0x0678])
    # The same class covers the Lao letters U+0EDC/U+0EDD
    # (ໜ/ໝ): the strict IDNA2008 path rejects them both,
    # while UTS46 punycodes them as-is (ໜ -> "xn--e7c9a",
    # ໝ -> "xn--m7ct"), matching Node's WHATWG parser. A
    # translate table cannot express this class (there is no
    # plain-letter target), so they join the UTS46 retry here;
    # the pipeline's lower() leaves them unchanged, so the
    # forms above are what the retry sees in practice. A full
    # scan of U+0E80-U+0EFF confirmed exactly these two are
    # strict-reject/UTS46-ok after lower(). The Georgian form
    # flagged alongside them is the same class but a separate
    # range, and joins the retry below; the Latin form
    # joins the retry below as well.
    _punycode_lao = frozenset([0x0EDC, 0x0EDD])
    # The same class covers MODIFIER LETTER GEORGIAN NAR
    # U+10FC (ჼ): the strict IDNA2008 path rejects it, while
    # UTS46 punycodes it as-is (ჼ -> "xn--xod"), matching
    # Node's WHATWG parser. A translate table cannot express
    # this class (there is no plain-letter target), so it
    # joins the UTS46 retry here; the pipeline's lower()
    # leaves it unchanged, so the form above is what the
    # retry sees in practice. A full scan of U+10A0-U+10FF
    # confirmed it is the only strict-reject/UTS46-ok member
    # of the Georgian block after lower().
    _punycode_georgian = frozenset([0x10FC])
    # The same class covers the Latin letters U+1E9A/U+1E9B
    # (ẚ/ẛ): the strict IDNA2008 path rejects them both,
    # while UTS46 punycodes them as-is (ẚ -> "xn--a-36a",
    # ẛ -> "xn--tig"), matching Node's WHATWG parser. A
    # translate table cannot express this class (there is no
    # plain-letter target), so they join the UTS46 retry here;
    # the pipeline's lower() leaves them unchanged, so the
    # forms above are what the retry sees in practice. A full
    # scan of U+1E00-U+1EFF confirmed exactly these two are
    # strict-reject/UTS46-ok after lower().
    _punycode_latin = frozenset([0x1E9A, 0x1E9B])
    # The same class covers MODIFIER LETTER CYRILLIC EN U+1D78
    # (ᵸ): the strict IDNA2008 path rejects it, while UTS46
    # punycodes it as-is (ᵸ -> "xn--m1a"), matching Node's
    # WHATWG parser. A translate table cannot express this
    # class (there is no plain-letter target), so it joins the
    # UTS46 retry here; the pipeline's lower() leaves it
    # unchanged, so the form above is what the retry sees in
    # practice. A full scan of U+1D00-U+1D7F confirmed it is
    # the only strict-reject/UTS46-ok member of the block
    # after lower() not already handled.
    _punycode_cyrillic = frozenset([0x1D78])
    # The same class covers COMBINING GREEK YPOGEGRAMMENI
    # U+0345 (ͅ): the strict IDNA2008 path rejects it, while
    # UTS46 punycodes it as-is (ͅ -> "xn--uxa"), matching
    # Node's WHATWG parser. A translate table cannot express
    # this class (there is no plain-letter target), so it joins
    # the UTS46 retry here; the pipeline's lower() leaves it
    # unchanged, so the form above is what the retry sees in
    # practice. A full scan of U+0300-U+036F confirmed it is
    # the only strict-reject/UTS46-ok member of the block
    # after lower().
    _punycode_combining = frozenset([0x0345])
    # The same class covers GREEK NUMERAL SIGN U+0374 (ʹ):
    # the strict IDNA2008 path rejects it, while UTS46
    # punycodes it as-is (ʹ -> "xn--jqa"), matching
    # Node's WHATWG parser. A translate table cannot express
    # this class (there is no plain-letter target), so it joins
    # the UTS46 retry here; the pipeline's lower() leaves it
    # unchanged, so the form above is what the retry sees in
    # practice. A full scan of U+0370-U+03CF confirmed it is
    # the only strict-reject/UTS46-ok member of the range
    # after lower().
    _punycode_greek_numeral = frozenset([0x0374])
    # The same class covers TIFINAGH MODIFIER LETTER
    # LABIALIZATION MARK U+2D6F (ⵯ): the strict IDNA2008 path
    # rejects it, while UTS46 punycodes it as-is (ⵯ ->
    # "xn--jnj"), matching Node's WHATWG parser. A translate
    # table cannot express this class (there is no
    # plain-letter target), so it joins the UTS46 retry here;
    # the pipeline's lower() leaves it unchanged, so the
    # form above is what the retry sees in practice. A full
    # scan of U+2D30-U+2D7F confirmed it is the only
    # strict-reject/UTS46-ok member of the block after lower().
    _punycode_tifinagh = frozenset([0x2D6F])
    # The same class covers the MODIFIER LETTER CYRILLIC HARD
    # SIGN U+A69C (ꚜ) and MODIFIER LETTER CYRILLIC SOFT SIGN
    # U+A69D (ꚝ): the strict IDNA2008 path rejects them, while
    # UTS46 punycodes them as-is (ꚜ -> "xn--z1a", ꚝ ->
    # "xn--11a"), matching Node's WHATWG parser. A translate
    # table cannot express this class (there is no
    # plain-letter target), so they join the UTS46 retry here;
    # the pipeline's lower() leaves them unchanged, so the
    # forms above are what the retry sees in practice. A full
    # scan of U+A600-U+A6FF confirmed they are the only
    # strict-reject/UTS46-ok members of the block after lower().
    _punycode_cyrillic_modifiers = frozenset([0xA69C, 0xA69D])
    # The same class covers the vertical kana repeat marks
    # U+3038 (〸), U+3039 (〹) and U+303A (〺): the strict
    # IDNA2008 path rejects them, while UTS46 punycodes them
    # as-is (〸 -> "xn--kkr", 〹 -> "xn--nkr", 〺 ->
    # "xn--okr"), matching Node's WHATWG parser. A translate
    # table cannot express this class (there is no
    # plain-letter target), so they join the UTS46 retry here;
    # the pipeline's lower() leaves them unchanged, so the
    # forms above are what the retry sees in practice. A full
    # scan of U+3000-U+303F confirmed they are the only
    # strict-reject/UTS46-ok members of the block after lower().
    _punycode_cjk_repeat = frozenset([0x3038, 0x3039, 0x303A])
    # U+AB5C (ꭜ), U+AB5D (ꭝ), U+AB5E (ꭞ), U+AB5F (ꭟ) and
    # U+AB69 (ꭩ), modifier letters from Ethiopic Extended-A: the
    # strict IDNA2008 path rejects them, while UTS46 punycodes
    # them as-is (ꭜ -> "xn--728a", ꭝ -> "xn--xx9a", ꭞ ->
    # "xn--boa", ꭟ -> "xn--py9a", ꭩ -> "xn--9oa"), matching
    # Node's WHATWG parser. A translate table cannot express
    # this class (there is no plain-letter target), so they
    # join the UTS46 retry here; the pipeline's lower() leaves
    # them unchanged, so the forms above are what the retry
    # sees in practice. A full scan of U+AB00-U+AB6F confirmed
    # they are the only strict-reject/UTS46-ok members of the
    # block after lower().
    _punycode_ethiopic = frozenset([0xAB5C, 0xAB5D, 0xAB5E, 0xAB5F, 0xAB69])
    # HIRAGANA DIGRAPH YORI U+309F (ゟ) and KATAKANA DIGRAPH
    # KOTO U+30FF (ヿ): the strict IDNA2008 path rejects them,
    # while UTS46 punycodes them as-is (ゟ -> "xn--lbke", ヿ ->
    # "xn--tckzb"), matching Node's WHATWG parser. A translate
    # table cannot express this class (there is no plain-letter
    # target), so they join the UTS46 retry here; the pipeline's
    # lower() leaves them unchanged, so the forms above are what
    # the retry sees in practice. A full scan of U+3000-U+30FF
    # confirmed they are the only strict-reject/UTS46-ok members
    # of the block after lower().
    _punycode_japanese_digraphs = frozenset([0x309F, 0x30FF])
    # MODIFIER LETTER US U+A770 (ꝰ), MODIFIER LETTER CAPITAL H
    # WITH STROKE U+A7F8 (ꟸ) and MODIFIER LETTER SMALL LIGATURE
    # OE U+A7F9 (ꟹ): the strict IDNA2008 path rejects them,
    # while UTS46 punycodes them as-is (ꝰ -> "xn--948a", ꟸ ->
    # "xn--1ea", ꟹ -> "xn--bga"), matching Node's WHATWG parser.
    # A translate table cannot express this class (there is no
    # plain-letter target), so they join the UTS46 retry here; the
    # pipeline's lower() leaves them unchanged, so the forms above
    # are what the retry sees in practice. A full scan of
    # U+A700-U+A7FF confirmed they are the only strict-reject/
    # UTS46-ok members of the block after lower() not already
    # handled by a translate table (U+A7F2-U+A7F4 map to plain
    # letters and need no retry entry).
    _punycode_latin_modifiers = frozenset([0xA770, 0xA7F8, 0xA7F9])
    # The same class covers the Phonetic Extensions Supplement
    # modifier letters U+1D9B-U+1DBF (ᶛ-ᶿ): the strict IDNA2008
    # path rejects them all, while UTS46 handles them (ᶛ ->
    # "xn--a-w0a" as-is, and ᶜ/ᶠ/ᶻ map to plain "c"/"f"/"z"
    # first, e.g. ᶜ -> "ca"), matching Node's WHATWG parser. A
    # translate table cannot express the as-is members (there is
    # no plain-letter target), so the whole range joins the UTS46
    # retry here — the retry's uts46=True encoding reproduces
    # both the mapped and the as-is forms. The pipeline's lower()
    # leaves them unchanged, so the forms above are what the retry
    # sees in practice. A full scan of U+1D00-U+1DFF confirmed
    # this range is the block's only remaining strict-reject/
    # UTS46-ok run after lower() not already handled (the
    # U+1D00-U+1D7F modifiers map via translate tables above,
    # and U+1D78 already has its own retry entry).
    _punycode_phonetic_supplement = frozenset(range(0x1D9B, 0x1DC0))
    # The same class covers the ideographic annotation marks
    # U+3192-U+319F (㆒-㆟): the strict IDNA2008 path rejects
    # them all, while UTS46 punycodes them as-is (㆒ ->
    # "xn--4gq", ㆟ -> "xn--gmq"), matching Node's WHATWG
    # parser. A translate table cannot express this class
    # (there is no plain-letter target), so they join the UTS46
    # retry here; the pipeline's lower() leaves them unchanged,
    # so the forms above are what the retry sees in practice.
    # A full scan of U+3190-U+319F confirmed exactly these
    # fourteen are strict-reject/UTS46-ok after lower()
    # (U+3190/U+3191 fail under both strict and UTS46 and are
    # deliberately left alone).
    # U+FF66-U+FF9D (ｦ-ﾝ): the strict IDNA2008 path rejects
    # them all, while UTS46 maps them to their fullwidth katakana
    # forms (ｦ -> ヲ, ｱ -> ア, ﾝ -> ン) and punycodes the result
    # (ｱ -> "xn--cck", ﾝ -> "xn--nek"), matching Node's WHATWG
    # parser. A translate table could express the mapping, but the
    # retry's uts46=True encoding reproduces it directly, as it
    # already does for the mapped members of the phonetic
    # supplement range; the pipeline's lower() leaves them
    # unchanged, so the forms above are what the retry sees in
    # practice. A full scan of U+FF66-U+FF9D confirmed exactly
    # these fifty-six are strict-reject/UTS46-ok after lower()
    # (the halfwidth voiced/semi-voiced marks U+FF9E/U+FF9F
    # combine with a preceding kana rather than standing alone,
    # so they are a separate case and are left alone here).
    _punycode_kanbun = frozenset(range(0x3192, 0x31A0))
    _punycode_halfwidth_katakana = frozenset(range(0xFF66, 0xFF9E))
    if any(
        ord(c) in _punycode_modifiers or ord(c) in _punycode_letterlike
        or ord(c) in _punycode_digraphs or ord(c) in _punycode_cherokee
        or ord(c) in _punycode_devanagari or ord(c) in _punycode_bengali
        or ord(c) in _punycode_gurmukhi or ord(c) in _punycode_oriya
        or ord(c) in _punycode_tibetan or ord(c) in _punycode_mod02
        or ord(c) in _punycode_subschwa or ord(c) in _punycode_greek
        or ord(c) in _punycode_armenian or ord(c) in _punycode_arabic
        or ord(c) in _punycode_lao or ord(c) in _punycode_georgian
        or ord(c) in _punycode_latin or ord(c) in _punycode_cyrillic
        or ord(c) in _punycode_combining
        or ord(c) in _punycode_greek_numeral
        or ord(c) in _punycode_tifinagh
        or ord(c) in _punycode_cyrillic_modifiers
        or ord(c) in _punycode_cjk_repeat
        or ord(c) in _punycode_ethiopic
        or ord(c) in _punycode_japanese_digraphs
        or ord(c) in _punycode_latin_modifiers
        or ord(c) in _punycode_phonetic_supplement
        or ord(c) in _punycode_kanbun
        or ord(c) in _punycode_halfwidth_katakana
        for c in host
    ):
        try:
            return _idna.encode(host, uts46=True).decode("ascii")
        except (UnicodeError, ValueError):
            pass
    # Fallback for underscore labels: the `idna` package follows
    # IDNA2008, where "_" is disallowed, but browsers serialize Origin
    # hosts per WHATWG URL (UTS46 without STD3 rules), which keeps "_"
    # and punycodes only the non-ASCII part — so "mün_chen.example"
    # becomes "xn--mn_chen-n2a.example" in the browser while the whole
    # host above fails and the entry never matches. Retry per label:
    # labels without "_" are re-encoded with the package (a label that
    # fails for another reason still returns None, as before), ASCII
    # underscore labels pass through unchanged (as browsers send
    # them), and non-ASCII underscore labels get the "xn--" + punycode
    # form, which preserves both "_" and characters like ß (unlike the
    # stdlib codec's ß -> "ss" mapping). Empty labels (a trailing dot)
    # pass through unchanged. Labels with a punycode-as-is
    # letterlike symbol are handled first, before the "_" branches:
    # the browser punycodes these symbols as-is (℄ -> "xn--31g",
    # ℈ -> "xn--71g") while the package's UTS46 processing
    # rejects them, so neither the strict path nor the retry above
    # reproduces them. Four of them map first per WHATWG (℃ ->
    # "°c", ℉ -> "°f", ⅀ -> "∑", and Ⅎ -> "ⅎ", which the
    # pipeline's lower() already folds before this helper runs, so
    # it matters only for direct calls, as with the circled and
    # Roman capital ranges); the rest punycode as-is. The branch
    # only runs when a listed codepoint is present, so every other
    # label keeps the existing behaviour, and a label mixing a
    # listed symbol with "_" still punycodes with "_" preserved,
    # as the browser does ("a_℃" -> "xn--a_c-tfa").
    _punycode_asis = frozenset(
        [
            0x2103, 0x2104, 0x2108, 0x2109, 0x2114, 0x2117,
            0x2118, 0x211E, 0x211F, 0x2123, 0x2125, 0x2127,
            0x2129, 0x212E, 0x2132, 0x213A, 0x2140, 0x2141,
            0x2142, 0x2143, 0x2144, 0x214A, 0x214B, 0x214C,
            0x214D, 0x214F,
        ]
    )
    _asis_map = {
        0x2103: "°c", 0x2109: "°f", 0x2132: "ⅎ", 0x2140: "∑",
    }
    try:
        encoded_labels = []
        for label in host.split("."):
            if not label:
                encoded_labels.append(label)
            elif any(ord(c) in _punycode_asis for c in label):
                encoded_labels.append(
                    "xn--"
                    + label.translate(_asis_map)
                    .encode("punycode")
                    .decode("ascii")
                )
            elif "_" not in label:
                encoded_labels.append(_idna.encode(label).decode("ascii"))
            elif any(ord(c) > 127 for c in label):
                encoded_labels.append(
                    "xn--" + label.encode("punycode").decode("ascii")
                )
            else:
                encoded_labels.append(label)
        return ".".join(encoded_labels)
    except (UnicodeError, ValueError):
        return None


# Browser Origin headers never carry a path or trailing slash, and
# Starlette matches allow_origins exactly, so a configured origin like
# "https://app.example.com/" would silently never match and the
# frontend's calls would fail with CORS errors. Normalize trailing
# slashes away (same class of fix as the frontend base-URL trim).
# Scheme and host are case-insensitive, and browsers send them
# lowercased, so also lowercase each entry: an uppercase typo like
# "HTTPS://App.Example.com" would otherwise silently never match.
# Browsers also omit the default port from the Origin header, so a
# configured "https://app.example.com:443" (or http :80) would
# likewise silently never match under exact matching; strip those
# default ports. Non-default ports (e.g. :3000, :8443) are kept.
# Finally, an Origin header never carries a path, so a configured
# "https://app.example.com/spa" would likewise never match; strip any
# path after scheme://host[:port] (the default-port strip below then
# still applies to e.g. "https://app.example.com:443/spa").
# Likewise a scheme-less entry like "app.example.com" would never
# match a browser Origin, which always carries a scheme; assume https
# (the production default) so the rest of the pipeline applies to it.
def _normalize_cors_origin(origin: str) -> str:
    o = origin.strip().rstrip("/").lower()
    # The WHATWG URL parser removes ASCII tab, LF and CR from anywhere
    # in the input before parsing, so a browser serializes an Origin
    # from "https://app.ex<TAB>ample.com" as "https://app.example.com"
    # (and "https://app.example.com:44<TAB>3" as port 443, which the
    # default-port strip below then drops). strip() above only handles
    # the ends, so a stray tab/newline pasted into the middle of a
    # configured origin would otherwise survive every branch below
    # and never match. Remove them up front; a space is not removed
    # by the URL parser (it fails host parsing instead), so spaces
    # are deliberately left alone.
    o = o.replace("\t", "").replace("\n", "").replace("\r", "")
    # The WHATWG URL parser also removes leading and trailing C0
    # controls (U+0000-U+001F) and spaces before parsing, so a browser
    # serializes an Origin from "\x01https://app.example.com" or
    # "https://app.example.com\x00" as "https://app.example.com".
    # Python's strip() above only removes whitespace, leaving controls
    # like \x00-\x08 and \x0e-\x1f in place, so such an entry would
    # never match. Strip them (and spaces) at the ends here; an
    # interior space is deliberately still left alone, since the URL
    # parser fails host parsing on it instead of removing it.
    o = o.strip("".join(chr(c) for c in range(0x20)) + " ")
    if not o:
        return ""
    # Leave "*" untouched: the wildcard filter below drops it with a
    # warning, and prepending a scheme here would turn it into a dead
    # "https://*" entry that escapes that filter.
    if o == "*":
        return "*"
    # The WHATWG URL parser treats "/" and "\" alike as separators
    # after a special scheme and tolerates any number of them, so a
    # browser serializes an Origin from "https:/app.example.com",
    # "https:\\app.example.com" (a slash dropped, or a Windows-style
    # separator pasted in) or even "https:///app.example.com" as
    # "https://app.example.com" — but the scheme-less branch below saw
    # no "://" and rebuilt the first two as a dead "https://https"
    # (and path-stripped the third to a dead "https://"), so none of
    # them ever matched. Collapse the run of "/" and "\" after a
    # leading http: or https: to "://" before that branch; an
    # already-correct "://" is unchanged by this (its two separators
    # are simply rewritten as themselves), scheme-less hosts have no
    # such prefix and are untouched, and a bare "https:host" with no
    # separator at all is left alone — it is ambiguous with a
    # host:port pair in the scheme-less branch.
    for _scheme in ("https:", "http:"):
        if o.startswith(_scheme):
            _after = o[len(_scheme) :]
            _seps = 0
            while _seps < len(_after) and _after[_seps] in "/\\":
                _seps += 1
            if _seps:
                o = _scheme + "//" + _after[_seps:]
            break
    # A bare "https:host" with no separator at all is likewise what
    # the WHATWG URL parser serializes as "https://host" (a special
    # scheme needs no slashes), but the scheme-less branch below saw
    # no "://" and rebuilt it as a dead "https://https:host", so it
    # never matched. Rewrite it to "https://host" here — but only
    # when the authority that follows the colon cannot be a port:
    # a purely numeric authority ("https:443") is ambiguous with a
    # host:port pair (host "https", port 443) in that branch, so it
    # is deliberately left alone, as before. Any other authority
    # (a dotted host, localhost, a host:port pair) cannot be a port,
    # so the scheme reading is unambiguous; an authority starting
    # with "?" or "#" is likewise left alone.
    for _scheme in ("https:", "http:"):
        if o.startswith(_scheme):
            _after = o[len(_scheme) :]
            if _after and _after[0] not in "/\\?#":
                _auth = _after
                for _sep in ("/", "\\", "?", "#"):
                    _auth = _auth.split(_sep, 1)[0]
                if _auth and not _auth.isdigit():
                    o = _scheme + "//" + _after
            break
    # A browser Origin always carries a scheme, so a scheme-less entry
    # like "app.example.com" (or protocol-relative "//app.example.com")
    # would likewise never match; assume https, the production default,
    # except for loopback hosts, which in development are served over
    # plain http — a scheme-less "localhost:3000" previously became
    # https://localhost:3000 and never matched the dev Origin.
    if o.startswith("//"):
        bare = o[2:]
    elif "://" not in o:
        bare = o
    else:
        bare = None
    if bare is not None:
        host_part = bare.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        host_part = host_part.rsplit("@", 1)[-1]
        # Bracketed IPv6 loopback: a naive rsplit(":", 1) mangles "[::1]"
        # (no port) into "[:" and never matches, so extract up to "]".
        # An unbracketed "::1" is likewise loopback, but browsers send it
        # bracketed, so it is re-bracketed below when it leads the entry.
        if host_part.startswith("["):
            host = host_part.split("]", 1)[0] + "]" if "]" in host_part else host_part
        elif host_part == "::1":
            host = "::1"
        else:
            host = host_part.rsplit(":", 1)[0]
        if bare.startswith("::1"):
            bare = "[::1]" + bare[3:]
            host = "[::1]"
        # A portless unbracketed expanded IPv6 host ("0:0:0:0:0:0:0:1")
        # is unambiguous — a port would add a ninth group, so such a
        # string cannot parse as an address — but without brackets it
        # never matches the bracketed Origin browsers send, and the
        # compression step below only handles bracketed hosts.
        # Re-bracket it here so the loopback check below and the
        # compression step both apply (expanded loopback becomes
        # http://[::1], any other expanded host becomes its
        # compressed bracketed form). Forms with a port, or
        # compressed forms like "::1" (handled above), are left alone
        # because they cannot be told apart from host:port safely.
        host_only = bare.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if host_only.count(":") == 7:
            try:
                ipaddress.IPv6Address(host_only)
            except ValueError:
                pass
            else:
                bare = "[" + host_only + "]" + bare[len(host_only) :]
                host = "[" + host_only + "]"
        # The same re-bracketing applies to an expanded IPv6 host
        # with a port ("0:0:0:0:0:0:0:1:3000"): nine colon-separated
        # segments cannot be a bare address (an address has at most
        # eight groups), so the only reading is address + port, and
        # without brackets it never matches the bracketed Origin
        # browsers send. Compressed forms with a port (e.g. "::1:3000")
        # stay ambiguous — they could also be an address — and are
        # left alone, as before; a non-digit or unparseable tail is
        # likewise left alone.
        if host_only.count(":") == 8 and "%" not in host_only:
            _segs = host_only.split(":")
            try:
                ipaddress.IPv6Address(":".join(_segs[:8]))
            except ValueError:
                pass
            else:
                if _segs[8].isdigit():
                    bare = (
                        "[" + ":".join(_segs[:8]) + "]:" + _segs[8]
                        + bare[len(host_only) :]
                    )
                    host = "[" + ":".join(_segs[:8]) + "]"
        # A trailing dot must not hide a loopback host from the http
        # assumption above (e.g. "localhost.:3000"); the dot itself is
        # stripped from the rebuilt origin by the scheme branch below.
        if host.endswith("."):
            host = host.rstrip(".") or host
        # A zero-padded IPv4 host must be classified by its canonical
        # form: ipaddress rejects leading zeros, so without this a
        # scheme-less "192.168.001.010:3000" would miss the private
        # check below and assume https. (The rebuilt origin itself is
        # canonicalized by the scheme branch below; this only fixes
        # the classification, which reads host, not bare.)
        canonical_v4 = _canonical_ipv4(host)
        if canonical_v4 is not None:
            host = canonical_v4
        # The same http assumption applies to private and link-local
        # IPv4 hosts (RFC 1918, CGNAT, link-local, unspecified): a
        # scheme-less "192.168.1.10:3000" — a dev frontend reached
        # over the LAN, e.g. from a phone — previously became
        # https://192.168.1.10:3000 and never matched the plain-http
        # Origin the browser sends, just as scheme-less loopback did
        # before. Public IPv4 hosts still assume https; explicit
        # schemes are untouched, so https://192.168.1.10 still means
        # https. is_global is False for every non-routable address,
        # so one check covers private, link-local, loopback and
        # unspecified hosts alike.
        is_private_v4 = False
        if "." in host and not host.startswith("["):
            try:
                is_private_v4 = not ipaddress.IPv4Address(host).is_global
            except ValueError:
                is_private_v4 = False
        # The whole 127.0.0.0/8 range is loopback (127.0.0.2, 127.0.1.1,
        # ...), not just 127.0.0.1, so a scheme-less entry for any of
        # them would otherwise assume https and never match the
        # plain-http Origin a dev frontend sends. Likewise an expanded
        # bracketed loopback ("[0:0:0:0:0:0:0:1]:3000") is not the
        # literal "[::1]" string, so without this check it assumed
        # https and never matched the dev http Origin even though the
        # later compression step rewrites it to "[::1]"; parse it to
        # test loopback instead of comparing strings.
        is_loopback_v6 = False
        if host.startswith("[") and host.endswith("]"):
            try:
                is_loopback_v6 = ipaddress.IPv6Address(host[1:-1]).is_loopback
            except ValueError:
                is_loopback_v6 = False
        # The same http assumption applies to non-globally-routable
        # IPv6 hosts (ULA fc00::/7, link-local fe80::/10, and the
        # loopback/unspecified forms already covered above): a
        # scheme-less "[fd00::1]:3000" — a dev frontend reached over
        # the LAN over IPv6, e.g. from a phone — previously became
        # https://[fd00::1]:3000 and never matched the plain-http
        # Origin the browser sends, just as scheme-less private IPv4
        # did before iteration 509. Public IPv6 hosts still assume
        # https; explicit schemes are untouched, and unparseable
        # (e.g. zone-id) hosts fall back to https as before.
        is_private_v6 = False
        if host.startswith("[") and host.endswith("]"):
            try:
                is_private_v6 = not ipaddress.IPv6Address(host[1:-1]).is_global
            except ValueError:
                is_private_v6 = False
        scheme = (
            "http"
            if host in ("localhost", "[::1]")
            or is_loopback_v6
            or is_private_v4
            or is_private_v6
            or host.startswith("127.")
            else "https"
        )
        o = scheme + "://" + bare if not o.startswith("//") else scheme + ":" + o
    scheme_end = o.find("://")
    if scheme_end != -1:
        # WHATWG treats a backslash as a slash in special-scheme URLs,
        # so a configured "https://app.example.com\docs" (pasted from
        # a Windows path, say) is serialized by browsers as the bare
        # Origin "https://app.example.com" — but the slash-only strip
        # above left "\docs" on the host, so it never matched. Cut
        # the host part at the first "/" or "\" alike; the query,
        # fragment and userinfo strips below still apply to what
        # remains, and a backslash cannot legitimately occur in a
        # host (bracketed IPv6 hosts included).
        path_starts = [
            i
            for i in (
                o.find("/", scheme_end + 3),
                o.find("\\", scheme_end + 3),
            )
            if i != -1
        ]
        if path_starts:
            o = o[: min(path_starts)]
        # Browsers send Origin as scheme://host[:port] only, never with a
        # query or fragment, so strip those too (before the default-port
        # strip below, so "https://app.example.com:443?ref=docs" still
        # normalizes to "https://app.example.com").
        for sep in ("?", "#"):
            sep_pos = o.find(sep, scheme_end + 3)
            if sep_pos != -1:
                o = o[:sep_pos]
        # Browsers send Origin as scheme://host[:port] only, never with
        # userinfo, so a configured "https://user@app.example.com"
        # would likewise never match; strip everything up to the last
        # "@" in the host part (before the default-port strip below,
        # so "https://user@app.example.com:443" still normalizes to
        # "https://app.example.com").
        at_pos = o.rfind("@", scheme_end + 3)
        if at_pos != -1:
            o = o[: scheme_end + 3] + o[at_pos + 1 :]
        # WHATWG domain parsing percent-decodes a host before IDNA, so
        # a browser serializes an Origin from
        # "https://app.example%2ecom" as "https://app.example.com" —
        # but the configured entry kept "%2e" and never matched under
        # exact matching. The same holds for any other percent-encoded
        # host-safe ASCII character (e.g. "%61" -> "a", "%31" -> "1",
        # "%2d" -> "-", "%5f" -> "_", all confirmed against Node's
        # WHATWG URL serializer), so decode every "%XX" whose byte is
        # a letter, digit, hyphen, underscore or dot in the host
        # here, before the trailing-dot / port / IDN steps below
        # (which then apply to the decoded form, e.g. a decoded
        # trailing dot is stripped and a decoded IPv4 canonicalizes).
        # o was lowercased at the top, so "%2E" already reads "%2e".
        # Only the host is decoded, and only when it holds at most one
        # colon (a port separator): unbracketed IPv6 hosts and
        # bracketed hosts (where "%" marks a zone id) are left alone,
        # and other percent-encodings are deliberately untouched —
        # "%2f", "%3a" and "%25" in a host are invalid URLs for
        # browsers (Node rejects them), not hosts that ever need to
        # match. The same WHATWG percent-decoding also applies to
        # UTF-8 bytes of a non-ASCII host, so a configured
        # "https://m%c3%bcnchen.example" is serialized by browsers
        # as the punycode Origin "https://xn--mnchen-3ya.example" —
        # but with only the ASCII decode above it kept "%c3%bc" and
        # never reached the IDN step below, so it never matched.
        # Decode runs of %XX that form valid UTF-8 with at least one
        # non-ASCII character here, so the IDN step then punycodes
        # them; invalid UTF-8, ASCII-only runs, and runs decoding to
        # a host separator are left alone, as above.
        _rest_pre = o[scheme_end + 3 :]
        if not _rest_pre.startswith("[") and _rest_pre.count(":") <= 1:
            _host_seg, _sep, _port_seg = _rest_pre.partition(":")

            def _decode_safe_hex(_m: re.Match[str]) -> str:
                _ch = chr(int(_m.group(1), 16))
                return _ch if _ch.isascii() and (_ch.isalnum() or _ch in "-_.") else _m.group(0)

            def _decode_utf8_run(_m: re.Match[str]) -> str:
                _raw = _m.group(0)
                try:
                    _decoded = bytes.fromhex(_raw.replace("%", "")).decode("utf-8")
                except (ValueError, UnicodeDecodeError):
                    return _raw
                if not any(ord(c) > 127 for c in _decoded):
                    return _raw
                if any(ord(c) < 0x20 or c in "/\\?#@:" for c in _decoded):
                    return _raw
                return _decoded

            _decoded_seg = re.sub(r"%([0-9a-f]{2})", _decode_safe_hex, _host_seg)
            _decoded_seg = re.sub(r"(?:%[0-9a-f]{2})+", _decode_utf8_run, _decoded_seg)
            # The lower() at the top of this helper ran before
            # decoding, so a decoded character can reintroduce
            # uppercase that browsers never send: "%41" decodes to
            # "A" (not "a") and "%c3%84" to "Ä" (not "ä"), and the
            # `idna` package rejects uppercase outright, so the IDN
            # step below returned None and such an entry never
            # matched. Browsers serialize hosts lowercased, so
            # lowercase the decoded segment here; the port segment
            # is untouched, and a segment with no decoding is
            # already lowercase from the top.
            _decoded_seg = _decoded_seg.lower()
            if _decoded_seg != _host_seg:
                o = o[: scheme_end + 3] + _decoded_seg
                if _sep:
                    o += _sep + _port_seg
        # A trailing dot is a valid DNS root label, so a configured
        # "https://app.example.com." names the same host — but browsers
        # send Origin without it, so it would never match. Strip
        # trailing dots from the host (before the default-port strip
        # below, so "https://app.example.com.:443" still normalizes to
        # "https://app.example.com"); a single-dot strip left a second
        # dot behind for "app.example.com..", which still never
        # matched. Bracketed IPv6 hosts never carry a trailing dot
        # and are left alone; a host of only dots is left alone
        # rather than being emptied.
        rest = o[scheme_end + 3 :]
        # An explicitly-schemed unbracketed IPv6 host (e.g.
        # "https://2001:db8::1") likewise never matches: browsers send
        # IPv6 Origins bracketed, and the port branch below would
        # mangle it by splitting on the last colon. Re-bracket it here
        # so the compression step below applies — but only when the
        # whole host parses as an address while the prefix before the
        # last colon does not; otherwise (e.g. "::1:3000") it cannot
        # be told apart from host:port safely, and it is left alone,
        # as with the scheme-less compressed forms. Zone-id hosts are
        # left alone, as in the compression step below.
        if ":" in rest and not rest.startswith("[") and "%" not in rest:
            try:
                ipaddress.IPv6Address(rest)
            except ValueError:
                pass
            else:
                try:
                    ipaddress.IPv6Address(rest.rsplit(":", 1)[0])
                except ValueError:
                    o = o[: scheme_end + 3] + "[" + rest + "]"
                    rest = o[scheme_end + 3 :]
        # An expanded IPv6 host with a port ("0:0:0:0:0:0:0:1:3000")
        # likewise never matches: nine colon-separated segments
        # cannot be a bare address, so the only reading is address +
        # port, and the whole-host parse above fails on it. Re-bracket
        # it here so the compression step below applies (and, for a
        # scheme-less entry rebuilt above, this branch is reached with
        # the scheme-less re-bracketing already applied, so it is a
        # no-op there). Compressed forms with a port stay ambiguous
        # and are left alone, as above.
        if (
            ":" in rest
            and not rest.startswith("[")
            and "%" not in rest
            and rest.count(":") == 8
        ):
            _segs = rest.split(":")
            try:
                ipaddress.IPv6Address(":".join(_segs[:8]))
            except ValueError:
                pass
            else:
                if _segs[8].isdigit():
                    o = (
                        o[: scheme_end + 3]
                        + "[" + ":".join(_segs[:8]) + "]:" + _segs[8]
                    )
                    rest = o[scheme_end + 3 :]
        # Browsers send IPv6 Origin hosts in compressed lowercase form
        # (WHATWG URL serialization), so an expanded configured host
        # like "[0:0:0:0:0:0:0:1]" or an uncompressed
        # "[2001:0db8:0000:0000:0000:ff00:0042:8329]" would never
        # match even though it names the
        # same host as "[::1]" / "[2001:db8::ff00:42:8329]". Compress
        # bracketed hosts here, before the port branches below, so
        # portless bracketed origins benefit too; zone-id hosts and
        # unparseable hosts are left alone.
        if rest.startswith("[") and "]" in rest:
            inner = rest[1 : rest.find("]")]
            if "%" not in inner:
                try:
                    canonical = ipaddress.IPv6Address(inner).compressed
                except ValueError:
                    canonical = None
                if canonical is not None and canonical != inner:
                    o = (
                        o[: scheme_end + 3]
                        + "["
                        + canonical
                        + "]"
                        + rest[rest.find("]") + 1 :]
                    )
                    rest = o[scheme_end + 3 :]
        # Browsers send Origin hosts in ASCII form (WHATWG URL
        # serialization), so a configured Unicode host like
        # "https://münchen.example" would never match: the browser
        # sends "https://xn--mnchen-3ya.example". Encode non-ASCII
        # hosts to punycode (IDNA) here, before the port branches
        # below (which still strip trailing dots / default ports);
        # bracketed IPv6 hosts are ASCII by construction and are
        # left alone, as are hosts that fail IDNA encoding.
        if not rest.startswith("["):
            idn_host, idn_port = (
                rest.rsplit(":", 1) if ":" in rest else (rest, None)
            )
            if any(ord(c) > 127 for c in idn_host):
                # UTS46 via _encode_idna (see its comment): the stdlib
                # IDNA2003 codec alone would map ß to "ss", which
                # browsers never send.
                idn_encoded = _encode_idna(idn_host)
                if idn_encoded is not None and idn_encoded != idn_host:
                    o = o[: scheme_end + 3] + idn_encoded
                    if idn_port is not None:
                        o += ":" + idn_port
                    rest = o[scheme_end + 3 :]
        if (
            rest.startswith("[")
            and "]" in rest
            and rest[rest.find("]") + 1 :].startswith(":")
        ):
            # Bracketed IPv6 hosts skip the port branch below, so a
            # zero-padded port (e.g. "https://[::1]:0443") or an empty
            # port ("https://[::1]:") likewise never matched: browsers
            # send the canonical port (or none). Apply the same port
            # normalization as the non-bracketed branch — strip port
            # dots, drop leading zeros from digit ports, drop an empty
            # port; a port of only dots is left alone, as there.
            close = rest.find("]")
            host = rest[: close + 1]
            port = rest[close + 1 :][1:]
            stripped_port = port.rstrip(".")
            if stripped_port.isdigit():
                stripped_port = stripped_port.lstrip("0") or "0"
            if stripped_port:
                o = o[: scheme_end + 3] + host + ":" + stripped_port
            elif port == "":
                o = o[: scheme_end + 3] + host
        elif not rest.startswith("[") and ":" in rest:
            host, port = rest.rsplit(":", 1)
            stripped = host.rstrip(".")
            # A trailing dot can also sit after the port (e.g.
            # "app.example.com:443.", copied with sentence
            # punctuation): the host strip above leaves it, and the
            # default-port strip below then misses ":443." entirely,
            # so the origin still never matches. Strip dots from the
            # port too (a port never legitimately contains one); a
            # port of only dots is left alone rather than emptied.
            stripped_port = port.rstrip(".")
            # A zero-padded port (e.g. "https://app.example.com:0443",
            # copied from a padded config) likewise never matches:
            # browsers send the canonical port, so ":0443" is not
            # ":443" under exact matching. Normalize digit ports by
            # dropping leading zeros (a port of only zeros becomes
            # "0"); the default-port strip below then still applies
            # to ":0443" for https. Non-digit ports are left alone.
            if stripped_port.isdigit():
                stripped_port = stripped_port.lstrip("0") or "0"
            if stripped and stripped_port:
                o = o[: scheme_end + 3] + stripped + ":" + stripped_port
            elif stripped and port == "":
                # A trailing colon with no port (e.g.
                # "https://app.example.com:", or with a path already
                # stripped above) likewise never matches: browsers
                # send Origin without the colon. Drop it; a port of
                # only dots is left alone by the branch above.
                o = o[: scheme_end + 3] + stripped
        elif rest.endswith("."):
            stripped = rest.rstrip(".")
            if stripped:
                o = o[: scheme_end + 3] + stripped
        # A zero-padded IPv4 host ("https://192.168.001.010", or a
        # scheme-less entry rebuilt above) never matches the canonical
        # Origin browsers send, just as a zero-padded port did before
        # iteration 502. Canonicalize the host here, after the port
        # and dot branches above (which rebuild o without updating
        # rest), so padded hosts with ports, trailing dots, or a
        # default port all normalize; the default-port strip below
        # then still applies to e.g. "https://192.168.001.010:0443".
        # Bracketed IPv6 hosts and hostnames are left alone.
        rest_now = o[scheme_end + 3 :]
        if not rest_now.startswith("[") and rest_now:
            if ":" in rest_now:
                host_now, port_now = rest_now.rsplit(":", 1)
            else:
                host_now, port_now = rest_now, None
            canonical_now = _canonical_ipv4(host_now)
            if canonical_now is not None and canonical_now != host_now:
                o = o[: scheme_end + 3] + canonical_now
                if port_now is not None:
                    o += ":" + port_now
    if o.startswith("https://") and o.endswith(":443"):
        return o[:-4]
    if o.startswith("http://") and o.endswith(":80"):
        return o[:-3]
    return o
_cors_origins = [o for o in (_normalize_cors_origin(o) for o in settings.cors_allow_origins.split(",")) if o]
# A "*" entry would defeat the exact-origins promise above: with
# allow_credentials=True, a wildcard origin is reflected back to the
# requester, so any site could make credentialed (cookie) calls; and
# a literal "*" is in any case ignored by browsers for credentialed
# requests. Drop it with a warning instead of opening up cookie auth;
# exact origins are unaffected, and if "*" was the only entry CORS
# simply stays disabled (the guard below).
if "*" in _cors_origins:
    logger.warning("CORS_ALLOW_ORIGINS contains '*', which is not allowed with credentialed cookie auth; ignoring the wildcard entry.")
    _cors_origins = [o for o in _cors_origins if o != "*"]
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=True,
        # Only the methods the API actually exposes and the generated
        # client actually uses (GET/POST/PUT/PATCH/DELETE, verified
        # against both the router decorators and the client services):
        # with allow_credentials=True, "*" would preflight-approve any
        # method (e.g. TRACE) from a configured origin. OPTIONS
        # preflights are handled by CORSMiddleware itself and need no
        # entry here.
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Tenant-ID"],
    )
    logger.info(f"CORS enabled for origins: {_cors_origins}")

# Security headers are added last so they run outermost (Starlette runs
# last-added first) and cover every response: API, error, cached, and
# SPA-shell alike, including when CORS is disabled. The middleware is
# pure ASGI, so it does not buffer streaming responses (ai-chat SSE).
app.add_middleware(SecurityHeadersMiddleware)


# Mount static files only if they exist (for production Docker deployment)
if os.path.exists(build_path) and os.path.exists(os.path.join(build_path, "assets")):
    app.mount("/assets", StaticFiles(directory=os.path.join(build_path, "assets")), name="assets")
    logger.info("Static files mounted successfully")
else:
    logger.warning(f"Static files directory not found - running in {settings.fastapi_env} mode")




router = APIRouter(prefix="/api/v1")


router.include_router(health_router)

if is_tenancy_enabled():
    router.include_router(tenant_router)
    router.include_router(features_router)
    router.include_router(branding_router)



router.include_router(app_configuration_router)
router.include_router(account_router)
router.include_router(manage_security_router)
router.include_router(dashboard_router)

router.include_router(user_router)
router.include_router(role_router)
router.include_router(permissions_router)
router.include_router(storage_router)
router.include_router(ai_router)
router.include_router(product_router)
router.include_router(prices_router)
router.include_router(billing_router)
router.include_router(stripe_router)
router.include_router(stripe_webhook_router)
router.include_router(invoice_router)
router.include_router(checkout_router)
router.include_router(notification_router)
router.include_router(audit_logs_router)
router.include_router(sso_router)


app.include_router(router)



# Catch-all route for React Router (only in production with static files)
@app.get("/{full_path:path}", include_in_schema=False)
async def react_router(full_path: str):
    # API paths must never serve the SPA shell: a web/mobile client
    # calling a mistyped or removed /api/v1 route previously got a 200
    # index.html (or a 200 "not found" message below), so the client
    # could not tell the route did not exist and failed opaquely on
    # the HTML body. Unmatched API paths are a 404 JSON instead, in
    # the same {"detail": ...} shape FastAPI returns for unknown routes.
    # SPA routes are unaffected: only the api/ prefix is intercepted.
    if full_path == "api" or full_path.startswith("api/"):
        return JSONResponse(
            status_code=404, content={"detail": "API route not found"}
        )
    if os.path.exists(os.path.join(build_path, "index.html")):
        # Never cache the SPA shell: asset filenames are content-hashed
        # per build, so a cached index.html from before a deploy can
        # reference asset files the new build no longer ships, leaving
        # the client broken until its cache expires. The hashed assets
        # themselves are cacheable; only the shell must stay fresh.
        return FileResponse(
            os.path.join(build_path, "index.html"),
            headers={"Cache-Control": "no-store"},
        )
    else:
        # No UI build exists, so there is no SPA shell to serve: return
        # a 404 JSON (same {"detail": ...} shape as the API guard
        # above) instead of a 200 body claiming an endpoint was not
        # found, which a client could mistake for a successful
        # response. API paths never reach here (intercepted above),
        # so this branch only serves SPA routes with no build.
        return JSONResponse(
            status_code=404, content={"detail": "UI build not found"}
        )

