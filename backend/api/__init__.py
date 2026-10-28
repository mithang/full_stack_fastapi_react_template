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
    # Browsers strip the invisible codepoints SOFT HYPHEN U+00AD,
    # ZERO WIDTH SPACE U+200B, WORD JOINER U+2060, FUNCTION
    # APPLICATION U+2061, INVISIBLE TIMES U+2062, INVISIBLE
    # SEPARATOR U+2063, INVISIBLE PLUS U+2064, and the deprecated
    # format characters U+206A-U+206F from a host before IDNA
    # processing (WHATWG URL serialization drops them: "a\u200bb"
    # -> "ab", "mün\u200bchen" -> "xn--mnchen-3ya"), while the
    # `idna` package rejects every one of them under strict and
    # UTS46 processing, so a configured origin containing one was
    # left alone and never matched. The same ignored class covers
    # COMBINING GRAPHEME JOINER U+034F, the Mongolian variation
    # selectors U+180B-U+180D, and ZERO WIDTH NO-BREAK SPACE
    # U+FEFF (verified against Node's WHATWG parser: "a\u034fb"
    # -> "ab", "a\u180bb" -> "ab", "a\ufeffb" -> "ab", and a
    # label of only such a form becomes empty, ".example", as
    # with the forms above); the same ignored class covers the
    # variation selectors U+FE00-U+FE0F and the variation
    # selectors supplement U+E0100-U+E01EF (verified against
    # Node's WHATWG parser: "a\ufe00b" -> "ab", "a\ufe0fb" ->
    # "ab", "a\U000e0100b" -> "ab", "a\U000e01efb" -> "ab", and
    # a label of only such a form becomes empty, ".example");
    # the package likewise rejects them
    # under its strict path, and its UTS46 retry is never reached
    # for them because no retry-guard set below contains them, so
    # they are stripped here too. Delete them up front, before
    # every other mapping and branch below, so mixed labels also
    # serialize as the browser does ("a©\u200b" -> "xn--a-nca",
    # "a\u203c\u200b" -> "a!!", "a\u00bc\u200b" ->
    # "xn--a14-pt0a"). A label consisting only of stripped forms
    # becomes empty, which the label loop below already preserves
    # as an empty label (".example"), matching the browser's
    # hostname for that input. Plain labels containing one were
    # previously left alone (the strict path rejected them), while
    # mixed as-is / double-exclamation labels punycoded the
    # invisible raw into a wrong, never-matching form; stripping
    # corrects both, and no correctly-matching host changes.
    host = host.translate(
        {0x00AD: None, 0x200B: None}
        | {cp: None for cp in range(0x2060, 0x2065)}
        | {cp: None for cp in range(0x206A, 0x2070)}
        | {0x034F: None, 0xFEFF: None}
        | {cp: None for cp in range(0x180B, 0x180E)}
        | {cp: None for cp in range(0xFE00, 0xFE10)}
        | {cp: None for cp in range(0xE0100, 0xE01F0)}
    )
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
    # WHATWG URL domainToASCII splits a host on "." and on the two
    # other dot forms, IDEOGRAPHIC FULL STOP U+3002 and HALFWIDTH
    # IDEOGRAPHIC FULL STOP U+FF61, as well as on U+FF0E — but
    # only U+FF0E is covered by the fullwidth table above (U+3002
    # is not a fullwidth ASCII form, and U+FF61 is a halfwidth
    # form, which that table deliberately leaves alone). A mixed
    # label containing one therefore reached the branches below
    # as a single label and was punycoded whole ("a©。b" ->
    # "xn--ab-tda8959b") instead of splitting ("xn--a-nca.b"),
    # so it never matched the browser's Origin. Map both to "."
    # up front, so every branch below sees the browser's
    # sub-labels; plain labels already matched via the UTS46
    # retry below, and empty sub-labels (leading, trailing or
    # doubled dots) are preserved by the label loop, as with ".".
    host = host.translate({0x3002: ".", 0xFF61: "."})
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
    # The same class covers the combining diacritical marks
    # U+0300-U+036F in context, after a base letter: the strict
    # IDNA2008 path rejects them ("Label must be in Normalization
    # Form C", since "a" + U+0300 is not NFC), while UTS46
    # NFC-normalizes first and punycodes the result (a + U+0300
    # -> "à" -> "xn--0ca", a + U+0301 -> "xn--1ca"), matching
    # Node's WHATWG parser. The U+0345 entry above came from a
    # standalone-label scan, where a mark alone fails under both
    # paths; after a base letter the whole range is UTS46-ok, so
    # it joins the UTS46 retry here. A mark alone at a label
    # start still fails under UTS46 ("illegal combining
    # character") and falls through, matching the browser's
    # rejection; U+034F is stripped up front and needs no entry.
    # The pipeline's lower() leaves these marks unchanged, so
    # the forms above are what the retry sees in practice.
    _punycode_combining_marks = frozenset(range(0x0300, 0x0370))
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
    # Halfwidth voiced/semi-voiced marks (U+FF9E/U+FF9F): they
    # combine with a preceding kana rather than standing alone, so
    # they are a separate case from the halfwidth katakana above.
    # When the preceding base is itself halfwidth katakana the
    # kana's guard entry already triggers the UTS46 retry, so that
    # combination already normalizes (ｶﾞ -> "xn--mck"). The gap is
    # a fullwidth kana, hiragana, ASCII or digit base, which passes
    # the strict path alone, so no retry fires and the mark makes
    # the whole host fail: カﾞ, かﾞ and aﾞ all return None today
    # while UTS46 (and Node's WHATWG parser) produce "xn--mck",
    # "xn--v8j" and "xn--a-wdu". Alone at a label start both UTS46
    # and browsers reject the mark, so the retry failing there
    # leaves behaviour unchanged. They join the retry here.
    _punycode_halfwidth_marks = frozenset([0xFF9E, 0xFF9F])
    # Greek Extended (U+1F00-U+1FFF): a full scan of the block
    # against the actual helper isolated 46 strict-reject/UTS46-ok
    # members after lower() — the rest of the block already passes
    # the strict path or fails under both strict and UTS46 (the
    # latter, e.g. U+1F16/U+1F46/U+1FBD, are deliberately left
    # alone, as browsers reject them too). UTS46 punycodes the
    # survivors as-is (ά -> "xn--hxa", ᾀ -> "xn--uxa970l",
    # ᾳ -> "xn--mxaq", ι -> "xn--uxa"), matching Node's WHATWG
    # parser on all 46. A translate table cannot express this
    # class (there is no plain-letter target), so they join the
    # UTS46 retry here. The set lists the lowercased forms: the
    # capitals U+1F88-U+1F8F/U+1F98-U+1F9F/U+1FA8-U+1FAF and
    # U+1FBB/U+1FBC/U+1FC9/U+1FCB/U+1FDB/U+1FEB/U+1FF9/U+1FFB
    # fold to members of this set under the pipeline's lower(),
    # so they are covered without separate entries.
    _punycode_greek_extended = frozenset(
        [
            0x1F71, 0x1F73, 0x1F75, 0x1F77, 0x1F79, 0x1F7B, 0x1F7D,
            0x1F80, 0x1F81, 0x1F82, 0x1F83, 0x1F84, 0x1F85, 0x1F86,
            0x1F87, 0x1F90, 0x1F91, 0x1F92, 0x1F93, 0x1F94, 0x1F95,
            0x1F96, 0x1F97, 0x1FA0, 0x1FA1, 0x1FA2, 0x1FA3, 0x1FA4,
            0x1FA5, 0x1FA6, 0x1FA7, 0x1FB2, 0x1FB3, 0x1FB4, 0x1FB7,
            0x1FBE, 0x1FC2, 0x1FC3, 0x1FC4, 0x1FC7, 0x1FD3, 0x1FE3,
            0x1FF2, 0x1FF3, 0x1FF4, 0x1FF7,
        ]
    )
    # Kangxi radicals (U+2F00-U+2FD5): a full scan of the block
    # against the actual helper isolated exactly these 214 as
    # strict-reject/UTS46-ok after lower() (they have no case, so
    # lower() is identity; nothing else in the block fails strict
    # while passing UTS46). UTS46 maps each radical to its unified
    # ideograph before encoding (⼀ -> 一 -> "xn--4gq",
    # ⼁ -> 丨 -> "xn--9hq"), matching Node's WHATWG parser on all
    # 214 alone and mid-word. That mapping happens inside the
    # package's UTS46 processing, so they join the UTS46 retry
    # here rather than needing a translate table.
    _punycode_kangxi = frozenset(range(0x2F00, 0x2FD6))
    # Enclosed CJK Letters and Months (U+3200-U+32FF): a full
    # scan of the block against the actual helper isolated
    # exactly these 165 as strict-reject/UTS46-ok after lower()
    # (they have no case, so lower() is identity; the remaining
    # 91 members of the block fail under both strict and UTS46
    # and are deliberately left alone, as browsers reject them
    # too). UTS46 maps some to plain forms (㉐ -> "pte",
    # ㉑ -> "21", ㊱ -> "36", ㋌ -> "hg") and punycodes the
    # others as-is (㉄ -> "xn--lzr", ㊀ -> "xn--4gq"),
    # matching Node's WHATWG parser on all 165 alone and
    # mid-word. They join the UTS46 retry here rather than
    # needing a translate table, since the retry's uts46=True
    # encoding reproduces both the mapped and the as-is forms.
    # U+327F is unassigned (InvalidCodepoint under both paths)
    # and is the only gap inside the covered runs.
    _punycode_enclosed_cjk = frozenset(
        list(range(0x3244, 0x3248))
        + list(range(0x3250, 0x3260))
        + list(range(0x326E, 0x327F))
        + list(range(0x3280, 0x3300))
    )
    # CJK Compatibility square forms (U+3300-U+33FF): a full
    # scan of the block against the actual helper isolated
    # exactly these 246 as strict-reject/UTS46-ok after lower()
    # (they have no case, so lower() is identity; the remaining
    # 10 members of the block fail under both strict and UTS46).
    # UTS46 maps some to plain forms (㍱ -> "hpa",
    # ㎀ -> "pa", ㏿ -> "gal") and punycodes the others as-is
    # (㌀ -> "xn--cckzd0a3n", ㍻ -> "xn--gwt73f"),
    # matching Node's WHATWG parser on all 246 alone and
    # mid-word. They join the UTS46 retry here rather than
    # needing a translate table, since the retry's uts46=True
    # encoding reproduces both the mapped and the as-is forms.
    # Seven of the remaining 10 (㎧/㎨/㎮/㎯/㏆/㏞/㏟) are a
    # different class — the browser punycodes them as-is while
    # the package's UTS46 processing rejects them — and are
    # assessed separately; the other three (㏂/㏇/㏘) are
    # rejected by the browser too and are deliberately left
    # alone.
    _punycode_square_cjk = frozenset(
        list(range(0x3300, 0x33A7))
        + list(range(0x33A9, 0x33AE))
        + list(range(0x33B0, 0x33C2))
        + list(range(0x33C3, 0x33C6))
        + list(range(0x33C8, 0x33D8))
        + list(range(0x33D9, 0x33DE))
        + list(range(0x33E0, 0x3400))
    )
    # Arabic Presentation Forms-B U+FE80-U+FEFC: UTS46 maps each to
    # its standard Arabic letter (isolated/final form -> base letter,
    # e.g. ﺀ -> ء, ﺋ -> ئ, ﻼ -> لا) and punycodes the result, while
    # strict IDNA2008 rejects them all, so the helper left a
    # configured origin containing one alone and never matched under
    # Starlette's exact allow_origins matching. The whole run shares
    # the class, so it is one range; U+FEFD-U+FEFF fail under both
    # strict and UTS46 (and are browser-rejected) and are left alone.
    # Note the UTS46 bidi rule: an LTR label cannot mix in these RTL
    # letters, so "aﺀb" is invalid in both the browser and the
    # package — the valid mixed forms are RTL-context ones (e.g.
    # "اﺀ"), which the retry reproduces exactly.
    _punycode_arabic_presentation_b = frozenset(range(0xFE80, 0xFEFD))
    # Arabic Presentation Forms-A (U+FB50-U+FDFF): UTS46 maps
    # each to its Arabic letter / letter-sequence form before
    # encoding, while strict IDNA2008 rejects them all, so the
    # helper left a configured origin containing one alone and
    # never matched under Starlette's exact allow_origins
    # matching. The remaining members of the block (U+FBB2-U+FBD2,
    # U+FC5E-U+FC63, U+FCF2-U+FCF4, U+FD3E-U+FD4F, U+FD90-U+FD91,
    # U+FDC8-U+FDEF, U+FDFA-U+FDFF) fail under both strict and
    # UTS46, and are left alone. Note the UTS46 bidi rule, as
    # with Arabic Presentation Forms-B: an LTR label cannot mix
    # in these RTL letters, so the valid forms are alone or
    # RTL-context ones, which the retry reproduces exactly.
    _punycode_arabic_presentation_a = (
        frozenset(range(0xFB50, 0xFBB2))
        | frozenset(range(0xFBD3, 0xFC5E))
        | frozenset(range(0xFC64, 0xFCF2))
        | frozenset(range(0xFCF5, 0xFD3E))
        | frozenset(range(0xFD50, 0xFD90))
        | frozenset(range(0xFD92, 0xFDC8))
        | frozenset(range(0xFDF0, 0xFDFA))
        | frozenset([0xFDFC])
    )
    # CJK Compatibility Ideographs (U+F900-U+FAD9): UTS46 maps each
    # to its unified ideograph before encoding, while strict IDNA2008
    # rejects them all, so the helper left a configured origin
    # containing one alone and never matched under Starlette's exact
    # allow_origins matching. Two runs share the class; U+FA6E-U+FA6F
    # and U+FADA-U+FAFF are unassigned, fail under both strict and
    # UTS46, and are left alone.
    _punycode_cjk_compat = frozenset(range(0xF900, 0xFA6E)) | frozenset(
        range(0xFA70, 0xFADA)
    )
    # Hebrew Alphabetic Presentation Forms (U+FB1D-U+FB4F): UTS46
    # maps each to its Hebrew letter / letter-plus-point form before
    # encoding, while strict IDNA2008 rejects them all, so the helper
    # left a configured origin containing one alone and never
    # matched under Starlette's exact allow_origins matching.
    # U+FB00-U+FB06 and U+FB13-U+FB17 are already mapped up front
    # (Latin/Armenian ligatures); U+FB1E is a combining mark that
    # the strict path already handles in context, and U+FB07-U+FB12,
    # U+FB18-U+FB1C, U+FB37, U+FB3D, U+FB3F, U+FB42 and U+FB45 are
    # unassigned, fail under both strict and UTS46, and are left
    # alone. Note the UTS46 bidi rule, as with Arabic Presentation
    # Forms-B: an LTR label cannot mix in these RTL letters, so
    # "aיִb" is invalid in both the browser and the package — the
    # valid forms are alone or RTL-context ones (e.g. "איִ"), which
    # the retry reproduces exactly. U+FB29 is excluded: UTS46 maps
    # it to "+" (a different fix class, since the package rejects
    # "+" itself), and is assessed separately.
    _punycode_hebrew_presentation = (
        frozenset([0xFB1D])
        | frozenset(range(0xFB1F, 0xFB29))
        | frozenset(range(0xFB2A, 0xFB37))
        | frozenset(range(0xFB38, 0xFB3D))
        | frozenset([0xFB3E])
        | frozenset(range(0xFB40, 0xFB42))
        | frozenset(range(0xFB43, 0xFB45))
        | frozenset(range(0xFB46, 0xFB50))
    )
    # U+FB29 mixed with an enclosed/square member whose UTS46
    # expansion is plain ASCII (㉐ -> "pte", ㊱ -> "36", ㋌ ->
    # "hg", ㍱ -> "hpa", ㎀ -> "pa"): browsers serialize the
    # label as that plain form with a literal "+" ("㉐﬩" ->
    # "pte+", "㍱﬩" -> "hpa+", verified against Node's WHATWG
    # parser), because WHATWG URL serialization does not apply
    # STD3 ASCII rules — but the UTS46 retry below encodes the
    # remapped label as punycode ("xn--pte+-") since "+" is not
    # a STD3-valid label character, so the entry never matched
    # under Starlette's exact allow_origins matching. The
    # U+FB29 branch further down never sees these hosts because
    # the retry returns first, so check here, before the retry:
    # when U+FB29 is present and every label remaps (via the
    # package's own UTS46 remap, the same mapping the retry
    # uses) to plain kept-verbatim characters (letters, digits,
    # "_", "+" and "-", the set the U+FB29 branch itself uses),
    # return that plain form directly. The gate keeps every
    # other host unchanged: a literally configured "+" host has
    # no U+FB29 and never reaches this check; a label whose
    # remap stays non-ASCII (an as-is enclosed/square member,
    # a fraction-slash square expansion such as "m∕s", a
    # non-ASCII letter such as "ß", or an RTL letter, whose
    # browser form with "+" is rejected) fails the check and
    # falls through to the retry and the U+FB29 branch exactly
    # as before; and a remap failure (a codepoint the package
    # rejects, such as an as-is mark) is caught and falls
    # through too. A genuinely empty label stays empty, as in
    # the U+FB29 branch, but a label that would remap to empty
    # does not qualify, so no character is silently dropped.
    # The same gap exists per label in a multi-label host whose
    # other label stays non-ASCII ("㉐﬩.münchen" -> browser
    # "pte+.xn--mnchen-3ya", verified against Node's WHATWG
    # parser): the enclosed/square member triggers the retry
    # below, and when the sibling is UTS46-valid the retry
    # succeeds and punycodes the plain label too
    # ("xn--pte+-.xn--mnchen-3ya"), so the entry never matched.
    # (When the sibling is UTS46-invalid the retry fails and the
    # later U+FB29 branch already gives the mixed form, so this
    # only changes hosts the retry currently gets wrong.) The
    # mixed form is built label by label, because WHATWG/UTS46
    # processing is per label: a plain label keeps its remapped
    # form, and each non-plain label is encoded on its own by
    # this same function (a single label has no dots, so it
    # cannot re-enter this mixed branch). The mixed form is
    # only used when at least one plain label actually contains
    # U+FB29 — the flagged class — and when every non-plain
    # label encodes to a single non-empty label on its own; any
    # failure, empty result, or dot in a delegated result falls
    # through to the retry and the later branches exactly as
    # before, so no host is newly dropped or silently altered.
    if "\uFB29" in host:
        try:
            _fb29_plain_labels = []
            _fb29_plain_flags = []
            _fb29_plain_origs = host.split(".")
            for _fb29_plain_label in _fb29_plain_origs:
                _fb29_plain_remapped = "".join(
                    _idna.uts46_remap(
                        c, std3_rules=False, transitional=False
                    )
                    if ord(c) > 127
                    else c
                    for c in _fb29_plain_label
                )
                # "!" joins the kept-verbatim set: UTS46 maps
                # DOUBLE EXCLAMATION MARK U+203C to "!!" and
                # FULLWIDTH EXCLAMATION MARK U+FF01 to "!", and
                # WHATWG keeps a literal "!" verbatim in a host
                # ("‼﬩" -> "!!+", "a!﬩" -> "a!+", verified
                # against Node's WHATWG parser), so without it
                # a double-exclamation + U+FB29 label failed
                # this check and fell through to the punycode
                # retry ("xn--!!-jf1n"). "?" stays excluded, so
                # the browser-rejected U+2048/U+2049 expansions
                # ("?!", "!?") still fail this check as before.
                _fb29_plain_flags.append(
                    (not _fb29_plain_label or _fb29_plain_remapped)
                    and all(
                        c in "abcdefghijklmnopqrstuvwxyz"
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                        "0123456789_+-!"
                        for c in _fb29_plain_remapped
                    )
                )
                _fb29_plain_labels.append(_fb29_plain_remapped)
            if all(_fb29_plain_flags):
                return ".".join(_fb29_plain_labels)
            if (
                any(_fb29_plain_flags)
                and not all(_fb29_plain_flags)
                and any(
                    flag and "\uFB29" in orig
                    for flag, orig in zip(
                        _fb29_plain_flags, _fb29_plain_origs
                    )
                )
            ):
                _fb29_mixed_labels = []
                _fb29_mixed_ok = True
                for _fb29_orig, _fb29_remapped, _fb29_flag in zip(
                    _fb29_plain_origs,
                    _fb29_plain_labels,
                    _fb29_plain_flags,
                ):
                    if _fb29_flag:
                        _fb29_mixed_labels.append(_fb29_remapped)
                    elif not _fb29_orig:
                        _fb29_mixed_labels.append("")
                    else:
                        _fb29_delegated = _encode_idna(_fb29_orig)
                        if (
                            not _fb29_delegated
                            or "." in _fb29_delegated
                        ):
                            _fb29_mixed_ok = False
                            break
                        _fb29_mixed_labels.append(_fb29_delegated)
                if _fb29_mixed_ok:
                    return ".".join(_fb29_mixed_labels)
        except (UnicodeError, ValueError):
            pass
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
        or ord(c) in _punycode_combining_marks
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
        or ord(c) in _punycode_halfwidth_marks
        or ord(c) in _punycode_greek_extended
        or ord(c) in _punycode_kangxi
        or ord(c) in _punycode_enclosed_cjk
        or ord(c) in _punycode_square_cjk
        or ord(c) in _punycode_arabic_presentation_b
        or ord(c) in _punycode_arabic_presentation_a
        or ord(c) in _punycode_cjk_compat
        or ord(c) in _punycode_hebrew_presentation
        for c in host
    ):
        try:
            return _idna.encode(host, uts46=True).decode("ascii")
        except (UnicodeError, ValueError):
            pass
    # The as-is symbol map, shared by the U+FB29 branch below (a
    # symbol mixed with U+FB29 must be mapped before qualifying)
    # and by the fallback branch further down.
    _asis_map = {
        0x2103: "°c", 0x2109: "°f", 0x2132: "ⅎ", 0x2140: "∑",
        0x33A7: "m∕s", 0x33A8: "m∕s2", 0x33AE: "rad∕s",
        0x33AF: "rad∕s2", 0x33C6: "c∕kg", 0x33DE: "v∕m",
        0x33DF: "a∕m",
        # General Punctuation expansions (same pattern): UTS46
        # maps these to repeated/single base forms before IDNA
        # processing (‑ -> "‐", ″ -> "′′", ‴ -> "′′′",
        # ‶ -> "‵‵", ‷ -> "‵‵‵", ⁗ -> "′′′′"), which the
        # browser then punycodes — but the package rejects both
        # the originals and the expansions under strict and UTS46
        # processing, so they need this branch with the mapping
        # below, not bare as-is entries.
        0x2011: "‐", 0x2033: "′′", 0x2034: "′′′",
        0x2036: "‵‵", 0x2037: "‵‵‵", 0x2057: "′′′′",
    }
    # Combining marks U+1ACF-U+1AEB punycoded as-is (the same
    # 27 codepoints listed in _punycode_asis below for standalone
    # labels: 0x1ACF, 0x1AD0-0x1ADD, 0x1AE0-0x1AEB, excluding
    # the browser-rejected 0x1ADE/0x1ADF). This Python's Unicode
    # data leaves them unassigned (category Cn) and the `idna`
    # package rejects them, so the U+FB29 mixed-label gate below
    # fails them on both its category check and its remap check,
    # and the label then fell through to a wrong form punycoding
    # U+FB29 itself ("a᫏﬩" -> "xn--a-58k1995i" instead of the
    # browser's "xn--a+-lrq"). Defined here, ahead of the FB29
    # branch, because _punycode_asis itself is defined below it.
    _fb29_punycode_asis_marks = frozenset(
        [0x1ACF]
        + list(range(0x1AD0, 0x1ADE))
        + list(range(0x1AE0, 0x1AEC))
    )
    # U+FB29 (HEBREW LETTER ALTERNATE PLUS SIGN): UTS46 maps it
    # to "+" before IDNA processing, but the `idna` package
    # rejects "+" itself under both strict and UTS46 processing,
    # so a configured origin containing it was left alone and
    # never matched (the Hebrew presentation retry above
    # deliberately excludes it). Browsers serialize it as a
    # literal "+" in the host ("﬩.example" -> "+.example",
    # "a﬩b.example" -> "a+b.example", verified against Node's
    # WHATWG parser), so when every label of the host is plain
    # ASCII once U+FB29 is replaced by "+" (underscores and
    # hyphens included, as browsers keep them; ligatures mapped
    # up front, e.g. "ﬀ﬩" -> "ff+", qualify), return that form
    # directly. The branch only runs when U+FB29 is present, so
    # a literally configured "+" host still returns None as
    # before, and a label mixing U+FB29 with other non-ASCII
    # (e.g. "ß﬩" -> browser "xn--+-pfa") falls through to the
    # existing paths unchanged, for separate assessment.
    if "\uFB29" in host:
        _fb29_candidate = host.replace("\uFB29", "+")
        _fb29_label_chars = (
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789_+-"
        )
        if all(
            all(c in _fb29_label_chars for c in label)
            for label in _fb29_candidate.split(".")
        ):
            return _fb29_candidate
        # Mixed U+FB29 labels: a label mixing U+FB29 with other
        # non-ASCII (e.g. "ß﬩" -> browser "xn--+-pfa") fell
        # through above (not all-ASCII after the replacement)
        # and then failed the strict path below, so the entry
        # never matched — and an underscore label even produced
        # a wrong form, punycoding U+FB29 itself ("a_ß﬩" ->
        # "xn--a_-hia0147w") instead of the browser's
        # "xn--a_+-6ka". Handle such labels per label: a label
        # without U+FB29 must already consist of kept-verbatim
        # characters (it passes through unchanged), or encode
        # per label with the same paths the post-FB29 fallback
        # uses (strict IDNA2008, then the "xn--" + punycode form
        # for underscore labels) — so a non-ASCII label without
        # U+FB29 (e.g. the "münchen" in "ß﬩.münchen", which
        # previously failed the whole host here) now encodes
        # instead of leaving the entry unmatched, while no
        # un-encoded label is ever emitted. A mixed label
        # qualifies only when every character is either an
        # ASCII letter, digit, "_", "+" or "-" (the characters
        # browsers keep verbatim in a label), or a non-ASCII
        # letter, mark or number, with no right-to-left
        # character (browsers reject RTL labels containing "+"
        # — "א﬩" is an invalid URL), no leading mark (browsers
        # reject a label starting with one), and UTS46
        # remapping leaves the label unchanged (this rejects
        # characters browsers map elsewhere, e.g. U+A770 ->
        # U+A76F, U+2103 -> "°c", U+0345 -> "ι", a soft hyphen,
        # and decomposed forms, whose raw punycode would not
        # match the browser form). Qualifying labels are then
        # punycoded directly, which preserves "_", "+" and "-"
        # exactly as browsers do. Anything else falls through
        # to the existing paths unchanged.
        import unicodedata as _fb29_unicodedata

        _fb29_mixed_labels = []
        _fb29_mixed_ok = True
        for _fb29_orig, _fb29_mapped in zip(
            host.split("."), _fb29_candidate.split(".")
        ):
            if not _fb29_orig:
                _fb29_mixed_labels.append("")
            elif "\uFB29" not in _fb29_orig:
                if all(
                    c in _fb29_label_chars for c in _fb29_orig
                ):
                    _fb29_mixed_labels.append(_fb29_mapped)
                else:
                    try:
                        _fb29_mixed_labels.append(
                            _idna.encode(_fb29_orig).decode("ascii")
                        )
                    except (UnicodeError, ValueError):
                        if "_" in _fb29_orig and any(
                            ord(c) > 127 for c in _fb29_orig
                        ):
                            _fb29_mixed_labels.append(
                                "xn--"
                                + _fb29_orig.encode("punycode").decode(
                                    "ascii"
                                )
                            )
                        else:
                            _fb29_mixed_ok = False
                            break
            elif all(c in _fb29_label_chars for c in _fb29_mapped):
                _fb29_mixed_labels.append(_fb29_mapped)
            else:
                # As-is symbols mixed with U+FB29 (e.g. "℃﬩"):
                # UTS46 maps the symbol first (℃ -> "°c"), so
                # translate through the as-is map before
                # qualifying, and allow the map's non-letter
                # outputs (°, ∑, ∕) alongside letters, marks
                # and numbers — but only outputs actually
                # introduced by a mapped symbol in this label.
                # A literal symbol ("°﬩", "©﬩") introduces
                # no mapped output, so it qualifies through
                # the symbol/punctuation categories below
                # instead: browsers punycode such symbols
                # as-is when UTS46 leaves them unchanged
                # ("©﬩" -> "xn--+-mca"), while symbols
                # browsers reject or remap (e.g. "¨", "¯",
                # "¸" decompose, "…" is disallowed) still
                # fail the remap gate, and RTL symbols
                # still fail the bidirectional gate.
                _fb29_mapped_t = _fb29_mapped.translate(_asis_map)
                _fb29_asis_outputs = frozenset(
                    c
                    for _k, _v in _asis_map.items()
                    if chr(_k) in _fb29_mapped
                    for c in _v
                    if ord(c) > 127
                )
                # The remap gate cannot be applied verbatim to
                # a label containing a _fb29_punycode_asis_marks
                # member: the package rejects the mark itself, so
                # the remap raises even though browsers leave it
                # as-is. Retry with each such mark replaced by a
                # plain letter: that proves the remaining
                # characters are remap-stable (a character
                # browsers map elsewhere still changes the
                # placeholder label or raises, failing the gate),
                # while a normalization difference caused by the
                # substitution only fails conservatively.
                try:
                    _fb29_remap_ok = (
                        _idna.uts46_remap(
                            _fb29_mapped_t,
                            std3_rules=False,
                            transitional=False,
                        )
                        == _fb29_mapped_t
                    )
                except (UnicodeError, ValueError):
                    if any(
                        ord(c) in _fb29_punycode_asis_marks
                        for c in _fb29_mapped_t
                    ):
                        try:
                            _fb29_placeholder = "".join(
                                "a"
                                if ord(c)
                                in _fb29_punycode_asis_marks
                                else c
                                for c in _fb29_mapped_t
                            )
                            _fb29_remap_ok = (
                                _idna.uts46_remap(
                                    _fb29_placeholder,
                                    std3_rules=False,
                                    transitional=False,
                                )
                                == _fb29_placeholder
                            )
                        except (UnicodeError, ValueError):
                            _fb29_remap_ok = False
                    else:
                        _fb29_remap_ok = False
                _fb29_mapped_ok = (
                    _fb29_unicodedata.category(_fb29_mapped_t[0])[0]
                    != "M"
                    and all(
                        c in _fb29_label_chars
                        or (
                            ord(c) > 127
                            and (
                                _fb29_unicodedata.category(c)[0]
                                in "LMNSP"
                                or c in _fb29_asis_outputs
                                or ord(c) in _fb29_punycode_asis_marks
                            )
                            and _fb29_unicodedata.bidirectional(c)
                            not in ("R", "AL", "AN")
                        )
                        for c in _fb29_mapped_t
                    )
                    and _fb29_remap_ok
                )
                if not _fb29_mapped_ok:
                    # UTS46-mapped symbols mixed with U+FB29
                    # (e.g. "¼﬩"): the gate above fails because
                    # browsers map the symbol first (¼ -> "1⁄4")
                    # while the label as written is unchanged by
                    # remapping, so remap the label and qualify
                    # the remapped form instead — the punycode of
                    # "1⁄4+" is exactly the browser form
                    # ("¼﬩" -> "xn--14+-ot0a"). The remapped
                    # label must still contain the U+FB29 "+",
                    # remap idempotently, and pass the same
                    # category/bidirectional/leading-mark gates,
                    # so a symbol browsers reject or remap to a
                    # disallowed form still falls through.
                    try:
                        _fb29_remapped = _idna.uts46_remap(
                            _fb29_mapped_t,
                            std3_rules=False,
                            transitional=False,
                        )
                        _fb29_mapped_ok = (
                            _fb29_remapped != _fb29_mapped_t
                            and "+" in _fb29_remapped
                            and _fb29_unicodedata.category(
                                _fb29_remapped[0]
                            )[0]
                            != "M"
                            and all(
                                c in _fb29_label_chars
                                or (
                                    ord(c) > 127
                                    and (
                                        _fb29_unicodedata.category(c)[0]
                                        in "LMNSP"
                                        or c in _fb29_asis_outputs
                                    )
                                    and _fb29_unicodedata.bidirectional(c)
                                    not in ("R", "AL", "AN")
                                )
                                for c in _fb29_remapped
                            )
                            and _idna.uts46_remap(
                                _fb29_remapped,
                                std3_rules=False,
                                transitional=False,
                            )
                            == _fb29_remapped
                        )
                        if _fb29_mapped_ok:
                            _fb29_mapped_t = _fb29_remapped
                    except (UnicodeError, ValueError):
                        # A mapped symbol mixed with U+FB29 and a
                        # _fb29_punycode_asis_marks member (e.g.
                        # "¼᫏﬩"): the remap above raises on the
                        # mark itself even though browsers leave
                        # it as-is, so the label fell through and
                        # was punycoded raw ("xn--zba464k6y2n"
                        # instead of the browser's
                        # "xn--14+-18v308a"). Recover by remapping
                        # per character, keeping the marks verbatim:
                        # UTS46 mapping is per codepoint (the
                        # package applies no context rule here — a
                        # sigma before a mark or a fraction stays
                        # a sigma, as in browsers), so the
                        # per-character form is the mapped form.
                        # It is accepted only if it differs, still
                        # contains "+", passes the same gates
                        # (marks allowed, as in the gate above),
                        # and agrees with the package's whole-label
                        # remap on the placeholder form in both
                        # directions — a remapped/disallowed
                        # character fails the agreement (or its
                        # per-character remap raises, e.g. "…") and
                        # falls through instead.
                        _fb29_mapped_ok = False
                        if any(
                            ord(c) in _fb29_punycode_asis_marks
                            for c in _fb29_mapped_t
                        ):
                            try:
                                _fb29_recovered = []
                                for _c in _fb29_mapped_t:
                                    if (
                                        ord(_c)
                                        in _fb29_punycode_asis_marks
                                        or _c in _fb29_label_chars
                                    ):
                                        _fb29_recovered.append(_c)
                                    else:
                                        _fb29_recovered.append(
                                            _idna.uts46_remap(
                                                _c,
                                                std3_rules=False,
                                                transitional=False,
                                            )
                                        )
                                _fb29_recovered = "".join(_fb29_recovered)
                                _fb29_rec_placeholder = "".join(
                                    "a"
                                    if ord(c)
                                    in _fb29_punycode_asis_marks
                                    else c
                                    for c in _fb29_recovered
                                )
                                _fb29_orig_placeholder = "".join(
                                    "a"
                                    if ord(c)
                                    in _fb29_punycode_asis_marks
                                    else c
                                    for c in _fb29_mapped_t
                                )
                                _fb29_mapped_ok = (
                                    _fb29_recovered != _fb29_mapped_t
                                    and "+" in _fb29_recovered
                                    and _fb29_unicodedata.category(
                                        _fb29_recovered[0]
                                    )[0]
                                    != "M"
                                    and all(
                                        c in _fb29_label_chars
                                        or (
                                            ord(c) > 127
                                            and (
                                                _fb29_unicodedata.category(c)[0]
                                                in "LMNSP"
                                                or c in _fb29_asis_outputs
                                                or ord(c)
                                                in _fb29_punycode_asis_marks
                                            )
                                            and _fb29_unicodedata.bidirectional(c)
                                            not in ("R", "AL", "AN")
                                        )
                                        for c in _fb29_recovered
                                    )
                                    and _idna.uts46_remap(
                                        _fb29_orig_placeholder,
                                        std3_rules=False,
                                        transitional=False,
                                    )
                                    == _fb29_rec_placeholder
                                    and _idna.uts46_remap(
                                        _fb29_rec_placeholder,
                                        std3_rules=False,
                                        transitional=False,
                                    )
                                    == _fb29_rec_placeholder
                                )
                                if _fb29_mapped_ok:
                                    _fb29_mapped_t = _fb29_recovered
                            except (UnicodeError, ValueError):
                                _fb29_mapped_ok = False
                if not _fb29_mapped_ok:
                    _fb29_mixed_ok = False
                    break
                _fb29_mixed_labels.append(
                    "xn--"
                    + _fb29_mapped_t.encode("punycode").decode("ascii")
                )
        if _fb29_mixed_ok:
            return ".".join(_fb29_mixed_labels)
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
    # Greek Extended members the as-is branch must remap first:
    # every member of _punycode_greek_extended above remaps under
    # UTS46 (the seven oxia/tonos forms to a single tonos letter,
    # e.g. ά U+1F71 -> ά U+03AC, and the rest to a base letter
    # plus iota subscript, e.g. ᾀ U+1F80 -> ἀι, ι U+1FBE -> ι),
    # verified against the package's uts46_remap for all 46. The
    # as-is branch below punycodes its label directly, because
    # the package rejects the as-is member under both strict and
    # UTS46 processing — but browsers remap the Greek Extended
    # member first, so a label mixing one with an as-is member
    # punycoded raw never matched ("ά©" -> helper "xn--gba378m",
    # browser "xn--gba55m", which decodes to the remapped "ά©").
    # Translating through this table before punycoding reproduces
    # the browser form; labels without a Greek Extended member
    # are unchanged, and the table's outputs are plain Greek
    # letters that need no further remap (translate does not
    # recurse, matching UTS46's single mapping pass). The
    # standalone as-is branch below applies it, as does the
    # fraction branch's gate; FB29 labels claim theirs, so mixes
    # with that class keep their existing behaviour for separate
    # assessment, as do as-is mixes with other UTS46-remapped
    # classes (enclosed CJK, Kangxi, and the like), which are a
    # broader class than this one.
    _greek_extended_remap = {
        0x1F71: "ά", 0x1F73: "έ", 0x1F75: "ή", 0x1F77: "ί",
        0x1F79: "ό", 0x1F7B: "ύ", 0x1F7D: "ώ",
        0x1F80: "ἀι", 0x1F81: "ἁι", 0x1F82: "ἂι", 0x1F83: "ἃι",
        0x1F84: "ἄι", 0x1F85: "ἅι", 0x1F86: "ἆι", 0x1F87: "ἇι",
        0x1F90: "ἠι", 0x1F91: "ἡι", 0x1F92: "ἢι", 0x1F93: "ἣι",
        0x1F94: "ἤι", 0x1F95: "ἥι", 0x1F96: "ἦι", 0x1F97: "ἧι",
        0x1FA0: "ὠι", 0x1FA1: "ὡι", 0x1FA2: "ὢι", 0x1FA3: "ὣι",
        0x1FA4: "ὤι", 0x1FA5: "ὥι", 0x1FA6: "ὦι", 0x1FA7: "ὧι",
        0x1FB2: "ὰι", 0x1FB3: "αι", 0x1FB4: "άι", 0x1FB7: "ᾶι",
        0x1FBE: "ι",
        0x1FC2: "ὴι", 0x1FC3: "ηι", 0x1FC4: "ήι", 0x1FC7: "ῆι",
        0x1FD3: "ΐ", 0x1FE3: "ΰ",
        0x1FF2: "ὼι", 0x1FF3: "ωι", 0x1FF4: "ώι", 0x1FF7: "ῶι",
    }
    # Enclosed CJK members the as-is branch must remap first:
    # every member of _punycode_enclosed_cjk above remaps under
    # UTS46 (a single CJK/Hangul letter, e.g. ㉄ -> 問, or
    # an ASCII/CJK expansion, e.g. ㉐ -> "pte", ㋿ -> "令和"),
    # verified against the package's uts46_remap for all 165.
    # The as-is branch below punycodes its label directly, because
    # the package rejects the as-is member under both strict and
    # UTS46 processing -- but browsers remap the enclosed member
    # first, so a label mixing one with an as-is member punycoded
    # raw never matched ("©㉄" -> helper "xn--gba215w",
    # browser "xn--gba4544b", which decodes to the remapped "©問").
    # Translating through this table before punycoding reproduces
    # the browser form; labels without an enclosed member are
    # unchanged, and the table's outputs need no further remap
    # (ASCII digits/letters and CJK/Hangul letters; translate does
    # not recurse, matching UTS46's single mapping pass). The
    # standalone as-is branch below applies it; mixes with other
    # UTS46-remapped classes keep their existing behaviour for
    # separate assessment.
    _enclosed_cjk_remap = {
        0x3244: "問", 0x3245: "幼", 0x3246: "文", 0x3247: "箏", 0x3250: "pte",
        0x3251: "21", 0x3252: "22", 0x3253: "23", 0x3254: "24", 0x3255: "25",
        0x3256: "26", 0x3257: "27", 0x3258: "28", 0x3259: "29", 0x325A: "30",
        0x325B: "31", 0x325C: "32", 0x325D: "33", 0x325E: "34", 0x325F: "35",
        0x326E: "가", 0x326F: "나", 0x3270: "다", 0x3271: "라", 0x3272: "마",
        0x3273: "바", 0x3274: "사", 0x3275: "아", 0x3276: "자", 0x3277: "차",
        0x3278: "카", 0x3279: "타", 0x327A: "파", 0x327B: "하", 0x327C: "참고",
        0x327D: "주의", 0x327E: "우", 0x3280: "一", 0x3281: "二", 0x3282: "三",
        0x3283: "四", 0x3284: "五", 0x3285: "六", 0x3286: "七", 0x3287: "八",
        0x3288: "九", 0x3289: "十", 0x328A: "月", 0x328B: "火", 0x328C: "水",
        0x328D: "木", 0x328E: "金", 0x328F: "土", 0x3290: "日", 0x3291: "株",
        0x3292: "有", 0x3293: "社", 0x3294: "名", 0x3295: "特", 0x3296: "財",
        0x3297: "祝", 0x3298: "労", 0x3299: "秘", 0x329A: "男", 0x329B: "女",
        0x329C: "適", 0x329D: "優", 0x329E: "印", 0x329F: "注", 0x32A0: "項",
        0x32A1: "休", 0x32A2: "写", 0x32A3: "正", 0x32A4: "上", 0x32A5: "中",
        0x32A6: "下", 0x32A7: "左", 0x32A8: "右", 0x32A9: "医", 0x32AA: "宗",
        0x32AB: "学", 0x32AC: "監", 0x32AD: "企", 0x32AE: "資", 0x32AF: "協",
        0x32B0: "夜", 0x32B1: "36", 0x32B2: "37", 0x32B3: "38", 0x32B4: "39",
        0x32B5: "40", 0x32B6: "41", 0x32B7: "42", 0x32B8: "43", 0x32B9: "44",
        0x32BA: "45", 0x32BB: "46", 0x32BC: "47", 0x32BD: "48", 0x32BE: "49",
        0x32BF: "50", 0x32C0: "1月", 0x32C1: "2月", 0x32C2: "3月", 0x32C3: "4月",
        0x32C4: "5月", 0x32C5: "6月", 0x32C6: "7月", 0x32C7: "8月", 0x32C8: "9月",
        0x32C9: "10月", 0x32CA: "11月", 0x32CB: "12月", 0x32CC: "hg", 0x32CD: "erg",
        0x32CE: "ev", 0x32CF: "ltd", 0x32D0: "ア", 0x32D1: "イ", 0x32D2: "ウ",
        0x32D3: "エ", 0x32D4: "オ", 0x32D5: "カ", 0x32D6: "キ", 0x32D7: "ク",
        0x32D8: "ケ", 0x32D9: "コ", 0x32DA: "サ", 0x32DB: "シ", 0x32DC: "ス",
        0x32DD: "セ", 0x32DE: "ソ", 0x32DF: "タ", 0x32E0: "チ", 0x32E1: "ツ",
        0x32E2: "テ", 0x32E3: "ト", 0x32E4: "ナ", 0x32E5: "ニ", 0x32E6: "ヌ",
        0x32E7: "ネ", 0x32E8: "ノ", 0x32E9: "ハ", 0x32EA: "ヒ", 0x32EB: "フ",
        0x32EC: "ヘ", 0x32ED: "ホ", 0x32EE: "マ", 0x32EF: "ミ", 0x32F0: "ム",
        0x32F1: "メ", 0x32F2: "モ", 0x32F3: "ヤ", 0x32F4: "ユ", 0x32F5: "ヨ",
        0x32F6: "ラ", 0x32F7: "リ", 0x32F8: "ル", 0x32F9: "レ", 0x32FA: "ロ",
        0x32FB: "ワ", 0x32FC: "ヰ", 0x32FD: "ヱ", 0x32FE: "ヲ", 0x32FF: "令和",
    }
    # Kangxi radicals the as-is branch must remap first:
    # every member of _punycode_kangxi above remaps under
    # UTS46 to a single unified CJK ideograph (e.g. ⼀ -> 一,
    # ⼐ -> 凵, ⿵ -> 龠), verified against the package's
    # uts46_remap for all 214. The as-is branch below
    # punycodes its label directly, because the package
    # rejects the as-is member under both strict and UTS46
    # processing -- but browsers remap the radical first, so
    # a label mixing one with an as-is member punycoded raw
    # never matched ("©⼀" -> helper "xn--gba048u",
    # browser "xn--gba2170b", which decodes to the remapped
    # "©一"). Translating through this table before
    # punycoding reproduces the browser form; labels without
    # a kangxi radical are unchanged, and the table's outputs
    # need no further remap (unified CJK ideographs; translate
    # does not recurse, matching UTS46's single mapping pass).
    # The standalone as-is branch below applies it; mixes
    # with other UTS46-remapped classes keep their existing
    # behaviour for separate assessment.
    _kangxi_remap = {
        0x2F00: "一", 0x2F01: "丨", 0x2F02: "丶", 0x2F03: "丿", 0x2F04: "乙",
        0x2F05: "亅", 0x2F06: "二", 0x2F07: "亠", 0x2F08: "人", 0x2F09: "儿",
        0x2F0A: "入", 0x2F0B: "八", 0x2F0C: "冂", 0x2F0D: "冖", 0x2F0E: "冫",
        0x2F0F: "几", 0x2F10: "凵", 0x2F11: "刀", 0x2F12: "力", 0x2F13: "勹",
        0x2F14: "匕", 0x2F15: "匚", 0x2F16: "匸", 0x2F17: "十", 0x2F18: "卜",
        0x2F19: "卩", 0x2F1A: "厂", 0x2F1B: "厶", 0x2F1C: "又", 0x2F1D: "口",
        0x2F1E: "囗", 0x2F1F: "土", 0x2F20: "士", 0x2F21: "夂", 0x2F22: "夊",
        0x2F23: "夕", 0x2F24: "大", 0x2F25: "女", 0x2F26: "子", 0x2F27: "宀",
        0x2F28: "寸", 0x2F29: "小", 0x2F2A: "尢", 0x2F2B: "尸", 0x2F2C: "屮",
        0x2F2D: "山", 0x2F2E: "巛", 0x2F2F: "工", 0x2F30: "己", 0x2F31: "巾",
        0x2F32: "干", 0x2F33: "幺", 0x2F34: "广", 0x2F35: "廴", 0x2F36: "廾",
        0x2F37: "弋", 0x2F38: "弓", 0x2F39: "彐", 0x2F3A: "彡", 0x2F3B: "彳",
        0x2F3C: "心", 0x2F3D: "戈", 0x2F3E: "戶", 0x2F3F: "手", 0x2F40: "支",
        0x2F41: "攴", 0x2F42: "文", 0x2F43: "斗", 0x2F44: "斤", 0x2F45: "方",
        0x2F46: "无", 0x2F47: "日", 0x2F48: "曰", 0x2F49: "月", 0x2F4A: "木",
        0x2F4B: "欠", 0x2F4C: "止", 0x2F4D: "歹", 0x2F4E: "殳", 0x2F4F: "毋",
        0x2F50: "比", 0x2F51: "毛", 0x2F52: "氏", 0x2F53: "气", 0x2F54: "水",
        0x2F55: "火", 0x2F56: "爪", 0x2F57: "父", 0x2F58: "爻", 0x2F59: "爿",
        0x2F5A: "片", 0x2F5B: "牙", 0x2F5C: "牛", 0x2F5D: "犬", 0x2F5E: "玄",
        0x2F5F: "玉", 0x2F60: "瓜", 0x2F61: "瓦", 0x2F62: "甘", 0x2F63: "生",
        0x2F64: "用", 0x2F65: "田", 0x2F66: "疋", 0x2F67: "疒", 0x2F68: "癶",
        0x2F69: "白", 0x2F6A: "皮", 0x2F6B: "皿", 0x2F6C: "目", 0x2F6D: "矛",
        0x2F6E: "矢", 0x2F6F: "石", 0x2F70: "示", 0x2F71: "禸", 0x2F72: "禾",
        0x2F73: "穴", 0x2F74: "立", 0x2F75: "竹", 0x2F76: "米", 0x2F77: "糸",
        0x2F78: "缶", 0x2F79: "网", 0x2F7A: "羊", 0x2F7B: "羽", 0x2F7C: "老",
        0x2F7D: "而", 0x2F7E: "耒", 0x2F7F: "耳", 0x2F80: "聿", 0x2F81: "肉",
        0x2F82: "臣", 0x2F83: "自", 0x2F84: "至", 0x2F85: "臼", 0x2F86: "舌",
        0x2F87: "舛", 0x2F88: "舟", 0x2F89: "艮", 0x2F8A: "色", 0x2F8B: "艸",
        0x2F8C: "虍", 0x2F8D: "虫", 0x2F8E: "血", 0x2F8F: "行", 0x2F90: "衣",
        0x2F91: "襾", 0x2F92: "見", 0x2F93: "角", 0x2F94: "言", 0x2F95: "谷",
        0x2F96: "豆", 0x2F97: "豕", 0x2F98: "豸", 0x2F99: "貝", 0x2F9A: "赤",
        0x2F9B: "走", 0x2F9C: "足", 0x2F9D: "身", 0x2F9E: "車", 0x2F9F: "辛",
        0x2FA0: "辰", 0x2FA1: "辵", 0x2FA2: "邑", 0x2FA3: "酉", 0x2FA4: "釆",
        0x2FA5: "里", 0x2FA6: "金", 0x2FA7: "長", 0x2FA8: "門", 0x2FA9: "阜",
        0x2FAA: "隶", 0x2FAB: "隹", 0x2FAC: "雨", 0x2FAD: "靑", 0x2FAE: "非",
        0x2FAF: "面", 0x2FB0: "革", 0x2FB1: "韋", 0x2FB2: "韭", 0x2FB3: "音",
        0x2FB4: "頁", 0x2FB5: "風", 0x2FB6: "飛", 0x2FB7: "食", 0x2FB8: "首",
        0x2FB9: "香", 0x2FBA: "馬", 0x2FBB: "骨", 0x2FBC: "高", 0x2FBD: "髟",
        0x2FBE: "鬥", 0x2FBF: "鬯", 0x2FC0: "鬲", 0x2FC1: "鬼", 0x2FC2: "魚",
        0x2FC3: "鳥", 0x2FC4: "鹵", 0x2FC5: "鹿", 0x2FC6: "麥", 0x2FC7: "麻",
        0x2FC8: "黃", 0x2FC9: "黍", 0x2FCA: "黑", 0x2FCB: "黹", 0x2FCC: "黽",
        0x2FCD: "鼎", 0x2FCE: "鼓", 0x2FCF: "鼠", 0x2FD0: "鼻", 0x2FD1: "齊",
        0x2FD2: "齒", 0x2FD3: "龍", 0x2FD4: "龜", 0x2FD5: "龠",
    }
    # Parenthesized enclosed CJK forms the as-is branch must
    # remap first: the parenthesized members of U+3200-U+32FF
    # (the same ranges the enclosed branch below gates on)
    # remap under UTS46 to a parenthesized letter (㈀ -> "(ᄀ)",
    # ㈠ -> "(一)", ㈜ -> "(株)") or, for the circled Hangul
    # jamo U+3260-U+326D, to the bare jamo (㉠ -> ᄀ), verified
    # against the package's uts46_remap for all 81 differing
    # members (U+3248-U+324F and U+327F map to themselves, so
    # they need no entry; browser-rejected U+321F is excluded).
    # The as-is branch below punycodes its label directly,
    # because the package rejects the as-is member under both
    # strict and UTS46 processing -- but browsers remap the
    # parenthesized member first, so a label mixing one with
    # an as-is member punycoded raw never matched ("©㈀" ->
    # helper "xn--gba673w", browser "xn--()-sda748n", which
    # decodes to the remapped "©(ᄀ)"). Translating through
    # this table before punycoding reproduces the browser
    # form; labels without a parenthesized member are
    # unchanged, and the table's outputs need no further
    # remap (ASCII parens and CJK/Hangul letters; translate
    # does not recurse, matching UTS46's single mapping pass,
    # and the table is applied last so no earlier remap can
    # rewrite its outputs). The standalone as-is branch below
    # applies it; mixes with other UTS46-remapped classes keep
    # their existing behaviour for separate assessment.
    _parenthesized_cjk_remap = {
        0x3200: "(ᄀ)", 0x3201: "(ᄂ)", 0x3202: "(ᄃ)", 0x3203: "(ᄅ)", 0x3204: "(ᄆ)",
        0x3205: "(ᄇ)", 0x3206: "(ᄉ)", 0x3207: "(ᄋ)", 0x3208: "(ᄌ)", 0x3209: "(ᄎ)",
        0x320A: "(ᄏ)", 0x320B: "(ᄐ)", 0x320C: "(ᄑ)", 0x320D: "(ᄒ)", 0x320E: "(가)",
        0x320F: "(나)", 0x3210: "(다)", 0x3211: "(라)", 0x3212: "(마)", 0x3213: "(바)",
        0x3214: "(사)", 0x3215: "(아)", 0x3216: "(자)", 0x3217: "(차)", 0x3218: "(카)",
        0x3219: "(타)", 0x321A: "(파)", 0x321B: "(하)", 0x321C: "(주)", 0x321D: "(오전)",
        0x321E: "(오후)", 0x3220: "(一)", 0x3221: "(二)", 0x3222: "(三)", 0x3223: "(四)",
        0x3224: "(五)", 0x3225: "(六)", 0x3226: "(七)", 0x3227: "(八)", 0x3228: "(九)",
        0x3229: "(十)", 0x322A: "(月)", 0x322B: "(火)", 0x322C: "(水)", 0x322D: "(木)",
        0x322E: "(金)", 0x322F: "(土)", 0x3230: "(日)", 0x3231: "(株)", 0x3232: "(有)",
        0x3233: "(社)", 0x3234: "(名)", 0x3235: "(特)", 0x3236: "(財)", 0x3237: "(祝)",
        0x3238: "(労)", 0x3239: "(代)", 0x323A: "(呼)", 0x323B: "(学)", 0x323C: "(監)",
        0x323D: "(企)", 0x323E: "(資)", 0x323F: "(協)", 0x3240: "(祭)", 0x3241: "(休)",
        0x3242: "(自)", 0x3243: "(至)", 0x3260: "ᄀ", 0x3261: "ᄂ", 0x3262: "ᄃ",
        0x3263: "ᄅ", 0x3264: "ᄆ", 0x3265: "ᄇ", 0x3266: "ᄉ", 0x3267: "ᄋ",
        0x3268: "ᄌ", 0x3269: "ᄎ", 0x326A: "ᄏ", 0x326B: "ᄐ", 0x326C: "ᄑ",
        0x326D: "ᄒ",
    }
    # CJK Compatibility Ideographs the as-is branch must remap
    # first: every differing member of _punycode_cjk_compat above
    # (U+F900-U+FA6D and U+FA70-U+FAD9) remaps under UTS46 to a
    # single unified CJK ideograph (e.g. \uF900 -> \u8C48,
    # \uF901 -> \u66F4, \uFAD9 -> \u9F8E), verified against the
    # package's uts46_remap for all 460 (the 12 identity members
    # U+FA0E, U+FA0F, U+FA11, U+FA13, U+FA14, U+FA1F, U+FA21,
    # U+FA23, U+FA24, U+FA27, U+FA28 and U+FA29 map to themselves
    # and need no entry). The as-is branch below punycodes its
    # label directly, because the package rejects the as-is member
    # under both strict and UTS46 processing -- but browsers
    # remap the compat ideograph first, so a label mixing one
    # with an as-is member punycoded raw never matched ("\u00A9\uF900"
    # -> helper "xn--gba4628j", browser "xn--gba0062e", which
    # decodes to the remapped "\u00A9\u8C48"). Translating through
    # this table before punycoding reproduces the browser form;
    # labels without a compat ideograph are unchanged, and the
    # table's outputs need no further remap (unified CJK
    # ideographs; translate does not recurse, matching UTS46's
    # single mapping pass, and the table is applied last so no
    # earlier remap can rewrite its outputs). The standalone
    # as-is branch below applies it; mixes with other
    # UTS46-remapped classes keep their existing behaviour for
    # separate assessment.
    _cjk_compat_remap = {
        0xF900: "豈", 0xF901: "更", 0xF902: "車", 0xF903: "賈", 0xF904: "滑",
        0xF905: "串", 0xF906: "句", 0xF907: "龜", 0xF908: "龜", 0xF909: "契",
        0xF90A: "金", 0xF90B: "喇", 0xF90C: "奈", 0xF90D: "懶", 0xF90E: "癩",
        0xF90F: "羅", 0xF910: "蘿", 0xF911: "螺", 0xF912: "裸", 0xF913: "邏",
        0xF914: "樂", 0xF915: "洛", 0xF916: "烙", 0xF917: "珞", 0xF918: "落",
        0xF919: "酪", 0xF91A: "駱", 0xF91B: "亂", 0xF91C: "卵", 0xF91D: "欄",
        0xF91E: "爛", 0xF91F: "蘭", 0xF920: "鸞", 0xF921: "嵐", 0xF922: "濫",
        0xF923: "藍", 0xF924: "襤", 0xF925: "拉", 0xF926: "臘", 0xF927: "蠟",
        0xF928: "廊", 0xF929: "朗", 0xF92A: "浪", 0xF92B: "狼", 0xF92C: "郎",
        0xF92D: "來", 0xF92E: "冷", 0xF92F: "勞", 0xF930: "擄", 0xF931: "櫓",
        0xF932: "爐", 0xF933: "盧", 0xF934: "老", 0xF935: "蘆", 0xF936: "虜",
        0xF937: "路", 0xF938: "露", 0xF939: "魯", 0xF93A: "鷺", 0xF93B: "碌",
        0xF93C: "祿", 0xF93D: "綠", 0xF93E: "菉", 0xF93F: "錄", 0xF940: "鹿",
        0xF941: "論", 0xF942: "壟", 0xF943: "弄", 0xF944: "籠", 0xF945: "聾",
        0xF946: "牢", 0xF947: "磊", 0xF948: "賂", 0xF949: "雷", 0xF94A: "壘",
        0xF94B: "屢", 0xF94C: "樓", 0xF94D: "淚", 0xF94E: "漏", 0xF94F: "累",
        0xF950: "縷", 0xF951: "陋", 0xF952: "勒", 0xF953: "肋", 0xF954: "凜",
        0xF955: "凌", 0xF956: "稜", 0xF957: "綾", 0xF958: "菱", 0xF959: "陵",
        0xF95A: "讀", 0xF95B: "拏", 0xF95C: "樂", 0xF95D: "諾", 0xF95E: "丹",
        0xF95F: "寧", 0xF960: "怒", 0xF961: "率", 0xF962: "異", 0xF963: "北",
        0xF964: "磻", 0xF965: "便", 0xF966: "復", 0xF967: "不", 0xF968: "泌",
        0xF969: "數", 0xF96A: "索", 0xF96B: "參", 0xF96C: "塞", 0xF96D: "省",
        0xF96E: "葉", 0xF96F: "說", 0xF970: "殺", 0xF971: "辰", 0xF972: "沈",
        0xF973: "拾", 0xF974: "若", 0xF975: "掠", 0xF976: "略", 0xF977: "亮",
        0xF978: "兩", 0xF979: "凉", 0xF97A: "梁", 0xF97B: "糧", 0xF97C: "良",
        0xF97D: "諒", 0xF97E: "量", 0xF97F: "勵", 0xF980: "呂", 0xF981: "女",
        0xF982: "廬", 0xF983: "旅", 0xF984: "濾", 0xF985: "礪", 0xF986: "閭",
        0xF987: "驪", 0xF988: "麗", 0xF989: "黎", 0xF98A: "力", 0xF98B: "曆",
        0xF98C: "歷", 0xF98D: "轢", 0xF98E: "年", 0xF98F: "憐", 0xF990: "戀",
        0xF991: "撚", 0xF992: "漣", 0xF993: "煉", 0xF994: "璉", 0xF995: "秊",
        0xF996: "練", 0xF997: "聯", 0xF998: "輦", 0xF999: "蓮", 0xF99A: "連",
        0xF99B: "鍊", 0xF99C: "列", 0xF99D: "劣", 0xF99E: "咽", 0xF99F: "烈",
        0xF9A0: "裂", 0xF9A1: "說", 0xF9A2: "廉", 0xF9A3: "念", 0xF9A4: "捻",
        0xF9A5: "殮", 0xF9A6: "簾", 0xF9A7: "獵", 0xF9A8: "令", 0xF9A9: "囹",
        0xF9AA: "寧", 0xF9AB: "嶺", 0xF9AC: "怜", 0xF9AD: "玲", 0xF9AE: "瑩",
        0xF9AF: "羚", 0xF9B0: "聆", 0xF9B1: "鈴", 0xF9B2: "零", 0xF9B3: "靈",
        0xF9B4: "領", 0xF9B5: "例", 0xF9B6: "禮", 0xF9B7: "醴", 0xF9B8: "隸",
        0xF9B9: "惡", 0xF9BA: "了", 0xF9BB: "僚", 0xF9BC: "寮", 0xF9BD: "尿",
        0xF9BE: "料", 0xF9BF: "樂", 0xF9C0: "燎", 0xF9C1: "療", 0xF9C2: "蓼",
        0xF9C3: "遼", 0xF9C4: "龍", 0xF9C5: "暈", 0xF9C6: "阮", 0xF9C7: "劉",
        0xF9C8: "杻", 0xF9C9: "柳", 0xF9CA: "流", 0xF9CB: "溜", 0xF9CC: "琉",
        0xF9CD: "留", 0xF9CE: "硫", 0xF9CF: "紐", 0xF9D0: "類", 0xF9D1: "六",
        0xF9D2: "戮", 0xF9D3: "陸", 0xF9D4: "倫", 0xF9D5: "崙", 0xF9D6: "淪",
        0xF9D7: "輪", 0xF9D8: "律", 0xF9D9: "慄", 0xF9DA: "栗", 0xF9DB: "率",
        0xF9DC: "隆", 0xF9DD: "利", 0xF9DE: "吏", 0xF9DF: "履", 0xF9E0: "易",
        0xF9E1: "李", 0xF9E2: "梨", 0xF9E3: "泥", 0xF9E4: "理", 0xF9E5: "痢",
        0xF9E6: "罹", 0xF9E7: "裏", 0xF9E8: "裡", 0xF9E9: "里", 0xF9EA: "離",
        0xF9EB: "匿", 0xF9EC: "溺", 0xF9ED: "吝", 0xF9EE: "燐", 0xF9EF: "璘",
        0xF9F0: "藺", 0xF9F1: "隣", 0xF9F2: "鱗", 0xF9F3: "麟", 0xF9F4: "林",
        0xF9F5: "淋", 0xF9F6: "臨", 0xF9F7: "立", 0xF9F8: "笠", 0xF9F9: "粒",
        0xF9FA: "狀", 0xF9FB: "炙", 0xF9FC: "識", 0xF9FD: "什", 0xF9FE: "茶",
        0xF9FF: "刺", 0xFA00: "切", 0xFA01: "度", 0xFA02: "拓", 0xFA03: "糖",
        0xFA04: "宅", 0xFA05: "洞", 0xFA06: "暴", 0xFA07: "輻", 0xFA08: "行",
        0xFA09: "降", 0xFA0A: "見", 0xFA0B: "廓", 0xFA0C: "兀", 0xFA0D: "嗀",
        0xFA10: "塚", 0xFA12: "晴", 0xFA15: "凞", 0xFA16: "猪", 0xFA17: "益",
        0xFA18: "礼", 0xFA19: "神", 0xFA1A: "祥", 0xFA1B: "福", 0xFA1C: "靖",
        0xFA1D: "精", 0xFA1E: "羽", 0xFA20: "蘒", 0xFA22: "諸", 0xFA25: "逸",
        0xFA26: "都", 0xFA2A: "飯", 0xFA2B: "飼", 0xFA2C: "館", 0xFA2D: "鶴",
        0xFA2E: "郞", 0xFA2F: "隷", 0xFA30: "侮", 0xFA31: "僧", 0xFA32: "免",
        0xFA33: "勉", 0xFA34: "勤", 0xFA35: "卑", 0xFA36: "喝", 0xFA37: "嘆",
        0xFA38: "器", 0xFA39: "塀", 0xFA3A: "墨", 0xFA3B: "層", 0xFA3C: "屮",
        0xFA3D: "悔", 0xFA3E: "慨", 0xFA3F: "憎", 0xFA40: "懲", 0xFA41: "敏",
        0xFA42: "既", 0xFA43: "暑", 0xFA44: "梅", 0xFA45: "海", 0xFA46: "渚",
        0xFA47: "漢", 0xFA48: "煮", 0xFA49: "爫", 0xFA4A: "琢", 0xFA4B: "碑",
        0xFA4C: "社", 0xFA4D: "祉", 0xFA4E: "祈", 0xFA4F: "祐", 0xFA50: "祖",
        0xFA51: "祝", 0xFA52: "禍", 0xFA53: "禎", 0xFA54: "穀", 0xFA55: "突",
        0xFA56: "節", 0xFA57: "練", 0xFA58: "縉", 0xFA59: "繁", 0xFA5A: "署",
        0xFA5B: "者", 0xFA5C: "臭", 0xFA5D: "艹", 0xFA5E: "艹", 0xFA5F: "著",
        0xFA60: "褐", 0xFA61: "視", 0xFA62: "謁", 0xFA63: "謹", 0xFA64: "賓",
        0xFA65: "贈", 0xFA66: "辶", 0xFA67: "逸", 0xFA68: "難", 0xFA69: "響",
        0xFA6A: "頻", 0xFA6B: "恵", 0xFA6C: "𤋮", 0xFA6D: "舘", 0xFA70: "並",
        0xFA71: "况", 0xFA72: "全", 0xFA73: "侀", 0xFA74: "充", 0xFA75: "冀",
        0xFA76: "勇", 0xFA77: "勺", 0xFA78: "喝", 0xFA79: "啕", 0xFA7A: "喙",
        0xFA7B: "嗢", 0xFA7C: "塚", 0xFA7D: "墳", 0xFA7E: "奄", 0xFA7F: "奔",
        0xFA80: "婢", 0xFA81: "嬨", 0xFA82: "廒", 0xFA83: "廙", 0xFA84: "彩",
        0xFA85: "徭", 0xFA86: "惘", 0xFA87: "慎", 0xFA88: "愈", 0xFA89: "憎",
        0xFA8A: "慠", 0xFA8B: "懲", 0xFA8C: "戴", 0xFA8D: "揄", 0xFA8E: "搜",
        0xFA8F: "摒", 0xFA90: "敖", 0xFA91: "晴", 0xFA92: "朗", 0xFA93: "望",
        0xFA94: "杖", 0xFA95: "歹", 0xFA96: "殺", 0xFA97: "流", 0xFA98: "滛",
        0xFA99: "滋", 0xFA9A: "漢", 0xFA9B: "瀞", 0xFA9C: "煮", 0xFA9D: "瞧",
        0xFA9E: "爵", 0xFA9F: "犯", 0xFAA0: "猪", 0xFAA1: "瑱", 0xFAA2: "甆",
        0xFAA3: "画", 0xFAA4: "瘝", 0xFAA5: "瘟", 0xFAA6: "益", 0xFAA7: "盛",
        0xFAA8: "直", 0xFAA9: "睊", 0xFAAA: "着", 0xFAAB: "磌", 0xFAAC: "窱",
        0xFAAD: "節", 0xFAAE: "类", 0xFAAF: "絛", 0xFAB0: "練", 0xFAB1: "缾",
        0xFAB2: "者", 0xFAB3: "荒", 0xFAB4: "華", 0xFAB5: "蝹", 0xFAB6: "襁",
        0xFAB7: "覆", 0xFAB8: "視", 0xFAB9: "調", 0xFABA: "諸", 0xFABB: "請",
        0xFABC: "謁", 0xFABD: "諾", 0xFABE: "諭", 0xFABF: "謹", 0xFAC0: "變",
        0xFAC1: "贈", 0xFAC2: "輸", 0xFAC3: "遲", 0xFAC4: "醙", 0xFAC5: "鉶",
        0xFAC6: "陼", 0xFAC7: "難", 0xFAC8: "靖", 0xFAC9: "韛", 0xFACA: "響",
        0xFACB: "頋", 0xFACC: "頻", 0xFACD: "鬒", 0xFACE: "龜", 0xFACF: "𢡊",
        0xFAD0: "𢡄", 0xFAD1: "𣏕", 0xFAD2: "㮝", 0xFAD3: "䀘", 0xFAD4: "䀹",
        0xFAD5: "𥉉", 0xFAD6: "𥳐", 0xFAD7: "𧻓", 0xFAD8: "齃", 0xFAD9: "龎",
    }
    # CJK Compatibility square forms the fraction branch must
    # remap first: every member of _punycode_square_cjk above
    # (U+3300-U+33FF, 246 members) remaps under UTS46 to a
    # katakana phrase, an ASCII unit, or a digit-plus-day form
    # (e.g. U+3300 -> "アパート", U+3371 -> "hpa",
    # U+33FB -> "28日"), verified against the package's
    # uts46_remap for all 246, with no identity members and no
    # raises. The standalone square members already reproduce
    # via the UTS46 retry above, but a label mixing one with a
    # fraction is claimed by the fraction branch first, whose
    # gate lacked a square candidate, so it fell through to
    # None even though the browser carries the remapped form
    # ("¼" + U+3371 -> "1⁄4hpa" -> "xn--14hpa-d33b"). This
    # table is disjoint from _asis_map's seven square entries
    # (U+33A7/U+33A8/U+33AE/U+33AF/U+33C6/U+33DE/U+33DF, whose
    # expansions contain the fraction slash and are already
    # covered by the as-is candidate), so the chained form is
    # identity for labels without a square member, and its
    # outputs need no further remap (translate does not
    # recurse, matching UTS46's single mapping pass). The
    # fraction branch below applies it; mixes with other
    # UTS46-remapped classes keep their existing behaviour
    # for separate assessment.
    _square_cjk_remap = {
        0x3300: "アパート", 0x3301: "アルファ", 0x3302: "アンペア", 0x3303: "アール", 0x3304: "イニング",
        0x3305: "インチ", 0x3306: "ウォン", 0x3307: "エスクード", 0x3308: "エーカー", 0x3309: "オンス",
        0x330A: "オーム", 0x330B: "カイリ", 0x330C: "カラット", 0x330D: "カロリー", 0x330E: "ガロン",
        0x330F: "ガンマ", 0x3310: "ギガ", 0x3311: "ギニー", 0x3312: "キュリー", 0x3313: "ギルダー",
        0x3314: "キロ", 0x3315: "キログラム", 0x3316: "キロメートル", 0x3317: "キロワット", 0x3318: "グラム",
        0x3319: "グラムトン", 0x331A: "クルゼイロ", 0x331B: "クローネ", 0x331C: "ケース", 0x331D: "コルナ",
        0x331E: "コーポ", 0x331F: "サイクル", 0x3320: "サンチーム", 0x3321: "シリング", 0x3322: "センチ",
        0x3323: "セント", 0x3324: "ダース", 0x3325: "デシ", 0x3326: "ドル", 0x3327: "トン",
        0x3328: "ナノ", 0x3329: "ノット", 0x332A: "ハイツ", 0x332B: "パーセント", 0x332C: "パーツ",
        0x332D: "バーレル", 0x332E: "ピアストル", 0x332F: "ピクル", 0x3330: "ピコ", 0x3331: "ビル",
        0x3332: "ファラッド", 0x3333: "フィート", 0x3334: "ブッシェル", 0x3335: "フラン", 0x3336: "ヘクタール",
        0x3337: "ペソ", 0x3338: "ペニヒ", 0x3339: "ヘルツ", 0x333A: "ペンス", 0x333B: "ページ",
        0x333C: "ベータ", 0x333D: "ポイント", 0x333E: "ボルト", 0x333F: "ホン", 0x3340: "ポンド",
        0x3341: "ホール", 0x3342: "ホーン", 0x3343: "マイクロ", 0x3344: "マイル", 0x3345: "マッハ",
        0x3346: "マルク", 0x3347: "マンション", 0x3348: "ミクロン", 0x3349: "ミリ", 0x334A: "ミリバール",
        0x334B: "メガ", 0x334C: "メガトン", 0x334D: "メートル", 0x334E: "ヤード", 0x334F: "ヤール",
        0x3350: "ユアン", 0x3351: "リットル", 0x3352: "リラ", 0x3353: "ルピー", 0x3354: "ルーブル",
        0x3355: "レム", 0x3356: "レントゲン", 0x3357: "ワット", 0x3358: "0点", 0x3359: "1点",
        0x335A: "2点", 0x335B: "3点", 0x335C: "4点", 0x335D: "5点", 0x335E: "6点",
        0x335F: "7点", 0x3360: "8点", 0x3361: "9点", 0x3362: "10点", 0x3363: "11点",
        0x3364: "12点", 0x3365: "13点", 0x3366: "14点", 0x3367: "15点", 0x3368: "16点",
        0x3369: "17点", 0x336A: "18点", 0x336B: "19点", 0x336C: "20点", 0x336D: "21点",
        0x336E: "22点", 0x336F: "23点", 0x3370: "24点", 0x3371: "hpa", 0x3372: "da",
        0x3373: "au", 0x3374: "bar", 0x3375: "ov", 0x3376: "pc", 0x3377: "dm",
        0x3378: "dm2", 0x3379: "dm3", 0x337A: "iu", 0x337B: "平成", 0x337C: "昭和",
        0x337D: "大正", 0x337E: "明治", 0x337F: "株式会社", 0x3380: "pa", 0x3381: "na",
        0x3382: "μa", 0x3383: "ma", 0x3384: "ka", 0x3385: "kb", 0x3386: "mb",
        0x3387: "gb", 0x3388: "cal", 0x3389: "kcal", 0x338A: "pf", 0x338B: "nf",
        0x338C: "μf", 0x338D: "μg", 0x338E: "mg", 0x338F: "kg", 0x3390: "hz",
        0x3391: "khz", 0x3392: "mhz", 0x3393: "ghz", 0x3394: "thz", 0x3395: "μl",
        0x3396: "ml", 0x3397: "dl", 0x3398: "kl", 0x3399: "fm", 0x339A: "nm",
        0x339B: "μm", 0x339C: "mm", 0x339D: "cm", 0x339E: "km", 0x339F: "mm2",
        0x33A0: "cm2", 0x33A1: "m2", 0x33A2: "km2", 0x33A3: "mm3", 0x33A4: "cm3",
        0x33A5: "m3", 0x33A6: "km3", 0x33A9: "pa", 0x33AA: "kpa", 0x33AB: "mpa",
        0x33AC: "gpa", 0x33AD: "rad", 0x33B0: "ps", 0x33B1: "ns", 0x33B2: "μs",
        0x33B3: "ms", 0x33B4: "pv", 0x33B5: "nv", 0x33B6: "μv", 0x33B7: "mv",
        0x33B8: "kv", 0x33B9: "mv", 0x33BA: "pw", 0x33BB: "nw", 0x33BC: "μw",
        0x33BD: "mw", 0x33BE: "kw", 0x33BF: "mw", 0x33C0: "kω", 0x33C1: "mω",
        0x33C3: "bq", 0x33C4: "cc", 0x33C5: "cd", 0x33C8: "db", 0x33C9: "gy",
        0x33CA: "ha", 0x33CB: "hp", 0x33CC: "in", 0x33CD: "kk", 0x33CE: "km",
        0x33CF: "kt", 0x33D0: "lm", 0x33D1: "ln", 0x33D2: "log", 0x33D3: "lx",
        0x33D4: "mb", 0x33D5: "mil", 0x33D6: "mol", 0x33D7: "ph", 0x33D9: "ppm",
        0x33DA: "pr", 0x33DB: "sr", 0x33DC: "sv", 0x33DD: "wb", 0x33E0: "1日",
        0x33E1: "2日", 0x33E2: "3日", 0x33E3: "4日", 0x33E4: "5日", 0x33E5: "6日",
        0x33E6: "7日", 0x33E7: "8日", 0x33E8: "9日", 0x33E9: "10日", 0x33EA: "11日",
        0x33EB: "12日", 0x33EC: "13日", 0x33ED: "14日", 0x33EE: "15日", 0x33EF: "16日",
        0x33F0: "17日", 0x33F1: "18日", 0x33F2: "19日", 0x33F3: "20日", 0x33F4: "21日",
        0x33F5: "22日", 0x33F6: "23日", 0x33F7: "24日", 0x33F8: "25日", 0x33F9: "26日",
        0x33FA: "27日", 0x33FB: "28日", 0x33FC: "29日", 0x33FD: "30日", 0x33FE: "31日",
        0x33FF: "gal",
    }

    # Hebrew Alphabetic Presentation Forms the as-is branch must
    # remap first: every member of _punycode_hebrew_presentation
    # above (U+FB1D, U+FB1F-U+FB28, U+FB2A-U+FB36, U+FB38-U+FB3C,
    # U+FB3E, U+FB40-U+FB41, U+FB43-U+FB44, U+FB46-U+FB4F)
    # remaps under UTS46 to a Hebrew letter / letter-plus-point
    # form (e.g. U+FB1D -> U+05D9 U+05B4, U+FB2C ->
    # U+05E9 U+05BC U+05C1, U+FB4F -> U+05D0 U+05DC), verified
    # against the package's uts46_remap for all 44, with no
    # identity members and no raises. The as-is branch below
    # punycodes its label directly, because the package rejects
    # the as-is member under both strict and UTS46 processing --
    # but browsers remap the presentation form first, so a label
    # mixing one with an as-is member punycoded raw never
    # matched ("ا©יִ" -> helper "xn--gba52zg37v", browser
    # "xn--gba69wfd8m", which decodes to the remapped "ا©יִ").
    # Translating through this table before punycoding
    # reproduces the browser form; labels without a Hebrew
    # presentation form are unchanged, and the table's outputs
    # need no further remap (Hebrew letters and nonspacing
    # marks; translate does not recurse, matching UTS46's
    # single mapping pass, and the table is applied last so no
    # earlier remap can rewrite its outputs). U+FB29 is
    # excluded: UTS46 maps it to "+" (a different fix class,
    # since the package rejects "+" itself), as in the set
    # above. The standalone as-is branch below applies it, as
    # does the underscore fallback; mixes with an Arabic
    # presentation form already work via the RTL-context
    # branch above, and fraction mixes keep their existing
    # behaviour for separate assessment.
    _hebrew_presentation_remap = {
        0xFB1D: 'יִ', 0xFB1F: 'ײַ', 0xFB20: 'ע', 0xFB21: 'א',
        0xFB22: 'ד', 0xFB23: 'ה', 0xFB24: 'כ', 0xFB25: 'ל',
        0xFB26: 'ם', 0xFB27: 'ר', 0xFB28: 'ת', 0xFB2A: 'שׁ',
        0xFB2B: 'שׂ', 0xFB2C: 'שּׁ', 0xFB2D: 'שּׂ', 0xFB2E: 'אַ',
        0xFB2F: 'אָ', 0xFB30: 'אּ', 0xFB31: 'בּ', 0xFB32: 'גּ',
        0xFB33: 'דּ', 0xFB34: 'הּ', 0xFB35: 'וּ', 0xFB36: 'זּ',
        0xFB38: 'טּ', 0xFB39: 'יּ', 0xFB3A: 'ךּ', 0xFB3B: 'כּ',
        0xFB3C: 'לּ', 0xFB3E: 'מּ', 0xFB40: 'נּ', 0xFB41: 'סּ',
        0xFB43: 'ףּ', 0xFB44: 'פּ', 0xFB46: 'צּ', 0xFB47: 'קּ',
        0xFB48: 'רּ', 0xFB49: 'שּ', 0xFB4A: 'תּ', 0xFB4B: 'וֹ',
        0xFB4C: 'בֿ', 0xFB4D: 'כֿ', 0xFB4E: 'פֿ', 0xFB4F: 'אל',
    }
    _punycode_asis = frozenset(
        [
            # Latin-1 symbols the browser punycodes as-is (© ->
            # "xn--gba", ° -> "xn--nba") while the package's
            # UTS46 processing rejects them: the FB29-mixed forms
            # ("©﬩" -> "xn--+-mca") already qualified through
            # the FB29 branch, but a standalone label ("©.example")
            # fell through every path above and never matched.
            # The as-is punycode form matches the browser for
            # mixed and underscore labels too ("a©" -> "xn--a-nca",
            # "a_©" -> "xn--a_-uda"), so no separate branch is
            # needed. The same class covers the remaining
            # Latin-1 symbols browsers punycode as-is (¡ -> "xn--7a",
            # ¢ -> "xn--8a", £ -> "xn--9a", ¤ -> "xn--bba",
            # ¥ -> "xn--cba", ¦ -> "xn--dba", § -> "xn--eba",
            # « -> "xn--iba", ® -> "xn--lba", ± -> "xn--oba",
            # ¶ -> "xn--tba", · -> "xn--uba", » -> "xn--yba",
            # ¿ -> "xn--2ba", × -> "xn--rca", ÷ -> "xn--oda"),
            # which likewise returned None standalone and never
            # matched. The soft hyphen U+00AD is deliberately
            # excluded, since browsers strip it rather than
            # punycode it; the UTS46-mapped forms (² -> "2",
            # ³ -> "3", ¹ -> "1", º -> "o") and fractions
            # (¼ -> "1⁄4", ½ -> "1⁄2", ¾ -> "3⁄4") need a
            # remap-before-qualify path rather than as-is
            # entries and are left for separate assessment, as
            # are the browser-rejected forms (¨, ¯, ´, ¸).
            0x00A9, 0x00B0,
            0x00A1, 0x00A2, 0x00A3, 0x00A4, 0x00A5, 0x00A6,
            0x00A7, 0x00AB, 0x00AE, 0x00B1, 0x00B6, 0x00B7,
            0x00BB, 0x00BF, 0x00D7, 0x00F7,
            0x2103, 0x2104, 0x2108, 0x2109, 0x2114, 0x2117,
            0x2118, 0x211E, 0x211F, 0x2123, 0x2125, 0x2127,
            0x2129, 0x212E, 0x2132, 0x213A, 0x2140, 0x2141,
            0x2142, 0x2143, 0x2144, 0x214A, 0x214B, 0x214C,
            0x214D, 0x214F,
            # CJK Compatibility square forms (see the square-CJK
            # comment above): UTS46 maps these seven to
            # division-slash expansions (㎧ -> "m∕s", ㎨ -> "m∕s2",
            # ㎮ -> "rad∕s", ㎯ -> "rad∕s2", ㏆ -> "c∕kg",
            # ㏞ -> "v∕m", ㏟ -> "a∕m"), which the browser then
            # punycodes — but the package rejects both the square
            # forms and U+2215 under strict and UTS46 processing,
            # so they need this branch with the mapping below
            # (same pattern as ℃ -> "°c"), not bare as-is entries.
            0x33A7, 0x33A8, 0x33AE, 0x33AF,
            0x33C6, 0x33DE, 0x33DF,
            # General Punctuation symbols the browser punycodes
            # as-is (‐ -> "xn--4ug", – -> "xn--7ug",
            # ’ -> "xn--evg", † -> "xn--lvg", ‰ -> "xn--1vg")
            # while the package's UTS46 processing rejects them,
            # so neither the strict path nor the retry above
            # reproduces them — same class as the Latin-1 symbols
            # above. The six UTS46 expansion forms (‑, ″, ‴,
            # ‶, ‷, ⁗) are included here with their expansions in
            # _asis_map above. Deliberately excluded: the
            # browser-stripped forms (U+200B, U+2060-U+2064,
            # U+206A-U+206F — browsers drop them rather than
            # punycode them, like the soft hyphen U+00AD),
            # the UTS46-mapped U+203C (‼ -> "!!"), which has its
            # own branch in the label loop below (an up-front
            # translate alone would not work, since the strict
            # path rejects the mapped "!"), and the
            # browser-rejected forms
            # (U+2017, U+200C/U+200D, spaces, U+2024, U+2028/29).
            0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015,
            0x2016, 0x2018, 0x2019, 0x201A, 0x201B, 0x201C,
            0x201D, 0x201E, 0x201F, 0x2020, 0x2021, 0x2022,
            0x2023, 0x2027, 0x2030, 0x2031, 0x2032, 0x2033,
            0x2034, 0x2035, 0x2036, 0x2037, 0x2038, 0x2039,
            0x203A, 0x203B, 0x203D, 0x203F, 0x2040, 0x2041,
            0x2042, 0x2043, 0x2044, 0x2045, 0x2046, 0x204A,
            0x204B, 0x204C, 0x204D, 0x204E, 0x204F, 0x2050,
            0x2051, 0x2052, 0x2053, 0x2054, 0x2055, 0x2056,
            0x2057, 0x2058, 0x2059, 0x205A, 0x205B, 0x205C,
            0x205D, 0x205E,
            # Combining marks U+1ACF-U+1AEB (same class as the
            # Latin-1 symbols above, but marks rather than
            # symbols): browsers serialize them as-is
            # ("a᫏" -> "xn--a-58k", "᫏a" ->
            # "xn--a-48k", "a᪾᫏" -> "xn--a-67kvc",
            # "a_᫏" -> "xn--a_-lrq"), while the `idna`
            # package rejects them under strict and UTS46
            # processing — they are unassigned in this
            # Python's Unicode data (15.0.0), so no
            # category-gated branch below can qualify them
            # and neither the strict path nor the retry
            # reproduces them. Verified as-is against Node's
            # WHATWG parser for every member across six
            # shapes (after a base letter, label-initial,
            # mid-label, underscore, and mixed with U+1ABE
            # in both orders). Deliberately excluded:
            # U+1ADE and U+1ADF, which browsers reject in
            # every shape, matching the helper's None, and
            # U+1AC0 and the rest of U+1AB0-U+1AC0, which
            # are browser-rejected at a label start as
            # noted in the U+1DFA branch below.
            0x1ACF,
            0x1AD0, 0x1AD1, 0x1AD2, 0x1AD3, 0x1AD4, 0x1AD5,
            0x1AD6, 0x1AD7, 0x1AD8, 0x1AD9, 0x1ADA, 0x1ADB,
            0x1ADC, 0x1ADD,
            0x1AE0, 0x1AE1, 0x1AE2, 0x1AE3, 0x1AE4, 0x1AE5,
            0x1AE6, 0x1AE7, 0x1AE8, 0x1AE9, 0x1AEA, 0x1AEB,
        ]
    )
    # UTS46 maps the vulgar fractions VULGAR FRACTION ONE
    # QUARTER U+00BC, ONE HALF U+00BD and THREE QUARTERS
    # U+00BE to their digit-plus-fraction-slash expansions
    # (¼ -> "1⁄4", ½ -> "1⁄2", ¾ -> "3⁄4") before IDNA
    # processing, while the `idna` package rejects them under
    # both strict and UTS46 processing — so a configured origin
    # containing one was left alone and never matched under
    # Starlette's exact allow_origins matching (and an
    # underscore label even produced a wrong form, punycoding
    # the raw fraction: "a_¼" -> "xn--a_-hfa" instead of the
    # browser's "xn--a_14-2g7a"). The superscript and ordinal
    # forms (²/³/¹/º/ª) need no entry here: the package's UTS46
    # processing already maps them to plain forms, as the
    # probe in this iteration confirmed. The same class covers
    # the remaining Number Forms vulgar fractions, which the
    # package likewise rejects while browsers expand them
    # (⅓ -> "1⁄3", "ا⅓" -> "xn--13-btd558x"): U+2150-U+215E
    # (⅐ ⅑ ⅒ ⅓ ⅔ ⅕ ⅖ ⅗ ⅘ ⅙ ⅚ ⅛ ⅜ ⅝ ⅞), U+215F (⅟ -> "1⁄",
    # the fraction slash with an empty denominator) and U+2189
    # (↉ -> "0⁄3"). They need no new branch: every gate in
    # the fraction branch below is built from this map, so
    # adding the entries extends the main, recovery, as-is
    # and RTL gates to them unchanged.
    _fraction_map = {
        0x00BC: "1⁄4",
        0x00BD: "1⁄2",
        0x00BE: "3⁄4",
        0x2150: "1⁄7",
        0x2151: "1⁄9",
        0x2152: "1⁄10",
        0x2153: "1⁄3",
        0x2154: "2⁄3",
        0x2155: "1⁄5",
        0x2156: "2⁄5",
        0x2157: "3⁄5",
        0x2158: "4⁄5",
        0x2159: "1⁄6",
        0x215A: "5⁄6",
        0x215B: "1⁄8",
        0x215C: "3⁄8",
        0x215D: "5⁄8",
        0x215E: "7⁄8",
        0x215F: "1⁄",
        0x2189: "0⁄3",
    }
    # UTS46 maps DOUBLE EXCLAMATION MARK U+203C to "!!" (see the
    # dedicated branch in the label loop below).
    _double_excl_map = {0x203C: "!!"}
    # A label combining a fraction with a DOUBLE EXCLAMATION MARK
    # ("¼‼" -> "1⁄4!!" -> "xn--14!!-0g7a") needs both expansions
    # in the fraction branch's gate below: the fraction branch
    # claims such a label before the double-exclamation branch,
    # and its gate previously required the remap to equal the
    # label with exactly the fractions expanded, so the "!!"
    # expansion failed the gate and the label fell through to
    # None (or, with an as-is mark, to the raw-fraction
    # punycode) instead of the browser's form.
    _fraction_excl_map = _fraction_map | _double_excl_map
    # Arabic Presentation Forms-A members the browser punycodes
    # as-is (\"a\\ufbc2b\" -> \"xn--ab-ms1n\", \"a\\ufd3eb\" ->
    # \"xn--ab-6p2n\") while the `idna` package rejects
    # them under both strict and UTS46 processing, so a
    # configured origin containing one was left alone and never
    # matched under Starlette's exact allow_origins matching.
    # These are the remainder of the block the
    # _punycode_arabic_presentation_a comment above leaves alone
    # (\"fail under both strict and UTS46\"): that is true of the
    # package, but Node's WHATWG parser serializes exactly these
    # 48 as-is, so they are the gap, not the package's verdict.
    # Deliberately excluded: U+FBB2-U+FBC1, U+FCD0-U+FDEF and
    # U+FDFA-U+FDFB, which browsers reject (matching the helper's
    # None), and U+FDFC, which the retry above already reproduces.
    # Verified as-is against Node's WHATWG parser for every member
    # in the mid-label shape, plus the standalone, label-initial,
    # underscore, mixed-letter, mixed-mark, Greek, CJK, symbol and
    # emoji shapes; all decode back to the raw label, so no remap
    # is needed — unlike the UTS46-mapped members in
    # _punycode_arabic_presentation_a, which the retry handles.
    # Browsers reject mixes of these forms with a strong-RTL
    # character (Arabic/Hebrew letter, Arabic digit, or another
    # presentation form), and a label starting with a combining
    # mark, so the branch below gates those out rather than
    # emitting a form no browser origin could carry.
    _punycode_arabic_presentation_as_is = (
        frozenset(range(0xFBC2, 0xFBD3))
        | frozenset(range(0xFD3E, 0xFD50))
        | frozenset([0xFD90, 0xFD91])
        | frozenset(range(0xFDC8, 0xFDD0))
        | frozenset(range(0xFDFD, 0xFE00))
    )
    import unicodedata as _arb_unicodedata

    try:
        # ASCII punctuation WHATWG URL domain parsing carries
        # through a label (verified against Node's parser):
        # "!", '"', "$", "&", "'", "(", ")", "*", "+", ",",
        # ";", "=", "`", "{", "}", "~". The hyphen-edge
        # branch below strips these from the label ends when
        # testing for a hyphen edge and admits them in its
        # character gate.
        _hyph_punct = "!\"$&'()*+,;=`{}~"
        # Dash punctuation (category Pd) that UTS46 leaves
        # unchanged but the `idna` package rejects under both
        # strict and UTS46 processing, so a label carrying one
        # fell through to None while browsers punycode it raw
        # ("م⸗م" -> "xn--hhba5961a", "a⸗b" ->
        # "xn--ab-ou2a", verified against Node's WHATWG parser
        # over the whole Pd range). The hyphen-edge branch
        # below admits these in its trigger, and its existing
        # character / RTL gates still decide each label, so a
        # browser-rejected mix (a Latin mix with a
        # right-to-left dash such as U+05BE or U+10EAD, a
        # digit-mixed RTL label, an edge dash on an RTL
        # label) still falls through to None exactly as
        # before. Excluded here: U+002D and U+2010-U+2015
        # and U+FF0D, which already match; and U+1806, whose
        # UTS46 remap raises and which the hyphen-edge
        # branch handles via its own exception below.
        # OBLIQUE HYPHEN U+2E5D is included here: browsers
        # carry it in Latin labels ("a⹝b" -> "xn--ab-o02a",
        # verified against Node's WHATWG parser) while
        # rejecting it in RTL labels, and the hyphen-edge
        # branch's RTL gate below bars it there, so the
        # RTL rejection is preserved without excluding the
        # Latin form.
        # UTS46-mapped dashes are a separate set, handled
        # in the hyphen-edge branch below rather than here:
        # PRESENTATION FORM FOR VERTICAL EM DASH U+FE31
        # and SMALL EM DASH U+FE58 map to EM DASH, U+FE32
        # to EN DASH, and SMALL HYPHEN-MINUS U+FE63 to
        # "-", so a label carrying one fell through to None
        # (or, for underscore labels, punycoded raw) while
        # browsers carry the mapped form ("a︱b" ->
        # "xn--ab-71t", "a﹣b" -> "a-b", "م︱م" ->
        # "xn--hhba439q", verified against Node's WHATWG
        # parser). The hyphen-edge branch admits them in
        # its trigger and accepts the remapped form only
        # when it differs from the label by exactly these
        # mappings, so no other UTS46 mapping can ride
        # along; its existing gates then run on the mapped
        # form, so a browser-rejected shape (an RTL edge
        # dash, a mark-first label, a space mix) still
        # falls through to None exactly as before.
        _dash_punct = frozenset(
            chr(cp)
            for cp in (
                0x058A,
                0x05BE,
                0x1400,
                0x2E17,
                0x2E1A,
                0x2E3A,
                0x2E3B,
                0x2E40,
                0x2E5D,
                0x301C,
                0x3030,
                0x30A0,
                0x10EAD,
            )
        )
        # UTS46-mapped dashes, as a codepoint -> mapped form
        # table for str.translate (see the hyphen-edge branch).
        _mapped_dash = {
            0xFE31: "\u2014",
            0xFE32: "\u2013",
            0xFE58: "\u2014",
            0xFE63: "-",
        }
        encoded_labels = []
        for label in host.split("."):
            if not label:
                encoded_labels.append(label)
            elif any(ord(c) in _fraction_map for c in label):
                # Remap the label and punycode the remapped form
                # directly, as the FB29 branch does for its
                # remapped labels: the fraction slash itself is
                # not IDNA-valid, so the strict path cannot
                # encode the remapped form. The gate requires
                # the remap to change exactly the fractions and
                # any DOUBLE EXCLAMATION MARKS (any other
                # remapped character, e.g. a literal MICRO
                # SIGN in a direct call, falls through to the
                # existing branches unchanged); in the pipeline
                # the up-front translate table has already folded
                # such characters, so the gate passes there. A
                # remap failure likewise falls through, so no
                # label gains a new failure mode. The gate also
                # accepts the Greek-Extended-remapped form (the
                # fraction-expanded label translated through
                # _greek_extended_remap): UTS46 remaps a Greek
                # Extended member first, so a label mixing one
                # with a fraction ("ά¼" -> browser
                # "xn--14-v8b5930a") failed the exact gate above
                # and fell through to None, the same class as
                # the as-is branch's Greek remap; labels without
                # a Greek Extended member are unchanged, since
                # that translate is identity for them.
                try:
                    _frac_remapped = _idna.uts46_remap(
                        label, std3_rules=False, transitional=False
                    )
                except (UnicodeError, ValueError):
                    _frac_remapped = None
                    # Recovery for a label that also contains a
                    # _punycode_asis mark (e.g. U+1ACF-U+1AEB):
                    # the whole-label remap above raises on the
                    # unassigned mark, so such a label fell
                    # through to the as-is branch and punycoded
                    # the raw fraction ("¼᫏" -> "xn--zba464k"
                    # instead of the browser's "xn--14-mrq114a").
                    # The same class covers a label mixing a
                    # fraction with an Arabic presentation form
                    # the package rejects (e.g. U+FBC3-U+FBD2,
                    # U+FD90/U+FD91, U+FDC8-U+FDCE): the
                    # whole-label remap raises on the form, so
                    # such a label fell through to None and never
                    # matched ("¼﯃" -> None instead of the
                    # browser's "xn--14-c6t7249i"), and a mix
                    # with an as-is mark fell through to the
                    # raw-fraction punycode instead ("¼﯃᫏" ->
                    # "xn--zba464kdh3n" instead of
                    # "xn--14-mrq114alt22a"). UTS46 mapping is
                    # per codepoint, so remap each character on
                    # its own, keeping the as-is marks and the
                    # Arabic presentation forms verbatim, and
                    # accept the result only under the same gate
                    # as the normal path (it must equal the label
                    # with exactly the fractions and double
                    # exclamation marks expanded, optionally
                    # further expanded through the as-is map
                    # and the Greek Extended remap): any other
                    # remapped character (e.g. MICRO SIGN -> mu,
                    # or a remap that raises, e.g. an ellipsis or
                    # a browser-rejected U+1ADE/U+1ADF mark) fails
                    # the gate or the remap and falls through
                    # unchanged. ZERO WIDTH JOINER / NON-JOINER
                    # are passed through unchanged by the
                    # single-character remap yet rejected by
                    # browsers, so they abort the recovery too.
                    # For a label with an Arabic presentation
                    # form, two further gates mirror the
                    # as-is branch below: a leading combining
                    # mark and any strong-RTL character outside
                    # the form set (or a space, which the
                    # allowed-character check excludes) are
                    # browser-rejected, so such a label falls
                    # through to None as before instead of
                    # emitting a form no browser origin could
                    # carry; a label with only as-is marks keeps
                    # its previous acceptance unchanged.
                    if any(
                        ord(c) in _punycode_asis
                        or ord(c)
                        in _punycode_arabic_presentation_as_is
                        for c in label
                    ):
                        try:
                            _frac_parts = []
                            for _c in label:
                                if ord(_c) in _asis_map:
                                    # An as-is expansion form
                                    # (DEGREE CELSIUS U+2103 ->
                                    # "°c", DEGREE FAHRENHEIT
                                    # U+2109 -> "°f", the square
                                    # CJK and punctuation
                                    # expansions): keeping it
                                    # verbatim here, as the
                                    # plain as-is members are
                                    # kept below, passed the old
                                    # gate with the raw form and
                                    # punycoded it ("¼℃᫏" ->
                                    # "xn--14-mrq114al1a"
                                    # instead of the browser's
                                    # "xn--14c-tfa0554an3g"),
                                    # so expand it through the
                                    # helper's own as-is map,
                                    # which the gate below then
                                    # matches exactly.
                                    _frac_parts.append(
                                        _asis_map[ord(_c)]
                                    )
                                elif (
                                    ord(_c) in _punycode_asis
                                    or ord(_c)
                                    in _punycode_arabic_presentation_as_is
                                ):
                                    _frac_parts.append(_c)
                                elif ord(_c) in (0x200C, 0x200D):
                                    raise ValueError("joiner")
                                else:
                                    _frac_parts.append(
                                        _idna.uts46_remap(
                                            _c,
                                            std3_rules=False,
                                            transitional=False,
                                        )
                                    )
                            _frac_recovered = "".join(_frac_parts)
                        except (UnicodeError, ValueError):
                            _frac_recovered = None
                        _frac_recovered_ok = (
                            _frac_recovered
                            == label.translate(_fraction_excl_map)
                            or _frac_recovered
                            == label.translate(_fraction_excl_map).translate(
                                _greek_extended_remap
                            )
                            or _frac_recovered
                            == label.translate(_fraction_excl_map).translate(
                                _asis_map
                            )
                            or _frac_recovered
                            == label.translate(_fraction_excl_map)
                            .translate(_asis_map)
                            .translate(_greek_extended_remap)
                            # A label mixing a fraction with a
                            # double exclamation mark and U+FB29
                            # plus an as-is mark ("¼‼﬩᫏" ->
                            # "1⁄4!!+᫏"): the per-character
                            # recovery expands all three, but
                            # this gate lacked the FB29
                            # candidate the main gate gains
                            # below, so it fell through to the
                            # raw-fraction punycode instead of
                            # the browser's form. Accept the
                            # fraction-expanded form further
                            # translated through the FB29 map
                            # (U+FB29 -> "+"); its key domain
                            # is disjoint from the fraction,
                            # as-is and Greek tables, so other
                            # labels are unchanged. It is still
                            # anchored to the real UTS46 remap:
                            # any other remapped character
                            # fails every candidate and falls
                            # through unchanged, as before.
                            or _frac_recovered
                            == label.translate(_fraction_excl_map)
                            .translate({0xFB29: "+"})
                            # A label mixing a fraction with an
                            # enclosed CJK member, a parenthesized
                            # CJK member, or a CJK Compatibility
                            # Ideograph plus an as-is mark
                            # ("¼㊣᫏" -> "1⁄4正᫏"): the recovery
                            # above remaps the enclosed member
                            # per character, but this gate lacked
                            # the enclosed-CJK candidate the main
                            # gate already has, so it fell through
                            # to the raw-fraction punycode instead
                            # of the browser's form. Accept the
                            # fraction-expanded form further
                            # translated through the three CJK
                            # remap tables, and the as-is-expanded
                            # variant of it, mirroring the main
                            # gate; their key domains are disjoint
                            # from the fraction, as-is and Greek
                            # tables, so other labels are unchanged.
                            or _frac_recovered
                            == label.translate(_fraction_excl_map)
                            .translate(_enclosed_cjk_remap)
                            .translate(_parenthesized_cjk_remap)
                            .translate(_cjk_compat_remap)
                            or _frac_recovered
                            == label.translate(_fraction_excl_map)
                            .translate(_asis_map)
                            .translate(_enclosed_cjk_remap)
                            .translate(_parenthesized_cjk_remap)
                            .translate(_cjk_compat_remap)
                            # A label mixing a fraction with a
                            # square CJK member plus an as-is
                            # mark ("¼㍱᫏" -> "1⁄4hpa᫏"): the
                            # recovery above remaps the square
                            # per character, but this gate
                            # lacked the square-CJK candidate
                            # the main gate already has, so it
                            # fell through to the raw-fraction
                            # punycode instead of the browser's
                            # form. Accept the
                            # fraction-expanded form further
                            # translated through the square
                            # CJK remap table, and the
                            # as-is-expanded variant of it,
                            # mirroring the enclosed-CJK
                            # candidates above; the square
                            # table's key domain is disjoint
                            # from the fraction, as-is and
                            # Greek tables, so other labels
                            # are unchanged.
                            or _frac_recovered
                            == label.translate(_fraction_excl_map)
                            .translate(_square_cjk_remap)
                            or _frac_recovered
                            == label.translate(_fraction_excl_map)
                            .translate(_asis_map)
                            .translate(_square_cjk_remap)
                            # A label mixing a fraction with
                            # both a square CJK member and an
                            # enclosed CJK member, a
                            # parenthesized CJK member, or a
                            # CJK Compatibility Ideograph,
                            # plus an as-is mark
                            # ("¼㍱㊣᫏" -> "1⁄4hpa正᫏"): the
                            # recovery above remaps the square
                            # and the enclosed members per
                            # character, but this gate lacked
                            # the combined square+enclosed
                            # candidate the main gate already
                            # has, so it fell through to the
                            # raw-fraction punycode instead of
                            # the browser's form. Accept the
                            # fraction-expanded form further
                            # translated through the square
                            # table and the three CJK remap
                            # tables, and the Greek and
                            # as-is variants of it, mirroring
                            # the main gate; their key domains
                            # are disjoint, so other labels
                            # are unchanged.
                            or _frac_recovered
                            == label.translate(_fraction_excl_map)
                            .translate(_square_cjk_remap)
                            .translate(_enclosed_cjk_remap)
                            .translate(_parenthesized_cjk_remap)
                            .translate(_cjk_compat_remap)
                            or _frac_recovered
                            == label.translate(_fraction_excl_map)
                            .translate(_greek_extended_remap)
                            .translate(_square_cjk_remap)
                            .translate(_enclosed_cjk_remap)
                            .translate(_parenthesized_cjk_remap)
                            .translate(_cjk_compat_remap)
                            or _frac_recovered
                            == label.translate(_fraction_excl_map)
                            .translate(_asis_map)
                            .translate(_square_cjk_remap)
                            .translate(_enclosed_cjk_remap)
                            .translate(_parenthesized_cjk_remap)
                            .translate(_cjk_compat_remap)
                        )
                        if any(
                            ord(c)
                            in _punycode_arabic_presentation_as_is
                            for c in label
                        ):
                            _frac_recovered_ok = (
                                _frac_recovered_ok
                                and _arb_unicodedata.category(label[0])[
                                    0
                                ]
                                != "M"
                                and all(
                                    ord(c) in _fraction_map
                                    or ord(c) in _double_excl_map
                                    or ord(c) in _punycode_asis
                                    or ord(c)
                                    in _punycode_arabic_presentation_as_is
                                    or c
                                    in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                                    or (
                                        ord(c) > 127
                                        and _arb_unicodedata.category(c)[
                                            0
                                        ]
                                        in "LMNSP"
                                        and _arb_unicodedata.bidirectional(
                                            c
                                        )
                                        not in ("R", "AL", "AN")
                                    )
                                    for c in label
                                )
                            )
                        if _frac_recovered_ok:
                            _frac_remapped = _frac_recovered
                # A label mixing a fraction with an as-is
                # expansion form (DEGREE CELSIUS U+2103 ->
                # "°c", DEGREE FAHRENHEIT U+2109 -> "°f"):
                # the whole-label remap expands both the
                # fraction and the degree form, so it equals
                # neither the fraction-only expansion nor its
                # Greek-remapped form, and the label fell
                # through to the as-is branch, which punycoded
                # the raw fraction ("¼℃" -> "xn--c-0ca9a"
                # instead of the browser's "xn--14c-tfa2351b").
                # Accepting the as-is-expanded form (and its
                # Greek-remapped form) as well is still anchored
                # to the real UTS46 remap: any other remapped
                # character fails every candidate and falls
                # through unchanged, as before.
                # A space in the label fails WHATWG host parsing
                # (the pipeline deliberately leaves interior spaces
                # alone in _normalize_cors_origin for exactly this
                # reason), yet the remap/translate gate above passes
                # it through, so a space label was punycoded with
                # the space still in it ("¼ " -> "xn--14 -ot0a"),
                # a form no browser origin could carry. Exclude
                # space labels from the main gate; they fall to
                # the strict path below, which rejects them, so
                # they return None as a browser-rejected label
                # should. Without this guard the new fraction
                # entries above would extend that over-emission
                # to every new vulgar fraction ("⅓ " likewise).
                # A label mixing a fraction with a Hebrew
                # Alphabetic Presentation Form ("ا¼יִ" ->
                # "ا1⁄4יִ" -> "xn--14-ijd1mmp505k"): the
                # whole-label remap expands both, so it equals
                # neither the fraction-only expansion nor its
                # Greek/as-is forms, and the label fell through
                # to None (or, with an as-is symbol, to the
                # raw-fraction punycode in the as-is branch
                # below). Accept the fraction-expanded form
                # further translated through
                # _hebrew_presentation_remap, but only under
                # the RTL gates the fraction RTL branch below
                # uses, checked on the remapped form: the
                # first character must be strong RTL, the last
                # non-mark strong RTL or a digit, European
                # and Arabic-Indic digits must not mix, and
                # every character must be strong RTL, a digit,
                # a neutral or an underscore — so a
                # digit-led ("¼יִ"), Latin-led ("a¼יִ"),
                # mixed-digit ("ا¼יִ١") or Latin-trailing
                # ("ا¼יִa") label still falls through to None
                # as the browser rejects it, and a trailing
                # underscore ("ا¼יִ_") keeps its existing
                # underscore-path behaviour. The candidate is
                # identity for labels without a Hebrew
                # presentation form, so those are unaffected
                # (the plain fraction candidate below already
                # accepts them, and this alternative can only
                # add acceptance where the gates pass).
                _frac_hebrew_end = None
                if _frac_remapped is not None:
                    for _c in reversed(_frac_remapped):
                        if _arb_unicodedata.bidirectional(_c) != "NSM":
                            _frac_hebrew_end = (
                                _arb_unicodedata.bidirectional(_c)
                            )
                            break
                _frac_hebrew_ok = (
                    _frac_remapped is not None
                    and _frac_remapped
                    == label.translate(_fraction_excl_map).translate(
                        _hebrew_presentation_remap
                    )
                    and _arb_unicodedata.bidirectional(_frac_remapped[0])
                    in ("R", "AL")
                    and _frac_hebrew_end in ("R", "AL", "EN", "AN")
                    and not (
                        any(
                            _arb_unicodedata.bidirectional(c) == "EN"
                            for c in _frac_remapped
                        )
                        and any(
                            _arb_unicodedata.bidirectional(c) == "AN"
                            for c in _frac_remapped
                        )
                    )
                    and all(
                        c == "_"
                        or _arb_unicodedata.bidirectional(c)
                        in (
                            "R",
                            "AL",
                            "EN",
                            "AN",
                            "ON",
                            "ET",
                            "CS",
                            "NSM",
                        )
                        for c in _frac_remapped
                    )
                )
                # The main gate above accepts the remapped
                # fraction form unconditionally, so a
                # fraction label in an RTL context that
                # fails the UTS46 bidi rule was punycoded
                # into a form no browser origin could
                # carry ("ا¼©" -> "ا1⁄4©", "¼ا" ->
                # "1⁄4ا", "ا¼٣" -> "ا1⁄4٣", "٣¼" ->
                # "٣1⁄4", "ا¼㊣" -> "ا1⁄4正"), while the
                # browser rejects every one of them. Gate
                # the main acceptance on the remapped form,
                # mirroring the Hebrew and RTL gates above
                # and below: when it contains a strong-RTL
                # character or an Arabic-Indic digit, the
                # first character must be strong RTL, the
                # last non-mark character must be strong
                # RTL or a digit, European and Arabic-Indic
                # digits must not mix, and every character
                # must be strong RTL, a digit, a neutral,
                # a mark or an underscore — so a Latin- or
                # CJK-trailing ("ا¼a", "ا¼㊣"), neutral- or
                # punctuation-trailing ("ا¼©", "ا¼!",
                # "ا¼_", "ا¼-"), digit-led ("¼ا") or
                # mixed-digit ("ا¼٣", "٣¼") label falls
                # through to None as the browser rejects
                # it. Labels without a strong-RTL or
                # Arabic-Indic character are unaffected
                # (the gate is vacuous for them), and
                # matching RTL fraction labels ("ا¼",
                # "م¼", "ا¼1", mid-underscore "ا¼_م")
                # pass every condition; the Hebrew gate
                # above already imposes the same rules on
                # its own candidates, so those labels pass
                # this gate too.
                _frac_main_bidi_end = None
                if _frac_remapped is not None:
                    for _c in reversed(_frac_remapped):
                        if _arb_unicodedata.bidirectional(_c) != "NSM":
                            _frac_main_bidi_end = (
                                _arb_unicodedata.bidirectional(_c)
                            )
                            break
                # The trigger above must not count an Arabic
                # presentation form as a strong-RTL character:
                # this Python's data gives U+FBC2 (ARABIC
                # SYMBOL WASLA ABOVE, the only member of the
                # presentation-as-is set with an AL class) an
                # AL class, so a fraction label carrying only
                # it ("¼﯂", "a¼﯂", "¼﯂᫏") triggered the
                # gate and failed its strong-RTL first
                # character requirement, falling through to
                # None — yet browsers carry all of them,
                # treating the symbol as neutral (as they do
                # the other, ON-class members of the set,
                # e.g. "¼﷾"). Excluding the presentation
                # set from the trigger makes the gate
                # vacuous for such labels, as it already is
                # for the ON-class members; a label that
                # also carries a strong-RTL character
                # outside the set still triggers the gate
                # (and is then barred by the mix check
                # below, as before, e.g. "ا¼﯂").
                _frac_main_bidi_ok = (
                    _frac_remapped is None
                    or not any(
                        ord(c)
                        not in _punycode_arabic_presentation_as_is
                        and _arb_unicodedata.bidirectional(c)
                        in ("R", "AL", "AN")
                        for c in _frac_remapped
                    )
                    or (
                        _arb_unicodedata.bidirectional(
                            _frac_remapped[0]
                        )
                        in ("R", "AL")
                        and _frac_main_bidi_end
                        in ("R", "AL", "EN", "AN")
                        and not (
                            any(
                                _arb_unicodedata.bidirectional(c) == "EN"
                                for c in _frac_remapped
                            )
                            and any(
                                _arb_unicodedata.bidirectional(c) == "AN"
                                for c in _frac_remapped
                            )
                        )
                        and all(
                            c == "_"
                            or _arb_unicodedata.bidirectional(c)
                            in (
                                "R",
                                "AL",
                                "EN",
                                "AN",
                                "ON",
                                "ET",
                                "CS",
                                "NSM",
                            )
                            for c in _frac_remapped
                        )
                    )
                )
                # The main gate above still passes a
                # fraction label mixing an as-is Arabic
                # presentation form with a strong-RTL
                # character: this Python's data gives
                # U+FBC2 an AL class, so it satisfies the
                # first/last/allowed checks ("ا¼﯂",
                # "ا¼﯂م", "م¼﯂"), and the ornate
                # parentheses U+FD3E/U+FD3F are ON, so a
                # mid-label one passes too ("ا¼﷾م",
                # "م¼﷾ا", "ا¼﷾1") — yet browsers treat
                # these forms as Latin-class letters in an
                # RTL label and reject it, so the main arm
                # emitted a raw-fraction punycode no
                # browser origin could carry. Bar the gate
                # for the mix, mirroring the as-is branch's
                # Latin mapping and the fallback mix below:
                # a presentation member alongside a
                # strong-RTL character outside the set.
                # Excepted: U+FDFD, which browsers carry
                # in exactly these shapes ("ا¼ﯽ",
                # "ا¼ﯽم", "م¼ﯽ1"), and labels with no
                # strong-RTL character outside the set
                # ("¼﯂", "a¼﯂"), for which the mix is
                # false and the gate is unchanged.
                _frac_main_bidi_asis_latin_mix = (
                    _frac_remapped is not None
                    and any(
                        ord(c) in _punycode_arabic_presentation_as_is
                        and ord(c) != 0xFDFD
                        for c in _frac_remapped
                    )
                    and any(
                        ord(c)
                        not in _punycode_arabic_presentation_as_is
                        and _arb_unicodedata.bidirectional(c)
                        in ("R", "AL", "AN")
                        for c in _frac_remapped
                    )
                )
                _frac_main_bidi_ok = (
                    _frac_main_bidi_ok
                    and not _frac_main_bidi_asis_latin_mix
                )
                # A fraction label mixing an as-is Arabic
                # presentation form with a strong-RTL
                # character outside that form set: the
                # recovery gate above bars exactly this
                # mix (its allowed-character check admits
                # no strong-RTL character alongside a
                # presentation form), and browsers reject
                # it too — but when recovery fails,
                # _frac_remapped is None, so
                # _frac_main_bidi_ok above is vacuously
                # true and the raw as-is and underscore
                # fallbacks below fired anyway, emitting
                # the raw-fraction punycode for a label
                # no browser origin could carry ("ا¼﯃᫏",
                # "م¼﯃᫏", "٣¼﯃᫏", "¼﯃᫏م",
                # "ا¼﯃᫏_", "ا¼﯃᫏x" — all
                # browser-rejected). Bar both fallbacks
                # for the mix, so it reaches the strict
                # arm, which rejects the fraction and
                # returns None; labels without a
                # presentation form, or with one but no
                # strong-RTL character outside the set
                # ("¼﯃᫏", "¼﯃᫏_", "a¼﯃᫏"), are
                # unaffected, and a presentation member
                # that is itself strong RTL in this
                # Python's data (U+FBC2, AL) does not
                # count against the label on its own.
                _frac_asis_presentation_rtl_mix = (
                    any(
                        ord(c)
                        in _punycode_arabic_presentation_as_is
                        for c in label
                    )
                    and any(
                        ord(c)
                        not in _punycode_arabic_presentation_as_is
                        and _arb_unicodedata.bidirectional(c)
                        in ("R", "AL", "AN")
                        for c in label
                    )
                )
                if (
                    _frac_remapped is not None
                    and " " not in label
                    and _frac_main_bidi_ok
                    and (
                        _frac_remapped
                        == label.translate(_fraction_excl_map)
                        or _frac_remapped
                        == label.translate(_fraction_excl_map).translate(
                            _greek_extended_remap
                        )
                        or _frac_remapped
                        == label.translate(_fraction_excl_map).translate(
                            _asis_map
                        )
                        or _frac_remapped
                        == label.translate(_fraction_excl_map)
                        .translate(_asis_map)
                        .translate(_greek_extended_remap)
                        # A label mixing a fraction with a
                        # double exclamation mark and U+FB29
                        # ("¼‼﬩" -> "1⁄4!!+", "a¼‼﬩" ->
                        # "a1⁄4!!+", "¼﬩‼" -> "1⁄4+!!"):
                        # the whole-label remap expands all
                        # three, so it equals none of the
                        # candidates above, and the label fell
                        # through to None even though the
                        # browser carries the remapped form
                        # (a fraction with U+FB29 but no
                        # double exclamation mark already
                        # matches via the FB29 branch, which
                        # is why only the combined class is
                        # the gap). Accept the
                        # fraction-expanded form further
                        # translated through the FB29 map
                        # (U+FB29 -> "+"); its key domain is
                        # disjoint from the fraction, as-is
                        # and Greek tables, so the chained
                        # form is identity for labels
                        # without such a member. It is still
                        # anchored to the real UTS46 remap:
                        # any other remapped character fails
                        # every candidate and falls through
                        # unchanged, as before.
                        or _frac_remapped
                        == label.translate(_fraction_excl_map)
                        .translate({0xFB29: "+"})
                        # A label mixing a fraction with a
                        # double exclamation mark, U+FB29 and
                        # an as-is expansion form ("¼‼﬩℃" ->
                        # "1⁄4!!+°c"): the whole-label remap
                        # expands all four, so it equals none
                        # of the candidates above, and the
                        # label fell through to the as-is
                        # branch's raw-fraction form
                        # ("¼‼﬩°c") instead of the browser's
                        # remapped form. Accept the
                        # fraction-expanded form further
                        # translated through the FB29 map and
                        # the as-is map; their key domains
                        # are disjoint from each other and
                        # from the fraction table, so the
                        # chained form is identity for labels
                        # without such a member. It is still
                        # anchored to the real UTS46 remap:
                        # any other remapped character fails
                        # every candidate and falls through
                        # unchanged, as before.
                        or _frac_remapped
                        == label.translate(_fraction_excl_map)
                        .translate({0xFB29: "+"})
                        .translate(_asis_map)
                        # A label mixing a fraction with a
                        # double exclamation mark, U+FB29 and
                        # an enclosed CJK member, a
                        # parenthesized CJK member, or a CJK
                        # Compatibility Ideograph ("¼‼﬩㊣" ->
                        # "1⁄4!!+正", "¼‼﬩豈" ->
                        # "1⁄4!!+豈"): the whole-label remap
                        # expands all four, so it equals none
                        # of the candidates above, and the
                        # label fell through to None even
                        # though the browser carries the
                        # remapped form. Accept the
                        # fraction-expanded form further
                        # translated through the FB29 map and
                        # the three CJK remap tables; their key
                        # domains are disjoint from each
                        # other and from the fraction table,
                        # so the chained form is identity for
                        # labels without such a member. It is
                        # still anchored to the real UTS46
                        # remap: any other remapped character
                        # fails every candidate and falls
                        # through unchanged, as before.
                        or _frac_remapped
                        == label.translate(_fraction_excl_map)
                        .translate({0xFB29: "+"})
                        .translate(_enclosed_cjk_remap)
                        .translate(_parenthesized_cjk_remap)
                        .translate(_cjk_compat_remap)
                        # A label mixing a fraction with a
                        # double exclamation mark, U+FB29 and
                        # a square CJK member ("¼‼﬩㍱" ->
                        # "1⁄4!!+hpa", "¼‼﬩㎀" ->
                        # "1⁄4!!+pa"): the whole-label remap
                        # expands all four, so it equals none
                        # of the candidates above, and the
                        # label fell through to None even
                        # though the browser carries the
                        # remapped form. The enclosed-CJK
                        # candidate above covers the
                        # enclosed members (e.g. "¼‼﬩㊣")
                        # but not the square members, whose
                        # expansions live in the separate
                        # square table. Accept the
                        # fraction-expanded form further
                        # translated through the FB29 map and
                        # the square CJK remap table; their key
                        # domains are disjoint from each
                        # other and from the fraction table,
                        # so the chained form is identity for
                        # labels without such a member. It is
                        # still anchored to the real UTS46
                        # remap: any other remapped character
                        # fails every candidate and falls
                        # through unchanged, as before.
                        or _frac_remapped
                        == label.translate(_fraction_excl_map)
                        .translate({0xFB29: "+"})
                        .translate(_square_cjk_remap)
                        # A label mixing a fraction with a
                        # double exclamation mark, U+FB29, a
                        # square CJK member and an enclosed
                        # CJK member, a parenthesized CJK
                        # member, or a CJK Compatibility
                        # Ideograph ("¼‼﬩㍱㊣" ->
                        # "1⁄4!!+hpa正"): the whole-label
                        # remap expands all five, so it
                        # equals none of the candidates
                        # above, and the label fell through
                        # to None even though the browser
                        # carries the remapped form. The
                        # square candidate above covers the
                        # square members and the enclosed
                        # candidate above covers the enclosed
                        # members, but neither covers their
                        # combination. Accept the
                        # fraction-expanded form further
                        # translated through the FB29 map,
                        # the square table and the three CJK
                        # remap tables; their key domains
                        # are disjoint from each other and
                        # from the fraction table, so the
                        # chained form is identity for
                        # labels without such a member. It
                        # is still anchored to the real
                        # UTS46 remap: any other remapped
                        # character fails every candidate
                        # and falls through unchanged, as
                        # before.
                        or _frac_remapped
                        == label.translate(_fraction_excl_map)
                        .translate({0xFB29: "+"})
                        .translate(_square_cjk_remap)
                        .translate(_enclosed_cjk_remap)
                        .translate(_parenthesized_cjk_remap)
                        .translate(_cjk_compat_remap)
                        # A label mixing a fraction with a
                        # double exclamation mark, U+FB29 and
                        # a Greek Extended member ("¼‼﬩ά" ->
                        # "1⁄4!!+ά"): the whole-label remap
                        # expands all four, so it equals none
                        # of the candidates above, and the
                        # label fell through to None even
                        # though the browser carries the
                        # remapped form. Accept the
                        # fraction-expanded form further
                        # translated through the FB29 map and
                        # the Greek Extended remap table;
                        # their key domains are disjoint from
                        # each other and from the fraction
                        # table, so the chained form is
                        # identity for labels without such a
                        # member. It is still anchored to the
                        # real UTS46 remap: any other remapped
                        # character fails every candidate and
                        # falls through unchanged, as before.
                        or _frac_remapped
                        == label.translate(_fraction_excl_map)
                        .translate({0xFB29: "+"})
                        .translate(_greek_extended_remap)
                        # A label mixing a fraction with a
                        # double exclamation mark, U+FB29, a
                        # square CJK member and a Greek
                        # Extended member ("¼‼﬩㍱ά" ->
                        # "1⁄4!!+hpaά"): the whole-label remap
                        # expands all five, so it equals none
                        # of the candidates above, and the
                        # label fell through to None even
                        # though the browser carries the
                        # remapped form. The square candidate
                        # above covers the square members and
                        # the Greek candidate above covers the
                        # Greek members, but neither covers
                        # their combination. Accept the
                        # fraction-expanded form further
                        # translated through the FB29 map, the
                        # square CJK remap table and the Greek
                        # Extended remap table; their key
                        # domains are disjoint from each other
                        # and from the fraction table, so the
                        # chained form is identity for labels
                        # without such a member. It is still
                        # anchored to the real UTS46 remap:
                        # any other remapped character fails
                        # every candidate and falls through
                        # unchanged, as before.
                        or _frac_remapped
                        == label.translate(_fraction_excl_map)
                        .translate({0xFB29: "+"})
                        .translate(_square_cjk_remap)
                        .translate(_greek_extended_remap)
                        # A label mixing a fraction with a
                        # double exclamation mark, U+FB29, a
                        # Greek Extended member and an
                        # enclosed CJK member, a parenthesized
                        # CJK member, or a CJK Compatibility
                        # Ideograph ("¼‼﬩㊣ά" ->
                        # "1⁄4!!+正ά"): the whole-label remap
                        # expands all five, so it equals none
                        # of the candidates above, and the
                        # label fell through to None even
                        # though the browser carries the
                        # remapped form. The Greek candidate
                        # above covers the Greek members and
                        # the enclosed candidate above covers
                        # the enclosed members, but neither
                        # covers their combination. Accept the
                        # fraction-expanded form further
                        # translated through the FB29 map, the
                        # Greek Extended remap table and the
                        # three CJK remap tables; their key
                        # domains are disjoint from each other
                        # and from the fraction table, so the
                        # chained form is identity for labels
                        # without such a member. It is still
                        # anchored to the real UTS46 remap:
                        # any other remapped character fails
                        # every candidate and falls through
                        # unchanged, as before.
                        or _frac_remapped
                        == label.translate(_fraction_excl_map)
                        .translate({0xFB29: "+"})
                        .translate(_greek_extended_remap)
                        .translate(_enclosed_cjk_remap)
                        .translate(_parenthesized_cjk_remap)
                        .translate(_cjk_compat_remap)
                        # A label mixing a fraction with a
                        # double exclamation mark, U+FB29, a
                        # square CJK member, a Greek Extended
                        # member and an enclosed CJK member,
                        # a parenthesized CJK member, or a CJK
                        # Compatibility Ideograph ("¼‼﬩㍱ά㊣"
                        # -> "1⁄4!!+hpaά正"): the whole-label
                        # remap expands all six, so it equals
                        # none of the candidates above, and
                        # the label fell through to None even
                        # though the browser carries the
                        # remapped form. The candidate above
                        # covers the Greek plus enclosed
                        # combination, but not the same
                        # combination with a square member
                        # added, whose expansion lives in the
                        # separate square table. Accept the
                        # fraction-expanded form further
                        # translated through the FB29 map, the
                        # square table, the Greek Extended
                        # remap table and the three CJK remap
                        # tables; their key domains are
                        # disjoint from each other and from
                        # the fraction table, so the chained
                        # form is identity for labels without
                        # such a member. It is still anchored
                        # to the real UTS46 remap: any other
                        # remapped character fails every
                        # candidate and falls through
                        # unchanged, as before.
                        or _frac_remapped
                        == label.translate(_fraction_excl_map)
                        .translate({0xFB29: "+"})
                        .translate(_square_cjk_remap)
                        .translate(_greek_extended_remap)
                        .translate(_enclosed_cjk_remap)
                        .translate(_parenthesized_cjk_remap)
                        .translate(_cjk_compat_remap)
                        # A label mixing a fraction with an
                        # enclosed CJK member, a parenthesized
                        # CJK member, or a CJK Compatibility
                        # Ideograph ("¼㊣" -> "1⁄4正",
                        # "¼㈀" -> "1⁄4(ᄀ)", "¼豈" ->
                        # "1⁄4豈"): the whole-label remap
                        # expands both, so it equals none of
                        # the candidates above, and the label
                        # fell through to None for old and new
                        # fractions alike, even though the
                        # browser carries the remapped form.
                        # Accept the fraction-expanded form
                        # further translated through the three
                        # CJK remap tables; their key domains
                        # are disjoint, so the chained form
                        # covers single-class labels and mixes
                        # of the three classes alike, and is
                        # identity for labels without such a
                        # member. It is still anchored to the
                        # real UTS46 remap: any other remapped
                        # character fails every candidate and
                        # falls through unchanged, as before.
                        or _frac_remapped
                        == label.translate(_fraction_excl_map)
                        .translate(_enclosed_cjk_remap)
                        .translate(_parenthesized_cjk_remap)
                        .translate(_cjk_compat_remap)
                        # A label mixing a fraction with both
                        # a Greek Extended member and an
                        # enclosed CJK member, a parenthesized
                        # CJK member, or a CJK Compatibility
                        # Ideograph ("¼㊣ά" -> "1⁄4正ά"):
                        # the whole-label remap expands all
                        # three, so it equals none of the
                        # candidates above, and the label fell
                        # through to None even though the
                        # browser carries the remapped form.
                        # Accept the fraction-expanded form
                        # further translated through the Greek
                        # remap and the three CJK remap tables;
                        # their key domains are disjoint, so
                        # the chained form covers the combined
                        # class and is identity for labels
                        # without such a member. It is still
                        # anchored to the real UTS46 remap: any
                        # other remapped character fails every
                        # candidate and falls through
                        # unchanged, as before.
                        or _frac_remapped
                        == label.translate(_fraction_excl_map)
                        .translate(_greek_extended_remap)
                        .translate(_enclosed_cjk_remap)
                        .translate(_parenthesized_cjk_remap)
                        .translate(_cjk_compat_remap)
                        # A label mixing a fraction with an
                        # as-is expansion form and an enclosed
                        # CJK member ("¼℃㊣" -> "1⁄4°c正"): the
                        # whole-label remap expands all three,
                        # so it equals none of the candidates
                        # above, and the label fell through to
                        # the as-is branch's raw-fraction form.
                        # Accept the fraction-expanded form
                        # further translated through the as-is
                        # map and the three CJK remap tables;
                        # their key domains are disjoint, so
                        # the chained form is identity for
                        # labels without such a member, and it
                        # is still anchored to the real UTS46
                        # remap, as with the candidates above.
                        or _frac_remapped
                        == label.translate(_fraction_excl_map)
                        .translate(_asis_map)
                        .translate(_enclosed_cjk_remap)
                        .translate(_parenthesized_cjk_remap)
                        .translate(_cjk_compat_remap)
                        # A label mixing a fraction with a
                        # square CJK member (fraction plus
                        # U+3371 -> "1⁄4hpa"): the whole-label
                        # remap expands both, so it equals
                        # none of the candidates above, and
                        # the label fell through to None even
                        # though the browser carries the
                        # remapped form. Accept the
                        # fraction-expanded form further
                        # translated through the square CJK
                        # remap table; its key domain is
                        # disjoint from the fraction, as-is,
                        # Greek and enclosed tables, so the
                        # chained form covers single-square
                        # labels and mixes of squares alike,
                        # and is identity for labels without
                        # such a member. The Greek and as-is
                        # variants below cover the same
                        # combinations the enclosed
                        # candidates above already cover, for
                        # the same reason. It is still
                        # anchored to the real UTS46 remap: any
                        # other remapped character fails every
                        # candidate and falls through
                        # unchanged, as before.
                        or _frac_remapped
                        == label.translate(_fraction_excl_map)
                        .translate(_square_cjk_remap)
                        or _frac_remapped
                        == label.translate(_fraction_excl_map)
                        .translate(_greek_extended_remap)
                        .translate(_square_cjk_remap)
                        or _frac_remapped
                        == label.translate(_fraction_excl_map)
                        .translate(_asis_map)
                        .translate(_square_cjk_remap)
                        # A label mixing a fraction with both
                        # a square CJK member and an enclosed
                        # CJK member, a parenthesized CJK
                        # member, or a CJK Compatibility
                        # Ideograph ("¼㍱㊣" -> "1⁄4hpa正"):
                        # the whole-label remap expands all
                        # three, so it equals none of the
                        # candidates above, and the label
                        # fell through to None even though
                        # the browser carries the remapped
                        # form. Accept the fraction-expanded
                        # form further translated through the
                        # square table and the three CJK
                        # remap tables; their key domains
                        # are disjoint, so the chained form
                        # covers single- and combined-class
                        # labels alike, and is identity for
                        # labels without such a member. The
                        # Greek and as-is variants below
                        # cover the same combinations the
                        # enclosed and square candidates
                        # above already cover, for the same
                        # reason. It is still anchored to
                        # the real UTS46 remap: any other
                        # remapped character fails every
                        # candidate and falls through
                        # unchanged, as before.
                        or _frac_remapped
                        == label.translate(_fraction_excl_map)
                        .translate(_square_cjk_remap)
                        .translate(_enclosed_cjk_remap)
                        .translate(_parenthesized_cjk_remap)
                        .translate(_cjk_compat_remap)
                        or _frac_remapped
                        == label.translate(_fraction_excl_map)
                        .translate(_greek_extended_remap)
                        .translate(_square_cjk_remap)
                        .translate(_enclosed_cjk_remap)
                        .translate(_parenthesized_cjk_remap)
                        .translate(_cjk_compat_remap)
                        or _frac_remapped
                        == label.translate(_fraction_excl_map)
                        .translate(_asis_map)
                        .translate(_square_cjk_remap)
                        .translate(_enclosed_cjk_remap)
                        .translate(_parenthesized_cjk_remap)
                        .translate(_cjk_compat_remap)
                        or _frac_hebrew_ok
                    )
                ):
                    if any(ord(c) > 127 for c in _frac_remapped):
                        encoded_labels.append(
                            "xn--"
                            + _frac_remapped.encode("punycode").decode(
                                "ascii"
                            )
                        )
                    else:
                        encoded_labels.append(_frac_remapped)
                elif any(
                    ord(c) in _punycode_arabic_presentation_b
                    or ord(c) in _punycode_arabic_presentation_a
                    for c in label
                ):
                    # A fraction label mixed with an Arabic
                    # Presentation Form in an RTL context:
                    # the main gate above only accepts a
                    # remap that changes exactly the
                    # fractions (and double exclamation
                    # marks, as-is expansions and Greek
                    # Extended members), so a form the
                    # browser also remaps ("ا¼©ﺚ" ->
                    # "ا1⁄4©ث" -> "xn--14-uda537cxa7911b")
                    # failed it and fell through to None,
                    # even though the browser carries it.
                    # The gates mirror the as-is branch's
                    # RTL-context branch below, checked on
                    # the per-character remapped form: the
                    # first character must be strong RTL
                    # (R/AL), the last strong RTL or a digit
                    # (R/AL/EN/AN), European and Arabic-Indic
                    # digits must not mix, and every
                    # character must be strong RTL, a digit,
                    # a neutral (ON/ET/CS) or an underscore
                    # — so the fraction expansion's EN digits
                    # and fraction slash (CS) pass, while an
                    # as-is symbol at an edge, an LTR
                    # context, a Latin as-is expansion
                    # ("ا¼℃ﺚ", browser-rejected) or a mixed
                    # -digit label ("ا¼©ﺚ١") fails. A label
                    # failing any gate falls through to the
                    # same "_" / strict / raw handling as
                    # the as-is RTL branch, so its behaviour
                    # is unchanged (in particular the
                    # underscore-edge raw fallback below is
                    # preserved). Combining marks (NSM) are
                    # admitted, and the end check ignores
                    # trailing marks, mirroring the
                    # standalone as-is gate below: a label
                    # like "ا¼©ﺚً" passes, as does one
                    # whose Hebrew presentation form remaps
                    # to a letter plus a mark ("ا¼©ﺚיִ"),
                    # while "ا¼©ً" still fails — its last
                    # non-mark is the neutral ©.
                    import unicodedata as _frac_rtl_unicodedata

                    try:
                        _frac_rtl_chars = [
                            _idna.uts46_remap(
                                c,
                                std3_rules=False,
                                transitional=False,
                            )
                            for c in label
                        ]
                    except (UnicodeError, ValueError):
                        _frac_rtl_chars = None
                    _frac_rtl_remapped = (
                        "".join(_frac_rtl_chars)
                        if _frac_rtl_chars is not None
                        else None
                    )
                    # The end of an RTL label is its last
                    # non-mark character, mirroring the
                    # standalone as-is gate below: a trailing
                    # combining mark (NSM) is allowed after a
                    # valid end, so "ا¼©ﺚً" passes, while
                    # "ا¼©ً" still fails (its last non-mark
                    # is the neutral ©).
                    _frac_rtl_end = None
                    if _frac_rtl_remapped is not None:
                        for _c in reversed(_frac_rtl_remapped):
                            if (
                                _frac_rtl_unicodedata.bidirectional(_c)
                                != "NSM"
                            ):
                                _frac_rtl_end = (
                                    _frac_rtl_unicodedata.bidirectional(_c)
                                )
                                break
                    if (
                        _frac_rtl_remapped is not None
                        and _frac_rtl_unicodedata.bidirectional(
                            _frac_rtl_remapped[0]
                        )
                        in ("R", "AL")
                        and _frac_rtl_end in ("R", "AL", "EN", "AN")
                        and not (
                            any(
                                _frac_rtl_unicodedata.bidirectional(c)
                                == "EN"
                                for c in _frac_rtl_remapped
                            )
                            and any(
                                _frac_rtl_unicodedata.bidirectional(c)
                                == "AN"
                                for c in _frac_rtl_remapped
                            )
                        )
                        and all(
                            c == "_"
                            or _frac_rtl_unicodedata.bidirectional(c)
                            in (
                                "R",
                                "AL",
                                "EN",
                                "AN",
                                "ON",
                                "ET",
                                "CS",
                                "NSM",
                            )
                            for c in _frac_rtl_remapped
                        )
                    ):
                        encoded_labels.append(
                            "xn--"
                            + _frac_rtl_remapped.translate(_asis_map)
                            .encode("punycode")
                            .decode("ascii")
                        )
                    elif "_" not in label:
                        encoded_labels.append(
                            _idna.encode(label).decode("ascii")
                        )
                    elif (
                        label.startswith("_") or label.endswith("_")
                    ) and any(
                        _frac_rtl_unicodedata.bidirectional(c)
                        in ("R", "AL", "AN")
                        for c in (_frac_rtl_remapped or label)
                    ):
                        # An underscore-edge label the RTL
                        # gate above just rejected: UTS46
                        # requires an RTL label to start
                        # with a strong-RTL character and
                        # end with a strong-RTL character
                        # or a digit, so a label starting
                        # or ending with "_" (bidi class
                        # ON, a neutral) while containing
                        # a strong-RTL or Arabic-Indic
                        # character is browser-rejected
                        # ("ا¼ﯽم_" / "_ا¼ﯽم" /
                        # "ا¼ﺚم_" / "ا¼©ﺚ_"), yet this
                        # raw fallback punycoded it raw,
                        # a form no browser origin could
                        # carry. Raise, so the outer
                        # handler returns None for the
                        # whole host, mirroring the
                        # generic underscore fallback's
                        # "rtl underscore edge" rule,
                        # which this earlier branch
                        # bypassed. Mid-label underscores
                        # are untouched ("ا¼ﯽ_م" /
                        # "ا¼ﯽم_م" still match), as are
                        # labels with no R/AL/AN
                        # character, for which the gate
                        # above already decides.
                        raise ValueError(
                            "fraction presentation underscore edge"
                        )
                    elif _frac_rtl_remapped is not None and (
                        any(
                            _frac_rtl_unicodedata.bidirectional(c)
                            == "EN"
                            for c in _frac_rtl_remapped
                        )
                        and any(
                            _frac_rtl_unicodedata.bidirectional(c)
                            == "AN"
                            for c in _frac_rtl_remapped
                        )
                    ):
                        # A mixed-digit label the RTL gate
                        # above just rejected: UTS46 bars
                        # European and Arabic-Indic digits
                        # from mixing in an RTL label, and
                        # the fraction expansion itself
                        # supplies European digits ("¼" ->
                        # "1⁄4"), so any Arabic-Indic digit
                        # in the remapped form ("ا¼ﯽم_٣" /
                        # "ا¼ﯽم_٣م" / "ا¼ﯽ٣_م") is such a
                        # mix and is browser-rejected, yet
                        # this raw fallback punycoded it
                        # raw, a form no browser origin
                        # could carry. Raise, so the outer
                        # handler returns None for the
                        # whole host, mirroring the gate
                        # above, which this earlier branch
                        # bypassed. Labels with only one
                        # digit class ("ا¼ﯽم_م" /
                        # "ا¼ﯽم_1" still match) are
                        # untouched, as are labels whose
                        # remap failed, for which the gate
                        # above already decides.
                        raise ValueError(
                            "fraction presentation mixed digits"
                        )
                    elif any(ord(c) > 127 for c in label):
                        encoded_labels.append(
                            "xn--"
                            + label.encode("punycode").decode("ascii")
                        )
                    else:
                        encoded_labels.append(label)
                elif any(ord(c) in _punycode_asis for c in label) and not any(
                    ord(c) in _punycode_arabic_presentation_b
                    or ord(c) in _punycode_arabic_presentation_a
                    for c in label
                ) and _frac_main_bidi_ok and not _frac_asis_presentation_rtl_mix:
                    # The bidi gate above also bars this
                    # raw fallback: without it a label the
                    # main gate just rejected ("ا¼©") fell
                    # through here and was emitted as the
                    # raw-fraction punycode, a form no
                    # browser origin could carry either.
                    # Gated out, such a label reaches the
                    # strict arm below, which rejects the
                    # fraction and returns None for the
                    # host, as the browser's rejection
                    # requires. Labels passing the gate
                    # behave as before.
                    # An as-is label mixed with an Arabic
                    # Presentation Form is excluded here: the
                    # browser either rejects the mix under the
                    # UTS46 bidi rule or carries the form's
                    # UTS46-remapped Arabic letter, so the raw
                    # punycode below never matched; falling
                    # through reaches the strict path, which
                    # rejects the presentation form and returns
                    # None for the rejected shapes (the
                    # remapped RTL-context shapes stay a
                    # separate candidate).
                    encoded_labels.append(
                        "xn--"
                        + label.translate(_asis_map)
                        .encode("punycode")
                        .decode("ascii")
                    )
                elif "_" not in label:
                    encoded_labels.append(_idna.encode(label).decode("ascii"))
                elif any(ord(c) > 127 for c in label) and _frac_main_bidi_ok and not _frac_asis_presentation_rtl_mix:
                    # The bidi gate above also bars this
                    # raw fallback, for the same reason as
                    # the as-is arm above: a label the main
                    # gate rejected ("ا¼_") otherwise fell
                    # through here as the raw-fraction
                    # punycode. Gated out, such an
                    # underscore label reaches the else
                    # arm below, which raises so the outer
                    # handler returns None, as the
                    # browser's rejection requires; labels
                    # passing the gate behave as before.
                    encoded_labels.append(
                        "xn--" + label.encode("punycode").decode("ascii")
                    )
                else:
                    # Only reachable when the bidi gate
                    # barred the raw fallback above: every
                    # fraction label is non-ASCII, so this
                    # arm otherwise never runs. Raise so
                    # the outer handler returns None for
                    # the whole host, as for other
                    # browser-rejected labels, instead of
                    # appending the raw label (which no
                    # browser origin could carry either,
                    # but would differ from the None every
                    # other rejected label yields).
                    raise ValueError(
                        "fraction label fails the UTS46 bidi rule"
                    )
            elif any(ord(c) in _punycode_asis for c in label) and any(
                ord(c) in _punycode_arabic_presentation_b
                or ord(c) in _punycode_arabic_presentation_a
                for c in label
            ):
                # An as-is label mixed with an Arabic
                # Presentation Form in an RTL context: the
                # browser carries the form's UTS46-remapped
                # Arabic letter when the as-is symbol sits
                # between strong-RTL characters ("ا©ﺀ" ->
                # "ا©ء" -> "xn--gba41zqa"), while the
                # iteration-633 gate leaves every such mix
                # at None. The remap is per character, so a
                # whole-label remap failure (e.g. an
                # unassigned mark) cannot mask a good
                # character, and the gates mirror the UTS46
                # bidi rule for RTL labels, checked on the
                # remapped form: the first character must be
                # strong RTL (R/AL, which covers the
                # presentation forms themselves), the last
                # non-mark character strong RTL or a digit
                # (R/AL/EN/AN), European and Arabic-Indic
                # digits must not mix, and every character
                # must be strong RTL, a digit, a neutral
                # (ON/ET/CS), a combining mark (NSM) or an
                # underscore, so "ا©ﺚً" and "ا©ﺚיִ" pass
                # while a label whose last non-mark is a
                # neutral still fails. Checking the
                # remapped form matters: an as-is expansion
                # to Latin letters (℃ -> "°c", a square
                # form -> "m∕s") fails the neutral gate,
                # matching the browser's rejection, while
                # neutral expansions (‑ -> "‐", ″ -> "′′")
                # pass, matching the browser's carried
                # form. A label failing any gate (an as-is
                # symbol at an edge, an LTR context, an
                # unassigned mark, a Greek/enclosed mix, a
                # joiner, or a mixed-digit label) falls
                # through to the same "_" / strict / plain
                # handling below, so its behaviour is
                # unchanged. Placed before the as-is branch,
                # whose Arabic gate would otherwise skip the
                # mix entirely.
                import unicodedata as _rtl_unicodedata

                try:
                    _rtl_remapped_chars = [
                        _idna.uts46_remap(
                            c, std3_rules=False, transitional=False
                        )
                        for c in label
                    ]
                except (UnicodeError, ValueError):
                    _rtl_remapped_chars = None
                _rtl_remapped = (
                    "".join(_rtl_remapped_chars)
                    if _rtl_remapped_chars is not None
                    else None
                )
                # The end of an RTL label is its last
                # non-mark character, mirroring the
                # standalone as-is gate below: a trailing
                # combining mark (NSM) is allowed after a
                # valid end, so "ا©ﺚً" passes, while a
                # label ending in a neutral plus a mark
                # still fails.
                _rtl_end = None
                if _rtl_remapped is not None:
                    for _c in reversed(_rtl_remapped):
                        if _rtl_unicodedata.bidirectional(_c) != "NSM":
                            _rtl_end = _rtl_unicodedata.bidirectional(_c)
                            break
                if (
                    _rtl_remapped is not None
                    and _rtl_unicodedata.bidirectional(_rtl_remapped[0])
                    in ("R", "AL")
                    and _rtl_end in ("R", "AL", "EN", "AN")
                    and not (
                        any(
                            _rtl_unicodedata.bidirectional(c) == "EN"
                            for c in _rtl_remapped
                        )
                        and any(
                            _rtl_unicodedata.bidirectional(c) == "AN"
                            for c in _rtl_remapped
                        )
                    )
                    and all(
                        c == "_"
                        or _rtl_unicodedata.bidirectional(c)
                        in (
                            "R",
                            "AL",
                            "EN",
                            "AN",
                            "ON",
                            "ET",
                            "CS",
                            "NSM",
                        )
                        for c in _rtl_remapped
                    )
                ):
                    encoded_labels.append(
                        "xn--"
                        + _rtl_remapped.translate(_asis_map)
                        .encode("punycode")
                        .decode("ascii")
                    )
                elif "_" not in label:
                    encoded_labels.append(
                        _idna.encode(label).decode("ascii")
                    )
                elif any(ord(c) > 127 for c in label):
                    encoded_labels.append(
                        "xn--" + label.encode("punycode").decode("ascii")
                    )
                else:
                    encoded_labels.append(label)
            elif any(ord(c) in _punycode_asis for c in label) and not any(
                ord(c) in _punycode_arabic_presentation_b
                or ord(c) in _punycode_arabic_presentation_a
                for c in label
            ):
                # As in the fraction-branch as-is fallback above,
                # a label mixing an as-is form with an Arabic
                # Presentation Form is excluded: the browser
                # either rejects the mix under the UTS46 bidi
                # rule or carries the form's UTS46-remapped
                # Arabic letter, so the raw punycode below never
                # matched; falling through reaches the strict
                # path, which rejects the presentation form and
                # returns None for the rejected shapes (the
                # remapped RTL-context shapes are handled by
                # the branch above).
                # A label combining an as-is form with DOUBLE
                # EXCLAMATION MARK U+203C ("©‼" -> browser
                # "xn--!!-sda") previously punycoded the raw
                # U+203C here, since this branch runs before the
                # double-exclamation branch below and never
                # expanded it. UTS46 maps U+203C to "!!" before
                # IDNA processing, so expand it alongside the
                # as-is map before punycoding; labels without
                # U+203C are unchanged, since the translate is
                # identity for them, and the fraction branch
                # above already handles fraction mixes itself.
                # Enclosed CJK members are likewise expanded
                # through _enclosed_cjk_remap (see there),
                # kangxi radicals through _kangxi_remap,
                # parenthesized enclosed forms through
                # _parenthesized_cjk_remap, and Hebrew
                # presentation forms through
                # _hebrew_presentation_remap; labels without one
                # are unchanged by them.
                # Square CJK members are likewise expanded
                # through _square_cjk_remap (see there): the
                # as-is branch punycoded the raw square form,
                # so an as-is mix never matched ("℃㌀" ->
                # helper "xn--c-0ca5579a", browser
                # "xn--c-0ca7397ameatb8q"; "℃㍱" -> helper
                # "xn--c-0ca4900b", browser "xn--chpa-4ga").
                # U+FB29 is likewise expanded to "+" here:
                # UTS46 maps it to "+" before IDNA
                # processing, but this branch never expanded
                # it, so an as-is mix with U+FB29 and a
                # double exclamation mark punycoded the raw
                # form ("©‼﬩" -> helper "xn--!!-sda8267w",
                # browser "xn--!!+-yea"); labels with U+FB29
                # but no double exclamation mark already
                # matched via the U+FB29 branch above, and
                # labels without U+FB29 are unchanged, since
                # the translate is identity for them. The
                # bidi gate below runs on the translated
                # form, so a trailing "+" still fails it
                # ("م©‼﬩" stays None, as browsers reject
                # it) while a medial "+" passes it
                # ("م©‼﬩م" -> browser "xn--!!+-yea392eea").
                # The seven as-is square members (U+33A7,
                # U+33A8, U+33AE, U+33AF, U+33C6, U+33DE,
                # U+33DF) are not in that table and keep
                # their _asis_map expansions, and
                # browser-rejected U+321F (in neither table)
                # keeps its existing behaviour for separate
                # assessment.
                # A UTS46 bidi violation in an as-is label: this
                # branch punycoded without any bidi gate, while
                # the underscore fallback below already raises
                # for the same violations, so a label claimed
                # here emitted a form no browser origin could
                # carry and never matched ("م_م·" and "م_م‚"
                # end in a neutral, "م_م·x" mixes a Latin
                # letter in, all browser-rejected). Mirror that
                # fallback's gate here, evaluated on the
                # translated form actually punycoded (checking
                # the raw label would miss an expansion that
                # introduces the violation: "م_م℃" expands to
                # "م_م°c" ending in a Latin letter, and "م©㉄"
                # expands to "م©問" mixing one in, both
                # browser-rejected too). A label containing a
                # strong-RTL character (R/AL) must start with
                # one, must end — ignoring trailing nonspacing
                # marks, which the rule allows after a valid
                # end ("م_م·م\u0301" still passes, while
                # "م_م·\u0301" fails: its last non-mark is the
                # neutral) — with a strong-RTL character or a
                # digit, must contain no Latin (L) character,
                # and must not mix European and Arabic-Indic
                # digits; a label containing an Arabic-Indic
                # digit but no strong-RTL character ("٣·",
                # "a·٣") is likewise neither a valid RTL label
                # nor a valid LTR label. Raise, so the outer
                # handler returns None for the whole host, as
                # for other rejected labels. Labels with no
                # R/AL/AN character keep their existing forms.
                # ONE DOT LEADER U+2024 and DOUBLE LOW LINE
                # U+2017 are not dot separators under WHATWG
                # (unlike U+3002/U+FF0E/U+FF61, mapped to "."
                # up front) and UTS46 disallows them outright,
                # so browsers reject every label containing
                # one — yet this branch punycoded an as-is
                # mix raw ("a©․b" -> "xn--ab-tda0533a",
                # "©․©", "é․©", "©․1", "a©‗b" likewise),
                # a form no browser origin could carry.
                # Reject here, before the bidi gate: no
                # translation in this branch introduces
                # either codepoint (they appear nowhere as a
                # map target), so checking the raw label is
                # complete, and raising returns None for the
                # whole host, as for other rejected labels.
                # Labels without either codepoint are
                # unchanged. The double-exclamation branch
                # emits the same shape for its own member
                # ("a‼․b") and keeps its existing behaviour
                # for separate assessment.
                if any(ord(c) in (0x2017, 0x2024) for c in label):
                    raise ValueError("dot-leader or double-low-line as-is")
                # The browser-rejected small forms U+FE52,
                # U+FE53, U+FE55, U+FE56 and U+FE5F are
                # likewise disallowed outright under UTS46,
                # so browsers reject every label containing
                # one — yet this branch punycoded an as-is
                # mix raw ("a©﹒b" ->
                # "xn--ab-tda2680x", and the same shape
                # for each of the other four), a form no
                # browser origin could carry. The carried
                # small forms (U+FE50, U+FE51, U+FE54,
                # U+FE57, U+FE59-U+FE5E) are mapped below
                # and are unaffected. Reject here, before
                # the bidi gate, mirroring the dot-leader
                # fix above: no translation in this branch
                # introduces any of them (they appear
                # nowhere in this helper), so checking the
                # raw label is complete, and raising
                # returns None for the whole host, as for
                # other rejected labels. Labels without
                # any of them are unchanged.
                if any(
                    ord(c) in (0xFE52, 0xFE53, 0xFE55, 0xFE56, 0xFE5F)
                    for c in label
                ):
                    raise ValueError("rejected small form as-is")
                import unicodedata as _asis_rtl_unicodedata

                # A mark-first label is browser-rejected under
                # UTS46, yet this branch punycoded an as-is
                # mix raw ("́©b" -> "xn--b-mca31p", and the
                # same shape for every combining, spacing and
                # enclosing mark first, "́©" likewise), a form
                # no browser origin could carry. Reject here,
                # before the bidi gate, mirroring the
                # dot-leader and small-form fixes above: no
                # translation in this branch introduces a
                # leading mark (no value in the as-is, double
                # exclamation, FB29, Greek Extended, enclosed,
                # kangxi, parenthesized, CJK compat, square or
                # Hebrew presentation tables starts with a
                # mark, and the mapped-dash/small-form and NFC
                # forms below cannot gain one), so checking
                # the raw label's first character is complete,
                # and raising returns None for the whole host,
                # as for other rejected labels. Labels whose
                # first character is not a mark are unchanged,
                # and mark-first labels without an as-is member
                # already fall through to None elsewhere.
                if _asis_rtl_unicodedata.category(label[0])[0] == "M":
                    raise ValueError("mark-first as-is")

                _asis_translated = (
                    label.translate(_asis_map)
                    .translate(_double_excl_map)
                    .translate({0xFB29: "+"})
                    .translate(_greek_extended_remap)
                    .translate(_enclosed_cjk_remap)
                    .translate(_kangxi_remap)
                    .translate(_parenthesized_cjk_remap)
                    .translate(_cjk_compat_remap)
                    .translate(_square_cjk_remap)
                    .translate(_hebrew_presentation_remap)
                )
                # The mapped-dash exception, mirroring the
                # hyphen-edge branch's: a label mixing an
                # as-is form with a UTS46-mapped dash
                # (U+FE31/U+FE58 to EM DASH, U+FE32 to EN
                # DASH, U+FE63 to "-") previously punycoded
                # the raw dash here, since this branch runs
                # before the hyphen-edge branch and never
                # expanded it, so such a label never matched
                # ("©︱b" -> helper "xn--b-mca6285q",
                # browser "xn--b-mca342v"; "©﹣b" ->
                # helper "xn--b-mca6795q", browser
                # "xn---b-sda"). Accept the mapped form
                # only when translating the translated form
                # through _mapped_dash reproduces its UTS46
                # remap exactly (so a label mixing a mapped
                # dash with any other UTS46-mapped character
                # keeps its existing behaviour) and the
                # mapped form is itself remap-stable; the
                # bidi gate and the punycode below then run
                # against the form actually punycoded. The
                # mapped dashes share their targets' bidi
                # classes (ON for U+FE31/U+FE32/U+FE58 to
                # EM/EN DASH, ES for U+FE63 to "-"), so the
                # gate sees the same classes either way and
                # browser-rejected mixes ("©︱م", "م︱©")
                # still fall through to None. A remap
                # failure likewise keeps the existing form.
                # The same exception covers the UTS46 small
                # forms that browsers carry in as-is labels
                # (U+FE50 -> ",", U+FE51 -> U+3001, U+FE54
                # -> ";", U+FE57 -> "!", U+FE59 -> "(",
                # U+FE5A -> ")", U+FE5B -> "{", U+FE5C ->
                # "}", U+FE5D -> U+3014, U+FE5E -> U+3015):
                # they previously punycoded raw here too
                # ("©﹔b" -> helper "xn--b-mca1395q",
                # browser "xn--;b-sda"). The exact-remap
                # and remap-stability gates below are
                # unchanged, so a mix with any other
                # UTS46-mapped character keeps its existing
                # behaviour, and the browser-rejected small
                # forms (U+FE52, U+FE53, U+FE55, U+FE56,
                # U+FE5F — URL delimiters/dot forms) are
                # deliberately not mapped here.
                _asis_mapped = _asis_translated.translate(
                    _mapped_dash
                ).translate(
                    {
                        0xFE50: ",",
                        0xFE51: "\u3001",
                        0xFE54: ";",
                        0xFE57: "!",
                        0xFE59: "(",
                        0xFE5A: ")",
                        0xFE5B: "{",
                        0xFE5C: "}",
                        0xFE5D: "\u3014",
                        0xFE5E: "\u3015",
                    }
                )
                if _asis_mapped != _asis_translated:
                    try:
                        _asis_remapped = _idna.uts46_remap(
                            _asis_translated,
                            std3_rules=False,
                            transitional=False,
                        )
                    except (UnicodeError, ValueError):
                        _asis_remapped = None
                    if _asis_remapped == _asis_mapped:
                        try:
                            _asis_mapped_stable = (
                                _idna.uts46_remap(
                                    _asis_mapped,
                                    std3_rules=False,
                                    transitional=False,
                                )
                            )
                        except (UnicodeError, ValueError):
                            _asis_mapped_stable = None
                        if _asis_mapped_stable == _asis_mapped:
                            _asis_translated = _asis_mapped
                    # The NFC-normalizing variant of the
                    # mapped-dash/small-form exception above,
                    # mirroring the hyphen-edge branch's NFC
                    # arm: a label such as
                    # "a\u0301\u00a9\ufe31b" was previously
                    # left at its raw form, because
                    # translating it through the mapped
                    # tables gives "a\u0301\u00a9\u2014b",
                    # whose remap is its NFC form
                    # "\u00e1\u00a9\u2014b" rather than
                    # itself — but UTS46 processing
                    # NFC-normalizes before punycoding, so
                    # the browser form is the punycode of
                    # that NFC form ("xn--b-mca1ov24j").
                    # Accept the NFC form only when it is
                    # exactly the remap (so a label mixing
                    # a mapped dash with another UTS46-mapped
                    # character, e.g. "a\u0301\u212a\ufe31b",
                    # keeps its existing behaviour) and it
                    # is itself remap-stable; the bidi gate
                    # and the punycode below then run against
                    # the form actually punycoded, so a
                    # browser-rejected mix still falls
                    # through to None.
                    if _asis_translated != _asis_mapped:
                        _asis_mapped_nfc = (
                            _asis_rtl_unicodedata.normalize(
                                "NFC", _asis_mapped
                            )
                        )
                        if _asis_mapped_nfc == _asis_remapped:
                            try:
                                _asis_mapped_nfc_stable = (
                                    _idna.uts46_remap(
                                        _asis_mapped_nfc,
                                        std3_rules=False,
                                        transitional=False,
                                    )
                                )
                            except (UnicodeError, ValueError):
                                _asis_mapped_nfc_stable = None
                            if (
                                _asis_mapped_nfc_stable
                                == _asis_mapped_nfc
                            ):
                                _asis_translated = _asis_mapped_nfc
                # The plain NFC-normalizing arm, mirroring
                # the mapped-dash/small-form NFC arm above: a
                # label mixing an as-is form with a decomposed
                # sequence but no mapped dash or small form
                # (so _asis_mapped == _asis_translated and the
                # arm above never ran) previously punycoded
                # raw here ("a\u0301\u00a9b" ->
                # "xn--ab-tda31v"), while UTS46 processing
                # NFC-normalizes before punycoding, so the
                # browser form is the punycode of the NFC
                # form ("xn--b-mca1o"). Accept the NFC form
                # only when it is exactly the UTS46 remap of
                # the translated form (so a label mixing in
                # any other UTS46-mapped character keeps its
                # existing behaviour) and it is itself
                # remap-stable; the bidi gate and the
                # punycode below then run against the form
                # actually punycoded, so a browser-rejected
                # mix still falls through to None. Labels
                # already in NFC are unchanged.
                if _asis_mapped == _asis_translated:
                    _asis_nfc = (
                        _asis_rtl_unicodedata.normalize(
                            "NFC", _asis_translated
                        )
                    )
                    if _asis_nfc != _asis_translated:
                        try:
                            _asis_nfc_remapped = (
                                _idna.uts46_remap(
                                    _asis_translated,
                                    std3_rules=False,
                                    transitional=False,
                                )
                            )
                        except (UnicodeError, ValueError):
                            _asis_nfc_remapped = None
                        if _asis_nfc_remapped == _asis_nfc:
                            try:
                                _asis_nfc_stable = (
                                    _idna.uts46_remap(
                                        _asis_nfc,
                                        std3_rules=False,
                                        transitional=False,
                                    )
                                )
                            except (UnicodeError, ValueError):
                                _asis_nfc_stable = None
                            if _asis_nfc_stable == _asis_nfc:
                                _asis_translated = _asis_nfc
                # A space separator (Unicode category Zs:
                # U+0020, U+00A0, U+2000-U+200A, U+202F,
                # U+205F, U+3000) in an as-is label is
                # browser-rejected under WHATWG/UTS46 — the
                # pipeline deliberately leaves an interior
                # space alone, since the URL parser fails
                # host parsing on it instead of removing
                # it — yet this branch punycoded an as-is
                # mix raw ("a© b" -> "xn--a b-zea", and
                # the same shape for every other Zs member),
                # a form no browser origin could carry.
                # Reject here, before the bidi gate,
                # checked on the translated form actually
                # punycoded (so a mapped-dash/small-form
                # or NFC form below cannot gain one either),
                # raising so the outer handler returns None
                # for the whole host, as for other rejected
                # labels. Labels without a space separator
                # are unchanged. ZERO WIDTH NON-JOINER
                # U+200C and ZERO WIDTH JOINER U+200D are
                # deliberately NOT rejected here: they are
                # ContextJ-valid in some as-is mixes the
                # browser carries and this branch already
                # matches ("م©‌م" with ZWNJ, "क्‍©" with
                # ZWJ after a virama), so a blanket joiner
                # reject would regress them; only the
                # never-valid space separators are gated.
                if any(
                    _asis_rtl_unicodedata.category(c) == "Zs"
                    for c in _asis_translated
                ):
                    raise ValueError("space separator as-is")
                # An Arabic presentation form carried as-is
                # (_punycode_arabic_presentation_as_is) in an
                # as-is label is invisible to this gate as
                # written: this Python's Unicode data leaves
                # most of the set unassigned (no bidi class
                # at all), gives others a neutral (ON) class,
                # and gives U+FBC2 an AL class — yet browsers
                # treat every one of them as a Latin-class
                # letter, so a label mixing one with a
                # strong-RTL character is browser-rejected
                # while the gate above passed it and emitted
                # raw punycode ("م©﯃1", "م©﯃٣" and "م©﯃م"
                # all rejected by the WHATWG parser, as are
                # the same shapes for every other member of
                # the set). Map each member to "L" for the
                # gate, so the existing "L" check raises for
                # exactly those mixes; labels without a
                # strong-RTL character are unaffected (the
                # gate only acts when one is present), so
                # standalone as-is mixes ("©﯃") keep their
                # existing forms, and U+FBC2's standalone
                # mix ("©﯂", previously None via its AL
                # class) now emits the browser's form too.
                # Excepted: U+FD3E, U+FD3F and U+FDFD, which
                # behave as neutrals in browsers (the same
                # shapes are accepted for them), so mapping
                # them to "L" would wrongly reject valid
                # labels.
                _asis_bidi = [
                    (
                        "L"
                        if ord(c)
                        in _punycode_arabic_presentation_as_is
                        and ord(c) not in (0xFD3E, 0xFD3F, 0xFDFD)
                        else _asis_rtl_unicodedata.bidirectional(c)
                    )
                    for c in _asis_translated
                ]
                # The U+0888 exception to the bidi gate below,
                # mirroring the hyphen-edge branch's
                # _hyph_0888_latin_ok: ARABIC RAISED ROUND DOT
                # U+0888 is a strong-RTL symbol (bidi class
                # AL), so the gate below raised for every
                # Latin as-is label mixing it in ("a—࢈b",
                # "a©࢈b", "a·࢈b" all fell through to None)
                # while browsers carry them (verified
                # against Node's WHATWG parser). Admit it
                # only in a Latin label: every R/AL/AN-bidi
                # character in the translated form must be
                # U+0888 itself (the _asis_bidi mapping above
                # already counts an Arabic presentation form
                # as "L", so a mix with one, e.g.
                # "a—﯂࢈b", is admitted too), the first
                # character must not be a mark (a mark-first
                # label is browser-rejected), every character
                # must be an admitted ASCII character, an
                # as-is member, an Arabic presentation
                # as-is member, or a non-ASCII letter, mark,
                # number, symbol or punctuation that is not
                # right-to-left (so a space, joiner or other
                # separator, which the positive gate already
                # excludes, keeps its existing behaviour),
                # and none may be a browser-rejected
                # dot-mapping or double-low-line form
                # (U+2017, U+2024, U+3002, U+FF0E, U+FF61).
                # An RTL mix ("م—࢈"), a Latin/RTL mix
                # ("a—א࢈b") or a mix with an Arabic-Indic
                # digit ("a—࢈٣"), which browsers reject,
                # raises: the Latin/RTL and digit mixes via
                # the gate below, and the pure RTL mix via
                # the U+0888-plus-strong-RTL clause in the
                # gate below, since the all-U+0888 condition
                # fails for all of them.
                _asis_0888_latin_ok = (
                    "\u0888" in _asis_translated
                    and _asis_rtl_unicodedata.category(
                        _asis_translated[0]
                    )[0] != "M"
                    and all(
                        ord(c) == 0x0888
                        for c, b in zip(
                            _asis_translated, _asis_bidi
                        )
                        if b in ("R", "AL", "AN")
                    )
                    and not any(
                        ord(c)
                        in (0x2017, 0x2024, 0x3002, 0xFF0E, 0xFF61)
                        for c in _asis_translated
                    )
                    and all(
                        c
                        in (
                            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-+()!"
                        )
                        or ord(c) == 0x0888
                        or ord(c) in _punycode_asis
                        or ord(c)
                        in _punycode_arabic_presentation_as_is
                        or (
                            ord(c) > 127
                            and _asis_rtl_unicodedata.category(c)[0]
                            in "LMNSP"
                            and _asis_rtl_unicodedata.bidirectional(c)
                            not in ("R", "AL", "AN")
                        )
                        for c in _asis_translated
                    )
                )
                if (
                    any(b in ("R", "AL") for b in _asis_bidi)
                    and not _asis_0888_latin_ok
                ):
                    _asis_end = None
                    for _b in reversed(_asis_bidi):
                        if _b != "NSM":
                            _asis_end = _b
                            break
                    if (
                        _asis_bidi[0] not in ("R", "AL")
                        or _asis_end
                        not in ("R", "AL", "EN", "AN")
                        or "L" in _asis_bidi
                        or ("EN" in _asis_bidi and "AN" in _asis_bidi)
                        # Browsers reject every RTL label that
                        # mixes U+0888 with another strong-RTL
                        # character ("م—࢈", "م—࢈م", "م·࢈م"
                        # all rejected by the WHATWG parser),
                        # even though the first/end/L checks
                        # above pass for them (first and last
                        # strong-RTL, no Latin letter), so
                        # they were emitted as raw punycode
                        # that no browser origin could carry.
                        # U+0888 alone or with neutrals/Latin
                        # ("—࢈", "a—࢈b") is unaffected: the
                        # Latin exception above already skips
                        # the raise for those, and this clause
                        # needs another strong-RTL character
                        # besides U+0888 itself.
                        or (
                            "\u0888" in _asis_translated
                            and any(
                                b in ("R", "AL")
                                and ord(c) != 0x0888
                                for c, b in zip(
                                    _asis_translated, _asis_bidi
                                )
                            )
                        )
                    ):
                        raise ValueError("rtl bidi as-is")
                elif "AN" in _asis_bidi:
                    raise ValueError("an as-is without rtl")
                encoded_labels.append(
                    "xn--"
                    + _asis_translated.encode("punycode").decode("ascii")
                )
            elif any(ord(c) in _double_excl_map for c in label):
                # UTS46 maps DOUBLE EXCLAMATION MARK U+203C to "!!"
                # before IDNA processing, while the `idna` package
                # rejects both the raw codepoint and the mapped "!"
                # under strict and UTS46 processing — so a
                # configured origin containing one was left alone
                # and never matched under Starlette's exact
                # allow_origins matching. An up-front translate
                # alone would not fix it: the mapped "!" would
                # hit _idna.encode below and fail the whole host.
                # Remap and handle the remapped form directly, as
                # the fraction branch does: a pure-ASCII remap
                # passes through unchanged (browsers leave ASCII
                # labels alone: "‼.example" -> "!!.example",
                # "a‼b.example" -> "a!!b.example"), while a remap
                # that still has non-ASCII punycodes directly
                # ("‼münchen" -> "xn--!!mnchen-85a"). Placed
                # after the as-is branch, which now expands
                # U+203C itself for as-is mixes (see there), so
                # this branch handles U+203C labels without an
                # as-is form, and labels combining it with a
                # fraction keep the fraction branch's behaviour
                # above.
                # Browsers remap an enclosed or parenthesized
                # CJK member first (㈀ -> "(ᄀ)", ㉄ -> "問",
                # ㉐ -> "pte", ㋿ -> "令和"), but this branch
                # punycoded the label raw, so a ‼ mix never
                # matched ("㈀‼" -> helper "xn--!!-gb5a",
                # browser "xn--()!!-qir"). Translate through
                # the enclosed and parenthesized tables the
                # as-is branch already uses; the tables' key
                # domains are disjoint and their outputs are
                # not members of either table, so labels
                # without such a member are unchanged, and
                # browser-rejected U+321F (in neither table)
                # keeps its existing behaviour for separate
                # assessment.
                # The same gap held for square CJK members
                # (㌀ -> "アパート", ㍱ -> "hpa"): the branch
                # punycoded them raw, so a ‼ mix never matched
                # ("‼㌀" -> helper "xn--!!-gx5a", browser
                # "xn--!!-ig4aogtb8q"; "‼㍱" -> helper
                # "xn--!!-465a", browser plain "!!hpa").
                # Translate through the square table too; its
                # key domain is disjoint from the other two
                # tables and its outputs are members of neither,
                # so labels without a square member are unchanged.
                # The same gap held for U+FB29: the branch
                # punycoded it raw, so a ‼ mix never matched
                # ("م‼﬩م" -> helper "xn--!!-vvdc37542a",
                # browser "xn--!!+-22ed"). UTS46 maps U+FB29
                # to "+" first, as the as-is branch already
                # does (see there); translate it here too.
                # Its key domain is disjoint from the other
                # tables, so labels without U+FB29 are
                # unchanged. Translating alone is not enough:
                # a "+" in an RTL label is only valid in the
                # middle (a trailing "+" is browser-rejected:
                # "م‼﬩" is an invalid URL), and the branch
                # had no bidi gate at all, so it also emitted
                # forms no browser origin could carry ("م‼",
                # "‼م", "٣‼"). Gate the remapped form exactly
                # as the as-is branch does (same "L" mapping
                # for the Arabic presentation as-is members,
                # which browsers treat as Latin letters):
                # an RTL label must start with R/AL, end
                # (ignoring NSM) with R/AL/EN/AN, contain no
                # L, and not mix EN and AN digits; a label
                # with AN but no R/AL is likewise rejected.
                # Raising here returns None for the whole
                # host via the loop's handler, matching the
                # browser's rejection; labels that already
                # matched ("م‼م", "م‼٣", "م٣‼م") pass the
                # gate unchanged.
                # The same gap held for Greek Extended members
                # (ά U+1F71 -> ά, ᾀ U+1F80 -> ἀι, ι U+1FBE
                # -> ι): the branch punycoded them raw, so a
                # ‼ mix never matched ("a‼ά" -> helper
                # "xn--a!!-m4z", browser "xn--a!!-5wc", which
                # decodes to the remapped "a!!ά"). Translate
                # through the Greek Extended table the as-is
                # branch already uses; its key domain is
                # disjoint from the other tables and its
                # outputs are plain Greek letters (bidi class
                # L, as the raw members are), so labels
                # without a Greek Extended member are
                # unchanged and the bidi gate above sees the
                # same classes either way.
                # ONE DOT LEADER U+2024 and DOUBLE LOW LINE
                # U+2017 are not dot separators under WHATWG
                # (unlike U+3002/U+FF0E/U+FF61, mapped to "."
                # up front) and UTS46 disallows them outright,
                # so browsers reject every label containing
                # one — yet this branch punycoded a ‼ mix raw
                # ("a‼․b" -> "xn--a!!b-ic7a", "‼․",
                # "a‼‗b" likewise), a form no browser origin
                # could carry. Reject here, before the bidi
                # gate, mirroring the as-is branch's fix
                # (iteration 704): no translation in this
                # branch introduces either codepoint (none
                # appears as a value in the ‼, enclosed,
                # parenthesized, square, FB29 or Greek
                # Extended tables above), so checking the raw
                # label is complete, and raising returns None
                # for the whole host, as for other rejected
                # labels. Labels without either codepoint are
                # unchanged.
                if any(ord(c) in (0x2017, 0x2024) for c in label):
                    raise ValueError("dot-leader or double-low-line double-exclamation")
                # The browser-rejected small forms U+FE52,
                # U+FE53, U+FE55, U+FE56 and U+FE5F are
                # likewise disallowed outright under UTS46,
                # so browsers reject every label containing
                # one — yet this branch punycoded a ‼ mix
                # raw ("a‼﹒b" -> "xn--a!!b-xh9x", and
                # the same shape for each of the other
                # four, including the RTL "م‼﹒م"), a form
                # no browser origin could carry. Reject
                # here, before the bidi gate, mirroring
                # the as-is branch's fix above: no
                # translation in this branch introduces
                # any of them (they appear nowhere in
                # this helper), so checking the raw label
                # is complete, and raising returns None
                # for the whole host, as for other
                # rejected labels. Labels without any of
                # them are unchanged.
                if any(
                    ord(c) in (0xFE52, 0xFE53, 0xFE55, 0xFE56, 0xFE5F)
                    for c in label
                ):
                    raise ValueError("rejected small form double-exclamation")
                # A mark-first label is browser-rejected under
                # UTS46, yet this branch punycoded a ‼ mix
                # raw ("́‼b" -> "xn--!!b-jdc", and the
                # same shape for every combining, spacing and
                # enclosing mark first, "́‼" likewise), a form
                # no browser origin could carry. Reject here,
                # before the bidi gate, mirroring the as-is
                # branch's mark-first fix (iteration 711):
                # no translation in this branch introduces a
                # leading mark (none appears as a value in
                # the ‼, enclosed, parenthesized, square,
                # FB29 or Greek Extended tables), so checking
                # the raw label's first character is complete,
                # and raising returns None for the whole host,
                # as for other rejected labels. Labels whose
                # first character is not a mark are unchanged.
                import unicodedata as _excl_mark_unicodedata

                if _excl_mark_unicodedata.category(label[0])[0] == "M":
                    raise ValueError("mark-first double-exclamation")
                _excl_remapped = (
                    label.translate(_double_excl_map)
                    .translate(_enclosed_cjk_remap)
                    .translate(_parenthesized_cjk_remap)
                    .translate(_square_cjk_remap)
                    .translate({0xFB29: "+"})
                    .translate(_greek_extended_remap)
                )
                import unicodedata as _excl_unicodedata

                # The NFC-normalizing arm, mirroring the
                # as-is branch's plain NFC arm (iteration
                # 708): a label mixing a double
                # exclamation with a decomposed sequence
                # previously punycoded raw here
                # ("a\u0301\u203cb" -> "xn--a!!b-vvc"),
                # while UTS46 processing
                # NFC-normalizes before punycoding, so
                # the browser form is the punycode of
                # the NFC form ("xn--!!b-dla").
                # Accept the NFC form only when it is
                # exactly the UTS46 remap of the
                # remapped form (so a label mixing in
                # any other UTS46-mapped character
                # keeps its existing behaviour) and it
                # is itself remap-stable, and only
                # when the remapped form contains no
                # space, separator or format character
                # (so the pre-existing space/joiner
                # over-emissions keep their existing
                # form for separate assessment). The
                # bidi gate and the punycode below
                # then run against the form actually
                # punycoded, so a browser-rejected
                # mix still falls through to None.
                # Labels already in NFC are unchanged.
                _excl_nfc = _excl_unicodedata.normalize(
                    "NFC", _excl_remapped
                )
                if _excl_nfc != _excl_remapped and not any(
                    _excl_unicodedata.category(c)[0] in "ZC"
                    for c in _excl_remapped
                ):
                    try:
                        _excl_nfc_remapped = _idna.uts46_remap(
                            _excl_remapped,
                            std3_rules=False,
                            transitional=False,
                        )
                    except (UnicodeError, ValueError):
                        _excl_nfc_remapped = None
                    if _excl_nfc_remapped == _excl_nfc:
                        try:
                            _excl_nfc_stable = _idna.uts46_remap(
                                _excl_nfc,
                                std3_rules=False,
                                transitional=False,
                            )
                        except (UnicodeError, ValueError):
                            _excl_nfc_stable = None
                        if _excl_nfc_stable == _excl_nfc:
                            _excl_remapped = _excl_nfc
                # The mapped-dash arm, mirroring the NFC
                # arm above: a label mixing a double
                # exclamation with a UTS46-mapped dash
                # previously punycoded the presentation
                # form raw here ("a\u203c\ufe31b" ->
                # "xn--a!!b-7c9x"), while UTS46
                # processing maps the dash first, so
                # the browser form is the punycode of
                # the mapped form ("xn--a!!b-786a",
                # which decodes to "a!!\u2014b"). The
                # candidate is the NFC form of the
                # mapped-dash translation (so a
                # decomposed mix such as
                # "a\u0301\u203c\ufe31b" also lands on
                # its browser form "xn--!!b-dla1501b"
                # rather than only the dash being
                # fixed). Accept it only when it is
                # exactly the UTS46 remap of the
                # remapped form (so a label mixing in
                # any other UTS46-mapped character,
                # e.g. "a\u203c\u212ab", keeps its
                # existing behaviour) and it is itself
                # remap-stable, and only when the
                # remapped form contains no space,
                # separator or format character (so
                # the pre-existing space/joiner
                # over-emissions keep their existing
                # form for separate assessment). The
                # bidi gate and the punycode below
                # then run against the form actually
                # punycoded, so a browser-rejected
                # mix still falls through to None.
                # Labels without a mapped dash are
                # unchanged.
                _excl_dash = _excl_unicodedata.normalize(
                    "NFC",
                    _excl_remapped.translate(_mapped_dash),
                )
                if (
                    _excl_dash != _excl_remapped
                    and _excl_unicodedata.category(
                        _excl_remapped[0]
                    )[0]
                    != "M"
                    and not any(
                        _excl_unicodedata.category(c)[0] in "ZC"
                        for c in _excl_remapped
                    )
                ):
                    try:
                        _excl_dash_remapped = _idna.uts46_remap(
                            _excl_remapped,
                            std3_rules=False,
                            transitional=False,
                        )
                    except (UnicodeError, ValueError):
                        _excl_dash_remapped = None
                    if _excl_dash_remapped == _excl_dash:
                        try:
                            _excl_dash_stable = _idna.uts46_remap(
                                _excl_dash,
                                std3_rules=False,
                                transitional=False,
                            )
                        except (UnicodeError, ValueError):
                            _excl_dash_stable = None
                        if _excl_dash_stable == _excl_dash:
                            _excl_remapped = _excl_dash
                # A space separator (Unicode category Zs:
                # U+0020, U+00A0, U+2000-U+200A, U+202F,
                # U+205F, U+3000) in a double-exclamation
                # label is browser-rejected under
                # WHATWG/UTS46 — the pipeline deliberately
                # leaves an interior space alone, since
                # the URL parser fails host parsing on it
                # instead of removing it — yet this branch
                # emitted a ‼ mix raw ("a‼ b" -> "a!! b",
                # and a punycode form for every other Zs
                # member, e.g. "a‼ b" -> "xn--a!!b-xea"),
                # a form no browser origin could carry.
                # Reject here, before the bidi gate,
                # mirroring the as-is branch's fix
                # (iteration 713), checked on the
                # remapped form actually punycoded: no
                # translation in this branch introduces
                # a Zs character (none appears as a value
                # in the ‼, enclosed, parenthesized,
                # square, FB29 or Greek Extended tables,
                # and the NFC/mapped-dash arms already
                # skip space labels via their ZC guards),
                # so the check is complete, and raising
                # returns None for the whole host, as for
                # other rejected labels. Labels without a
                # space separator are unchanged. ZERO WIDTH
                # NON-JOINER U+200C and ZERO WIDTH JOINER
                # U+200D are deliberately NOT rejected
                # here: they are ContextJ-valid in some
                # ‼ mixes the browser carries and this
                # branch already matches ("م‼‌م" with
                # ZWNJ, "क्‍‼b" with ZWJ after a virama),
                # so a blanket joiner reject would
                # regress them; only the never-valid
                # space separators are gated here, and
                # the Latin-ZWNJ over-emission ("a‼‌b")
                # is gated by the ZWNJ gate below;
                # the ZWJ over-emission is gated just
                # below.
                if any(
                    _excl_unicodedata.category(c) == "Zs"
                    for c in _excl_remapped
                ):
                    raise ValueError("space separator double-exclamation")
                # ZERO WIDTH JOINER U+200D in a
                # double-exclamation label is
                # browser-rejected under WHATWG/UTS46
                # unless its ContextJ rule holds — and
                # the browser's rule, verified against
                # Node's WHATWG parser, checks only
                # the label's first ZWJ: scanning back
                # from it past any joiners (U+200C /
                # U+200D) must reach a virama (a
                # character with canonical combining
                # class 9, e.g. DEVANAGARI SIGN VIRAMA
                # U+094D) — yet this branch emitted a
                # ‼ mix raw ("a‼‍b" ->
                # "xn--a!!b-776a", "م‼‍م" likewise), a
                # form no browser origin could carry.
                # Reject here, before the bidi gate,
                # checked on the remapped form actually
                # punycoded: no translation in this
                # branch introduces or removes a
                # virama or a joiner (none appears as a
                # value in the ‼, enclosed,
                # parenthesized, square, FB29 or Greek
                # Extended tables, and the NFC /
                # mapped-dash arms already skip joiner
                # labels via their ZC guards), so the
                # check is complete, and raising
                # returns None for the whole host, as
                # for other rejected labels. A first
                # ZWJ that does follow a virama
                # (directly or past joiners) is
                # unchanged, and later ZWJs are
                # unchecked, matching the browser
                # ("क्‍‼b", "क्‍b‍c", "क्‌‍‼b" all
                # carried; "a‼‍b", "a‌‍‼b", "م‌‍‼b"
                # all rejected). ZERO WIDTH NON-JOINER
                # U+200C is gated just below: its full
                # ContextJ rule depends on Joining_Type
                # data the stdlib does not expose, and
                # the browser carries some ZWNJ ‼ mixes
                # ("م‼‌م"), so the gate below only
                # rejects the no-joining-letter-on-a-
                # side cases and the finer rule stays
                # for a separate assessment.
                _excl_zwj = _excl_remapped.find("\u200d")
                if _excl_zwj != -1:
                    _excl_zwj_prev = _excl_zwj - 1
                    while (
                        _excl_zwj_prev >= 0
                        and _excl_remapped[_excl_zwj_prev]
                        in ("\u200c", "\u200d")
                    ):
                        _excl_zwj_prev -= 1
                    if (
                        _excl_zwj_prev < 0
                        or _excl_unicodedata.combining(
                            _excl_remapped[_excl_zwj_prev]
                        )
                        != 9
                    ):
                        raise ValueError(
                            "joiner without virama double-exclamation"
                        )
                # ZERO WIDTH NON-JOINER U+200C in a
                # double-exclamation label is
                # browser-rejected under WHATWG/UTS46
                # unless its ContextJ rule holds — and
                # this branch emitted a ‼ mix raw
                # ("a‼‌b" -> "xn--a!!b-276a",
                # "a‼‌" -> "xn--a!!-cn0a",
                # "م‼م‌٣" likewise), a form no browser
                # origin could carry. The browser's
                # rule, verified against Node's WHATWG
                # parser, checks only the label's first
                # joiner (a ZWNJ here is unchecked when
                # a ZWJ precedes it, as in "क्‍‼‌b",
                # and later ZWNJs are unchecked, as in
                # "م‼‌م‌٣"), and the first ZWNJ needs a
                # joining letter on both sides: scanning
                # out from it past every non-joining
                # character (digits, punctuation, the
                # "!!" the ‼ maps to, marks, and other
                # joiners) must reach a letter of a
                # joining script on each side, or the
                # label is rejected ("a‼‌b" has no
                # joining letter before it, "a‼‌" and
                # "م‼م‌٣" none after it). Checked on the
                # remapped form actually punycoded, so
                # the check is complete, and raising
                # returns None for the whole host, as
                # for other rejected labels. A joining
                # letter on both sides is unchanged
                # ("م‼‌م", "م‼٣‌م", "م‼م‌٣‌م" all still
                # emit). The finer rule — a
                # right-joining-only letter before the
                # ZWNJ ("ا‌م", "ܐ‼‌ܐ") is
                # browser-rejected unless it is itself
                # joined from the left ("م‌و‌م") — needs
                # Joining_Type data the stdlib does not
                # expose, so those mixes keep their
                # existing behaviour for a separate
                # assessment; this gate only rejects
                # the no-joining-letter-on-a-side cases.
                def _excl_zwnj_joining(_c: str) -> bool:
                    # A letter of a joining script:
                    # Arabic (including Supplement,
                    # Extended-A/B and the presentation
                    # forms), Syriac (including
                    # Supplement), NKo, Mongolian,
                    # Adlam, Manichaean, Psalter
                    # Pahlavi and Hanifi Rohingya.
                    # Deliberately broad: a letter
                    # counted here can only keep a label
                    # emitting, never newly reject one,
                    # so an over-broad block is safe
                    # while a missed joining letter
                    # would be a false reject.
                    return _excl_unicodedata.category(_c)[0] == "L" and (
                        0x0600 <= ord(_c) <= 0x06FF
                        or 0x0700 <= ord(_c) <= 0x074F
                        or 0x0750 <= ord(_c) <= 0x077F
                        or 0x07C0 <= ord(_c) <= 0x07FF
                        or 0x0860 <= ord(_c) <= 0x086F
                        or 0x0870 <= ord(_c) <= 0x089F
                        or 0x08A0 <= ord(_c) <= 0x08FF
                        or 0x1800 <= ord(_c) <= 0x18AF
                        or 0x1E900 <= ord(_c) <= 0x1E95F
                        or 0x10AC0 <= ord(_c) <= 0x10AFF
                        or 0x10B80 <= ord(_c) <= 0x10BAF
                        or 0x10D00 <= ord(_c) <= 0x10D8F
                        or 0xFB50 <= ord(_c) <= 0xFDFF
                        or 0xFE70 <= ord(_c) <= 0xFEFF
                    )

                _excl_zwnj = _excl_remapped.find("\u200c")
                if (
                    _excl_zwnj != -1
                    and "\u200d" not in _excl_remapped[:_excl_zwnj]
                ):
                    _excl_zwnj_prev = _excl_zwnj - 1
                    while _excl_zwnj_prev >= 0 and not _excl_zwnj_joining(
                        _excl_remapped[_excl_zwnj_prev]
                    ):
                        _excl_zwnj_prev -= 1
                    _excl_zwnj_next = _excl_zwnj + 1
                    while _excl_zwnj_next < len(
                        _excl_remapped
                    ) and not _excl_zwnj_joining(_excl_remapped[_excl_zwnj_next]):
                        _excl_zwnj_next += 1
                    if (
                        _excl_zwnj_prev < 0
                        or _excl_zwnj_next >= len(_excl_remapped)
                    ):
                        raise ValueError(
                            "joiner without joining letters double-exclamation"
                        )
                _excl_bidi = [
                    (
                        "L"
                        if ord(c)
                        in _punycode_arabic_presentation_as_is
                        and ord(c) not in (0xFD3E, 0xFD3F, 0xFDFD)
                        else _excl_unicodedata.bidirectional(c)
                    )
                    for c in _excl_remapped
                ]
                # The U+0888 exception to the bidi gate below,
                # mirroring the as-is branch's
                # _asis_0888_latin_ok: ARABIC RAISED ROUND DOT
                # U+0888 is a strong-RTL symbol (bidi class
                # AL), so the gate below raised for every
                # Latin double-exclamation label mixing it in
                # ("a‼࢈b", "‼࢈b", "a‼࢈" all fell through
                # to None) while browsers carry them
                # (verified against Node's WHATWG parser).
                # Admit it only in a Latin label: every
                # R/AL/AN-bidi character in the remapped form
                # must be U+0888 itself (the _excl_bidi
                # mapping above already counts an Arabic
                # presentation form as "L", so a mix with
                # one, e.g. "a‼﯂࢈b", is admitted too), the
                # first character must not be a mark (a
                # mark-first label is browser-rejected),
                # every character must be an admitted ASCII
                # character, an as-is member, an Arabic
                # presentation as-is member, or a non-ASCII
                # letter, mark, number, symbol or
                # punctuation that is not right-to-left (so
                # a space, joiner or other separator, which
                # the positive gate already excludes, keeps
                # its existing behaviour), and none may be
                # a browser-rejected dot-mapping or
                # double-low-line form (U+2017, U+2024,
                # U+3002, U+FF0E, U+FF61). An RTL mix
                # ("م‼࢈", "م‼࢈م"), a Latin/RTL mix
                # ("a‼࢈אb") or a mix with an Arabic-Indic
                # digit ("a‼࢈٣"), which browsers reject,
                # raises: the Latin/RTL and digit mixes via
                # the gate below, and the pure RTL mix via
                # the U+0888-plus-strong-RTL clause in the
                # gate below, since the all-U+0888 condition
                # fails for all of them.
                _excl_0888_latin_ok = (
                    "\u0888" in _excl_remapped
                    and _excl_unicodedata.category(
                        _excl_remapped[0]
                    )[0] != "M"
                    and all(
                        ord(c) == 0x0888
                        for c, b in zip(
                            _excl_remapped, _excl_bidi
                        )
                        if b in ("R", "AL", "AN")
                    )
                    and not any(
                        ord(c)
                        in (0x2017, 0x2024, 0x3002, 0xFF0E, 0xFF61)
                        for c in _excl_remapped
                    )
                    and all(
                        c
                        in (
                            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-+()!"
                        )
                        or ord(c) == 0x0888
                        or ord(c) in _punycode_asis
                        or ord(c)
                        in _punycode_arabic_presentation_as_is
                        or (
                            ord(c) > 127
                            and _excl_unicodedata.category(c)[0]
                            in "LMNSP"
                            and _excl_unicodedata.bidirectional(c)
                            not in ("R", "AL", "AN")
                        )
                        for c in _excl_remapped
                    )
                )
                if (
                    any(b in ("R", "AL") for b in _excl_bidi)
                    and not _excl_0888_latin_ok
                ):
                    _excl_end = None
                    for _b in reversed(_excl_bidi):
                        if _b != "NSM":
                            _excl_end = _b
                            break
                    if (
                        _excl_bidi[0] not in ("R", "AL")
                        or _excl_end
                        not in ("R", "AL", "EN", "AN")
                        or "L" in _excl_bidi
                        or ("EN" in _excl_bidi and "AN" in _excl_bidi)
                        # Browsers reject every RTL label that
                        # mixes U+0888 with another strong-RTL
                        # character ("م‼࢈", "م‼࢈م", "م‼م࢈"
                        # all rejected by the WHATWG parser),
                        # even though the first/end/L checks
                        # above pass for them, so they were
                        # emitted as raw punycode that no
                        # browser origin could carry — the
                        # same class as the as-is branch's
                        # gate above. U+0888 alone or with
                        # neutrals/Latin is unaffected: the
                        # Latin exception above already skips
                        # the raise for those, and this clause
                        # needs another strong-RTL character
                        # besides U+0888 itself.
                        or (
                            "\u0888" in _excl_remapped
                            and any(
                                b in ("R", "AL")
                                and ord(c) != 0x0888
                                for c, b in zip(
                                    _excl_remapped, _excl_bidi
                                )
                            )
                        )
                    ):
                        raise ValueError("rtl bidi double-exclamation")
                elif "AN" in _excl_bidi:
                    raise ValueError("an double-exclamation without rtl")
                if any(ord(c) > 127 for c in _excl_remapped):
                    encoded_labels.append(
                        "xn--"
                        + _excl_remapped.encode("punycode").decode(
                            "ascii"
                        )
                    )
                else:
                    encoded_labels.append(_excl_remapped)
            elif any(0x20D0 <= ord(c) <= 0x20F0 for c in label) and not any(
                ord(c) in (0x0608, 0x060B)
                or 0xFBB2 <= ord(c) <= 0xFBC1
                or ord(c) in (0x1ECAC, 0x1ECB0, 0x1ED2E)
                for c in label
            ):
                # Combining marks for symbols U+20D0-U+20F0: the
                # gap-symbol exclusion above mirrors the emoji
                # branch's _emoji_al_gap set below: a label with
                # both a gap symbol and a U+20D0-U+20F0 mark was
                # claimed here, but the whole-label remap below
                # raises on the gap symbol, so the gate failed
                # and the label fell through to None (or to the
                # raw "_" punycode for underscore labels) even
                # though browsers carry it ("م؈⃐" ->
                # "xn--qfb5jl92f", verified against Node's
                # WHATWG parser). Such a label now falls
                # through to the emoji branch's gap arm, whose
                # first/last bidi, digit-mix and per-character
                # gates already admit exactly the carried
                # shapes (a U+20D0-U+20F0 mark is category M
                # with bidi NSM, admitted mid-label and at the
                # end, and remaps to itself), including the
                # mapped-symbol forms, while still rejecting
                # Latin mixes and underscore labels, which the
                # browser rejects too. Labels without a gap
                # symbol are unchanged.
                # `idna` package rejects them under both strict
                # and UTS46 processing, so neither path above
                # reproduces them — but browsers punycode a label
                # with such a mark after a base character as-is
                # ("a\u20d0" -> "xn--a-zrn", "a\u20d0b" ->
                # "xn--ab-cju", stacked "a\u20d0\u20d1" ->
                # "xn--a-zrnd"), matching the punycode form.
                # A mark alone at a label start is browser-rejected
                # ("\u20d0a" is an invalid URL), as are the
                # unassigned U+20F1-U+20FF forms even after a base
                # ("a\u20f1" is rejected), so the range gate above
                # excludes them, the remap below raises for them,
                # and the first-character gate excludes mark-first
                # labels — all fall through to the existing
                # branches (None for a plain label, as before).
                # The label is punycoded in its UTS46-remapped
                # form, not raw: a decomposed "a\u0300\u20d0"
                # normalizes to "à\u20d0" and a micro sign remaps
                # to μ before browsers punycode, so the remapped
                # punycode ("xn--0ca664n", "xn--a-mmb644t") is the
                # browser form while the raw punycode is not.
                # The gates mirror the FB29 mixed-label gates: the
                # remap must succeed and be idempotent, the mark
                # must survive it, the first character must not
                # be a mark, and every other character must be an
                # ASCII label character or a non-ASCII letter,
                # mark, number, symbol or punctuation that is not
                # right-to-left (so a ZWJ, a remap to a disallowed
                # form, or an RTL mix still falls through).
                # Placed after the fraction/as-is/double-exclamation
                # branches, so labels mixing a mark with one of
                # those keep their existing behaviour, and a gate
                # failure falls through to the same "_" / strict /
                # plain handling below rather than adding a new
                # failure mode. Underscore labels already
                # punycoded correctly via the "_" branch below;
                # this branch produces the identical form for
                # them, so their behaviour is unchanged.
                import unicodedata as _sym_unicodedata

                try:
                    _sym_remapped = _idna.uts46_remap(
                        label, std3_rules=False, transitional=False
                    )
                    _sym_remapped_again = _idna.uts46_remap(
                        _sym_remapped, std3_rules=False,
                        transitional=False,
                    )
                except (UnicodeError, ValueError):
                    _sym_remapped = None
                    _sym_remapped_again = None
                _sym_label_chars = (
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "0123456789_-"
                )
                if (
                    _sym_remapped is not None
                    and _sym_remapped_again == _sym_remapped
                    and any(
                        0x20D0 <= ord(c) <= 0x20F0
                        for c in _sym_remapped
                    )
                    and not any(
                        0x20F1 <= ord(c) <= 0x20FF
                        for c in _sym_remapped
                    )
                    and _sym_unicodedata.category(
                        _sym_remapped[0]
                    )[0] != "M"
                    and all(
                        c in _sym_label_chars
                        or (
                            ord(c) > 127
                            and _sym_unicodedata.category(c)[0]
                            in "LMNSP"
                            and _sym_unicodedata.bidirectional(c)
                            not in ("R", "AL", "AN")
                        )
                        for c in _sym_remapped
                    )
                ):
                    encoded_labels.append(
                        "xn--"
                        + _sym_remapped.encode("punycode").decode(
                            "ascii"
                        )
                    )
                elif "_" not in label:
                    encoded_labels.append(
                        _idna.encode(label).decode("ascii")
                    )
                elif any(ord(c) > 127 for c in label):
                    encoded_labels.append(
                        "xn--" + label.encode("punycode").decode("ascii")
                    )
                else:
                    encoded_labels.append(label)
            elif any(
                ord(c) == 0x1DFA or 0x1AC1 <= ord(c) <= 0x1ACE
                for c in label
            ):
                # COMBINING DOT BELOW LEFT U+1DFA: the `idna`
                # package rejects it under both strict and UTS46
                # processing when it starts a label ("Label
                # begins with an illegal combining character"),
                # so the helper left such a host alone and it
                # never matched under Starlette's exact
                # allow_origins matching — but browsers
                # serialize a label starting with it as-is
                # ("᷺" -> "xn--vfg", "᷺a" -> "xn--a-hlm",
                # "᷺᷺" -> "xn--vfga"), matching the punycode
                # form. It is the only member of U+1DC0-U+1DFF
                # with this property: every other mark in the
                # block is browser-rejected at a label start,
                # matching the helper's None, and a mark after
                # a base letter already encodes via the strict
                # path, so only the label-start case is the gap.
                # The combining marks U+1AC1-U+1ACE share exactly
                # that property: the package rejects them at a
                # label start but accepts them after a base
                # letter, while browsers serialize a label
                # starting with one as-is ("᫁" -> "xn--brf",
                # "᫁a" -> "xn--a-c8k"), so they are handled by
                # the same branch and the same remapped-first-
                # character gate below. (U+1AC0 and the rest of
                # U+1AB0-U+1AC0 are browser-rejected at a label
                # start, matching the helper's None. The
                # U+1ACF-U+1AEB forms are unassigned in this
                # Python's Unicode data, so they are not part
                # of this branch; they are handled by the
                # _punycode_asis branch above instead, which
                # is checked before this branch.)
                # The label is punycoded in its UTS46-remapped
                # form, not raw: the remap reorders combining
                # marks canonically ("᷺̀" -> "᷺̀" ->
                # "xn--ksa529k") and maps other characters
                # first ("᷺ͅ" -> "᷺ι" -> "xn--uxa555k",
                # "᷺µ" -> "᷺μ" -> "xn--xxa945k"), matching the
                # browser, while the raw punycode is not. The
                # gates mirror the U+20D0 branch: the remap
                # must succeed and be idempotent, the remapped
                # label must start with U+1DFA (so a remap that
                # reorders another mark first, e.g. "᷺ﾞ" ->
                # "゙᷺", still falls through, matching the
                # browser's rejection), and every other
                # character must be an ASCII label character
                # ("+" included, covering the U+FB29 remap
                # "᷺﬩" -> "᷺+" -> "xn--+-hlm" and the literal
                # "+" form, which browsers accept the same way)
                # or a non-ASCII letter, mark, number, symbol
                # or punctuation that is not right-to-left (so
                # an RTL mix, a ZWJ/ZWNJ, or a space still falls
                # through, matching browser rejection). Placed
                # after the fraction/as-is/double-exclamation/
                # U+20D0 branches, so labels mixing U+1DFA with
                # one of those keep their existing behaviour,
                # and a gate failure falls through to the same
                # "_" / strict / plain handling below rather
                # than adding a new failure mode. A label
                # mixing U+1DFA (not first) with U+1ABE never
                # reaches the U+1ABE branch below, because
                # this branch claims every label containing
                # U+1DFA first — and its first-character gate
                # then fails it, so "a᷺᪾" fell through to the
                # strict path and returned None instead of
                # the browser form "xn--a-67kx8n". The
                # fallback alternative in the gate below
                # mirrors the U+1ABE branch's gates (the mark
                # survives the remap, the first character is
                # not a mark, every other character passes
                # the same category / bidirectional check),
                # so such a mix now punycodes its remapped
                # form while a mark-first, RTL, or otherwise
                # gated mix still falls through as before.
                import unicodedata as _dfl_unicodedata

                try:
                    _dfl_remapped = _idna.uts46_remap(
                        label, std3_rules=False, transitional=False
                    )
                    _dfl_remapped_again = _idna.uts46_remap(
                        _dfl_remapped, std3_rules=False,
                        transitional=False,
                    )
                except (UnicodeError, ValueError):
                    _dfl_remapped = None
                    _dfl_remapped_again = None
                _dfl_label_chars = (
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "0123456789_+-"
                )
                if (
                    _dfl_remapped is not None
                    and _dfl_remapped_again == _dfl_remapped
                    and _dfl_remapped
                    and (
                        ord(_dfl_remapped[0]) == 0x1DFA
                        or 0x1AC1 <= ord(_dfl_remapped[0]) <= 0x1ACE
                        or (
                            any(
                                ord(c) == 0x1ABE
                                for c in _dfl_remapped
                            )
                            and _dfl_unicodedata.category(
                                _dfl_remapped[0]
                            )[0] != "M"
                        )
                    )
                    and all(
                        c in _dfl_label_chars
                        or (
                            ord(c) > 127
                            and _dfl_unicodedata.category(c)[0]
                            in "LMNSP"
                            and _dfl_unicodedata.bidirectional(c)
                            not in ("R", "AL", "AN")
                        )
                        for c in _dfl_remapped
                    )
                ):
                    encoded_labels.append(
                        "xn--"
                        + _dfl_remapped.encode("punycode").decode(
                            "ascii"
                        )
                    )
                elif "_" not in label:
                    encoded_labels.append(
                        _idna.encode(label).decode("ascii")
                    )
                elif any(ord(c) > 127 for c in label):
                    encoded_labels.append(
                        "xn--" + label.encode("punycode").decode("ascii")
                    )
                else:
                    encoded_labels.append(label)
            elif any(ord(c) == 0x1ABE for c in label):
                # COMBINING PARENTHESES OVERLAY U+1ABE: the
                # `idna` package rejects it under both strict
                # and UTS46 processing even after a base
                # character ("a\u1abe" -> InvalidCodepoint),
                # so a configured origin containing one was
                # left alone and never matched under
                # Starlette's exact allow_origins matching —
                # but browsers punycode a label with it after
                # a base character as-is ("a\u1abe" ->
                # "xn--a-67k", "a\u1abeb" -> "xn--ab-4pq",
                # stacked "a\u1abe\u1abe" -> "xn--a-67ka"),
                # matching the punycode form. A mark alone
                # at a label start is browser-rejected
                # ("\u1abea" is an invalid URL), so the
                # first-character gate below excludes
                # mark-first labels, which fall through to
                # the existing handling (None, as before).
                # The label is punycoded in its UTS46-remapped
                # form, not raw: the remap normalizes a
                # decomposed base ("a\u0300\u1abe" -> "à\u1abe")
                # and maps other characters first ("µ\u1abe"
                # -> "μ\u1abe"), matching the browser, while
                # the raw punycode is not. The gates mirror
                # the U+20D0 branch: the remap must succeed
                # and be idempotent, the mark must survive
                # it, the first character must not be a
                # mark, and every other character must be an
                # ASCII label character ("+" included, since
                # browsers accept a literal "+" in a label:
                # "a\u1abe+" -> "xn--a+-4pq") or a non-ASCII
                # letter, mark, number, symbol or punctuation
                # that is not right-to-left (so a ZWJ, a
                # remap to a disallowed form, or an RTL mix
                # still falls through). Placed after the
                # fraction/as-is/double-exclamation/U+20D0/
                # U+1DFA branches, so labels mixing U+1ABE
                # with one of those keep their existing
                # behaviour ("a\u1abe\u20d0" via the U+20D0
                # branch, "\u1dfaa\u1abe" via the U+1DFA
                # branch), and a gate failure falls through
                # to the same "_" / strict / plain handling
                # below rather than adding a new failure mode.
                import unicodedata as _pov_unicodedata

                try:
                    _pov_remapped = _idna.uts46_remap(
                        label, std3_rules=False, transitional=False
                    )
                    _pov_remapped_again = _idna.uts46_remap(
                        _pov_remapped, std3_rules=False,
                        transitional=False,
                    )
                except (UnicodeError, ValueError):
                    _pov_remapped = None
                    _pov_remapped_again = None
                _pov_label_chars = (
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "0123456789_+-"
                )
                if (
                    _pov_remapped is not None
                    and _pov_remapped_again == _pov_remapped
                    and any(
                        ord(c) == 0x1ABE for c in _pov_remapped
                    )
                    and _pov_unicodedata.category(
                        _pov_remapped[0]
                    )[0] != "M"
                    and all(
                        c in _pov_label_chars
                        or (
                            ord(c) > 127
                            and _pov_unicodedata.category(c)[0]
                            in "LMNSP"
                            and _pov_unicodedata.bidirectional(c)
                            not in ("R", "AL", "AN")
                        )
                        for c in _pov_remapped
                    )
                ):
                    encoded_labels.append(
                        "xn--"
                        + _pov_remapped.encode("punycode").decode(
                            "ascii"
                        )
                    )
                elif "_" not in label:
                    encoded_labels.append(
                        _idna.encode(label).decode("ascii")
                    )
                elif any(ord(c) > 127 for c in label):
                    encoded_labels.append(
                        "xn--" + label.encode("punycode").decode("ascii")
                    )
                else:
                    encoded_labels.append(label)
            elif (
                any(
                    ord(c) in _punycode_arabic_presentation_as_is
                    for c in label
                )
                and not any(ord(c) == 0xFB29 for c in label)
                and _arb_unicodedata.category(label[0])[0] != "M"
                and all(
                    ord(c) in _punycode_arabic_presentation_as_is
                    or c
                    in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                    or (
                        ord(c) > 127
                        and _arb_unicodedata.category(c)[0] in "LMNSP"
                        and _arb_unicodedata.bidirectional(c)
                        not in ("R", "AL", "AN")
                    )
                    for c in label
                )
            ):
                # Placed after the fraction/as-is/double-exclamation/
                # symbol-marks/1DFA/1ABE branches, so labels mixing
                # one of those with an Arabic presentation form keep
                # their existing behaviour (fraction and
                # double-exclamation mixes already produce the
                # browser form through their own branches, as do
                # as-is-symbol mixes through the as-is branch), and
                # a label reaching here has none of them, so the
                # raw punycode is the browser form. The gates mirror
                # the symbol-marks branch: a strong-RTL character
                # outside the set, a space or joiner, or a leading
                # combining mark falls through to None as before,
                # matching the browser's rejection of those labels,
                # instead of emitting a form no browser origin could
                # carry. The U+FB29 gate likewise keeps
                # pre-pass-declined FB29 mixes at None as before:
                # the browser maps U+FB29 to \"+\", so a raw
                # punycode containing it could never match.
                # Underscore labels already punycoded correctly
                # via the fallback below; this branch produces the
                # identical form for them, so their behaviour is
                # unchanged.
                # A mapped dash in such a label is punycoded
                # here in its mapped form, not raw: browsers
                # apply UTS46 mapping before punycoding, so a
                # Latin label mixing an as-is form with a
                # mapped dash emitted the raw dash ("a︱﯂b"
                # -> "xn--ab-ms1n11f") while browsers carry
                # the mapped form ("xn--ab-71t4259i",
                # verified against Node's WHATWG parser).
                # The mapped form is accepted only when
                # translating the label through _mapped_dash
                # reproduces the UTS46 remap exactly (or its
                # NFC form does, mirroring the hyphen-edge
                # branch's NFC arm) and that form is itself
                # remap-stable, so a label mixing a mapped
                # dash with any other UTS46-mapped character
                # keeps its existing raw behaviour; labels
                # without a mapped dash are unchanged, since
                # the translate is identity for them, and the
                # branch's own gates above already ran on the
                # raw label (a mapped dash is neutral and NFC
                # composition only turns a base letter plus a
                # mark into a letter, so neither can newly
                # violate them).
                _arb_form = label
                _arb_mapped = label.translate(_mapped_dash)
                if _arb_mapped != label:
                    try:
                        _arb_remapped = _idna.uts46_remap(
                            label, std3_rules=False,
                            transitional=False,
                        )
                    except (UnicodeError, ValueError):
                        _arb_remapped = None
                    if _arb_remapped is not None:
                        _arb_mapped_nfc = (
                            _arb_unicodedata.normalize(
                                "NFC", _arb_mapped
                            )
                        )
                        _arb_candidate = None
                        if _arb_mapped == _arb_remapped:
                            _arb_candidate = _arb_mapped
                        elif _arb_mapped_nfc == _arb_remapped:
                            _arb_candidate = _arb_mapped_nfc
                        if _arb_candidate is not None:
                            try:
                                _arb_candidate_stable = (
                                    _idna.uts46_remap(
                                        _arb_candidate,
                                        std3_rules=False,
                                        transitional=False,
                                    )
                                )
                            except (UnicodeError, ValueError):
                                _arb_candidate_stable = None
                            if (
                                _arb_candidate_stable
                                == _arb_candidate
                            ):
                                _arb_form = _arb_candidate
                if any(ord(c) > 127 for c in _arb_form):
                    encoded_labels.append(
                        "xn--"
                        + _arb_form.encode("punycode").decode("ascii")
                    )
                else:
                    encoded_labels.append(_arb_form)
            elif any(
                0x3200 <= ord(c) <= 0x321E
                or 0x3220 <= ord(c) <= 0x3243
                or 0x3248 <= ord(c) <= 0x324F
                or 0x3260 <= ord(c) <= 0x326D
                or ord(c) == 0x327F
                or ord(c) in _punycode_enclosed_cjk
                or ord(c) in _punycode_square_cjk
                for c in label
            ):
                # Enclosed CJK Letters and Months forms that
                # UTS46 remaps before IDNA processing but the
                # `idna` package rejects under both strict and
                # UTS46 processing, so neither path above
                # reproduces them — but browsers punycode the
                # remapped form ("㈀" -> "(ᄀ)" ->
                # "xn--()-dmk", "㈠" -> "(一)" ->
                # "xn--()-vu2c", "㉈" -> "xn--eok"). The
                # ranges above are exactly the members of
                # U+3200-U+32FF whose remapped punycode the
                # browser carries while this helper returned
                # None (verified against Node's WHATWG parser
                # over the whole range): the remaining
                # members already match via the UTS46 retry
                # above (circled digits/letters, square era
                # names), and U+321F is browser-rejected, so
                # it is excluded here. The gate also claims
                # the remaining enclosed members in
                # _punycode_enclosed_cjk (U+3244-U+3247,
                # U+3250-U+325F, U+326E-U+327E, U+3280-U+32FF):
                # alone they already match via the UTS46 retry
                # above, but a mix with a codepoint the `idna`
                # package rejects under UTS46 — an emoji, which
                # browsers punycode as-is ("㉄😀" ->
                # "xn--lzr8018g") — fails the retry and fell
                # through to the fallback's None, while the
                # branch members above already punycoded the
                # same mix through this branch ("㈀😀" ->
                # "xn--()-dmk25139a"). The gate likewise
                # claims the CJK Compatibility square members
                # in _punycode_square_cjk (U+3300-U+33FF runs):
                # alone they already match via the UTS46 retry
                # above, but the same emoji mix fails the retry
                # and fell through to the fallback's None, while
                # the branch's remap-then-punycode body
                # reproduces the browser form ("㌀😀" ->
                # "xn--cckzd0a3n9514t", "㍱😀" -> "xn--hpa-th33b").
                # The seven as-is square
                # members (U+33A7, U+33A8, U+33AE, U+33AF,
                # U+33C6, U+33DE, U+33DF) are not in that set
                # and keep their earlier as-is branch, and the
                # browser-rejected square members outside the
                # set are deliberately left alone. The branch's
                # own gates
                # (idempotent remap, first character not a
                # mark, every character an ASCII label
                # character or a non-RTL letter/mark/number/
                # symbol/punctuation) still decide each label,
                # so a gated mix (RTL, space, joiner, mark-
                # first) falls through to None exactly as
                # before, and labels mixing one of these
                # members with a fraction, as-is symbol or
                # double exclamation mark keep their earlier
                # branches, which run first. The gates mirror the
                # U+1ABE branch: the remap must succeed and
                # be idempotent, the first character must not
                # be a mark, and every remapped character must
                # be an ASCII label character ("+" included,
                # covering a U+FB29 remap that fell through,
                # and "(" / ")" for the parenthesized forms
                # themselves — ASCII punctuation, so they need
                # explicit listing rather than the non-ASCII
                # category check below)
                # or a non-ASCII letter, mark, number, symbol
                # or punctuation that is not right-to-left —
                # so a space, joiner, RTL mix or mark-first
                # label falls through to the fallback below
                # (None, as before) instead of emitting a form
                # no browser origin could carry. Placed after
                # every earlier branch, so labels mixing one
                # of these forms with a fraction, as-is symbol,
                # double exclamation mark, symbol mark, Arabic
                # presentation form or similar keep their
                # existing behaviour, and a gate failure falls
                # through to the same fallback below rather
                # than adding a new failure mode.
                import unicodedata as _enc_unicodedata

                try:
                    _enc_remapped = _idna.uts46_remap(
                        label, std3_rules=False, transitional=False
                    )
                    _enc_remapped_again = _idna.uts46_remap(
                        _enc_remapped, std3_rules=False,
                        transitional=False,
                    )
                except (UnicodeError, ValueError):
                    _enc_remapped = None
                    _enc_remapped_again = None
                _enc_label_chars = (
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "0123456789_+-()"
                )
                if (
                    _enc_remapped is not None
                    and _enc_remapped_again == _enc_remapped
                    and _enc_unicodedata.category(
                        _enc_remapped[0]
                    )[0] != "M"
                    and all(
                        c in _enc_label_chars
                        or (
                            ord(c) > 127
                            and _enc_unicodedata.category(c)[0]
                            in "LMNSP"
                            and _enc_unicodedata.bidirectional(c)
                            not in ("R", "AL", "AN")
                        )
                        for c in _enc_remapped
                    )
                ):
                    if any(ord(c) > 127 for c in _enc_remapped):
                        encoded_labels.append(
                            "xn--"
                            + _enc_remapped.encode("punycode").decode(
                                "ascii"
                            )
                        )
                    else:
                        encoded_labels.append(_enc_remapped)
                elif "_" not in label:
                    encoded_labels.append(
                        _idna.encode(label).decode("ascii")
                    )
                elif any(ord(c) > 127 for c in label):
                    encoded_labels.append(
                        "xn--" + label.encode("punycode").decode("ascii")
                    )
                else:
                    encoded_labels.append(label)
            elif (
                label.strip(_hyph_punct).startswith("-")
                or label.strip(_hyph_punct).endswith("-")
                or any(c in _hyph_punct for c in label)
                or any(c in _dash_punct for c in label)
                or any(ord(c) in _mapped_dash for c in label)
                or any(ord(c) == 0x1806 for c in label)
            ) and any(ord(c) > 127 for c in label):
                # A non-ASCII label with a leading or trailing
                # hyphen: WHATWG URL serialization punycodes it
                # as-is ("münchen-" -> "xn--mnchen--n2a",
                # "-münchen" -> "xn---mnchen-o2a", "é-" ->
                # "xn----9fa"), but the `idna` package rejects
                # hyphen-edge labels under its strict path, so
                # the fallback below raised and the whole host
                # fell through to None and never matched — even
                # a multi-label host such as "münchen-.example".
                # Pure-ASCII hyphen labels need no branch: they
                # already fall through to None, and leaving the
                # host alone is the browser form for them.
                # The same branch covers a hyphen edge hidden
                # behind WHATWG-allowed ASCII punctuation:
                # domain parsing carries the _hyph_punct set
                # through a label ("münchen-!" ->
                # "xn--mnchen-!-65a", "!-münchen" ->
                # "xn--!-mnchen-85a"), but the package rejects
                # those characters under its strict path, so
                # such a label fell through to None too. The
                # edge test therefore strips leading/trailing
                # punctuation of that set first, and the
                # character gate below admits it. The other
                # gates (first character not a mark, non-RTL)
                # still run against the form actually
                # punycoded, so a mark-first ("́!-") or RTL
                # ("م-!") label still falls through to None,
                # matching the browser's rejection, unless it
                # satisfies UTS46's RTL-label rule (see the
                # _hyph_rtl_ok gate below: first character
                # strong RTL, last character strong RTL, a
                # digit or NSM, no Latin character, no
                # European/Arabic-Indic digit mix), in which
                # case the browser carries it ("م_م!٣" ->
                # "xn--_!-vvdb5m", "م!٣" -> "xn--!-ooc5g")
                # and the gate admits it. A label
                # with punctuation but no hyphen edge
                # ("münchen!" -> "xn--mnchen!-n2a") is
                # covered by the same branch: the condition
                # above admits any _hyph_punct member, and
                # the character gate below already admits
                # that set, so the package's rejection of
                # the punctuation no longer makes the whole
                # host fall through to None. The
                # gates mirror the enclosed-CJK branch: the
                # UTS46 remap must be identity, except for the
                # one NFC-normalizing exception below (a label
                # such as "a\u0301-" whose remap is exactly its
                # NFC form "á-", punycoded as "xn----tfa"),
                # the first character must not be a mark (a
                # hyphen-first label such as "-\u0300a" passes
                # this, as the browser carries it, while a
                # mark-first label such as "\u0300-" is
                # browser-rejected and falls through to None
                # as before), and every character must be an
                # ASCII letter, digit, hyphen, underscore or
                # one of the _hyph_punct punctuation marks, or
                # a non-ASCII letter, mark, number, symbol or
                # punctuation that is not right-to-left — so an
                # RTL hyphen-edge label such as "م-" stays None,
                # matching the browser's rejection, while the
                # mid-label RTL form "م-م" keeps working via
                # the strict path above. The edge test runs on
                # the form with leading/trailing _hyph_punct
                # stripped, so a hyphen edge hidden behind
                # punctuation ("münchen-!") qualifies. A gate
                # failure falls through to the same fallback
                # below rather than adding a new failure mode.
                import unicodedata as _hyph_unicodedata

                try:
                    _hyph_remapped = _idna.uts46_remap(
                        label, std3_rules=False, transitional=False
                    )
                except (UnicodeError, ValueError):
                    _hyph_remapped = None
                # The one exception to the identity gate: an
                # NFC-normalizing hyphen-edge label such as
                # "a\u0301-" was previously left at None, but
                # UTS46 processing NFC-normalizes it to "á-"
                # before punycoding, so the browser form is the
                # punycode of the normalized form ("xn----tfa"),
                # not of the raw label. Accept the remapped form
                # only when it is exactly that NFC form (so no
                # other UTS46 mapping can ride along) and it is
                # itself remap-stable; every gate below then runs
                # against the form actually punycoded. Any other
                # remap leaves _hyph_form None and falls through
                # exactly as before.
                _hyph_form = None
                if _hyph_remapped == label:
                    _hyph_form = label
                elif _hyph_remapped is not None:
                    _hyph_nfc = _hyph_unicodedata.normalize(
                        "NFC", label
                    )
                    if _hyph_remapped == _hyph_nfc:
                        try:
                            _hyph_stable = _idna.uts46_remap(
                                _hyph_nfc, std3_rules=False,
                                transitional=False,
                            )
                        except (UnicodeError, ValueError):
                            _hyph_stable = None
                        if _hyph_stable == _hyph_nfc:
                            _hyph_form = _hyph_nfc
                # The mapped-dash exception, mirroring the
                # NFC exception above: a label whose UTS46
                # remap differs from the label only by the
                # _mapped_dash mappings (U+FE31/U+FE58 to EM
                # DASH, U+FE32 to EN DASH, U+FE63 to "-")
                # is punycoded in its mapped form, which is
                # what browsers carry. Accept it only when
                # translating the label through _mapped_dash
                # reproduces the remap exactly (so a label
                # mixing a mapped dash with any other
                # UTS46-mapped character keeps its existing
                # behaviour) and the mapped form is itself
                # remap-stable; every gate below then runs
                # against the form actually punycoded.
                if _hyph_form is None and _hyph_remapped is not None:
                    _hyph_mapped = label.translate(_mapped_dash)
                    if (
                        _hyph_mapped != label
                        and _hyph_mapped == _hyph_remapped
                    ):
                        try:
                            _hyph_mapped_stable = (
                                _idna.uts46_remap(
                                    _hyph_mapped,
                                    std3_rules=False,
                                    transitional=False,
                                )
                            )
                        except (UnicodeError, ValueError):
                            _hyph_mapped_stable = None
                        if _hyph_mapped_stable == _hyph_mapped:
                            _hyph_form = _hyph_mapped
                    # The NFC-normalizing variant of the
                    # mapped-dash exception, mirroring the
                    # NFC exception above and the NFC arm
                    # of the U+1806 exception below: a label
                    # such as "a\u0301\ufe31\u0888b" was
                    # previously left at None, because
                    # translating it through _mapped_dash
                    # gives "a\u0301\u2014\u0888b", whose
                    # remap is its NFC form
                    # "\u00e1\u2014\u0888b" rather than
                    # itself — but UTS46 processing
                    # NFC-normalizes before punycoding, so
                    # the browser form is the punycode of
                    # that NFC form ("xn--b-tfa199c5m0a").
                    # Accept the NFC form only when it is
                    # exactly the remap (so no other UTS46
                    # mapping can ride along — a label
                    # mixing a mapped dash with another
                    # mapped character, e.g.
                    # "a\u0301\ufe31\u212ab", keeps its
                    # existing behaviour) and it is itself
                    # remap-stable; every gate below then
                    # runs against the form actually
                    # punycoded.
                    if _hyph_form is None:
                        _hyph_mapped_nfc = (
                            _hyph_unicodedata.normalize(
                                "NFC", _hyph_mapped
                            )
                        )
                        if _hyph_mapped_nfc == _hyph_remapped:
                            try:
                                _hyph_mapped_nfc_stable = (
                                    _idna.uts46_remap(
                                        _hyph_mapped_nfc,
                                        std3_rules=False,
                                        transitional=False,
                                    )
                                )
                            except (UnicodeError, ValueError):
                                _hyph_mapped_nfc_stable = None
                            if (
                                _hyph_mapped_nfc_stable
                                == _hyph_mapped_nfc
                            ):
                                _hyph_form = _hyph_mapped_nfc
                # The U+1806 exception, mirroring the
                # mapped-dash exception above: MONGOLIAN TODO
                # SOFT HYPHEN U+1806 is category Pd, but its
                # UTS46 remap raises InvalidCodepoint, so a
                # label carrying one fell through to None
                # while browsers punycode it raw ("a᠆b" ->
                # "xn--ab-h0o", "م᠆م" -> "xn--hhba847k",
                # verified against Node's WHATWG parser).
                # Accept the raw label only when the remap
                # raised (so this fires for no other label)
                # and substituting every U+1806 with "-"
                # remaps to itself, proving no other
                # character in the label needs a UTS46
                # mapping or is disallowed (a label mixing
                # U+1806 with another mapped character, e.g.
                # "aK᠆b", keeps its existing behaviour);
                # every gate below then runs against the
                # raw form actually punycoded, so a
                # browser-rejected shape (an RTL edge dash,
                # a Latin/RTL mix, a mark-first label, a
                # space mix, a European/Arabic-Indic digit
                # mix) still falls through to None exactly
                # as before.
                if (
                    _hyph_form is None
                    and _hyph_remapped is None
                    and "\u1806" in label
                ):
                    _hyph_1806_sub = label.replace("\u1806", "-")
                    try:
                        _hyph_1806_sub_remapped = (
                            _idna.uts46_remap(
                                _hyph_1806_sub,
                                std3_rules=False,
                                transitional=False,
                            )
                        )
                    except (UnicodeError, ValueError):
                        _hyph_1806_sub_remapped = None
                    if _hyph_1806_sub_remapped == _hyph_1806_sub:
                        _hyph_form = label
                    elif _hyph_1806_sub_remapped is not None:
                        # The NFC-normalizing variant of the
                        # U+1806 exception, mirroring the NFC
                        # exception above: a label such as
                        # "a\u0301\u1806b" was previously left
                        # at None, because substituting U+1806
                        # with "-" gives "a\u0301-b", whose
                        # remap is its NFC form "á-b" rather
                        # than itself — but UTS46 processing
                        # NFC-normalizes before punycoding, so
                        # the browser form is the punycode of
                        # the NFC form "á\u1806b"
                        # ("xn--b-tfa988o"). Accept the NFC
                        # form only when the substituted
                        # label's remap is exactly its NFC
                        # form, that NFC form corresponds to
                        # the NFC form of the label with
                        # U+1806 put back, and the NFC form
                        # is itself remap-stable (so a label
                        # mixing U+1806 with another mapped
                        # character, e.g. "a\u212a\u1806b",
                        # keeps its existing behaviour);
                        # every gate below then runs against
                        # the NFC form actually punycoded.
                        _hyph_1806_nfc = (
                            _hyph_unicodedata.normalize(
                                "NFC", label
                            )
                        )
                        _hyph_1806_sub_nfc = (
                            _hyph_unicodedata.normalize(
                                "NFC", _hyph_1806_sub
                            )
                        )
                        if (
                            _hyph_1806_sub_remapped
                            == _hyph_1806_sub_nfc
                            and _hyph_1806_nfc.replace(
                                "\u1806", "-"
                            )
                            == _hyph_1806_sub_nfc
                        ):
                            try:
                                _hyph_1806_nfc_stable = (
                                    _idna.uts46_remap(
                                        _hyph_1806_sub_nfc,
                                        std3_rules=False,
                                        transitional=False,
                                    )
                                )
                            except (UnicodeError, ValueError):
                                _hyph_1806_nfc_stable = None
                            if (
                                _hyph_1806_nfc_stable
                                == _hyph_1806_sub_nfc
                            ):
                                _hyph_form = _hyph_1806_nfc
                # The RTL-label alternative to the character
                # gate below, mirroring the underscore
                # fallback's UTS46 bidi gate: a label whose
                # first character is strong RTL, whose last
                # character is strong RTL, a digit or NSM,
                # which contains no Latin character and does
                # not mix European and Arabic-Indic digits,
                # and whose every character is otherwise an
                # admitted ASCII or _hyph_punct character or a
                # non-ASCII letter, mark, number, symbol or
                # punctuation, is a valid RTL label under
                # UTS46 even though it contains RTL
                # characters, so the browser carries it
                # ("م_م!٣", "م!٣", "م-م!٣") while a
                # hyphen-edge RTL label ("م_م-", "م!٣-",
                # "-م!٣") or a Latin-mixing one ("م_م!x")
                # still fails the rule and falls through as
                # before. The gate runs on the form actually
                # punycoded, and a label with no strong-RTL
                # first character ("١!م", "1!م") fails it.
                # It also bars three codepoints browsers
                # reject in every RTL mix even though the
                # category gate above would admit them:
                # OBLIQUE HYPHEN U+2E5D (admitted in
                # _dash_punct for Latin labels, but barred
                # here so an RTL mix still fails, e.g.
                # "م⸗⹝م" and, with the mapped-dash
                # exception above, "م︱⹝م"), and the
                # strong-RTL symbols
                # ARABIC RAISED ROUND DOT U+0888 and
                # ARABIC PRESENTATION FORM U+FBC2 (barred
                # in RTL mixes by the gap-symbol branch for
                # the same reason). Their Latin mixes keep
                # their existing behaviour: the non-RTL gate
                # below, not this gate, decides those.
                _hyph_rtl_ok = False
                if _hyph_form is not None:
                    _hyph_rtl_bidi = [
                        _hyph_unicodedata.bidirectional(c)
                        for c in _hyph_form
                    ]
                    _hyph_rtl_ok = (
                        _hyph_rtl_bidi[0] in ("R", "AL")
                        and _hyph_rtl_bidi[-1]
                        in ("R", "AL", "EN", "AN", "NSM")
                        and "L" not in _hyph_rtl_bidi
                        and not (
                            "EN" in _hyph_rtl_bidi
                            and "AN" in _hyph_rtl_bidi
                        )
                        and not any(
                            ord(c) in (0x2E5D, 0x0888, 0xFBC2)
                            for c in _hyph_form
                        )
                        and all(
                            c
                            in (
                                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                                + _hyph_punct
                            )
                            or (
                                ord(c) > 127
                                and _hyph_unicodedata.category(c)[0]
                                in "LMNSP"
                            )
                            for c in _hyph_form
                        )
                    )
                # The U+0888 exception to the character gate
                # below: ARABIC RAISED ROUND DOT U+0888 is a
                # strong-RTL symbol (bidi class AL), so the
                # non-RTL gate bars it and the RTL gate bars
                # it explicitly, and a Latin label mixing it
                # with a mapped dash or dash punctuation fell
                # through to None while browsers carry it
                # ("a︱࢈b" -> "xn--ab-jbf522v", "a⸗࢈b" ->
                # "xn--ab-jbf3589a", verified against Node's
                # WHATWG parser). Admit it only in a Latin
                # label: the form must contain no other
                # R/AL/AN-bidi character apart from itself
                # and the fellow admitted symbol U+FBC2 (see
                # below), so an RTL mix ("م︱࢈م") or a
                # Latin/RTL mix ("a︱࢈م"), which browsers
                # reject, still fails the gate exactly as
                # before; the RTL gate's explicit U+0888 bar
                # is unchanged, so an RTL-led label keeps
                # its existing behaviour.
                _hyph_0888_latin_ok = (
                    _hyph_form is not None
                    and "\u0888" in _hyph_form
                    and not any(
                        _hyph_unicodedata.bidirectional(c)
                        in ("R", "AL", "AN")
                        for c in _hyph_form
                        if ord(c) not in (0x0888, 0xFBC2)
                    )
                )
                # The U+FBC2 exception to the character gate
                # below, mirroring the U+0888 exception
                # above: ARABIC PRESENTATION FORM U+FBC2 is
                # likewise a strong-RTL symbol (bidi class
                # AL, category Sk), so the non-RTL gate
                # barred it and the RTL gate bars it
                # explicitly, and a Latin label mixing it
                # with a mapped dash fell through to the
                # fallback, which punycoded the raw label
                # ("a︱﯂b" -> "xn--ab-ms1n11f") while
                # browsers carry the mapped-dash form
                # ("xn--ab-71t4259i", verified against
                # Node's WHATWG parser). Admit it only in a
                # Latin label, on the same terms as U+0888:
                # the form must contain no other R/AL/AN
                # bidi character apart from itself and
                # U+0888, so an RTL mix ("م︱﯂م") or a
                # Latin/RTL mix ("a︱﯂م"), which browsers
                # reject, still falls through to None
                # exactly as before; the RTL gate's explicit
                # U+FBC2 bar is unchanged, so an RTL-led
                # label keeps its existing behaviour. The
                # gate runs on the mapped form, so the
                # mapped dash (or its NFC form) is what
                # gets punycoded, not the raw dash.
                _hyph_fbc2_latin_ok = (
                    _hyph_form is not None
                    and "\ufbc2" in _hyph_form
                    and not any(
                        _hyph_unicodedata.bidirectional(c)
                        in ("R", "AL", "AN")
                        for c in _hyph_form
                        if ord(c) not in (0x0888, 0xFBC2)
                    )
                )
                if (
                    _hyph_form is not None
                    and (
                        _hyph_form.strip(_hyph_punct).startswith("-")
                        or _hyph_form.strip(_hyph_punct).endswith("-")
                        or any(c in _hyph_punct for c in _hyph_form)
                        or any(c in _dash_punct for c in _hyph_form)
                        or any(
                            ord(c) in _mapped_dash for c in label
                        )
                        or any(ord(c) == 0x1806 for c in label)
                    )
                    and _hyph_unicodedata.category(_hyph_form[0])[0]
                    != "M"
                    and (
                        all(
                            c
                            in (
                                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                                + _hyph_punct
                            )
                            or (
                                ord(c) > 127
                                and _hyph_unicodedata.category(c)[0]
                                in "LMNSP"
                                and _hyph_unicodedata.bidirectional(c)
                                not in ("R", "AL", "AN")
                            )
                            or (
                                ord(c) == 0x0888
                                and _hyph_0888_latin_ok
                            )
                            or (
                                ord(c) == 0xFBC2
                                and _hyph_fbc2_latin_ok
                            )
                            for c in _hyph_form
                        )
                        or _hyph_rtl_ok
                    )
                ):
                    # A mapped form that became pure ASCII
                    # (a U+FE63 label, e.g. "a﹣b" -> "a-b")
                    # is passed through verbatim, as browsers
                    # carry it; every other admitted form is
                    # punycoded. Existing identity/NFC forms
                    # are non-ASCII here, so they are
                    # unchanged.
                    if any(ord(c) > 127 for c in _hyph_form):
                        encoded_labels.append(
                            "xn--"
                            + _hyph_form.encode("punycode").decode(
                                "ascii"
                            )
                        )
                    else:
                        encoded_labels.append(_hyph_form)
                elif "_" not in label:
                    encoded_labels.append(
                        _idna.encode(label).decode("ascii")
                    )
                elif any(
                    _hyph_unicodedata.bidirectional(c)
                    in ("R", "AL", "AN")
                    for c in label
                ):
                    # A hyphen-edge underscore label containing
                    # a strong-RTL or Arabic-Indic character:
                    # UTS46's RTL-label rules require the first
                    # character to be strong RTL and the last
                    # to be strong RTL or a digit, so a label
                    # starting or ending with a hyphen (or a
                    # hyphen hidden behind _hyph_punct) is
                    # browser-rejected ("م_م-" / "-م_م" /
                    # "م_م-!" / "٣_٣-" all fail in the WHATWG
                    # parser), yet this fallback punycoded it
                    # raw, bypassing the underscore fallback's
                    # RTL-edge gate (which this branch never
                    # reaches). Non-underscore labels are
                    # unaffected: they take the strict branch
                    # above and already return None. Raise, so
                    # the outer handler returns None for the
                    # whole host, as for other rejected labels.
                    # Mid-label hyphens ("م_م-م") never enter
                    # this branch, and non-RTL hyphen-edge
                    # underscore labels ("mün_chen-") keep
                    # their existing forms.
                    raise ValueError("rtl hyphen-edge underscore")
                elif any(ord(c) > 127 for c in label):
                    encoded_labels.append(
                        "xn--" + label.encode("punycode").decode("ascii")
                    )
                else:
                    encoded_labels.append(label)
            elif all(
                c
                in (
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                    + _hyph_punct
                )
                for c in label
            ):
                # A pure-ASCII label of letters, digits, hyphen,
                # underscore or WHATWG-carried punctuation: the
                # `idna` package rejects the punctuation (and
                # hyphen-edge forms such as "a-") under its
                # strict path, so such a label fell through to
                # _idna.encode below, raised, and returned None
                # for the whole host. That only matters when
                # the host reaches this helper at all — i.e.
                # when another label is non-ASCII, or when the
                # label itself became pure ASCII only after the
                # up-front UTS46 translate (a ligature label
                # such as "ﬀ!" -> "ff!", or "ﬀ!.example" ->
                # "ff!.example") — because the pipeline only
                # calls this helper for non-ASCII hosts and
                # leaves a purely ASCII host alone either way.
                # Browsers carry every one of these characters
                # through a label verbatim (verified against
                # Node's WHATWG parser: all 17 _hyph_punct marks
                # in 10 positions each, plus hyphen-edge and
                # underscore mixes), so pass the label through
                # unchanged instead of failing the host. A
                # label containing any other character still
                # falls through to the strict path below, so
                # browser-rejected forms keep returning None.
                encoded_labels.append(label)
            elif "_" not in label:
                # An emoji / symbol label: WHATWG URL
                # serialization punycodes emoji and miscellaneous
                # symbols as-is ("😀" -> "xn--e28h", "a😀" ->
                # "xn--a-jv3s", "🇺🇸" -> "xn--w77hd", "👍🏽" ->
                # "xn--on8h5e", verified against Node's WHATWG
                # parser), but the `idna` package rejects them
                # under both strict and UTS46 processing, so
                # such a label fell through to the strict path
                # below, raised, and returned None for the whole
                # host — including multi-label hosts ("😀.example",
                # "‼﬩.😀", where the other label already encodes).
                # Punycode the label directly when every character
                # is an ASCII letter, digit or hyphen, a
                # non-ASCII symbol (general categories So/Sk, which
                # covers emoji, dingbats and miscellaneous symbols
                # including skin-tone modifiers), or a non-ASCII
                # letter mixed with such a symbol (\"münchen☀\",
                # \"中☀\"), the UTS46 remap
                # leaves the label unchanged (this rejects
                # characters browsers map elsewhere, e.g. a
                # parenthesized letter -> "(a)", or a UTS46-mapped
                # letter mixed with an emoji, e.g. "😀K" -> "😀k",
                # which keeps its existing behaviour for separate
                # assessment), and, for the LTR gate below, no
                # character is strong-RTL or Arabic-Indic (so an
                # invalid emoji/RTL mix such as "😀م", which
                # browsers reject, still falls through to None,
                # as do joiner sequences, whose Cf characters
                # fail the character gate; combining marks are
                # admitted below except at the label start,
                # where browsers reject them) — except ARABIC RAISED
                # ROUND DOT U+0888, the one strong-RTL symbol
                # browsers carry in every position (verified
                # against Node's WHATWG parser: standalone,
                # letter mixes and emoji mixes all punycode,
                # unlike the other two AL symbols of this class,
                # U+06FD/U+06FE, which browsers carry standalone
                # but reject in any mix). Labels without an
                # emoji/symbol character keep the strict path
                # exactly as before, so no correctly-matching
                # host changes.
                import unicodedata as _emoji_unicodedata

                # WHATWG URL serialization NFC-normalizes the
                # label during IDNA processing, so a decomposed
                # letter+mark sequence ("e\u0301☀") serializes
                # as its composed form ("é☀") and Hangul jamo
                # compose to syllables — while the gate below
                # saw only the raw label and rejected every mark.
                # Normalize here, before the remap check and the
                # gate, so both see the browser's form; labels
                # already in NFC are unchanged.
                label = _emoji_unicodedata.normalize("NFC", label)

                try:
                    _emoji_remapped = _idna.uts46_remap(
                        label, std3_rules=False, transitional=False
                    )
                except (UnicodeError, ValueError):
                    _emoji_remapped = None
                # The AL-symbol gap set: strong-RTL symbols the
                # `idna` package rejects under both strict and
                # UTS46 processing, but browsers carry in RTL
                # labels (verified against Node's WHATWG
                # parser): ARABIC RAY U+0608, AFGHANI SIGN
                # U+060B, the Arabic symbol dots U+FBB2-U+FBC1,
                # and the Siyaq marks U+1ECAC, U+1ECB0, U+1ED2E.
                # Their neighbours in the same class are
                # deliberately not in the set: U+06FD/U+06FE
                # and RIAL SIGN U+FDFC already encode through
                # the package paths, while U+0888 and U+FBC2
                # are browser-rejected in RTL mixes (and fall
                # out of the per-character remap check below
                # anyway).
                _emoji_al_gap = frozenset(
                    [0x0608, 0x060B]
                    + list(range(0xFBB2, 0xFBC2))
                    + [0x1ECAC, 0x1ECB0, 0x1ED2E]
                )
                # ZWNJ (U+200C) in a gap label: browsers carry
                # it only under its CONTEXTJ rule, which the
                # single-character remap below cannot judge
                # (it raises without neighbours). Verified
                # against Node's WHATWG parser, the rule as
                # implemented is: some dual-joining letter
                # precedes the ZWNJ in the same label, and
                # some joining letter follows it in the same
                # label. A right-joining-only prefix fails
                # ("ا‌م", "د‌م", "ا؈‌م" are all rejected),
                # a dual-joining letter anywhere earlier
                # suffices ("م؈و‌م" carries), a digit,
                # Hebrew letter, Latin letter or gap symbol
                # alone after it fails ("م؈‌1", "م؈‌א",
                # "م؈‌a", "م؈م‌؈" are all rejected), and a
                # mapped symbol's expansion letters count
                # on both sides ("م؈‌﷼", "؈﷼‌م" carry).
                # The ranges below are those two sets,
                # derived by probing Node over every letter
                # with bidi class R/AL in U+0590-U+0900,
                # U+FB50-U+FE00 and U+FE70-U+FF00 as the
                # prefix of "<letter>‌م" (dual set) and as
                # the follower in "م؈‌<letter>" (joining
                # set); the dual set is a subset of the
                # joining set, as dual-joining letters are
                # joining letters, and presentation forms
                # classify by their mapped letter, since
                # the probes map before judging context.
                # ZWJ (U+200D) is not in either set and
                # stays barred: it needs a preceding virama.
                _emoji_gap_zwnj_dual = (
                    (1568, 1568), (1574, 1574), (1576, 1576),
                    (1578, 1582), (1587, 1599), (1601, 1607),
                    (1609, 1610), (1646, 1647), (1656, 1671),
                    (1690, 1727), (1729, 1730), (1740, 1740),
                    (1742, 1742), (1744, 1745), (1786, 1788),
                    (1791, 1791), (1810, 1812), (1818, 1821),
                    (1823, 1831), (1833, 1833), (1835, 1835),
                    (1837, 1838), (1870, 1880), (1884, 1894),
                    (2128, 2131), (2133, 2133), (2208, 2208),
                    (2210, 2217), (64338, 64385),
                    (64398, 64419), (64422, 64429),
                    (64467, 64470), (64484, 64602),
                    (64605, 64605), (64612, 64753),
                    (64757, 64827), (64848, 64911),
                    (64914, 64967), (65008, 65017),
                    (65161, 65164), (65167, 65170),
                    (65173, 65192), (65201, 65260),
                    (65263, 65276),
                )
                _emoji_gap_zwnj_join = (
                    (1568, 1568), (1570, 1599), (1601, 1610),
                    (1646, 1647), (1649, 1651), (1653, 1747),
                    (1749, 1749), (1774, 1775), (1786, 1788),
                    (1791, 1791), (1808, 1808), (1810, 1839),
                    (1869, 1894), (2128, 2133), (2208, 2208),
                    (2210, 2220), (64336, 64433),
                    (64467, 64605), (64612, 64753),
                    (64757, 64829), (64848, 64911),
                    (64914, 64967), (65008, 65017),
                    (65153, 65276),
                )

                def _emoji_zwnj_context_ok(_zlabel):
                    for _zi, _zch in enumerate(_zlabel):
                        if _zch != "\u200c":
                            continue
                        if not any(
                            _lo <= ord(_pc) <= _hi
                            for _pc in _zlabel[:_zi]
                            for (_lo, _hi)
                            in _emoji_gap_zwnj_dual
                        ):
                            return False
                        if not any(
                            _lo <= ord(_fc) <= _hi
                            for _fc in _zlabel[_zi + 1:]
                            for (_lo, _hi)
                            in _emoji_gap_zwnj_join
                        ):
                            return False
                    return True

                # Per-character remap stability for the new arm
                # below: the whole-label remap above raises on
                # a gap symbol, so it cannot gate the arm, but
                # UTS46 mapping is per codepoint — a gap symbol
                # is kept verbatim, and every other character
                # must remap to itself (this bars UTS46-mapped
                # letters, and the remap-rejected U+0888 /
                # U+FBC2, exactly as browsers reject those
                # mixes). A ZWNJ is judged by its label
                # context instead of its single-character
                # remap (which raises without neighbours);
                # any other character whose single-character
                # remap raises fails the arm.
                try:
                    _emoji_gap_remap_ok = all(
                        ord(c) in _emoji_al_gap
                        or (
                            c == "\u200c"
                            and _emoji_zwnj_context_ok(label)
                        )
                        # MONGOLIAN TODO SOFT HYPHEN U+1806:
                        # browsers carry it raw in RTL labels
                        # ("م؈᠆م"), but the `idna` package's
                        # single-character remap raises on it,
                        # so it is treated as remap-stable
                        # here, like the ZWNJ context clause
                        # above; the first/last gates below
                        # still bar it at the edges, where
                        # browsers reject it ("᠆؈م", "م؈᠆").
                        or ord(c) == 0x1806
                        or _idna.uts46_remap(
                            c, std3_rules=False, transitional=False
                        )
                        == c
                        for c in label
                    )
                except (UnicodeError, ValueError):
                    _emoji_gap_remap_ok = False
                # A gap label with a UTS46-mapped symbol: RIAL
                # SIGN U+FDFC maps to "ریال" (and U+FDF2 to
                # "الله"), so a gap label containing one fell
                # through even though browsers carry the mapped
                # form ("م؈﷼م" -> "م؈ریالم" ->
                # "xn--qfb6d3a7ebe65g", verified against
                # Node's WHATWG parser). The identity check
                # above bars exactly these labels, so build
                # the mapped label alongside it: gap symbols
                # stay verbatim, and every other character
                # must remap to itself or to strong-RTL
                # letters only (this bars mapped Latin
                # letters such as "K" -> "k", digit or
                # space expansions such as the "ﷺ" form,
                # whose space makes browsers reject the
                # mix, and the remap-rejected U+0888 /
                # U+FBC2, which browsers reject in RTL
                # mixes). A ZWNJ keeps itself as its part
                # (its single-character remap raises without
                # neighbours) and its context is judged on
                # the mapped label below, so an expansion
                # letter can supply the context a raw
                # symbol cannot ("م؈‌﷼" carries via the
                # mapped "ریال"); any other character
                # whose single-character remap raises fails
                # the arm. The arm below gates on the raw
                # label, and the raw gates imply the mapped
                # gates here: an expansion adds only
                # strong-RTL letters or a dash (see the
                # mapped-dash clause below), so first/last
                # bidi, the digit-mix bar and the per-char
                # classes all carry over to the mapped
                # label, which is what the arm punycodes
                # when this check holds. (A mapped dash
                # sits mid-label in every admitted case:
                # a mapped dash at an edge fails the raw
                # first/last gates, since its raw bidi
                # class is ON or ES.)
                try:
                    _emoji_gap_mapped_parts = [
                        c
                        if ord(c) in _emoji_al_gap
                        else (
                            c
                            if c == "\u200c"
                            else _idna.uts46_remap(
                                c, std3_rules=False,
                                transitional=False
                            )
                        )
                        for c in label
                    ]
                    _emoji_gap_mapped_label = "".join(
                        _emoji_gap_mapped_parts
                    )
                    _emoji_gap_mapped_ok = (
                        _emoji_gap_mapped_label != label
                        and _emoji_zwnj_context_ok(
                            _emoji_gap_mapped_label
                        )
                        and any(
                            ord(c) in _emoji_al_gap for c in label
                        )
                        and all(
                            ord(c) in _emoji_al_gap
                            or _part == c
                            or (
                                _part != ""
                                and all(
                                    _emoji_unicodedata.category(mc)[0]
                                    == "L"
                                    and _emoji_unicodedata.bidirectional(mc)
                                    in ("R", "AL")
                                    and ord(mc)
                                    not in (0x0888, 0xFBC2)
                                    for mc in _part
                                )
                            )
                            # A UTS46-mapped dash: PRESENTATION
                            # FORM FOR VERTICAL EM DASH U+FE31
                            # and SMALL EM DASH U+FE58 map to
                            # EM DASH, U+FE32 to EN DASH, and
                            # SMALL HYPHEN-MINUS U+FE63 to "-",
                            # so a gap label containing one
                            # fell through even though browsers
                            # carry the mapped form ("م؈﹘م" ->
                            # "م؈—م", "م؈﹣م" -> "م؈-م").
                            # The raw label's first/last gates
                            # below still bar a mapped dash at
                            # the edges, where browsers reject
                            # it ("﹣؈م", "م؈﹣").
                            or (
                                len(_part) == 1
                                and _emoji_unicodedata.category(_part)
                                == "Pd"
                            )
                            for c, _part in zip(
                                label, _emoji_gap_mapped_parts
                            )
                        )
                    )
                except (UnicodeError, ValueError):
                    _emoji_gap_mapped_label = label
                    _emoji_gap_mapped_ok = False
                # ZWNJ context on the raw label, for the
                # gate below: a mapped label's context is
                # already enforced inside
                # _emoji_gap_mapped_ok above, so the gate
                # admits a ZWNJ on either check.
                _emoji_gap_zwnj_ok = _emoji_zwnj_context_ok(label)
                if (
                    _emoji_remapped == label
                    # A mark at the label start is barred here:
                    # browsers reject mark-first labels, and the
                    # mark arm below would otherwise admit them.
                    # (NFC cannot compose a leading mark away,
                    # since it has no preceding starter, so this
                    # check on the normalized label is exact.)
                    and _emoji_unicodedata.category(label[0])[0]
                    != "M"
                    and any(
                        ord(c) > 127
                        and _emoji_unicodedata.category(c)
                        in ("So", "Sk")
                        for c in label
                    )
                    and (all(
                        c
                        in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"
                        or (
                            ord(c) > 127
                            and _emoji_unicodedata.category(c)
                            in ("So", "Sk")
                            and (
                                _emoji_unicodedata.bidirectional(c)
                                not in ("R", "AL", "AN")
                                or ord(c) == 0x0888
                            )
                        )
                        or (
                            # A non-ASCII letter mixed with an
                            # emoji/symbol (\"münchen☀\" ->
                            # \"xn--mnchen-3ya7296e\", \"中☀\" ->
                            # \"xn--k3h518l\"): the strict path
                            # below rejects the symbol, so such
                            # a label fell through to None even
                            # though browsers carry the raw
                            # label punycoded. The
                            # remap-unchanged condition above
                            # already bars UTS46-mapped letters
                            # (\"µ\" -> \"μ\", \"K\" -> \"k\"), and
                            # strong-RTL letters stay barred
                            # here, as with the symbols, so an
                            # emoji/RTL mix still falls through
                            # to None as browsers reject it.
                            # Combining marks are admitted by
                            # the mark arm below (except at the
                            # label start, barred above); joiners
                            # still fail this gate, unchanged.
                            ord(c) > 127
                            and _emoji_unicodedata.category(c)[0]
                            == "L"
                            and _emoji_unicodedata.bidirectional(c)
                            not in ("R", "AL", "AN")
                        )
                        or (
                            # A combining mark mixed with an
                            # emoji/symbol: browsers carry such a
                            # label ("q\u0301☀" ->
                            # "xn--q-xbb199x" where no composition
                            # applies, "☀\u0301" likewise, Mc/Me
                            # marks likewise), so it fell through
                            # to None before for the same reason
                            # as the letter mixes above. Marks
                            # keep the strong-RTL bar, as with
                            # letters and symbols, so an
                            # emoji/RTL mix still falls through
                            # to None as browsers reject it; a
                            # mark at the label start is barred
                            # by the condition above, and joiners
                            # (Cf) still fail this gate.
                            ord(c) > 127
                            and _emoji_unicodedata.category(c)[0]
                            == "M"
                            and _emoji_unicodedata.bidirectional(c)
                            not in ("R", "AL", "AN")
                        )
                        for c in label
                    )
                    or (
                        # An RTL label with an emoji/symbol: the
                        # LTR gate above bars every strong-RTL
                        # character, so a label browsers carry
                        # under the UTS46 RTL-label rules fell
                        # through to None ("א☀ב" ->
                        # "xn--4dbc038v", "م☀م" ->
                        # "xn--hhba284v", verified against
                        # Node's WHATWG parser), and a CORS
                        # origin for such a host never matched.
                        # Admit exactly the labels those rules
                        # admit, for the character classes this
                        # branch already handles: the first
                        # character is strong-RTL (R/AL), the
                        # last is strong-RTL, a European digit
                        # (EN) or a nonspacing mark (NSM), and
                        # every character is an ASCII digit or
                        # hyphen, a neutral symbol (So/Sk whose
                        # bidi class is neither strong-RTL,
                        # Arabic-Indic nor L — so the AL symbols
                        # U+0888/U+06FD/U+06FE stay out of this
                        # arm, as with the LTR gate's bar), a
                        # strong-RTL letter, or a mark of class
                        # NSM/R/AL. The arms together bar Latin
                        # letters (bidi L) and Arabic-Indic
                        # digits (category Nd, admitted by no
                        # arm), so invalid mixes still fall
                        # through exactly as before ("😀م",
                        # "א☀", "☀ב", "א☀ב☀", "אaב",
                        # "א1☀" are all browser-rejected and
                        # still return None). AL-symbol labels
                        # are not admitted by this arm; whatever
                        # form they take comes from their own
                        # branches elsewhere, unchanged here.
                        # The remap-unchanged,
                        # mark-not-first and symbol-present
                        # conditions above still apply to this
                        # arm, since it sits inside the same
                        # parenthesized condition.
                        _emoji_unicodedata.bidirectional(label[0])
                        in ("R", "AL")
                        and _emoji_unicodedata.bidirectional(label[-1])
                        in ("R", "AL", "EN", "NSM")
                        and all(
                            c in "0123456789-"
                            or (
                                ord(c) > 127
                                and _emoji_unicodedata.category(c)
                                in ("So", "Sk")
                                and _emoji_unicodedata.bidirectional(c)
                                not in ("R", "AL", "AN", "L")
                            )
                            or (
                                ord(c) > 127
                                and _emoji_unicodedata.category(c)[0]
                                == "L"
                                and _emoji_unicodedata.bidirectional(c)
                                in ("R", "AL")
                            )
                            or (
                                ord(c) > 127
                                and _emoji_unicodedata.category(c)[0]
                                == "M"
                                and _emoji_unicodedata.bidirectional(c)
                                in ("NSM", "R", "AL")
                            )
                            for c in label
                        )
                    )
                    )
                    or (
                        # An RTL label with an AL symbol from
                        # the gap set above: the LTR and RTL arms
                        # above bar every strong-RTL symbol, and
                        # the whole-label remap gate bars the gap
                        # symbols outright, so such a label fell
                        # through to the strict path, raised, and
                        # returned None ("م؈م" -> browser
                        # "xn--qfb5jb", "م؈" -> "xn--qfb5j",
                        # "؈" -> "xn--qfb", verified against
                        # Node's WHATWG parser), and a CORS
                        # origin for such a host never matched.
                        # Admit exactly the labels the browser
                        # carries for this class: at least one
                        # gap symbol, a first character that is
                        # strong-RTL (R/AL), a last character
                        # that is strong-RTL, a European or
                        # Arabic-Indic digit, or a nonspacing
                        # mark, no Latin letter, no space, no
                        # joiner except a context-valid ZWNJ
                        # (see the sets above; ZWJ stays
                        # barred), no mixed European and
                        # Arabic-Indic digits, and the
                        # per-character remap check above, plus
                        # the explicit U+0888 / U+FBC2 exclusion
                        # below (both are remap-identity, so the
                        # check alone would pass them, yet
                        # browsers reject them in RTL mixes, so
                        # they still fall through, as do
                        # UTS46-mapped letters). Neutral symbols
                        # (So/Sk, bidi neither R/AL/AN nor L)
                        # are admitted mid-label, since browsers
                        # carry them there ("م؈☀م"), while the
                        # first/last gates bar them at the edges
                        # ("م؈☀", "☀؈م" are browser-rejected);
                        # ASCII punctuation beyond the hyphen
                        # ("+", ",") is left for later
                        # iterations, as are non-ASCII
                        # European digits, which browsers
                        # reject in this class.
                        # Either the raw label is remap-stable
                        # (the iteration-684 case) or it carries
                        # a UTS46-mapped symbol handled by the
                        # mapped check above, in which case the
                        # arm punycodes the mapped label below.
                        (_emoji_gap_remap_ok or _emoji_gap_mapped_ok)
                        and any(
                            ord(c) in _emoji_al_gap for c in label
                        )
                        and _emoji_unicodedata.category(label[0])[
                            0
                        ]
                        != "M"
                        and _emoji_unicodedata.bidirectional(
                            label[0]
                        )
                        in ("R", "AL")
                        and _emoji_unicodedata.bidirectional(
                            label[-1]
                        )
                        in ("R", "AL", "EN", "AN", "NSM")
                        and not (
                            any(
                                _emoji_unicodedata.bidirectional(c)
                                == "EN"
                                for c in label
                            )
                            and any(
                                _emoji_unicodedata.bidirectional(c)
                                == "AN"
                                for c in label
                            )
                        )
                        and all(
                            c in "0123456789-"
                            or ord(c) in _emoji_al_gap
                            or (
                                ord(c) > 127
                                and _emoji_unicodedata.category(c)
                                in ("So", "Sk")
                                and _emoji_unicodedata.bidirectional(c)
                                not in ("R", "AL", "AN", "L")
                            )
                            or (
                                ord(c) > 127
                                and _emoji_unicodedata.category(c)[0]
                                == "S"
                                and _emoji_unicodedata.bidirectional(c)
                                == "AL"
                                # U+0888 and U+FBC2 are
                                # remap-identity, so the check
                                # above passes them, but browsers
                                # reject them in RTL mixes
                                # ("م؈࢈م", "م؈﯂م" are both
                                # rejected), so admitting them
                                # here would emit a form no
                                # browser origin could carry.
                                and ord(c) not in (0x0888, 0xFBC2)
                            )
                            or (
                                # A dash-punctuation character
                                # (general category Pd) in a gap
                                # label: browsers carry such
                                # dashes raw mid-label ("م؈⸗م",
                                # "م؈֊م", "م؈᐀م"), while the
                                # gate above admitted no Pd
                                # character, so they fell
                                # through to None. The first/
                                # last gates above still bar a
                                # dash at the edges, where
                                # browsers reject it ("⸗؈م",
                                # "م؈⸗") — except the bidi-R
                                # dashes MAQAF U+05BE and YEZIDI
                                # HYPHENATION MARK U+10EAD, which
                                # browsers carry at the edges
                                # too ("־؈م", "م؈𐺭") and which
                                # pass those gates as R. OBLIQUE
                                # HYPHEN U+2E5D is excluded: it
                                # is carried standalone and in
                                # LTR mixes, but browsers reject
                                # it in every RTL mix ("م؈⹝م"),
                                # like U+0888/U+FBC2 above.
                                ord(c) > 127
                                and _emoji_unicodedata.category(c)
                                == "Pd"
                                and ord(c) != 0x2E5D
                            )
                            or (
                                ord(c) > 127
                                and _emoji_unicodedata.category(c)[0]
                                == "L"
                                and _emoji_unicodedata.bidirectional(c)
                                in ("R", "AL")
                            )
                            or (
                                ord(c) > 127
                                and _emoji_unicodedata.category(c)[0]
                                == "M"
                                and _emoji_unicodedata.bidirectional(c)
                                in ("NSM", "R", "AL")
                            )
                            or (
                                ord(c) > 127
                                and _emoji_unicodedata.category(c)
                                == "Nd"
                                and _emoji_unicodedata.bidirectional(c)
                                == "AN"
                            )
                            or (
                                # A context-valid ZWNJ (see
                                # the sets above): the
                                # first/last gates already
                                # bar it at the edges, and
                                # the raw/mapped context
                                # checks bar the
                                # right-joining-only,
                                # digit-only and
                                # follower-less shapes
                                # browsers reject. ZWJ
                                # stays barred: it is in
                                # neither set, so it still
                                # fails this gate.
                                ord(c) == 0x200C
                                and (
                                    _emoji_gap_zwnj_ok
                                    or _emoji_gap_mapped_ok
                                )
                            )
                            for c in label
                        )
                    )
                ):
                    encoded_labels.append(
                        "xn--"
                        + (
                            _emoji_gap_mapped_label
                            if _emoji_gap_mapped_ok
                            else label
                        )
                        .encode("punycode")
                        .decode("ascii")
                    )
                else:
                    encoded_labels.append(
                        _idna.encode(label).decode("ascii")
                    )
            elif any(ord(c) > 127 for c in label):
                # An underscore label with a UTS46-remapped
                # character: the whole-host UTS46 retry above
                # rejects every underscore host, and no earlier
                # per-label branch claims these members (the
                # parenthesized branch claims its own range,
                # and fraction/as-is/double-exclamation labels
                # keep their own handling), so such a label
                # reached this fallback and was punycoded raw
                # — but browsers remap first ("a_ά" ->
                # "a_ά" -> "xn--a_-x8b", "a_㊣" -> "a_正",
                # "a_豈" -> "a_豈", "a_⼀" -> "a_一"), so the
                # raw form never matched. Translate through
                # the same six remap tables the as-is branch
                # uses (Greek Extended, enclosed CJK, kangxi,
                # parenthesized CJK, CJK compat, Hebrew
                # presentation) before
                # punycoding; labels without one are unchanged,
                # since every translate is identity for them.
                # A remap that leaves the label pure ASCII
                # (e.g. "a_㉐" -> "a_pte") passes through
                # unchanged, as browsers leave ASCII labels
                # alone, instead of gaining a bogus "xn--"
                # prefix; a remap that still has non-ASCII
                # punycodes directly, as before.
                _us_remapped = (
                    label.translate(_greek_extended_remap)
                    .translate(_enclosed_cjk_remap)
                    .translate(_kangxi_remap)
                    .translate(_parenthesized_cjk_remap)
                    .translate(_cjk_compat_remap)
                    .translate(_hebrew_presentation_remap)
                )
                # An underscore label at a right-to-left edge:
                # UTS46's RTL-label rules require the first
                # character to be strong RTL (R/AL) and the
                # last character to be strong RTL or a digit,
                # so a label that starts or ends with "_"
                # (bidi class ON, a neutral) while containing
                # a strong-RTL or Arabic-Indic character is
                # browser-rejected ("ا_" / "_ا" / "م_" /
                # "م_م_" / "٣_" all fail in the WHATWG
                # parser), yet this fallback punycoded it raw
                # ("ا_" -> "xn--_-ymc"), a form no browser
                # origin could carry, so it never matched.
                # Raise, so the outer handler returns None
                # for the whole host, as for other rejected
                # labels. Mid-label underscores are untouched
                # ("م_م" stays valid), as are labels with no
                # R/AL/AN character ("a_" / "mün_chen" keep
                # their existing forms), and labels claimed
                # by an earlier branch (fraction, as-is, FB29
                # and the like) keep their own handling.
                import unicodedata as _us_rtl_unicodedata

                if (
                    _us_remapped.startswith("_")
                    or _us_remapped.endswith("_")
                ) and any(
                    _us_rtl_unicodedata.bidirectional(c)
                    in ("R", "AL", "AN")
                    for c in _us_remapped
                ):
                    raise ValueError("rtl underscore edge")
                # A browser-rejected codepoint in an underscore
                # label: U+321F is unassigned (general category
                # Cn) and the WHATWG parser rejects any host
                # containing it, yet this fallback punycoded it
                # raw ("a_㈟" -> "xn--a_-5d5a"), a form no browser
                # origin could carry, so it never matched. Raise,
                # so the outer handler returns None for the whole
                # host, as for other rejected labels. U+321F is
                # excluded from the parenthesized remap above, so
                # it survives into the remapped form unchanged;
                # labels without it keep their existing forms, and
                # labels claimed by an earlier branch keep their
                # own handling.
                if "\u321f" in _us_remapped:
                    raise ValueError("unassigned underscore")
                # A UTS46 bidi violation in an underscore label:
                # the `idna` package's strict path rejects these,
                # but this fallback punycoded them raw, producing
                # a form no browser origin could carry, so it
                # never matched. UTS46's RTL-label rules require
                # a label containing a strong-RTL character
                # (R/AL) to start with one, to end with a
                # strong-RTL character, a European or
                # Arabic-Indic digit, or a nonspacing mark, to
                # contain no Latin (L) character, and to not mix
                # European and Arabic-Indic digits ("a_م" /
                # "م_a" / "م_مa" / "1_م" / "٣_م" / "م_٣1" all
                # fail in the WHATWG parser, while "م_م" /
                # "م_٣" / "م_1" / "م_1م" / "م_م\u0301" pass).
                # A label containing an Arabic-Indic digit but
                # no strong-RTL character is likewise neither a
                # valid RTL label (which needs R/AL) nor a valid
                # LTR label (which may not contain AN), so
                # "٣_٣" / "٣_1" / "a_٣" also fail in the WHATWG
                # parser. Raise, so the outer handler returns
                # None for the whole host, as for other rejected
                # labels. Labels with no R/AL/AN character keep
                # their existing forms, and labels claimed by an
                # earlier branch keep their own handling.
                _us_bidi = [
                    _us_rtl_unicodedata.bidirectional(c)
                    for c in _us_remapped
                ]
                if any(b in ("R", "AL") for b in _us_bidi):
                    if (
                        _us_bidi[0] not in ("R", "AL")
                        or _us_bidi[-1]
                        not in ("R", "AL", "EN", "AN", "NSM")
                        or "L" in _us_bidi
                        or ("EN" in _us_bidi and "AN" in _us_bidi)
                    ):
                        raise ValueError("rtl bidi underscore")
                elif "AN" in _us_bidi:
                    raise ValueError("an underscore without rtl")
                # Browsers reject every underscore label that
                # mixes U+0888 with another strong-RTL
                # character or an Arabic-Indic digit ("م_࢈م",
                # "࢈_م", "࢈_٣" all rejected by the WHATWG
                # parser), even though the first/end/L checks
                # above pass for them, so they were emitted as
                # raw punycode that no browser origin could
                # carry. U+0888 alone, with only itself, or
                # with European digits / nonspacing marks
                # ("࢈_࢈", "࢈_1", "࢈_\u0301") is unaffected:
                # this clause needs another R/AL/AN character
                # besides U+0888 itself. (The as-is and
                # double-exclamation branches gained the R/AL
                # form of this clause in iteration 699; the
                # underscore branch's own gate above did not,
                # and AN mixes reach only this branch — a bare
                # "࢈٣" is already None.)
                if "\u0888" in _us_remapped and any(
                    b in ("R", "AL", "AN") and ord(c) != 0x0888
                    for c, b in zip(_us_remapped, _us_bidi)
                ):
                    raise ValueError("rtl bidi underscore 0888")
                if any(ord(c) > 127 for c in _us_remapped):
                    encoded_labels.append(
                        "xn--"
                        + _us_remapped.encode("punycode").decode(
                            "ascii"
                        )
                    )
                else:
                    encoded_labels.append(_us_remapped)
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

