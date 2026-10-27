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
    # probe in this iteration confirmed.
    _fraction_map = {0x00BC: "1⁄4", 0x00BD: "1⁄2", 0x00BE: "3⁄4"}
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
                if (
                    _frac_remapped is not None
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
            elif any(ord(c) in _punycode_asis for c in label):
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
                # through _enclosed_cjk_remap (see there);
                # labels without one are unchanged by it.
                encoded_labels.append(
                    "xn--"
                    + label.translate(_asis_map)
                    .translate(_double_excl_map)
                    .translate(_greek_extended_remap)
                    .translate(_enclosed_cjk_remap)
                    .encode("punycode")
                    .decode("ascii")
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
                _excl_remapped = label.translate(_double_excl_map)
                if any(ord(c) > 127 for c in _excl_remapped):
                    encoded_labels.append(
                        "xn--"
                        + _excl_remapped.encode("punycode").decode(
                            "ascii"
                        )
                    )
                else:
                    encoded_labels.append(_excl_remapped)
            elif any(0x20D0 <= ord(c) <= 0x20F0 for c in label):
                # Combining marks for symbols U+20D0-U+20F0: the
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
                encoded_labels.append(
                    "xn--" + label.encode("punycode").decode("ascii")
                )
            elif any(
                0x3200 <= ord(c) <= 0x321E
                or 0x3220 <= ord(c) <= 0x3243
                or 0x3248 <= ord(c) <= 0x324F
                or 0x3260 <= ord(c) <= 0x326D
                or ord(c) == 0x327F
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
                # it is excluded here. The gates mirror the
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
                # matching the browser's rejection. A label
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
                if (
                    _hyph_form is not None
                    and (
                        _hyph_form.strip(_hyph_punct).startswith("-")
                        or _hyph_form.strip(_hyph_punct).endswith("-")
                        or any(c in _hyph_punct for c in _hyph_form)
                    )
                    and _hyph_unicodedata.category(_hyph_form[0])[0]
                    != "M"
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
                            and _hyph_unicodedata.bidirectional(c)
                            not in ("R", "AL", "AN")
                        )
                        for c in _hyph_form
                    )
                ):
                    encoded_labels.append(
                        "xn--"
                        + _hyph_form.encode("punycode").decode("ascii")
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

