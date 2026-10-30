from typing import Annotated
from beanie import PydanticObjectId
from fastapi import APIRouter, Body, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.params import Query
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import EmailStr
from api.common.dtos.passkey_rep_dto import HasPasskeysDto
from api.common.dtos.token_dto import TokenRefreshRequestDto, TokenSetDto
from api.common.dtos.worker_dto import WorkerPayloadDto
from api.common.exceptions import ApiBaseException, ForbiddenException, InvalidOperationException
from api.common.utils import get_logger, is_tenancy_enabled, validate_password
from api.core.container import get_auth_service, get_email_magic_link_service, get_passkey_service, get_role_service, get_sso_auth_provider, get_user_magic_link_repository
from api.core.exceptions import PassKeyException, UserNotFoundException
from api.domain.dtos.auth_dto import ChangeEmailConfirmRequestDto, ChangeEmailRequestDto, ChangeEmailResponseDto, MagicLinkResponseDto, MeResponseDto, PasswordResetConfirmRequestDto, PasswordResetRequestDto, PasswordResetResponseDto
from api.domain.dtos.login_dto import LoginRequestDto
from api.domain.dtos.user_dto import CreateUserDto, UserActivationRequestDto, UserDto, UserResendActivationEmailRequestDto
from api.domain.entities.sso_settings import SSOProvider
from api.domain.enum.permission import Permission
from api.infrastructure.externals.sso_auth_provider import SSOAuthProvider
from api.infrastructure.messaging.celery_worker import handle_post_tenant_creation
from api.infrastructure.persistence.repositories.user_magic_link_repository_impl import UserMagicLinkRepository
from api.infrastructure.security.current_user import CurrentUser, CurrentUserOptional
from api.infrastructure.security.passkey_service import PasskeyService
from api.interfaces.middlewares.tenant_middleware import FrontendHost, get_tenant_id
from api.interfaces.security.role_checker import check_permissions_for_current_role
from api.usecases.auth_service import AuthService
from api.core.config import settings
from api.common.dtos.cookies import Cookies
from api.common.security import hash_it
from api.usecases.magic_link_service import EmailMagicLinkService
from api.usecases.role_service import RoleService
from api.domain.enum.role import RoleType

logger = get_logger(__name__)


def _safe_log_value(value) -> str:
    # OAuth2PasswordRequestForm username is a free-form form field, and
    # this log line runs before LoginRequestDto's EmailStr validation,
    # so a newline in a login attempt could otherwise forge extra log
    # lines — unauthenticated (same class as the tenant-name,
    # preference-key, cache-path and user-update fixes in iterations
    # 951-954). Only the logged copy is flattened. x_tenant_id needs no
    # such treatment: it arrives as an HTTP header value, which cannot
    # carry a raw newline.
    return str(value).replace("\r", " ").replace("\n", " ")


router = APIRouter(prefix="/account", tags=["Account"])

@router.post("/login", response_model=TokenSetDto, status_code=status.HTTP_200_OK)
async def login(
    response: Response,
    login_request: Annotated[OAuth2PasswordRequestForm, Depends()],
    auth_service: AuthService = Depends(get_auth_service),
    x_tenant_id: str | None = Depends(get_tenant_id)
):
    logger.info(f"Login attempt for user: {_safe_log_value(login_request.username)} x_tenant_id: {x_tenant_id}")
    token_set: TokenSetDto = await auth_service.login(LoginRequestDto(
        email=login_request.username,
        password=login_request.password
    ))
    # Token response (access token in the body, rotated refresh token
    # in Set-Cookie): POST responses are not cached by default, but
    # make that explicit so no browser/proxy cache can ever store a
    # token body or replay a Set-Cookie — same no-store hardening as
    # the magic-link validation GET in this controller.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.set_cookie(
        key="refresh_token",
        value=token_set.refresh_token,
        httponly=True,
        secure=settings.fastapi_env == "production",
        samesite="lax",
        max_age=settings.refresh_token_expire_days * 24 * 60 * 60
    )
    return token_set


@router.post("/refresh",  response_model=TokenSetDto, status_code=status.HTTP_200_OK)
async def refresh_token(
    response: Response,
    cookies: Annotated[Cookies, Cookie()],
    auth_service: AuthService = Depends(get_auth_service)
):
    if cookies.refresh_token is None:
        raise ForbiddenException("Refresh token missing!")
    
    token = TokenRefreshRequestDto(refresh_token=cookies.refresh_token)
    
    token_set = await auth_service.refresh_token(token)
    # Same token-response no-store hardening as login() above.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.set_cookie(
        key="refresh_token",
        value=token_set.refresh_token,
        httponly=True,
        secure=settings.fastapi_env == "production",
        samesite="lax",
        max_age=settings.refresh_token_expire_days * 24 * 60 * 60
    )
    return token_set

@router.get("/logout", status_code=status.HTTP_200_OK)
async def logout(
    response: Response,
    current_user: CurrentUserOptional,
    auth_service: AuthService = Depends(get_auth_service)
):
    # This GET deletes the refresh cookie and records a logout, so it
    # must never be served from a browser or proxy cache: a cached 200
    # would replay without running the handler, leaving the refresh
    # cookie (and the session it backs) in place while the user believes
    # they logged out. Same no-store hardening as the other
    # state-changing GETs in this controller (magic-link validation and
    # the SSO login/callback redirects).
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    # Mirror the attributes used when the cookie was set (login/refresh):
    # a deletion Set-Cookie without Secure cannot clear a Secure cookie
    # in production, leaving a stale refresh token in the browser.
    response.delete_cookie(
        "refresh_token",
        path="/",
        secure=settings.fastapi_env == "production",
        httponly=True,
        samesite="lax",
    )
    # Logout must succeed even when the access token has already expired
    # (or is absent): with the required CurrentUser dependency the
    # endpoint 401'd before reaching the cookie deletion above, so the
    # refresh cookie survived logout — and the background worker then
    # refreshed it back into a live session within 10 minutes, silently
    # undoing the logout. The cookie deletion is the session-ending act
    # here (auth_service.logout only writes an audit log; there is no
    # server-side token denylist), so it runs unconditionally and the
    # audit entry is written only when a user actually resolved.
    if current_user is not None:
        await auth_service.logout(user_id=str(current_user.id), tenant_id=str(current_user.tenant_id) if current_user.tenant_id else None)
    return status.HTTP_200_OK

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    data: CreateUserDto,
    auth_service: AuthService = Depends(get_auth_service),
    role_service: RoleService = Depends(get_role_service),
    x_tenant_id: PydanticObjectId | None = Depends(get_tenant_id)
):
    logger.info(f"Register attempt for user: {data.email} x_tenant_id: {x_tenant_id}")
    role_guest = await role_service.find_by_name(name=RoleType.GUEST)

    if x_tenant_id is not None:
        data.tenant_id = x_tenant_id
      
    def process_user_creation(tenant_id: PydanticObjectId):
        logger.info(f"Processing user creation for tenant_id: {tenant_id}")
        data.tenant_id = tenant_id
        # The Celery payload is persisted in the broker until consumed,
        # so it must never carry the plaintext password (iteration
        # 1004): validate the plaintext policy here first — the worker
        # now skips validation — then hash it, and let the worker skip
        # re-hashing. Only this payload copy is hashed — `data` itself
        # stays plaintext, so the direct create_user() branches in
        # AuthService.register() (subdomain-taken path) still validate
        # and hash normally and are unaffected. A weak password now
        # fails synchronously here instead of failing later in the
        # worker after a false 201.
        validate_password(data.password)
        payload_user = data.model_copy(update={"password": hash_it(data.password)})
        payload=WorkerPayloadDto[CreateUserDto](
            label="post-tenant-creation",
            data=payload_user,
            tenant_id=str(tenant_id)
        )
        handle_post_tenant_creation.delay(
            payload=payload.model_dump_json()
        )
    
    data.role_id = role_guest.id
    if x_tenant_id is not None and is_tenancy_enabled():
        # Tenant-context registration: the middleware already selected
        # this tenant's database and stamped the DTO above, but
        # AuthService.register() only creates when tenant_id is None
        # (its branches cover a brand-new subdomain or a taken one),
        # so a request carrying X-Tenant-ID — e.g. the frontend's
        # ApiClient with a stale _tenant entry, or a visit on a tenant
        # subdomain — previously returned 201 while creating nothing,
        # and the "check your email" toast promised an account that
        # never existed. Create directly into the already-selected
        # tenant DB, stamped with that tenant, mirroring the
        # single-tenant path (which also goes through
        # new_user_creation). The stamp is the middleware-resolved id
        # already on the DTO, not a fresh client value; a forged header
        # can only land a self-owned GUEST account in that header's
        # isolated tenant DB, never in another tenant's data.
        await auth_service.new_user_creation(new_user=data, tenant_id=x_tenant_id)
        return status.HTTP_201_CREATED
    await auth_service.register(data, process_user_creation)
    return status.HTTP_201_CREATED
        

@router.get("/me", response_model=MeResponseDto, status_code=status.HTTP_200_OK)
async def read_users_me(
    response: Response,
    current_user: CurrentUser
):
    # /me returns the authenticated user's identity, role, and
    # subscription, and is fetched on every protected navigation, so it
    # must never be served from a browser or proxy cache: a cached 200
    # could serve the previous user's identity after logout or an
    # account switch, or a stale role after a role change. Same
    # no-store hardening as the other GETs in this controller.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return current_user


@router.post("/password_reset_request", response_model=PasswordResetResponseDto, status_code=status.HTTP_200_OK)
async def password_reset_request(
    request: PasswordResetRequestDto,
    frontend_host: FrontendHost,
    auth_service: AuthService = Depends(get_auth_service)
):
    try:
        await auth_service.initate_password_reset(request.email, domain=frontend_host)
    except Exception as e:
        logger.error(f"Password reset request for email: {request.email} wasn't successful: {e}")
    finally:
        return PasswordResetResponseDto(message="If the email exists, a password reset link has been sent.")


@router.post("/password_reset_confirmation", response_model=PasswordResetResponseDto)
async def password_reset_confirm(
    request: PasswordResetConfirmRequestDto,
    token: str = Query(..., description="The password reset token"),
    user_id: str = Query(..., description="The user ID associated with the token"),
    tenant_id: str | None = Query(None, description="The tenant ID associated with the user, if applicable"),
    auth_service: AuthService = Depends(get_auth_service)

):
    logger.info(f"Password reset confirmation attempt for user_id: {_safe_log_value(user_id)} with tenant_id: {_safe_log_value(tenant_id)}")
    # Query params arrive verbatim: a token or user id copied from an
    # email link with surrounding whitespace would otherwise fail JWT
    # verification / the reset-data lookup with the generic "Invalid or
    # expired password reset token" error, even though the link itself
    # is valid — the same deferred-failure class as the change-email
    # confirmation token trim. JWTs and user ids never legitimately
    # carry surrounding whitespace, and a whitespace-only value still
    # fails afterwards, so the error path is unchanged. The new
    # password itself is never trimmed.
    token = token.strip()
    user_id = user_id.strip()
    await auth_service.change_password(
        new_password=request.new_password,
        token=token,
        user_id=user_id
    )
   
    return PasswordResetResponseDto(message="Password has been reset successfully. A notification email has been sent!")

@router.post("/resend_activation_email", status_code=status.HTTP_202_ACCEPTED)
async def resend_activation_email(
    req: UserResendActivationEmailRequestDto,
    frontend_host: FrontendHost,
    auth_service: AuthService = Depends(get_auth_service),
    _bool: bool = Depends(check_permissions_for_current_role(
        required_permissions=[Permission.USER_READ_AND_WRITE_ONLY, Permission.FULL_ACCESS]
    ))
):
    await auth_service.send_activation_email(req, frontend_host)
    return status.HTTP_202_ACCEPTED


@router.post("/activate", status_code=status.HTTP_200_OK)
async def activate_account(
    req: UserActivationRequestDto,
    tenant_id: str | None = Query(None, description="The tenant ID associated with the user, if applicable"),
    auth_service: AuthService = Depends(get_auth_service)
):
    await auth_service.activate_account(req)
    return status.HTTP_200_OK


@router.patch("/change_email_request",  status_code=status.HTTP_202_ACCEPTED)
async def change_email(
    request: ChangeEmailRequestDto,
    current_user: CurrentUser,
    frontend_host: FrontendHost,
    auth_service: AuthService = Depends(get_auth_service)
):
    
    # Do not wrap this in try/finally with a return: a return in finally
    # would swallow the service's InvalidOperationException (same email,
    # new email already in use, email-send failure) and report 202 for a
    # request that never happened. Unlike password_reset_request, this
    # endpoint is authenticated, so there is no anti-enumeration reason
    # to hide failures; they surface via the InvalidOperationException
    # handler as a clean 406 {"error": ...}.
    await auth_service.change_email_request(
        current_email=current_user.email,
        new_email=request.new_email,
        domain=frontend_host
    )
    return status.HTTP_202_ACCEPTED

    
@router.patch("/change_email_confirmation",  status_code=status.HTTP_200_OK, response_model=ChangeEmailResponseDto)
async def change_email_confirmation(
    request: ChangeEmailConfirmRequestDto,
    current_user: CurrentUser,
    auth_service: AuthService = Depends(get_auth_service)
):
    try:
        await auth_service.change_email_confirmation(
            token=request.token,
            current_user_id=str(current_user.id)
        )
    except InvalidOperationException as e:
        raise HTTPException(status_code=400, detail="Email change confirmation failed.")
    
    return ChangeEmailResponseDto(message="Email changed successfully.")



@router.post("/passkey/register_options", status_code=status.HTTP_200_OK)
async def passkey_register_options(
    email: EmailStr = Body(...),
    passkey_service: PasskeyService = Depends(get_passkey_service),
    auth_service: AuthService = Depends(get_auth_service)
):
    user_service = await auth_service.get_user_service()
    user = await user_service.find_by_email(email=email)
    user_dto = await user.to_serializable_dict()
    try:
        result = await passkey_service.register_options(user_dto=UserDto(**user_dto))
    except PassKeyException:
        raise
    except Exception as e:
        # register_options resolves the relying party, creates the passkey
        # record if missing, and calls the webauthn library's
        # generate_registration_options; a tenant lookup or library error
        # would otherwise escape as a 500 instead of the mapped 406, unlike
        # passkey_login_options which already wraps its service call
        # (iteration 324). find_by_email stays outside the try so
        # unknown-email 404s are unchanged.
        logger.error(f"Passkey registration options failed for email: {email} with error: {e}")
        raise PassKeyException("Passkey registration failed.") from e

    return result


@router.post("/passkey/register", status_code=status.HTTP_202_ACCEPTED)
async def passkey_register(
    email: EmailStr = Body(...),
    credential: dict = Body(...),
    passkey_service: PasskeyService = Depends(get_passkey_service)
):
    try:
        result = await passkey_service.complete_registration(email, credential)

        if result is False:
            raise PassKeyException("Passkey registration failed.")
    except Exception as e:
        # verify_registration_response raises the webauthn library's own
        # exceptions for a malformed/forged credential, not PassKeyException:
        # without this guard they escape as a 500 instead of the mapped 406,
        # mirroring the try/except already present on passkey_login.
        logger.error(f"Passkey registration failed for email: {email} with error: {e}")
        raise PassKeyException("Passkey registration failed.") from e

    return status.HTTP_202_ACCEPTED
    

@router.post("/passkey/login_options", status_code=status.HTTP_200_OK)
async def passkey_login_options(
    email: EmailStr = Body(...),
    passkey_service: PasskeyService = Depends(get_passkey_service),
    auth_service: AuthService = Depends(get_auth_service)
):
    user_service = await auth_service.get_user_service()
    try:
        user = await user_service.find_by_email(email=email)
    except UserNotFoundException:
        # Same class of account-enumeration leak closed for password login
        # (iteration 792): an unknown email otherwise escapes as 404
        # "User with identifier <email> not found.", while a known account
        # without passkeys gets 406 "No credentials found...". Return the
        # identical 406 response so the two cases are indistinguishable
        # to a prober. The normal UI never reaches this path: loginFlow
        # only runs after has_passkeys returns true, so no UX change.
        raise PassKeyException("No credentials found for the user. Please register first.") from None
    user_doc = await user.to_serializable_dict()
    try:
        return await passkey_service.auth_login_options(user_dto=UserDto(**user_doc))
    except PassKeyException:
        raise
    except Exception as e:
        # auth_login_options base64-decodes stored credential ids and calls
        # the webauthn library's generate_authentication_options; a corrupt
        # stored credential (or a library error) would otherwise escape as a
        # 500 instead of the mapped 406, unlike passkey_login/register which
        # already wrap their service calls (iteration 323). The known
        # PassKeyException ("No credentials found...") passes through intact.
        logger.error(f"Passkey login options failed for email: {email} with error: {e}")
        raise PassKeyException("Passkey authentication failed.") from e


@router.post("/passkey/login", status_code=status.HTTP_200_OK, response_model=TokenSetDto)
async def passkey_login(
    response: Response,
    email: EmailStr = Body(...),
    credential: dict = Body(...),
    passkey_service: PasskeyService = Depends(get_passkey_service),
    auth_service: AuthService = Depends(get_auth_service)
):
    try:
        result = await passkey_service.complete_auth_login(email, credential)
        if result is False:
            raise PassKeyException("Passkey authentication failed.")
        
        token_set: TokenSetDto = await auth_service.login_with_passkey(email=email)

        # Same token-response no-store hardening as login() above.
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.set_cookie(
            key="refresh_token",
            value=token_set.refresh_token,
            httponly=True,
            secure=settings.fastapi_env == "production",
            samesite="lax",
            max_age=settings.refresh_token_expire_days * 24 * 60 * 60
        )
        return token_set
    except Exception as e:
        logger.error(f"Passkey login failed for email: {email} with error: {e}")
        raise PassKeyException("Passkey authentication failed.") from e
    

@router.post("/passkey/has_passkeys", response_model=HasPasskeysDto, status_code=status.HTTP_200_OK)
async def has_passkeys(
    email: EmailStr = Body(...),
    passkey_service: PasskeyService = Depends(get_passkey_service)
):
    return HasPasskeysDto(has_passkeys=await passkey_service.has_passkeys(email=email))


@router.post("/email_magic_link_login", response_model=MagicLinkResponseDto, status_code=status.HTTP_200_OK)
async def email_magic_link_login(
    email: EmailStr = Body(...),
    magic_link_service: EmailMagicLinkService = Depends(get_email_magic_link_service),
    auth_service: AuthService = Depends(get_auth_service)
):
    try:
        user_service = await auth_service.get_user_service()
        user = await user_service.find_by_email(email=email)
        user_doc = await user.to_serializable_dict()
        user_dto = UserDto(**user_doc)
        await magic_link_service.create_magic_link(user_dto)
        return MagicLinkResponseDto(message="If the email exists, a magic link has been sent.")
  
    except Exception as e:
        if isinstance(e, UserNotFoundException):
            logger.error(f"Magic link login request for email: {email} wasn't successful: {e}")
            return MagicLinkResponseDto(message="If the email exists, a magic link has been sent.")
        elif isinstance(e, ApiBaseException):
            raise e
        # Any other failure (email send, DB) for an existing user must not
        # be reported as success: the user would wait for a link that was
        # never sent. Only the unknown-email response stays generic, to
        # avoid enumerating accounts.
        logger.error(f"Magic link login request for email: {email} wasn't successful: {e}")
        raise
    
       
@router.get("/email_magic_link_validate", response_model=TokenSetDto, status_code=status.HTTP_200_OK)
async def email_magic_link_validate(
    response: Response,
    token: str = Query(..., description="The magic link token"),
    user_id: str = Query(..., description="The user ID associated with the token"),
    tenant_id: str | None = Query(None, description="The tenant ID associated with the user, if applicable"),
    auth_service: AuthService = Depends(get_auth_service),
    magic_link_service: EmailMagicLinkService = Depends(get_email_magic_link_service),
):
    from urllib.parse import unquote
    token = unquote(token)
    logger.info(f"Magic link validation attempt for user_id: {_safe_log_value(user_id)} with tenant_id: {_safe_log_value(tenant_id)}")
    is_valid = await magic_link_service.validate_magic_link(user_id=user_id, token=token)
    if is_valid is False:
        raise ForbiddenException("Invalid or expired magic link.")
    
    token_set: TokenSetDto = await auth_service.login_with_magic_link(user_id=user_id)

    # This is a GET that returns live tokens and sets the refresh
    # cookie, so it must never be served from a browser or proxy
    # cache: a cached 200 would replay a consumed link's token set
    # without re-validating it (and without the handler's Set-Cookie
    # on a replay that bypasses the handler). POST token endpoints
    # are not cached by default, so this GET is the exposed one.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.set_cookie(
        key="refresh_token",
        value=token_set.refresh_token,
        httponly=True,
        secure=settings.fastapi_env == "production",
        samesite="lax",
        max_age=settings.refresh_token_expire_days * 24 * 60 * 60
    )
    return token_set


@router.get("/sso/{provider_name}/login", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
async def sso_provider_login(
    provider_name: SSOProvider,
    sso_auth_provider: SSOAuthProvider = Depends(get_sso_auth_provider)
):
    # This redirect carries a per-request provider authorization URL,
    # so it must never be served from a browser or proxy cache: a
    # cached redirect would send a later user to the provider with
    # another login's authorization request instead of starting a
    # fresh one. Same no-store hardening as the SSO callback and the
    # magic-link validation GET below; the redirect target and the
    # 307 status are unchanged.
    redirect = await sso_auth_provider.login(provider_name)
    redirect.headers["Cache-Control"] = "no-store"
    redirect.headers["Pragma"] = "no-cache"
    return redirect
    
@router.get("/sso/{provider_name}/callback", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
async def sso_provider_callback(
    provider_name: SSOProvider,
    req: Request,
    tenant_id: PydanticObjectId | None = Depends(get_tenant_id),
    sso_auth_provider: SSOAuthProvider = Depends(get_sso_auth_provider),
    auth_service: AuthService = Depends(get_auth_service)

):
    user = await sso_auth_provider.callback(provider_name, req)
    token_set = await auth_service.login_with_sso(provider_name=provider_name, user_info=user , tenant_id=tenant_id)
    response = RedirectResponse(url=f"{sso_auth_provider.get_redirect_uri_to_app()}/dashboard", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    # This callback exchanges a one-time provider code and sets the
    # refresh cookie, so it must not be a permanent redirect: a 308
    # tells browsers/proxies the mapping is permanent and cacheable,
    # so a cached redirect would replay the one-time code URL straight
    # to /dashboard without re-validating it and without the handler's
    # Set-Cookie below (same class as the magic-link GET hardened in
    # the previous iteration). 307 preserves the GET method exactly
    # like 308 but carries no permanence, matching the SSO login
    # endpoint above; the no-store headers below stay as defence in
    # depth. Never cache it.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.set_cookie(
        key="refresh_token",
        value=token_set.refresh_token,
        httponly=True,
        secure=settings.fastapi_env == "production",
        samesite="lax",
        max_age=settings.refresh_token_expire_days * 24 * 60 * 60
    )
   
    
    return response
    

    

