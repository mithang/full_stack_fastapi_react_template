from fastapi import APIRouter, Depends, UploadFile, status
from api.common.utils import get_logger
from api.core.container import get_deps
from api.core.exceptions import BrandingException
from api.domain.dtos.branding_dto import UpdateBrandingDto
from api.domain.enum.permission import Permission
from api.infrastructure.security.current_user import CurrentUser
from api.interfaces.middlewares.tenant_middleware import get_tenant_id
from api.interfaces.security.role_checker import check_permissions_for_current_role
from api.usecases.branding_service import BrandingService
from api.usecases.file_service import FileService

logger = get_logger(__name__)


def _safe_log_value(value: object) -> str:
    # The logo filename comes from the multipart header, so it is
    # client-controlled: a newline-bearing name could forge extra log
    # lines. Flatten CR/LF in the logged copy only; the raw filename
    # still drives the storage key, same shape as file_upload.py.
    return str(value).replace("\r", " ").replace("\n", " ")


router = APIRouter(prefix="/brandings", dependencies=[Depends(check_permissions_for_current_role(required_permissions=[Permission.FULL_ACCESS]))])
router.tags = ["Branding"]


def _assert_create_scope(current_user: CurrentUser, request_tenant_id) -> None:
    # Branding create-when-none guard, closing the residual squat case
    # left open by the update scoping (iteration 866): branding is a
    # singleton in the current DB and create refuses a second record,
    # and there is no branding delete endpoint, so a tenant caller
    # creating on the host DB (no X-Tenant-ID/subdomain, request scope
    # None) would permanently occupy the host branding slot with a
    # tenant-stamped record the host could never replace — and the
    # host branding GET would then serve that tenant's branding.
    # Legitimate tenant creation happens in the caller's own tenant
    # DB, where the middleware scope equals their tenant id, and host
    # callers (tenant_id None) are unaffected. A mismatched scope
    # fails closed rather than stamping a record into the wrong DB.
    if current_user.tenant_id is not None and (
        request_tenant_id is None or str(request_tenant_id) != str(current_user.tenant_id)
    ):
        raise BrandingException("Branding cannot be created outside your tenant's scope.")


@router.post("/", status_code=status.HTTP_204_NO_CONTENT)
async def update_branding(
    current_user: CurrentUser,
    data: UpdateBrandingDto,
    branding_service: BrandingService = Depends(get_deps(BrandingService)),
    request_tenant_id = Depends(get_tenant_id)
):

    # Do not log the full DTO: it carries contact_info (PII) and the
    # api logger runs at DEBUG in all environments (see iteration 432).
    logger.debug(f"Update branding called for tenant: {current_user.tenant_id}")
    branding = await branding_service.get_branding()
    if branding is None:
        _assert_create_scope(current_user, request_tenant_id)
        data.tenant_id = current_user.tenant_id
        branding = await branding_service.create_branding(data=data)
    else:
        await branding_service.update_branding(id=str(branding.id), data=data, tenant_id=current_user.tenant_id, request_tenant_id=request_tenant_id)

@router.patch("/{branding_id}", status_code=status.HTTP_204_NO_CONTENT)
async def partial_update_branding(
    current_user: CurrentUser,
    branding_id: str,
    data: UpdateBrandingDto,
    branding_service: BrandingService = Depends(get_deps(BrandingService)),
    request_tenant_id = Depends(get_tenant_id)
):
    branding = await branding_service.get_branding()
    if branding is None:
        raise BrandingException("Branding not found.")

    # Branding is a singleton (create_branding refuses a second one).
    # update_branding now also raises on an unknown id, but this check
    # stays as explicit id validation: the existence check alone does
    # not validate the requested id, only that some branding exists,
    # so a mismatched id should fail here rather than reaching the
    # update call at all.
    if branding.id != branding_id:
        raise BrandingException("Branding not found.")

    data.tenant_id = current_user.tenant_id
    await branding_service.update_branding(id=branding_id, data=data, tenant_id=current_user.tenant_id, request_tenant_id=request_tenant_id)


@router.put("/logo", status_code=status.HTTP_202_ACCEPTED)
async def upload_logo(
    current_user: CurrentUser,
    file: UploadFile,
    branding_service: BrandingService = Depends(get_deps(BrandingService)),
    file_service: FileService = Depends(get_deps(FileService)),
    request_tenant_id = Depends(get_tenant_id)
):
    # The frontend caps logos at 5 MB, but a direct API call bypasses
    # it, so enforce the same cap server-side before the file reaches
    # storage (mirroring the profile-picture upload). Chunks are
    # counted, not retained, and the stream is rewound afterwards:
    # the endpoint previously read the whole file into memory and
    # left the stream at EOF, so the storage backends below (S3 via
    # file.file, Azure via file.read()) uploaded from the end of the
    # stream instead of the full logo.
    max_size = 5 * 1024 * 1024
    size = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        size += len(chunk)
        if size > max_size:
            raise BrandingException("File size must be less than 5MB.")
    await file.seek(0)
    logger.debug(f"Received logo file: {_safe_log_value(file.filename)}, size: {size} bytes")
    if size == 0:
        raise BrandingException("Uploaded file is empty.")
    # PNG/JPEG only, matching the LogoType literal on BrandingDto /
    # UpdateBrandingDto (and the frontend file picker's accept list):
    # SVG was listed here, but constructing those DTOs with
    # logo_type="image/svg+xml" fails validation — after the file had
    # already been uploaded, so an SVG upload orphaned a storage object
    # and surfaced as a validation error instead of this clean
    # "Unsupported file type" rejection. Rejecting it here, before any
    # storage write, keeps the allowlist and the DTO in agreement; no
    # legitimate SVG branding can exist to lose, since the DTO path
    # could never have stored one.
    if file.content_type not in ["image/png", "image/jpeg"]:
        raise BrandingException("Unsupported file type. Please upload a PNG or JPEG image.")
    
    # Resolve the branding record before uploading: the create-scope
    # guard below used to run only after the upload, so a tenant
    # caller on the wrong DB (no X-Tenant-ID/subdomain, request scope
    # None) still wrote their logo into the current scope's storage
    # before being refused — an orphaned object in the wrong bucket,
    # the same wrong-scope class as the POST create guard, even
    # though the record creation itself was blocked. Failing fast
    # here keeps the upload out of the refused path; legitimate
    # uploads (branding exists, or a matching-scope creation) are
    # unchanged, and the update path below still runs its
    # service-level scope check.
    branding = await branding_service.get_branding()
    if branding is None:
        # Same create-scope guard as the POST route: a logo-first
        # creation by a tenant caller on the host DB would squat the
        # singleton slot just as a POST creation would.
        _assert_create_scope(current_user, request_tenant_id)
    else:
        # Update-scope pre-check before the upload: the service-level
        # scope check in update_branding below runs only after the
        # file is written, so a refused update still left its logo
        # orphaned in the current scope's storage — the same
        # upload-before-refusal ordering fixed for the create branch
        # above. This mirrors that check's decision (host callers
        # allowed; a tenant caller allowed only for their own stamp,
        # or for a legacy None-stamped record claimed from their own
        # tenant DB) using the record already fetched here, and the
        # service check still runs as the authoritative backstop.
        # The refusal message matches the service's "not found" so a
        # probe cannot distinguish a refused record from a missing one.
        if current_user.tenant_id is not None:
            stamp = branding.tenant_id
            claim_legacy = (
                stamp is None
                and request_tenant_id is not None
                and str(request_tenant_id) == str(current_user.tenant_id)
            )
            if not claim_legacy and (stamp is None or str(stamp) != str(current_user.tenant_id)):
                raise BrandingException("Branding not found.")
    key = await file_service.upload_file(file=file)
    logger.debug(f"Logo uploaded successfully with key: {key}")
    if branding is None:
        # Stamp the logo-first creation with the caller's tenant, as
        # the POST route does: without it the record is host-stamped
        # (tenant_id None) and the update scope check in
        # BrandingService would then refuse the tenant caller any
        # later update of their own branding (the previous code here
        # was a no-op self-assignment, not a stamp).
        branding = await branding_service.create_branding(data=UpdateBrandingDto(logo_url=key, logo_type=file.content_type, tenant_id=current_user.tenant_id))
        return
    

    await branding_service.update_branding(id=str(branding.id), data=UpdateBrandingDto(logo_url=key, logo_type=file.content_type), tenant_id=current_user.tenant_id, request_tenant_id=request_tenant_id)
