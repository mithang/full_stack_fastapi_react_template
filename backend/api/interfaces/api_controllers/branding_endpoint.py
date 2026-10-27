from fastapi import APIRouter, Depends, UploadFile, status
from pydantic import Json
from api.common.utils import get_logger
from api.core.container import get_deps
from api.core.exceptions import BrandingException
from api.domain.dtos.branding_dto import IdentityDto, UpdateBrandingDto
from api.domain.enum.permission import Permission
from api.infrastructure.security.current_user import CurrentUser
from api.interfaces.security.role_checker import check_permissions_for_current_role
from api.usecases.branding_service import BrandingService
from api.usecases.file_service import FileService

logger = get_logger(__name__)

router = APIRouter(prefix="/brandings", dependencies=[Depends(check_permissions_for_current_role(required_permissions=[Permission.FULL_ACCESS]))])
router.tags = ["Branding"]

@router.post("/", status_code=status.HTTP_204_NO_CONTENT)
async def update_branding(
    current_user: CurrentUser,
    data: UpdateBrandingDto,
    branding_service: BrandingService = Depends(get_deps(BrandingService))
):

    logger.debug(f"Update branding called with data: {data}")  
    branding = await branding_service.get_branding()
    if branding is None:
        data.tenant_id = current_user.tenant_id
        branding = await branding_service.create_branding(data=data)
    else:
        await branding_service.update_branding(id=str(branding.id), data=data)

@router.patch("/{branding_id}", status_code=status.HTTP_204_NO_CONTENT)
async def partial_update_branding(
    current_user: CurrentUser,
    branding_id: str,
    data: UpdateBrandingDto,
    branding_service: BrandingService = Depends(get_deps(BrandingService))
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
    await branding_service.update_branding(id=branding_id, data=data)


@router.put("/logo", status_code=status.HTTP_202_ACCEPTED)
async def upload_logo(
    current_user: CurrentUser,
    file: UploadFile,
    branding_service: BrandingService = Depends(get_deps(BrandingService)),
    file_service: FileService = Depends(get_deps(FileService))
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
    logger.debug(f"Received logo file: {file.filename}, size: {size} bytes")
    if size == 0:
        raise BrandingException("Uploaded file is empty.")
    if file.content_type not in ["image/png", "image/jpeg", "image/svg+xml"]:
        raise BrandingException("Unsupported file type. Please upload a PNG, JPEG, or SVG image.")
    
    key = await file_service.upload_file(file=file)
    logger.debug(f"Logo uploaded successfully with key: {key}")
    branding = await branding_service.get_branding()
    if branding is None:
        current_user.tenant_id = current_user.tenant_id
        branding = await branding_service.create_branding(data=UpdateBrandingDto(logo_url=key, logo_type=file.content_type))
        return
    

    await branding_service.update_branding(id=str(branding.id), data=UpdateBrandingDto(logo_url=key, logo_type=file.content_type))