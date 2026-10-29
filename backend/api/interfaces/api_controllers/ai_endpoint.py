
from typing import Any, List
from beanie import PydanticObjectId
from fastapi import APIRouter, BackgroundTasks, Depends, Response, status
from fastapi.responses import StreamingResponse

from api.common.dtos.new_session_dto import NewSessionResponseDto
from api.common.exceptions import ForbiddenException, InvalidOperationException
from api.core.container import get_local_ai_service, get_user_preference_service
from api.domain.dtos.ai_dto import AIAskRequestDto, AIModelInfoDto, AIHistoriesDto
from api.infrastructure.security.current_user import CurrentUser
from api.infrastructure.externals.local_ai_model import OllamaChat, OllamaModels
from api.usecases.local_ai_service import LocalAIService
from api.domain.dtos.ai_dto import AISessionByUserIdDto
from api.usecases.user_preference_service import UserPreferenceService
from api.domain.security.feature_access_management import check_feature_access
from api.interfaces.middlewares.tenant_middleware import get_tenant_id
from api.domain.enum.feature import Feature as FeatureEnum

router = APIRouter(prefix="/ai", dependencies=[Depends(check_feature_access(FeatureEnum.CHAT))])
router.tags = ["AI"]


def _assert_create_scope(current_user: CurrentUser, request_tenant_id) -> None:
    # Create-in-wrong-DB guard, mirroring the product/price/plan and
    # checkout guards: /ask saves the exchange as chat history and
    # session records in the current DB, stamped with the caller's
    # tenant_id (LocalAIService.save_user_query), and its session
    # lookup runs in that same DB. So a tenant caller without a
    # tenant DB selected (no X-Tenant-ID/subdomain, request scope
    # None) would have their chat history written to the host DB —
    # invisible to their own tenant DB's history list, and a
    # duplicate session row under the same session_id, since the
    # existing tenant-DB session is not found in the host DB.
    # Legitimate tenant asks carry X-Tenant-ID (ai-chat.tsx sends
    # it whenever a tenant is selected), so the middleware scope
    # equals their tenant id; host callers (tenant_id None) are
    # unaffected. A mismatched scope fails closed before any LLM
    # call or history write, rather than stamping records into the
    # wrong DB.
    if current_user.tenant_id is not None and (
        request_tenant_id is None or str(request_tenant_id) != str(current_user.tenant_id)
    ):
        raise ForbiddenException("AI chat history cannot be saved outside your tenant's scope.")

@router.get("/models", response_model=List[AIModelInfoDto])
async def get_models(
    response: Response,
    # current_user: CurrentUser
):
    # Live Ollama model list, feature-gated at the router level: a cached
    # 200 could show a stale list after models change, or serve the list
    # to a different user after an account switch on a shared machine.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return OllamaModels().list_models()

@router.get("/history", response_model=List[AISessionByUserIdDto])
async def get_history(
    current_user: CurrentUser,
    response: Response,
    ai_service: LocalAIService = Depends(get_local_ai_service),
):
    # Private per-user chat history: never let a browser/proxy cache serve a
    # stale session list (or one belonging to a previous user on a shared
    # machine) instead of running the handler.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return await ai_service.get_user_sessions(current_user.id)


@router.get("/new_session", response_model=NewSessionResponseDto)
async def create_new_session(current_user: CurrentUser, response: Response):
    # A fresh session id is minted on every call: a browser/proxy-cached
    # 200 would hand the same session id to every new chat, merging
    # distinct conversations into one history. The server Redis cache
    # already bypasses this route; no-store is the browser/proxy
    # counterpart, matching get_history/get_single_session above.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return NewSessionResponseDto(session_id=str(PydanticObjectId()))


@router.get("/sessions/{session_id}", response_model=List[AIHistoriesDto])
async def get_single_session(
    current_user: CurrentUser,
    response: Response,
    session_id: str,
    ai_service: LocalAIService = Depends(get_local_ai_service),

):
    # Private per-user chat history: never let a browser/proxy cache serve a
    # stale session transcript (or one belonging to a previous user on a
    # shared machine) instead of running the handler. Same no-store
    # hardening as get_history above; the server-side Redis bypass for
    # this route does not stop browser/proxy caching.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return await ai_service.get_histories_by_session_id(current_user.id, session_id)

@router.delete("/sessions/{session_id}", status_code=status.HTTP_202_ACCEPTED)
async def delete_session(
    current_user: CurrentUser,
    session_id: str,
    ai_service: LocalAIService = Depends(get_local_ai_service),
):
    await ai_service.delete_session(current_user.id, session_id)
    return status.HTTP_202_ACCEPTED


@router.put("/set_model_preference/{model_name}", status_code=status.HTTP_204_NO_CONTENT)
async def set_preferred_model(
    current_user: CurrentUser,
    model_name: str,
    user_preference: UserPreferenceService = Depends(get_user_preference_service)
):
    if model_name is None or model_name.strip() == "":
        raise InvalidOperationException("Model name cannot be empty")

    payload: dict[str, Any] = {}
    payload["model_name"] = model_name
    await user_preference.set_preferences(user_id=current_user.id, payload=payload)
    return status.HTTP_204_NO_CONTENT


@router.post("/ask")
async def ask_ai(
    current_user: CurrentUser,
    query: AIAskRequestDto,
    background_tasks: BackgroundTasks,
    local_ai_service: LocalAIService = Depends(get_local_ai_service),
    request_tenant_id = Depends(get_tenant_id),
):
    _assert_create_scope(current_user, request_tenant_id)
    if query.question is None or query.question.strip() == "":
        raise InvalidOperationException("Question cannot be empty")

    if query.model_name is None or query.model_name.strip() == "":
        raise InvalidOperationException("Model name cannot be empty")
    
 
    chat = OllamaChat(
        username=current_user.first_name,
        user_id=current_user.id,
        model_name=query.model_name,
        current_session=query.session_id,
        tenant_id=current_user.tenant_id,
        local_ai_service=local_ai_service
    )
    stream = await chat.generate_response(query.question, background_tasks)
    return StreamingResponse(stream(), media_type="text/plain")