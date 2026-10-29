from typing import List, Optional
from pydantic import BaseModel, Field


class AIModelInfoDto(BaseModel):
    name: str
    digest: str
    size: str
    created: str

class AIHistoryDto(BaseModel):
    uid: str
    query: str
    response: str
    timestamp: str
    tenant_id: str | None = None

class AIHistoriesDto(BaseModel):
    id: str
    histories: List[AIHistoryDto]


class AISessionDto(BaseModel):
    id: str
    session_id: str
    created_at: str
    history_id: str
    tenant_id: str | None = None
    user_id: str

class AISessionByUserIdDto(AISessionDto):
    sessions: List[AIHistoriesDto]



class AIAskRequestDto(BaseModel):
    # The chat textarea caps input at 2000 characters, but a direct API
    # call bypasses it, so enforce the same cap server-side: an uncapped
    # question flows verbatim into the LLM prompt and the persisted
    # history record, so an oversized question inflates model cost /
    # context and history storage. 2000 matches the frontend cap exactly,
    # so no legitimate client flow is affected; overlong questions now
    # fail FastAPI validation (422) before reaching the model.
    question: str = Field(..., max_length=2000)
    model_name: Optional[str] = None
    session_id: Optional[str] = None
