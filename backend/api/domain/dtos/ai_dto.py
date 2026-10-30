from typing import List, Optional
from pydantic import BaseModel, Field, model_validator


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

    @model_validator(mode="after")
    def normalize_identifiers(self):
        # Normalize before use: the chat UI sends model_name/session_id
        # verbatim from server-provided lists, but a direct API client
        # can pad either value, and neither can legitimately carry
        # surrounding whitespace. A padded model_name passes the
        # endpoint's blank check yet is handed verbatim to
        # ChatOllama(model=...), which fails the model lookup with a
        # generic error; a padded session_id likewise misses the
        # stored session lookup and silently starts a new session
        # instead of continuing the old one — the same
        # deferred-failure class as the storage/SSO/Stripe DTO
        # validators. Trimming here covers every caller of /ask.
        # Whitespace-only values are left as "" so the endpoint's
        # existing "cannot be empty" error path is unchanged, and
        # None still means "not provided". The question is deliberately
        # not trimmed: its whitespace can be meaningful content.
        for field in ("model_name", "session_id"):
            value = getattr(self, field, None)
            if isinstance(value, str):
                setattr(self, field, value.strip())
        return self
