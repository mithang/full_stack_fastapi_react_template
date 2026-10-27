from typing import Any, Dict, Literal, Optional
from pydantic import BaseModel, Field
from datetime import datetime

AuditActionType = Literal["create", "update", "delete", "read", "login", "logout", "error", "download"]
class AuditLogDto(BaseModel):
    entity: str
    action: AuditActionType
    changes: Dict[str, Any] = {}
    user_id: Optional[str] = None
    # default_factory, not a plain default: datetime.now().isoformat()
    # as a plain default is evaluated once at class definition, so every
    # entry constructed without a timestamp (all app writers: the read
    # middleware and the repositories) shared the server-start time.
    # Entries read back from disk pass timestamp explicitly, so stored
    # lines are unaffected by this change.
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    tenant_id: Optional[str] = None

class AuditLogListDto(BaseModel):
    total: int
    logs: list[AuditLogDto]
    has_next: bool
    has_previous: bool
    limit: int
    skip: int

class DownloadAuditRequestDto(BaseModel):
    action: Optional[AuditActionType] = None
    total_records: int