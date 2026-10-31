from typing import Any, Dict, Literal, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone

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
    # UTC-aware, not naive local time: the log filename already uses
    # get_utc_now()'s date, and the frontend renders this with
    # new Date(timestamp), which reads a naive string as browser-local
    # time — so a naive server-local timestamp displayed wrong whenever
    # server and browser timezones differed. The "+00:00" suffix makes
    # the instant unambiguous; entries read back from disk pass
    # timestamp explicitly and are unaffected.
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
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
