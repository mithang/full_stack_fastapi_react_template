from collections import deque
import glob
import json
import tempfile
from typing import List, Optional
from pydantic import ValidationError
from api.common.utils import capture_audit_log, get_logger
from api.domain.dtos.audit_logs_dto import AuditActionType, AuditLogDto, AuditLogListDto

logger = get_logger(__name__)

class AuditLogRepository:

    async def _get_files_matching_pattern(self, tenant_id: str | None = None) -> List[str]:
        # Read from the same directory the writer uses: capture_audit_log
        # resolves it via tempfile.gettempdir(), which honours TMPDIR, so
        # hardcoding /tmp here made listings silently empty wherever
        # TMPDIR points elsewhere (containers, test harnesses).
        temp_dir = tempfile.gettempdir()
        file_path_pattern = f"{temp_dir}/audit_logs_forhost_*.jsonl"
        if tenant_id:
            # tenant_id is interpolated into a glob pattern, so escape it:
            # a metacharacter (e.g. "*") in an id would otherwise match
            # other tenants' log files and leak their audit entries to
            # this tenant's AUDIT_LOGS_VIEW_ONLY reader. The trailing
            # "_*" date wildcard is intentional and stays unescaped.
            file_path_pattern = f"{temp_dir}/audit_logs_for{glob.escape(tenant_id)}_*.jsonl"

        logger.info(f"Reading audit logs from files matching pattern: {file_path_pattern}")

        files = glob.glob(file_path_pattern)

        # IMPORTANT: scan oldest → newest so the deque ends up with the last K lines
        # If your filenames end with YYYY-MM-DD, name sort works for chronological asc.
        files.sort()  # ascending
        return files

    async def add_audit_log(self, audit_log: AuditLogDto) -> None:
        await capture_audit_log(audit_log)

    async def list_audit_logs(self, tenant_id: str | None = None, limit: int = 10, skip: int = 0, action: Optional[AuditActionType] = None) -> AuditLogListDto:
       
        files = await self._get_files_matching_pattern(tenant_id=tenant_id)

        total = 0
        keep = skip + limit
        ring = deque(maxlen=keep) # keep the last (skip + limit) lines

        for file_path in files:
            try:
                # Explicit utf-8 with replacement: the default encoding
                # depends on locale (under LANG=C it is ascii, so any
                # non-ASCII audit entry would abort the listing), and a
                # torn multi-byte character from a concurrent append
                # would raise UnicodeDecodeError mid-iteration. With
                # errors="replace" such a line just fails JSON parsing
                # below and is skipped like any other torn line.
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        try:
                            obj = json.loads(line)
                        except json.JSONDecodeError:
                            # A torn line (crash mid-append, or a read racing
                            # a concurrent append — capture_audit_log appends
                            # without locking) must not abort the whole listing;
                            # skip it and keep the parseable entries.
                            logger.warning(f"Skipping unparseable audit log line in {file_path}")
                            continue
                        if not isinstance(obj, dict):
                            # A JSON value that is not an object (e.g. a bare
                            # list or number) has no fields to validate;
                            # skip it like an unparseable line.
                            logger.warning(f"Skipping non-object audit log line in {file_path}")
                            continue
                        if action and obj.get("action") != action:
                            continue
                        try:
                            dto = AuditLogDto(**obj)
                        except ValidationError:
                            # A line that parses as JSON but fails DTO
                            # validation (missing required field, unknown
                            # action value, wrong field type — e.g. written
                            # under an older schema) must not abort the
                            # whole listing; skip it and keep the valid
                            # entries. It is not counted in total, so total
                            # and has_next stay consistent with what is shown.
                            logger.warning(f"Skipping audit log line failing validation in {file_path}")
                            continue
                        total += 1
                        ring.append(dto)  # older ones drop automatically when full
            except OSError:
                # FileNotFoundError is the glob-to-open race (file removed
                # between listing and opening), but an unreadable file
                # (PermissionError) or a directory matching the pattern
                # (IsADirectoryError) must not abort the whole listing
                # either — skip that file like a missing one and keep
                # the entries from the readable files.
                continue

        # Now ring holds the last (skip+limit) lines globally (latest lines overall)
        # Convert to newest-first
        newest_first = list(ring)[::-1]

        # Slice for pagination
        sliced = newest_first[skip:skip + limit]

        # sliced already holds validated DTOs (constructed in the loop above)
        logs: List[AuditLogDto] = sliced

        return AuditLogListDto(
            total=total,
            logs=logs,
            has_next=(skip + limit) < total,
            has_previous=skip > 0,
            limit=limit,
            skip=skip
        )

    async def return_all_audit_logs(self, action: Optional[AuditActionType] = None, tenant_id: str | None = None) -> List[AuditLogDto]:
        files = await self._get_files_matching_pattern(tenant_id=tenant_id)
        results: List[AuditLogDto] = []
        for file_path in files:
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        try:
                            obj = json.loads(line)
                        except json.JSONDecodeError:
                            # Same torn-line reasoning as list_audit_logs:
                            # one unparseable line must not abort the report.
                            logger.warning(f"Skipping unparseable audit log line in {file_path}")
                            continue
                        if not isinstance(obj, dict):
                            # Same non-object reasoning as list_audit_logs.
                            logger.warning(f"Skipping non-object audit log line in {file_path}")
                            continue
                        if action and obj.get("action") != action:
                            continue
                        try:
                            results.append(AuditLogDto(**obj))
                        except ValidationError:
                            # Same schema-drift reasoning as list_audit_logs:
                            # one invalid entry must not abort the report.
                            logger.warning(f"Skipping audit log line failing validation in {file_path}")
                            continue
            except OSError:
                # Same reasoning as list_audit_logs: a missing, unreadable,
                # or directory-matching file must not abort the report;
                # skip it and keep the entries from the readable files.
                continue
    
        if len(results) == 0:
            logger.info("No audit logs found.")
            return []
    
        return results[::-1]  # return newest first
