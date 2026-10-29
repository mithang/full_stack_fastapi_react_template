from typing import Any, Dict, List, Optional, TypeVar, Generic
from beanie import Document, PydanticObjectId
from beanie.operators import Set
from beanie.odm.interfaces.aggregate import DocumentProjectionType, AggregationQuery
from api.common.utils import get_logger, get_utc_now

logger = get_logger(__name__)


def _safe_log_value(value: Any) -> str:
    # Path ids arrive percent-decoded (same premise as the cache-middleware
    # fix), so a newline-bearing id could forge extra log lines. Flatten
    # CR/LF in the logged copy only; the raw id still drives the lookup.
    return str(value).replace("\r", " ").replace("\n", " ")

T = TypeVar("T", bound=Document)

class BaseRepository(Generic[T]):
    def __init__(self, model: type[T]):
        self.model = model

    async def single_or_none(self, **kwargs) -> Optional[T]:
        result = await self.model.find(kwargs).first_or_none()
        return result
    
    async def get(self, id: str) -> Optional[T]:
        try:
            object_id = PydanticObjectId(id)
        except Exception:
            # A malformed id (e.g. a tampered detail URL) cannot match any
            # document, so treat it as "not found" instead of escaping as
            # a 500; callers already map None to their NotFound exception,
            # and update()/delete() below already handle a None doc.
            # Broad catch is deliberate and safe here: the conversion is
            # pure (no I/O), and beanie/bson raise InvalidId while the
            # pydantic-validated paths raise ValidationError, so catching
            # one shape alone would leave the other escaping as a 500.
            return None
        result = await self.model.find_one({"_id": object_id})
        # Do not log the full document: this repository is generic over
        # every collection, including User (hashed password), passkey,
        # magic-link and password-reset documents, and the api logger
        # runs at DEBUG in all environments — so the old line leaked
        # credential material into server logs on every get (and, via
        # update()/delete(), on every update/delete). Found/not-found
        # is all a debug line here needs.
        logger.debug(f"Get result for id {id}: {'found' if result is not None else 'not found'}")
        return result

    async def list(self) -> List[T]:
        results = await self.model.find_all().to_list()
        return results
    
    async def search(self, query: Dict[str, Any], limit: int = 100) -> List[T]:      
        results = await self.model.find(query).to_list(length=limit)
        return results
    
    async def create(self, data: dict) -> T:
        doc = self.model(**data)
        result = await doc.insert()
        return result


    async def update(self, id: str, data: dict) -> Optional[T]:
        doc = await self.get(id)
        if not doc:
            return None
        # updated_at is a creation-time default_factory (iteration 410),
        # so without this every update left it at the creation time:
        # branding was the only caller bumping it manually. Stamp it
        # centrally instead, on a copy so the caller's dict is untouched;
        # models without an updated_at field are left alone. This flows
        # through the role/user overrides and the tenant, billing,
        # subscription-plan and SSO callers, all of which go through
        # this method.
        if "updated_at" in self.model.model_fields:
            data = {**data, "updated_at": get_utc_now()}
        await doc.update(Set(data))
        return doc

    async def delete(self, id: str) -> bool:
        doc = await self.get(id)
        logger.info(f"Deleting document with id: {_safe_log_value(id)}, Found doc: {doc is not None}")
        if not doc:
            return False
        await doc.delete()
        logger.info(f"Document with id: {id} deleted successfully.")
        return True
    
    async def count(self, params: Optional[Any] | None = None) -> int:
        if params:
            return await self.model.find(params).count()
        return await self.model.count()

    async def aggregate(self, pipeline: List[dict], projection_model: type[DocumentProjectionType] | None = None) -> type[DocumentProjectionType] | AggregationQuery[Dict[str, Any]]:
        if not projection_model:
            return self.model.aggregate(pipeline)
        else:
            data = self.model.aggregate(pipeline, projection_model=projection_model)
            return await data.to_list()
        
    async def collection_name(self) -> str:
        return self.model.get_collection_name()
