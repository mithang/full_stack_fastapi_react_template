# Keep generic exceptions here

class ApiBaseException(Exception):
    """Base exception for the app."""
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message

class NotFoundException(ApiBaseException):
    """Entity not found."""
    def __init__(self, entity: str, identifier: str):
        # The ApiBaseException handler logs ex.message verbatim, and
        # every subclass (User/Tenant/Role/Product/Pricing/BillingRecord/
        # StripeSettings not-found) funnels its identifier through here,
        # including raw path params and JSON-body values (tenant name,
        # role name, user id) that Starlette/Pydantic pass through
        # unvalidated — a newline-bearing identifier would otherwise
        # forge extra log lines on every failed lookup. Flatten CR/LF
        # here, at the single construction site, covering all raise
        # sites at once; the raw value still drives the lookup, and
        # normal identifiers render identically.
        safe_identifier = str(identifier).replace("\r", " ").replace("\n", " ")
        message = f"{entity} with identifier {safe_identifier} not found."
        super().__init__(message)

class ConflictException(ApiBaseException):
    """Entity already exists / conflict."""
    def __init__(self, entity: str, identifier: str):
        # Same handler-logging premise as NotFoundException above:
        # ConflictException identifiers (tenant name, role name, email)
        # are raw JSON-body values, so flatten CR/LF at this single
        # construction site as well.
        safe_identifier = str(identifier).replace("\r", " ").replace("\n", " ")
        message = f"{entity} with identifier {safe_identifier} already exists."
        super().__init__(message)

class UnauthorizedException(ApiBaseException):
    """Unauthorized or forbidden action."""
    def __init__(self, message: str):
        super().__init__(message)

class InvalidOperationException(ApiBaseException):
    """Invalid input or operation."""
    def __init__(self, message: str):
        # The ApiBaseException handler logs ex.message verbatim, and
        # these two bases take caller-built messages directly — unlike
        # NotFound/Conflict, which take an identifier. Direct raise
        # sites embed raw values (dns_resolver's hostname, which
        # reaches the Celery worker through an unvalidated
        # dict[str, str] payload; role_endpoint's path-param role_id;
        # auth_service's plain-str subdomain, which its own except
        # handler re-logs via {ioe}), so a newline-bearing value
        # would otherwise forge extra log lines on every failure.
        # Flatten CR/LF here, at the single construction site,
        # covering all raise sites at once (subclass messages from
        # api/core/exceptions.py funnel through here too, and the
        # flattening is idempotent with their own sanitizing); the
        # raw values still drive the lookups, and normal messages
        # render identically.
        safe_message = str(message).replace("\r", " ").replace("\n", " ")
        super().__init__(safe_message)


class ForbiddenException(ApiBaseException):
    """Forbidden action."""
    def __init__(self, message: str):
        # Same handler-logging premise as InvalidOperationException
        # above: today's ForbiddenException raise sites are fixed
        # strings, but the base takes caller-built messages directly,
        # so flatten CR/LF here to keep any future caller embedding
        # a raw identifier from re-opening the vector.
        safe_message = str(message).replace("\r", " ").replace("\n", " ")
        super().__init__(safe_message)


class AuthenticationFailedException(ApiBaseException):
    """Authentication failed."""
    def __init__(self, message: str = "Authentication failed."):
        super().__init__(message)


class AwsException(ApiBaseException):
    def __init__(self, message: str):
        super().__init__(message)

class AzureException(ApiBaseException):
    def __init__(self, message: str):
        super().__init__(message)

