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
        super().__init__(message)


class ForbiddenException(ApiBaseException):
    """Forbidden action."""
    def __init__(self, message: str):
        super().__init__(message)


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

