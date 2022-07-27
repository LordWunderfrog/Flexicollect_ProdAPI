from typing import Any

from stripe.error import StripeError as StripeError

class OAuthError(StripeError):
    def __init__(
        self,
        code,
        description,
        http_body: Any | None = ...,
        http_status: Any | None = ...,
        json_body: Any | None = ...,
        headers: Any | None = ...,
    ) -> None: ...
    def construct_error_object(self): ...

class InvalidClientError(OAuthError): ...
class InvalidGrantError(OAuthError): ...
class InvalidRequestError(OAuthError): ...
class InvalidScopeError(OAuthError): ...
class UnsupportedGrantTypeError(OAuthError): ...
class UnsupportedResponseTypeError(OAuthError): ...
