from collections.abc import Container, Mapping
from typing import Any

from .backends.base import Key

def sign(
    payload: str | Mapping[str, Any],
    # Internally it's passed down to jwk.construct(), which explicitly checks for
    # key as dict instance, instead of a Mapping
    key: str | dict[str, Any] | Key,
    headers: Mapping[str, Any] | None = ...,
    algorithm: str = ...,
) -> str: ...
def verify(
    token: str,
    key: str | Mapping[str, Any] | Key,
    # Callers of this function, like jwt.decode(), and functions called internally,
    # like jws._verify_signature(), use and accept algorithms=None
    algorithms: str | Container[str] | None,
    verify: bool = ...,
) -> str: ...
def get_unverified_header(token: str) -> dict[str, Any]: ...
def get_unverified_headers(token: str) -> dict[str, Any]: ...
def get_unverified_claims(token: str) -> str: ...
