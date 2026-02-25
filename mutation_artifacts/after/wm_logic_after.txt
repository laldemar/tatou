# server/src/wm_logic.py
from typing import Dict


class WatermarkLogicError(Exception):
    """Raised when watermark logic validation fails."""


def validate_method_name(method: str) -> None:
    if not isinstance(method, str):
        raise WatermarkLogicError("method must be a string")

    # Reject empty or whitespace-only strings
    if not method.strip():
        raise WatermarkLogicError("method must not be empty")


def validate_secret_and_key(secret: str, key: str) -> None:
    # Reject non-strings or whitespace-only values
    if not isinstance(secret, str) or not secret.strip():
        raise WatermarkLogicError("invalid secret")

    if not isinstance(key, str) or not key.strip():
        raise WatermarkLogicError("invalid key")


def resolve_method(registry: Dict[str, object], method: str) -> object:
    validate_method_name(method)

    if method not in registry:
        raise WatermarkLogicError(f"unknown method: {method}")

    return registry[method]