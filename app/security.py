"""Lightweight auth helpers for demo purposes."""
from __future__ import annotations

import os
from dotenv import load_dotenv

from werkzeug.security import check_password_hash, generate_password_hash
load_dotenv()

_DEFAULT_USERNAME = os.getenv("APP_USERNAME")
_DEFAULT_PASSWORD_HASH = generate_password_hash(os.getenv("APP_PASSWORD"))


def verify_credentials(username: str, password: str) -> bool:
    """Validate provided credentials against demo configuration."""
    if username != _DEFAULT_USERNAME:
        return False
    return check_password_hash(_DEFAULT_PASSWORD_HASH, password)
