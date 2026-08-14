from __future__ import annotations

import hmac
import os


def configured_password() -> str:
    return os.getenv("DASHBOARD_PASSWORD", "").strip()


def password_configured() -> bool:
    return bool(configured_password())


def password_matches(candidate: str | None) -> bool:
    expected = configured_password()
    if not expected or candidate is None:
        return False
    return hmac.compare_digest(candidate, expected)
