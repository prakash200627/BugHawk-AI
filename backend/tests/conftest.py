"""Keep the test process off any non-local database."""
from urllib.parse import urlparse

import pytest


def pytest_configure(config):
    from app.config import settings

    host = (urlparse(settings.database_url).hostname or "").lower()
    if host not in {"localhost", "127.0.0.1", "::1"}:
        raise pytest.UsageError(
            "Refusing to run tests against a non-local database host."
        )
