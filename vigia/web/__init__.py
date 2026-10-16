"""The local web of Vigía (T12): a lookout post on 127.0.0.1, read-only.

``create_app`` builds it; ``vigia web`` runs it. Security reasoning: ``vigia.web.security``.
"""

from vigia.web.app import create_app
from vigia.web.reader import BoxReader, BoxUnavailable
from vigia.web.security import make_token

__all__ = ["BoxReader", "BoxUnavailable", "create_app", "make_token"]
