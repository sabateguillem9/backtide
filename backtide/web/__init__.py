"""The local web of backtide (T12): a lookout post on 127.0.0.1, read-only.

``create_app`` builds it; ``backtide web`` runs it. Security reasoning: ``backtide.web.security``.
"""

from backtide.web.app import create_app
from backtide.web.reader import BoxReader, BoxUnavailable
from backtide.web.security import make_token

__all__ = ["BoxReader", "BoxUnavailable", "create_app", "make_token"]
