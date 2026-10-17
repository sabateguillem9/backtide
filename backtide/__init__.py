"""backtide: a black box for AI agents."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("backtide")
except PackageNotFoundError:  # imported from source, as in the proxy's container (docs/21)
    __version__ = "0+unknown"
