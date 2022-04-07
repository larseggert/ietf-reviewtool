"""ietf-reviewtool module"""

try:
    from importlib.metadata import version, PackageNotFoundError
except ImportError:
    from importlib.metadata import version, PackageNotFoundError


try:
    __version__ = version(__name__)
except PackageNotFoundError:
    __version__ = "unknown"
