class WarrantException(Exception):
    """Base class for all __MASKED__ exceptions"""


class ForceChangePasswordException(WarrantException):
    """Raised when the user is forced to change their password"""


class TokenVerificationException(WarrantException):
    """Raised when token verification fails."""
