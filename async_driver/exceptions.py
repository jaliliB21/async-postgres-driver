class DriverError(Exception):
    """Base exception for all driver-related errors."""
    pass


class ConnectionError(DriverError):
    """Raised for TCP or connection-related issues."""
    pass


class AuthenticationError(DriverError):
    """Raised for errors during the authentication process."""
    pass


class QueryError(DriverError):
    """Raised for errors during query execution."""
    pass