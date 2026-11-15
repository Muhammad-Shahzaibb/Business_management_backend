"""Safe error responses.

Internal exception details (SQL, stack traces, connection strings, ...) are written
to the server log only. Clients get a short generic message.
"""
import logging

from fastapi import HTTPException, status

logger = logging.getLogger("app")


def server_error(message: str, status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR) -> HTTPException:
    """Log the exception currently being handled and return a generic HTTPException.

    Call it inside an `except` block:  raise server_error("Failed to fetch sales")
    """
    logger.exception(message)
    return HTTPException(status_code=status_code, detail=message)
