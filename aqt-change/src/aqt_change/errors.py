"""Errors with a stable code, a message and an exit status (1 = check failed, 2 = usage/runtime)."""

from __future__ import annotations


class ChangeError(Exception):
    def __init__(self, code: str, message: str, *, details: dict | None = None, exit_code: int = 1):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}
        self.exit_code = exit_code

    def as_dict(self) -> dict:
        return {"ok": False, "code": self.code, "message": self.message, "details": self.details}


def usage(code: str, message: str, **details) -> ChangeError:
    return ChangeError(code, message, details=details, exit_code=2)


def refused(code: str, message: str, **details) -> ChangeError:
    return ChangeError(code, message, details=details, exit_code=1)
