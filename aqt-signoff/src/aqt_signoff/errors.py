"""Errors with a stable code and the CLI exit code they map to."""

from __future__ import annotations


class SignoffError(Exception):
    """Base error. ``exit`` is 1 for a failed check or refusal, 2 for usage/runtime problems."""
    code = "error"
    exit = 2

    def __init__(self, message: str, *, code: str | None = None, details: dict | None = None):
        super().__init__(message)
        if code:
            self.code = code
        self.details = details or {}


class UsageError(SignoffError):
    code = "usage"


class NotFound(SignoffError):
    code = "not_found"


class Refused(SignoffError):
    """A rule refused the operation (agent context, self-approval, role, grace period)."""
    code = "refused"
    exit = 1


class Conflict(SignoffError):
    """The caller's view is stale or conflicts with the stored state (hash mismatch, request key reuse)."""
    code = "conflict"
    exit = 1


class AlreadyClaimed(Conflict):
    code = "already_claimed"


class AuthFailed(SignoffError):
    code = "auth_failed"
    exit = 1
